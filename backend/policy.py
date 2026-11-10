"""Permission and data-flow constraints. A model never grants execution authority."""
import hashlib
import json
import math
import re
import shlex
import urllib.parse
from functools import lru_cache
from pathlib import PurePosixPath
from .detection import detect, model_configured, model_review, normalize, sensitive

TOOLS = {"kb.search", "fs.read", "fs.write", "net.fetch", "exec", "git.status", "git.push", "git.commit", "agent.delegate", "script.run", "memory.read", "memory.write"}
TRUSTED_HOSTS = {"docs.example.test", "intranet.example.test"}
RANK = {"allow": 0, "confirm": 1, "block": 2}
BUILTINS = [
    {"id": "core.sensitive_path", "name": "敏感路径保护", "description": "禁止访问凭据、启动项、系统目录以及路径越界", "enabled": True, "priority": 1000, "condition": {"tools": ["fs.read", "fs.write"]}, "action": "block", "mandatory": True},
    {"id": "core.secret_flow", "name": "敏感数据流约束", "description": "阻断网络外发或向子 Agent 传递凭据，包括已标记来源的派生数据", "enabled": True, "priority": 1000, "condition": {"tools": ["net.fetch", "agent.delegate"], "sensitive": True}, "action": "block", "mandatory": True},
    {"id": "core.command", "name": "命令行为约束", "description": "拒绝下载执行、编码执行、未知解释器和无法覆盖的动态命令", "enabled": True, "priority": 1000, "condition": {"tools": ["exec"]}, "action": "block", "mandatory": True},
    {"id": "core.readonly", "name": "只读任务授权边界", "description": "只读会话禁止文件写入、Git 提交/推送和通过命令进行等价写入", "enabled": True, "priority": 1000, "condition": {"scope": "read_only"}, "action": "block", "mandatory": True},
    {"id": "core.source_risk", "name": "来源污染拦截", "description": "候选操作引用被阻断来源时禁止执行", "enabled": True, "priority": 1000, "condition": {"risk_min": 80}, "action": "block", "mandatory": True},
    {"id": "review.write", "name": "写入前确认", "description": "开发任务的文件写入需要对具体参数确认", "enabled": True, "priority": 100, "condition": {"tools": ["fs.write"], "scope": "development"}, "action": "confirm", "mandatory": False},
    {"id": "review.git", "name": "代码变更确认", "description": "开发任务的提交和推送需要对具体参数确认；候选参数不能自行证明无副作用", "enabled": True, "priority": 100, "condition": {"tools": ["git.push", "git.commit"]}, "action": "confirm", "mandatory": False},
]

def parameter_hash(tool: str, args: dict) -> str:
    return hashlib.sha256(json.dumps({"tool": tool, "args": args}, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()

def canonical_path(path: str) -> str:
    return urllib.parse.unquote(normalize(path)[0]).replace("\\", "/")

def dangerous_path(path: str) -> bool:
    path = canonical_path(path)
    segments = path.split("/")
    # Win32 normalizes trailing dots/spaces before opening components. Reject
    # ambiguous spellings on every OS so the same policy stays portable.
    ambiguous_component = any(s not in {"", ".", ".."} and s != s.rstrip(" .") for s in segments)
    return (
        not path or ambiguous_component or path.startswith(("/", "~")) or bool(re.match(r"^[a-z]:", path))
        or any(s in {"..", ".ssh", ".aws", ".env", ".git", "credentials", "secrets", "startup", "windows", "system32", "proc", "sys", "dev"} for s in segments)
        or any(x in path for x in ["id_rsa", "id_ed25519", "private_key", "private-key", "cron."])
        or any(s.rstrip(" .").startswith(".env") for s in segments)
        or any(re.fullmatch(r"(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", s.rstrip(" .")) for s in segments)
        or "\x00" in path or ":" in path
    )

def command_structure(command: str) -> dict:
    normalized = normalize(command)[0]
    try:
        # Normalization is only a detection view, never the execution payload.
        words = shlex.split(command, posix=True)
    except ValueError:
        return {"kind": "unknown", "coverage": "parse_error"}
    if command in {"git status", "git diff", "git log --oneline"}:
        return {"kind": "git_read", "words": words, "coverage": "complete_fixture_grammar"}
    if re.search(r"\bgit\s+(?:push|commit)\b", normalized):
        return {"kind": "git_write", "coverage": "recognized_git_write"}
    if words and words[0] == "echo" and not re.search(r"[;&|`$()%!^<\r\n]", normalized):
        if ">" not in normalized:
            return {"kind": "echo", "text": " ".join(words[1:]), "coverage": "complete_fixture_grammar"}
        match = re.fullmatch(r"echo\s+(.+?)\s*>\s*(reports/[A-Za-z0-9_.-]+)", command)
        if match and not dangerous_path(match[2]):
            return {"kind": "echo_write", "text": " ".join(shlex.split(match[1], posix=True)), "path": match[2], "coverage": "complete_fixture_grammar"}
    scan = detect(command, "code", use_model=False)
    return {"kind": "dangerous" if scan["findings"] else "unknown", "coverage": "uncovered_shell_grammar", "findings": scan["findings"]}

class ParameterEvaluationError(ValueError):
    """A relevant parameter condition could not be safely evaluated."""


@lru_cache(maxsize=512)
def parameter_path(path: str) -> tuple:
    """Bounded JSON path: root, exact member names and non-negative indices."""
    if not isinstance(path, str) or not 1 <= len(path) <= 256 or not path.startswith("$"):
        raise ValueError("Parameter path must start with $ and contain at most 256 characters")
    parts, position = [], 1
    decoder = json.JSONDecoder()
    while position < len(path):
        if len(parts) >= 16:
            raise ValueError("Parameter paths are limited to 16 steps")
        if path[position] == ".":
            match = re.match(r"[A-Za-z_][A-Za-z0-9_-]*", path[position + 1:])
            if not match:
                raise ValueError("Parameter path has an invalid exact member name")
            parts.append(match[0])
            position += 1 + len(match[0])
        elif path[position:position + 2] == '["':
            try:
                member, length = decoder.raw_decode(path[position + 1:])
            except ValueError as exc:
                raise ValueError("Parameter path has an invalid quoted member") from exc
            position += 1 + length
            if not isinstance(member, str) or not member or path[position:position + 1] != "]":
                raise ValueError("Parameter path requires a nonempty quoted member and closing ]")
            if any(0xD800 <= ord(c) <= 0xDFFF for c in member):
                raise ValueError("Parameter path cannot contain a lone Unicode surrogate")
            parts.append(member)
            position += 1
        elif path[position] == "[":
            match = re.match(r"\[(0|[1-9][0-9]{0,4})\]", path[position:])
            if not match or int(match[1]) > 65535:
                raise ValueError("Parameter array index must be between 0 and 65535")
            parts.append(int(match[1]))
            position += len(match[0])
        else:
            raise ValueError("Unsupported JSON path syntax; wildcards, recursion and filters are forbidden")
    return tuple(parts)


@lru_cache(maxsize=256)
def safe_parameter_pattern(pattern: str):
    """Full-match subset: at most one quantified single-character atom.

    No groups, alternatives, backreferences or nested repetitions. Bounded
    expression/input lengths and a single quantifier prevent combinatorial
    backtracking. Actual parameter text is never normalized for matching.
    """
    if not isinstance(pattern, str) or not 1 <= len(pattern) <= 128:
        raise ValueError("Parameter pattern must contain 1–128 characters")
    i, quantifiers = (1 if pattern.startswith("^") else 0), 0
    allowed_escapes = set(r"dDsSwW\.^$|?*+()[]{}-/ ")
    while i < len(pattern):
        char = pattern[i]
        if char == "$" and i == len(pattern) - 1:
            i += 1
            break
        if char == "\\":
            if i + 1 >= len(pattern) or pattern[i + 1] not in allowed_escapes:
                raise ValueError("Unsupported pattern escape")
            i += 2
        elif char == "[":
            i += 1
            if i < len(pattern) and pattern[i] == "^":
                i += 1
            start = i
            while i < len(pattern) and pattern[i] != "]":
                if pattern[i] == "\\":
                    if i + 1 >= len(pattern) or pattern[i + 1] not in allowed_escapes:
                        raise ValueError("Unsupported character-class escape")
                    i += 2
                elif pattern[i] == "[" or pattern[i:i + 2] in {"&&", "--", "~~", "||"}:
                    raise ValueError("Nested character classes and set operations are forbidden")
                else:
                    i += 1
            if i >= len(pattern) or i == start:
                raise ValueError("Empty or unclosed character class")
            i += 1
        elif char in "^$*+?{}]()|" or ord(char) < 32:
            raise ValueError("Groups, alternation, assertions and standalone quantifiers are forbidden")
        else:
            i += 1
        if i < len(pattern) and pattern[i] in "*+?{":
            quantifiers += 1
            if quantifiers > 1:
                raise ValueError("A parameter pattern permits at most one quantifier")
            if pattern[i] == "{":
                match = re.match(r"\{([0-9]{1,3})(?:,([0-9]{0,3}))?\}", pattern[i:])
                if not match:
                    raise ValueError("Invalid bounded pattern repetition")
                low = int(match[1])
                high = int(match[2]) if match[2] else low
                if low > 128 or high > 128 or high < low:
                    raise ValueError("Explicit pattern repetition counts must be ordered and <=128")
                i += len(match[0])
            else:
                i += 1
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise ValueError("Invalid parameter pattern") from exc


def _json_type(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float) and math.isfinite(value):
        return "number"
    return {str: "string", list: "array", dict: "object"}.get(type(value), "unsupported")


def _scalar(value):
    return _json_type(value) in {"boolean", "integer", "number", "string"} and (not isinstance(value, str) or len(value) <= 4096)


def validate_parameter_conditions(parameters):
    """Shared API/runtime validation; no code evaluation or arbitrary regex."""
    if parameters is None:
        return
    if not isinstance(parameters, list) or not 1 <= len(parameters) <= 16:
        raise ValueError("parameters requires 1–16 conditions")
    for item in parameters:
        if not isinstance(item, dict) or set(item) != {"path", "operator", "value"}:
            raise ValueError("Each parameter condition requires exactly path, operator and value")
        if not isinstance(item["path"], str):
            raise ValueError("Parameter path must be a string")
        parameter_path(item["path"])
        op, value = item["operator"], item["value"]
        if op == "equals":
            if not _scalar(value):
                raise ValueError("equals requires a finite JSON scalar; use type:null for null")
        elif op == "enum":
            if not isinstance(value, list) or not 1 <= len(value) <= 64 or not all(_scalar(v) for v in value):
                raise ValueError("enum requires 1–64 finite non-null JSON scalar values")
        elif op == "pattern":
            if not isinstance(value, str):
                raise ValueError("pattern requires a string")
            safe_parameter_pattern(value)
        elif op == "type":
            if not isinstance(value, str) or value not in {"string", "integer", "number", "boolean", "null", "array", "object"}:
                raise ValueError("type requires a supported JSON type name")
        else:
            raise ValueError("Unsupported parameter condition operator")
    if len(json.dumps(parameters, ensure_ascii=False)) > 32768:
        raise ValueError("Combined parameter conditions exceed 32768 characters")


def _parameter_matches(item, args):
    value = args
    for part in parameter_path(item["path"]):
        if isinstance(part, str) and isinstance(value, dict) and part in value:
            value = value[part]
        elif isinstance(part, int) and isinstance(value, list) and part < len(value):
            value = value[part]
        else:
            raise ParameterEvaluationError("参数路径不存在或容器类型不符")
    op, expected = item["operator"], item["value"]
    actual_type = _json_type(value)
    if op == "type":
        return actual_type == expected or (expected == "number" and actual_type == "integer")
    if not _scalar(value):
        raise ParameterEvaluationError("待匹配参数不是支持的有限标量或超过 4096 字符")
    if op == "pattern":
        if actual_type != "string":
            raise ParameterEvaluationError("pattern 仅接受字符串参数")
        return safe_parameter_pattern(expected).fullmatch(value) is not None
    candidates = [expected] if op == "equals" else expected
    compatible = [x for x in candidates if _json_type(x) == actual_type or {_json_type(x), actual_type} <= {"integer", "number"}]
    if not compatible:
        raise ParameterEvaluationError("参数类型与条件值不兼容；不进行字符串/布尔/数字隐式转换")
    return any(value == x for x in compatible)


def matches(condition: dict, context: dict) -> bool:
    if condition.get("json_schema") is not None:
        from .schema_policy import schema_matches
        try:
            if not schema_matches(condition["json_schema"], context["args"]):
                return False
        except Exception as exc:
            raise ParameterEvaluationError("JSON Schema 无法安全求值") from exc
    if condition.get("tools") is not None and context["tool"] not in condition["tools"]:
        return False
    if condition.get("scope") is not None and context["scope"] != condition["scope"]:
        return False
    if condition.get("risk_min") is not None and context["risk_score"] < condition["risk_min"]:
        return False
    if condition.get("sensitive") is not None and context["sensitive"] != condition["sensitive"]:
        return False
    if condition.get("path_prefixes") is not None and not any(context["path"] == canonical_path(x).rstrip("/") or context["path"].startswith(canonical_path(x).rstrip("/") + "/") for x in condition["path_prefixes"]):
        return False
    if condition.get("destinations") is not None and context["destination"] not in condition["destinations"]:
        return False
    parameters = condition.get("parameters")
    if parameters is None:
        return True
    try:
        validate_parameter_conditions(parameters)
        # A non-match must not conceal a later missing/unsupported field.
        results = [_parameter_matches(item, context["args"]) for item in parameters]
    except (ValueError, TypeError, KeyError) as exc:
        raise ParameterEvaluationError("参数约束无法完整、安全地求值") from exc
    return all(results)

def explicit_prohibitions(text, findings):
    """Narrow lexical eligibility, never a security verdict or authorization."""
    prefix = re.compile(r'(?:^|[，。；;.!?、\n"])(?:请)?(?:不要|不得|禁止|切勿|绝不|不许|不能)(?:尝试)?\s*$|(?:^|[.;!?\n"])\s*(?:please\s+)?(?:do not|never|must not)\s+$', re.I)
    brackets = [(m.start(), m.end()) for m in re.finditer(
        r'不要执行(?:该|这些|任何)?(?:参考资料|文件|外部材料|来源文本)中的任何指令[（(][^）)\n]{1,240}[）)]', text)]
    return bool(findings) and all(
        f['rule_id'] == 'inj.override' and f['mapping'] == 'normalized'
        and (prefix.search(text[max(0, f['start'] - 80):f['start']])
             or any(low <= f['start'] < f['end'] <= high for low, high in brackets))
        for f in findings)


def review(session: dict, candidate: dict, sources: list[dict], history: list[dict], policy: dict, approved: bool = False, use_model: bool = True, observed_sources: list[dict] | None = None, model_redactor=None) -> dict:
    tool, args = candidate["tool"], candidate["args"]
    decision, reasons, matched, gaps = "allow", [], [], []
    rule_actions = {}
    risk = 0
    path = str(args.get("path", ""))
    url = str(args.get("url", ""))
    try:
        parsed_url = urllib.parse.urlparse(url)
        host = (parsed_url.hostname or "").lower()
    except ValueError:
        parsed_url, host = urllib.parse.urlparse(""), ""
    source_sensitive = any(s.get("sensitive") for s in sources)
    session_sensitive = any(s.get("sensitive") and s.get("decision") == "allow" for s in (observed_sources or []))
    # Session taint is a conservative policy assumption, not proof of exact word lineage.
    history_sensitive = any(c.get("_sensitive_result") for c in history)
    is_sensitive = sensitive(args) or source_sensitive or history_sensitive or session_sensitive
    command = command_structure(str(args.get("command", ""))) if tool == "exec" else None

    def hit(action: str, rid: str, reason: str, value: int):
        nonlocal decision, risk
        if RANK[action] > RANK[decision]:
            decision = action
        risk = max(risk, value)
        reasons.append(reason)
        matched.append(rid)
        if RANK[action] > RANK[rule_actions.get(rid, 'allow')]:
            rule_actions[rid] = action
        else:
            rule_actions.setdefault(rid, action)

    if tool not in TOOLS:
        hit("block", "core.unknown_tool", "工具未注册，默认拒绝执行", 100)
    if candidate.get("resource_facts", {}).get("gap_code"):
        hit("block", "core.resource_unverified", "实际资源对象未能绑定；禁止下发执行许可", 100)
        gaps.append(str(candidate["resource_facts"]["gap_code"]))
    if tool == "script.run":
        check = candidate.get("_script_precheck") or {}
        if session["scope"] != "development" or not check.get("valid") or check.get("prohibited"):
            hit("block", "core.script_authorization", "脚本授权、版本或强制禁止检查未通过", 100)
        else:
            hit("confirm", "review.script_behavior", "项目脚本内部行为尚需取证；试验不产生正式执行许可", 55)
            gaps.extend(check.get("gaps", []))
            gaps.append("测试路径不代表全部分支；正式脚本执行尚需受约束执行器及完整检查")
    for gap in candidate.get("_data_flow_errors", []):
        hit("block", "core.data_permission", "数据用途、实际接收方或字段版本绑定未通过核验", 100)
        gaps.append(gap)
    if tool in {"fs.read", "fs.write"} and (not isinstance(args.get("path"), str) or dangerous_path(path)):
        hit("block", "core.sensitive_path", "路径涉及敏感资产、绝对路径或目录越界；任务未获得相应权限", 100)
    if tool == "fs.write" and not isinstance(args.get("content"), str):
        hit("block", "core.schema", "fs.write 必须提供字符串 content", 90)
    if tool == "memory.read" and (set(args) != {"memory_id"} or not isinstance(args.get("memory_id"), str)):
        hit("block", "core.schema", "记忆读取必须绑定明确对象", 90)
    if tool == "memory.write":
        if set(args) != {"content", "label"} or not all(isinstance(args[k], str) and args[k].strip() for k in ("content", "label")):
            hit("block", "core.schema", "记忆写入必须提供完整正文与标签", 90)
        elif not approved:
            hit("confirm", "review.memory_write", "持久记忆写入需确认；获准后仍须污染检测", 50)
    if (tool in {"net.fetch", "agent.delegate", "git.push"} or candidate.get("mcp_server", "local-fixture") not in {"local-fixture", "deepseek-harness/native"}) and is_sensitive:
        hit("block", "core.secret_flow", "待传递参数或关联来源具有凭据标签；禁止外发或传入子 Agent", 100)
        if source_sensitive or history_sensitive or session_sensitive:
            reasons.append("依据已登记来源/成功读取的敏感标签保守继承限制，非精确字词血缘证明")
        if session_sensitive and not source_sensitive:
            gaps.append("候选参数未提供可核验的逐字数据关系；会话已准入敏感内容，按保守数据流约束阻断")
    if session["scope"] == "read_only" or candidate.get('_delegation_context', {}).get('scope') == 'read_only':
        writes = tool in {"fs.write", "git.push", "git.commit", "memory.write"} or (tool == "exec" and command["kind"] in {"git_write", "echo_write"})
        if writes:
            hit("block", "core.readonly", "原始任务授权为只读；候选写入或代码提交/推送超出授权范围", 100)
    for source in sources:
        if source["decision"] == "block":
            hit("block", "core.source_risk", f"引用来源 {source['id']} 已被内容准入审查阻断", source["detection"]["risk_score"])
        elif (source["decision"] == "confirm" and model_configured()
              and not source["detection"].get("semantic_complete")):
            hit("confirm", "review.source_incomplete", "来源的必要语义检查尚未完成；普通批准不能补齐检查", 55)
            gaps.extend(source["detection"].get("information_gaps", []))
        elif source["decision"] == "confirm" and not approved:
            hit("confirm", "review.source_gap", "来源存在尚需人工复核的风险或检测缺口", 50)
    if tool == "exec":
        if command["kind"] in {"dangerous", "unknown", "git_write"}:
            hit("block", "core.command", "命令包含危险行为或不属于已覆盖的有限语法；拒绝启动解释器", 100)
            gaps.append("仅解析受控 echo、Git 只读查询及 reports 下单次 echo 写入；未知 shell 语法无法证明安全")
        elif command["kind"] == "echo_write" and not approved:
            hit("confirm", "review.command_write", "命令会写入报告文件，需要绑定路径与内容的人工确认", 50)
    if tool == "net.fetch":
        if parsed_url.scheme not in {"https", "http"} or not host or parsed_url.username or parsed_url.password:
            hit("block", "core.destination", "网络目的地址格式无效或包含用户凭据", 95)
        elif host not in TRUSTED_HOSTS and not approved:
            hit("confirm", "review.destination", "目的地不在受控信任清单，需要对目的地址与发送内容确认", 55)
        elif str(args.get("method", "GET")).upper() not in {"GET", "HEAD"} and not approved:
            hit("confirm", "review.network_write", "有副作用的请求需要确认用途、收件目标及参数", 55)
    if tool == "agent.delegate":
        if not isinstance(args.get("task"), str) or not args.get("task", "").strip():
            hit("block", "core.delegate_schema", "子 Agent 派发缺少明确任务", 80)
        elif args.get("scope", session["scope"]) not in {"read_only", "development"}:
            hit("block", "core.delegate_scope", "子 Agent 请求了未知权限范围", 95)
        elif session["scope"] == "read_only" and args.get("scope", "read_only") != "read_only":
            hit("block", "core.delegate_scope", "子 Agent 权限不能超过父任务授权", 100)
        elif args.get("agent_id") and not approved:
            hit("confirm", "review.delegate_target", "派发到指定子 Agent 前需要核对接收方与任务上下文", 45)
    argument_text = json.dumps(args, ensure_ascii=False)
    argument_scan = detect(argument_text, "code", use_model=False)
    argument_hash = parameter_hash(tool, args)
    prohibition_eligible = (tool == 'agent.delegate' and args.get('scope') == 'read_only'
                           and explicit_prohibitions(argument_text, argument_scan['findings']))
    cached_prohibition = (not use_model and prohibition_eligible
                          and candidate.get('_argument_prohibition_hash') == argument_hash)
    deferred_prohibition = prohibition_eligible and use_model and model_configured() and decision != 'block'
    prohibition_review = None
    if deferred_prohibition:
        prohibition_payload = {'kind': 'content', 'source_type': 'code', 'task': session['intent'],
            'content': args['task'], 'rule_findings': detect(args['task'], 'code', use_model=False)['findings']}
        if model_redactor:
            prohibition_payload = model_redactor(prohibition_payload)
        prohibition_review, error = model_review(prohibition_payload)
        from .detection import semantic_risk
        from .excerpts import locate_excerpt
        if (error or not prohibition_review or semantic_risk(prohibition_review)
                or prohibition_review['relation'] != 'aligned' or prohibition_review['information_gaps']
                or any(i['quote'] and not locate_excerpt(prohibition_payload['content'], i['quote']) for i in prohibition_review.get('instructions', []))):
            deferred_prohibition = False
    if argument_scan["findings"] and not (cached_prohibition or deferred_prohibition):
        hit("block", "core.argument_injection", "候选参数包含覆盖安全约束或外泄/执行指令", argument_scan["risk_score"])
    if not candidate.get("plan"):
        gaps.append("未提供可观察计划；仅依据原始任务、候选参数和已记录历史研判")
    if not sources:
        gaps.append("未提交显式来源关联；不能推断调用由哪段内容诱发")
    from .semantic import alignment_batches
    alignment_coverage = {"model_attempted": False, "sources": [], "history_total": len(history),
                          "history_checked": 0, "complete": False, "batches": []}
    if not model_configured():
        gaps.append("未配置大模型语义研判；工具授权/数据流规则生效，开放语义泛化未验证")
    elif use_model and decision != "block":
        alignment_coverage["model_attempted"] = True
        complete = True
        checked_sources = {}
        # Mask complete sources before chunking: a private value may straddle a
        # window boundary and would not match a whole-value mask afterwards.
        model_sources = [{**s, "content": model_redactor(s["content"])} for s in sources] if model_redactor else sources
        for batch in alignment_batches(session, candidate, model_sources, history):
            answer, error = model_review(model_redactor(batch) if model_redactor else batch)
            alignment_coverage["batches"].append({"index": batch["related_history"]["batch_index"], "completed": bool(answer),
                "assessment": {k: answer.get(k) for k in ('risk', 'relation', 'active_redirection', 'unauthorized_operation',
                                                           'reason', 'decision_basis')} if answer else None})
            if error or not answer:
                from .detection import review_failure
                if review_failure(error):
                    alignment_coverage['provider_failure'] = review_failure(error)
                gaps.append(error or "语义审查无有效响应")
                hit("block", "core.model_unavailable", "已启用的必要语义检查未完成，故障关闭", 80)
                complete = False
                break
            alignment_coverage["history_checked"] += len(batch["related_history"]["calls"])
            for item in batch["detection_evidence"]:
                checked_sources[item["source_id"]] = item["end"]
            gaps.extend(answer["information_gaps"])
            from .detection import semantic_risk
            if semantic_risk(answer):
                hit("block", "review.model_deviation", answer["reason"], 85)
            if answer["information_gaps"] or answer["relation"] == "uncertain":
                complete = False
                hit("confirm", "review.model_gap", "语义研判仍存在信息缺口；普通批准不能补齐检查", 55)
        alignment_coverage["sources"] = [{"source_id": s["id"], "total_chars": len(s["content"]), "checked_chars": checked_sources.get(s["id"], 0)} for s in sources]
        if complete and len(alignment_coverage['batches']) > 1:
            from .semantic import correlate
            global_review = correlate(session, [{'source_id': s['id'], 'start': 0, 'end': len(s['content']), 'content': s['content']} for s in model_sources],
                lambda payload: model_review(model_redactor(payload) if model_redactor else payload),
                candidate={k: candidate.get(k) for k in ('tool', 'args', 'plan', 'resource_facts', '_delegation_context',
                                                        'agent_id', 'parent_call_id', 'mcp_server', 'data_references')},
                history=[{k: h.get(k) for k in ('id', 'tool', 'args', 'execution_status', 'agent_id', 'parent_call_id', 'mcp_server', 'result_admissions')} for h in history])
            alignment_coverage['global_review'] = global_review
            complete &= global_review['complete']
            gaps.extend(global_review['information_gaps'])
            if global_review['risk']:
                hit('block', 'review.global_deviation', '联合来源与完整调用历史发现跨轮次偏离', 85)
            elif not global_review['complete']:
                hit('confirm', 'review.global_gap', '全局关联研判未完成，不能用普通批准补齐', 55)
        alignment_coverage["complete"] = complete and all(e["checked_chars"] == e["total_chars"] for e in alignment_coverage["sources"]) and alignment_coverage["history_checked"] == len(history)
    context = {"tool": tool, "scope": session["scope"], "risk_score": risk, "path": canonical_path(path), "destination": host, "sensitive": bool(is_sensitive), "args": args}
    for rule in sorted(policy["rules"], key=lambda x: (-x["priority"], x["id"])):
        # Mandatory invariant descriptions are exposed as DSL, implementation above
        # supplies their richer predicates. They cannot be replaced by UI edits.
        if rule["mandatory"] or not rule["enabled"]:
            continue
        try:
            rule_matches = matches(rule["condition"], context)
        except ParameterEvaluationError:
            # No raw parameter values enter error text or public audit output.
            hit("block", "core.parameter_evaluation", f"策略 {rule['id']} 参数约束无法完整求值，故障关闭", 90)
            gaps.append("参数路径缺失、类型不兼容、超过限制或策略格式无效；普通批准不能忽略该约束")
            continue
        if not rule_matches:
            continue
        if rule["action"] == "confirm" and approved:
            continue
        hit(rule["action"], rule["id"], rule["description"] or rule["name"], 80 if rule["action"] == "block" else 45 if rule["action"] == "confirm" else 0)
    # A literal prohibition is only exempt from the lexical false positive
    # after the complete independent task/argument/history review succeeds.
    # Persist a server-only exact-argument binding for the atomic claim recheck.
    prohibition_proof = candidate.get('_argument_prohibition_hash') if cached_prohibition else None
    if deferred_prohibition:
        if alignment_coverage['complete'] and decision == 'allow':
            prohibition_proof = argument_hash
        else:
            hit('block', 'core.argument_injection', '禁止性措辞的完整语义核验未通过；保留阻断', argument_scan['risk_score'])
    if not reasons:
        reasons.append("候选操作满足当前可信授权、已登记来源和工具约束")
    relation = "deviating" if decision == "block" else "uncertain" if decision == "confirm" else "aligned_with_constraints"
    return {"decision": decision, "risk_score": risk, "severity": "critical" if risk >= 95 else "high" if risk >= 75 else "medium" if risk >= 40 else "low", "reasons": list(dict.fromkeys(reasons)), "matched_rules": list(dict.fromkeys(matched)), "information_gaps": list(dict.fromkeys(gaps)), "report": {"rule_actions": rule_actions, "task_relation": relation, "deviation_level": "high" if decision == "block" else "medium" if decision == "confirm" else "low", "reason": reasons[0], "resources": [x for x in [path, url, args.get("agent_id")] if x], "evidence_refs": [s["id"] for s in sources], "information_gaps": list(dict.fromkeys(gaps)), "analysis_mode": "rules+model" if model_configured() else "deterministic", "command_analysis": command, "argument_prohibition_review": prohibition_review, "alignment_coverage": alignment_coverage}, "_sensitive": bool(is_sensitive), "_argument_prohibition_hash": prohibition_proof}
