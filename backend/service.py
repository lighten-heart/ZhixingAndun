"""Application services for four modules; guards and receipts share durable state."""
import copy
import hashlib
import json
import os
import secrets
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from fastapi import HTTPException
from .detection import detect, model_configured, model_configuration_valid, normalize, redact, sensitive
from .models import CallInput, SessionInput, SourceInput
from .policy import BUILTINS, command_structure, dangerous_path, parameter_hash, review
from .storage import Store
from .evidence import EvidenceServices
from .operations import Operations
from .usage import audited

def now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def ident(prefix):
    return prefix + "_" + uuid.uuid4().hex[:16]

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()

class GuardService(EvidenceServices, Operations):
    def __init__(self, directory):
        self.store = Store(directory)
        self.store.acquire_runtime()
        self.fixtures = self.store.directory / "fixtures"
        self.fixtures.mkdir(exist_ok=True)
        with self.store.transaction():
            if not self.store.meta("policy"):
                self.store.set_meta("policy", {"version": 1, "rules": copy.deepcopy(BUILTINS)})
            # A process restart cannot know whether a trusted external adapter ran.
            for call in self.store.all("call"):
                if call.pop("_recheck_in_progress", None):
                    if call.get("_permit"):
                        call["_permit"]["revoked"] = True
                    self.store.put("call", call)
                    self.event(call["session_id"], "call.recheck_interrupted", "服务重启后释放未完成重审状态；旧许可仍撤销，需重新审查", call_id=call["id"])
                if call["execution_status"] == "executing":
                    call["execution_status"] = "unknown"
                    call["receipt"] = {"status": "unknown", "detail": "服务重启，执行回执未确认；许可已消费，禁止自动重试", "executed_at": now(), "result": None}
                    self.store.put("call", call)
        # The database owner lock is held, but no transaction spans Docker I/O.
        from .forensics import Forensics
        Forensics(self).recover_interrupted()

    def require(self, kind, identifier):
        value = self.store.get(kind, identifier)
        if not value:
            raise HTTPException(404, f"{kind} 不存在")
        return value

    def event(self, session_id, kind, summary, call_id=None, source_id=None, details=None):
        with self.store.transaction():
            event = {"id": ident("evt"), "session_id": session_id, "type": kind, "timestamp": now(), "sequence": len(self.store.all("event", session_id)) + 1, "summary": summary, "details": details or {}}
            if call_id:
                event["call_id"] = call_id
            if source_id:
                event["source_id"] = source_id
            self.store.put("event", event)
            return event

    def create_session(self, data):
        data = data.model_dump() if hasattr(data, "model_dump") else data
        with self.store.transaction():
            session = {"id": ident("ses"), **data, "created_at": now(), "status": "active", "call_count": 0, "blocked_count": 0, "authorization_version": 1}
            self.store.put("session", session)
            self.event(session["id"], "session.created", "建立原始任务与可信授权范围", details={"scope": session["scope"], "intent": session["intent"]})
        self.add_source(session["id"], {"type": "user_input", "content": session["intent"], "resource": "trusted-task-entry", "metadata": {"role": "user", "authorization_version": 1}})
        self.fixture_root(session["id"])
        return session

    def session_view(self, session):
        calls = self.store.all("call", session["id"])
        return {**session, "call_count": len(calls), "blocked_count": sum(c["decision"] == "block" for c in calls)}

    def policy(self):
        return self.store.meta("policy")

    def update_policy(self, data):
        data = data.model_dump(exclude_none=True)
        with self.store.transaction():
            current = self.policy()
            if data["version"] != current["version"]:
                raise HTTPException(409, "策略版本已变化，请重新加载后编辑")
            ids = [r["id"] for r in data["rules"]]
            if len(ids) != len(set(ids)):
                raise HTTPException(422, "策略 ID 不能重复")
            originals = {r["id"]: r for r in BUILTINS if r["mandatory"]}
            submitted = {r["id"]: r for r in data["rules"]}
            for rid, mandatory in originals.items():
                if submitted.get(rid) != mandatory:
                    raise HTTPException(422, f"强制不变量 {rid} 不能移除或修改")
            if any(r["mandatory"] and r["id"] not in originals for r in data["rules"]):
                raise HTTPException(422, "自定义规则不能冒充内置强制不变量")
            saved = {"version": current["version"] + 1, "rules": data["rules"]}
            self.store.set_meta("policy", saved)
            for call in self.store.all("call"):
                if call.get("_permit") and not call["_permit"]["used"]:
                    call["_permit"]["revoked"] = True
                    self.store.put("call", call)
            return saved

    @audited()
    def add_source(self, session_id, data, internal_parent=False, _delegation=None):
        data = data.model_dump() if hasattr(data, "model_dump") else data
        session_snapshot = self.require("session", session_id)
        source_snapshot = self.store.all('source', session_id)
        # Only the private, claim-verified entry point can supply this context.
        # A source's metadata or a claimed role never changes review authority.
        if _delegation:
            # Exact bytes were already independently reviewed as the parent's
            # candidate arguments. Reuse that decision only after claim proof;
            # do not invent another model request or widen session authority.
            detection = {'status': 'clear', 'risk_score': 0, 'findings': [], 'quoted_findings': [],
                'instructions': [], 'information_gaps': [], 'mode': 'verified_delegation_reuse',
                'semantic_complete': True, 'coverage': {'checked_chars': 0, 'total_chars': len(data['content']),
                    'model_checked_chars': 0, 'batches': [], 'overlap_chars': 0,
                    'delegation_review_reuse': {'call_id': _delegation['id'],
                        'parameter_hash': _delegation['parameter_hash'],
                        'authorization_version': session_snapshot['authorization_version'],
                        'grants_tool_authority': False, 'new_model_inference': False}}}
        else:
            detection = detect(data["content"], data["type"], session_snapshot['intent'], model_redactor=self.public_view)
        if model_configured() and detection.get('semantic_complete') and detection['risk_score'] < 80:
            from .semantic import correlate
            from .detection import model_review
            prior = [s for s in source_snapshot if s['decision'] == 'allow' and s['type'] not in {'user_input', 'mcp_description'}]
            if prior and data['type'] not in {'user_input', 'mcp_description'}:
                units = [{'source_id': s['id'], 'start': 0, 'end': len(s['content']), 'content': self.public_view(s['content'])} for s in prior]
                units.append({'source_id': 'current', 'start': 0, 'end': len(data['content']), 'content': self.public_view(data['content'])})
                joint = correlate(session_snapshot, units, model_review)
                detection['coverage']['session_correlation'] = joint
                detection['semantic_complete'] &= joint['complete']
                detection['information_gaps'].extend(joint['information_gaps'])
                if joint['risk']:
                    detection['risk_score'] = max(80, detection['risk_score'])
                    detection['status'] = 'risk'
                    for f in joint['findings']:
                        current = next((s for s in f['linked_spans'] if s['source_id'] == 'current'), {'start': 0, 'end': 0})
                        detection['findings'].append({**f, 'category': 'cross_source_semantic', 'start': current['start'], 'end': current['end'],
                            'quote': data['content'][current['start']:current['end']], 'mapping': 'joint_exact_evidence'})
        with self.store.transaction():
            session = self.require("session", session_id)
            if _delegation and self.require('call', _delegation['id']) != _delegation:
                raise HTTPException(409, 'Delegation changed while reviewing its input')
            if session != session_snapshot or self.store.all('source', session_id) != source_snapshot:
                raise HTTPException(409, "来源扫描期间任务授权发生变化，请重试")
            parent_id = data.get("parent_source_id")
            if parent_id:
                parent = self.require("source", parent_id)
                if parent["session_id"] != session_id and not internal_parent:
                    raise HTTPException(422, "跨会话来源只允许通过已核验的记忆读取关系建立")
            metadata = data.get("metadata", {})
            if len(json.dumps(metadata, ensure_ascii=False)) > 10000:
                raise HTTPException(422, "metadata 过大")
            call_id = metadata.get("call_id")
            if call_id:
                call = self.require("call", call_id)
                if call["session_id"] != session_id:
                    raise HTTPException(422, "来源关联调用不属于本会话")
            recent = self.store.all("source", session_id)[-5:]
            recent = [s for s in recent if len(s["content"]) <= 12000]
            if recent:
                prefix = "\n".join(s["content"] for s in recent) + "\n"
                combined = detect(prefix + data["content"], data["type"], use_model=False)
                for finding in combined["findings"]:
                    if finding["start"] < len(prefix) < finding["end"]:
                        local_end = min(len(data["content"]), finding["end"] - len(prefix))
                        if local_end > 0:
                            spans, offset = [], 0
                            for previous in recent:
                                low, high = max(0, finding["start"] - offset), min(len(previous["content"]), finding["end"] - offset)
                                if low < high:
                                    spans.append({"source_id": previous["id"], "start": low, "end": high})
                                offset += len(previous["content"]) + 1
                            detection["findings"].append({**finding, "start": 0, "end": local_end, "quote": data["content"][:local_end], "mapping": "cross_source_aggregation", "reason": "跨片段聚合发现完整行为要求：" + finding["reason"], "related_source_ids": [s["source_id"] for s in spans], "linked_spans": spans})
                            detection["risk_score"] = max(detection["risk_score"], combined["risk_score"])
                            detection["status"] = "risk"
                            detection["information_gaps"].append("跨来源组合是同会话序列聚合证据，不宣称模型内部采用了该组合")
            score = detection["risk_score"]
            decision = "block" if score >= 80 else "confirm" if score >= 40 else "allow"
            if model_configured() and detection["mode"] == "deterministic":
                decision = "block"
            elif model_configured() and not detection.get("semantic_complete") and decision == "allow":
                decision = "confirm"
            if parent_id and parent["decision"] == "block":
                decision = "block"
                detection["risk_score"] = max(detection["risk_score"], parent["detection"]["risk_score"])
                detection["information_gaps"].append("派生自已阻断来源，未提供可信净化证明；保守继承阻断")
            record = {"id": ident("src"), "session_id": session_id, "type": data["type"], "resource": data.get("resource", ""), "content": data["content"], "normalized": normalize(data["content"])[0], "version": 1, "created_at": now(), "parent_source_id": parent_id, "decision": decision, "detection": detection, "sensitive": sensitive(data["content"]), "metadata": metadata, "offset_unit": "unicode_codepoint", "_content_hash": digest(data["content"])}
            if parent_id and self.require("source", parent_id).get("sensitive"):
                record["sensitive"] = True
                record["sensitivity_basis"] = "conservative_parent_inheritance"
            for finding in detection['findings']:
                for span in finding.get('linked_spans', []):
                    if span.get('source_id') == 'current':
                        span['source_id'] = record['id']
            self.store.put("source", record)
            self.event(session_id, "source.reviewed", "来源完成归一化和风险扫描", source_id=record["id"], details={"decision": decision, "risk_score": detection["risk_score"], "source_type": data["type"]})
            return record

    def add_delegated_source(self, session_id, data):
        """Admit the exact already-claimed subtask, without granting child tools."""
        from .detection import original_task_proposal
        data = data.model_dump() if hasattr(data, 'model_dump') else data
        with self.store.transaction():
            call = self.require('call', data['call_id'])
            session = self.require('session', session_id)
            if (call['session_id'] != session_id or call['tool'] != 'agent.delegate'
                    or call.get('_execution_mode') != 'adapter' or call['execution_status'] != 'executing'
                    or call['decision'] != 'allow' or not call.get('_permit', {}).get('used')
                    or not call.get('report', {}).get('alignment_coverage', {}).get('complete')
                    or call.get('_permit', {}).get('revoked')
                    or call.get('_claim_authorization_version') != session['authorization_version']
                    or call['policy_version'] != self.policy()['version']
                    or not secrets.compare_digest(call.get('_claim_id', ''), data['claim_id'])):
                raise HTTPException(403, 'Delegated input requires a current consumed adapter claim')
            if (call['args'].get('scope') != 'read_only'
                    or not original_task_proposal(data['content'], 'user_input', call['args']['task'])
                    or call['parameter_hash'] != parameter_hash(call['tool'], call['args'])
                    or data['agent_id'] == call['agent_id']
                    or call.get('_delegated_agent_id', data['agent_id']) != data['agent_id']):
                raise HTTPException(422, 'Delegated input does not match the exact child task')
            call['_delegated_agent_id'] = data['agent_id']
            self.store.put('call', call)
        return self.add_source(session_id, {
            'type': 'user_input', 'content': data['content'],
            'resource': f"harness://{data['agent_id']}/delegated-input",
            'metadata': {'call_id': call['id'], 'harness_agent_id': data['agent_id'],
                         'verified_delegation': True, 'grants_tool_authority': False}}, _delegation=call)

    def context_binding(self, session_id, call):
        session = self.require("session", session_id)
        return digest({"session": session["id"], "scope": session["scope"], "authorization_version": session["authorization_version"], "agent": call["agent_id"], "parent": call.get("parent_call_id"), "mcp_server": call.get("mcp_server"), "resource_facts": call.get("resource_facts", {}), "sources": [{"id": s["id"], "version": s["version"], "decision": s["decision"], "content": s["_content_hash"], "sensitive": s["sensitive"]} for s in self.store.all("source", session_id)], "executed_history": [{"id": c["id"], "status": c["execution_status"], "hash": c["parameter_hash"], "sensitive": c.get("_sensitive_result", False)} for c in self.store.all("call", session_id) if c["id"] != call.get("id") and c["execution_status"] in {"succeeded", "unknown", "executing"}], "context_admissions": self.store.all("context_admission", session_id), "data_registry": self.store.all("data"), "auth": digest(os.getenv("GUARD_API_TOKEN", "")), "model": {"backend": os.getenv("GUARD_MODEL_BACKEND", ""), "url": os.getenv("GUARD_MODEL_BASE_URL", ""), "name": os.getenv("GUARD_MODEL_NAME", "")}})

    def grant(self, call):
        token = secrets.token_urlsafe(32)
        expires_at = time.time() + 300
        call["_permit"] = {"token": token, "parameter_hash": call["parameter_hash"], "context": self.context_binding(call["session_id"], call), "policy_version": self.policy()["version"], "expires_at": expires_at, "used": False, "revoked": False}
        call["permit_expires_at"] = datetime.fromtimestamp(expires_at, timezone.utc).isoformat().replace("+00:00", "Z")
        return token

    def with_permit(self, call):
        public = self.public_view(call)
        if call.get("_permit") and not call["_permit"]["used"] and not call["_permit"].get("revoked"):
            public["permit"] = call["_permit"]["token"]
        return public

    @audited()
    def review_call(self, session_id, data):
        start = time.perf_counter()
        data = data.model_dump() if hasattr(data, "model_dump") else CallInput(**data).model_dump()
        if len(json.dumps(data["args"], ensure_ascii=False)) > 200000:
            raise HTTPException(422, "工具参数超过 200000 字符上限")
        if "dry_run" in data["args"] and not isinstance(data["args"]["dry_run"], bool):
            raise HTTPException(422, "dry_run 必须是布尔值")
        with self.store.lock:
            session = self.require("session", session_id)
            if data.get("parent_call_id"):
                parent = self.require("call", data["parent_call_id"])
                if parent["session_id"] != session_id:
                    raise HTTPException(422, "父调用不属于当前会话")
                if parent.get('_delegated_agent_id'):
                    if (parent['_delegated_agent_id'] != data['agent_id']
                            or parent['execution_status'] != 'executing'
                            or parent.get('_claim_authorization_version') != session['authorization_version']
                            or parent['policy_version'] != self.policy()['version']):
                        raise HTTPException(403, 'Child operation has no current bound delegation')
                    data['_delegation_context'] = {
                        'agent_id': data['agent_id'], 'parent_agent_id': parent['agent_id'],
                        'parent_call_id': parent['id'], 'task': parent['args']['task'],
                        'scope': 'read_only', 'authority': 'server_verified_active_claim_and_exact_child_input',
                        'authorization_version': session['authorization_version']}
            sources = [self.require("source", sid) for sid in data["source_ids"]]
            if any(s["session_id"] != session_id for s in sources):
                raise HTTPException(422, "来源不属于当前会话，请先通过记忆读取入口引入")
            policy = self.policy()
            history = self.review_history(session_id)
            observed_sources = self.store.all("source", session_id)
            context_snapshot = self.context_binding(session_id, data)
        data["_data_flow_errors"] = self.data_flow_errors(session_id, data)
        from .forensics import script_precheck
        data["_script_precheck"] = script_precheck(self, session_id, data)
        verdict = review(session, data, sources, history, policy, observed_sources=observed_sources, model_redactor=self.public_view)
        with self.store.transaction():
            if context_snapshot != self.context_binding(session_id, data) or policy["version"] != self.policy()["version"]:
                raise HTTPException(409, "审查期间来源、执行历史、授权或策略发生变化，请重新审查")
            call = {"id": ident("call"), "session_id": session_id, **data, **verdict, "created_at": now(), "execution_status": "pending" if verdict["decision"] == "confirm" else "not_executed", "latency_ms": round((time.perf_counter() - start) * 1000, 3), "policy_version": policy["version"], "parameter_hash": parameter_hash(data["tool"], data["args"]), "_approved": False}
            call["report"].update({"review_object_id": call["id"], "task_id": session_id})
            call["_review_context"] = self.context_binding(session_id, call)
            if call["decision"] == "allow":
                self.grant(call)
            self.store.put("call", call)
            self.event(session_id, "call.reviewed", "执行前研判与策略决策", call_id=call["id"], details={"decision": call["decision"], "tool": call["tool"], "matched_rules": call["matched_rules"], "parameter_hash": call["parameter_hash"], "policy_version": policy["version"]})
            return call

    @audited('call')
    def approve(self, call_id, approved, comment="", actor="local-operator"):
        with self.store.lock:
            call = self.require("call", call_id)
            if call.get("_superseded_by") or call.get("_recheck_in_progress"):
                raise HTTPException(409, "此调用正在重新审查或已被新调用替代，请使用新记录")
            if call["decision"] != "confirm" or call["execution_status"] != "pending":
                raise HTTPException(409, "此调用不处于待确认状态；强制阻断不能用确认覆盖")
            if call.get("control_receipt"):
                raise HTTPException(409, "适配器已结束本次执行尝试；请重新审查后使用新调用")
            call_snapshot = digest(call)
            context_snapshot = self.context_binding(call["session_id"], call)
            policy_snapshot = self.policy()
            session = self.require("session", call["session_id"])
            sources = [self.require("source", sid) for sid in call["source_ids"]]
            history = self.review_history(call["session_id"])
            observed_sources = self.store.all("source", call["session_id"])
        call["_data_flow_errors"] = self.data_flow_errors(call["session_id"], call)
        from .forensics import script_precheck
        call["_script_precheck"] = script_precheck(self, call["session_id"], call)
        verdict = review(session, call, sources, history, policy_snapshot, approved=True, observed_sources=observed_sources, model_redactor=self.public_view) if approved else None
        with self.store.transaction():
            current = self.require("call", call_id)
            if call_snapshot != digest(current) or context_snapshot != self.context_binding(call["session_id"], call) or policy_snapshot["version"] != self.policy()["version"]:
                raise HTTPException(409, "审批期间调用、授权、来源或策略发生变化，请重新加载后复核")
            if not approved:
                call.update({"decision": "block", "execution_status": "not_executed", "reasons": ["用户拒绝此次操作"], "_approved": False})
            else:
                call.update(verdict)
                call.update({"execution_status": "not_executed" if verdict["decision"] != "confirm" else "pending", "policy_version": self.policy()["version"], "_approved": True})
                call["report"].update({"review_object_id": call_id, "task_id": call["session_id"]})
                if call["decision"] == "allow":
                    self.grant(call)
            call["approval"] = {"approved": approved, "comment": comment, "actor": actor, "at": now(), "policy_version": self.policy()["version"]}
            self.store.put("call", call)
            self.event(call["session_id"], "approval.reviewed", "人工答复已记录并重新执行策略检查", call_id=call_id, details={"approved": approved, "decision": call["decision"], "comment": comment})
            return call

    def recheck(self, call_id):
        """Create one fresh review from durable raw arguments, never replay effects."""
        marker = secrets.token_urlsafe(24)
        with self.store.transaction():
            original = self.require("call", call_id)
            if original["execution_status"] not in {"not_executed", "pending"}:
                raise HTTPException(409, "已经开始执行或存在回执的调用不能自动重新审查，以免重复副作用")
            if original.get("_superseded_by") or original.get("_recheck_in_progress"):
                raise HTTPException(409, "此调用正在重新审查或已被新调用替代")
            original["_recheck_in_progress"] = marker
            if original.get("_permit"):
                original["_permit"]["revoked"] = True
            self.store.put("call", original)
            # Only typed candidate fields are copied. Approval and permit are new.
            candidate = CallInput(**{key: copy.deepcopy(original[key]) for key in CallInput.model_fields if key in original}).model_dump()
        try:
            replacement = self.review_call(original["session_id"], candidate)
            with self.store.transaction():
                old = self.require("call", call_id)
                if old.get("_recheck_in_progress") != marker:
                    raise HTTPException(409, "重新审查状态发生冲突")
                old.pop("_recheck_in_progress", None)
                old["_superseded_by"] = replacement["id"]
                old["superseded_by"] = replacement["id"]
                replacement["recheck_of_call_id"] = call_id
                self.store.put("call", old)
                self.store.put("call", replacement)
                self.event(old["session_id"], "call.rechecked", "使用原始参数完成独立重审，旧许可已撤销；不继承人工确认", call_id=replacement["id"], details={"original_call_id": call_id, "replacement_call_id": replacement["id"], "parameter_hash": replacement["parameter_hash"]})
                return replacement
        except Exception:
            with self.store.transaction():
                old = self.require("call", call_id)
                if old.get("_recheck_in_progress") == marker:
                    old.pop("_recheck_in_progress", None)
                    self.store.put("call", old)
            raise

    def claim(self, call_id, supplied_permit=None, supplied_hash=None, execution_mode="adapter"):
        with self.store.transaction():
            if execution_mode == "adapter" and not supplied_permit:
                raise HTTPException(403, "外部适配器必须显式提供执行许可")
            call = self.require("call", call_id)
            if call.get("_superseded_by") or call.get("_recheck_in_progress"):
                raise HTTPException(409, "旧调用已进入重新审查流程，不能继续消费许可")
            permit = call.get("_permit")
            if call["decision"] != "allow" or call["execution_status"] != "not_executed" or not permit:
                raise HTTPException(409, "操作未获有效放行或已经执行，无法消费许可")
            if supplied_permit is not None and not secrets.compare_digest(supplied_permit, permit["token"]):
                raise HTTPException(403, "执行许可不匹配")
            expected_hash = parameter_hash(call["tool"], call["args"])
            if supplied_hash is not None and supplied_hash != expected_hash:
                raise HTTPException(409, "调用参数哈希不匹配，需重新审查")
            if permit["used"] or permit.get("revoked") or permit["expires_at"] < time.time() or permit["parameter_hash"] != expected_hash or permit["policy_version"] != self.policy()["version"] or permit["context"] != self.context_binding(call["session_id"], call):
                raise HTTPException(409, "许可已过期、被消费或授权/来源/策略发生变化，需重新审查")
            session = self.require("session", call["session_id"])
            sources = [self.require("source", sid) for sid in call["source_ids"]]
            verdict = review(session, call, sources, self.store.all("call", call["session_id"]), self.policy(), approved=call.get("_approved", False), use_model=False, observed_sources=self.store.all("source", call["session_id"]))
            if verdict["decision"] != "allow":
                raise HTTPException(409, "执行前复核不再满足许可条件，需重新审查")
            permit["used"] = True
            call["_claim_id"] = secrets.token_urlsafe(24)
            call["_execution_mode"] = execution_mode
            call["_claim_authorization_version"] = session['authorization_version']
            call["execution_status"] = "executing"
            self.store.put("call", call)
            self.event(call["session_id"], "execution.claimed", "一次性许可已绑定参数并消费", call_id=call_id, details={"mode": execution_mode, "parameter_hash": expected_hash})
            return {"claim_id": call["_claim_id"], "call": call}

    def receipt(self, call_id, claim_id, status, detail, result):
        if len(json.dumps(result, ensure_ascii=False)) > 200000:
            raise HTTPException(422, "回执结果超过 200000 字符上限")
        with self.store.transaction():
            call = self.require("call", call_id)
            if not call.get("_claim_id") or not secrets.compare_digest(call["_claim_id"], claim_id):
                raise HTTPException(403, "回执未绑定有效执行 claim")
            fingerprint = digest({"status": status, "detail": detail, "result": result})
            if call.get("_receipt_fingerprint"):
                if call["_receipt_fingerprint"] == fingerprint:
                    return call
                raise HTTPException(409, "执行回执已经写入，拒绝冲突覆盖")
            if call["execution_status"] not in {"executing", "unknown"}:
                raise HTTPException(409, "调用状态不接受执行回执")
            call["_receipt_fingerprint"] = fingerprint
            call["execution_status"] = status
            call["_sensitive_result"] = sensitive(result)
            call["receipt"] = {"status": status, "detail": detail, "result": result, "executed_at": now(), "evidence_type": "isolated_fixture_observed" if call.get("_execution_mode") == "fixture" else "trusted_adapter_reported"}
            self.store.put("call", call)
            self.event(call["session_id"], "execution.receipt", "记录实际执行回执", call_id=call_id, details={"status": status, "evidence_type": call["receipt"]["evidence_type"], "detail": detail})
            return call

    def fixture_root(self, session_id):
        # IDs are generated by the service and caller sessions are required first.
        root = (self.fixtures / session_id).resolve()
        if not root.is_relative_to(self.fixtures.resolve()):
            raise HTTPException(422, "非法 fixture 目录")
        root.mkdir(exist_ok=True)
        if not (root / "README.md").exists():
            (root / "README.md").write_text("# AegisGuard fixture\n这是隔离演示项目。安装依赖后启动前后端，以安全审查入口执行工具。\n", encoding="utf-8")
        (root / "reports").mkdir(exist_ok=True)
        return root

    def safe_fixture_path(self, root, relative):
        if dangerous_path(relative):
            raise ValueError("fixture 路径不合法")
        target = (root / relative).resolve()
        if not target.is_relative_to(root.resolve()):
            raise ValueError("fixture 路径越界")
        # Reject existing symlinks on every component, including Windows junctions.
        current = root
        for part in Path(relative).parts:
            current = current / part
            if current.is_symlink() or (hasattr(current, "is_junction") and current.is_junction()):
                raise ValueError("fixture 不允许符号链接或目录联接")
        return target

    def fixture_effects(self, session_id):
        root = self.fixture_root(session_id)
        return {str(p.relative_to(root)).replace("\\", "/"): hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob("*") if p.is_file() and not p.is_symlink()}

    def execute_fixture(self, call_id, permit=None):
        if self.require("call", call_id).get("execution_owner") == "adapter":
            raise HTTPException(409, "此调用由真实宿主负责执行，不能改由演示执行器代执行")
        claimed = self.claim(call_id, permit, execution_mode="fixture")
        call = claimed["call"]
        try:
            result = self.run_fixture(call)
            return self.receipt(call_id, claimed["claim_id"], "succeeded", "已执行隔离 fixture 行为；网络、Git 推送与子 Agent 均为本地受控替身", result)
        except Exception as exc:
            return self.receipt(call_id, claimed["claim_id"], "failed", f"隔离 fixture 执行失败：{type(exc).__name__}: {str(exc)[:300]}", None)

    def run_fixture(self, call):
        root = self.fixture_root(call["session_id"])
        tool, args = call["tool"], call["args"]
        if tool == "fs.read":
            target = self.safe_fixture_path(root, args["path"])
            return {"content": target.read_text(encoding="utf-8"), "fixture": True, "path": args["path"]}
        if tool == "fs.write":
            target = self.safe_fixture_path(root, args["path"])
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(args["content"], encoding="utf-8")
            return {"fixture": True, "path": args["path"], "bytes_written": target.stat().st_size, "sha256": hashlib.sha256(target.read_bytes()).hexdigest()}
        if tool == "exec":
            structure = command_structure(args["command"])
            if structure["kind"] == "echo":
                return {"stdout": structure["text"] + "\n", "fixture": True, "shell_started": False}
            if structure["kind"] == "git_read":
                return {"stdout": "fixture repository: no external Git process launched", "fixture": True, "shell_started": False}
            if structure["kind"] == "echo_write":
                target = self.safe_fixture_path(root, structure["path"])
                target.write_text(structure["text"] + "\n", encoding="utf-8")
                return {"path": structure["path"], "bytes_written": target.stat().st_size, "fixture": True, "shell_started": False}
            raise ValueError("命令不在 fixture 有限语法中")
        if tool == "net.fetch":
            method = str(args.get("method", "GET")).upper()
            if method not in {"GET", "HEAD"}:
                self.append_fixture(root, "outbox.jsonl", {"call_id": call["id"], "url": args["url"], "method": method, "body": args.get("body"), "at": now()})
            return {"fixture": True, "network_sent": False, "url": args["url"], "content": "AegisGuard 本地文档 fixture：工具调用须经过来源审查及执行许可。", "local_outbox_recorded": method not in {"GET", "HEAD"}}
        if tool in {"git.push", "git.commit"}:
            dry_run = args.get("dry_run", False)
            if not dry_run:
                self.append_fixture(root, "git-ledger.jsonl", {"call_id": call["id"], "operation": tool, "args": args, "at": now()})
            return {"fixture": True, "external_git_executed": False, "local_ledger_recorded": not dry_run, "dry_run": dry_run}
        if tool == "agent.delegate":
            child = ident("agent")
            self.append_fixture(root, "delegations.jsonl", {"call_id": call["id"], "child_agent_id": child, "task": args["task"], "scope": args.get("scope", self.require("session", call["session_id"])["scope"])})
            return {"fixture": True, "child_agent_id": child, "external_agent_started": False, "task_recorded": True}
        raise ValueError("未知工具")

    @staticmethod
    def append_fixture(root, name, record):
        target = root / name
        if target.is_symlink():
            raise ValueError("fixture 台账不能是符号链接")
        with target.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    def create_memory(self, data):
        data = data.model_dump() if hasattr(data, "model_dump") else data
        self.require("session", data["session_id"])
        source = self.add_source(data["session_id"], {"type": "memory", "content": data["content"], "resource": "memory-write-candidate"})
        with self.store.transaction():
            memory = {"id": ident("mem"), "label": data.get("label", "新记忆"), "content": data["content"], "version": 1, "status": "active" if source["decision"] == "allow" else "quarantined", "source_session_id": data["session_id"], "source_id": source["id"], "created_at": now(), "detection": source["detection"]}
            self.store.put("memory", memory)
            self.event(data["session_id"], "memory.stored", "记忆写入审查完成", source_id=source["id"], details={"memory_id": memory["id"], "status": memory["status"], "version": 1})
            return memory

    @audited('memory')
    def scan_memory(self, memory_id):
        memory_snapshot = self.require("memory", memory_id)
        session = self.require("session", memory_snapshot["source_session_id"])
        detection = detect(memory_snapshot["content"], "memory", session["intent"], model_redactor=self.public_view)
        with self.store.transaction():
            memory = self.require("memory", memory_id)
            if memory != memory_snapshot or self.require("session", session["id"]) != session:
                raise HTTPException(409, "扫描期间记忆版本变化，请重试")
            self.store.put("memory_revision", {"id": ident("mrev"), "memory_id": memory_id,
                "session_id": session["id"], "snapshot": copy.deepcopy(memory), "actor": "guard-scanner",
                "action": "scan", "reason": "存量记忆复检", "created_at": now()})
            memory.update({"detection": detection, "version": memory["version"] + 1, "last_scanned_at": now()})
            if detection["risk_score"] >= 40 or (model_configured() and not detection.get("semantic_complete")):
                memory["status"] = "quarantined"
            # Rescanning cannot silently restore a quarantined record.
            self.store.put("memory", memory)
            for linked in self.store.all("source"):
                if linked.get("metadata", {}).get("memory_id") == memory_id:
                    linked["version"] += 1
                    linked["decision"] = "block"
                    linked["detection"]["information_gaps"].append("关联记忆已产生新版本，先前准入撤销；须重新读取")
                    self.store.put("source", linked)
            self.event(memory["source_session_id"], "memory.scanned", "存量记忆扫描并保留隔离状态", source_id=memory.get("source_id"), details={"memory_id": memory_id, "version": memory["version"], "status": memory["status"]})
            return memory

    def read_memory(self, session_id, memory_id):
        self.require("session", session_id)
        memory_snapshot = self.require("memory", memory_id)
        source = self.add_source(session_id, {"type": "memory", "content": memory_snapshot["content"], "resource": "memory://" + memory_id, "parent_source_id": memory_snapshot.get("source_id"), "metadata": {"memory_id": memory_id, "memory_version": memory_snapshot["version"], "source_session_id": memory_snapshot["source_session_id"]}}, internal_parent=True)
        with self.store.transaction():
            memory = self.require("memory", memory_id)
            if memory != memory_snapshot:
                source["decision"] = "block"
                source["detection"]["information_gaps"].append("读取扫描期间记忆版本发生变化，需重新读取")
                self.store.put("source", source)
            if memory["status"] == "quarantined":
                source["decision"] = "block"
                source["detection"]["information_gaps"].append("此记忆处于隔离区，禁止进入业务模型上下文")
                self.store.put("source", source)
            self.event(session_id, "memory.read_reviewed", "跨会话记忆在引入上下文前完成复核", source_id=source["id"], details={"memory_id": memory_id, "decision": source["decision"], "origin_session_id": memory["source_session_id"]})
            return source

    def graph(self, session_id):
        session = self.require("session", session_id)
        sources, calls = self.store.all("source", session_id), self.store.all("call", session_id)
        nodes = {session_id: {"id": session_id, "label": session["title"], "type": "session", "status": "active", "detail": session["intent"]}}
        edges = []
        for source in sources:
            nodes[source["id"]] = {"id": source["id"], "label": source["type"], "type": "source", "status": source["decision"], "detail": source["resource"]}
            edges.append({"source": session_id, "target": source["id"], "label": "会话接入", "type": "membership"})
            cited = {span['source_id'] for finding in source['detection']['findings'] for span in finding.get('linked_spans', [])}
            for cited_id in cited - {source['id'], 'current'}:
                if any(s['id'] == cited_id for s in sources):
                    edges.append({'source': cited_id, 'target': source['id'], 'label': '联合研判引用（非生成因果）', 'type': 'context'})
            if source.get("parent_source_id"):
                parent = self.require("source", source["parent_source_id"])
                nodes[parent["id"]] = {"id": parent["id"], "label": parent["type"] + (" · 上一会话" if parent["session_id"] != session_id else ""), "type": "source", "status": parent["decision"], "detail": parent["resource"]}
                edges.append({"source": parent["id"], "target": source["id"], "label": "记忆版本引用" if source.get("metadata", {}).get("memory_id") else "来源关联（未核验变换）", "type": "provenance" if source.get("metadata", {}).get("memory_id") else "context"})
            if source.get("metadata", {}).get("call_id"):
                edges.append({"source": source["metadata"]["call_id"], "target": source["id"], "label": "结果来源", "type": "result"})
        for call in calls:
            nodes[call["id"]] = {"id": call["id"], "label": call["tool"], "type": "call", "status": call["decision"], "detail": call["reasons"][0]}
            edges.append({"source": session_id, "target": call["id"], "label": "候选调用", "type": "membership"})
            # Identity snapshots are per call so repeated identities cannot form cycles.
            agent_node = "agent:" + call["id"]
            nodes[agent_node] = {"id": agent_node, "label": call["agent_id"], "type": "agent", "detail": "本次候选调用登记的 Agent 身份；属于上下文关系，不推断模型内部因果"}
            edges.append({"source": session_id, "target": agent_node, "label": "登记身份快照", "type": "context"})
            edges.append({"source": agent_node, "target": call["id"], "label": "候选调用所属 Agent", "type": "context"})
            if call.get("mcp_server"):
                mcp_node = "mcp:" + call["id"]
                nodes[mcp_node] = {"id": mcp_node, "label": call["mcp_server"], "type": "mcp", "status": call["decision"], "detail": "审查请求登记的候选服务目标；该节点不表示调用已经转发或远端已经执行"}
                edges.append({"source": call["id"], "target": mcp_node, "label": "候选接收目标", "type": "target"})
            for sid in call["source_ids"]:
                edges.append({"source": sid, "target": call["id"], "label": "显式上下文引用", "type": "context"})
            if call.get("parent_call_id"):
                edges.append({"source": call["parent_call_id"], "target": call["id"], "label": "已登记父子调用", "type": "parent_call"})
            if call.get("receipt"):
                rid = call["id"] + ":receipt"
                nodes[rid] = {"id": rid, "label": "执行回执", "type": "receipt", "status": call["execution_status"], "detail": call["receipt"]["detail"]}
                edges.append({"source": call["id"], "target": rid, "label": call["receipt"]["evidence_type"] if "evidence_type" in call["receipt"] else "回执未知", "type": "receipt"})
                result = call["receipt"].get("result")
                child_id = result.get("child_agent_id") if isinstance(result, dict) else None
                if call["tool"] == "agent.delegate" and call["execution_status"] == "succeeded" and isinstance(child_id, str) and child_id:
                    child_node = "child:" + call["id"]
                    fixture = call["receipt"].get("evidence_type") == "isolated_fixture_observed"
                    nodes[child_node] = {"id": child_node, "label": child_id, "type": "child_agent", "status": "recorded", "detail": "本地受控任务台账登记；未启动外部子 Agent" if fixture else "可信适配器回执所报子 Agent 身份；后台未独立核验是否真正启动"}
                    edges.append({"source": rid, "target": child_node, "label": "回执登记的子任务身份", "type": "context"})
        for item in self.store.all("data", session_id):
            nodes[item["id"]] = {"id": item["id"], "label": item["label"], "type": "data", "status": item["sensitivity"], "detail": "用途：" + ", ".join(item["allowed_purposes"]) + "；接收方：" + ", ".join(item["allowed_recipients"])}
            edges.append({"source": item["source_id"], "target": item["id"], "label": "可信标签登记", "type": "data_label"})
            for span in (item.get("derivation") or {}).get("spans", []):
                edges.append({"source": span["data_id"], "target": item["id"], "label": "已核验 " + item["derivation"]["operation"], "type": "verified_derivation"})
        return {"nodes": list(nodes.values()), "edges": edges}

    def detail(self, session_id):
        return {**self.session_view(self.require("session", session_id)), "sources": self.store.all("source", session_id), "calls": self.store.all("call", session_id), "events": self.store.all("event", session_id), "external_events": self.external_events(session_id), "data_records": [self.public_data(d) for d in self.store.all("data", session_id)], "authorization_history": self.store.all("authorization", session_id), "memory_revisions": self.store.all("memory_revision", session_id), "knowledge_documents": [{k: v for k, v in d.items() if k != "segments"} for d in self.store.all("knowledge", session_id)], "graph": self.graph(session_id)}

    def dashboard(self):
        sessions, calls, sources = self.store.all("session"), self.store.all("call"), self.store.all("source")
        trends, distribution = {}, {}
        for call in calls:
            date = call["created_at"][:10]
            trends.setdefault(date, {"date": date, "allow": 0, "confirm": 0, "block": 0})[call["decision"]] += 1
        for source in sources:
            distribution[source["type"]] = distribution.get(source["type"], 0) + 1
        return {"stats": {"sessions": len(sessions), "calls": len(calls), "blocked": sum(c["decision"] == "block" for c in calls), "pending": sum(c["execution_status"] == "pending" and not c.get("_superseded_by") and not c.get("_recheck_in_progress") for c in calls), "allowed": sum(c["decision"] == "allow" for c in calls), "avg_latency_ms": round(sum(c["latency_ms"] for c in calls) / len(calls), 2) if calls else 0}, "trend": [trends[k] for k in sorted(trends)[-14:]], "source_distribution": [{"name": k, "value": v} for k, v in distribution.items()], "recent_alerts": [c for c in calls if c["decision"] != "allow"][:8], "components": [{"name": "来源预处理", "status": "healthy", "detail": "10 类结构化来源、Unicode 规范化与原文字符映射"}, {"name": "风险检测与语义研判", "status": ("configured" if model_configuration_valid() else "error") if model_configured() else "limited", "detail": ("规则 + 已配置模型，调用可用性以具体请求为准" if model_configuration_valid() else "模型配置不完整，必要语义检查故障关闭") if model_configured() else "确定性规则工作中；语义模型未配置"}, {"name": "策略与执行控制", "status": "healthy", "detail": "三态决策、审批复核、单次许可与受控工具执行"}, {"name": "证据溯源", "status": "healthy", "detail": "SQLite 持久化、显式引用与上下文关系、脱敏导出"}, {"name": "Hermes 宿主接入", "status": "not_connected", "detail": "固定版本适配器已核验；真实 Hermes 与模型联调尚未完成"}, {"name": "动态沙箱", "status": "unavailable", "detail": "本地受控工具可用；Docker 动态取证未启用"}]}
