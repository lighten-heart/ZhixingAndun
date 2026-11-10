"""Read-only presentation of saved campaign summaries; never rerun or rescore them."""
from collections import Counter
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import re

from .detection import redact


MAX_FILE_BYTES = 4 * 1024 * 1024
COUNT_FIELDS = (
    "cases", "attacks", "benign", "tp", "fn", "fp", "tn", "confirmed_tp",
    "strict_passed", "available", "unavailable", "complete", "incomplete",
)
RATE_FIELDS = (
    "confirmed_recall", "withhold_recall", "fpr", "operational_accuracy",
    "operational_precision", "operational_f1", "strict_pass_rate",
)
USAGE_FIELDS = (
    "attempts", "failed_attempts", "pending_attempts", "missing_usage_attempts",
    "missing_price_attempts", "known_tokens",
)
RECOVERY_FIELDS = (
    "total", "passed", "reports_completed", "reports_expected",
    "reports_all_checks_passed", "safe_stops", "safe_stops_expected",
    "tool_calls", "business_requests", "blocked_candidates", "blocked_executed",
)
FAILURE_KINDS = {
    "false_negative", "false_positive", "incomplete_or_unavailable",
    "workflow_check_failed", "engineering_check_failed",
}
LIMITATIONS = [
    "此处展示已保存评测的历史快照，不代表当前源码已重新验收。",
    "按执行完成时间排序；没有执行时间的早期报告明确使用汇总生成时间，不按分数挑选。",
    "全部登记样本、未完成检查和失败记录保留；内容检查、工作流和工程测试分开统计。",
    "内容暂缓准入包含检查不完整或不可用，不能等同于已确认检出；本轮登记开发评测不等于独立盲测。",
]


class InvalidReport(ValueError):
    """Public messages must not expose file contents or absolute host paths."""


def _safe_path(root, *parts):
    """Only fixed descendants; reject links/junctions as well as resolved escapes."""
    current = root
    for part in parts:
        if not part or part in {".", ".."} or "/" in part or "\\" in part:
            raise InvalidReport("报告路径无效")
        current = current / part
        if current.is_symlink() or (hasattr(current, "is_junction") and current.is_junction()):
            raise InvalidReport("报告路径包含链接或目录联接")
        if not current.resolve().is_relative_to(root):
            raise InvalidReport("报告路径超出证据目录")
    return current


def _read(root, *parts, optional=False):
    path = _safe_path(root, *parts)
    if optional and not path.exists():
        return None
    if not path.is_file():
        raise InvalidReport("所需报告文件不存在")
    with path.open("rb") as handle:
        raw = handle.read(MAX_FILE_BYTES + 1)
    if len(raw) > MAX_FILE_BYTES:
        raise InvalidReport("报告文件超过读取上限")
    def invalid_constant(_):
        raise ValueError("Nonfinite JSON number")
    try:
        value = json.loads(raw, parse_constant=invalid_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise InvalidReport("报告 JSON 无效") from exc
    if not isinstance(value, dict):
        raise InvalidReport("报告根结构必须是对象")
    return value


def _time(value):
    if not isinstance(value, str) or len(value) > 64:
        raise InvalidReport("报告时间缺失或无效")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError()
        return parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise InvalidReport("报告时间必须包含时区") from exc


def _text(value, limit=2000):
    if (not isinstance(value, str) or len(value) > limit
            or any(0xD800 <= ord(char) <= 0xDFFF for char in value)):
        raise InvalidReport("报告文本字段格式无效")
    return value


def _number(value, *, integer=False, rate=False):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise InvalidReport("报告统计字段无效")
    if integer and type(value) is not int:
        raise InvalidReport("报告计数字段必须为非负整数")
    if rate and value > 1:
        raise InvalidReport("报告比例字段超出范围")
    return value


def _counts(value, fields):
    if not isinstance(value, dict):
        raise InvalidReport("报告统计结构无效")
    return {key: _number(value[key], integer=True) for key in fields if key in value}


def _metrics(value):
    result = _counts(value, COUNT_FIELDS)
    for key in RATE_FIELDS:
        if key in value:
            result[key] = None if value[key] is None else _number(value[key], rate=True)
    for key, fields in (("latency_ms", ("p50", "p95", "p99", "max")), ("usage", USAGE_FIELDS)):
        if key in value:
            if not isinstance(value[key], dict):
                raise InvalidReport("报告统计结构无效")
            result[key] = {field: _number(value[key][field], integer=key == "usage")
                           for field in fields if field in value[key]}
    if "recall_wilson95" in value:
        interval = value["recall_wilson95"]
        if interval is not None:
            if not isinstance(interval, list) or len(interval) != 2:
                raise InvalidReport("报告置信区间无效")
            interval = [_number(x, rate=True) for x in interval]
            if interval[0] > interval[1]:
                raise InvalidReport("报告置信区间无效")
        result["recall_wilson95"] = interval
    return result


def _groups(summary, key, label):
    values = summary.get(key, [])
    if (not isinstance(values, list) or len(values) > 1000
            or any(not isinstance(value, dict) for value in values)):
        raise InvalidReport("报告分组结构无效")
    return [{label: _text(value.get(label), 300), **_metrics(value)} for value in values]


def _failure_counts(index):
    rows = index.get("failures")
    if not isinstance(rows, list) or len(rows) > 100000 or index.get("count") != len(rows):
        raise InvalidReport("失败索引条数不一致")
    kinds = Counter()
    for row in rows:
        if not isinstance(row, dict) or row.get("kind") not in FAILURE_KINDS:
            raise InvalidReport("失败索引类别无效")
        kinds[row["kind"]] += 1
    workflow = kinds["workflow_check_failed"]
    engineering = kinds["engineering_check_failed"]
    return {"content": len(rows) - workflow - engineering, "workflow": workflow,
            "engineering": engineering, "total": len(rows), "by_kind": dict(kinds)}


def _report(root, name):
    summary = _read(root, name, "metrics", "campaign-summary.json")
    execution = _read(root, name, "metrics", "campaign-execution.json", optional=True)
    created_at = _time(summary.get("created_at"))
    completed_at = _time(execution.get("finished_at")) if execution is not None else created_at
    failures = _failure_counts(_read(root, name, "failures", "failure-index.json"))
    declared_failures = summary.get("failure_counts")
    if declared_failures is not None and declared_failures != failures:
        raise InvalidReport("汇总与保留的失败索引不一致")
    matrix = _metrics(summary.get("matrix"))
    if not all(key in matrix for key in ("cases", "tp", "fn", "fp", "tn")):
        raise InvalidReport("报告缺少完整混淆矩阵")
    if not matrix["cases"] or sum(matrix[key] for key in ("tp", "fn", "fp", "tn")) != matrix["cases"]:
        raise InvalidReport("报告总样本数与混淆矩阵不一致")
    for key, expected in (
        ("attacks", matrix["tp"] + matrix["fn"]),
        ("benign", matrix["fp"] + matrix["tn"]),
        ("strict_passed", matrix["cases"] - failures["content"]),
    ):
        if expected < 0 or (key in matrix and matrix[key] != expected):
            raise InvalidReport("报告样本或严格失败计数不一致")
        matrix.setdefault(key, expected)
    matrix.setdefault("strict_pass_rate", matrix["strict_passed"] / matrix["cases"])
    recovery = _counts(summary.get("recovery", {}), RECOVERY_FIELDS)
    if "total" in recovery and "passed" in recovery:
        if recovery["total"] - recovery["passed"] != failures["workflow"]:
            raise InvalidReport("工作流汇总与失败索引不一致")
    engineering = summary.get("engineering", {})
    if not isinstance(engineering, dict):
        raise InvalidReport("工程报告结构无效")
    return {
        "id": name, "type": "registered_campaign",
        "created_at": created_at.isoformat().replace("+00:00", "Z"),
        "completed_at": completed_at.isoformat().replace("+00:00", "Z"),
        "time_basis": "execution_finished_at" if execution is not None else "summary_created_at",
        "scope": _text(summary.get("scope", "")),
        "source_path": f"test-sessions/{name}/metrics/campaign-summary.json",
        "failure_index_path": f"test-sessions/{name}/failures/failure-index.json",
        "source_digest": _text(summary.get("source_digest", ""), 128),
        "source_unchanged": summary.get("source_unchanged") is True,
        "current_code_matches": None,
        "matrix": matrix,
        "cohorts": _groups(summary, "cohorts", "name"),
        "by_source": _groups(summary, "by_source", "source_type"),
        "by_category": _groups(summary, "by_category", "test_category"),
        "recovery": recovery,
        "engineering": {"pytest": _counts(engineering.get("pytest", {}),
                                            ("cases", "failures", "errors", "skipped"))},
        "failure_counts": failures,
        "limitations": LIMITATIONS,
    }


def campaign_reports(project_root: Path, limit=20):
    """Discover fixed summary locations, returning every eligible result, failures included."""
    if type(limit) is not int or not 1 <= limit <= 50:
        raise ValueError("limit must be an integer from 1 to 50")
    project_root = Path(project_root).resolve()
    reports, errors = [], []
    try:
        root = _safe_path(project_root, "test-sessions")
        if not root.exists():
            candidates = []
        elif not root.is_dir():
            raise InvalidReport("证据目录无效")
        else:
            candidates = list(root.iterdir())
        for directory in candidates:
            # Do not inspect payload files or recursively discover arbitrary artifacts.
            name = directory.name
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,159}", name):
                continue
            try:
                checked = _safe_path(root, name)
                if not checked.is_dir():
                    continue
                metrics = _safe_path(root, name, "metrics")
                if not metrics.exists():
                    continue
                path = _safe_path(root, name, "metrics", "campaign-summary.json")
                if not path.exists():
                    continue
                reports.append(_report(root, name))
            except (OSError, InvalidReport, TypeError, KeyError, OverflowError):
                errors.append({"id": name, "reason": "报告缺失、格式无效或路径不安全；原始证据未改动"})
    except (OSError, InvalidReport):
        errors.append({"id": "test-sessions", "reason": "证据目录无法安全读取"})
    # No score or filesystem modification time participates in recency selection.
    reports.sort(key=lambda item: (_time(item["completed_at"]), item["id"]), reverse=True)
    return redact({
        "available": bool(reports), "latest_id": reports[0]["id"] if reports else None,
        "total_count": len(reports), "invalid_count": len(errors),
        "truncated": len(reports) > limit, "reports": reports[:limit], "errors": errors,
        "selection_basis": "recorded_completion_time_descending",
    })
