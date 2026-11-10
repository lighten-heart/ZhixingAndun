"""Offline saved-report reading: no database, model calls, or evidence rewriting."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest

from backend import campaign_reports as reports


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


def campaign(root, name, finished="2026-10-20T10:00:00+00:00", *, failed=False):
    directory = root / "test-sessions" / name
    matrix = {"cases": 10, "attacks": 5, "benign": 5,
              "tp": 4 if failed else 5, "fn": 1 if failed else 0,
              "fp": 0, "tn": 5, "confirmed_recall": .8 if failed else 1,
              "strict_passed": 9 if failed else 10,
              "strict_pass_rate": .9 if failed else 1,
              "unavailable": 0, "incomplete": 0}
    summary = {"created_at": "2026-10-20T12:00:00+00:00", "scope": "Registered development evaluation",
               "source_digest": "a" * 64, "source_unchanged": True,
               "matrix": matrix, "cohorts": [{"name": "registered", **matrix}],
               "recovery": {"total": 2, "passed": 1 if failed else 2},
               "engineering": {"pytest": {"cases": 12, "failures": 0, "errors": 0, "skipped": 0}}}
    failures = [] if not failed else [
        {"kind": "false_negative", "input": {"content": "RAW INPUT MUST NOT BE EXPOSED"}},
        {"kind": "workflow_check_failed", "result": "RAW RESULT MUST NOT BE EXPOSED"},
    ]
    save(directory / "metrics/campaign-summary.json", summary)
    if finished is not None:
        save(directory / "metrics/campaign-execution.json",
             {"finished_at": finished, "command": ["DO NOT EXPOSE COMMAND"]})
    save(directory / "failures/failure-index.json", {"count": len(failures), "failures": failures})
    return directory


def fingerprints(root):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in root.rglob("*.json")}


def test_latest_is_recorded_completion_time_even_when_score_is_worse(tmp_path):
    older = campaign(tmp_path, "run-999-best-score", "2026-10-20T09:00:00Z")
    newer = campaign(tmp_path, "run-001-with-failures", "2026-10-20T10:00:00Z", failed=True)
    # Make the earlier high-score report look newer on disk; metadata still wins.
    os.utime(older / "metrics/campaign-summary.json", (1900000000, 1900000000))
    before = fingerprints(tmp_path)
    result = reports.campaign_reports(tmp_path, limit=1)
    assert result["latest_id"] == newer.name
    assert result["total_count"] == 2 and result["truncated"] is True
    latest = result["reports"][0]
    assert latest["type"] == "registered_campaign"
    assert latest["matrix"]["cases"] == 10 and latest["matrix"]["strict_passed"] == 9
    assert latest["failure_counts"] == {"content": 1, "workflow": 1, "engineering": 0,
                                       "total": 2, "by_kind": {"false_negative": 1, "workflow_check_failed": 1}}
    assert latest["current_code_matches"] is None
    assert latest["source_path"] == f"test-sessions/{newer.name}/metrics/campaign-summary.json"
    assert fingerprints(tmp_path) == before
    complete = reports.campaign_reports(tmp_path)
    assert [row["id"] for row in complete["reports"]] == [newer.name, older.name]
    assert complete["truncated"] is False


def test_old_report_timestamp_fallback_and_derived_counts_are_explicit(tmp_path):
    directory = campaign(tmp_path, "early-format", finished=None, failed=True)
    path = directory / "metrics/campaign-summary.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    for field in ("strict_passed", "strict_pass_rate", "attacks", "benign"):
        data["matrix"].pop(field)
    save(path, data)
    result = reports.campaign_reports(tmp_path)["reports"][0]
    assert result["time_basis"] == "summary_created_at"
    assert result["completed_at"] == data["created_at"].replace("+00:00", "Z")
    assert result["matrix"]["strict_passed"] == 9
    assert result["matrix"]["strict_pass_rate"] == .9
    assert result["matrix"]["attacks"] == result["matrix"]["benign"] == 5


def test_reports_only_project_whitelisted_fields(tmp_path):
    directory = campaign(tmp_path, "fields", failed=True)
    path = directory / "metrics/campaign-summary.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["raw"] = "DO NOT EXPOSE RAW"
    data["matrix"]["request"] = {"content": "DO NOT EXPOSE REQUEST"}
    data["engineering"]["command"] = "DO NOT EXPOSE COMMAND"
    data["recovery"]["execution_rows"] = [{"payload": "DO NOT EXPOSE ROW"}]
    save(path, data)
    serialized = json.dumps(reports.campaign_reports(tmp_path))
    assert "DO NOT EXPOSE" not in serialized and "RAW INPUT" not in serialized
    assert "RAW RESULT" not in serialized and str(tmp_path) not in serialized


@pytest.mark.parametrize("damage", ["bad_json", "nonfinite", "oversized", "wrong_total", "wrong_failures",
                                   "invalid_timestamp", "invalid_group", "missing_failure_index"])
def test_invalid_report_is_disclosed_and_never_presented_as_success(tmp_path, damage, monkeypatch):
    directory = campaign(tmp_path, "damaged", failed=True)
    path = directory / "metrics/campaign-summary.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    if damage == "bad_json":
        path.write_text("{broken", encoding="utf-8")
    elif damage == "nonfinite":
        data["matrix"]["fpr"] = float("nan")
        save(path, data)
    elif damage == "oversized":
        monkeypatch.setattr(reports, "MAX_FILE_BYTES", 50)
    elif damage == "wrong_total":
        data["matrix"]["cases"] = 11
        save(path, data)
    elif damage == "wrong_failures":
        data["failure_counts"] = {"content": 0, "total": 0}
        save(path, data)
    elif damage == "invalid_timestamp":
        save(directory / "metrics/campaign-execution.json", {"finished_at": "2026-10-20T10:00:00"})
    elif damage == "invalid_group":
        data["cohorts"] = ["not a group"]
        save(path, data)
    else:
        (directory / "failures/failure-index.json").unlink()
    before = fingerprints(tmp_path)
    result = reports.campaign_reports(tmp_path)
    assert result["available"] is False and result["latest_id"] is None
    assert result["invalid_count"] == 1 and result["errors"][0]["id"] == "damaged"
    assert result["reports"] == []
    assert fingerprints(tmp_path) == before


def test_safe_path_rejects_traversal_and_links(tmp_path):
    with pytest.raises(reports.InvalidReport):
        reports._safe_path(tmp_path, "..", "outside")
    external = tmp_path / "external"
    external.mkdir()
    sessions = tmp_path / "project/test-sessions"
    sessions.mkdir(parents=True)
    link = sessions / "outside"
    if os.name == "nt":
        # A real directory junction needs no Windows symlink privilege.
        subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(external)],
                       check=True, capture_output=True, text=True)
    else:
        link.symlink_to(external, target_is_directory=True)
    try:
        result = reports.campaign_reports(tmp_path / "project")
        assert result["available"] is False and result["invalid_count"] == 1
        assert result["errors"][0]["id"] == "outside"
    finally:
        # Remove only the link, never its target.
        if os.name == "nt":
            link.rmdir()
        else:
            link.unlink()


def test_missing_reports_are_an_empty_read_only_state(tmp_path):
    assert not (tmp_path / "test-sessions").exists()
    result = reports.campaign_reports(tmp_path)
    assert result["available"] is False and result["total_count"] == 0
    assert result["invalid_count"] == 0 and result["truncated"] is False
    assert not (tmp_path / "test-sessions").exists()


@pytest.mark.parametrize("limit", [0, 51, True, "20"])
def test_limit_does_not_allow_unbounded_report_output(tmp_path, limit):
    with pytest.raises(ValueError):
        reports.campaign_reports(tmp_path, limit)
