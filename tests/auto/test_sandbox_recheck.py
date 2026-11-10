"""A single trace-backed supplemental review may tighten, never grant, permission."""
import copy
import hashlib
import threading

import pytest
from fastapi import HTTPException

from backend.forensics import Forensics, parse_trace
from backend.service import GuardService, digest


TRACE = ('12 execve("/usr/local/bin/python3", ["python3", "-I", "/materials/program.py"], 0x0) = 0\n'
         '13 execve("/work/steal_payload.py", ["/work/steal_payload.py"], 0x0) = 0\n')


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    service = GuardService(tmp_path)
    session = service.create_session({"title": "supplemental review", "intent": "Check a public test script",
                                      "scope": "development", "agent_id": "main"})
    forensic = Forensics(service)
    script = forensic.register(session["id"], "open('/work/result.txt', 'w').write('ok')", "public test")
    call = service.review_call(session["id"], {"tool": "script.run", "args": {"script_id": script["id"]}})
    monkeypatch.setattr("backend.forensics.image_id", lambda: "sha256:" + "a" * 64)
    def probe(code, directory, image, *, identity, on_created):
        assert service.store._depth == 0
        directory.mkdir(parents=True)
        trace = directory / "strace.log"
        trace.write_text(TRACE, encoding="utf-8", newline="")
        on_created("b" * 64)
        return {"status": "completed", "events": parse_trace(TRACE), "cleanup_verified": True,
                "trace_file": str(trace), "trace_sha256": hashlib.sha256(TRACE.encode()).hexdigest()}
    monkeypatch.setattr("backend.forensics.docker_probe", probe)
    monkeypatch.setattr("backend.detection.model_configured", lambda: True)
    yield service, forensic, call
    service.store.close()


def answer(risk=False, relation="aligned", quote="", gaps=None):
    return {"risk": risk, "relation": relation, "quote": quote, "reason": "review result", "information_gaps": gaps or []}, None


def test_verified_new_risk_blocks_and_keeps_original_report(prepared, monkeypatch):
    service, forensic, call = prepared
    original = copy.deepcopy(call["report"])
    invocations = []
    def model(payload):
        invocations.append(payload)
        assert service.store._depth == 0
        persisted = service.store.all("sandbox")[0]
        assert persisted["status"] == "reviewing" and persisted["supplemental_review_count"] == 1
        return answer(True, "deviating", "/work/steal_payload.py")
    monkeypatch.setattr("backend.detection.model_review", model)
    result = forensic.run(call["id"])
    current = service.require("call", call["id"])
    assert len(invocations) == 1
    assert result["supplemental_review"]["model_invocations"] == 1
    assert current["decision"] == "block" and current["execution_status"] == "not_executed"
    assert "_permit" not in current
    assert result["original_report"] == original
    assert result["original_report_sha256"] == digest(original)
    assert current["report"]["sandbox_review"] == result["recheck"]
    finding = result["recheck"]["findings"][0]
    assert finding["quote"] == "/work/steal_payload.py" and finding["verified"]
    assert finding["evidence_refs"][0].endswith(":L2-L2")
    assert finding["evidence_refs"][0] in current["report"]["evidence_refs"]
    assert set(original["information_gaps"]).issubset(current["report"]["information_gaps"])
    assert "FILE_ACCESS_UNKNOWN" in result["recheck"]["remaining_gaps"]
    assert any(e["type"] == "sandbox.rechecked" for e in service.store.all("event", call["session_id"]))
    with pytest.raises(HTTPException):
        forensic.run(call["id"])
    assert len(invocations) == 1 and len(service.store.all("call")) == 1


@pytest.mark.parametrize("mode", ["clear", "uncertain", "unverified_risk", "failure"])
def test_unknown_or_clear_never_grants_formal_permission(prepared, monkeypatch, mode):
    service, forensic, call = prepared
    values = {"clear": answer(), "uncertain": answer(relation="uncertain"),
              "unverified_risk": answer(True, "deviating", "invented quote"), "failure": (None, "provider unavailable")}
    count = []
    def model(payload):
        count.append(1)
        return values[mode]
    monkeypatch.setattr("backend.detection.model_review", model)
    result = forensic.run(call["id"])
    current = service.require("call", call["id"])
    assert count == [1]
    assert result["recheck"]["status"] == "applied"
    assert result["recheck"]["decision_after"] == current["decision"] == "confirm"
    assert result["formal_execution_permit"] is False and "_permit" not in current
    assert "FORMAL_EXECUTION_CHECKS_UNRESOLVED" in current["information_gaps"]
    if mode != "clear":
        assert result["supplemental_review"]["semantic_complete"] is False
        assert result["supplemental_review"]["status"] == "incomplete"


@pytest.mark.parametrize("mutation", ["authorization", "policy", "candidate", "reject"])
def test_late_result_cannot_modify_changed_review(prepared, monkeypatch, mutation):
    service, forensic, call = prepared
    changed = []
    def model(payload):
        with service.store.transaction():
            if mutation == "authorization":
                session = service.require("session", call["session_id"])
                session["authorization_version"] += 1
                service.store.put("session", session)
            elif mutation == "policy":
                policy = service.policy()
                policy["version"] += 1
                service.store.set_meta("policy", policy)
            elif mutation == "candidate":
                value = service.require("call", call["id"])
                value["args"]["script_id"] = "different-script"
                service.store.put("call", value)
            else:
                service.approve(call["id"], False)
            changed.append(service.require("call", call["id"]))
        return answer(True, "deviating", "/work/steal_payload.py")
    monkeypatch.setattr("backend.detection.model_review", model)
    result = forensic.run(call["id"])
    assert result["recheck"]["status"] == "stale"
    assert result["applicable_to_current_review"] is False
    assert service.require("call", call["id"]) == changed[0]
    assert "sandbox_review" not in changed[0]["report"]


def test_tampered_trace_is_not_accepted_as_new_evidence(prepared, monkeypatch):
    service, forensic, call = prepared
    original_probe = __import__("backend.forensics", fromlist=["docker_probe"]).docker_probe
    def probe(*args, **kwargs):
        result = original_probe(*args, **kwargs)
        result["trace_sha256"] = "0" * 64
        return result
    monkeypatch.setattr("backend.forensics.docker_probe", probe)
    monkeypatch.setattr("backend.detection.model_review", lambda payload: pytest.fail("No verified trace means no model invocation"))
    result = forensic.run(call["id"])
    assert result["supplemental_review_count"] == 0
    assert result["supplemental_review"]["model_invocations"] == 0
    assert result["recheck"]["evidence_refs"] == []
    assert "SANDBOX_TRACE_UNVERIFIED" in result["recheck"]["remaining_gaps"]
    assert service.require("call", call["id"])["decision"] == "confirm"


def test_timeout_discards_late_model_result_and_keeps_budget(prepared, monkeypatch):
    service, forensic, call = prepared
    release, finished = threading.Event(), threading.Event()
    monkeypatch.setattr("backend.forensics.SUPPLEMENTAL_TIMEOUT", 0.01)
    def model(payload):
        release.wait(3)
        finished.set()
        return answer(True, "deviating", "/work/steal_payload.py")
    monkeypatch.setattr("backend.detection.model_review", model)
    try:
        result = forensic.run(call["id"])
        current = service.require("call", call["id"])
        assert "SANDBOX_SUPPLEMENTAL_REVIEW_TIMEOUT" in result["recheck"]["remaining_gaps"]
        assert current["decision"] == "confirm"
        release.set()
        assert finished.wait(3)
        assert service.require("call", call["id"]) == current
        assert len(service.store.all("call")) == 1
        with pytest.raises(HTTPException):
            forensic.run(call["id"])
    finally:
        release.set()
        finished.wait(3)


def test_bounded_projection_still_calls_model_only_once(prepared, monkeypatch):
    service, forensic, call = prepared
    original_probe = __import__("backend.forensics", fromlist=["docker_probe"]).docker_probe
    def probe(*args, **kwargs):
        result = original_probe(*args, **kwargs)
        from pathlib import Path
        raw = TRACE + ''.join(f'{i + 20} execve("/work/{"x" * 600}", [], 0x0) = 0\n' for i in range(100))
        Path(result["trace_file"]).write_text(raw, encoding="utf-8", newline="")
        result.update(trace_sha256=hashlib.sha256(raw.encode()).hexdigest(), events=parse_trace(raw))
        return result
    calls = []
    monkeypatch.setattr("backend.forensics.docker_probe", probe)
    def model(payload):
        calls.append(payload)
        assert len(payload["content"]) <= 12000
        return answer()
    monkeypatch.setattr("backend.detection.model_review", model)
    result = forensic.run(call["id"])
    assert len(calls) == 1
    assert "SANDBOX_PROJECTION_PARTIAL" in result["recheck"]["remaining_gaps"]
    assert result["recheck"]["decision_after"] == "confirm"
