"""Regression oracles for transport failure, private API data and platform aliases."""
import json
import os
import sys
import threading

import httpx
import pytest
from fastapi.testclient import TestClient

from adapters import mcp_proxy
from adapters.mcp_proxy import Upstream, MAX_FRAME_CHARS
from adapters.sdk import GuardClient, GuardUnavailable, ReceiptUnconfirmed, ExecutionOutcomeUnknown
from backend.main import create_app
from backend import policy


@pytest.fixture
def client(tmp_path, monkeypatch):
    for name in ["GUARD_API_TOKEN", "GUARD_MODEL_BASE_URL", "GUARD_MODEL_NAME", "GUARD_MODEL_KEY"]:
        monkeypatch.delenv(name, raising=False)
    with TestClient(create_app(tmp_path)) as transport:
        yield transport


def test_notification_stream_cannot_extend_absolute_upstream_deadline(monkeypatch):
    class NotificationQueue:
        def get(self, timeout):
            return {"jsonrpc": "2.0", "method": "notifications/progress", "params": {}}

    upstream = Upstream.__new__(Upstream)
    upstream.counter, upstream.timeout = 0, .05
    upstream._request_lock = threading.Lock()
    upstream._reader_error = None
    upstream.inbox = NotificationQueue()
    upstream.send = lambda message: None
    closed = []
    upstream.close = lambda: closed.append(True)
    ticks = iter([0, .01, .02, .03, .04, .051, .1])
    monkeypatch.setattr(mcp_proxy.time, "monotonic", lambda: next(ticks))
    with pytest.raises(TimeoutError):
        upstream.request("tools/call", {"name": "operation"})
    assert closed == [True], "A permanently nonempty notification queue must still time out"


def test_oversized_unterminated_upstream_frame_is_rejected_before_complete_line():
    # The child never emits a newline. The frame guard must act while it is alive.
    script = f"import sys,time; sys.stdout.write('x'*{MAX_FRAME_CHARS + 10}); sys.stdout.flush(); time.sleep(10)"
    upstream = Upstream([sys.executable, "-u", "-c", script], timeout=3)
    try:
        with pytest.raises(ExecutionOutcomeUnknown):
            upstream.request("ping")
        assert upstream.process.poll() is not None
    finally:
        upstream.close()


def test_mismatched_rpc_response_id_closes_transport_without_reusing_it():
    script = "import sys,json,time; json.loads(sys.stdin.readline()); print(json.dumps({'jsonrpc':'2.0','id':999,'result':{}}),flush=True); time.sleep(10)"
    upstream = Upstream([sys.executable, "-u", "-c", script], timeout=3)
    try:
        with pytest.raises(ExecutionOutcomeUnknown):
            upstream.request("tools/call", {"name": "operation"})
        assert upstream.process.poll() is not None
        with pytest.raises(ExecutionOutcomeUnknown):
            upstream.request("tools/call", {"name": "operation"})
    finally:
        upstream.close()


def test_operator_token_protects_record_reads_exports_and_instance_identity(client, monkeypatch):
    sid = client.post("/api/sessions", json={"title": "Private business task", "intent": "Read README"}).json()["id"]
    monkeypatch.setenv("GUARD_API_TOKEN", "local-test-operator")
    monkeypatch.setenv("GUARD_INSTANCE_ID", "test-instance-nonce")
    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.json()["instance_id"] == "test-instance-nonce"
    assert health.json()["process_id"] == os.getpid()
    for path in ["/api/dashboard", "/api/sessions", f"/api/sessions/{sid}", f"/api/sessions/{sid}/export", "/api/policies", "/api/memories"]:
        denied = client.get(path)
        assert denied.status_code == 401
        assert "Private business task" not in denied.text
        allowed = client.get(path, headers={"X-Guard-Token": "local-test-operator"})
        assert allowed.status_code == 200, allowed.text


@pytest.mark.parametrize("path", [".aws./credentials", ".ssh /config", "Startup./run.txt", "reports /file.txt"])
def test_win32_trailing_dot_or_space_alias_never_gets_file_execution_permit(client, path):
    sid = client.post("/api/sessions", json={"title": "Portable paths", "intent": "Create a project report", "scope": "development"}).json()["id"]
    response = client.post(f"/api/sessions/{sid}/calls", json={"tool": "fs.write", "args": {"path": path, "content": "candidate"}})
    assert response.status_code == 200
    assert response.json()["decision"] == "block"
    assert "permit" not in response.json()


def test_model_declared_necessary_gap_cannot_be_overridden_by_plain_approval(client, monkeypatch):
    sid = client.post("/api/sessions", json={"title": "Model gap", "intent": "Read README"}).json()["id"]
    monkeypatch.setenv("GUARD_MODEL_BASE_URL", "https://model.example.test/v1")
    monkeypatch.setenv("GUARD_MODEL_NAME", "controlled-reply")
    monkeypatch.setattr(policy, "model_review", lambda payload: ({"risk": False, "relation": "aligned", "reason": "Plausibly aligned", "quote": "", "information_gaps": ["Actual target ownership is unverified"]}, None))
    response = client.post(f"/api/sessions/{sid}/calls", json={"tool": "fs.read", "args": {"path": "README.md"}})
    call = response.json()
    assert call["decision"] == "confirm" and "permit" not in call
    approved = client.post(f"/api/approvals/{call['id']}", json={"approved": True})
    assert approved.status_code == 200
    assert approved.json()["decision"] == "confirm"
    assert "permit" not in approved.json()


def test_malformed_claim_binding_never_runs_callback(client):
    class TamperedClaim:
        def request(self, method, path, **kwargs):
            response = client.request(method, path, **kwargs)
            if path.endswith("/claim") and response.status_code == 200:
                payload = response.json()
                payload["call"]["parameter_hash"] = "different-candidate"
                return httpx.Response(200, json=payload, request=httpx.Request(method, "http://testserver" + path))
            return response

    sdk = GuardClient(client=TamperedClaim())
    sid = sdk.session("Claim binding", "Read README")["id"]
    reviewed = sdk.review(sid, "fs.read", {"path": "README.md"})
    effects = []
    with pytest.raises(GuardUnavailable):
        sdk.execute_reviewed(reviewed, "fs.read", {"path": "README.md"}, lambda args: effects.append(args))
    assert effects == []


def test_nonfinite_callback_result_reports_unconfirmed_without_replaying(client):
    sdk = GuardClient(client=client)
    sid = sdk.session("Receipt encoding", "Read README")["id"]
    reviewed = sdk.review(sid, "fs.read", {"path": "README.md"})
    effects = []

    def callback(args):
        effects.append(args)
        return {"value": float("nan")}

    with pytest.raises(ReceiptUnconfirmed):
        sdk.execute_reviewed(reviewed, "fs.read", {"path": "README.md"}, callback)
    with pytest.raises(GuardUnavailable):
        sdk.execute_reviewed(reviewed, "fs.read", {"path": "README.md"}, callback)
    assert len(effects) == 1


def test_chunked_oversized_body_and_excessive_json_nesting_fail_without_server_error(client):
    oversized = client.post("/api/sessions", content=iter([b"x" * 800000, b"x" * 800000]), headers={"Content-Type": "application/json"})
    assert oversized.status_code == 413
    nested = client.post("/api/sessions", content="[" * 2000 + "0" + "]" * 2000, headers={"Content-Type": "application/json"})
    assert nested.status_code == 422
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/sessions").json() == []


@pytest.mark.parametrize("omission", ["long_source", "long_history"])
def test_full_model_context_batches_cover_sources_and_history(client, monkeypatch, omission):
    sid = client.post("/api/sessions", json={"title": "Coverage", "intent": "Read README"}).json()["id"]
    refs = []
    if omission == "long_source":
        admitted = client.post(f"/api/sessions/{sid}/sources", json={"type": "document", "content": "Ordinary public reference. " * 100}).json()
        refs = [admitted["id"]]
    else:
        for _ in range(21):
            response = client.post(f"/api/sessions/{sid}/calls", json={"tool": "fs.read", "args": {"path": "README.md"}})
            assert response.status_code == 200
    monkeypatch.setenv("GUARD_MODEL_BASE_URL", "https://model.example.test/v1")
    monkeypatch.setenv("GUARD_MODEL_NAME", "controlled-reply")
    monkeypatch.setattr(policy, "model_review", lambda payload: ({"risk": False, "relation": "aligned", "reason": "Visible content appears aligned", "quote": "", "information_gaps": []}, None))
    response = client.post(f"/api/sessions/{sid}/calls", json={"tool": "fs.read", "args": {"path": "README.md"}, "source_ids": refs})
    call = response.json()
    assert call["decision"] == "allow", call
    coverage = call["report"]["alignment_coverage"]
    assert coverage["complete"] is True
    assert all(s["checked_chars"] == s["total_chars"] for s in coverage["sources"])
    assert coverage["history_checked"] == coverage["history_total"]
    if omission == "long_history":
        assert len(coverage["batches"]) >= 3



def test_interrupted_recheck_recovers_without_reviving_the_old_permit(tmp_path, monkeypatch):
    for name in ["GUARD_API_TOKEN", "GUARD_MODEL_BASE_URL", "GUARD_MODEL_NAME", "GUARD_MODEL_KEY"]:
        monkeypatch.delenv(name, raising=False)
    with TestClient(create_app(tmp_path)) as first:
        sid = first.post("/api/sessions", json={"title": "Recovery", "intent": "Read README"}).json()["id"]
        call = first.post(f"/api/sessions/{sid}/calls", json={"tool": "fs.read", "args": {"path": "README.md"}}).json()
        service = first.app.state.service
        with service.store.transaction():
            persisted = service.require("call", call["id"])
            persisted["_recheck_in_progress"] = "persisted-at-crash-boundary"
            persisted["_permit"]["revoked"] = True
            service.store.put("call", persisted)
    with TestClient(create_app(tmp_path)) as recovered:
        assert recovered.post(f"/api/calls/{call['id']}/execute", json={"permit": call["permit"]}).status_code == 409
        rerun = recovered.post(f"/api/calls/{call['id']}/recheck", json={})
        assert rerun.status_code == 200, rerun.text
        assert rerun.json()["id"] != call["id"] and rerun.json()["decision"] == "allow"
        calls = recovered.get(f"/api/sessions/{sid}").json()["calls"]
        assert all(c["execution_status"] == "not_executed" for c in calls)


def test_fixture_command_execution_preserves_original_case_and_unicode(client):
    sid = client.post("/api/sessions", json={"title": "Original command", "intent": "Write a report after confirmation", "scope": "development"}).json()["id"]
    call = client.post(f"/api/sessions/{sid}/calls", json={"tool": "exec", "args": {"command": "echo MiXeD中文 > reports/CaseReport.TXT"}}).json()
    assert call["decision"] == "confirm"
    approved = client.post(f"/api/approvals/{call['id']}", json={"approved": True}).json()
    executed = client.post(f"/api/calls/{call['id']}/execute", json={"permit": approved["permit"]})
    assert executed.status_code == 200 and executed.json()["execution_status"] == "succeeded"
    directory = client.app.state.service.fixture_root(sid) / "reports"
    assert [p.name for p in directory.iterdir()] == ["CaseReport.TXT"]
    assert (directory / "CaseReport.TXT").read_text(encoding="utf-8") == "MiXeD中文\n"


@pytest.mark.parametrize("key,value", [("GUARD_MODEL_BASE_URL", "https://model.example.test/v1"), ("GUARD_MODEL_NAME", "chosen-model"), ("GUARD_MODEL_KEY", "synthetic-operator-key")])
def test_partial_model_configuration_fails_closed_instead_of_becoming_rule_mode(client, monkeypatch, key, value):
    sid = client.post("/api/sessions", json={"title": "Partial config", "intent": "Read README"}).json()["id"]
    monkeypatch.setenv(key, value)
    health = client.get("/api/health").json()
    assert health["model_configured"] is True
    assert health["model_configuration_valid"] is False
    assert health["model_status"] == "invalid_configuration"
    assert value not in json.dumps(health)
    source = client.post(f"/api/sessions/{sid}/sources", json={"type": "document", "content": "Public documentation."}).json()
    assert source["decision"] == "block"
    call = client.post(f"/api/sessions/{sid}/calls", json={"tool": "fs.read", "args": {"path": "README.md"}}).json()
    assert call["decision"] == "block"
    assert "core.model_unavailable" in call["matched_rules"]
    assert "permit" not in call


@pytest.mark.parametrize("url", ["https://[invalid", "https://model.example.test:invalid/v1", "https://model.example.test:99999/v1"])
def test_malformed_model_url_does_not_crash_admission_or_fall_back_to_allow(client, monkeypatch, url):
    sid = client.post("/api/sessions", json={"title": "Invalid URL", "intent": "Read README"}).json()["id"]
    monkeypatch.setenv("GUARD_MODEL_BASE_URL", url)
    monkeypatch.setenv("GUARD_MODEL_NAME", "chosen-model")
    response = client.post(f"/api/sessions/{sid}/sources", json={"type": "document", "content": "Ordinary instructions."})
    assert response.status_code == 200, response.text
    assert response.json()["decision"] == "block"
    assert url not in response.text


def test_malformed_origin_is_rejected_without_server_error(client):
    response = client.post("/api/sessions", json={"title": "Origin", "intent": "Read README"}, headers={"Origin": "http://[invalid"})
    assert response.status_code == 403
