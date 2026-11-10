"""Security boundary regressions using isolated stores and controlled model replies.

The model transport tests do not contact any external service. Their assertions
cover emitted request data and failure semantics, not real-model accuracy.
"""
import base64
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

import httpx
import pytest
from fastapi.testclient import TestClient

from backend import detection, policy
from backend.main import create_app


PASSWORD = "SyntheticPassphrase734!"
API_KEY = "SyntheticOpaqueKey734"
JSON_SECRET = json.dumps({"password": PASSWORD, "api_key": API_KEY})
ENCODED_SECRET = base64.b64encode(JSON_SECRET.encode()).decode()
SECRET_CONTENT = [
    pytest.param(JSON_SECRET, id="quoted-json"),
    pytest.param(json.dumps(JSON_SECRET), id="escaped-json-string"),
    pytest.param(f'password: "{PASSWORD}"\napi_key: "{API_KEY}"', id="quoted-yaml"),
    pytest.param(ENCODED_SECRET, id="base64-json"),
    pytest.param(quote(JSON_SECRET, safe=""), id="percent-encoded-json"),
]


@pytest.fixture
def client(tmp_path, monkeypatch):
    for name in ["GUARD_API_TOKEN", "GUARD_MODEL_BASE_URL", "GUARD_MODEL_KEY", "GUARD_MODEL_NAME"]:
        monkeypatch.delenv(name, raising=False)
    with TestClient(create_app(data_dir=tmp_path)) as instance:
        yield instance


def session(client):
    response = client.post("/api/sessions", json={"title": "Security boundary", "intent": "Read the public README and summarize the installation instructions."})
    assert response.status_code == 200, response.text
    return response.json()["id"]


def source(client, sid, content):
    return client.post(f"/api/sessions/{sid}/sources", json={"type": "document", "content": content})


def review(client, sid, tool="fs.read", args=None):
    response = client.post(f"/api/sessions/{sid}/calls", json={"tool": tool, "args": args or {"path": "README.md"}})
    assert response.status_code == 200, response.text
    return response.json()


def configure_model(monkeypatch):
    monkeypatch.setenv("GUARD_MODEL_BASE_URL", "https://model.example.test/v1")
    monkeypatch.setenv("GUARD_MODEL_NAME", "controlled-test-model")
    monkeypatch.setenv("GUARD_MODEL_KEY", "transport-test-key")


def model_answer(**overrides):
    return {"risk": False, "relation": "aligned", "reason": "The observed content is relevant to the task.", "quote": "", "information_gaps": [], **overrides}


@pytest.mark.parametrize("content", SECRET_CONTENT)
def test_secret_text_is_redacted_from_public_source_memory_and_export(client, content):
    sid = session(client)
    response = source(client, sid, content)
    assert response.status_code == 200, response.text
    record = response.json()
    assert record["sensitive"] is True
    assert len(record["content"]) == len(content), "Masking must preserve original codepoint offsets"
    assert record["content"] != content
    memory = client.post("/api/memories", json={"session_id": sid, "label": "credential reference", "content": content})
    assert memory.status_code == 200, memory.text
    for public in [response, memory, client.get("/api/memories"), client.get(f"/api/sessions/{sid}"), client.get(f"/api/sessions/{sid}/export")]:
        assert public.status_code == 200
        assert PASSWORD not in public.text
        assert API_KEY not in public.text
        assert ENCODED_SECRET not in public.text


@pytest.mark.parametrize("content", SECRET_CONTENT)
def test_model_transport_receives_only_redacted_content(monkeypatch, content):
    configure_model(monkeypatch)
    captured = []
    original_client = httpx.Client

    def respond(request):
        captured.append(request)
        return httpx.Response(200, json={"choices": [{"finish_reason": "stop", "message": {"content": json.dumps({**model_answer(), "active_redirection": False})}}]})

    def client_factory(**kwargs):
        assert kwargs["follow_redirects"] is False
        assert kwargs["trust_env"] is False
        return original_client(transport=httpx.MockTransport(respond), **kwargs)

    monkeypatch.setattr(detection.httpx, "Client", client_factory)
    answer, error = detection.model_review({"kind": "content", "content": content})
    assert answer is not None and error is None
    assert len(captured) == 1
    transmitted = json.loads(captured[0].content)["messages"][1]["content"]
    assert PASSWORD not in transmitted
    assert API_KEY not in transmitted
    assert ENCODED_SECRET not in transmitted
    assert json.loads(transmitted)["content"] == detection.redact(content)


@pytest.mark.parametrize("tool,args", [
    ("net.fetch", {"url": "https://docs.example.test/report", "method": "POST", "body": "rewritten material without explicit source IDs"}),
    ("agent.delegate", {"task": "Inspect the supplied material", "context": "rewritten material without explicit source IDs"}),
])
def test_omitting_source_references_does_not_clear_sensitive_session_state(client, tool, args):
    sid = session(client)
    admitted = source(client, sid, JSON_SECRET).json()
    assert admitted["decision"] == "allow"
    assert admitted["sensitive"] is True
    before = client.app.state.service.fixture_effects(sid)
    call = review(client, sid, tool, args)
    assert call["source_ids"] == []
    assert call["decision"] == "block"
    assert "core.secret_flow" in call["matched_rules"]
    assert call["information_gaps"], "Conservative taint is not exact data lineage"
    assert client.post(f"/api/calls/{call['id']}/execute", json={}).status_code == 409
    assert client.app.state.service.fixture_effects(sid) == before


@pytest.mark.parametrize("answer,content", [
    pytest.param(model_answer(relation="uncertain"), "Ordinary project notes.", id="uncertain-relation"),
    pytest.param(model_answer(information_gaps=["Original authorization is incomplete"]), "Ordinary project notes.", id="necessary-information-gap"),
    pytest.param(model_answer(risk=True, relation="deviating", quote="invented quote absent from the submitted content"), "Ordinary project notes.", id="unverifiable-risk-quote"),
])
def test_incomplete_model_source_review_requires_confirmation(client, monkeypatch, answer, content):
    sid = session(client)
    configure_model(monkeypatch)
    monkeypatch.setattr(detection, "model_review", lambda payload: (answer, None))
    response = source(client, sid, content)
    assert response.status_code == 200, response.text
    record = response.json()
    assert record["decision"] == "confirm"
    assert record["detection"]["information_gaps"]
    assert record["detection"]["coverage"]["checked_chars"] == len(content)
    assert record["detection"]["coverage"]["model_checked_chars"] == len(content)
    assert not any(f["rule_id"] == "model.verified" for f in record["detection"]["findings"])


@pytest.mark.parametrize("failure", ["timeout", "invalid-schema", "redirect"])
def test_configured_model_transport_failure_blocks_source_admission(client, monkeypatch, failure):
    sid = session(client)
    configure_model(monkeypatch)
    requests = []
    original_client = httpx.Client

    def respond(request):
        requests.append(request)
        if failure == "timeout":
            raise httpx.ReadTimeout("controlled timeout", request=request)
        if failure == "redirect":
            return httpx.Response(302, headers={"Location": "https://unexpected.example.test/collect"})
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"risk":"not a boolean"}'}}]})

    monkeypatch.setattr(detection.httpx, "Client", lambda **kwargs: original_client(transport=httpx.MockTransport(respond), **kwargs))
    response = source(client, sid, "Ordinary documentation.")
    assert response.status_code == 200, response.text
    assert response.json()["decision"] == "block"
    assert response.json()["detection"]["information_gaps"]
    assert len(requests) == 2, "At most one bounded inference-only retry"
    assert all(str(r.url) == "https://model.example.test/v1/chat/completions" for r in requests), "Authorization-bearing model requests must never follow redirects"
    assert requests[0].content == requests[1].content
    batch = response.json()["detection"]["coverage"]["batches"][0]
    assert batch["attempts"] == 2 and len(batch["attempt_errors"]) == 2
    assert requests[0].url.host == "model.example.test"


def test_configured_semantic_failure_blocks_tool_execution_even_without_rule_hits(client, monkeypatch):
    sid = session(client)
    configure_model(monkeypatch)
    monkeypatch.setattr(policy, "model_review", lambda payload: (None, "Controlled semantic service failure"))
    call = review(client, sid)
    assert call["decision"] == "block"
    assert "core.model_unavailable" in call["matched_rules"]
    assert "permit" not in call
    assert client.post(f"/api/calls/{call['id']}/execute", json={}).status_code == 409


def test_slow_semantic_review_does_not_hold_database_lock(client, monkeypatch):
    sid = session(client)
    configure_model(monkeypatch)
    entered, release = threading.Event(), threading.Event()

    def slow_model(payload):
        entered.set()
        assert release.wait(5), "Test must release the controlled model barrier"
        return model_answer(), None

    monkeypatch.setattr(detection, "model_review", slow_model)
    with ThreadPoolExecutor(max_workers=2) as pool:
        pending = pool.submit(source, client, sid, "Ordinary documentation awaiting model review.")
        try:
            assert entered.wait(2)
            dashboard = pool.submit(client.get, "/api/dashboard")
            response = dashboard.result(timeout=1)
            assert response.status_code == 200
            assert not pending.done(), "Dashboard must respond while semantic review is still waiting"
        finally:
            release.set()
        assert pending.result(timeout=2).status_code == 200


def test_source_context_change_revokes_previously_issued_permit(client):
    sid = session(client)
    call = review(client, sid)
    assert call["decision"] == "allow"
    assert source(client, sid, "Newly observed ordinary documentation.").status_code == 200
    before = client.app.state.service.fixture_effects(sid)
    claim = client.post(f"/api/calls/{call['id']}/claim", json={"permit": call["permit"], "parameter_hash": call["parameter_hash"]})
    assert claim.status_code == 409, claim.text
    assert client.app.state.service.fixture_effects(sid) == before
    fresh = review(client, sid)
    result = client.post(f"/api/calls/{fresh['id']}/execute", json={"permit": fresh["permit"]})
    assert result.status_code == 200 and result.json()["execution_status"] == "succeeded"


def test_configured_loopback_port_accepts_exact_origin_only(tmp_path, monkeypatch):
    for name in ["GUARD_API_TOKEN", "GUARD_MODEL_BASE_URL", "GUARD_MODEL_KEY", "GUARD_MODEL_NAME"]:
        monkeypatch.delenv(name, raising=False)
    with TestClient(create_app(data_dir=tmp_path), base_url="http://127.0.0.1:8899") as client:
        body = {"title": "custom port", "intent": "Read README"}
        allowed = client.post("/api/sessions", json=body, headers={"Origin": "http://127.0.0.1:8899"})
        assert allowed.status_code == 200, allowed.text
        for origin in ["http://127.0.0.1:8898", "http://attacker@127.0.0.1:8899", "null"]:
            refused = client.post("/api/sessions", json=body, headers={"Origin": origin})
            assert refused.status_code == 403, origin
        assert len(client.get("/api/sessions").json()) == 1


def test_expired_approved_call_rechecks_raw_arguments_without_inheriting_approval(client):
    created = client.post("/api/sessions", json={"title": "Recheck", "intent": "Create a report after confirmation", "scope": "development"})
    sid = created.json()["id"]
    original = review(client, sid, "fs.write", {"path": "reports/recheck.txt", "content": JSON_SECRET})
    assert original["decision"] == "confirm"
    approved = client.post(f"/api/approvals/{original['id']}", json={"approved": True}).json()
    assert approved["decision"] == "allow" and approved["permit_expires_at"].endswith("Z")
    service = client.app.state.service
    with service.store.transaction():
        record = service.require("call", original["id"])
        record["_permit"]["expires_at"] = 0
        service.store.put("call", record)
    assert client.post(f"/api/calls/{original['id']}/execute", json={"permit": approved["permit"]}).status_code == 409
    refreshed = client.post(f"/api/calls/{original['id']}/recheck", json={})
    assert refreshed.status_code == 200, refreshed.text
    fresh = refreshed.json()
    assert fresh["id"] != original["id"]
    assert fresh["decision"] == "confirm", "Prior user approval cannot authorize the replacement"
    assert fresh["execution_status"] == "pending"
    assert fresh["recheck_of_call_id"] == original["id"]
    assert "permit" not in fresh
    assert fresh["parameter_hash"] == original["parameter_hash"]
    assert service.require("call", fresh["id"])["args"]["content"] == JSON_SECRET
    assert PASSWORD not in refreshed.text and API_KEY not in refreshed.text
    assert client.post(f"/api/approvals/{original['id']}", json={"approved": True}).status_code == 409
    assert client.post(f"/api/calls/{original['id']}/recheck", json={}).status_code == 409
    again = client.post(f"/api/approvals/{fresh['id']}", json={"approved": True}).json()
    executed = client.post(f"/api/calls/{fresh['id']}/execute", json={"permit": again["permit"]})
    assert executed.status_code == 200 and executed.json()["execution_status"] == "succeeded"
    assert (service.fixture_root(sid) / "reports/recheck.txt").read_text(encoding="utf-8") == JSON_SECRET
    events = client.get(f"/api/sessions/{sid}").json()["events"]
    assert any(e["type"] == "call.rechecked" and e["details"]["replacement_call_id"] == fresh["id"] for e in events)


def test_execution_started_call_cannot_recheck_or_duplicate_effects(client):
    sid = session(client)
    original = review(client, sid)
    claimed = client.post(f"/api/calls/{original['id']}/claim", json={"permit": original["permit"], "parameter_hash": original["parameter_hash"]})
    assert claimed.status_code == 200
    assert claimed.json()["call"]["execution_status"] == "executing"
    assert client.post(f"/api/calls/{original['id']}/recheck", json={}).status_code == 409
    receipt = client.post(f"/api/calls/{original['id']}/receipt", json={"claim_id": claimed.json()["claim_id"], "status": "unknown", "detail": "Callback result cannot be confirmed", "result": None})
    assert receipt.status_code == 200
    assert client.post(f"/api/calls/{original['id']}/recheck", json={}).status_code == 409
    assert len(client.get(f"/api/sessions/{sid}").json()["calls"]) == 1


def test_pending_recheck_replaces_approval_queue_and_pending_metric(client):
    sid = client.post("/api/sessions", json={"title": "Pending replacement", "intent": "Write report after confirmation", "scope": "development"}).json()["id"]
    old = review(client, sid, "fs.write", {"path": "reports/report.txt", "content": "public summary"})
    assert old["decision"] == "confirm"
    replacement = client.post(f"/api/calls/{old['id']}/recheck", json={})
    assert replacement.status_code == 200, replacement.text
    assert replacement.json()["decision"] == "confirm"
    queue = client.get("/api/approvals").json()
    assert [c["id"] for c in queue] == [replacement.json()["id"]]
    assert client.get("/api/dashboard").json()["stats"]["pending"] == 1


@pytest.mark.parametrize("tool", ["git.push", "git.commit"])
def test_development_git_dry_run_parameter_does_not_grant_execution_authority(client, tool):
    sid = client.post("/api/sessions", json={"title": "Git candidate", "intent": "Review a proposed Git operation", "scope": "development"}).json()["id"]
    call = review(client, sid, tool, {"dry_run": True, "remote": "origin", "branch": "main"})
    assert call["decision"] == "confirm"
    assert "permit" not in call
    assert client.post(f"/api/calls/{call['id']}/execute", json={}).status_code == 409


def test_evidence_dag_distinguishes_agent_context_mcp_target_and_child_receipt(client):
    sid = session(client)
    public_source = source(client, sid, "Public installation instructions.").json()
    parent = client.post(f"/api/sessions/{sid}/calls", json={"tool": "agent.delegate", "args": {"task": "Summarize the public README", "scope": "read_only"}, "source_ids": [public_source["id"]], "agent_id": "main-agent", "mcp_server": "local-delegation-fixture"}).json()
    assert parent["decision"] == "allow"
    executed = client.post(f"/api/calls/{parent['id']}/execute", json={"permit": parent["permit"]}).json()
    assert executed["execution_status"] == "succeeded"
    child_id = executed["receipt"]["result"]["child_agent_id"]
    child_call = client.post(f"/api/sessions/{sid}/calls", json={"tool": "fs.read", "args": {"path": "README.md"}, "parent_call_id": parent["id"], "agent_id": child_id, "mcp_server": "document-service", "source_ids": [public_source["id"]]}).json()
    assert child_call["decision"] == "allow"
    blocked = client.post(f"/api/sessions/{sid}/calls", json={"tool": "git.push", "args": {"branch": "main"}, "agent_id": "main-agent", "mcp_server": "git-service"}).json()
    assert blocked["decision"] == "block"
    graph = client.get(f"/api/sessions/{sid}").json()["graph"]
    nodes = {n["id"]: n for n in graph["nodes"]}
    assert {"agent", "mcp", "child_agent", "call", "receipt", "source"}.issubset({n["type"] for n in nodes.values()})
    assert nodes["agent:" + parent["id"]]["label"] == "main-agent"
    assert nodes["agent:" + child_call["id"]]["label"] == child_id
    assert nodes["child:" + parent["id"]]["label"] == child_id
    assert "未启动" in nodes["child:" + parent["id"]]["detail"]
    blocked_targets = [e for e in graph["edges"] if e["source"] == blocked["id"] and e["target"] == "mcp:" + blocked["id"]]
    assert blocked_targets == [{"source": blocked["id"], "target": "mcp:" + blocked["id"], "label": "候选接收目标", "type": "target"}]
    assert blocked["id"] + ":receipt" not in nodes
    # Kahn's algorithm validates acyclicity independently of the visual layout.
    indegree = {identifier: 0 for identifier in nodes}
    adjacency = {identifier: [] for identifier in nodes}
    for edge in graph["edges"]:
        assert edge["source"] in nodes and edge["target"] in nodes
        adjacency[edge["source"]].append(edge["target"])
        indegree[edge["target"]] += 1
    ready = [identifier for identifier, count in indegree.items() if count == 0]
    visited = 0
    while ready:
        identifier = ready.pop()
        visited += 1
        for target in adjacency[identifier]:
            indegree[target] -= 1
            if indegree[target] == 0:
                ready.append(target)
    assert visited == len(nodes), "Repeated Agent and MCP identities must not create graph cycles"
