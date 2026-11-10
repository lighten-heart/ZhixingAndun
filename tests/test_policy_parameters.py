"""Parameter DSL regressions: S2/api and S2/sdk in release-v3.md.

Actual API writes, review decisions and callback effects are separate oracles.
No live model, arbitrary shell, remote network or real credentials are used.
"""
import copy

import pytest
from fastapi.testclient import TestClient

from adapters.sdk import GuardClient, GuardDenied
from backend.main import create_app


@pytest.fixture
def client(tmp_path, monkeypatch):
    for key in ("GUARD_API_TOKEN", "GUARD_MODEL_BASE_URL", "GUARD_MODEL_KEY", "GUARD_MODEL_NAME"):
        monkeypatch.delenv(key, raising=False)
    with TestClient(create_app(data_dir=tmp_path)) as instance:
        yield instance


def condition(path="$.mode", operator="equals", value="restricted"):
    return {"path": path, "operator": operator, "value": value}


def policy_payload(client, parameters, action="block", tools=None):
    payload = client.get("/api/policies").json()
    payload["rules"].append({"id": "custom.parameters", "name": "Parameter restriction",
                             "description": "Parameter restriction", "enabled": True,
                             "priority": 90, "condition": {"tools": tools or ["fs.read"], "parameters": parameters},
                             "action": action, "mandatory": False})
    return payload


def install(client, parameters, **kwargs):
    response = client.put("/api/policies", json=policy_payload(client, parameters, **kwargs))
    assert response.status_code == 200, response.text
    return response.json()


def session(client):
    return GuardClient(client=client).session("Parameter contract", "Read public README", "read_only")["id"]


def call(client, sid, args):
    response = client.post(f"/api/sessions/{sid}/calls", json={"tool": "fs.read", "args": {"path": "README.md", **args}})
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.parametrize("predicate,blocked,allowed", [
    (condition(), {"mode": "restricted"}, {"mode": "public"}),
    (condition("$.options.labels[1]", "enum", ["private", "internal"]),
     {"options": {"labels": ["public", "internal"]}}, {"options": {"labels": ["public", "external"]}}),
    (condition('$["a.b"]["分类"]', "equals", "秘密"),
     {"a.b": {"分类": "秘密"}}, {"a.b": {"分类": "公开"}}),
    (condition("$.label", "pattern", r"^restricted/[A-Za-z0-9_-]+\.txt$"),
     {"label": "restricted/Doc_1.txt"}, {"label": "public/Doc_1.txt"}),
    (condition("$.label", "pattern", r"[A-Z]{2,4}"), {"label": "ABC"}, {"label": "prefixABC"}),
    (condition("$.flag", "type", "boolean"), {"flag": True}, {"flag": 1}),
    (condition("$.flag", "type", "null"), {"flag": None}, {"flag": "null"}),
    (condition("$.count", "type", "number"), {"count": 1}, {"count": "1"}),
    (condition("$.count", "type", "integer"), {"count": 1}, {"count": 1.0}),
    (condition("$.label", "equals", "Case.TXT"), {"label": "Case.TXT"}, {"label": "case.txt"}),
])
def test_parameter_policy_has_positive_and_negative_api_controls(client, predicate, blocked, allowed):
    saved = install(client, [predicate])
    assert saved["rules"][-1]["condition"]["parameters"] == [predicate]
    sid = session(client)
    denied, normal = call(client, sid, blocked), call(client, sid, allowed)
    assert denied["decision"] == "block" and "custom.parameters" in denied["matched_rules"]
    assert normal["decision"] == "allow", normal
    assert client.post(f"/api/calls/{denied['id']}/execute", json={}).status_code >= 400


@pytest.mark.parametrize("parameters", [
    [], [condition()] * 17,
    [{"path": "$.mode", "operator": "equals"}],
    [{**condition(), "negate": True}],
    [condition("$.mode", "script", "true")],
    [condition("$.mode", "equals", None)],
    [condition("$.mode", "equals", {})],
    [condition("$.mode", "enum", [])],
    [condition("$.mode", "enum", [None])],
    [condition("$.mode", "enum", list(range(65)))],
    [condition("$.mode", "type", "str")],
    [condition("$.mode", "pattern", 123)],
    [condition("$..mode")], [condition("$.items[*]")], [condition("$.items[-1]")],
    [condition("$.items[01]")], [condition("$.items[65536]")],
    [condition("$['mode']")], [condition("$.items[?(@.enabled)]")],
    [condition("$" + ".x" * 17)],
    [condition("$.mode", "equals", "x" * 4097)],
    [condition("$.mode", "pattern", "x" * 129)],
])
def test_invalid_parameter_dsl_is_rejected_atomically(client, parameters):
    before = client.get("/api/policies").json()
    response = client.put("/api/policies", json=policy_payload(client, parameters))
    assert response.status_code == 422, response.text
    assert client.get("/api/policies").json() == before


@pytest.mark.parametrize("pattern", [
    "(a+)+$", "a|b", "(?=a)a", r"(a)\1", "a*a*", "a{128}a{128}",
    "a{129}", "a{4,2}", "[", "[z-a]", "[a&&b]", r"\bword\b", "^a^b$",
])
def test_unbounded_regex_features_are_rejected_before_storage(client, pattern):
    before = client.get("/api/policies").json()
    response = client.put("/api/policies", json=policy_payload(client, [condition("$.mode", "pattern", pattern)]))
    assert response.status_code == 422, (pattern, response.text)
    assert client.get("/api/policies").json() == before


@pytest.mark.parametrize("predicate,args", [
    (condition(), {}),
    (condition(), {"mode": 1}),
    (condition("$.mode", "equals", True), {"mode": 1}),
    (condition("$.mode", "equals", 1), {"mode": True}),
    (condition("$.mode", "pattern", "a+"), {"mode": ["aaa"]}),
    (condition("$.mode", "pattern", "a+"), {"mode": "a" * 4097}),
    (condition("$.mode[0]"), {"mode": {"0": "restricted"}}),
    (condition("$.mode[1]"), {"mode": ["restricted"]}),
])
def test_unevaluable_parameters_fail_closed_even_with_allow_rule(client, predicate, args):
    install(client, [predicate], action="allow")
    sid = session(client)
    denied = call(client, sid, args)
    assert denied["decision"] == "block"
    assert "core.parameter_evaluation" in denied["matched_rules"]
    assert not denied.get("permit")
    assert client.post(f"/api/approvals/{denied['id']}", json={"approved": True}).status_code >= 400


def test_and_conditions_do_not_hide_missing_later_parameter(client):
    install(client, [condition(), condition("$.other")])
    denied = call(client, session(client), {"mode": "public"})
    assert denied["decision"] == "block"
    assert "core.parameter_evaluation" in denied["matched_rules"]


def test_irrelevant_tool_conditions_do_not_require_foreign_parameters(client):
    install(client, [condition("$.branch")], tools=["git.push"])
    assert call(client, session(client), {})["decision"] == "allow"


def test_multiple_parameter_conditions_are_conjunctive(client):
    install(client, [condition(), condition("$.level", "enum", [2, 3])])
    sid = session(client)
    assert call(client, sid, {"mode": "restricted", "level": 2})["decision"] == "block"
    assert call(client, sid, {"mode": "restricted", "level": 1})["decision"] == "allow"
    assert call(client, sid, {"mode": "public", "level": 2})["decision"] == "allow"


def test_safe_pattern_bound_is_usable_at_long_input_limit(client):
    install(client, [condition("$.label", "pattern", "a+b")])
    sid = session(client)
    assert call(client, sid, {"label": "a" * 4095 + "b"})["decision"] == "block"
    assert call(client, sid, {"label": "a" * 4096})["decision"] == "allow"


def test_sdk_denies_rule_and_missing_value_without_callback_but_preserves_allowed_snapshot(client):
    install(client, [condition()])
    sdk, sid, effects = GuardClient(client=client), session(client), []

    def callback(args):
        effects.append(copy.deepcopy(args))
        return {"read": args["path"], "classification": args["mode"]}

    for candidate in ({"path": "README.md", "mode": "restricted"}, {"path": "README.md"}):
        with pytest.raises(GuardDenied):
            sdk.execute_guarded(sid, "fs.read", candidate, callback)
    assert effects == []
    expected = {"path": "README.md", "mode": "public", "options": {"case": "Case.TXT"}}
    result = sdk.execute_guarded(sid, "fs.read", expected, callback)
    assert result == {"read": "README.md", "classification": "public"}
    assert effects == [expected]
    stored = client.get(f"/api/sessions/{sid}").json()["calls"]
    assert sum(c["execution_status"] == "succeeded" for c in stored) == 1


def test_parameter_allow_cannot_override_mandatory_path_denial(client):
    install(client, [condition("$.path", "type", "string")], action="allow")
    denied = call(client, session(client), {"path": "~/.ssh/id_rsa"})
    assert denied["decision"] == "block" and "core.sensitive_path" in denied["matched_rules"]


def test_parameter_condition_cannot_be_added_to_mandatory_rule(client):
    before = client.get("/api/policies").json()
    changed = copy.deepcopy(before)
    mandatory = next(rule for rule in changed["rules"] if rule["mandatory"])
    mandatory["condition"]["parameters"] = [condition()]
    assert client.put("/api/policies", json=changed).status_code >= 400
    assert client.get("/api/policies").json() == before
