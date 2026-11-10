"""Contract tests for pinned Hermes callbacks, without importing its LLM dependencies.

These prove adapter behavior against the statically inspected function contracts;
they do not constitute a real Hermes/model integration test.
"""
import copy
import json
from types import SimpleNamespace

import pytest

from adapters.hermes.adapter import AdapterDenied, Binding, HermesGuardAdapter
from adapters.sdk import GuardClient, GuardDenied, GuardUnavailable, ReceiptUnconfirmed, parameter_hash


class Agent:
    def __init__(self):
        self._memory_store = None


class Client:
    def __init__(self):
        self.decision = "allow"
        self.content_decision = "allow"
        self.calls = []
        self.sources = []
        self.claimed = 0
        self.raise_review = False
        self.lose_receipt = False

    def ingest(self, session_id, source_type, content, resource, **metadata):
        item = {"id": f"source-{len(self.sources)}", "decision": self.content_decision,
                "type": source_type, "content": content, "resource": resource}
        self.sources.append(item)
        return item

    def review(self, session_id, tool, args, **context):
        if self.raise_review:
            raise GuardUnavailable("test outage")
        call = {"id": f"call-{len(self.calls)}", "decision": self.decision, "tool": tool,
                "parameter_hash": parameter_hash(tool, args), "args": copy.deepcopy(args), **context}
        self.calls.append(call)
        return call

    def execute_reviewed(self, call, tool, args, callback):
        if call["decision"] != "allow":
            raise GuardDenied(call)
        assert call["parameter_hash"] == parameter_hash(tool, args)
        self.claimed += 1
        result = callback(copy.deepcopy(args))
        if self.lose_receipt:
            raise ReceiptUnconfirmed(call["id"])
        return result


@pytest.fixture
def wired(tmp_path):
    client = Client()
    adapter = HermesGuardAdapter(client, tmp_path)
    agent = Agent()
    adapter._attach(agent, Binding("session-test", "main", "read_only"))

    # This mimics the actual Hermes callback timing: upstream middleware has
    # already rewritten arguments by the time it invokes the supplied callback.
    def middleware(agent, *, function_name, function_args, execute, **kw):
        final = copy.deepcopy(function_args)
        final.update(kw.get("middleware_rewrite", {}))
        return SimpleNamespace(result=execute(final), blocked=False, args=final)

    def commit(agent, messages, ref, function_result, **kw):
        messages.append(function_result)
        return function_result

    class Facade:
        def run_conversation(self, user_message, system_message=None, conversation_history=None, **kw):
            return user_message

    class Memory:
        def format_for_system_prompt(self, target):
            return "stored note"

        @staticmethod
        def _write_file(path, entries):
            path.write_text("\n".join(entries))

    def child_factory(task_index, goal, context, toolsets, model, max_iterations, task_count, parent_agent):
        child = Agent()
        child._subagent_id = f"child-{task_index}"
        return child

    modules = {
        "agent.tool_executor": SimpleNamespace(_run_agent_tool_execution_middleware=middleware, _commit_tool_result=commit),
        "agent.turn_facade": SimpleNamespace(TurnFacadeMixin=Facade),
        "tools.memory_tool_store": SimpleNamespace(MemoryStore=Memory),
        "tools.delegate_tool": SimpleNamespace(_build_child_agent=child_factory),
    }
    adapter._install_hooks(modules)
    return adapter, client, agent, modules


def invoke(wired, name, args, callback, **extra):
    adapter, client, agent, modules = wired
    return modules["agent.tool_executor"]._run_agent_tool_execution_middleware(
        agent, function_name=name, function_args=args, execute=callback,
        effective_task_id="t", tool_call_id="hermes-call", **extra)


@pytest.mark.parametrize("decision", ["block", "confirm"])
def test_denied_or_pending_never_calls_native(wired, decision):
    wired[1].decision = decision
    effects = []
    outcome = invoke(wired, "read_file", {"path": "README.md"}, effects.append)
    assert outcome.blocked and not effects and wired[1].claimed == 0
    assert json.loads(outcome.result)["aegisguard"]["decision"] == decision


def test_final_rewritten_arguments_are_reviewed_and_executed(wired):
    effects = []
    invoke(wired, "read_file", {"path": "old.md"}, effects.append,
           middleware_rewrite={"path": "new.md"})
    assert wired[1].calls[0]["args"]["path"] == "new.md"
    assert effects[0]["path"] == str(wired[0].workspace / "new.md")
    assert wired[1].calls[0]["args"]["hermes"]["original_args"]["path"] == "new.md"


@pytest.mark.parametrize("tool,args", [("write_file", {"path": "new.md", "content": "text"}),
                                       ("terminal", {"command": "echo hello"}),
                                       ("memory", {"content": "hello"}),
                                       ("mcp_fake_read", {"path": "README.md"})])
def test_unverified_native_effects_are_denied_even_if_backend_allows(wired, tool, args):
    effects = []
    assert invoke(wired, tool, args, effects.append).blocked
    assert not effects and wired[1].claimed == 0


def test_backend_outage_never_dispatches(wired):
    wired[1].raise_review = True
    effects = []
    assert invoke(wired, "read_file", {"path": "README.md"}, effects.append).blocked
    assert not effects


def test_unbound_agent_cannot_use_global_hook(wired):
    wired = (wired[0], wired[1], Agent(), wired[3])
    effects = []
    assert invoke(wired, "read_file", {"path": "README.md"}, effects.append).blocked
    assert not effects


def test_path_escape_fails_before_review_or_execution(wired):
    effects = []
    assert invoke(wired, "read_file", {"path": "../outside"}, effects.append).blocked
    assert not effects and not wired[1].calls


def test_lost_receipt_halts_agent_and_does_not_claim_not_executed(wired):
    wired[1].lose_receipt = True
    effects = []
    outcome = invoke(wired, "read_file", {"path": "README.md"}, effects.append)
    assert len(effects) == 1
    assert not outcome.blocked
    assert json.loads(outcome.result)["aegisguard"]["native_callback_ran"] is True
    assert invoke(wired, "read_file", {"path": "README.md"}, effects.append).blocked
    assert len(effects) == 1


def test_result_quarantine_precedes_context_append(wired):
    wired[1].content_decision = "block"
    messages = []
    ref = SimpleNamespace(name="read_file", call_id="host-1")
    wired[3]["agent.tool_executor"]._commit_tool_result(wired[2], messages, ref, "untrusted-injection")
    assert "untrusted-injection" not in str(messages)
    assert wired[1].sources[-1]["content"] == "untrusted-injection"


def test_memory_without_binding_is_not_inserted_and_native_write_is_blocked(wired, tmp_path):
    memory = wired[3]["tools.memory_tool_store"].MemoryStore()
    assert memory.format_for_system_prompt("memory") is None
    with pytest.raises(AdapterDenied):
        memory._write_file(tmp_path / "MEMORY.md", ["pollution"])
    assert not (tmp_path / "MEMORY.md").exists()


def test_children_inherit_authorization_and_parent_call_before_native_run(wired):
    children = []

    def spawn(args):
        child = wired[3]["tools.delegate_tool"]._build_child_agent(
            1, "Read README", "", ["file"], "", 3, 1, wired[2])
        children.append(child)
        return "spawned"

    outcome = invoke(wired, "delegate_task", {"goal": "Read README"}, spawn)
    assert not outcome.blocked
    child_binding = wired[0]._binding(children[0])
    assert child_binding.scope == "read_only"
    assert child_binding.session_id == "session-test"
    assert child_binding.parent_call_id == "call-0"


def test_restored_history_is_reviewed_before_turn(wired):
    facade = wired[3]["agent.turn_facade"].TurnFacadeMixin
    result = facade.run_conversation(wired[2], "read doc", conversation_history=[{"role": "tool", "content": "old"}])
    assert result == "read doc"
    assert [s["type"] for s in wired[1].sources] == ["memory", "user_input"]


def test_adapter_read_uses_real_backend_claim_and_receipt(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from backend.main import create_app

    for key in ("GUARD_API_TOKEN", "GUARD_MODEL_BASE_URL", "GUARD_MODEL_KEY", "GUARD_MODEL_NAME"):
        monkeypatch.delenv(key, raising=False)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "README.md").write_text("A real local read result", encoding="utf-8")
    with TestClient(create_app(data_dir=str(tmp_path / "backend"))) as transport:
        sdk = GuardClient(client=transport)
        session = sdk.session("Hermes adapter contract", "Read README", "read_only")
        adapter = HermesGuardAdapter(sdk, workspace)
        agent = Agent()
        adapter._attach(agent, Binding(session["id"], "hermes-main", "read_only"))
        result = adapter.dispatch(agent, "read_file", {"path": "README.md"},
                                  lambda args: __import__("pathlib").Path(args["path"]).read_text(encoding="utf-8"))
        assert result == "A real local read result"
        details = transport.get(f"/api/sessions/{session['id']}").json()
        assert details["calls"][0]["execution_status"] == "succeeded"
        assert details["calls"][0]["receipt"]["result"] == result
