"""Guard the real dispatch callback in a statically verified Hermes baseline.

No upstream source is modified. Hooks are installed process-wide, so an unbound
agent is denied. Construct agents through create_agent() in a dedicated process.
"""
from __future__ import annotations

import copy
import contextvars
import functools
import hashlib
import importlib
import inspect
import json
import sys
import threading
import weakref
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from adapters.sdk import GuardDenied, GuardUnavailable, ReceiptUnconfirmed

BASELINE = "be5e9f72c6681af9dfb75bf480f08844f1499949"
_constructing = contextvars.ContextVar("aegis_hermes_constructing", default=None)
_parent_call = contextvars.ContextVar("aegis_hermes_parent_call", default=None)


class BaselineMismatch(RuntimeError):
    pass


class AdapterDenied(RuntimeError):
    pass


def verify_baseline(root: str | Path) -> dict:
    """Check actual source bytes, normalizing Git's optional CRLF checkout only."""
    root = Path(root).resolve(strict=True)
    manifest = json.loads(Path(__file__).with_name("baseline.json").read_text(encoding="utf-8"))
    checked, errors = [], []
    for relative, expected in manifest["files"].items():
        path = root / relative
        if not path.is_file():
            errors.append(f"missing {relative}")
            continue
        digest = hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
        if digest != expected:
            errors.append(f"changed {relative}")
        else:
            checked.append(relative)
    if errors:
        raise BaselineMismatch("Hermes baseline verification failed: " + "; ".join(errors))
    return {"commit": BASELINE, "status": "static_verified", "files": checked,
            "runtime_status": "not_verified", "root": str(root)}


@dataclass
class Binding:
    session_id: str
    agent_id: str
    scope: str
    parent_call_id: str | None = None
    source_ids: list[str] = field(default_factory=list)
    halted: bool = False


def _text(value: Any) -> str:
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True)


def _notice(reason: str, *, executed: bool = False, decision: str = "block", call_id=None) -> str:
    # Never echo untrusted text or sensitive parameters into an error result.
    return json.dumps({"error": "AegisGuard withheld this operation or content",
                       "aegisguard": {"reason": reason, "decision": decision,
                                      "native_callback_ran": executed, "call_id": call_id}},
                      ensure_ascii=False)


class HermesGuardAdapter:
    """A bounded local read/delegation profile for the pinned Hermes version.

    Native writes, shell execution and MCP direct dispatch remain denied until
    an execution-boundary implementation for that environment has been verified.
    The project's separate fixture executor demonstrates their policy decisions.
    """

    def __init__(self, client, workspace: str | Path):
        self.client = client
        self.workspace = Path(workspace).resolve(strict=True)
        if not self.workspace.is_dir():
            raise ValueError("workspace must be an existing directory")
        self._bindings = weakref.WeakKeyDictionary()
        self._stores = weakref.WeakKeyDictionary()
        self._native_calls = weakref.WeakKeyDictionary()
        self._lock = threading.RLock()
        self._installed = False
        self._originals: list[tuple[Any, str, Any]] = []
        self.baseline = None

    def _binding(self, agent) -> Binding:
        with self._lock:
            binding = self._bindings.get(agent)
        if binding is None:
            raise AdapterDenied("Agent has no trusted AegisGuard task binding")
        if binding.halted:
            raise AdapterDenied("Agent halted after an unconfirmed execution; manual reconciliation required")
        return binding

    def _attach(self, agent, binding: Binding):
        with self._lock:
            self._bindings[agent] = binding
            store = getattr(agent, "_memory_store", None)
            if store is not None:
                self._stores[store] = binding
        return agent

    def _admit(self, binding, value, source_type, resource, **metadata):
        source = self.client.ingest(binding.session_id, source_type, _text(value), resource,
                                    metadata={"host": "hermes", "commit": BASELINE,
                                              "agent_id": binding.agent_id, **metadata})
        with self._lock:
            if source.get("id"):
                binding.source_ids.append(source["id"])
        if source.get("decision") != "allow":
            raise AdapterDenied("Content admission requires an allow decision")
        return source

    def _map_request(self, name: str, arguments: dict) -> tuple[str, dict, bool]:
        original = copy.deepcopy(arguments)
        effective = copy.deepcopy(arguments)
        allowed = False
        if name in {"read_file", "write_file"}:
            canonical = "fs.read" if name == "read_file" else "fs.write"
            raw = arguments.get("path")
            if not isinstance(raw, str) or not raw:
                raise AdapterDenied("Missing file path")
            path = Path(raw).expanduser()
            path = (self.workspace / path if not path.is_absolute() else path).resolve(strict=False)
            # A service-owned workspace is required; this check is not a TOCTOU sandbox.
            try:
                path.relative_to(self.workspace)
            except ValueError as exc:
                raise AdapterDenied("File target is outside the bound local workspace") from exc
            effective["path"] = str(path)
            args = {"path": path.relative_to(self.workspace).as_posix(),
                    "execution_environment": {"workspace": str(self.workspace), "type": "local"}}
            if name == "write_file":
                args["content"] = arguments.get("content", "")
            allowed = name == "read_file"
        elif name == "terminal":
            canonical, args = "exec", {"command": arguments.get("command", ""),
                                        "workdir": arguments.get("workdir", str(self.workspace))}
        elif name == "delegate_task":
            canonical = "agent.delegate"
            tasks = arguments.get("tasks", [])
            goals = [str(item.get("goal", "")) for item in tasks if isinstance(item, dict)] if isinstance(tasks, list) else []
            task = arguments.get("goal") or "; ".join(goals) or "Manage child agent: " + str(arguments.get("action", "spawn"))
            args = {"task": task, "context": arguments.get("context", ""),
                    "tasks": arguments.get("tasks", []), "message": arguments.get("message", ""),
                    "action": arguments.get("action", "spawn")}
            # Includes control actions so steer content is checked before forwarding.
            allowed = True
        else:
            canonical, args = "hermes.unmapped", {}
        args["hermes"] = {"tool_name": name, "original_args": original,
                          "execution_args": effective, "baseline": BASELINE}
        return canonical, args, allowed

    def dispatch(self, agent, name: str, arguments: dict, execute, *, tool_call_id=""):
        """Called with final arguments AFTER upstream rewrite middleware."""
        binding = self._binding(agent)
        canonical, args, supported = self._map_request(name, arguments)
        with self._lock:
            refs = list(binding.source_ids)
        context = {"agent_id": binding.agent_id, "source_ids": refs,
                   "parent_call_id": binding.parent_call_id}
        call = self.client.review(binding.session_id, canonical, args, **context)
        if not supported:
            # Review documents recognized risks, but no permit is claimed for an
            # operation whose native effects cannot be controlled by this profile.
            raise AdapterDenied(f"Native operation {name} is outside this verified execution profile")

        def native_callback(snapshot):
            if snapshot.get("hermes", {}).get("tool_name") != name:
                raise AdapterDenied("Reviewed native tool identity changed")
            interrupted = getattr(agent, "is_interrupted", None)
            if interrupted is not None and interrupted():
                raise AdapterDenied("Hermes task was cancelled before native dispatch")
            token = _parent_call.set(call["id"])
            try:
                with self._lock:
                    self._native_calls.setdefault(agent, {})[tool_call_id] = True
                return execute(copy.deepcopy(snapshot["hermes"]["execution_args"]))
            finally:
                _parent_call.reset(token)

        try:
            return self.client.execute_reviewed(call, canonical, args, native_callback)
        except ReceiptUnconfirmed:
            # Never turn this into a harmless retryable tool error.
            binding.halted = True
            raise

    def _replace(self, module, name, replacement):
        self._originals.append((module, name, getattr(module, name)))
        setattr(module, name, replacement)

    def install(self, hermes_root: str | Path):
        if self._installed:
            return self.baseline
        root = Path(hermes_root).resolve(strict=True)
        self.baseline = verify_baseline(root)
        sys.path.insert(0, str(root))
        modules = {}
        for name in ("agent.tool_executor", "agent.turn_facade", "tools.memory_tool_store",
                     "tools.delegate_tool", "tools.terminal_tool", "run_agent"):
            module = importlib.import_module(name)
            if not Path(module.__file__).resolve().is_relative_to(root):
                raise BaselineMismatch(f"Module {name} was imported from a different checkout")
            modules[name] = module
        executor = modules["agent.tool_executor"]
        if getattr(executor, "_aegisguard_installed", False):
            raise RuntimeError("A Hermes guard is already installed in this process")
        env = modules["tools.terminal_tool"]._get_env_config()
        if env.get("env_type") != "local":
            raise AdapterDenied("Only the local Hermes execution environment has been mapped")
        self._install_hooks(modules)
        executor._aegisguard_installed = True
        self._installed = True
        self._agent_class = modules["run_agent"].AIAgent
        return self.baseline

    def _install_hooks(self, modules):
        """Separated to test the exact upstream callback contracts without its dependencies."""
        executor = modules["agent.tool_executor"]
        original_dispatch = executor._run_agent_tool_execution_middleware

        @functools.wraps(original_dispatch)
        def guarded_dispatch(agent, **kwargs):
            native = kwargs["execute"]
            denied = False

            def checked(final_args):
                nonlocal denied
                try:
                    return self.dispatch(agent, kwargs["function_name"], final_args, native,
                                         tool_call_id=kwargs.get("tool_call_id", ""))
                except GuardDenied as exc:
                    denied = True
                    return _notice("Policy withheld native dispatch", decision=exc.call.get("decision", "block"),
                                   call_id=exc.call.get("id"))
                except (AdapterDenied, GuardUnavailable):
                    denied = True
                    return _notice("Native dispatch could not be authorized")
                except ReceiptUnconfirmed as exc:
                    # Callback may already have had effects; never mark this as blocked.
                    return _notice("Execution receipt unconfirmed; agent halted; do not retry",
                                   executed=True, call_id=exc.call_id)

            outcome = original_dispatch(agent, **{**kwargs, "execute": checked})
            if denied:
                outcome.blocked = True
            return outcome

        self._replace(executor, "_run_agent_tool_execution_middleware", guarded_dispatch)
        original_commit = executor._commit_tool_result

        @functools.wraps(original_commit)
        def guarded_commit(agent, messages, ref, function_result, **kwargs):
            with self._lock:
                callback_ran = self._native_calls.get(agent, {}).pop(ref.call_id, False)
            try:
                binding = self._binding(agent)
                self._admit(binding, function_result, "mcp_result", f"hermes://tools/{ref.name}",
                            host_tool_call_id=ref.call_id, tool_name=ref.name)
            except (AdapterDenied, GuardUnavailable):
                function_result = _notice("Tool result content withheld before model context", executed=callback_ran)
            return original_commit(agent, messages, ref, function_result, **kwargs)

        self._replace(executor, "_commit_tool_result", guarded_commit)
        facade = modules["agent.turn_facade"].TurnFacadeMixin
        original_turn = facade.run_conversation
        turn_signature = inspect.signature(original_turn)

        @functools.wraps(original_turn)
        def guarded_turn(agent, *args, **kwargs):
            bound = turn_signature.bind(agent, *args, **kwargs)
            binding = self._binding(agent)
            history = bound.arguments.get("conversation_history")
            if history:
                # Resume paths are not silently treated as trusted user input.
                self._admit(binding, history, "memory", "hermes://restored-conversation")
            self._admit(binding, bound.arguments.get("user_message", ""), "user_input", "hermes://user-input")
            return original_turn(agent, *args, **kwargs)

        self._replace(facade, "run_conversation", guarded_turn)
        store_class = modules["tools.memory_tool_store"].MemoryStore
        original_prompt = store_class.format_for_system_prompt

        @functools.wraps(original_prompt)
        def guarded_memory_prompt(store, target):
            content = original_prompt(store, target)
            if not content:
                return content
            binding = self._stores.get(store) or _constructing.get()
            if binding is None:
                return None
            try:
                self._admit(binding, content, "memory", f"hermes://builtin-memory/{target}")
            except (AdapterDenied, GuardUnavailable):
                return None
            return content

        self._replace(store_class, "format_for_system_prompt", guarded_memory_prompt)
        # Block writes at the final actual persistence function, including direct
        # /memory approval paths. Backend memory demonstration is a separate store.
        original_write = inspect.getattr_static(store_class, "_write_file")

        def denied_memory_write(*args, **kwargs):
            raise AdapterDenied("Native Hermes memory persistence is not enabled in this profile")

        self._originals.append((store_class, "_write_file", original_write))
        store_class._write_file = staticmethod(denied_memory_write)
        delegate = modules["tools.delegate_tool"]
        original_child = delegate._build_child_agent
        child_signature = inspect.signature(original_child)

        @functools.wraps(original_child)
        def guarded_child(*args, **kwargs):
            bound = child_signature.bind(*args, **kwargs)
            parent = self._binding(bound.arguments["parent_agent"])
            child_binding = Binding(parent.session_id, "hermes-child", parent.scope,
                                    parent_call_id=_parent_call.get(), source_ids=list(parent.source_ids))
            token = _constructing.set(child_binding)
            try:
                child = original_child(*args, **kwargs)
            finally:
                _constructing.reset(token)
            child_binding.agent_id = str(getattr(child, "_subagent_id", "hermes-child"))
            return self._attach(child, child_binding)

        self._replace(delegate, "_build_child_agent", guarded_child)

    def create_agent(self, intent: str, *, title="Hermes 受控任务", scope="read_only", **agent_options):
        if not self._installed:
            raise RuntimeError("Call install(hermes_root) first")
        forbidden = {"skip_memory", "skip_context_files", "skip_background_review", "memory_manager",
                     "prefill_messages", "cwd", "ephemeral_system_prompt", "enabled_toolsets", "disabled_toolsets"}
        if forbidden.intersection(agent_options):
            raise ValueError("Controlled startup options cannot be overridden")
        session = self.client.session(title, intent, scope)
        binding = Binding(session["id"], "hermes-main", scope)
        self._admit(binding, intent, "user_input", "hermes://task-entry")
        token = _constructing.set(binding)
        try:
            agent = self._agent_class(
                **{"enabled_toolsets": ["file", "delegation"], **agent_options},
                skip_memory=True, skip_context_files=True, skip_background_review=True,
                cwd=str(self.workspace))
        finally:
            _constructing.reset(token)
        if getattr(agent, "_memory_manager", None) is not None:
            raise AdapterDenied("External memory providers are outside this integration profile")
        return self._attach(agent, binding), session
