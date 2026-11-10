"""Synchronous guard SDK with single-use permits and explicit execution receipts."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from typing import Any, Callable

import httpx


def parameter_hash(tool: str, args: dict) -> str:
    return hashlib.sha256(json.dumps({"tool": tool, "args": args}, ensure_ascii=False,
                                    sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class GuardUnavailable(RuntimeError):
    """A failed review must never fall through to execution."""


class ExecutionOutcomeUnknown(RuntimeError):
    """A transport/protocol failure cannot determine whether effects occurred."""


class GuardDenied(RuntimeError):
    def __init__(self, call: dict, *, executed: bool = False):
        self.call = call
        self.executed = executed
        super().__init__(f"{call.get('decision', 'block')}: " + "; ".join(call.get("reasons", [])))


class ReceiptUnconfirmed(RuntimeError):
    """The callback ran, but its receipt could not be persisted. Do not retry it."""
    def __init__(self, call_id: str):
        self.call_id = call_id
        super().__init__(f"Call {call_id} executed but receipt is unconfirmed; do not replay")


class GuardClient:
    def __init__(self, base_url: str | None = None, token: str | None = None,
                 timeout: float = 45, client: httpx.Client | None = None):
        self._owns_client = client is None
        self.client = client or httpx.Client(
            base_url=(base_url or os.getenv("GUARD_URL", "http://127.0.0.1:8765")).rstrip("/"),
            headers={"X-Guard-Token": token or os.getenv("GUARD_API_TOKEN", "")}, timeout=timeout,
            follow_redirects=False, trust_env=False)

    def close(self):
        if self._owns_client:
            self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _request(self, method: str, path: str, body: dict | None = None) -> Any:
        try:
            response = self.client.request(method, path, json=body)
            response.raise_for_status()
            return response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise GuardUnavailable(f"Guard request failed ({method} {path}); execution withheld") from exc

    def session(self, title: str, intent: str, scope: str = "read_only") -> dict:
        return self._request("POST", "/api/sessions", {"title": title, "intent": intent, "scope": scope})

    def ingest(self, session_id: str, source_type: str, content: str,
               resource: str = "", **kwargs) -> dict:
        return self._request("POST", f"/api/sessions/{session_id}/sources",
                             {"type": source_type, "content": content, "resource": resource, **kwargs})

    def review(self, session_id: str, tool: str, args: dict, **context) -> dict:
        return self._request("POST", f"/api/sessions/{session_id}/calls",
                             {"tool": tool, "args": args, "execution_owner": "adapter", **context})

    def save_memory(self, session_id: str, content: str, label: str = "Agent memory") -> dict:
        return self._request("POST", "/api/memories", {"session_id": session_id, "content": content, "label": label})

    def load_memory(self, session_id: str, memory_id: str, recipient: str, purpose: str = "task") -> dict:
        source = self._request("POST", f"/api/sessions/{session_id}/memory/{memory_id}", {})
        admission = self._request("POST", f"/api/sessions/{session_id}/context-admission",
                                  {"source_id": source["id"], "recipient": recipient, "purpose": purpose})
        if admission.get("decision") != "allow":
            raise GuardDenied({"decision": "block", "reasons": ["Memory is not admitted to this recipient"]})
        return source

    def bound_file(self, session_id, workspace, path, *, content=None, approve=None, **context):
        """Controlled text I/O, retaining the same reviewed file/parent handle."""
        from .file_boundary import BoundFile
        with BoundFile(workspace, path, write=content is not None) as bound:
            tool = "fs.write" if content is not None else "fs.read"
            args = {"path": path, **({"content": content} if content is not None else {})}
            call = self.review(session_id, tool, args, resource_facts=bound.facts, **context)
            if call.get("decision") == "confirm" and approve:
                call = approve(call)
            return self.execute_reviewed(call, tool, args, lambda frozen: bound.execute(frozen.get("content")))

    def execute_reviewed(self, call: dict, tool: str, args: dict,
                         callback: Callable[[dict], Any]) -> Any:
        """callback receives an isolated exact-argument snapshot; it must not substitute arguments.

        This SDK is a cooperative trusted adapter, not an OS sandbox. Callback internals,
        destination redirections, paths and subprocesses need their own execution-boundary guard.
        """
        frozen = copy.deepcopy(args)
        digest = parameter_hash(tool, frozen)
        if call.get("decision") != "allow":
            if call.get("id") and call.get("execution_owner") == "adapter" and digest == call.get("parameter_hash"):
                try:
                    self._request("POST", f"/api/calls/{call['id']}/control", {"parameter_hash": digest, "boundary": "sdk_callback"})
                except GuardUnavailable:
                    pass  # Callback is withheld regardless; missing control evidence stays a gap.
            raise GuardDenied(call)
        if digest != call.get("parameter_hash") or call.get("tool") != tool:
            raise GuardUnavailable("Candidate arguments changed after review; re-review required")
        claimed = self._request("POST", f"/api/calls/{call['id']}/claim",
                                {"permit": call.get("permit"), "parameter_hash": digest})
        claimed_call = claimed.get("call") if isinstance(claimed, dict) else None
        if (not isinstance(claimed, dict) or not isinstance(claimed.get("claim_id"), str)
                or not claimed["claim_id"] or not isinstance(claimed_call, dict)
                or claimed_call.get("id") != call["id"] or claimed_call.get("parameter_hash") != digest
                or claimed_call.get("tool") != tool or claimed_call.get("execution_status") != "executing"):
            raise GuardUnavailable("Invalid claim binding; callback withheld")
        receipt = {"claim_id": claimed["claim_id"]}
        try:
            result = callback(frozen)
        except Exception as exc:
            # Exceptions can occur after a partial side effect. Explicitly retain that uncertainty.
            unknown = isinstance(exc, (TimeoutError, ExecutionOutcomeUnknown))
            receipt.update(status="unknown" if unknown else "failed", detail="Adapter callback outcome is unknown; partial effects are not excluded" if unknown else "Adapter callback failed; partial effects are not excluded",
                           result={"exception_type": type(exc).__name__})
            try:
                self._request("POST", f"/api/calls/{call['id']}/receipt", receipt)
            except GuardUnavailable:
                raise ReceiptUnconfirmed(call["id"]) from exc
            raise
        receipt.update(status="succeeded", detail="Execution reported by trusted SDK callback", result=result)
        try:
            self._request("POST", f"/api/calls/{call['id']}/receipt", receipt)
        except (GuardUnavailable, TypeError) as exc:
            raise ReceiptUnconfirmed(call["id"]) from exc
        return result

    def execute_guarded(self, session_id: str, tool: str, args: dict,
                        callback: Callable[[dict], Any], **context) -> Any:
        frozen = copy.deepcopy(args)
        call = self.review(session_id, tool, frozen, **context)
        return self.execute_reviewed(call, tool, frozen, callback)
