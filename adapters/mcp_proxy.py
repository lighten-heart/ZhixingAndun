"""A fail-closed, serial JSON-RPC stdio MCP tool gateway.

It guards tool discovery, calls and results. Explicitly unsupported capabilities are
not advertised. Trust maps come from an operator-owned config, never tool descriptions.
"""
from __future__ import annotations

import argparse
import json
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path

from adapters.sdk import GuardClient, GuardDenied, GuardUnavailable, ReceiptUnconfirmed, ExecutionOutcomeUnknown

MAX_FRAME_CHARS = 2_000_000


class Upstream:
    def __init__(self, command: list[str], timeout: float = 30):
        if not command or not all(isinstance(s, str) for s in command):
            raise ValueError("upstream_command must be an operator-supplied argv list")
        if not isinstance(timeout, (int, float)) or not 0 < timeout <= 300:
            raise ValueError("upstream timeout must be greater than zero and at most 300 seconds")
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, text=True, encoding="utf-8", bufsize=1,
                                        shell=False)
        self.timeout, self.counter = timeout, 0
        self.inbox = queue.Queue(maxsize=256)
        self._request_lock = threading.Lock()
        self._reader_error = None
        self._closed = threading.Event()
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        try:
            while not self._closed.is_set():
                line = self.process.stdout.readline(MAX_FRAME_CHARS + 1)
                if not line:
                    raise ExecutionOutcomeUnknown("Upstream disconnected before a complete response")
                if len(line) > MAX_FRAME_CHARS:
                    raise ExecutionOutcomeUnknown("Upstream message exceeds size limit")
                message = json.loads(line)
                if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
                    raise ExecutionOutcomeUnknown("Upstream stdout is not a JSON-RPC object")
                self.inbox.put_nowait(message)
        except (ValueError, OSError, queue.Full, ExecutionOutcomeUnknown) as exc:
            self._reader_error = ExecutionOutcomeUnknown("Upstream framing, stream or notification limit failed")
            try:
                self.inbox.put_nowait(self._reader_error)
            except queue.Full:
                pass

    def send(self, message):
        if self._closed.is_set() or self.process.poll() is not None:
            raise ExecutionOutcomeUnknown("Upstream not running")
        frame = json.dumps(message, ensure_ascii=False, allow_nan=False) + "\n"
        if len(frame) > MAX_FRAME_CHARS:
            raise GuardUnavailable("Outgoing MCP frame exceeds size limit")
        completed, errors = threading.Event(), []
        def write():
            try:
                self.process.stdin.write(frame)
                self.process.stdin.flush()
            except (OSError, ValueError) as exc:
                errors.append(exc)
            finally:
                completed.set()
        writer = threading.Thread(target=write, daemon=True)
        writer.start()
        remaining = max(0, getattr(self, "_send_deadline", time.monotonic() + self.timeout) - time.monotonic())
        if not completed.wait(remaining):
            self.close()
            writer.join(timeout=1)
            raise TimeoutError("Upstream write timed out; outcome may be unknown")
        if errors:
            self.close()
            raise ExecutionOutcomeUnknown("Upstream write was interrupted") from errors[0]

    def notify(self, method, params=None):
        with self._request_lock:
            self._send_deadline = time.monotonic() + self.timeout
            self.send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def request(self, method, params=None):
        with self._request_lock:
            return self._request_serial(method, params)

    def _request_serial(self, method, params=None):
        self.counter += 1
        request_id = self.counter
        # Only serial requests are accepted; timeout closes the process to prevent stale reuse.
        deadline = time.monotonic() + self.timeout
        self._send_deadline = deadline
        try:
            self.send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}})
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise queue.Empty
                if self._reader_error:
                    raise self._reader_error
                response = self.inbox.get(timeout=remaining)
                if isinstance(response, Exception):
                    raise response
                if "method" in response:
                    if "id" in response:
                        self.send({"jsonrpc": "2.0", "id": response["id"], "error": {
                            "code": -32601, "message": "Server initiated requests are not supported by this gateway"}})
                    continue
                if response.get("id") != request_id:
                    raise ExecutionOutcomeUnknown("Mismatched upstream request ID")
                if "error" in response:
                    raise ExecutionOutcomeUnknown("Upstream returned a JSON-RPC error; tool effects are not independently known")
                if not isinstance(response.get("result"), dict):
                    raise ExecutionOutcomeUnknown("Upstream result must be a JSON object")
                return response["result"]
        except queue.Empty as exc:
            self.close()
            raise TimeoutError("Upstream timed out; execution result may be unknown") from exc
        except ExecutionOutcomeUnknown:
            self.close()
            raise

    def close(self):
        self._closed.set()
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(3)
            except subprocess.TimeoutExpired:
                self.process.kill(); self.process.wait()


class Gateway:
    def __init__(self, guard: GuardClient, upstream: Upstream, config: dict):
        self.guard, self.upstream, self.config = guard, upstream, config
        self.session = guard.session(config.get("title", "MCP 受控工具会话"),
                                     config["intent"], config.get("scope", "read_only"))
        self.id = self.session["id"]
        self.discovered: dict[str, dict] = {}
        self.context_sources: list[str] = []
        self.halted = False

    def _inspect(self, text, resource, source_type, *, call_id=None):
        source = self.guard.ingest(self.id, source_type, text, resource,
                                   metadata={"call_id": call_id} if call_id else {})
        if source["decision"] != "allow":
            raise GuardDenied({"decision": source["decision"], "reasons": ["MCP content admission denied"],
                               "source_id": source["id"], "call_id": call_id}, executed=call_id is not None)
        if source_type == "mcp_result":
            self.context_sources.append(source["id"])
        return source

    def handle(self, method, params):
        if method == "initialize":
            result = self.upstream.request(method, {**params, "capabilities": {}})
            version = result.get("protocolVersion")
            if version not in {"2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"}:
                raise ValueError("Unsupported upstream MCP protocol version")
            admitted = {"protocolVersion": version, "capabilities": {"tools": {"listChanged": False}},
                        "serverInfo": {"name": "aegisguard-mcp-proxy", "version": "1.0.0"}}
            # Initialize.instructions is also model-visible external content.
            if "instructions" in result:
                if not isinstance(result["instructions"], str):
                    raise ValueError("Invalid upstream instructions")
                self._inspect(result["instructions"], f"mcp://{self.config['server_id']}/initialize", "mcp_description")
                admitted["instructions"] = result["instructions"]
            return admitted
        if method == "notifications/initialized":
            self.upstream.notify(method, params); return None
        if method == "ping":
            return {}
        if method == "tools/list":
            if not params.get("cursor"):
                # A fresh listing replaces the previous registry, including removed tools.
                self.discovered.clear()
            result = self.upstream.request(method, params)
            admitted = []
            for tool in result.get("tools", []):
                name = tool.get("name")
                if name not in self.config.get("tool_map", {}):
                    continue
                self.discovered.pop(name, None)
                try:
                    source = self._inspect(json.dumps(tool, ensure_ascii=False),
                                           f"mcp://{self.config['server_id']}/{name}/description", "mcp_description")
                except GuardDenied:
                    continue
                self.discovered[name] = {"source_id": source["id"], "definition": tool}
                admitted.append(tool)
            listing = {"tools": admitted}
            if isinstance(result.get("nextCursor"), str):
                listing["nextCursor"] = result["nextCursor"]
            return listing
        if method == "tools/call":
            if self.halted:
                raise GuardUnavailable("Gateway halted after an unconfirmed operation; manual reconciliation required")
            name = params.get("name")
            if name not in self.discovered:
                return {"isError": True, "content": [{"type": "text", "text": "Tool not discovered or not admitted"}]}
            mapping = self.config["tool_map"][name]
            canonical = mapping["tool"]
            original_args = params.get("arguments", {})
            # Only identity parameter maps: do not review different parameters than those forwarded.
            if not isinstance(original_args, dict):
                raise ValueError("Tool arguments must be an object")

            def forward(checked_args):
                result = self.upstream.request("tools/call", {"name": name, "arguments": checked_args})
                if not isinstance(result, dict):
                    raise ExecutionOutcomeUnknown("Upstream tool result has an invalid shape")
                if result.get("isError"):
                    raise RuntimeError("Upstream tool reported failure; partial effects are not excluded")
                return result

            try:
                call = self.guard.review(self.id, canonical, original_args,
                           execution_owner="adapter", mcp_server=self.config["server_id"],
                           source_ids=[self.discovered[name]["source_id"], *self.context_sources])
                result = self.guard.execute_reviewed(call, canonical, original_args, forward)
            except (ReceiptUnconfirmed, TimeoutError, ExecutionOutcomeUnknown):
                self.halted = True
                self.upstream.close()
                raise
            # Inspect the entire structured result, including nested fields, before returning it.
            self._inspect(json.dumps(result, ensure_ascii=False),
                          f"mcp://{self.config['server_id']}/{name}/result", "mcp_result", call_id=call["id"])
            return result
        raise ValueError("Unsupported MCP method; this gateway advertises only guarded tools")


def main():
    # Only load operator configuration beside this project, not the tool workspace.
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent / ".env", override=False)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    sys.stdin.reconfigure(encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")
    upstream = Upstream(config["upstream_command"], config.get("timeout_seconds", 30))
    try:
        with GuardClient() as guard:
            gateway = Gateway(guard, upstream, config)
            while True:
                line = sys.stdin.readline(MAX_FRAME_CHARS + 1)
                if not line:
                    break
                if len(line) > MAX_FRAME_CHARS:
                    print(json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "MCP frame exceeds size limit"}}), flush=True)
                    break
                request = None
                try:
                    if len(line) > 2_000_000:
                        raise ValueError("Message too large")
                    request = json.loads(line)
                    if request.get("jsonrpc") != "2.0" or not isinstance(request.get("method"), str):
                        raise ValueError("Invalid JSON-RPC request")
                    result = gateway.handle(request["method"], request.get("params", {}))
                    if "id" not in request:
                        continue
                    response = {"jsonrpc": "2.0", "id": request["id"], "result": result}
                except Exception as exc:
                    if isinstance(request, dict) and "id" not in request:
                        continue
                    # Avoid reflecting secrets or untrusted service error strings into the model.
                    response = {"jsonrpc": "2.0", "id": request.get("id") if isinstance(request, dict) else None,
                                "error": {"code": -32001, "message": f"Guarded request rejected: {type(exc).__name__}"}}
                print(json.dumps(response, ensure_ascii=False), flush=True)
    finally:
        upstream.close()


if __name__ == "__main__":
    main()
