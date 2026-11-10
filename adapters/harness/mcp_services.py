"""Two independent stdio MCP services, each reads only fixed demonstration files."""
import argparse
import json
from pathlib import Path
import sys
import os
import urllib.request
import uuid
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from adapters.file_boundary import BoundFile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--service", choices=["project-docs", "knowledge"], required=True)
    parser.add_argument("--guard-url")
    parser.add_argument("--session-id")
    args = parser.parse_args()
    root = Path(args.workspace).resolve(strict=True)
    name = "read_document" if args.service == "project-docs" else "search_knowledge"
    schema = {"type": "object", "properties": {"path" if name == "read_document" else "query": {"type": "string"}},
              "required": ["path" if name == "read_document" else "query"], "additionalProperties": False}
    sys.stdin.reconfigure(encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")
    bindings = {}
    for line in sys.stdin:
        if len(line) > 250000:
            break
        request = json.loads(line)
        if "id" not in request:
            continue
        method, params = request.get("method"), request.get("params", {})
        try:
            if method == "initialize":
                result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                          "serverInfo": {"name": args.service, "version": "1.0"}}
            elif method == "tools/list":
                result = {"tools": [{"name": name, "description": "Read approved project documentation" if name == "read_document" else "Search project knowledge documents", "inputSchema": schema}]}
            elif method == "files/prepare" and name == "read_document":
                if params.get("path") not in {"README.md", "external-note.txt"} or len(bindings) >= 8:
                    raise ValueError("Invalid file binding")
                bound = BoundFile(root, params["path"])
                key = uuid.uuid4().hex
                bindings[key] = bound
                result = {"binding_id": key, "facts": bound.facts}
            elif method == "files/close":
                bound = bindings.pop(params.get("binding_id"), None)
                if bound:
                    bound.close()
                result = {"closed": True}
            elif method == "tools/call" and params.get("name") == name:
                arguments = params.get("arguments", {})
                if name == "read_document":
                    filename = arguments.get("path")
                    if filename not in {"README.md", "external-note.txt"}:
                        raise ValueError("document is not registered")
                else:
                    if not isinstance(arguments.get("query"), str) or not arguments["query"].strip():
                        raise ValueError("query required")
                    if args.guard_url and args.session_id:
                        from urllib.parse import urlparse
                        if urlparse(args.guard_url).hostname not in {"127.0.0.1", "localhost", "::1"}:
                            raise ValueError("guard must be local")
                        payload = json.dumps({"query": arguments["query"], "purpose": "task", "recipient": "knowledge"}).encode()
                        req = urllib.request.Request(args.guard_url.rstrip("/") + "/api/sessions/" + args.session_id + "/knowledge/search", data=payload,
                            headers={"Content-Type": "application/json", "X-Guard-Token": os.getenv("GUARD_API_TOKEN", "")})
                        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=120) as reply:
                            found = json.loads(reply.read(250000))
                        result = {"isError": False, "content": [{"type": "text", "text": json.dumps(found, ensure_ascii=False)}]}
                        print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}, ensure_ascii=False), flush=True)
                        continue
                    filename = "knowledge.txt"
                if name == "read_document":
                    bound = bindings.get(params.get("binding_id"))
                    if not bound or bound.path != filename:
                        raise ValueError("Reviewed file binding required")
                    text = bound.execute()["content"]
                else:
                    with BoundFile(root, filename) as bound:
                        text = bound.execute()["content"]
                result = {"isError": False, "content": [{"type": "text", "text": text}],
                          "structuredContent": {"document_id": filename, "version": 1, "service": args.service}}
            elif method == "ping":
                result = {}
            else:
                raise ValueError("unsupported method")
            response = {"jsonrpc": "2.0", "id": request["id"], "result": result}
        except (OSError, ValueError):
            response = {"jsonrpc": "2.0", "id": request["id"], "error": {"code": -32602, "message": "Request rejected"}}
        print(json.dumps(response, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
