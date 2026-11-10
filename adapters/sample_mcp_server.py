"""Small real stdio MCP fixture server; reads only its own packaged README data."""
import json
import sys


def main():
    sys.stdin.reconfigure(encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")
    for line in sys.stdin:
        request = json.loads(line)
        if "id" not in request:
            continue
        method = request["method"]
        result = {}
        if method == "initialize":
            result = {"protocolVersion": request.get("params", {}).get("protocolVersion", "2025-06-18"),
                      "capabilities": {"tools": {}}, "serverInfo": {"name": "aegis-fixture", "version": "1.0"}}
        elif method == "tools/list":
            result = {"tools": [{"name": "read_document", "description": "Read the project README documentation",
                       "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}},
                                       "required": ["path"], "additionalProperties": False}}]}
        elif method == "tools/call":
            params = request.get("params", {})
            allowed = params.get("name") == "read_document" and params.get("arguments", {}).get("path") == "README.md"
            result = {"isError": not allowed, "content": [{"type": "text", "text":
                      "# Fixture project\nInstall Python 3.11+, install requirements, run the application."
                      if allowed else "Fixture can only read README.md"}]}
        print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}), flush=True)


if __name__ == "__main__":
    main()
