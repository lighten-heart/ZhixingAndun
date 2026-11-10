"""Actual HTTP effects with fixed request bytes, pinned DNS and per-hop review.

No proxy, cookie jar, implicit credentials, decompression or automatic redirects.
Harness uses one_hop; SDK users can use guarded_fetch for a reviewed redirect loop.
Binary attachments are rejected: text attachments are frozen in the reviewed body.
"""
from __future__ import annotations
import hashlib
import http.client
import ipaddress
import json
import re
import socket
import ssl
import sys
from urllib.parse import urljoin, urlsplit, urlunsplit


def prepare(url, method="GET", headers=None, body=""):
    if not isinstance(url, str) or len(url) > 8192 or any(ord(c) < 33 or ord(c) > 126 for c in url):
        raise ValueError("URL must be bounded ASCII with percent-encoded components")
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("Explicit HTTP(S) destination without credentials or fragment required")
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError("Invalid port")
    method = method.upper()
    if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}:
        raise ValueError("Unsupported HTTP method")
    if not isinstance(body, str) or len(body.encode("utf-8")) > 100000 or (body and method in {"GET", "HEAD"}):
        raise ValueError("Unsupported request body")
    if not isinstance(headers or {}, dict) or len(headers or {}) > 30:
        raise ValueError("Invalid headers")
    cleaned = {}
    reserved = {"host", "content-length", "transfer-encoding", "connection", "proxy-authorization", "proxy-connection", "upgrade", "trailer", "te", "expect", "accept-encoding"}
    for key, value in (headers or {}).items():
        if (not isinstance(key, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key)
                or key.lower() in reserved or key.lower() in cleaned or not isinstance(value, str)
                or len(value) > 8192 or any(ord(c) < 32 or ord(c) > 126 for c in value)):
            raise ValueError("Unsafe or duplicate header")
        cleaned[key.lower()] = value
    cleaned.update({"host": parsed.netloc, "connection": "close", "accept-encoding": "identity",
                    "content-length": str(len(body.encode("utf-8")))})
    return {"url": url, "method": method, "headers": cleaned, "body": body}


def text_attachments(url, attachments, *, method="POST", headers=None, body=""):
    """Freeze explicitly supplied (name, UTF-8 bytes) attachments; never send paths.

    Register data references against args.body when data carries ACL labels.
    The full encoded bytes, including attachments, are inspected before the permit.
    """
    parts = []
    for name, data in attachments:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", name) or not isinstance(data, bytes):
            raise ValueError("Invalid text attachment")
        parts.append({"name": name, "text": data.decode("utf-8")})
    content = json.dumps({"body": body, "attachments": parts}, ensure_ascii=False, separators=(",", ":"))
    return prepare(url, method, {**(headers or {}), "content-type": "application/json; charset=utf-8"}, content)


def one_hop(request, *, allow_loopback=False):
    # Only trusted adapter code can set allow_loopback, never request/model fields.
    canonical = prepare(request["url"], request["method"],
                        {k: v for k, v in request["headers"].items()
                         if k not in {"host", "connection", "content-length", "accept-encoding"}}, request["body"])
    if canonical != request:
        raise ValueError("Request bytes changed after review")
    parsed = urlsplit(request["url"])
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    addresses = socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
    if not addresses:
        raise OSError("DNS returned no destination")
    for _, _, _, _, sockaddr in addresses:
        ip = ipaddress.ip_address(sockaddr[0])
        if ip.is_multicast or (not ip.is_global and not (allow_loopback and ip.is_loopback)):
            raise ValueError("Private, local, multicast and reserved destinations are closed")
    family, socktype, protocol, _, sockaddr = addresses[0]
    raw = socket.socket(family, socktype, protocol)
    raw.settimeout(15)
    connection = http.client.HTTPConnection(parsed.hostname, port, timeout=15)
    try:
        raw.connect(sockaddr)  # Use exactly the reviewed resolution; no second DNS lookup.
        connection.sock = (ssl.create_default_context().wrap_socket(raw, server_hostname=parsed.hostname)
                           if parsed.scheme == "https" else raw)
        target = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        connection.putrequest(request["method"], target, skip_host=True, skip_accept_encoding=True)
        for key, value in request["headers"].items():
            connection.putheader(key, value)
        payload = request["body"].encode("utf-8")
        connection.endheaders(payload)
        response = connection.getresponse()
        content = response.read(100001)
        if len(content) > 100000 or response.getheader("Content-Encoding", "identity").lower() != "identity":
            raise ValueError("Response exceeds supported envelope")
        location = response.getheader("Location") if response.status in {301, 302, 303, 307, 308} else None
        return {"status": response.status, "url": request["url"], "peer_ip": sockaddr[0],
                "request_body_sha256": hashlib.sha256(payload).hexdigest(),
                "response_sha256": hashlib.sha256(content).hexdigest(), "content": content.decode("utf-8", errors="strict"),
                "redirect_url": urljoin(request["url"], location) if location else None,
                "redirect_followed": False, "execution": "pinned_http_single_hop"}
    finally:
        connection.close()
        raw.close()


def guarded_fetch(guard, session_id, request, *, approve=None, context=None, max_redirects=5, allow_loopback=False):
    """Review/claim/receipt on every hop. An approval callback must return a fresh
    authorized call from the operator API; it cannot authorize locally.
    Content admission of final response remains the host's separate responsibility.
    """
    request = json.loads(json.dumps(request))
    context = dict(context or {})
    seen = set()
    for hop in range(max_redirects + 1):
        if request["url"] in seen:
            raise ValueError("Redirect loop")
        seen.add(request["url"])
        call = guard.review(session_id, "net.fetch", request, **context,
                            resource_facts={"redirect_hop": hop, "request_body_sha256": hashlib.sha256(request["body"].encode()).hexdigest(),
                                            "evidence_type": "frozen_http_request"})
        if call.get("decision") == "confirm" and approve:
            call = approve(call)
        result = guard.execute_reviewed(call, "net.fetch", request, lambda frozen: one_hop(frozen, allow_loopback=allow_loopback))
        if not result["redirect_url"]:
            return result
        if hop == max_redirects:
            raise ValueError("Redirect budget exhausted; next destination not contacted")
        # Non-GET redirect semantics are ambiguous; never silently drop/replay a body.
        if request["method"] not in {"GET", "HEAD"}:
            raise ValueError("Redirect of a request with effects requires a new explicit task")
        headers = {k: v for k, v in request["headers"].items()
                   if k not in {"host", "connection", "content-length", "accept-encoding"}}
        if urlsplit(request["url"]).netloc != urlsplit(result["redirect_url"]).netloc:
            headers = {k: v for k, v in headers.items() if k not in {"authorization", "cookie"}}
        request = prepare(result["redirect_url"], request["method"], headers)
        context["parent_call_id"] = call["id"]


def main():
    frozen = None
    sys.stdin.reconfigure(encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")
    while line := sys.stdin.readline(250001):
        if len(line) > 250000:
            break
        message = json.loads(line)
        try:
            if message["method"] == "prepare" and frozen is None:
                frozen = prepare(**message.get("params", {}))
                result = frozen
            elif message["method"] == "execute" and frozen is not None:
                request, frozen = frozen, None
                result = one_hop(request)
            else:
                raise ValueError("Invalid network boundary state")
            response = {"jsonrpc": "2.0", "id": message["id"], "result": result}
        except (OSError, ValueError, TypeError, http.client.HTTPException):
            response = {"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32000, "message": "Network boundary rejected operation; do not retry an executed request"}}
        print(json.dumps(response, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
