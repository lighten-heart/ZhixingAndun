import json
import os
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import pytest
from adapters.file_boundary import BoundFile
from adapters.network_boundary import prepare, one_hop, guarded_fetch, text_attachments
from adapters.sdk import GuardDenied


def test_files_prepare_has_no_write_effect_and_consumes_once(tmp_path):
    (tmp_path / "reports").mkdir()
    target = tmp_path / "reports/result.txt"
    with BoundFile(tmp_path, "reports/result.txt", True) as bound:
        assert not target.exists()
        result = bound.execute("一行\nsecond")
        assert target.read_bytes() == "一行\nsecond".encode()
        assert result["identity"]["inode"]
        with pytest.raises(ValueError):
            bound.execute("overwrite")
    with pytest.raises(FileExistsError):
        BoundFile(tmp_path, "reports/result.txt", True)


def test_read_binds_handle_and_blocks_links(tmp_path):
    (tmp_path / "notes.txt").write_bytes(b"public notes")
    with BoundFile(tmp_path, "notes.txt") as bound:
        if os.name == "nt":
            with pytest.raises(OSError):
                (tmp_path / "notes.txt").write_bytes(b"replacement")
            with pytest.raises(OSError):
                (tmp_path / "notes.txt").rename(tmp_path / "renamed.txt")
        assert bound.execute()["content"] == "public notes"
    os.link(tmp_path / "notes.txt", tmp_path / "linked.txt")
    with pytest.raises(ValueError):
        BoundFile(tmp_path, "linked.txt")


def test_parent_swap_cannot_redirect_write(tmp_path):
    reports = tmp_path / "reports"
    reports.mkdir()
    with BoundFile(tmp_path, "reports/new.txt", True) as bound:
        if os.name == "nt":
            with pytest.raises(OSError):
                reports.rename(tmp_path / "old")
            assert bound.execute("ok")["bytes"] == 2
        else:
            reports.rename(tmp_path / "old")
            reports.mkdir()
            with pytest.raises(OSError):
                bound.execute("not written")
            assert not (reports / "new.txt").exists()
            assert not (tmp_path / "old/new.txt").exists()


@pytest.mark.parametrize("name", ["../escape", "/etc/passwd", "reports/../a.txt", "reports/x.txt:stream", "NUL", "reports/COM1.txt", "a\\b", "reports/a. "])
def test_invalid_paths_never_touch_files(tmp_path, name):
    with pytest.raises((OSError, ValueError)):
        BoundFile(tmp_path, name, True)


@pytest.fixture
def http_server():
    seen = []
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append((self.path, dict(self.headers), ""))
            self.send_response(302 if self.path == "/redirect" else 200)
            if self.path == "/redirect":
                self.send_header("Location", "/final")
            self.end_headers()
            self.wfile.write(b"public response")
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"])).decode("utf-8")
            seen.append((self.path, dict(self.headers), body))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"received")
        def log_message(self, *_):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}", seen
    server.shutdown()
    server.server_close()
    thread.join()


def test_private_network_is_closed_and_redirect_is_not_followed(http_server):
    url, seen = http_server
    with pytest.raises(ValueError):
        one_hop(prepare(url + "/redirect"))
    assert seen == []
    result = one_hop(prepare(url + "/redirect"), allow_loopback=True)
    assert result["redirect_url"] == url + "/final" and not result["redirect_followed"]
    assert [r[0] for r in seen] == ["/redirect"]


def test_redirect_denial_has_no_second_request(http_server):
    url, seen = http_server
    class Guard:
        def __init__(self): self.reviewed = []
        def review(self, sid, tool, args, **context):
            self.reviewed.append({"args": args, "context": context})
            return {"id": str(len(self.reviewed)), "decision": "allow" if len(self.reviewed) == 1 else "block"}
        def execute_reviewed(self, call, tool, args, callback):
            if call["decision"] != "allow": raise GuardDenied(call)
            return callback(args)
    guard = Guard()
    with pytest.raises(GuardDenied):
        guarded_fetch(guard, "test", prepare(url + "/redirect"), allow_loopback=True)
    assert [r[0] for r in seen] == ["/redirect"]
    assert guard.reviewed[1]["args"]["url"] == url + "/final"
    assert guard.reviewed[1]["context"]["parent_call_id"] == "1"


def test_text_attachment_bytes_match_reviewed_body(http_server):
    url, seen = http_server
    request = text_attachments(url + "/upload?name=report", [("report.txt", "中文报告\n".encode())], headers={"X-Review": "explicit"})
    result = one_hop(request, allow_loopback=True)
    assert result["status"] == 200
    assert seen[0][2] == request["body"]
    assert json.loads(seen[0][2])["attachments"][0]["text"] == "中文报告\n"
    assert seen[0][1]["x-review"] == "explicit"
    assert seen[0][0] == "/upload?name=report"


@pytest.mark.parametrize("headers", [{"Host": "substitute"}, {"x": "a\r\nHost: other"}, {"X-A": "one", "x-a": "two"}, {"Transfer-Encoding": "chunked"}])
def test_ambiguous_headers_rejected(headers):
    with pytest.raises(ValueError):
        prepare("https://example.com", headers=headers)
