"""Persistent isolated Harness provider worker; authenticated provider stays in Harness."""
import atexit
import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import tempfile
import threading
import uuid
from .runtime import prepare_runtime, runtime_directory, write_profile

_lock = threading.Lock()
_worker = None
_REVIEW_FAILURE_CODES = frozenset({'REVIEW_STREAM_INCOMPLETE', 'REVIEW_TOOL_CALL',
    'REVIEW_RESPONSE_SIZE', 'REVIEW_JSON_INVALID', 'REVIEW_OBJECT_REQUIRED'})


class ReviewResponseInvalid(RuntimeError):
    """Fixed diagnostic only; does not suppress the existing bounded retry."""
    def __init__(self, code):
        if type(code) is not str or code not in _REVIEW_FAILURE_CODES:
            raise ValueError('Unsupported review failure')
        self.code = code
        super().__init__(code)


class ProviderUnavailable(RuntimeError):
    """Allowlisted transport metadata, never provider messages or model text."""
    def __init__(self, code, status):
        if (code, status) not in {('ACCOUNT_QUOTA', 402), ('ACCOUNT_TOKEN_INVALID', 401)}:
            raise ValueError('Unsupported provider failure')
        self.code, self.status = code, status
        super().__init__(code)


class Worker:
    def __init__(self):
        prepare_runtime()
        self.directory = tempfile.TemporaryDirectory(prefix="aegisguard-judge-", ignore_cleanup_errors=True)
        self.closed = False
        root = Path(self.directory.name)
        profile = write_profile(root / "home", root, "independent-judge", "http://127.0.0.1:8765", "read_only")
        patch = json.loads(profile.read_text(encoding="utf-8"))
        patch = [p for p in patch if "insert" not in p]
        patch.extend([{"id": "headless-runner", "disabled": True},
                      {"insert": [{"id": "aegisguard-judge", "name": str(Path(__file__).with_name("judge.mjs")),
                                   "config": {"provider": os.getenv("GUARD_HARNESS_PROVIDER", "deepseek-account"),
                                              "model": os.getenv("GUARD_HARNESS_MODEL", "deepseek-flash")}}]}])
        profile.write_text(json.dumps(patch), encoding="utf-8")
        env = dict(os.environ, DSH_HOME=str(root / "home"), AEGIS_DSH_RUNTIME=str(runtime_directory()), NO_COLOR="1")
        env.pop("ELECTRON_RUN_AS_NODE", None)
        self.messages = queue.Queue(maxsize=20)
        self.diagnostics = []
        self.process = subprocess.Popen([shutil.which("node"), str(runtime_directory() / "node_modules/@deepseek-ai/dsh/lib/bin.js"),
                                         "--profile", "aegisguard", "independent-review"],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        text=True, encoding="utf-8", env=env, cwd=root,
                                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        threading.Thread(target=self._read, daemon=True).start()
        atexit.register(self.close)
        try:
            if not self.messages.get(timeout=30).get("ready"):
                raise RuntimeError("judge startup failed: " + "".join(self.diagnostics)[-3000:])
        except Exception:
            self.close()
            raise

    def _read(self):
        try:
            for line in self.process.stdout:
                if not line.startswith("AEGIS_JUDGE "):
                    self.diagnostics = (self.diagnostics + [line])[-10:]
                if line.startswith("AEGIS_JUDGE "):
                    self.messages.put_nowait(json.loads(line[12:]))
        except Exception:
            pass
        finally:
            try:
                self.messages.put_nowait({"error": "judge stopped"})
            except queue.Full:
                pass

    def review(self, payload, system):
        identifier = uuid.uuid4().hex
        self.process.stdin.write(json.dumps({"id": identifier, "system": system, "payload": payload}, ensure_ascii=False) + "\n")
        self.process.stdin.flush()
        result = self.messages.get(timeout=100)
        from backend.usage import observe_provider
        observe_provider(result.get("route") or {"provider": os.getenv("GUARD_HARNESS_PROVIDER", "deepseek-account"), "model": os.getenv("GUARD_HARNESS_MODEL", "deepseek-flash")}, result.get("usage"))
        if result.get("id") != identifier or "answer" not in result:
            import logging
            logging.getLogger(__name__).warning("Independent judge response invalid; correlation=%s", result.get("id") == identifier)
            failure = result.get('provider_failure')
            if (result.get('id') == identifier and result.get('finish_kinds') == ['error']
                    and isinstance(failure, dict) and set(failure) == {'code', 'status'}
                    and type(failure['code']) is str and type(failure['status']) is int
                    and (failure['code'], failure['status']) in {('ACCOUNT_QUOTA', 402), ('ACCOUNT_TOKEN_INVALID', 401)}):
                raise ProviderUnavailable(failure['code'], failure['status'])
            code = result.get('review_failure_code')
            if result.get('id') == identifier and type(code) is str and code in _REVIEW_FAILURE_CODES:
                raise ReviewResponseInvalid(code)
            raise RuntimeError("judge response failed")
        return {**result["answer"], "_provider_route": result.get("route"), "_provider_usage": result.get("usage")}

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.process.poll() is None:
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(self.process.pid), "/T", "/F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(5)
        for stream in (self.process.stdin, self.process.stdout):
            if stream:
                stream.close()
        self.directory.cleanup()


def review(payload, system):
    global _worker
    with _lock:
        try:
            if _worker is None:
                _worker = Worker()
            return _worker.review(payload, system)
        except Exception:
            if _worker:
                _worker.close()
                _worker = None
            raise


@atexit.register
def close():
    global _worker
    with _lock:
        if _worker:
            _worker.close()
            _worker = None
