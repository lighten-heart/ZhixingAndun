"""Single-attempt Docker/strace evidence collection, never business execution."""
import ast
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import queue
import secrets
import subprocess
import time
import threading
from fastapi import HTTPException

ROOT = Path(__file__).resolve().parents[1]
GAPS = {"FILE_ACCESS_UNKNOWN": "SBX_FILE_01", "SUBPROCESS_UNKNOWN": "SBX_PROC_01", "NETWORK_TARGET_UNKNOWN": "SBX_NET_01"}
PROJECT_ID = hashlib.sha256(str(ROOT.resolve()).casefold().encode()).hexdigest()
SUPPLEMENTAL_TIMEOUT = 20.0
_SUPPLEMENTAL_SLOT = threading.BoundedSemaphore(1)
_STATUS_LOCK = threading.Lock()
_STATUS_CACHE = {"available": False, "checking": True, "reason": "Sandbox readiness check pending"}
_STATUS_AT = 0.0
_STATUS_RUNNING = False


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def image_id():
    value = os.getenv("GUARD_SANDBOX_IMAGE", "")
    if not value and (ROOT / "data/sandbox-image.json").exists():
        value = json.loads((ROOT / "data/sandbox-image.json").read_text(encoding="utf-8"))["image"]
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", value):
        raise ValueError("A locally built immutable sandbox image ID is required")
    return value


def status():
    try:
        image = image_id()
        result = subprocess.run(["docker", "image", "inspect", image, "--format", "{{.Id}}"], capture_output=True, text=True, timeout=5)
        return {"available": result.returncode == 0 and result.stdout.strip() == image, "image": image,
                "network": "none", "candidate_uid": 10001, "scope": "test_environment_only"}
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired):
        return {"available": False, "reason": "Build with docker build -t aegisguard-sandbox:local sandbox, then set GUARD_SANDBOX_IMAGE to the sha256 image ID"}


def cached_status():
    """Liveness must not wait for a stopped/unresponsive Docker daemon.

    This is display-only readiness. Actual probes always enforce the live Docker
    checks, immutable image and container lifecycle independently.
    """
    global _STATUS_RUNNING
    with _STATUS_LOCK:
        if time.monotonic() - _STATUS_AT >= 10 and not _STATUS_RUNNING:
            _STATUS_RUNNING = True
            def refresh():
                global _STATUS_CACHE, _STATUS_AT, _STATUS_RUNNING
                try:
                    value = status()
                except Exception:
                    value = {"available": False, "reason": "Sandbox readiness check failed"}
                with _STATUS_LOCK:
                    _STATUS_CACHE = {**value, "checking": False, "observed_at": time.time()}
                    _STATUS_AT, _STATUS_RUNNING = time.monotonic(), False
            threading.Thread(target=refresh, name="sandbox-readiness", daemon=True).start()
        return {**_STATUS_CACHE, "refreshing": _STATUS_RUNNING}


def analyze(code):
    """Fixed gap types come from the parser, never a model or client assertion."""
    from .detection import detect, sensitive
    tree = ast.parse(code)
    gaps, prohibited = set(), []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [x.name for x in node.names] if isinstance(node, ast.Import) else [node.module or ""]
            for name in names:
                if name.split('.')[0] in {"os", "pathlib", "io"}: gaps.add("FILE_ACCESS_UNKNOWN")
                if name.split('.')[0] in {"subprocess", "multiprocessing", "os"}: gaps.add("SUBPROCESS_UNKNOWN")
                if name.split('.')[0] in {"socket", "urllib", "http", "requests"}: gaps.add("NETWORK_TARGET_UNKNOWN")
        if isinstance(node, ast.Call):
            name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr if isinstance(node.func, ast.Attribute) else ""
            if name in {"open", "read_text", "read_bytes", "write_text", "write_bytes"}: gaps.add("FILE_ACCESS_UNKNOWN")
            if name in {"eval", "exec", "__import__"}: prohibited.append("dynamic_code_execution")
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if re.search(r"(?:\.ssh|\.env|/etc/shadow|/proc/|docker\.sock|credentials)", node.value, re.I):
                prohibited.append("known_protected_resource")
    if sensitive(code) or detect(code, "code", use_model=False)["findings"]:
        prohibited.append("sensitive_or_prohibited_instruction")
    return {"parser": "python_ast_v1", "code_sha256": sha(code), "gaps": sorted(gaps),
            "prohibited": sorted(set(prohibited)), "coverage": "static_screening_not_general_safety_proof"}


def script_precheck(service, session_id, candidate):
    if candidate["tool"] != "script.run":
        return None
    if set(candidate["args"]) != {"script_id"} or not isinstance(candidate["args"].get("script_id"), str):
        return {"valid": False, "reason": "脚本参数必须精确绑定已授权 script_id"}
    artifact = service.store.get("script", candidate["args"]["script_id"])
    if not artifact or artifact["session_id"] != session_id or sha(artifact["_code"]) != artifact["sha256"]:
        return {"valid": False, "reason": "脚本身份、授权或版本核验失败"}
    return {"valid": True, "script_id": artifact["id"], "sha256": artifact["sha256"], **artifact["analysis"]}


def parse_trace(raw):
    """Keep syscall return values; open != read and connect != delivered."""
    events, pending = [], {}
    for number, line in enumerate(raw.splitlines(), 1):
        first_line = number
        unfinished = re.match(r"\s*(\d+)\s+([a-zA-Z0-9_]+)\(.*<unfinished \.\.\.>$", line)
        if unfinished:
            pending[(unfinished[1], unfinished[2])] = (number, line[:line.rfind("<unfinished ...>")].rstrip())
            continue
        resumed = re.match(r"\s*(\d+)\s+<\.\.\. ([a-zA-Z0-9_]+) resumed>(.*)$", line)
        if resumed:
            previous = pending.pop((resumed[1], resumed[2]), None)
            if not previous:
                continue
            first_line, prefix = previous
            line = prefix + resumed[3]
        match = re.match(r"\s*(\d+)\s+([a-zA-Z0-9_]+)\((.*)\)\s+=\s+(.+)$", line)
        if not match:
            continue
        pid, syscall, arguments, result = match.groups()
        category = ("file_open" if syscall in {"open", "openat", "openat2"} else
                    "file_read" if syscall in {"read", "pread64"} else
                    "file_write" if syscall in {"write", "pwrite64"} else
                    "process" if syscall in {"execve", "execveat", "clone", "clone3", "fork", "vfork"} else
                    "network_attempt" if syscall in {"connect", "sendto", "sendmsg", "bind"} else None)
        if category:
            events.append({"line": first_line, "end_line": number, "pid": int(pid), "syscall": syscall, "category": category,
                           "arguments": arguments, "result": result, "succeeded": not result.startswith('-1'),
                           "scope": "test_environment", "delivery_proven": False})
    return events


def container_identity(probe_id):
    return {"name": "aegis-probe-" + secrets.token_hex(12), "project": PROJECT_ID, "probe": probe_id}


def inspect_container(identity, expected_id=None):
    """An unavailable daemon is unknown, never proof that cleanup succeeded."""
    if (not isinstance(identity, dict) or identity.get("project") != PROJECT_ID or
        not isinstance(identity.get("name"), str) or not isinstance(identity.get("probe"), str) or
        not re.fullmatch(r"aegis-probe-[a-f0-9]{24}", identity["name"]) or
        not re.fullmatch(r"(?:sbx_[a-f0-9]{16}|standalone_[a-f0-9]{24})", identity["probe"])):
        return {"state": "identity_unverified"}
    try:
        check = subprocess.run(["docker", "inspect", identity["name"]], capture_output=True, text=True, timeout=5)
        if check.returncode:
            missing = re.search(r"No such (?:object|container):", check.stderr or "", re.I)
            return {"state": "absent" if missing else "unavailable"}
        inspected = json.loads(check.stdout)[0]
        labels = inspected.get("Config", {}).get("Labels") or {}
        identifier = inspected.get("Id", "")
        if (inspected.get("Name") != "/" + identity["name"] or
            labels.get("org.aegisguard.forensic") != "true" or
            labels.get("org.aegisguard.project") != identity["project"] or
            labels.get("org.aegisguard.probe") != identity["probe"] or
            not re.fullmatch(r"[a-f0-9]{64}", identifier) or
            (expected_id and identifier != expected_id)):
            return {"state": "ownership_mismatch"}
        return {"state": "owned", "id": identifier, "running": bool(inspected.get("State", {}).get("Running"))}
    except (OSError, ValueError, KeyError, IndexError, TypeError, subprocess.TimeoutExpired):
        return {"state": "unavailable"}


def cleanup_container(identity, expected_id=None, preserve_directory=None):
    """Only remove a specifically identified owned container, using its full ID."""
    found = inspect_container(identity, expected_id)
    evidence = {"cleanup_verified": found["state"] == "absent", "cleanup_state": found["state"]}
    if found["state"] != "owned":
        return evidence
    evidence["container_id"] = found["id"]
    if preserve_directory is not None:
        try:
            preserve_directory.mkdir(parents=True, exist_ok=True)
            trace_path = preserve_directory / "strace.log"
            if not trace_path.exists():
                # Docker's archive API may not expose a running tmpfs. Read only
                # the fixed root-owned trace using the immutable image's Python;
                # never restart the candidate or execute candidate-supplied code.
                if found["running"]:
                    evidence["recovery_trace_method"] = "bounded_live_read"
                    reader = ("import sys; "
                              "sys.stdout.buffer.write(open('/evidence/trace.log', 'rb').read(1048577))")
                    copied = subprocess.run(["docker", "exec", "--user", "0", found["id"],
                                             "/usr/local/bin/python3", "-I", "-c", reader],
                                            capture_output=True, timeout=5)
                    valid = copied.returncode == 0 and 0 < len(copied.stdout) <= 1024 * 1024
                    if valid:
                        with trace_path.open("xb") as stream:
                            stream.write(copied.stdout)
                    evidence["recovery_trace_copy_succeeded"] = valid
                else:
                    evidence["recovery_trace_method"] = "stopped_container_archive"
                    copied = subprocess.run(["docker", "cp", found["id"] + ":/evidence/trace.log", str(trace_path)],
                                            capture_output=True, timeout=5)
                    evidence["recovery_trace_copy_succeeded"] = (copied.returncode == 0 and trace_path.is_file()
                                                               and 0 < trace_path.stat().st_size <= 1024 * 1024)
                evidence["recovery_trace_returncode"] = copied.returncode
            if trace_path.is_file() and trace_path.stat().st_size <= 1024 * 1024:
                raw = trace_path.read_bytes()
                evidence.update(trace_file=str(trace_path), trace_sha256=hashlib.sha256(raw).hexdigest(),
                                trace_bytes=len(raw), trace_scope="partial_recovery_not_complete_execution")
        except (OSError, subprocess.TimeoutExpired):
            evidence["recovery_trace_copy_succeeded"] = False
    try:
        removed = subprocess.run(["docker", "rm", "-f", found["id"]], capture_output=True, timeout=10)
        verified = inspect_container(identity, found["id"])
        evidence.update(cleanup_verified=removed.returncode == 0 and verified["state"] == "absent",
                        cleanup_state=verified["state"])
    except (OSError, subprocess.TimeoutExpired):
        evidence.update(cleanup_verified=False, cleanup_state="cleanup_unavailable")
    return evidence


def docker_probe(code, directory, image, timeout=18, identity=None, on_created=None):
    directory.mkdir(parents=True, exist_ok=False)
    material = directory / "materials"
    material.mkdir()
    # Preserve the exact reviewed bytes on Windows as well as Linux.
    (material / "program.py").write_bytes(code.encode("utf-8"))
    identity = identity or container_identity("standalone_" + secrets.token_hex(12))
    name = identity["name"]
    flags = ["docker", "create", "--name", name, "--label", "org.aegisguard.forensic=true",
        "--label", "org.aegisguard.project=" + identity["project"], "--label", "org.aegisguard.probe=" + identity["probe"],
        "--network", "none", "--read-only", "--memory", "256m", "--memory-swap", "256m", "--cpus", "1",
        "--pids-limit", "64", "--cap-drop", "ALL", "--cap-add", "SYS_PTRACE", "--cap-add", "SETUID", "--cap-add", "SETGID",
        "--security-opt", "no-new-privileges:true", "--ulimit", "nofile=256:256", "--ulimit", "cpu=10:10",
        "--tmpfs", "/work:rw,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0755",
        "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=8m,mode=1777",
        "--tmpfs", "/evidence:rw,nosuid,nodev,noexec,size=8m,mode=0700",
        "--mount", f"type=bind,source={material.resolve()},target=/materials,readonly",
        "--log-driver", "json-file", "--log-opt", "max-size=4m", "--log-opt", "max-file=2", image]
    result = {"status": "failed", "container": name, "image": image, "scope": "test_environment",
              "formal_effects": False, "events": [], "cleanup_verified": False}
    try:
        subprocess.run(flags, capture_output=True, check=True, timeout=15)
        created = inspect_container(identity)
        if created["state"] != "owned":
            raise ValueError("created container ownership cannot be verified")
        result["container_id"] = created["id"]
        if on_created is not None:
            on_created(created["id"])
        run = subprocess.run(["docker", "start", "-a", created["id"]], capture_output=True, timeout=timeout)
        result["collector_exit_code"] = run.returncode
        result["collector_diagnostic"] = run.stderr[-2000:].decode("utf-8", errors="replace")
        if len(run.stdout) > 2 * 1024 * 1024:
            raise ValueError("collector output limit")
        envelope = json.loads(run.stdout)
        raw = base64.b64decode(envelope["trace_b64"], validate=True)
        if len(raw) > 1024 * 1024:
            raise ValueError("trace limit")
        trace = raw.decode("utf-8", errors="replace")
        (directory / "strace.log").write_bytes(raw)
        events = parse_trace(trace)
        traced_candidate = any(e["syscall"] == "execve" and "/materials/program.py" in e["arguments"] and e["succeeded"] for e in events)
        result.update(status="completed" if traced_candidate and not envelope["truncated"] else "incomplete",
                      exit_code=envelope["exit_code"], events=events, trace_sha256=hashlib.sha256(raw).hexdigest(),
                      trace_bytes=len(raw), trace_file=str(directory / "strace.log"),
                      candidate_stdout_untrusted=envelope["stdout"], candidate_stderr_untrusted=envelope["stderr"],
                      material_sha256=sha(code), coverage="one_execution_path_only", collector="strace_kernel_syscalls")
    except subprocess.TimeoutExpired:
        result.update(status="timeout", reason="Sandbox deadline reached; no automatic retry")
    except (OSError, subprocess.CalledProcessError, ValueError, KeyError) as exc:
        result.update(reason=type(exc).__name__)
    finally:
        result.update(cleanup_container(identity, result.get("container_id")))
    return result


def review_fingerprint(call):
    from .service import digest
    return digest({key: call.get(key) for key in ("tool", "args", "parameter_hash", "decision", "execution_status",
                   "report", "reasons", "matched_rules", "policy_version", "approval", "_approved", "control_receipt")})


def trace_projection(result, directory, sandbox_id):
    """Build bounded exact raw-log excerpts, each with a verifiable line reference."""
    projection = {"verified": False, "content": "", "segments": [], "information_gaps": [],
                  "total_events": 0, "reviewed_events": 0, "scope": "bounded_test_path_projection"}
    try:
        path = directory / "strace.log"
        if Path(result.get("trace_file", "")).resolve() != path.resolve():
            raise ValueError("wrong trace path")
        raw = path.read_bytes()
        if len(raw) > 1024 * 1024 or hashlib.sha256(raw).hexdigest() != result.get("trace_sha256"):
            raise ValueError("trace integrity failed")
        text = raw.decode("utf-8", errors="strict")
        events = parse_trace(text)
        lines = text.splitlines()
        selected = [e for e in events if e["category"] in {"process", "network_attempt"} or
                    any(p in e["arguments"] for p in ("/work/", "/materials/", "/evidence/"))]
        projection.update(verified=True, trace_sha256=result["trace_sha256"], total_events=len(events))
        seen = set()
        for event in selected:
            bounds = (event["line"], event["end_line"])
            if bounds in seen:
                continue
            quote = "\n".join(lines[bounds[0] - 1:bounds[1]])
            start = len(projection["content"])
            if len(projection["segments"]) >= 40 or start + len(quote) + 1 > 12000:
                break
            seen.add(bounds)
            projection["content"] += quote + "\n"
            projection["segments"].append({"start": start, "end": start + len(quote), "quote": quote,
                "line": bounds[0], "end_line": bounds[1], "category": event["category"],
                "reference": f"sandbox:{sandbox_id}:strace:{result['trace_sha256']}:L{bounds[0]}-L{bounds[1]}"})
        projection["reviewed_events"] = len(projection["segments"])
        if len(projection["segments"]) < len(selected):
            projection["information_gaps"].append("SANDBOX_PROJECTION_PARTIAL")
        if not projection["segments"]:
            projection["information_gaps"].append("SANDBOX_NO_RELEVANT_TRACE_EVENTS")
    except (OSError, ValueError, UnicodeError, TypeError):
        projection["information_gaps"].append("SANDBOX_TRACE_UNVERIFIED")
    return projection


def supplemental_review(projection, session, call, redactor):
    """One bounded model invocation; late responses have no state-writing path."""
    from .detection import detect, model_configured, model_review
    report = {"status": "incomplete", "semantic_complete": False, "model_attempted": False,
              "model_invocations": 0, "findings": [], "information_gaps": list(projection["information_gaps"]),
              "scope": "test_environment_only", "timeout_seconds": SUPPLEMENTAL_TIMEOUT}
    content = projection["content"]
    if not projection["verified"] or not projection["segments"]:
        return report

    def add_finding(quote, reason, rule_id):
        if not isinstance(quote, str) or not quote:
            return False
        start = content.find(quote)
        if start < 0:
            return False
        end = start + len(quote)
        # A quote must be fully contained in one genuine contiguous log excerpt.
        spans = [s for s in projection["segments"] if s["start"] <= start and end <= s["end"]]
        if not spans:
            return False
        report["findings"].append({"rule_id": rule_id, "quote": quote, "reason": reason,
            "start": start, "end": end, "verified": True, "scope": "test_environment_only",
            "evidence_refs": [s["reference"] for s in spans], "trace_sha256": projection["trace_sha256"]})
        return True

    deterministic = detect(content, "code", use_model=False)
    for finding in deterministic["findings"]:
        add_finding(finding["quote"], finding["reason"], finding["rule_id"])
    report["information_gaps"].extend(deterministic["information_gaps"])
    if not model_configured():
        report["information_gaps"].append("SANDBOX_SEMANTIC_MODEL_NOT_CONFIGURED")
    elif not _SUPPLEMENTAL_SLOT.acquire(blocking=False):
        report["information_gaps"].append("SANDBOX_SUPPLEMENTAL_REVIEW_BUSY")
    else:
        try:
            payload = redactor({"kind": "content", "source_type": "code", "content": content,
                "task": session["intent"], "task_baseline": {"task_id": session["id"], "intent": session["intent"],
                    "scope": session["scope"], "authorization_version": session["authorization_version"]},
                "candidate_operation": {"tool": call["tool"], "args": call["args"]},
                "evidence_scope": "Sandbox syscall observations only. Review observed deviation; no production effect or complete branch coverage is established.",
                "rule_findings": deterministic["findings"]})
        except Exception:
            _SUPPLEMENTAL_SLOT.release()
            raise
        answers = queue.Queue(maxsize=1)
        def worker():
            try:
                from .usage import review_scope
                owner = getattr(redactor, '__self__', None)
                if owner is not None and hasattr(owner, 'store'):
                    with review_scope(owner.store, session['id'], 'sandbox_supplemental'):
                        answers.put_nowait(model_review(payload))
                else:
                    answers.put_nowait(model_review(payload))
            except Exception as exc:
                answers.put_nowait((None, type(exc).__name__))
            finally:
                _SUPPLEMENTAL_SLOT.release()
        report.update(model_attempted=True, model_invocations=1)
        try:
            threading.Thread(target=worker, daemon=True, name="aegis-sandbox-supplemental").start()
        except Exception:
            _SUPPLEMENTAL_SLOT.release()
            raise
        try:
            answer, error = answers.get(timeout=SUPPLEMENTAL_TIMEOUT)
            if error or not answer:
                report["information_gaps"].append("SANDBOX_SUPPLEMENTAL_REVIEW_FAILED")
                report["error"] = error or "empty_response"
            else:
                report["information_gaps"].extend(answer["information_gaps"])
                report["semantic_complete"] = answer["relation"] != "uncertain" and not answer["information_gaps"]
                if answer["relation"] == "uncertain":
                    report["information_gaps"].append("SANDBOX_SEMANTIC_UNCERTAIN")
                if answer["risk"] or answer["relation"] == "deviating":
                    verified = add_finding(answer.get("quote"), answer["reason"], "model.sandbox_verified")
                    if not verified:
                        report["semantic_complete"] = False
                        report["information_gaps"].append("SANDBOX_RISK_QUOTE_UNVERIFIED")
        except queue.Empty:
            report.update(late_results_discarded=True, semantic_complete=False)
            report["information_gaps"].append("SANDBOX_SUPPLEMENTAL_REVIEW_TIMEOUT")
    report["information_gaps"] = list(dict.fromkeys(report["information_gaps"]))
    report["status"] = "risk" if report["findings"] else "clear_within_projection" if report["semantic_complete"] else "incomplete"
    return report


class Forensics:
    def __init__(self, service):
        self.service = service

    def recover_interrupted(self):
        """Run after acquiring the service owner lock; never re-run a probe."""
        from .service import now
        service = self.service
        for attempt in service.store.all("sandbox"):
            interrupted_cleanup = (attempt.get("status") == "interrupted" and not attempt.get("cleanup_verified")
                                   and attempt.get("container_identity"))
            if attempt.get("status") not in {"registered", "running", "reviewing", "recovering"} and not interrupted_cleanup:
                continue
            # Make interruption durable before Docker I/O, without clearing the
            # call's attempt marker. A second crash can safely resume cleanup.
            with service.store.transaction():
                attempt.update(status="recovering", recovery_reason="guard_process_interrupted", formal_execution_permit=False)
                service.store.put("sandbox", attempt)
            directory = service.store.directory / "sandbox" / attempt["id"]
            cleanup = cleanup_container(attempt.get("container_identity"), attempt.get("container_id"), directory)
            # Existing host evidence is retained even if Docker cannot be reached.
            trace = directory / "strace.log"
            if trace.is_file() and trace.stat().st_size <= 1024 * 1024:
                raw = trace.read_bytes()
                cleanup.update(trace_file=str(trace), trace_sha256=hashlib.sha256(raw).hexdigest(), trace_bytes=len(raw),
                               trace_scope="partial_recovery_not_complete_execution")
            with service.store.transaction():
                attempt.update(cleanup, status="interrupted", finished_at=now(), applicable_to_current_review=False)
                service.store.put("sandbox", attempt)
                service.event(attempt["session_id"], "sandbox.interrupted", "服务重启：取证中断，保留单次预算；未自动重试", call_id=attempt["call_id"],
                              details={"sandbox_id": attempt["id"], "cleanup_verified": attempt["cleanup_verified"], "cleanup_state": attempt["cleanup_state"]})

    def register(self, session_id, code, label):
        from .service import ident, now
        service = self.service
        session = service.require("session", session_id)
        if session["scope"] != "development":
            raise HTTPException(409, "只读任务不能授权项目脚本取证")
        try:
            analysis = analyze(code)
        except (SyntaxError, ValueError, RecursionError):
            raise HTTPException(422, "脚本必须是可解析的有界 Python 源码")
        record = {"id": ident("script"), "session_id": session_id, "created_at": now(), "label": label,
                  "_code": code, "sha256": sha(code), "analysis": analysis, "authorization": "operator_registered_test_copy",
                  "material_policy": "public_synthetic_only", "version": 1}
        with service.store.transaction():
            service.store.put("script", record)
            service.event(session_id, "script.registered", "登记授权测试材料及不可变版本", details={"script_id": record["id"], "sha256": record["sha256"]})
        return service.public_view(record)

    def run(self, call_id):
        from .service import ident, now, digest
        service = self.service
        with service.store.transaction():
            call = service.require("call", call_id)
            check = script_precheck(service, call["session_id"], call)
            if (call["tool"] != "script.run" or call["decision"] != "confirm" or
                call["execution_status"] != "pending" or call.get("_sandbox_attempt") or
                call.get("_superseded_by") or call.get("_recheck_in_progress") or call.get("control_receipt") or
                not check or not check.get("valid") or check.get("prohibited") or not check.get("gaps") or
                service.require("session", call["session_id"])["scope"] != "development" or
                call["policy_version"] != service.policy()["version"] or
                call.get("_review_context") != service.context_binding(call["session_id"], call) or
                any(r.startswith("core.") for r in call["matched_rules"]) or
                service.data_flow_errors(call["session_id"], call)):
                raise HTTPException(409, "不满足单轮沙箱取证前置条件，或本轮已经尝试")
            attempt = {"id": ident("sbx"), "session_id": call["session_id"], "call_id": call_id,
                       "created_at": now(), "status": "registered", "rules": [GAPS[x] for x in check["gaps"]],
                       "script_sha256": check["sha256"], "parameter_hash": call["parameter_hash"],
                       "context": service.context_binding(call["session_id"], call), "policy_version": service.policy()["version"],
                       "scope": "test_environment", "formal_execution_permit": False,
                       "permit": {"id": ident("sbxp"), "used": True, "expires_at": time.time() + 30,
                                  "network": "none", "memory_mb": 256, "pids": 64, "seconds": 18},
                       "remaining_gaps": check["gaps"], "supplemental_review_count": 0,
                       "original_report": copy.deepcopy(call["report"]), "original_report_sha256": digest(call["report"]),
                       "review_snapshot_sha256": review_fingerprint(call)}
            attempt["container_identity"] = container_identity(attempt["id"])
            call["_sandbox_attempt"] = attempt["id"]
            call["sandbox_id"] = attempt["id"]
            service.store.put("call", call)
            service.store.put("sandbox", attempt)
            code = service.require("script", check["script_id"])["_code"]
        # No database transaction/business lock across Docker or model waits.
        try:
            if time.time() >= attempt["permit"]["expires_at"]:
                raise ValueError("sandbox permit expired")
            def created(container_id):
                # The name/probe labels were committed before Docker create;
                # persist the immutable ID before any candidate can start.
                with service.store.transaction():
                    attempt.update(container_id=container_id, status="running")
                    service.store.put("sandbox", attempt)
            result = docker_probe(code, service.store.directory / "sandbox" / attempt["id"], image_id(),
                                  identity=attempt["container_identity"], on_created=created)
        except Exception as exc:
            result = {"status": "failed", "reason": type(exc).__name__, "events": []}
        projection = trace_projection(result, service.store.directory / "sandbox" / attempt["id"], attempt["id"])
        result["supplemental_projection"] = {key: value for key, value in projection.items() if key not in {"content", "segments"}}
        usable = bool(projection["verified"] and projection["segments"])
        if usable:
            attempt["supplemental_review_count"] = 1
            # Persist the closed review budget before the model wait. A crash
            # during this wait is recovered as interrupted, never reviewed twice.
            with service.store.transaction():
                running = {**attempt, **result, "probe_status": result["status"], "status": "reviewing"}
                service.store.put("sandbox", running)
            try:
                result["supplemental_review"] = supplemental_review(projection, service.require("session", call["session_id"]), call, service.public_view)
            except Exception as exc:
                result["supplemental_review"] = {"status": "failed", "semantic_complete": False, "findings": [],
                    "information_gaps": ["SANDBOX_SUPPLEMENTAL_REVIEW_FAILED"], "reason": type(exc).__name__}
        else:
            result["supplemental_review"] = {"status": "not_run", "semantic_complete": False, "findings": [],
                "model_attempted": False, "model_invocations": 0, "information_gaps": projection["information_gaps"]}
        with service.store.transaction():
            current = service.require("call", call_id)
            current_check = script_precheck(service, call["session_id"], current)
            session = service.require("session", call["session_id"])
            policy = service.policy()
            checks = {"candidate_binding": bool(current_check and current_check.get("valid") and
                        current_check.get("sha256") == attempt["script_sha256"] and current["parameter_hash"] == attempt["parameter_hash"]),
                      "authorization_valid": session["scope"] == "development", "policy_version": policy["version"] == attempt["policy_version"],
                      "context": attempt["context"] == service.context_binding(call["session_id"], current),
                      "review_unchanged": attempt["review_snapshot_sha256"] == review_fingerprint(current),
                      "data_flow": not service.data_flow_errors(call["session_id"], current)}
            stale = (not all(checks.values()) or current.get("_superseded_by") or current.get("_recheck_in_progress") or
                     current.get("_sandbox_attempt") != attempt["id"] or current["execution_status"] != "pending")
            attempt.update(result, finished_at=now(), applicable_to_current_review=not bool(stale))
            supplemental = result["supplemental_review"]
            gaps = list(dict.fromkeys(current["information_gaps"] + attempt["remaining_gaps"] + supplemental["information_gaps"] +
                        ["SANDBOX_ONE_PATH_ONLY", "FORMAL_EXECUTION_CHECKS_UNRESOLVED"]))
            if result["status"] != "completed":
                gaps.append("SANDBOX_EXECUTION_INCOMPLETE")
            if not result.get("cleanup_verified"):
                gaps.append("SANDBOX_CLEANUP_UNVERIFIED")
            references = [s["reference"] for s in projection["segments"]] if usable else []
            recheck = {"status": "stale" if stale else "applied", "decision_before": call["decision"], "decision_after": current["decision"],
                       "reason": "审查状态、授权、策略或上下文已改变；补审结果仅归档，不修改现有决定" if stale else "测试路径证据已纳入复查；仍有正式执行检查及分支覆盖缺口，保持待确认",
                       "checks": checks, "evidence_refs": references, "findings": supplemental.get("findings", []),
                       "remaining_gaps": gaps, "original_report_sha256": attempt["original_report_sha256"],
                       "scope": "test_environment_only", "formal_execution_permit": False}
            if not stale:
                from .policy import review
                candidate = {**current, "_script_precheck": current_check,
                             "_data_flow_errors": service.data_flow_errors(call["session_id"], current)}
                deterministic = review(session, candidate, [service.require("source", sid) for sid in current["source_ids"]],
                    service.store.all("call", call["session_id"]), policy, approved=current.get("_approved", False), use_model=False,
                    observed_sources=service.store.all("source", call["session_id"]))
                checks["deterministic_decision"] = deterministic["decision"]
                block = deterministic["decision"] == "block" or bool(supplemental.get("findings"))
                decision = "block" if block else "confirm"
                reason = "沙箱补审发现可核验风险或必要检查未通过，正式操作已阻断" if block else recheck["reason"]
                recheck.update(decision_after=decision, reason=reason)
                recheck["remaining_gaps"] = list(dict.fromkeys(gaps + deterministic["information_gaps"]))
                current.update(decision=decision, execution_status="not_executed" if block else "pending",
                    risk_score=max(current["risk_score"], deterministic["risk_score"], 85 if block else 55),
                    reasons=list(dict.fromkeys(current["reasons"] + deterministic["reasons"] + [reason])),
                    matched_rules=list(dict.fromkeys(current["matched_rules"] + deterministic["matched_rules"] +
                        (["review.sandbox_verified_risk"] if supplemental.get("findings") else ["review.sandbox_remaining_gap"]))),
                    information_gaps=recheck["remaining_gaps"])
                current["severity"] = "critical" if current["risk_score"] >= 95 else "high" if current["risk_score"] >= 75 else "medium"
                if current.get("_permit"):
                    current["_permit"]["revoked"] = True
                current["report"].update(sandbox_review=copy.deepcopy(recheck),
                    prior_report_ref=f"sandbox:{attempt['id']}:original_report", task_relation="deviating" if block else "uncertain",
                    deviation_level="high" if block else "medium", reason=reason,
                    evidence_refs=list(dict.fromkeys(current["report"].get("evidence_refs", []) + references)),
                    information_gaps=recheck["remaining_gaps"])
                service.store.put("call", current)
            attempt["recheck"] = recheck
            attempt["remaining_gaps"] = recheck["remaining_gaps"]
            attempt["decision_after"] = current["decision"]
            service.store.put("sandbox", attempt)
            service.event(call["session_id"], "sandbox.rechecked", recheck["reason"], call_id=call_id,
                          details={"sandbox_id": attempt["id"], "status": recheck["status"], "decision": recheck["decision_after"],
                                   "original_report_sha256": attempt["original_report_sha256"], "evidence_refs": references,
                                   "remaining_gaps": recheck["remaining_gaps"]})
            service.event(call["session_id"], "sandbox.completed", "单轮取证结束；正式操作仍按原授权与剩余缺口控制", call_id=call_id,
                          details={"sandbox_id": attempt["id"], "status": attempt["status"], "scope": "test_environment"})
        return service.public_view(attempt)
