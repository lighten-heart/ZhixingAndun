"""Recovery preserves the consumed attempt and only touches its owned container."""
import base64
import hashlib
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from backend.forensics import Forensics, cleanup_container, container_identity, docker_probe
from backend.service import GuardService
from backend.storage import Store


def prepare_interruption(tmp_path, monkeypatch):
    service = GuardService(tmp_path)
    session = service.create_session({"title": "recovery", "intent": "Check the public test script in isolation",
                                      "scope": "development", "agent_id": "main"})
    forensic = Forensics(service)
    script = forensic.register(session["id"], "open('/work/result.txt', 'w').write('ok')", "test copy")
    call = service.review_call(session["id"], {"tool": "script.run", "args": {"script_id": script["id"]}})
    monkeypatch.setattr("backend.forensics.image_id", lambda: "sha256:" + "a" * 64)
    def crash(*args, identity, on_created, **kwargs):
        persisted = service.store.all("sandbox")[0]
        assert persisted["container_identity"] == identity  # committed before Docker create
        assert service.store._depth == 0
        on_created("b" * 64)
        assert service.store.all("sandbox")[0]["container_id"] == "b" * 64
        raise SystemExit("injected guard-process loss")
    monkeypatch.setattr("backend.forensics.docker_probe", crash)
    with pytest.raises(SystemExit):
        forensic.run(call["id"])
    attempt = service.store.all("sandbox")[0]
    service.store.close()
    return call, attempt


def inspector(identity, identifier="b" * 64, **overrides):
    data = {"Name": "/" + identity["name"], "Id": identifier, "State": {"Running": True},
            "Config": {"Labels": {"org.aegisguard.forensic": "true", "org.aegisguard.project": identity["project"],
                                  "org.aegisguard.probe": identity["probe"]}}}
    data.update(overrides)
    return SimpleNamespace(returncode=0, stdout=json.dumps([data]), stderr="")


def test_interruption_recovers_trace_and_keeps_consumed_budget(tmp_path, monkeypatch):
    call, attempt = prepare_interruption(tmp_path, monkeypatch)
    calls, deleted = [], []
    raw = b'12 write(1, "test", 4) = 4\n'
    def docker(command, **kwargs):
        calls.append(command)
        if command[1] == "inspect":
            if deleted:
                return SimpleNamespace(returncode=1, stdout="", stderr="Error: No such object: test")
            return inspector(attempt["container_identity"])
        if command[1] == "exec":
            assert command[2:8] == ["--user", "0", "b" * 64, "/usr/local/bin/python3", "-I", "-c"]
            assert "/materials/" not in command[-1] and "read(1048577)" in command[-1]
            return SimpleNamespace(returncode=0, stdout=raw, stderr=b"")
        elif command[1] == "rm":
            assert command[2:] == ["-f", "b" * 64]
            deleted.append(True)
        else:
            pytest.fail("Recovery must not create/start a container")
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    monkeypatch.setattr("backend.forensics.subprocess.run", docker)
    restarted = GuardService(tmp_path)
    try:
        recovered = restarted.require("sandbox", attempt["id"])
        assert recovered["status"] == "interrupted"
        assert recovered["cleanup_verified"] is True
        assert recovered["trace_sha256"] == hashlib.sha256(raw).hexdigest()
        assert recovered["trace_scope"] == "partial_recovery_not_complete_execution"
        assert recovered["applicable_to_current_review"] is False
        assert recovered["formal_execution_permit"] is False
        assert restarted.require("call", call["id"])["_sandbox_attempt"] == attempt["id"]
        with pytest.raises(HTTPException) as error:
            Forensics(restarted).run(call["id"])
        assert error.value.status_code == 409
        assert recovered["recovery_trace_method"] == "bounded_live_read"
        assert [c[1] for c in calls] == ["inspect", "exec", "rm", "inspect"]
    finally:
        restarted.store.close()


@pytest.mark.parametrize("mismatch", ["project", "probe", "forensic", "name", "container_id"])
def test_cleanup_never_removes_different_container(monkeypatch, mismatch):
    identity = container_identity("sbx_" + "a" * 16)
    value = json.loads(inspector(identity).stdout)[0]
    if mismatch in {"project", "probe", "forensic"}:
        value["Config"]["Labels"]["org.aegisguard." + mismatch] = "wrong"
    elif mismatch == "name":
        value["Name"] = "/other"
    else:
        value["Id"] = "c" * 64
    calls = []
    def docker(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout=json.dumps([value]), stderr="")
    monkeypatch.setattr("backend.forensics.subprocess.run", docker)
    result = cleanup_container(identity, "b" * 64, preserve_directory=Path("unused"))
    assert result == {"cleanup_verified": False, "cleanup_state": "ownership_mismatch"}
    assert len(calls) == 1 and calls[0][1] == "inspect"


def test_daemon_unavailable_is_not_verified_cleanup_and_retries_only_cleanup(tmp_path, monkeypatch):
    _, attempt = prepare_interruption(tmp_path, monkeypatch)
    trace = tmp_path / "sandbox" / attempt["id"] / "strace.log"
    trace.parent.mkdir(parents=True)
    trace.write_bytes(b"existing raw evidence")
    commands = []
    def offline(command, **kwargs):
        commands.append(command)
        return SimpleNamespace(returncode=1, stdout="", stderr="Cannot connect to the Docker daemon")
    monkeypatch.setattr("backend.forensics.subprocess.run", offline)
    restarted = GuardService(tmp_path)
    saved = restarted.require("sandbox", attempt["id"])
    assert saved["cleanup_verified"] is False and saved["cleanup_state"] == "unavailable"
    assert saved["trace_sha256"] == hashlib.sha256(trace.read_bytes()).hexdigest()
    restarted.store.close()
    def absent(command, **kwargs):
        commands.append(command)
        return SimpleNamespace(returncode=1, stdout="", stderr="Error: No such object: probe")
    monkeypatch.setattr("backend.forensics.subprocess.run", absent)
    restarted = GuardService(tmp_path)
    assert restarted.require("sandbox", attempt["id"])["cleanup_verified"] is True
    assert all(command[1] == "inspect" for command in commands)
    assert trace.read_bytes() == b"existing raw evidence"
    restarted.store.close()


def test_legacy_probe_without_identity_is_not_guessed(tmp_path, monkeypatch):
    _, attempt = prepare_interruption(tmp_path, monkeypatch)
    store = Store(tmp_path, "")
    attempt.pop("container_identity")
    store.put("sandbox", attempt)
    store.close()
    monkeypatch.setattr("backend.forensics.subprocess.run", lambda *a, **k: pytest.fail("No identity, no Docker call"))
    restarted = GuardService(tmp_path)
    recovered = restarted.require("sandbox", attempt["id"])
    assert recovered["status"] == "interrupted"
    assert recovered["cleanup_state"] == "identity_unverified"
    assert recovered["cleanup_verified"] is False
    restarted.store.close()


def test_owner_lock_failure_prevents_recovery(tmp_path, monkeypatch):
    def deny(store):
        store.close()
        raise RuntimeError("another runtime owns the database")
    monkeypatch.setattr(Store, "acquire_runtime", deny)
    monkeypatch.setattr(Forensics, "recover_interrupted", lambda self: pytest.fail("Recovery before ownership"))
    with pytest.raises(RuntimeError, match="another runtime"):
        GuardService(tmp_path)


def test_container_id_persisted_before_start_and_cleanup_uses_id(tmp_path, monkeypatch):
    identity = container_identity("sbx_" + "d" * 16)
    persisted, removed = [], []
    trace = b'12 execve("/usr/local/bin/python3", ["python3", "-I", "/materials/program.py"], 0x0) = 0\n'
    envelope = {"trace_b64": base64.b64encode(trace).decode(), "truncated": False, "exit_code": 0, "stdout": "", "stderr": ""}
    def docker(command, **kwargs):
        if command[1] == "create":
            assert "org.aegisguard.project=" + identity["project"] in command
            assert "org.aegisguard.probe=" + identity["probe"] in command
        elif command[1] == "inspect":
            if removed:
                return SimpleNamespace(returncode=1, stdout="", stderr="Error: No such object: probe")
            return inspector(identity)
        elif command[1] == "start":
            assert persisted == ["b" * 64]
            assert command[-1] == "b" * 64
            return SimpleNamespace(returncode=0, stdout=json.dumps(envelope).encode(), stderr=b"")
        elif command[1] == "rm":
            assert command[-1] == "b" * 64
            removed.append(True)
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    monkeypatch.setattr("backend.forensics.subprocess.run", docker)
    result = docker_probe("print('test')", tmp_path / "probe", "sha256:" + "a" * 64,
                          identity=identity, on_created=persisted.append)
    assert result["status"] == "completed" and result["cleanup_verified"] is True


def test_trace_copy_failure_still_cleans_owned_container(tmp_path, monkeypatch):
    identity = container_identity("sbx_" + "f" * 16)
    removed = []
    def docker(command, **kwargs):
        if command[1] == "inspect":
            return (SimpleNamespace(returncode=1, stdout="", stderr="No such object: probe") if removed
                    else inspector(identity))
        if command[1] == "exec":
            raise subprocess.TimeoutExpired(command, 5)
        assert command[1] == "rm"
        removed.append(True)
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr("backend.forensics.subprocess.run", docker)
    result = cleanup_container(identity, preserve_directory=tmp_path)
    assert result["recovery_trace_copy_succeeded"] is False
    assert result["cleanup_verified"] is True


@pytest.mark.parametrize("returncode,raw", [(1, b"error"), (0, b""), (0, b"x" * 1048577)],
                         ids=["read-failed", "empty", "oversized"])
def test_invalid_live_trace_is_not_saved_but_container_is_cleaned(tmp_path, monkeypatch, returncode, raw):
    identity = container_identity("sbx_" + "a" * 16)
    removed = []
    def docker(command, **kwargs):
        if command[1] == "inspect":
            return (SimpleNamespace(returncode=1, stdout="", stderr="No such object: probe") if removed
                    else inspector(identity))
        if command[1] == "exec":
            return SimpleNamespace(returncode=returncode, stdout=raw, stderr=b"")
        assert command[1] == "rm"
        removed.append(True)
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr("backend.forensics.subprocess.run", docker)
    result = cleanup_container(identity, preserve_directory=tmp_path)
    assert result["recovery_trace_copy_succeeded"] is False
    assert result["cleanup_verified"] is True
    assert "trace_sha256" not in result and not (tmp_path / "strace.log").exists()


def test_stopped_container_uses_archive_without_starting_it(tmp_path, monkeypatch):
    identity = container_identity("sbx_" + "a" * 16)
    removed = []
    def docker(command, **kwargs):
        if command[1] == "inspect":
            return (SimpleNamespace(returncode=1, stdout="", stderr="No such object: probe") if removed
                    else inspector(identity, State={"Running": False}))
        if command[1] == "cp":
            Path(command[3]).write_bytes(b"retained trace")
        else:
            assert command[1] == "rm"
            removed.append(True)
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr("backend.forensics.subprocess.run", docker)
    result = cleanup_container(identity, preserve_directory=tmp_path)
    assert result["recovery_trace_copy_succeeded"] is True
    assert result["recovery_trace_method"] == "stopped_container_archive"
    assert result["cleanup_verified"] is True
