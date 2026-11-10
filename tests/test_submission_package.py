"""Submission-copy regressions using temporary sources and synthetic reports."""
import builtins
import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from backend import code_fingerprint, main


def write(root, relative, raw):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return path


def json_bytes(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True).encode("utf-8")


def test_source_fingerprint_preserves_file_selection_and_exact_byte_hashes(tmp_path):
    # Explicit expected membership records the pre-extraction public contract.
    # The oracle does not import the removed development tools.
    included = {
        "backend/core.py": b"one\r\ntwo\r\n",
        "backend/nested/policy.yaml": b"enabled: true\n",
        "adapters/bridge.mjs": "export const label = '安全';\n".encode("utf-8"),
        "sandbox/probe.py": b"print('probe')\n",
        "scripts/optional.py": b"optional_source = True\n",
        "frontend/src/app.tsx": b"export const App = () => null;\n",
        "frontend/src/types.ts": b"export type Verdict = string;\n",
        "frontend/src/helpers.js": b"export const value = 1;\n",
        "frontend/src/style.css": b"body { margin: 0; }\n",
        "evals/promptfoo/cases.json": b'{"tests": []}\n',
        "requirements.txt": b"example==1\n",
        "requirements.lock.txt": b"example==1\r\n",
        "evals/requirements.txt": b"optional==2\n",
        "frontend/package.json": b'{"private": true}\n',
        "frontend/package-lock.json": b'{"lockfileVersion": 3}\n',
        "Dockerfile": b"FROM python:3.12-slim\n",
        "sandbox/Dockerfile": b"FROM python:3.12-slim\nRUN true\n",
        "assets/tokenizer/manifest.json": b'{"version": "fixture"}\n',
        "compose.infrastructure.yaml": b"services: {}\n",
    }
    ignored = {
        "backend/node_modules/vendor.py",
        "backend/__pycache__/cached.py",
        "frontend/src/nested/node_modules/vendor.ts",
        "frontend/src/__pycache__/cached.json",
        "backend/readme.md",
        "backend/module.pyc",
        "backend/unsupported.yml",
        "frontend/dist/bundle.js",
        "output/report.json",
        "tests/test_example.py",
        "assets/tokenizer/tokenizer.json",
        ".env",
        "README.md",
    }
    for relative, raw in included.items():
        write(tmp_path, relative, raw)
    for relative in ignored:
        write(tmp_path, relative, b"excluded fixture\n")

    expected = {relative: hashlib.sha256(raw).hexdigest()
                for relative, raw in included.items()}
    actual = code_fingerprint.fingerprint(tmp_path)
    assert actual == expected
    assert list(actual) == sorted(expected, key=lambda relative: tmp_path / relative)
    assert all("\\" not in relative for relative in actual)

    # Report/provenance checks must notice byte changes without absorbing output.
    write(tmp_path, "backend/core.py", b"one\ntwo\n")
    changed = code_fingerprint.fingerprint(tmp_path)
    assert {name for name in actual if actual[name] != changed[name]} == {"backend/core.py"}
    write(tmp_path, "output/report.json", b"another report\n")
    assert code_fingerprint.fingerprint(tmp_path) == changed


def test_source_fingerprint_allows_omitted_development_directories(tmp_path, monkeypatch):
    write(tmp_path, "backend/main.py", b"application = True\n")
    monkeypatch.setattr(code_fingerprint, "ROOT", tmp_path)
    expected = {"backend/main.py": hashlib.sha256(b"application = True\n").hexdigest()}
    assert not (tmp_path / "scripts").exists()
    assert not (tmp_path / "evals").exists()
    assert code_fingerprint.fingerprint() == expected
    assert code_fingerprint.fingerprint(tmp_path / "absent") == {}


@pytest.mark.parametrize("endpoint", ["/api/evaluations/blind", "/api/agent-comparisons"])
@pytest.mark.parametrize("report_state", ["missing", "matching", "changed"])
def test_evaluation_routes_work_without_development_scripts(tmp_path, monkeypatch, endpoint, report_state):
    root = tmp_path / "submission"
    write(root, "backend/core.py", b"original source\n")
    monkeypatch.setattr(main, "PROJECT_ROOT", root)
    monkeypatch.setattr(code_fingerprint, "ROOT", root)
    code = code_fingerprint.fingerprint()
    retained = []
    if report_state != "missing":
        if endpoint == "/api/evaluations/blind":
            retained.append(write(root, "output/blind-latest.json", json_bytes({
                "available": True, "code": code, "cases": 1,
            })))
        else:
            manifest = json_bytes({"code": code, "created_at": "2026-10-22T00:00:00Z"})
            retained.append(write(root, "output/agent-comparison/fixture/manifest.json", manifest))
            retained.append(write(root, "output/agent-comparison/fixture/report.json", json_bytes({
                "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
                "completed": True, "arms": {}, "rows": [{"case_id": "fixture"}],
                "scope": "synthetic_packaging_regression",
            })))
    if report_state == "changed":
        write(root, "backend/core.py", b"modified source\n")
    before = {path: path.read_bytes() for path in retained}
    assert not (root / "scripts").exists()
    assert not (root / "evals").exists()

    original_import = builtins.__import__

    def no_development_import(name, *args, **kwargs):
        if name == "scripts" or name.startswith("scripts."):
            raise AssertionError("Runtime report API imported omitted development tools")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_development_import)
    with TestClient(main.create_app(data_dir=tmp_path / "database")) as client:
        response = client.get(endpoint)
    assert response.status_code == 200, response.text
    data = response.json()
    if report_state == "missing":
        assert data == ({"available": False} if endpoint.endswith("/blind") else [])
    else:
        report = data if endpoint.endswith("/blind") else data[0]
        assert report["current_code_matches"] is (report_state == "matching")
        if endpoint.endswith("/blind"):
            assert report["available"] is True and report["cases"] == 1
        else:
            assert len(data) == 1 and report["id"] == "fixture" and report["runs"] == 1
    assert {path: path.read_bytes() for path in retained} == before
