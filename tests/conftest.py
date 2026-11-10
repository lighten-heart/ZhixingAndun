"""Isolate collection/imports from any operator data or live model configuration."""
import os
import tempfile
from pathlib import Path
import uuid

_collection_data = tempfile.TemporaryDirectory(prefix="aegis-pytest-import-")
for _name in list(os.environ):
    if _name.startswith("GUARD_"):
        os.environ.pop(_name)
os.environ["GUARD_DATA_DIR"] = _collection_data.name
# A missing caller override must never replace evidence from a prior run.
os.environ.setdefault("AEGIS_TEST_EVIDENCE_DIR", str(
    Path(__file__).resolve().parents[1] / "output/engineering-runs" / uuid.uuid4().hex))


def pytest_unconfigure(config):
    _collection_data.cleanup()
