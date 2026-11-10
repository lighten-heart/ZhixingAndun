"""Database paths must preserve read-only semantics and Windows sidecar access."""
from contextlib import closing
import os
import sqlite3

import pytest

from backend.storage import Store, sqlite_filename, sqlite_readonly_uri


def test_readonly_snapshot_preserves_literal_filename(tmp_path):
    source = tmp_path / "source # 中文.sqlite3"
    with closing(sqlite3.connect(sqlite_filename(source))) as db:
        db.execute("CREATE TABLE facts(value TEXT)")
        db.execute("INSERT INTO facts VALUES ('original')")
        db.commit()
    with closing(sqlite3.connect(sqlite_readonly_uri(source), uri=True)) as db:
        assert db.execute("SELECT value FROM facts").fetchall() == [("original",)]
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            db.execute("DELETE FROM facts")
    missing = tmp_path / "missing # source.sqlite3"
    with pytest.raises(sqlite3.OperationalError):
        sqlite3.connect(sqlite_readonly_uri(missing), uri=True)
    assert not missing.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows MAX_PATH and SQLite sidecars")
def test_long_path_wal_backup_and_reopen(tmp_path):
    directory = tmp_path
    while len(str(directory)) < 280:
        directory = directory / "nested-evidence-directory"
    store = Store(directory, "")
    store.put("fact", {"id": "preserved", "value": "中文🙂"})
    with pytest.raises(ValueError):
        with store.transaction():
            store.put("fact", {"id": "rollback", "value": "must not persist"})
            raise ValueError("rollback")
    store.close()
    backup = directory / "snapshot.sqlite3"
    with closing(sqlite3.connect(sqlite_readonly_uri(directory / "guard.sqlite3"), uri=True)) as source, \
            closing(sqlite3.connect(sqlite_filename(backup))) as target:
        source.backup(target)
        assert target.execute("SELECT id FROM records").fetchall() == [("preserved",)]
    reopened = Store(directory, "")
    try:
        assert reopened.get("fact", "preserved")["value"] == "中文🙂"
        assert reopened.get("fact", "rollback") is None
    finally:
        reopened.close()
