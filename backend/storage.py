"""Durable evidence store with serialized PostgreSQL/SQLite transactions."""
import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import quote

TRANSACTION_LOCK = 72514321001
RUNTIME_LOCK = 72514321002


def sqlite_filename(path: str | Path) -> str:
    """Include Windows journal/WAL files in support for long absolute paths."""
    value = str(Path(path).resolve())
    if os.name == "nt" and not value.startswith("\\\\?\\"):
        return "\\\\?\\UNC\\" + value[2:] if value.startswith("\\\\") else "\\\\?\\" + value
    return value


def sqlite_readonly_uri(path: str | Path) -> str:
    # Encode '?' in the Windows prefix and '#'/'?' in filenames as data.
    return "file:" + quote(sqlite_filename(path), safe="/") + "?mode=ro"


class Store:
    def __init__(self, directory: str | Path, database_url: str | None = None):
        self.directory = Path(directory).resolve()
        Path(sqlite_filename(self.directory)).mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self._depth = 0
        self._runtime_owned = False
        url = os.getenv("GUARD_DATABASE_URL", "") if database_url is None else database_url
        self.backend = "postgresql" if url else "sqlite"
        if url:
            if not url.startswith(("postgresql://", "postgres://")):
                raise ValueError("GUARD_DATABASE_URL must be a PostgreSQL URL")
            import psycopg
            self.connection = psycopg.connect(url, autocommit=True, connect_timeout=10,
                                             application_name="aegisguard",
                                             options="-c statement_timeout=15000 -c lock_timeout=10000")
            with self.transaction():
                self._execute("CREATE TABLE IF NOT EXISTS records (row_seq BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE,kind TEXT NOT NULL,id TEXT PRIMARY KEY,session_id TEXT,created_at TEXT NOT NULL,data TEXT NOT NULL)")
                self._execute("CREATE INDEX IF NOT EXISTS records_kind_session ON records(kind,session_id)")
                self._execute("CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY,data TEXT NOT NULL)")
        else:
            self.connection = sqlite3.connect(sqlite_filename(self.directory / "guard.sqlite3"), check_same_thread=False, isolation_level=None)
            self.connection.execute("PRAGMA journal_mode=WAL")
            self.connection.execute("PRAGMA synchronous=FULL")
            self.connection.execute("PRAGMA busy_timeout=10000")
            self.connection.execute("CREATE TABLE IF NOT EXISTS records (kind TEXT NOT NULL,id TEXT PRIMARY KEY,session_id TEXT,created_at TEXT NOT NULL,data TEXT NOT NULL)")
            self.connection.execute("CREATE INDEX IF NOT EXISTS records_kind_session ON records(kind,session_id)")
            self.connection.execute("CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY,data TEXT NOT NULL)")
        # Keep old history off the hot path of the frequently refreshed console.
        suffix = ',row_seq DESC' if self.backend == 'postgresql' else ''
        self._execute(f'CREATE INDEX IF NOT EXISTS records_history_order ON records(kind,created_at DESC{suffix})')

    def _execute(self, sql, args=()):
        return self.connection.execute(sql.replace("?", "%s") if self.backend == "postgresql" else sql, args)

    def acquire_runtime(self):
        """Reject a second server before it can recover a live owner's calls."""
        with self.lock:
            if self.backend == "postgresql" and not self._runtime_owned:
                if not self._execute("SELECT pg_try_advisory_lock(?)", (RUNTIME_LOCK,)).fetchone()[0]:
                    self.close()
                    raise RuntimeError("Another AegisGuard service owns this database; use one worker")
                self._runtime_owned = True

    @contextmanager
    def transaction(self):
        with self.lock:
            depth = self._depth
            savepoint = f"aegis_nested_{depth}"
            if depth:
                self._execute(f"SAVEPOINT {savepoint}")
            else:
                self._execute("BEGIN" if self.backend == "postgresql" else "BEGIN IMMEDIATE")
            self._depth += 1
            try:
                if not depth and self.backend == "postgresql":
                    self._execute("SELECT pg_advisory_xact_lock(?)", (TRANSACTION_LOCK,))
                yield
                self._execute(f"RELEASE SAVEPOINT {savepoint}" if depth else "COMMIT")
            except BaseException:
                if depth:
                    self._execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                    self._execute(f"RELEASE SAVEPOINT {savepoint}")
                else:
                    self._execute("ROLLBACK")
                raise
            finally:
                self._depth -= 1

    def put(self, kind: str, record: dict[str, Any]):
        with self.lock:
            self._execute(
                "INSERT INTO records(kind,id,session_id,created_at,data) VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data WHERE records.kind=excluded.kind",
                (kind, record["id"], record.get("session_id", record.get("source_session_id")), record.get("created_at", record.get("timestamp", "")), json.dumps(record, ensure_ascii=False)),
            )

    def get(self, kind: str, identifier: str) -> dict | None:
        with self.lock:
            row = self._execute("SELECT data FROM records WHERE kind=? AND id=?", (kind, identifier)).fetchone()
            return json.loads(row[0]) if row else None

    def all(self, kind: str, session_id: str | None = None) -> list[dict]:
        order = "row_seq" if self.backend == "postgresql" else "rowid"
        with self.lock:
            if session_id is None:
                rows = self._execute(f"SELECT data FROM records WHERE kind=? ORDER BY created_at DESC,{order} DESC", (kind,)).fetchall()
            else:
                rows = self._execute(f"SELECT data FROM records WHERE kind=? AND session_id=? ORDER BY created_at,{order}", (kind, session_id)).fetchall()
            return [json.loads(row[0]) for row in rows]

    def page(self, kind: str, limit: int = 50, offset: int = 0) -> list[dict]:
        """Bound history reads in SQL before decoding/redacting large records."""
        if type(limit) is not int or type(offset) is not int or not 1 <= limit <= 200 or not 0 <= offset <= 1000000:
            raise ValueError('Invalid history page')
        order = 'row_seq' if self.backend == 'postgresql' else 'rowid'
        with self.lock:
            rows = self._execute(f'SELECT data FROM records WHERE kind=? ORDER BY created_at DESC,{order} DESC LIMIT ? OFFSET ?',
                                 (kind, limit, offset)).fetchall()
            return [json.loads(row[0]) for row in rows]

    def meta(self, key: str, default=None):
        with self.lock:
            row = self._execute("SELECT data FROM metadata WHERE key=?", (key,)).fetchone()
            return json.loads(row[0]) if row else default

    def set_meta(self, key: str, value):
        with self.lock:
            self._execute("INSERT INTO metadata VALUES(?,?) ON CONFLICT(key) DO UPDATE SET data=excluded.data", (key, json.dumps(value, ensure_ascii=False)))

    def health(self):
        with self.lock:
            self._execute("SELECT 1").fetchone()
            return {"backend": self.backend, "connected": True, "runtime_owner": self._runtime_owned,
                    "deployment": "single_guard_process", "automatic_replay": False}

    def call_counts(self):
        """Project only counts; listing sessions must not load every audit body."""
        decision = "data::jsonb ->> 'decision'" if self.backend == "postgresql" else "json_extract(data, '$.decision')"
        with self.lock:
            rows = self._execute(f"SELECT session_id, COUNT(*), SUM(CASE WHEN {decision}='block' THEN 1 ELSE 0 END) FROM records WHERE kind='call' GROUP BY session_id").fetchall()
            return {row[0]: {"call_count": row[1], "blocked_count": row[2]} for row in rows}

    def close(self):
        with self.lock:
            self.connection.close()
