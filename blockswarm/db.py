"""SQLite (WAL) storage. One connection, used only from the event-loop thread."""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
    agent_id    TEXT PRIMARY KEY,
    pubkey      TEXT NOT NULL,
    label       TEXT NOT NULL,
    roles       TEXT NOT NULL DEFAULT '[]',
    status      TEXT NOT NULL DEFAULT 'idle',
    failures    INTEGER NOT NULL DEFAULT 0,
    tasks_done  INTEGER NOT NULL DEFAULT 0,
    last_used   REAL NOT NULL DEFAULT 0,
    created_at  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS tasks (
    task_id        TEXT PRIMARY KEY,
    kind           TEXT NOT NULL,
    payload        TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'pending',
    priority       INTEGER NOT NULL DEFAULT 0,
    irreversible   INTEGER NOT NULL DEFAULT 0,
    required_caps  TEXT NOT NULL DEFAULT '[]',
    attempts       INTEGER NOT NULL DEFAULT 0,
    max_attempts   INTEGER NOT NULL DEFAULT 3,
    lease_owner    TEXT,
    lease_expires  REAL,
    excluded       TEXT NOT NULL DEFAULT '[]',
    commitment     TEXT,
    error          TEXT,
    created_at     REAL NOT NULL,
    updated_at     REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS tasks_status ON tasks(status, priority DESC, created_at);
CREATE TABLE IF NOT EXISTS task_deps (
    task_id    TEXT NOT NULL REFERENCES tasks(task_id),
    depends_on TEXT NOT NULL REFERENCES tasks(task_id),
    PRIMARY KEY (task_id, depends_on)
);
CREATE TABLE IF NOT EXISTS results (
    task_id      TEXT PRIMARY KEY REFERENCES tasks(task_id),
    agent_id     TEXT NOT NULL,
    output       TEXT NOT NULL,
    record       TEXT NOT NULL,
    signature    TEXT NOT NULL,
    verification TEXT NOT NULL,
    receipt      TEXT,
    created_at   REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS nonces (
    scope      TEXT NOT NULL,
    nonce      TEXT NOT NULL,
    expires_at REAL NOT NULL,
    PRIMARY KEY (scope, nonce)
);
CREATE TABLE IF NOT EXISTS memory (
    agent_id   TEXT NOT NULL,
    key        TEXT NOT NULL,
    value      BLOB NOT NULL,
    compressed INTEGER NOT NULL DEFAULT 0,
    updated_at REAL NOT NULL,
    PRIMARY KEY (agent_id, key)
);
CREATE TABLE IF NOT EXISTS checkpoints (
    agent_id   TEXT PRIMARY KEY,
    state      TEXT NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS execution_log (
    idempotency_key TEXT PRIMARY KEY,
    task_id         TEXT NOT NULL,
    agent_id        TEXT NOT NULL,
    status          TEXT NOT NULL,
    started_at      REAL NOT NULL,
    finished_at     REAL
);
CREATE TABLE IF NOT EXISTS ledger_blocks (
    height      INTEGER PRIMARY KEY,
    prev_hash   TEXT NOT NULL,
    merkle_root TEXT NOT NULL,
    entries     TEXT NOT NULL,
    block_hash  TEXT NOT NULL UNIQUE,
    created_at  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS ledger_pending (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    entry      TEXT NOT NULL,
    entry_hash TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS ledger_index (
    entry_hash  TEXT PRIMARY KEY,
    height      INTEGER NOT NULL,
    entry_index INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       REAL NOT NULL,
    event    TEXT NOT NULL,
    agent_id TEXT,
    task_id  TEXT,
    detail   TEXT
);
"""


class Database:
    def __init__(self, path: str | Path):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.execute("PRAGMA cache_size=-4096")  # ~4 MiB page cache
        self.conn.executescript(SCHEMA)

    def execute(self, sql: str, params: tuple | list = ()) -> sqlite3.Cursor:
        return self.conn.execute(sql, params)

    def one(self, sql: str, params: tuple | list = ()) -> sqlite3.Row | None:
        return self.conn.execute(sql, params).fetchone()

    def all(self, sql: str, params: tuple | list = ()) -> list[sqlite3.Row]:
        return self.conn.execute(sql, params).fetchall()

    def transaction(self) -> "_Tx":
        return _Tx(self.conn)

    def audit(self, event: str, agent_id: str | None = None, task_id: str | None = None,
              **detail: Any) -> None:
        self.conn.execute(
            "INSERT INTO audit(ts, event, agent_id, task_id, detail) VALUES (?,?,?,?,?)",
            (time.time(), event, agent_id, task_id, json.dumps(detail, default=str)),
        )

    def close(self) -> None:
        self.conn.close()


class _Tx:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def __enter__(self) -> sqlite3.Connection:
        self.conn.execute("BEGIN IMMEDIATE")
        return self.conn

    def __exit__(self, exc_type, exc, tb) -> None:
        self.conn.execute("ROLLBACK" if exc_type else "COMMIT")
