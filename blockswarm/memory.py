"""Private, agent-scoped memory backed by SQLite.

An agent receives an ``AgentMemoryView`` bound to its own identity. The view
exposes no way to name another agent, so cross-agent reads are impossible
through the API. (In-process this is an API boundary, not a security
boundary; Phase 2 moves the view behind the sandbox RPC.)
"""

from __future__ import annotations

import time
import zlib

from .db import Database

COMPRESS_OVER = 1024


class MemoryLimitError(Exception):
    pass


class MemoryStore:
    def __init__(self, db: Database, max_entries: int, max_value_bytes: int):
        self.db = db
        self.max_entries = max_entries
        self.max_value_bytes = max_value_bytes

    def view(self, agent_id: str) -> "AgentMemoryView":
        return AgentMemoryView(self, agent_id)

    def wipe(self, agent_id: str) -> None:
        self.db.execute("DELETE FROM memory WHERE agent_id=?", (agent_id,))


class AgentMemoryView:
    __slots__ = ("__store", "__agent_id")

    def __init__(self, store: MemoryStore, agent_id: str):
        self.__store = store
        self.__agent_id = agent_id

    def put(self, key: str, value: str) -> None:
        data = value.encode("utf-8")
        if len(data) > self.__store.max_value_bytes:
            raise MemoryLimitError("memory value too large")
        if len(key) > 200:
            raise MemoryLimitError("memory key too long")
        compressed = len(data) > COMPRESS_OVER
        if compressed:
            data = zlib.compress(data, 6)
        db = self.__store.db
        db.execute(
            "INSERT INTO memory(agent_id, key, value, compressed, updated_at) VALUES (?,?,?,?,?) "
            "ON CONFLICT(agent_id, key) DO UPDATE SET value=excluded.value, "
            "compressed=excluded.compressed, updated_at=excluded.updated_at",
            (self.__agent_id, key, data, int(compressed), time.time()),
        )
        # Evict oldest entries beyond the per-agent quota.
        db.execute(
            "DELETE FROM memory WHERE agent_id=? AND key NOT IN ("
            "SELECT key FROM memory WHERE agent_id=? ORDER BY updated_at DESC LIMIT ?)",
            (self.__agent_id, self.__agent_id, self.__store.max_entries),
        )

    def get(self, key: str) -> str | None:
        row = self.__store.db.one("SELECT value, compressed FROM memory WHERE agent_id=? AND key=?",
                                  (self.__agent_id, key))
        return _decode(row) if row else None

    def recent(self, n: int = 3) -> list[tuple[str, str]]:
        rows = self.__store.db.all(
            "SELECT key, value, compressed FROM memory WHERE agent_id=? "
            "ORDER BY updated_at DESC LIMIT ?", (self.__agent_id, n))
        return [(r["key"], _decode(r)) for r in rows]

    def keys(self) -> list[str]:
        return [r["key"] for r in self.__store.db.all(
            "SELECT key FROM memory WHERE agent_id=? ORDER BY key", (self.__agent_id,))]


def _decode(row) -> str:
    data = row["value"]
    return (zlib.decompress(data) if row["compressed"] else data).decode("utf-8")
