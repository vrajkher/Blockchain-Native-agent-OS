"""Local agent registry: the off-chain view of agent identities."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass

from .db import Database

ACTIVE_STATES = ("idle", "active", "suspended")


@dataclass
class AgentRecord:
    agent_id: str
    pubkey: str
    label: str
    roles: list[str]
    status: str
    failures: int
    tasks_done: int
    last_used: float


class AgentRegistry:
    def __init__(self, db: Database):
        self.db = db

    def add(self, agent_id: str, pubkey: str, label: str, roles: list[str]) -> None:
        self.db.execute(
            "INSERT INTO agents(agent_id, pubkey, label, roles, created_at) VALUES (?,?,?,?,?)",
            (agent_id, pubkey, label, json.dumps(sorted(roles)), time.time()),
        )

    def get(self, agent_id: str) -> AgentRecord | None:
        row = self.db.one("SELECT * FROM agents WHERE agent_id=?", (agent_id,))
        return self._rec(row) if row else None

    def list(self, status: str | None = None) -> list[AgentRecord]:
        if status:
            rows = self.db.all("SELECT * FROM agents WHERE status=? ORDER BY created_at", (status,))
        else:
            rows = self.db.all("SELECT * FROM agents ORDER BY created_at")
        return [self._rec(r) for r in rows]

    def count(self) -> int:
        return self.db.one("SELECT COUNT(*) AS n FROM agents")["n"]

    def is_revoked(self, agent_id: str) -> bool:
        row = self.db.one("SELECT status FROM agents WHERE agent_id=?", (agent_id,))
        # Unknown identities are treated as revoked: fail closed.
        return row is None or row["status"] in ("revoked", "quarantined")

    def set_status(self, agent_id: str, status: str) -> None:
        self.db.execute("UPDATE agents SET status=? WHERE agent_id=?", (status, agent_id))

    def mark_used(self, agent_id: str) -> None:
        self.db.execute("UPDATE agents SET last_used=? WHERE agent_id=?", (time.time(), agent_id))

    def record_success(self, agent_id: str) -> None:
        self.db.execute("UPDATE agents SET tasks_done=tasks_done+1 WHERE agent_id=?", (agent_id,))

    def record_failure(self, agent_id: str, max_failures: int) -> bool:
        """Increment failures; quarantine past the threshold. Returns True if quarantined."""
        self.db.execute("UPDATE agents SET failures=failures+1 WHERE agent_id=?", (agent_id,))
        rec = self.get(agent_id)
        if rec and rec.failures >= max_failures and rec.status != "revoked":
            self.set_status(agent_id, "quarantined")
            return True
        return False

    @staticmethod
    def _rec(row) -> AgentRecord:
        return AgentRecord(
            agent_id=row["agent_id"], pubkey=row["pubkey"], label=row["label"],
            roles=json.loads(row["roles"]), status=row["status"], failures=row["failures"],
            tasks_done=row["tasks_done"], last_used=row["last_used"],
        )
