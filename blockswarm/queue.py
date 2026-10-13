"""Durable, dependency-aware task queue on SQLite.

Status flow: pending -> leased -> done | pending (retry) | failed | needs_review

Duplicate irreversible execution is prevented with ``execution_log``: an
irreversible task must insert its idempotency key *before* it executes; if
the key already exists (a previous attempt may have performed the side
effect) the task goes to ``needs_review`` instead of running again.
"""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from dataclasses import dataclass
from typing import Any

from .db import Database

TERMINAL = ("done", "failed", "needs_review", "cancelled")


@dataclass
class Task:
    task_id: str
    kind: str
    payload: dict
    status: str
    priority: int
    irreversible: bool
    required_caps: list[str]
    attempts: int
    max_attempts: int
    lease_owner: str | None
    lease_expires: float | None
    excluded: list[str]
    commitment: str | None
    error: str | None
    deps: list[str]


class QueueError(Exception):
    pass


class TaskQueue:
    def __init__(self, db: Database):
        self.db = db

    # -- submission -----------------------------------------------------
    def submit(self, kind: str, payload: dict, deps: list[str] | None = None, priority: int = 0,
               irreversible: bool = False, required_caps: list[str] | None = None,
               max_attempts: int = 3, task_id: str | None = None) -> str:
        task_id = task_id or "t-" + uuid.uuid4().hex[:16]
        deps = list(dict.fromkeys(deps or []))
        now = time.time()
        with self.db.transaction() as conn:
            for d in deps:  # deps must already exist => the graph is acyclic by construction
                if conn.execute("SELECT 1 FROM tasks WHERE task_id=?", (d,)).fetchone() is None:
                    raise QueueError(f"unknown dependency {d}")
            try:
                conn.execute(
                    "INSERT INTO tasks(task_id, kind, payload, priority, irreversible, required_caps,"
                    " max_attempts, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
                    (task_id, kind, json.dumps(payload), priority, int(irreversible),
                     json.dumps(sorted(set(required_caps or []))), max_attempts, now, now))
            except sqlite3.IntegrityError as exc:
                raise QueueError(f"duplicate task id {task_id}") from exc
            conn.executemany("INSERT INTO task_deps(task_id, depends_on) VALUES (?,?)",
                             [(task_id, d) for d in deps])
        return task_id

    # -- reads ------------------------------------------------------------
    def get(self, task_id: str) -> Task | None:
        row = self.db.one("SELECT * FROM tasks WHERE task_id=?", (task_id,))
        return self._task(row) if row else None

    def deps(self, task_id: str) -> list[str]:
        return [r["depends_on"] for r in self.db.all(
            "SELECT depends_on FROM task_deps WHERE task_id=? ORDER BY depends_on", (task_id,))]

    def ready(self, limit: int = 50) -> list[Task]:
        """Pending tasks whose dependencies are all done, highest priority first."""
        self._propagate_dependency_failures()
        rows = self.db.all(
            "SELECT t.* FROM tasks t WHERE t.status='pending' AND NOT EXISTS ("
            " SELECT 1 FROM task_deps d JOIN tasks p ON p.task_id=d.depends_on"
            " WHERE d.task_id=t.task_id AND p.status!='done')"
            " ORDER BY t.priority DESC, t.created_at LIMIT ?", (limit,))
        return [self._task(r) for r in rows]

    def counts(self) -> dict[str, int]:
        return {r["status"]: r["n"] for r in self.db.all(
            "SELECT status, COUNT(*) AS n FROM tasks GROUP BY status")}

    def unfinished(self) -> int:
        return self.db.one(
            "SELECT COUNT(*) AS n FROM tasks WHERE status IN ('pending','leased')")["n"]

    # -- state transitions ---------------------------------------------
    def claim(self, task_id: str, agent_id: str, lease_seconds: float) -> bool:
        now = time.time()
        cur = self.db.execute(
            "UPDATE tasks SET status='leased', lease_owner=?, lease_expires=?,"
            " attempts=attempts+1, updated_at=? WHERE task_id=? AND status='pending'",
            (agent_id, now + lease_seconds, now, task_id))
        return cur.rowcount == 1

    def begin_execution(self, task_id: str, agent_id: str) -> bool:
        """Record the start of an irreversible execution. False => already attempted."""
        try:
            self.db.execute(
                "INSERT INTO execution_log(idempotency_key, task_id, agent_id, status, started_at)"
                " VALUES (?,?,?,?,?)", (f"exec:{task_id}", task_id, agent_id, "started", time.time()))
            return True
        except sqlite3.IntegrityError:
            return False

    def end_execution(self, task_id: str, status: str) -> None:
        self.db.execute("UPDATE execution_log SET status=?, finished_at=? WHERE idempotency_key=?",
                        (status, time.time(), f"exec:{task_id}"))

    def complete(self, task_id: str, agent_id: str, commitment: str) -> bool:
        cur = self.db.execute(
            "UPDATE tasks SET status='done', commitment=?, error=NULL, lease_owner=NULL,"
            " lease_expires=NULL, updated_at=? WHERE task_id=? AND status='leased' AND lease_owner=?",
            (commitment, time.time(), task_id, agent_id))
        return cur.rowcount == 1

    def fail(self, task_id: str, agent_id: str, error: str, retryable: bool = True,
             blame_agent: bool = True) -> str:
        """Release a failed lease. Returns the new status.

        ``blame_agent=False`` (infrastructure failures) lets the same agent retry.
        """
        task = self.get(task_id)
        if task is None or task.status != "leased" or task.lease_owner != agent_id:
            return task.status if task else "missing"
        excluded = sorted(set(task.excluded) | ({agent_id} if blame_agent else set()))
        started = self.db.one("SELECT 1 FROM execution_log WHERE idempotency_key=?",
                              (f"exec:{task_id}",)) is not None
        if task.irreversible and started:
            status = "needs_review"  # a side effect may have happened; never auto-retry
        elif retryable and task.attempts < task.max_attempts:
            status = "pending"
        else:
            status = "failed"
        self.db.execute(
            "UPDATE tasks SET status=?, error=?, excluded=?, lease_owner=NULL, lease_expires=NULL,"
            " updated_at=? WHERE task_id=?",
            (status, error[:500], json.dumps(excluded), time.time(), task_id))
        return status

    def recover_expired(self, now: float | None = None) -> list[tuple[str, str]]:
        """Return expired leases to the queue (reversible) or to review (irreversible)."""
        now = time.time() if now is None else now
        changed = []
        for row in self.db.all("SELECT task_id, lease_owner FROM tasks"
                               " WHERE status='leased' AND lease_expires < ?", (now,)):
            status = self.fail(row["task_id"], row["lease_owner"], "lease expired")
            changed.append((row["task_id"], status))
        return changed

    def requeue_review(self, task_id: str) -> None:
        """Operator action: explicitly allow a needs_review task to run again."""
        with self.db.transaction() as conn:
            conn.execute("DELETE FROM execution_log WHERE idempotency_key=?", (f"exec:{task_id}",))
            conn.execute("UPDATE tasks SET status='pending', updated_at=? WHERE task_id=?"
                         " AND status='needs_review'", (time.time(), task_id))

    def _propagate_dependency_failures(self) -> None:
        while True:
            cur = self.db.execute(
                "UPDATE tasks SET status='failed', error='dependency failed', updated_at=?"
                " WHERE status='pending' AND EXISTS (SELECT 1 FROM task_deps d JOIN tasks p"
                " ON p.task_id=d.depends_on WHERE d.task_id=tasks.task_id"
                " AND p.status IN ('failed','cancelled'))", (time.time(),))
            if cur.rowcount == 0:
                return

    def _task(self, row) -> Task:
        return Task(
            task_id=row["task_id"], kind=row["kind"], payload=json.loads(row["payload"]),
            status=row["status"], priority=row["priority"], irreversible=bool(row["irreversible"]),
            required_caps=json.loads(row["required_caps"]), attempts=row["attempts"],
            max_attempts=row["max_attempts"], lease_owner=row["lease_owner"],
            lease_expires=row["lease_expires"], excluded=json.loads(row["excluded"]),
            commitment=row["commitment"], error=row["error"], deps=self.deps(row["task_id"]),
        )
