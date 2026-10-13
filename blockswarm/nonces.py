"""Durable replay protection: each (scope, nonce) may be consumed exactly once."""

from __future__ import annotations

import sqlite3
import time

from .db import Database


class NonceStore:
    def __init__(self, db: Database):
        self.db = db

    def consume(self, scope: str, nonce: str, expires_at: float) -> bool:
        if not nonce or len(nonce) > 128:
            return False
        try:
            self.db.execute(
                "INSERT INTO nonces(scope, nonce, expires_at) VALUES (?,?,?)",
                (scope, nonce, expires_at),
            )
            return True
        except sqlite3.IntegrityError:
            return False

    def prune(self, now: float | None = None) -> int:
        # Pruning is safe because expired messages are rejected before nonce lookup.
        cur = self.db.execute("DELETE FROM nonces WHERE expires_at < ?", ((now or time.time()) - 60,))
        return cur.rowcount
