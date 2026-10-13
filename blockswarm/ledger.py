"""Blockchain-native runtime functions.

``BlockchainRuntime`` exposes the first-class operations (register_agent,
resolve_agent, authorize_capability, register_task, commit_result_hash,
submit_attestation, verify_receipt, revoke_agent) over a pluggable ledger.

Phase 1 ships ``SimulatedLedger`` only: a local, hash-chained, Merkle-batched
block log in SQLite. It is a LOCAL SIMULATION with NO CONSENSUS and NO
FINALITY; receipts say so explicitly (``finality: "simulated-local"``).
Phase 3 adds an EVM backend (Anvil locally, remote RPC for real finality)
that anchors the same Merkle roots on-chain.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from . import crypto
from .db import Database

ZERO = "0x" + "00" * 32


def _h(data: bytes) -> str:
    return "0x" + hashlib.sha256(data).hexdigest()


def _pair(a: str, b: str) -> str:
    lo, hi = sorted((a, b))  # sorted pairs: proofs need no left/right flags
    return _h(b"\x01" + bytes.fromhex(lo[2:]) + bytes.fromhex(hi[2:]))


def merkle_root(leaves: list[str]) -> str:
    if not leaves:
        return ZERO
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [_pair(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def merkle_proof(leaves: list[str], index: int) -> list[str]:
    proof, level = [], list(leaves)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        proof.append(level[index ^ 1])
        level = [_pair(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        index //= 2
    return proof


def verify_proof(leaf: str, proof: list[str], root: str) -> bool:
    node = leaf
    for sib in proof:
        node = _pair(node, sib)
    return node == root


def entry_hash(entry: dict) -> str:
    return _h(b"\x00" + crypto.canonical_json(entry))


class SimulatedLedger:
    finality = "simulated-local"
    consensus = "none (single-process local simulation)"

    def __init__(self, db: Database, batch_size: int = 16):
        self.db = db
        self.batch_size = batch_size

    def append(self, entry: dict) -> str:
        h = entry_hash(entry)
        self.db.execute("INSERT OR IGNORE INTO ledger_pending(entry, entry_hash) VALUES (?,?)",
                        (json.dumps(entry, sort_keys=True), h))
        if self.pending_count() >= self.batch_size:
            self.flush()
        return h

    def pending_count(self) -> int:
        return self.db.one("SELECT COUNT(*) AS n FROM ledger_pending")["n"]

    def flush(self) -> dict | None:
        """Seal all pending entries into one block (one batched 'transaction')."""
        with self.db.transaction() as conn:
            rows = conn.execute("SELECT id, entry, entry_hash FROM ledger_pending ORDER BY id").fetchall()
            if not rows:
                return None
            tip = conn.execute("SELECT height, block_hash FROM ledger_blocks"
                               " ORDER BY height DESC LIMIT 1").fetchone()
            height = tip["height"] + 1 if tip else 0
            prev = tip["block_hash"] if tip else ZERO
            hashes = [r["entry_hash"] for r in rows]
            root = merkle_root(hashes)
            created = time.time()
            header = {"height": height, "prev_hash": prev, "merkle_root": root, "created_at": created}
            bhash = _h(b"\x02" + crypto.canonical_json(header))
            conn.execute("INSERT INTO ledger_blocks(height, prev_hash, merkle_root, entries,"
                         " block_hash, created_at) VALUES (?,?,?,?,?,?)",
                         (height, prev, root, json.dumps([json.loads(r["entry"]) for r in rows]),
                          bhash, created))
            conn.executemany("INSERT INTO ledger_index(entry_hash, height, entry_index) VALUES (?,?,?)",
                             [(h, height, i) for i, h in enumerate(hashes)])
            conn.execute("DELETE FROM ledger_pending WHERE id <= ?", (rows[-1]["id"],))
        return {"height": height, "block_hash": bhash, "entries": len(rows)}

    def receipt(self, h: str) -> dict | None:
        idx = self.db.one("SELECT height, entry_index FROM ledger_index WHERE entry_hash=?", (h,))
        if idx is None:
            return None
        block = self.db.one("SELECT * FROM ledger_blocks WHERE height=?", (idx["height"],))
        leaves = [entry_hash(e) for e in json.loads(block["entries"])]
        return {
            "entry_hash": h, "block_height": block["height"], "block_hash": block["block_hash"],
            "merkle_root": block["merkle_root"], "proof": merkle_proof(leaves, idx["entry_index"]),
            "finality": self.finality,
        }

    def verify_receipt(self, receipt: dict) -> bool:
        try:
            block = self.db.one("SELECT * FROM ledger_blocks WHERE height=?", (receipt["block_height"],))
            if block is None or block["block_hash"] != receipt["block_hash"]:
                return False
            header = {"height": block["height"], "prev_hash": block["prev_hash"],
                      "merkle_root": block["merkle_root"], "created_at": block["created_at"]}
            if _h(b"\x02" + crypto.canonical_json(header)) != block["block_hash"]:
                return False
            if block["merkle_root"] != receipt["merkle_root"]:
                return False
            if merkle_root([entry_hash(e) for e in json.loads(block["entries"])]) != block["merkle_root"]:
                return False
            return verify_proof(receipt["entry_hash"], receipt["proof"], receipt["merkle_root"])
        except (KeyError, TypeError, ValueError):
            return False

    def verify_chain(self) -> bool:
        prev = ZERO
        for block in self.db.all("SELECT * FROM ledger_blocks ORDER BY height"):
            header = {"height": block["height"], "prev_hash": block["prev_hash"],
                      "merkle_root": block["merkle_root"], "created_at": block["created_at"]}
            if block["prev_hash"] != prev:
                return False
            if _h(b"\x02" + crypto.canonical_json(header)) != block["block_hash"]:
                return False
            if merkle_root([entry_hash(e) for e in json.loads(block["entries"])]) != block["merkle_root"]:
                return False
            prev = block["block_hash"]
        return True

    def entries(self, kind: str | None = None) -> list[dict]:
        out = []
        for block in self.db.all("SELECT entries FROM ledger_blocks ORDER BY height"):
            out += [e for e in json.loads(block["entries"]) if kind is None or e["op"] == kind]
        return out


class BlockchainRuntime:
    """First-class blockchain operations used by the swarm runtime."""

    def __init__(self, ledger: SimulatedLedger, host_pubkey: str):
        self.ledger = ledger
        self.host_pubkey = host_pubkey

    def _entry(self, op: str, **fields: Any) -> dict:
        return {"op": op, "ts": round(time.time(), 6), **fields}

    def register_agent(self, agent_id: str, pubkey: str, roles: list[str]) -> dict:
        h = self.ledger.append(self._entry("register_agent", agent_id=agent_id, pubkey=pubkey,
                                           roles=sorted(roles)))
        return self._sealed(h)

    def resolve_agent(self, agent_id: str) -> dict | None:
        """Current on-ledger state of an identity (latest registration / revocation)."""
        state = None
        for e in self.ledger.entries():
            if e.get("agent_id") != agent_id:
                continue
            if e["op"] == "register_agent":
                state = {"agent_id": agent_id, "pubkey": e["pubkey"], "roles": e["roles"],
                         "revoked": False}
            elif e["op"] == "revoke_agent" and state:
                state["revoked"] = True
        return state

    def authorize_capability(self, cap_body: dict) -> str:
        return self.ledger.append(self._entry(
            "authorize_capability", agent_id=cap_body["agent_id"], cap_id=cap_body["cap_id"],
            cap_hash=crypto.commitment(cap_body), scopes=cap_body["scopes"],
            expires_at=cap_body["expires_at"]))

    def register_task(self, task_id: str, kind: str, payload_hash: str) -> str:
        return self.ledger.append(self._entry("register_task", task_id=task_id, kind=kind,
                                              payload_hash=payload_hash))

    def commit_result_hash(self, task_id: str, agent_id: str, record_hash: str,
                           output_commitment: str, signature: str) -> str:
        return self.ledger.append(self._entry(
            "commit_result", task_id=task_id, agent_id=agent_id, record_hash=record_hash,
            output_commitment=output_commitment, signature=signature))

    def submit_attestation(self, task_id: str, validator_id: str, verdict: bool,
                           result_entry: str, method: str, signature: str) -> str:
        return self.ledger.append(self._entry(
            "attestation", task_id=task_id, validator_id=validator_id, verdict=verdict,
            result_entry=result_entry, method=method, signature=signature))

    def verify_receipt(self, receipt: dict) -> bool:
        return self.ledger.verify_receipt(receipt)

    def revoke_agent(self, agent_id: str, reason: str) -> dict:
        h = self.ledger.append(self._entry("revoke_agent", agent_id=agent_id, reason=reason))
        return self._sealed(h)

    def flush(self) -> dict | None:
        return self.ledger.flush()

    def receipt(self, entry_hash_: str) -> dict | None:
        return self.ledger.receipt(entry_hash_)

    def _sealed(self, h: str) -> dict:
        # Identity changes are sealed immediately rather than waiting for a batch.
        self.ledger.flush()
        return self.ledger.receipt(h)
