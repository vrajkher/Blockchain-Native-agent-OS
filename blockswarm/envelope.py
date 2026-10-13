"""Signed task envelopes and signed result records."""

from __future__ import annotations

import time
from typing import Any

from . import crypto
from .nonces import NonceStore

TASK_DOMAIN = "task-envelope"
RESULT_DOMAIN = "task-result"


class EnvelopeError(PermissionError):
    pass


def make_task_envelope(signer, task_id: str, kind: str, payload: Any, assignee: str,
                       cap_id: str, ttl: float) -> dict:
    now = time.time()
    body = {
        "v": 1,
        "task_id": task_id,
        "kind": kind,
        "payload_hash": crypto.commitment(payload),
        "assignee": assignee,
        "cap_id": cap_id,
        "nonce": crypto.new_nonce(),
        "issued_at": now,
        "expires_at": now + ttl,
    }
    return {"body": body, "signature": signer.sign_as_host(TASK_DOMAIN, body)}


def check_task_envelope(envelope: dict, payload: Any, host_pubkey: str, agent_id: str,
                        now: float | None = None) -> dict:
    """Stateless checks (signature, binding, expiry). Replay is checked separately."""
    try:
        body, sig = envelope["body"], envelope["signature"]
        if body.get("v") != 1:
            raise EnvelopeError("unsupported envelope version")
        if not crypto.verify(host_pubkey, sig, TASK_DOMAIN, body):
            raise EnvelopeError("bad envelope signature")
        if body["assignee"] != agent_id:
            raise EnvelopeError("envelope addressed to a different agent")
        if body["payload_hash"] != crypto.commitment(payload):
            raise EnvelopeError("payload does not match envelope hash")
        now = time.time() if now is None else now
        if not body["issued_at"] - 5 <= now < body["expires_at"]:
            raise EnvelopeError("envelope expired")
        return body
    except EnvelopeError:
        raise
    except Exception as exc:
        raise EnvelopeError(f"malformed envelope: {exc!r}") from exc


def accept_task_envelope(envelope: dict, payload: Any, host_pubkey: str, agent_id: str,
                         nonces: NonceStore, now: float | None = None) -> dict:
    body = check_task_envelope(envelope, payload, host_pubkey, agent_id, now)
    if not nonces.consume(f"task:{agent_id}", body["nonce"], body["expires_at"]):
        raise EnvelopeError("replayed envelope")
    return body


def result_record(envelope: dict, agent_id: str, output: Any, tool_calls: list[dict]) -> dict:
    return {
        "v": 1,
        "task_id": envelope["body"]["task_id"],
        "agent_id": agent_id,
        "envelope_hash": crypto.commitment(envelope),
        "output_commitment": crypto.commitment(output),
        "tool_calls_commitment": crypto.commitment(tool_calls),
        "produced_at": time.time(),
    }
