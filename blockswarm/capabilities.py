"""Short-lived, scoped, host-signed capability tokens.

Policy (which agent may hold which scope) lives on the host and is outside
agent control. Every check fails closed.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable

from . import crypto
from .signing import SigningService

DOMAIN = "capability"

# Scopes every agent may receive; others must be granted through roles.
BASE_SCOPES = frozenset({"inference"})
ROLE_SCOPES: dict[str, frozenset[str]] = {
    "worker": frozenset({"inference"}),
    "calculator": frozenset({"inference", "tool:calculator"}),
    "validator": frozenset({"inference", "validate"}),
}


class CapabilityError(PermissionError):
    pass


@dataclass(frozen=True)
class Capability:
    body: dict
    signature: str

    @property
    def agent_id(self) -> str:
        return self.body["agent_id"]

    @property
    def scopes(self) -> frozenset[str]:
        return frozenset(self.body["scopes"])

    @property
    def cap_id(self) -> str:
        return self.body["cap_id"]

    def to_dict(self) -> dict:
        return {"body": self.body, "signature": self.signature}


def allowed_scopes(roles: list[str]) -> frozenset[str]:
    scopes = set(BASE_SCOPES)
    for role in roles:
        scopes |= ROLE_SCOPES.get(role, frozenset())
    return frozenset(scopes)


class CapabilityAuthority:
    def __init__(self, signer: SigningService, host_pubkey: str,
                 is_revoked: Callable[[str], bool], ttl_seconds: int):
        self.signer = signer
        self.host_pubkey = host_pubkey
        self.is_revoked = is_revoked
        self.ttl = ttl_seconds
        self._revoked_caps: set[str] = set()

    def issue(self, agent_id: str, roles: list[str], scopes: set[str] | frozenset[str],
              task_id: str | None = None, ttl: float | None = None) -> Capability:
        if self.is_revoked(agent_id):
            raise CapabilityError(f"agent not eligible: {agent_id}")
        permitted = allowed_scopes(roles)
        denied = set(scopes) - permitted
        if denied:
            raise CapabilityError(f"scopes not permitted for agent roles: {sorted(denied)}")
        now = time.time()
        body = {
            "v": 1,
            "cap_id": crypto.new_nonce(),
            "agent_id": agent_id,
            "scopes": sorted(scopes),
            "task_id": task_id,
            "issued_at": now,
            "expires_at": now + (ttl if ttl is not None else self.ttl),
        }
        return Capability(body, self.signer.sign_as_host(DOMAIN, body))

    def revoke(self, cap_id: str) -> None:
        self._revoked_caps.add(cap_id)

    def check(self, cap: Capability | None, agent_id: str, scope: str,
              now: float | None = None) -> Capability:
        """Return the capability if valid for (agent, scope); raise otherwise."""
        try:
            if cap is None:
                raise CapabilityError("missing capability")
            body = cap.body
            if body.get("v") != 1:
                raise CapabilityError("unsupported capability version")
            if not crypto.verify(self.host_pubkey, cap.signature, DOMAIN, body):
                raise CapabilityError("bad capability signature")
            now = time.time() if now is None else now
            if not body["issued_at"] - 5 <= now < body["expires_at"]:
                raise CapabilityError("capability expired or not yet valid")
            if body["agent_id"] != agent_id:
                raise CapabilityError("capability bound to a different agent")
            if scope not in body["scopes"]:
                raise CapabilityError(f"scope not granted: {scope}")
            if body["cap_id"] in self._revoked_caps:
                raise CapabilityError("capability revoked")
            if self.is_revoked(agent_id):
                raise CapabilityError("agent revoked")
            return cap
        except CapabilityError:
            raise
        except Exception as exc:  # malformed input: fail closed
            raise CapabilityError(f"invalid capability: {exc!r}") from exc
