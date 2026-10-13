"""External authorization gateway.

Every action a sandboxed agent asks the host to perform (inference, a tool
call, a memory read or write) is decided here, against:

* a host-signed, short-lived capability for that agent and scope,
* the agent's registry status (revoked / quarantined / unknown => deny),
* a host-side policy file the agent cannot see or change
  (role -> allowed actions, per-action rate limits, argument size limits).

Deny by default; any error denies. Every decision is audited.

``AuthorizationGateway`` runs in-process, or out of process behind
``GatewayServer`` (``python -m blockswarm gateway``) with ``RemoteGateway``
as the client. A remote gateway that cannot be reached denies.
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import time
import tomllib
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from . import crypto, rpc
from .capabilities import Capability, CapabilityAuthority, CapabilityError


class GatewayDenied(PermissionError):
    pass


DEFAULT_POLICY: dict[str, Any] = {
    "version": 1,
    "roles": {
        "worker": {
            "inference": {"max_per_minute": 30, "max_arg_bytes": 65536},
            "memory.read": {"max_per_minute": 120, "max_arg_bytes": 1024},
            "memory.write": {"max_per_minute": 60, "max_arg_bytes": 20000},
        },
        "calculator": {
            "tool:calculator": {"max_per_minute": 60, "max_arg_bytes": 512},
        },
        "validator": {
            "inference": {"max_per_minute": 30, "max_arg_bytes": 65536},
        },
    },
}


@dataclass
class Rule:
    max_per_minute: int
    max_arg_bytes: int


@dataclass
class Policy:
    version: int
    roles: dict[str, dict[str, Rule]]
    digest: str

    @classmethod
    def from_dict(cls, data: dict) -> "Policy":
        roles: dict[str, dict[str, Rule]] = {}
        for role, actions in data.get("roles", {}).items():
            roles[role] = {a: Rule(int(r["max_per_minute"]), int(r["max_arg_bytes"]))
                           for a, r in actions.items()}
        return cls(int(data.get("version", 1)), roles, crypto.commitment(data))

    @classmethod
    def load(cls, path: str | os.PathLike | None) -> "Policy":
        if not path:
            return cls.from_dict(DEFAULT_POLICY)
        with open(path, "rb") as fh:
            return cls.from_dict(tomllib.load(fh))

    def rule(self, roles: list[str], action: str) -> Rule | None:
        """Most permissive matching rule across the agent's roles (None = deny)."""
        found = [self.roles[r][action] for r in roles if r in self.roles and action in self.roles[r]]
        if not found:
            return None
        return Rule(max(r.max_per_minute for r in found), max(r.max_arg_bytes for r in found))


def scope_for(action: str) -> str:
    """Capability scope required for an action."""
    if action.startswith("memory."):
        return "memory"
    return action


@dataclass
class Decision:
    allowed: bool
    agent_id: str
    action: str
    reason: str
    policy_digest: str


@dataclass
class _Window:
    calls: deque = field(default_factory=deque)


class AuthorizationGateway:
    def __init__(self, policy: Policy, authority: CapabilityAuthority,
                 agent_info: Callable[[str], tuple[str, list[str]] | None],
                 audit: Callable[..., None] | None = None):
        self.policy = policy
        self.authority = authority
        self._agent_info = agent_info  # agent_id -> (status, roles) or None
        self._audit = audit or (lambda *a, **k: None)
        self._windows: dict[tuple[str, str], _Window] = {}
        self.decisions = {"allow": 0, "deny": 0}

    async def authorize(self, agent_id: str, cap: dict | None, action: str, arg_bytes: int,
                        task_id: str | None = None) -> Decision:
        try:
            decision = self._decide(agent_id, cap, action, arg_bytes)
        except Exception as exc:  # fail closed on anything unexpected
            decision = Decision(False, agent_id, action, f"gateway error: {exc!r}", self.policy.digest)
        self.decisions["allow" if decision.allowed else "deny"] += 1
        self._audit("gateway_" + ("allow" if decision.allowed else "deny"), agent_id, task_id,
                    action=action, reason=decision.reason, policy=decision.policy_digest)
        return decision

    def _decide(self, agent_id: str, cap: dict | None, action: str, arg_bytes: int) -> Decision:
        def deny(reason: str) -> Decision:
            return Decision(False, agent_id, action, reason, self.policy.digest)

        info = self._agent_info(agent_id)
        if info is None:
            return deny("unknown agent")
        status, roles = info
        if status in ("revoked", "quarantined"):
            return deny(f"agent {status}")
        try:
            capability = Capability(cap["body"], cap["signature"]) if cap else None
            self.authority.check(capability, agent_id, scope_for(action))
        except (CapabilityError, KeyError, TypeError) as exc:
            return deny(f"capability: {exc}")
        rule = self.policy.rule(roles, action)
        if rule is None:
            return deny("not permitted by policy")
        if not isinstance(arg_bytes, int) or arg_bytes < 0 or arg_bytes > rule.max_arg_bytes:
            return deny(f"arguments exceed {rule.max_arg_bytes} bytes")
        now = time.monotonic()
        win = self._windows.setdefault((agent_id, action), _Window())
        while win.calls and now - win.calls[0] > 60:
            win.calls.popleft()
        if len(win.calls) >= rule.max_per_minute:
            return deny("rate limit")
        win.calls.append(now)
        return Decision(True, agent_id, action, "ok", self.policy.digest)


# ---------------------------------------------------------------------------
# Out-of-process deployment
# ---------------------------------------------------------------------------

def registry_reader(db_path: str | os.PathLike) -> Callable[[str], tuple[str, list[str]] | None]:
    """Read-only view of the agent registry for a separate gateway process."""
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, check_same_thread=False)

    def info(agent_id: str):
        row = conn.execute("SELECT status, roles FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
        return (row[0], json.loads(row[1])) if row else None
    return info


class _ReadOnlyAuthority(CapabilityAuthority):
    """Verifies capabilities with the host public key; cannot issue them."""

    def __init__(self, host_pubkey: str, is_revoked: Callable[[str], bool]):
        self.host_pubkey = host_pubkey
        self.is_revoked = is_revoked
        self._revoked_caps = set()

    def issue(self, *a, **k):  # pragma: no cover - defensive
        raise CapabilityError("the gateway cannot issue capabilities")


def build_standalone(db_path: str, host_pubkey: str, policy_path: str | None,
                     audit_path: str | None) -> AuthorizationGateway:
    info = registry_reader(db_path)

    def is_revoked(agent_id: str) -> bool:
        i = info(agent_id)
        return i is None or i[0] in ("revoked", "quarantined")

    audit_fh = open(audit_path, "a", buffering=1) if audit_path else None

    def audit(event, agent_id=None, task_id=None, **detail):
        if audit_fh:
            audit_fh.write(json.dumps({"ts": time.time(), "event": event, "agent_id": agent_id,
                                       "task_id": task_id, **detail}) + "\n")
    return AuthorizationGateway(Policy.load(policy_path), _ReadOnlyAuthority(host_pubkey, is_revoked),
                                info, audit)


class GatewayServer:
    def __init__(self, gateway: AuthorizationGateway, socket_path: str):
        self.gateway = gateway
        self.socket_path = socket_path

    async def start(self) -> asyncio.base_events.Server:
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)
        server = await asyncio.start_unix_server(self._handle, path=self.socket_path)
        os.chmod(self.socket_path, 0o600)  # only the host runtime user may ask
        return server

    async def _handle(self, reader, writer):
        try:
            while True:
                msg = await rpc.recv(reader)
                d = await self.gateway.authorize(msg.get("agent_id", ""), msg.get("capability"),
                                                 msg.get("action", ""), msg.get("arg_bytes", -1),
                                                 msg.get("task_id"))
                await rpc.send(writer, {"allowed": d.allowed, "reason": d.reason,
                                        "policy": d.policy_digest})
        except (rpc.ProtocolError, ConnectionError):
            pass
        finally:
            writer.close()


class RemoteGateway:
    """Client for an out-of-process gateway. Unreachable or malformed => deny."""

    def __init__(self, socket_path: str, timeout: float = 5.0):
        self.socket_path = socket_path
        self.timeout = timeout
        self._conn: tuple | None = None  # (event loop, reader, writer)
        self._lock: asyncio.Lock | None = None
        self._lock_loop = None
        self.policy = Policy(0, {}, "remote")
        self.decisions = {"allow": 0, "deny": 0}

    async def _ask(self, request: dict) -> dict:
        loop = asyncio.get_running_loop()
        if self._conn is None or self._conn[0] is not loop:
            reader, writer = await asyncio.wait_for(
                asyncio.open_unix_connection(self.socket_path), self.timeout)
            self._conn = (loop, reader, writer)
        _, reader, writer = self._conn
        await rpc.send(writer, request)
        return await asyncio.wait_for(rpc.recv(reader), self.timeout)

    async def authorize(self, agent_id, cap, action, arg_bytes, task_id=None) -> Decision:
        request = {"agent_id": agent_id, "capability": cap, "action": action,
                   "arg_bytes": arg_bytes, "task_id": task_id}
        if self._lock is None or self._lock_loop is not asyncio.get_running_loop():
            self._lock, self._lock_loop = asyncio.Lock(), asyncio.get_running_loop()
        async with self._lock:
            d = None
            for _ in range(2):  # one reconnect on a stale connection, then deny
                try:
                    reply = await self._ask(request)
                    d = Decision(reply.get("allowed") is True, agent_id, action,
                                 str(reply.get("reason")), str(reply.get("policy")))
                    break
                except Exception as exc:
                    self._conn = None
                    d = Decision(False, agent_id, action, f"gateway unreachable: {exc!r}", "none")
        self.decisions["allow" if d.allowed else "deny"] += 1
        return d


async def serve_forever(db_path: str, host_pubkey: str, socket_path: str,
                        policy_path: str | None, audit_path: str | None) -> None:
    gw = build_standalone(db_path, host_pubkey, policy_path, audit_path)
    server = await GatewayServer(gw, socket_path).start()
    print(f"gateway listening on {socket_path} policy={gw.policy.digest}", flush=True)
    async with server:
        await server.serve_forever()
