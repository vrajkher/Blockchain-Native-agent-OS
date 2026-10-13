"""Result verification.

Deterministic checks first (signatures, commitments, schema, permissions,
evidence, kind-specific checkers). Agreement between AI agents is never
treated as proof of correctness: a ``Verdict`` records which checks were
deterministic proofs and which were only structural.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from . import crypto, schema
from .envelope import RESULT_DOMAIN, TASK_DOMAIN
from .registry import AgentRegistry
from .tasks import KINDS


@dataclass
class Verdict:
    ok: bool
    validator: str
    method: str
    checks: dict[str, bool] = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)
    proves_correctness: bool = False

    def to_dict(self) -> dict:
        return {"ok": self.ok, "validator": self.validator, "method": self.method,
                "checks": self.checks, "problems": self.problems,
                "proves_correctness": self.proves_correctness}


@dataclass
class Submission:
    task_id: str
    kind: str
    payload: dict
    envelope: dict
    output: dict
    record: dict
    signature: str
    tool_calls: list[dict]
    granted_scopes: list[str]


class Validator(Protocol):
    validator_id: str

    def verify(self, sub: Submission) -> Verdict: ...


class DeterministicVerifier:
    validator_id = "host-deterministic-verifier"

    def __init__(self, registry: AgentRegistry, host_pubkey: str):
        self.registry = registry
        self.host_pubkey = host_pubkey

    def verify(self, sub: Submission) -> Verdict:
        v = Verdict(ok=False, validator=self.validator_id, method="deterministic")
        kind = KINDS.get(sub.kind)

        def check(name: str, ok: bool, problem: str) -> None:
            v.checks[name] = bool(ok)
            if not ok:
                v.problems.append(problem)

        agent = self.registry.get(sub.record.get("agent_id", ""))
        check("agent_active", agent is not None and agent.status not in ("revoked", "quarantined"),
              "agent unknown, revoked or quarantined")
        check("kind_known", kind is not None, f"unknown kind {sub.kind}")
        env = sub.envelope.get("body", {})
        check("envelope_signature",
              crypto.verify(self.host_pubkey, sub.envelope.get("signature", ""), TASK_DOMAIN, env),
              "task envelope not signed by host")
        check("envelope_binding",
              env.get("task_id") == sub.task_id and env.get("kind") == sub.kind
              and env.get("assignee") == sub.record.get("agent_id")
              and env.get("payload_hash") == crypto.commitment(sub.payload),
              "envelope does not bind this task/agent/payload")
        check("record_binding",
              sub.record.get("task_id") == sub.task_id
              and sub.record.get("envelope_hash") == crypto.commitment(sub.envelope),
              "result record does not reference this envelope")
        check("output_commitment", sub.record.get("output_commitment") == crypto.commitment(sub.output),
              "output does not match signed commitment")
        check("tool_evidence",
              sub.record.get("tool_calls_commitment") == crypto.commitment(sub.tool_calls),
              "tool-call evidence does not match commitment")
        check("result_signature",
              agent is not None and crypto.verify(agent.pubkey, sub.signature, RESULT_DOMAIN, sub.record),
              "result record not signed by the assigned agent")
        if kind is not None:
            errors = schema.validate(sub.output, kind.output_schema)
            check("output_schema", not errors, f"schema: {errors}")
            used = {f"tool:{c['tool']}" for c in sub.tool_calls}
            check("permissions", used <= set(sub.granted_scopes),
                  f"tools used without capability: {sorted(used - set(sub.granted_scopes))}")
            if kind.checker and not errors:
                problems = kind.checker(sub.payload, sub.output)
                check("kind_checker", not problems, "; ".join(problems))
        v.ok = all(v.checks.values())
        v.proves_correctness = bool(v.ok and kind and kind.deterministic)
        return v
