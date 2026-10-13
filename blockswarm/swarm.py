"""Swarm runtime: wires the components together and runs the asyncio scheduler."""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from typing import Any, Callable

from . import crypto, schema
from .capabilities import CapabilityAuthority, allowed_scopes
from .config import Config
from .db import Database
from .envelope import RESULT_DOMAIN, accept_task_envelope, make_task_envelope, result_record
from .governor import ResourceGovernor
from .harness import AgentContext, AgentHarness
from .inference import Backend, InferenceService, make_backend
from .ledger import BlockchainRuntime, SimulatedLedger
from .memory import MemoryStore
from .nonces import NonceStore
from .queue import Task, TaskQueue
from .registry import AgentRecord, AgentRegistry
from .sandbox import Sandbox, SandboxFactory
from .signing import SigningService
from .tasks import KINDS
from .tools import ToolGateway
from .verifier import DeterministicVerifier, Submission

ATTESTATION_DOMAIN = "attestation"


class VerificationFailed(Exception):
    pass


@dataclass
class Running:
    task_id: str
    future: asyncio.Task
    sandbox: Sandbox | None = None


class Swarm:
    def __init__(self, cfg: Config, backend: Backend | None = None,
                 governor: ResourceGovernor | None = None):
        self.cfg = cfg
        # Fail closed on security policy before anything else is created.
        self.sandboxes = SandboxFactory(cfg.security)
        cfg.home_path.mkdir(parents=True, exist_ok=True)
        self.db = Database(cfg.db_path)
        self.registry = AgentRegistry(self.db)
        self.signer = SigningService(cfg.keystore_path, is_revoked=self.registry.is_revoked)
        self.host_pubkey = self.signer.ensure_host_key()
        self.nonces = NonceStore(self.db)
        self.authority = CapabilityAuthority(self.signer, self.host_pubkey, self.registry.is_revoked,
                                             cfg.security.capability_ttl_seconds)
        self.memory = MemoryStore(self.db, cfg.security.max_memory_entries_per_agent,
                                  cfg.security.max_memory_value_bytes)
        self.backend = backend or make_backend(cfg.inference)
        self.inference = InferenceService(self.backend, self.authority, cfg.inference,
                                          cfg.governor.inference_concurrency)
        self.tools = ToolGateway(self.authority, self.db)
        self.chain = BlockchainRuntime(SimulatedLedger(self.db, cfg.ledger.batch_size), self.host_pubkey)
        self.verifier = DeterministicVerifier(self.registry, self.host_pubkey)
        self.queue = TaskQueue(self.db)
        self.governor = governor or ResourceGovernor(cfg.governor)
        self.running: dict[str, Running] = {}
        self.paused = False
        self.poll_interval = 0.05
        self.max_active_seen = 0
        self.allowed_seen: set[int] = set()
        self.fault_injector: Callable[[str, Task], None] | None = None
        self._recover_after_crash()

    # -- identities -----------------------------------------------------
    def create_agents(self, n: int, roles: list[str] | None = None, prefix: str = "agent") -> list[str]:
        roles = roles or ["worker"]
        start = self.registry.count()
        ids = []
        for i in range(n):
            agent_id, pub = self.signer.create_agent_key()
            self.registry.add(agent_id, pub, f"{prefix}-{start + i:03d}", roles)
            self.chain.register_agent(agent_id, pub, roles)
            self.db.audit("agent_registered", agent_id, roles=roles)
            ids.append(agent_id)
        return ids

    def revoke_agent(self, agent_id: str, reason: str = "operator") -> dict:
        self.registry.set_status(agent_id, "revoked")
        self.signer.forget(agent_id)
        receipt = self.chain.revoke_agent(agent_id, reason)
        self.db.audit("agent_revoked", agent_id, reason=reason)
        run = self.running.get(agent_id)
        if run:
            run.future.cancel()  # emergency termination
            if run.sandbox:
                asyncio.ensure_future(run.sandbox.kill())
        return receipt

    async def terminate_agent(self, agent_id: str) -> bool:
        run = self.running.get(agent_id)
        if not run:
            return False
        if run.sandbox:
            await run.sandbox.kill()
        run.future.cancel()
        self.db.audit("agent_terminated", agent_id, task_id=run.task_id)
        return True

    # -- tasks ----------------------------------------------------------
    def submit(self, kind: str, data: dict, deps: list[str] | None = None, priority: int = 0,
               irreversible: bool = False, max_attempts: int = 3, task_id: str | None = None) -> str:
        k = KINDS.get(kind)
        if k is None:
            raise ValueError(f"unknown task kind {kind}")
        errors = schema.validate(data, k.input_schema)
        if errors:
            raise ValueError(f"invalid input: {errors}")
        tid = self.queue.submit(kind, data, deps=deps, priority=priority, irreversible=irreversible,
                                required_caps=list(k.required_caps), max_attempts=max_attempts,
                                task_id=task_id)
        self.chain.register_task(tid, kind, crypto.commitment(data))
        return tid

    def result(self, task_id: str) -> dict | None:
        row = self.db.one("SELECT * FROM results WHERE task_id=?", (task_id,))
        if row is None:
            return None
        return {"task_id": task_id, "agent_id": row["agent_id"], "output": json.loads(row["output"]),
                "record": json.loads(row["record"]), "signature": row["signature"],
                "verification": json.loads(row["verification"]),
                "receipt": json.loads(row["receipt"]) if row["receipt"] else None}

    # -- scheduling -----------------------------------------------------
    def pause(self) -> None:
        self.paused = True

    def resume(self) -> None:
        self.paused = False

    def _eligible(self, task: Task) -> list[AgentRecord]:
        need = set(task.required_caps)
        return [a for a in self.registry.list()
                if a.status in ("idle", "active") and a.agent_id not in task.excluded
                and need <= allowed_scopes(a.roles)]

    def pick_agent(self, task: Task) -> AgentRecord | None | bool:
        """An idle eligible agent, None if all are busy, False if none can ever run it."""
        eligible = self._eligible(task)
        if not eligible:
            return False
        idle = [a for a in eligible if a.status == "idle" and a.agent_id not in self.running]
        if not idle:
            return None
        return min(idle, key=lambda a: (a.last_used, a.tasks_done))

    def _dispatch(self, allowed: int) -> int:
        started = 0
        for task in self.queue.ready(limit=max(8, allowed * 4)):
            if len(self.running) >= allowed:
                break
            agent = self.pick_agent(task)
            if agent is False:
                error = "no eligible agent" + (f"; last error: {task.error}" if task.error else "")
                self.db.execute("UPDATE tasks SET status='failed', error=?, updated_at=?"
                                " WHERE task_id=? AND status='pending'",
                                (error[:500], time.time(), task.task_id))
                continue
            if agent is None or not self.queue.claim(task.task_id, agent.agent_id,
                                                     self.cfg.security.lease_seconds):
                continue
            self.registry.set_status(agent.agent_id, "active")
            self.registry.mark_used(agent.agent_id)
            fut = asyncio.ensure_future(self._execute(self.queue.get(task.task_id), agent))
            self.running[agent.agent_id] = Running(task.task_id, fut)
            started += 1
        self.max_active_seen = max(self.max_active_seen, len(self.running))
        return started

    async def run(self, until_idle: bool = True, timeout: float | None = None) -> dict:
        deadline = time.monotonic() + timeout if timeout else None
        try:
            while True:
                self.queue.recover_expired()
                allowed = 0 if self.paused else self.governor.allowed_active(len(self.running))
                self.allowed_seen.add(allowed)
                started = self._dispatch(allowed)
                if self.running:
                    await asyncio.wait([r.future for r in self.running.values()],
                                       timeout=self.poll_interval,
                                       return_when=asyncio.FIRST_COMPLETED)
                else:
                    self._flush_ledger()
                    if until_idle and not started and not self.queue.ready(limit=1):
                        break
                    await asyncio.sleep(self.poll_interval)
                if deadline and time.monotonic() > deadline:
                    raise TimeoutError("swarm run timed out")
        finally:
            self._flush_ledger()
        return self.status()

    async def shutdown(self) -> None:
        for run in list(self.running.values()):
            run.future.cancel()
        if self.running:
            await asyncio.gather(*(r.future for r in self.running.values()), return_exceptions=True)
        self._flush_ledger()
        self.backend.close()
        self.db.close()

    # -- execution of one task by one agent -----------------------------
    async def _execute(self, task: Task, agent: AgentRecord) -> None:
        aid = agent.agent_id
        kind = KINDS[task.kind]
        state = self.load_checkpoint(aid)
        try:
            payload = dict(task.payload)
            if task.deps:
                payload["dependencies"] = {d: {"output": self.result(d)["output"],
                                               "commitment": self.queue.get(d).commitment}
                                           for d in task.deps}
            scopes = set(kind.required_caps) | set(task.required_caps)
            cap = self.authority.issue(aid, agent.roles, scopes, task.task_id,
                                       ttl=self.cfg.security.task_timeout_seconds + 30)
            self.chain.authorize_capability(cap.body)
            envelope = make_task_envelope(self.signer, task.task_id, task.kind, payload, aid,
                                          cap.cap_id, self.cfg.security.envelope_ttl_seconds)
            accept_task_envelope(envelope, payload, self.host_pubkey, aid, self.nonces)
            if task.irreversible and not self.queue.begin_execution(task.task_id, aid):
                self.queue.fail(task.task_id, aid, "already executed once; needs review", False)
                self.db.audit("duplicate_execution_blocked", aid, task.task_id)
                return

            ctx = AgentContext(
                agent_id=aid, host_pubkey=self.host_pubkey, memory=self.memory.view(aid),
                infer=lambda msgs, sch: self.inference.infer(cap, aid, msgs, json_schema=sch),
                call_tool=lambda name, args: self.tools.call(cap, aid, name, args))
            harness = AgentHarness(ctx)

            async def body():
                if self.fault_injector:
                    self.fault_injector(aid, task)
                return await harness.run(envelope, payload)

            sandbox = self.sandboxes.create(aid)
            self.running[aid].sandbox = sandbox
            result = await sandbox.run(body, self.cfg.security.task_timeout_seconds)

            record = result_record(envelope, aid, result.output, result.tool_calls)
            signature = self.signer.sign_as_agent(aid, RESULT_DOMAIN, record)
            sub = Submission(task.task_id, task.kind, payload, envelope, result.output, record,
                             signature, result.tool_calls, sorted(cap.scopes))
            verdict = self.verifier.verify(sub)
            if task.irreversible:
                self.queue.end_execution(task.task_id, "done" if verdict.ok else "rejected")
            if not verdict.ok:
                raise VerificationFailed("; ".join(verdict.problems))

            record_hash = crypto.commitment(record)
            entry = self.chain.commit_result_hash(task.task_id, aid, record_hash,
                                                  record["output_commitment"], signature)
            att = {"task_id": task.task_id, "verdict": True, "result_entry": entry,
                   "method": verdict.method}
            self.chain.submit_attestation(task.task_id, verdict.validator, True, entry, verdict.method,
                                          self.signer.sign_as_host(ATTESTATION_DOMAIN, att))
            verification = verdict.to_dict() | {"mock_inference": result.mock,
                                                "backend": self.backend.name,
                                                "isolation": self.sandboxes.isolation}
            with self.db.transaction() as conn:
                ok = conn.execute(
                    "UPDATE tasks SET status='done', commitment=?, error=NULL, lease_owner=NULL,"
                    " lease_expires=NULL, updated_at=? WHERE task_id=? AND status='leased'"
                    " AND lease_owner=?",
                    (record["output_commitment"], time.time(), task.task_id, aid)).rowcount == 1
                if ok:
                    conn.execute(
                        "INSERT INTO results(task_id, agent_id, output, record, signature,"
                        " verification, receipt, created_at) VALUES (?,?,?,?,?,?,?,?)",
                        (task.task_id, aid, json.dumps(result.output), json.dumps(record), signature,
                         json.dumps(verification), json.dumps({"pending": entry}), time.time()))
            if not ok:
                self.db.audit("result_discarded_lease_lost", aid, task.task_id)
                return
            self.registry.record_success(aid)
            state["tasks_done"] = state.get("tasks_done", 0) + 1
            state["tokens"] = state.get("tokens", 0) + result.tokens
            state["last_task"] = task.task_id
            self.db.audit("task_done", aid, task.task_id, commitment=record["output_commitment"])
        except asyncio.CancelledError:
            self.queue.fail(task.task_id, aid, "agent terminated", retryable=True)
            self.db.audit("task_cancelled", aid, task.task_id)
            raise
        except Exception as exc:
            status = self.queue.fail(task.task_id, aid, f"{type(exc).__name__}: {exc}")
            quarantined = self.registry.record_failure(aid, self.cfg.security.max_agent_failures)
            self.db.audit("task_failed", aid, task.task_id, error=repr(exc)[:300],
                          new_status=status, quarantined=quarantined)
            state["failures"] = state.get("failures", 0) + 1
        finally:
            self.save_checkpoint(aid, state)
            rec = self.registry.get(aid)
            if rec and rec.status == "active":
                self.registry.set_status(aid, "idle")  # suspend: sandbox discarded, state checkpointed
            self.signer.forget(aid)
            self.running.pop(aid, None)

    # -- checkpoints & recovery -----------------------------------------
    def load_checkpoint(self, agent_id: str) -> dict:
        row = self.db.one("SELECT state FROM checkpoints WHERE agent_id=?", (agent_id,))
        return json.loads(row["state"]) if row else {}

    def save_checkpoint(self, agent_id: str, state: dict) -> None:
        self.db.execute(
            "INSERT INTO checkpoints(agent_id, state, updated_at) VALUES (?,?,?) ON CONFLICT(agent_id)"
            " DO UPDATE SET state=excluded.state, updated_at=excluded.updated_at",
            (agent_id, json.dumps(state), time.time()))

    def _recover_after_crash(self) -> None:
        # Agents marked active belong to a previous process; their leases expire normally.
        self.db.execute("UPDATE agents SET status='idle' WHERE status='active'")
        self.db.execute("UPDATE tasks SET lease_expires=0 WHERE status='leased'")
        self.queue.recover_expired()

    def _flush_ledger(self) -> None:
        if self.chain.ledger.pending_count():
            self.chain.flush()
        for row in self.db.all("SELECT task_id, receipt FROM results WHERE receipt LIKE '{\"pending\"%'"):
            receipt = self.chain.receipt(json.loads(row["receipt"])["pending"])
            if receipt:
                self.db.execute("UPDATE results SET receipt=? WHERE task_id=?",
                                (json.dumps(receipt), row["task_id"]))

    # -- status ---------------------------------------------------------
    def status(self) -> dict[str, Any]:
        agents: dict[str, int] = {}
        for a in self.registry.list():
            agents[a.status] = agents.get(a.status, 0) + 1
        sample = self.governor.last
        tip = self.db.one("SELECT height, block_hash FROM ledger_blocks ORDER BY height DESC LIMIT 1")
        return {
            "tasks": self.queue.counts(),
            "agents": agents,
            "running": {aid: r.task_id for aid, r in self.running.items()},
            "max_active_seen": self.max_active_seen,
            "inference": {"backend": self.backend.name, "mock": self.backend.is_mock,
                          "requests": self.inference.requests,
                          "max_concurrent": self.inference.max_in_flight},
            "isolation": self.sandboxes.isolation,
            "security_mode": self.cfg.security.mode,
            "ledger": {"backend": "simulated", "finality": self.chain.ledger.finality,
                       "consensus": self.chain.ledger.consensus,
                       "height": tip["height"] if tip else None,
                       "tip": tip["block_hash"] if tip else None},
            "memory": None if sample is None else {
                "app_rss_mib": round(sample.app_rss / 2**20, 1),
                "host_available_mib": round(sample.available / 2**20, 1),
                "allowed_active": sample.allowed_active, "reason": sample.reason},
        }
