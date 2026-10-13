"""Host-side broker for one sandboxed agent run.

The broker is the only thing a sandbox can talk to. It:

* sends the signed task (envelope, payload, host public key) to the guest,
* serves the guest's requests (inference, tool calls, private memory),
  each one authorized by the gateway with the agent's capability, which
  stays on the host and is never sent to the guest,
* records the evidence itself (tool calls, inference count/tokens, mock
  flag) instead of trusting what the guest reports,
* enforces per-run limits (frame size, number of calls), fails closed.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any

from . import rpc
from .capabilities import Capability
from .gateway import GatewayDenied
from .harness import HarnessResult
from .inference import InferenceService, ServiceUnavailable
from .memory import AgentMemoryView
from .tools import ToolGateway


class SandboxFailure(Exception):
    """The guest reported failure or broke the protocol."""


@dataclass
class SandboxJob:
    agent_id: str
    task_id: str
    host_pubkey: str
    envelope: dict
    payload: dict


@dataclass
class BrokerLimits:
    max_calls: int = 32
    max_frame: int = rpc.MAX_FRAME


@dataclass
class BrokerStats:
    calls: dict[str, int] = field(default_factory=dict)
    denied: list[str] = field(default_factory=list)


class SandboxBroker:
    def __init__(self, job: SandboxJob, cap: Capability, gateway: Any,
                 inference: InferenceService, tools: ToolGateway, memory: AgentMemoryView,
                 limits: BrokerLimits | None = None):
        self.job = job
        self.cap = cap
        self.gateway = gateway
        self.inference = inference
        self.tools = tools
        self.memory = memory
        self.limits = limits or BrokerLimits()
        self.stats = BrokerStats()
        self._tool_calls: list[dict] = []
        self._inference_calls = 0
        self._tokens = 0
        self._mock = False
        self.service_error: ServiceUnavailable | None = None

    async def serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> HarnessResult:
        await rpc.send(writer, {"t": "task", "agent_id": self.job.agent_id,
                                "host_pubkey": self.job.host_pubkey,
                                "envelope": self.job.envelope, "payload": self.job.payload})
        calls = 0
        while True:
            msg = await rpc.recv(reader, self.limits.max_frame)
            kind = msg.get("t")
            if kind == "result":
                output = msg.get("output")
                if not isinstance(output, dict):
                    raise SandboxFailure("guest returned a non-object output")
                return HarnessResult(output=output, tool_calls=list(self._tool_calls),
                                     inference_calls=self._inference_calls, tokens=self._tokens,
                                     mock=self._mock)
            if kind == "fail":
                if self.service_error is not None:
                    raise self.service_error
                raise SandboxFailure(str(msg.get("error", "guest failed"))[:500])
            if kind != "call":
                raise SandboxFailure(f"unexpected message type {kind!r}")
            calls += 1
            if calls > self.limits.max_calls:
                raise SandboxFailure("guest exceeded the per-run call limit")
            reply = await self._call(msg)
            await rpc.send(writer, reply)

    async def _call(self, msg: dict) -> dict:
        call_id = msg.get("id")
        op = msg.get("op")
        args = msg.get("args") if isinstance(msg.get("args"), dict) else {}
        action = {"infer": "inference", "mem.get": "memory.read", "mem.recent": "memory.read",
                  "mem.put": "memory.write"}.get(op)
        if op == "tool":
            action = f"tool:{args.get('name', '')}"
        if action is None:
            return {"t": "reply", "id": call_id, "ok": False, "error": f"unknown op {op!r}"}
        self.stats.calls[action] = self.stats.calls.get(action, 0) + 1
        arg_bytes = len(json.dumps(args))
        decision = await self.gateway.authorize(self.job.agent_id, self.cap.to_dict(), action,
                                                arg_bytes, self.job.task_id)
        if not decision.allowed:
            self.stats.denied.append(f"{action}: {decision.reason}")
            return {"t": "reply", "id": call_id, "ok": False, "error": f"denied: {decision.reason}"}
        try:
            value = await self._dispatch(op, args)
            return {"t": "reply", "id": call_id, "ok": True, "value": value}
        except ServiceUnavailable as exc:
            self.service_error = exc
            return {"t": "reply", "id": call_id, "ok": False, "error": "model service unavailable"}
        except Exception as exc:
            return {"t": "reply", "id": call_id, "ok": False, "error": f"{type(exc).__name__}: {exc}"[:300]}

    async def _dispatch(self, op: str, args: dict) -> Any:
        aid = self.job.agent_id
        if op == "infer":
            c = await self.inference.infer(self.cap, aid, args.get("messages"),
                                           json_schema=args.get("schema"))
            self._inference_calls += 1
            self._tokens += c.prompt_tokens + c.completion_tokens
            self._mock = self._mock or c.mock
            return {"text": c.text, "prompt_tokens": c.prompt_tokens,
                    "completion_tokens": c.completion_tokens, "mock": c.mock}
        if op == "tool":
            name, tool_args = args.get("name"), args.get("args")
            value = await self.tools.call(self.cap, aid, name, tool_args)
            self._tool_calls.append({"tool": name, "args": tool_args})  # host-recorded evidence
            return value
        if op == "mem.get":
            return self.memory.get(str(args.get("key", "")))
        if op == "mem.recent":
            return self.memory.recent(min(int(args.get("n", 3)), 10))
        if op == "mem.put":
            self.memory.put(str(args.get("key", "")), str(args.get("value", "")))
            return True
        raise ValueError(op)
