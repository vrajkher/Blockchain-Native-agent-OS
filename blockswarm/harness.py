"""Lightweight per-agent AI harness.

Each agent gets its own harness instance holding only: its identity, the
host public key, its private memory view, and two bound clients (inference
and tool gateway) that carry its own short-lived capability. It never holds
private keys, the database, or references to other agents. In Phase 2 this
module is what runs inside the microVM, with the clients becoming RPC stubs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from . import schema
from .envelope import check_task_envelope
from .memory import AgentMemoryView
from .tasks import KINDS, TaskKind


class HarnessError(Exception):
    pass


@dataclass
class AgentContext:
    agent_id: str
    host_pubkey: str
    memory: AgentMemoryView
    infer: Callable[[list[dict], dict | None], Awaitable[Any]]
    call_tool: Callable[[str, dict], Awaitable[Any]]


@dataclass
class HarnessResult:
    output: dict
    tool_calls: list[dict] = field(default_factory=list)
    inference_calls: int = 0
    tokens: int = 0
    mock: bool = False


def extract_json(text: str) -> Any:
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("no JSON object in model output")
    return json.loads(text[start:end + 1])


def normalize(value: Any, sch: dict) -> Any:
    """Light, schema-guided cleanup of small-model output before validation."""
    t = sch.get("type")
    if t == "object" and isinstance(value, dict):
        props = sch.get("properties", {})
        if sch.get("additionalProperties") is False:
            value = {k: v for k, v in value.items() if k in props}
        return {k: normalize(v, props[k]) if k in props else v for k, v in value.items()}
    if t == "array":
        if isinstance(value, str):
            value = [value]
        if isinstance(value, list):
            value = value[: sch.get("maxItems", len(value))]
            return [normalize(v, sch.get("items", {})) for v in value]
    if t == "string":
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            value = str(value)
        if isinstance(value, str):
            if "enum" in sch and value.strip().lower() in sch["enum"]:
                return value.strip().lower()
            return value[: sch.get("maxLength", len(value))]
    if t == "number" and isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return value
    return value


class AgentHarness:
    max_repairs = 1

    def __init__(self, ctx: AgentContext):
        self.ctx = ctx

    async def run(self, envelope: dict, payload: dict) -> HarnessResult:
        body = check_task_envelope(envelope, payload, self.ctx.host_pubkey, self.ctx.agent_id)
        kind = KINDS.get(body["kind"])
        if kind is None:
            raise HarnessError(f"unknown task kind {body['kind']}")
        errors = schema.validate(payload, kind.input_schema)
        if errors:
            raise HarnessError(f"invalid task input: {errors}")
        result = await (self._run_llm(kind, payload) if kind.uses_llm
                        else self._run_tool(kind, payload))
        self.ctx.memory.put(f"task:{body['task_id']}",
                            json.dumps({"kind": kind.name, "output": result.output})[:2000])
        return result

    async def _run_tool(self, kind: TaskKind, payload: dict) -> HarnessResult:
        if kind.name != "arithmetic":
            raise HarnessError(f"no tool plan for {kind.name}")
        res = await self.ctx.call_tool("calculator", {"expression": payload["expression"]})
        return HarnessResult({"answer": res["value"]},
                             tool_calls=[{"tool": "calculator", "args": payload}])

    def _messages(self, kind: TaskKind, payload: dict) -> list[dict]:
        notes = self.ctx.memory.recent(2)
        note_text = "".join(f"\n- {v[:200]}" for _, v in notes)
        system = (
            f"TASK_KIND: {kind.name}\n"
            f"You are agent {self.ctx.agent_id[:12]} in a verified swarm. {kind.instructions}\n"
            "Reply with ONLY one JSON object, no prose. JSON schema:\n"
            f"{json.dumps(kind.output_schema, separators=(',', ':'))}\n"
            f"Example: {json.dumps(kind.example)}"
            + (f"\nYour private notes from earlier tasks:{note_text}" if notes else "")
        )
        return [{"role": "system", "content": system},
                {"role": "user", "content": "Input:\n" + json.dumps(payload, ensure_ascii=False)}]

    async def _run_llm(self, kind: TaskKind, payload: dict) -> HarnessResult:
        messages = self._messages(kind, payload)
        calls = tokens = 0
        mock = False
        last_error = "no attempt"
        for _attempt in range(1 + self.max_repairs):
            completion = await self.ctx.infer(messages, kind.output_schema)
            calls += 1
            tokens += completion.prompt_tokens + completion.completion_tokens
            mock = mock or completion.mock
            try:
                output = normalize(extract_json(completion.text), kind.output_schema)
                errors = schema.validate(output, kind.output_schema)
            except (ValueError, json.JSONDecodeError) as exc:
                errors = [str(exc)]
            if not errors:
                return HarnessResult(output, inference_calls=calls, tokens=tokens, mock=mock)
            last_error = "; ".join(errors)[:300]
            messages = messages[:2] + [
                {"role": "assistant", "content": completion.text[:1000]},
                {"role": "user", "content": f"Invalid output ({last_error}). "
                                            "Reply with only the corrected JSON object."},
            ]
        raise HarnessError(f"model output failed validation: {last_error}")
