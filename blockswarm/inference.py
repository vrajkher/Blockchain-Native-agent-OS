"""Shared inference service: one resident model behind an authenticated gate.

* exactly one backend/model instance per process
* capability-authenticated (scope ``inference``) per request
* per-agent context, output and rolling token-budget limits
* bounded concurrency (default 1 simultaneous CPU inference)
* stateless requests: no conversation/KV state is shared between agents
"""

from __future__ import annotations

import asyncio
import json
import math
import os
import re
import threading
import time
import urllib.request
from collections import deque
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from .capabilities import Capability, CapabilityAuthority
from .config import InferenceConfig

ROLES = ("system", "user", "assistant")


class InferenceError(Exception):
    pass


class QuotaError(InferenceError, PermissionError):
    pass


@dataclass
class Completion:
    text: str
    prompt_tokens: int
    completion_tokens: int
    backend: str
    mock: bool
    seconds: float


class Backend:
    name = "abstract"
    is_mock = False

    def complete(self, messages: list[dict], max_tokens: int, temperature: float,
                 json_schema: dict | None) -> tuple[str, int, int]:
        """Blocking completion. ``json_schema`` (when given) constrains decoding."""
        raise NotImplementedError

    def count_tokens(self, text: str) -> int:
        # Conservative estimate for backends without a tokenizer (~3 bytes/token).
        return math.ceil(len(text.encode("utf-8")) / 3)

    def close(self) -> None:
        pass


class MockBackend(Backend):
    """Deterministic MOCK. Not a language model. Clearly labelled in all outputs."""

    name = "mock"
    is_mock = True

    def __init__(self, delay: float = 0.05):
        self.delay = delay
        self.requests: list[list[dict]] = []  # for isolation tests

    def complete(self, messages, max_tokens, temperature, json_schema):
        from .tasks import mock_response

        self.requests.append(messages)
        time.sleep(self.delay)  # simulate CPU-bound work off the event loop
        system = next(m["content"] for m in messages if m["role"] == "system")
        kind = re.search(r"TASK_KIND: (\S+)", system).group(1)
        user = messages[-1]["content"]
        data = json.loads(user[user.index("{"):])
        text = json.dumps(mock_response(kind, data))
        return text, self.count_tokens(system + user), self.count_tokens(text)


class LlamaCppBackend(Backend):
    """In-process llama.cpp via llama-cpp-python. Model is mmapped once."""

    name = "llama-cpp"

    def __init__(self, cfg: InferenceConfig):
        try:
            from llama_cpp import Llama
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise InferenceError("pip install llama-cpp-python to use backend 'llama-cpp'") from exc
        if not cfg.model_path or not os.path.exists(cfg.model_path):
            raise InferenceError(f"GGUF model not found: {cfg.model_path!r}")
        self._lock = threading.Lock()  # llama.cpp contexts are not thread-safe
        self.llm = Llama(
            model_path=cfg.model_path, n_ctx=cfg.n_ctx, n_threads=cfg.n_threads or None,
            n_batch=256, n_gpu_layers=0, use_mmap=True, use_mlock=False, verbose=False,
        )

    def count_tokens(self, text: str) -> int:
        with self._lock:
            return len(self.llm.tokenize(text.encode("utf-8"), add_bos=False, special=True))

    def complete(self, messages, max_tokens, temperature, json_schema):
        with self._lock:
            self.llm.reset()  # never reuse another agent's KV cache
            kwargs: dict[str, Any] = {"messages": messages, "max_tokens": max_tokens,
                                      "temperature": temperature}
            if json_schema is not None:
                # Grammar-constrained decoding: output is forced into the schema's shape.
                kwargs["response_format"] = {"type": "json_object",
                                             "schema": grammar_schema(json_schema)}
            out = self.llm.create_chat_completion(**kwargs)
            self.llm.reset()
        usage = out.get("usage", {})
        return (out["choices"][0]["message"]["content"] or "",
                usage.get("prompt_tokens", 0), usage.get("completion_tokens", 0))

    def close(self) -> None:
        if hasattr(self.llm, "close"):
            self.llm.close()


class HttpBackend(Backend):
    """OpenAI-compatible HTTP: a local ``llama-server`` or an optional remote model."""

    name = "http"

    def __init__(self, cfg: InferenceConfig):
        self.cfg = cfg
        self.api_key = os.environ.get(cfg.http_api_key_env, "")
        host = urlparse(cfg.http_url).hostname or ""
        self.local = host in ("127.0.0.1", "localhost", "::1")
        if not self.local and urlparse(cfg.http_url).scheme != "https":
            raise InferenceError("remote model adapters must use https")

    def complete(self, messages, max_tokens, temperature, json_schema):
        body: dict[str, Any] = {"model": self.cfg.http_model, "messages": messages,
                                "max_tokens": max_tokens, "temperature": temperature}
        if json_schema is not None:
            body["response_format"] = {"type": "json_schema",
                                       "json_schema": {"name": "output",
                                                       "schema": grammar_schema(json_schema)}}
        if self.local:
            body["cache_prompt"] = False  # llama-server: no cross-request KV reuse
        req = urllib.request.Request(self.cfg.http_url, data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
        if self.api_key:
            req.add_header("Authorization", f"Bearer {self.api_key}")
        with urllib.request.urlopen(req, timeout=self.cfg.request_timeout_seconds) as resp:
            out = json.loads(resp.read(4 * 1024 * 1024))
        usage = out.get("usage", {})
        return (out["choices"][0]["message"]["content"] or "",
                usage.get("prompt_tokens", 0), usage.get("completion_tokens", 0))


_GRAMMAR_DROP = ("maxLength", "minimum", "maximum")


def grammar_schema(schema: dict) -> dict:
    """Schema copy for constrained decoding.

    Length/range bounds are dropped because GBNF expands them into huge rule
    sets; they are still enforced after decoding by normalization and the
    deterministic verifier.
    """
    out = {k: v for k, v in schema.items() if k not in _GRAMMAR_DROP}
    if out.get("minLength", 0) > 8:
        out.pop("minLength")
    if "properties" in out:
        out["properties"] = {k: grammar_schema(v) for k, v in out["properties"].items()}
    if isinstance(out.get("items"), dict):
        out["items"] = grammar_schema(out["items"])
    return out


def make_backend(cfg: InferenceConfig) -> Backend:
    if cfg.backend == "mock":
        return MockBackend()
    if cfg.backend == "llama-cpp":
        return LlamaCppBackend(cfg)
    if cfg.backend == "http":
        return HttpBackend(cfg)
    raise InferenceError(f"unknown backend {cfg.backend}")


class InferenceService:
    def __init__(self, backend: Backend, authority: CapabilityAuthority, cfg: InferenceConfig,
                 concurrency: int = 1):
        self.backend = backend
        self.authority = authority
        self.cfg = cfg
        self._sem = asyncio.Semaphore(concurrency)
        self._usage: dict[str, deque[tuple[float, int]]] = {}
        self.in_flight = 0
        self.max_in_flight = 0
        self.requests = 0

    def usage(self, agent_id: str, now: float | None = None) -> int:
        now = time.time() if now is None else now
        window = self._usage.setdefault(agent_id, deque())
        while window and now - window[0][0] > self.cfg.budget_window_seconds:
            window.popleft()
        return sum(n for _, n in window)

    async def infer(self, cap: Capability, agent_id: str, messages: list[dict],
                    max_tokens: int | None = None, json_schema: dict | None = None) -> Completion:
        self.authority.check(cap, agent_id, "inference")
        if not isinstance(messages, list) or not messages or len(messages) > 16:
            raise InferenceError("messages must be a non-empty list (max 16)")
        for m in messages:
            if not isinstance(m, dict) or m.get("role") not in ROLES or not isinstance(m.get("content"), str):
                raise InferenceError("malformed message")
        max_out = min(max_tokens or self.cfg.max_output_tokens_per_request,
                      self.cfg.max_output_tokens_per_request)
        prompt_tokens = sum(self.backend.count_tokens(m["content"]) for m in messages)
        if prompt_tokens > self.cfg.max_context_tokens_per_agent:
            raise QuotaError(f"prompt of {prompt_tokens} tokens exceeds per-agent context limit "
                             f"{self.cfg.max_context_tokens_per_agent}")
        if prompt_tokens + max_out > self.cfg.n_ctx:
            raise QuotaError("request exceeds model context window")
        if self.usage(agent_id) + prompt_tokens + max_out > self.cfg.token_budget_per_agent_window:
            raise QuotaError("per-agent token budget exhausted")

        async with self._sem:
            self.in_flight += 1
            self.max_in_flight = max(self.max_in_flight, self.in_flight)
            start = time.perf_counter()
            try:
                text, p, c = await asyncio.to_thread(
                    self.backend.complete, messages, max_out, self.cfg.temperature, json_schema)
            finally:
                self.in_flight -= 1
        self.requests += 1
        p = p or prompt_tokens
        self._usage.setdefault(agent_id, deque()).append((time.time(), p + c))
        return Completion(text, p, c, self.backend.name, self.backend.is_mock,
                          time.perf_counter() - start)
