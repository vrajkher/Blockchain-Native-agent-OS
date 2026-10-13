"""Shared inference service: one model API behind an authenticated gate.

* exactly one backend (one model) shared by every agent
* capability-authenticated (scope ``inference``) per request
* per-agent context, output and rolling token-budget limits
* bounded concurrency (default 1 request in flight)
* stateless requests: no conversation state is shared between agents
"""

from __future__ import annotations

import asyncio
import json
import math
import re
import time
from collections import deque
from dataclasses import dataclass
from typing import Any

from .capabilities import Capability, CapabilityAuthority
from .config import InferenceConfig

ROLES = ("system", "user", "assistant")


class InferenceError(Exception):
    pass


class QuotaError(InferenceError, PermissionError):
    pass


class ServiceUnavailable(InferenceError):
    """The model service failed (auth, network, rate limit, 5xx): not the agent's fault."""


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

    def preflight(self) -> None:
        """Fail fast at startup if the backend cannot serve requests."""

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


class AnthropicBackend(Backend):
    """Claude via the official Anthropic SDK. The single shared model for all agents.

    * structured outputs (``output_config.format``) constrain replies to the task schema
    * server-side refusal fallbacks are opted into by default
    * credentials come from the SDK's normal resolution (``ANTHROPIC_API_KEY``,
      ``ANTHROPIC_AUTH_TOKEN`` or an ``ant auth login`` profile); never from config
    * every request is stateless: it carries only the calling agent's messages
    """

    name = "anthropic"
    FALLBACK_BETA = "server-side-fallback-2026-07-01"

    def __init__(self, cfg: InferenceConfig, client: Any = None):
        self.cfg = cfg
        if client is None:
            try:
                import anthropic
            except ImportError as exc:  # pragma: no cover - dependency is declared
                raise InferenceError("pip install anthropic") from exc
            client = anthropic.Anthropic(timeout=cfg.request_timeout_seconds,
                                         max_retries=cfg.max_retries)
        self.client = client

    def preflight(self) -> None:
        """Check credentials and the model ID without generating tokens."""
        import anthropic
        try:
            self.client.models.retrieve(self.cfg.model)
        except anthropic.NotFoundError as exc:
            raise InferenceError(f"unknown model {self.cfg.model!r}") from exc
        except Exception as exc:
            raise self._service_error(exc) from exc

    @staticmethod
    def _service_error(exc: Exception) -> Exception:
        import anthropic
        if isinstance(exc, (anthropic.AuthenticationError, TypeError)):
            # TypeError: the SDK found no credentials at all.
            return ServiceUnavailable("Anthropic API credentials missing or invalid: set "
                                      "ANTHROPIC_API_KEY or run `ant auth login`")
        if isinstance(exc, anthropic.PermissionDeniedError):
            return ServiceUnavailable("Anthropic API key lacks permission for this model")
        if isinstance(exc, anthropic.RateLimitError):
            return ServiceUnavailable("Anthropic API rate limit (retries exhausted)")
        if isinstance(exc, anthropic.APIStatusError):
            return ServiceUnavailable(f"Anthropic API error {exc.status_code}")
        if isinstance(exc, anthropic.APIConnectionError):
            return ServiceUnavailable("cannot reach the Anthropic API")
        return exc

    def complete(self, messages, max_tokens, temperature, json_schema):
        import anthropic

        system = "\n\n".join(m["content"] for m in messages if m["role"] == "system")
        convo = [{"role": m["role"], "content": m["content"]}
                 for m in messages if m["role"] != "system"]
        output_config: dict[str, Any] = {"effort": self.cfg.effort}
        if json_schema is not None:
            output_config["format"] = {"type": "json_schema",
                                       "schema": decoding_schema(json_schema)}
        kwargs: dict[str, Any] = {"model": self.cfg.model, "max_tokens": max_tokens,
                                  "messages": convo, "output_config": output_config}
        if system:
            kwargs["system"] = system
        try:
            if self.cfg.refusal_fallbacks:
                resp = self.client.beta.messages.create(
                    betas=[self.FALLBACK_BETA], fallbacks="default", **kwargs)
            else:
                resp = self.client.messages.create(**kwargs)
        except anthropic.BadRequestError as exc:
            raise InferenceError(f"Anthropic API rejected the request: {exc.message}") from exc
        except (anthropic.APIError, TypeError) as exc:
            raise self._service_error(exc) from exc
        if resp.stop_reason == "refusal":
            category = getattr(resp.stop_details, "category", None) if resp.stop_details else None
            raise InferenceError(f"model declined the request (category: {category})")
        if resp.stop_reason == "max_tokens":
            raise InferenceError("model output hit max_tokens")
        text = "".join(b.text for b in resp.content if b.type == "text")
        usage = resp.usage
        return text, usage.input_tokens, usage.output_tokens


_DECODING_DROP = ("minLength", "maxLength", "minimum", "maximum", "minItems", "maxItems")


def decoding_schema(schema: dict) -> dict:
    """Schema copy sent to the API for constrained decoding.

    Length/range/count bounds are dropped so the request only uses the core
    structured-output keywords; the bounds are still enforced after decoding by
    normalization and the deterministic verifier.
    """
    out = {k: v for k, v in schema.items() if k not in _DECODING_DROP}
    if "properties" in out:
        out["properties"] = {k: decoding_schema(v) for k, v in out["properties"].items()}
    if isinstance(out.get("items"), dict):
        out["items"] = decoding_schema(out["items"])
    return out


def make_backend(cfg: InferenceConfig) -> Backend:
    if cfg.backend == "mock":
        return MockBackend()
    if cfg.backend == "anthropic":
        return AnthropicBackend(cfg)
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
