"""Runtime configuration. Memory values are starting targets, not guarantees."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Any

MiB = 1024 * 1024


@dataclass
class GovernorConfig:
    total_physical_ram_target_mib: int = 8192
    target_application_ram_mib: int = 5120
    minimum_host_headroom_mib: int = 1024
    default_active_agents: int = 2
    maximum_active_agents: int = 3
    preferred_guest_ram_mib: int = 256
    model_instances: int = 1  # one shared model endpoint for all agents
    inference_concurrency: int = 1
    idle_agent_policy: str = "suspend_or_terminate"
    ram_pressure_policy: str = "reduce_concurrency"
    overload_policy: str = "queue_tasks"
    enforce_limits: bool = True


@dataclass
class InferenceConfig:
    # anthropic: Claude via the Anthropic API (default) | mock: deterministic test double
    backend: str = "anthropic"
    model: str = "claude-opus-5-5"
    # Short structured tasks: low effort keeps latency and cost down; raise for harder kinds.
    effort: str = "low"  # low | medium | high | xhigh | max
    refusal_fallbacks: bool = True  # server-side fallback on safety declines
    max_retries: int = 2
    max_context_tokens_per_agent: int = 6000
    max_output_tokens_per_request: int = 2048
    token_budget_per_agent_window: int = 100000
    budget_window_seconds: int = 3600
    temperature: float = 0.1  # used by the mock only; current Claude models reject sampling params
    request_timeout_seconds: float = 120.0


@dataclass
class SecurityConfig:
    # dev: in-process sandbox allowed (NOT a security boundary)
    # secure: microVM isolation required; startup fails closed otherwise
    mode: str = "dev"
    sandbox_backend: str = "inprocess"  # inprocess | firecracker
    capability_ttl_seconds: int = 300
    envelope_ttl_seconds: int = 300
    max_agent_failures: int = 3
    task_timeout_seconds: float = 180.0
    lease_seconds: float = 240.0
    max_memory_entries_per_agent: int = 200
    max_memory_value_bytes: int = 16384


@dataclass
class LedgerConfig:
    # simulated: local hash-chained log, NO consensus (Phase 1)
    backend: str = "simulated"
    batch_size: int = 16


@dataclass
class ApiConfig:
    host: str = "127.0.0.1"
    port: int = 8787
    max_body_bytes: int = 65536


@dataclass
class Config:
    home: str = ".blockswarm"
    governor: GovernorConfig = field(default_factory=GovernorConfig)
    inference: InferenceConfig = field(default_factory=InferenceConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    ledger: LedgerConfig = field(default_factory=LedgerConfig)
    api: ApiConfig = field(default_factory=ApiConfig)

    @property
    def home_path(self) -> Path:
        return Path(self.home).expanduser().resolve()

    @property
    def db_path(self) -> Path:
        return self.home_path / "swarm.db"

    @property
    def keystore_path(self) -> Path:
        return self.home_path / "keystore"


def _merge(obj: Any, data: dict[str, Any]) -> None:
    known = {f.name: f for f in fields(obj)}
    for key, value in data.items():
        if key not in known:
            raise ValueError(f"unknown config key: {key}")
        current = getattr(obj, key)
        if is_dataclass(current):
            if not isinstance(value, dict):
                raise ValueError(f"config section {key} must be a table")
            _merge(current, value)
        else:
            setattr(obj, key, type(current)(value) if current is not None else value)


def load_config(path: str | os.PathLike | None = None, **overrides: Any) -> Config:
    cfg = Config()
    if path:
        with open(path, "rb") as fh:
            _merge(cfg, tomllib.load(fh))
    _merge(cfg, overrides)
    validate(cfg)
    return cfg


def validate(cfg: Config) -> None:
    g = cfg.governor
    if g.model_instances != 1:
        raise ValueError("exactly one shared model is supported")
    if g.inference_concurrency < 1:
        raise ValueError("inference_concurrency must be >= 1")
    if not 1 <= g.default_active_agents <= g.maximum_active_agents:
        raise ValueError("default_active_agents must be within 1..maximum_active_agents")
    if cfg.security.mode not in ("dev", "secure"):
        raise ValueError("security.mode must be 'dev' or 'secure'")
    if cfg.inference.backend not in ("anthropic", "mock"):
        raise ValueError("inference.backend must be 'anthropic' or 'mock'")
    if cfg.inference.effort not in ("low", "medium", "high", "xhigh", "max"):
        raise ValueError("inference.effort must be low, medium, high, xhigh or max")
