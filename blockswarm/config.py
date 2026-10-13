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
    sandbox_backend: str = "inprocess"  # inprocess | process | firecracker
    # process sandbox (dev): uid to drop to when started as root, address-space cap
    process_uid: int = 65534
    process_memory_mib: int = 1024
    # authorization gateway: "inprocess" or "unix:/path/to/gateway.sock"
    gateway: str = "inprocess"
    policy_file: str = ""  # empty = built-in default policy
    max_rpc_calls_per_task: int = 32
    capability_ttl_seconds: int = 300
    envelope_ttl_seconds: int = 300
    max_agent_failures: int = 3
    task_timeout_seconds: float = 180.0
    lease_seconds: float = 240.0
    max_memory_entries_per_agent: int = 200
    max_memory_value_bytes: int = 16384


@dataclass
class FirecrackerConfig:
    firecracker_bin: str = "/usr/local/bin/firecracker"
    jailer_bin: str = "/usr/local/bin/jailer"
    kernel_image: str = "/var/lib/blockswarm/vmlinux"
    rootfs_image: str = "/var/lib/blockswarm/guest-rootfs.ext4"
    chroot_base: str = "/srv/blockswarm-jail"
    uid: int = 65534  # unprivileged user firecracker runs as inside the jail
    gid: int = 65534
    vcpus: int = 1
    guest_mem_mib: int = 256
    vmm_overhead_mib: int = 64  # cgroup memory limit = guest + overhead
    cpu_quota_pct: int = 100  # of one CPU
    pids_max: int = 64
    cgroup_version: int = 2
    vsock_port: int = 5000
    boot_timeout_seconds: float = 30.0
    boot_args: str = "console=ttyS0 reboot=k panic=1 pci=off ro quiet init=/sbin/blockswarm-init"


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
    firecracker: FirecrackerConfig = field(default_factory=FirecrackerConfig)
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
    if cfg.security.sandbox_backend not in ("inprocess", "process", "firecracker"):
        raise ValueError("security.sandbox_backend must be inprocess, process or firecracker")
    if cfg.firecracker.cgroup_version not in (1, 2):
        raise ValueError("firecracker.cgroup_version must be 1 or 2")
    if cfg.inference.effort not in ("low", "medium", "high", "xhigh", "max"):
        raise ValueError("inference.effort must be low, medium, high, xhigh or max")
