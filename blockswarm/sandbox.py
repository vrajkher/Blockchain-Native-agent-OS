"""Execution sandboxes.

Phase 1 ships only ``InProcessSandbox``. It is NOT a security boundary: it
gives each agent run its own asyncio task, timeout and kill switch, nothing
more. Secure mode refuses to start without a microVM backend (fail closed).
``FirecrackerSandbox`` is the Phase 2 placeholder and is not implemented.
"""

from __future__ import annotations

import asyncio
import os
import shutil
from typing import Any, Awaitable, Callable

from .config import SecurityConfig


class SandboxUnavailable(RuntimeError):
    pass


class SecurityPolicyError(RuntimeError):
    pass


class SandboxTimeout(TimeoutError):
    pass


class Sandbox:
    isolation = "abstract"
    secure = False

    def __init__(self, agent_id: str):
        self.agent_id = agent_id

    async def run(self, fn: Callable[[], Awaitable[Any]], timeout: float) -> Any:
        raise NotImplementedError

    async def kill(self) -> None:
        raise NotImplementedError


class InProcessSandbox(Sandbox):
    isolation = "none: in-process asyncio task (DEV ONLY, NOT a security boundary)"
    secure = False

    def __init__(self, agent_id: str):
        super().__init__(agent_id)
        self._task: asyncio.Task | None = None

    async def run(self, fn, timeout):
        self._task = asyncio.ensure_future(fn())
        try:
            return await asyncio.wait_for(self._task, timeout)
        except asyncio.TimeoutError as exc:
            raise SandboxTimeout(f"agent {self.agent_id} exceeded {timeout}s") from exc
        finally:
            self._task = None

    async def kill(self) -> None:
        if self._task and not self._task.done():
            self._task.cancel()


class FirecrackerSandbox(Sandbox):
    """Phase 2: one Firecracker microVM per agent run, launched via jailer."""

    isolation = "firecracker microVM + jailer"
    secure = True

    def __init__(self, agent_id: str):
        super().__init__(agent_id)
        raise SandboxUnavailable(
            "Firecracker sandbox is not implemented yet (Phase 2). "
            f"/dev/kvm present: {os.path.exists('/dev/kvm')}; "
            f"firecracker binary: {shutil.which('firecracker')}")


class SandboxFactory:
    def __init__(self, cfg: SecurityConfig):
        self.cfg = cfg
        if cfg.mode == "secure" and cfg.sandbox_backend != "firecracker":
            raise SecurityPolicyError(
                "secure mode requires microVM isolation (sandbox_backend='firecracker'); "
                "refusing to run agents in-process")
        if cfg.sandbox_backend not in ("inprocess", "firecracker"):
            raise SecurityPolicyError(f"unknown sandbox backend {cfg.sandbox_backend}")

    @property
    def isolation(self) -> str:
        return (FirecrackerSandbox if self.cfg.sandbox_backend == "firecracker"
                else InProcessSandbox).isolation

    def create(self, agent_id: str) -> Sandbox:
        if self.cfg.sandbox_backend == "firecracker":
            return FirecrackerSandbox(agent_id)
        return InProcessSandbox(agent_id)
