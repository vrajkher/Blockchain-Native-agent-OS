"""Execution sandboxes. Every backend runs the same guest agent over the
same broker protocol; only the isolation differs.

| backend      | isolation                                                    | secure mode |
|--------------|--------------------------------------------------------------|-------------|
| inprocess    | none: asyncio task in the host process                       | refused     |
| process      | separate OS process: unprivileged uid, empty env, rlimits,   | refused     |
|              | own network namespace when run as root. NOT a microVM.       |             |
| firecracker  | one Firecracker microVM per run, launched via jailer         | required    |

Only Firecracker is treated as a security boundary, and no sandbox
guarantees absolute containment.
"""

from __future__ import annotations

import asyncio
import os
import resource
import socket
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from .config import Config, SecurityConfig

if TYPE_CHECKING:  # pragma: no cover
    from .broker import SandboxBroker
    from .harness import HarnessResult

PACKAGE_PARENT = str(Path(__file__).resolve().parent.parent)


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
        self.guest_peak_rss: int | None = None

    async def run(self, broker: "SandboxBroker", timeout: float) -> "HarnessResult":
        raise NotImplementedError

    async def kill(self) -> None:
        raise NotImplementedError

    @staticmethod
    async def _serve(broker, sock: socket.socket, timeout: float, agent_id: str):
        reader, writer = await asyncio.open_connection(sock=sock)
        try:
            return await asyncio.wait_for(broker.serve(reader, writer), timeout)
        except asyncio.TimeoutError as exc:
            raise SandboxTimeout(f"agent {agent_id} exceeded {timeout}s") from exc
        finally:
            writer.close()


class InProcessSandbox(Sandbox):
    isolation = "none: in-process asyncio task (DEV ONLY, NOT a security boundary)"

    def __init__(self, agent_id: str):
        super().__init__(agent_id)
        self._guest: asyncio.Task | None = None

    async def run(self, broker, timeout):
        from .guest.agent import run_guest

        host_sock, guest_sock = socket.socketpair()
        g_reader, g_writer = await asyncio.open_connection(sock=guest_sock)

        async def guest():
            try:
                await run_guest(g_reader, g_writer)
            finally:
                g_writer.close()
        self._guest = asyncio.ensure_future(guest())
        try:
            return await self._serve(broker, host_sock, timeout, self.agent_id)
        finally:
            await self.kill()

    async def kill(self) -> None:
        if self._guest and not self._guest.done():
            self._guest.cancel()
            await asyncio.gather(self._guest, return_exceptions=True)


GUEST_BOOT = ("import sys; sys.path.insert(0, {path!r}); "
              "from {module} import main; sys.exit(main(['--fd', '{fd}']))")


class ProcessSandbox(Sandbox):
    isolation = ("process: separate OS process, unprivileged uid, empty environment, rlimits, "
                 "private network namespace when root (DEV ONLY, NOT equivalent to a microVM)")

    guest_module = "blockswarm.guest.agent"
    python = sys.executable
    package_parent = PACKAGE_PARENT

    def __init__(self, agent_id: str, cfg: SecurityConfig):
        super().__init__(agent_id)
        self.cfg = cfg
        self._proc: asyncio.subprocess.Process | None = None
        self.network_isolated = False
        self.uid: int | None = None

    def _preexec(self, timeout: float):
        is_root = os.geteuid() == 0
        cpu = int(timeout) + 5
        mem = self.cfg.process_memory_mib * 1024 * 1024
        unshare_net = is_root and hasattr(os, "unshare")
        uid = self.cfg.process_uid

        def fn():  # runs in the child between fork and exec
            os.setsid()
            if unshare_net:
                os.unshare(os.CLONE_NEWNET)  # empty netns: only a down loopback, no routes
            resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
            resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
            resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
            resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))  # cannot write file contents
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            if is_root:
                os.setgroups([])
                os.setgid(uid)
                os.setuid(uid)
        self.network_isolated = unshare_net
        self.uid = uid if is_root else os.geteuid()
        return fn

    async def run(self, broker, timeout):
        host_sock, guest_sock = socket.socketpair()
        fd = guest_sock.fileno()
        try:
            self._proc = await asyncio.create_subprocess_exec(
                self.python, "-I", "-B", "-c",
                GUEST_BOOT.format(path=self.package_parent, module=self.guest_module, fd=fd),
                pass_fds=(fd,), cwd="/", env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
                stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE, preexec_fn=self._preexec(timeout))
        finally:
            guest_sock.close()
        try:
            result = await self._serve(broker, host_sock, timeout, self.agent_id)
            self._sample_rss()
            return result
        except Exception:
            err = await self._stderr_tail()
            if err and not isinstance(sys.exc_info()[1], SandboxTimeout):
                broker.stats.denied.append(f"guest stderr: {err}")
            raise
        finally:
            await self.kill()

    def _sample_rss(self) -> None:
        try:
            with open(f"/proc/{self._proc.pid}/status") as fh:
                for line in fh:
                    if line.startswith("VmHWM:"):
                        self.guest_peak_rss = int(line.split()[1]) * 1024
        except (OSError, AttributeError):
            pass

    async def _stderr_tail(self) -> str:
        if not self._proc or not self._proc.stderr:
            return ""
        try:
            data = await asyncio.wait_for(self._proc.stderr.read(4096), 0.5)
            return data.decode(errors="replace").strip()[-500:]
        except Exception:
            return ""

    async def kill(self) -> None:
        proc = self._proc
        if proc is None or proc.returncode is not None:
            return
        try:
            await asyncio.wait_for(proc.wait(), 1.0)
            return
        except asyncio.TimeoutError:
            pass
        try:
            os.killpg(proc.pid, 9)
        except ProcessLookupError:
            pass
        await proc.wait()


class SandboxFactory:
    BACKENDS = ("inprocess", "process", "firecracker")

    def __init__(self, cfg: Config | SecurityConfig):
        self.full = cfg if isinstance(cfg, Config) else None
        self.cfg = cfg.security if isinstance(cfg, Config) else cfg
        if self.cfg.sandbox_backend not in self.BACKENDS:
            raise SecurityPolicyError(f"unknown sandbox backend {self.cfg.sandbox_backend}")
        if self.cfg.mode == "secure" and self.cfg.sandbox_backend != "firecracker":
            raise SecurityPolicyError(
                "secure mode requires microVM isolation (sandbox_backend='firecracker'); "
                f"refusing to run agents with the '{self.cfg.sandbox_backend}' sandbox")

    @property
    def isolation(self) -> str:
        if self.cfg.sandbox_backend == "firecracker":
            from .firecracker import FirecrackerSandbox
            return FirecrackerSandbox.isolation
        return (ProcessSandbox if self.cfg.sandbox_backend == "process" else InProcessSandbox).isolation

    def check(self) -> None:
        """Fail closed at startup if the configured backend cannot run."""
        if self.cfg.sandbox_backend == "firecracker":
            from .firecracker import preflight
            preflight(self.full.firecracker if self.full else None)

    def create(self, agent_id: str) -> Sandbox:
        if self.cfg.sandbox_backend == "firecracker":
            from .firecracker import FirecrackerSandbox
            return FirecrackerSandbox(agent_id, self.full.firecracker if self.full else None)
        if self.cfg.sandbox_backend == "process":
            return ProcessSandbox(agent_id, self.cfg)
        return InProcessSandbox(agent_id)
