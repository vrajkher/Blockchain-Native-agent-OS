"""Resource governor: measures real memory and sets active-agent concurrency.

Policy: start at ``default_active_agents`` (2); allow up to
``maximum_active_agents`` (3) only when measured memory permits; under
pressure reduce concurrency (down to 0 = pause dispatch) rather than risk
host exhaustion. Excess work is queued, never dropped.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable

from .config import GovernorConfig

KiB = 1024
MiB = 1024 * 1024


def read_meminfo(path: str = "/proc/meminfo") -> dict[str, int]:
    out = {}
    with open(path) as fh:
        for line in fh:
            key, rest = line.split(":", 1)
            out[key] = int(rest.split()[0]) * KiB
    return out


def rss_bytes(pid: int | str = "self") -> int:
    with open(f"/proc/{pid}/status") as fh:
        for line in fh:
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * KiB
    return 0


def peak_rss_bytes(pid: int | str = "self") -> int:
    with open(f"/proc/{pid}/status") as fh:
        for line in fh:
            if line.startswith("VmHWM:"):
                return int(line.split()[1]) * KiB
    return 0


@dataclass
class MemorySample:
    total: int
    available: int
    app_rss: int
    allowed_active: int
    reason: str


class ResourceGovernor:
    def __init__(self, cfg: GovernorConfig,
                 meminfo: Callable[[], dict[str, int]] = read_meminfo,
                 app_rss: Callable[[], int] | None = None,
                 extra_pids: list[int] | None = None):
        self.cfg = cfg
        self._meminfo = meminfo
        self._extra_pids = extra_pids or []  # e.g. a co-located helper process
        self._app_rss = app_rss or self._measure_app_rss
        self.last: MemorySample | None = None

    def _measure_app_rss(self) -> int:
        total = rss_bytes()
        for pid in self._extra_pids:
            try:
                total += rss_bytes(pid)
            except OSError:
                pass
        return total

    def sample(self, active_now: int = 0) -> MemorySample:
        c = self.cfg
        info = self._meminfo()
        total, avail = info["MemTotal"], info["MemAvailable"]
        app = self._app_rss()
        guest = c.preferred_guest_ram_mib * MiB
        headroom = c.minimum_host_headroom_mib * MiB
        app_budget = c.target_application_ram_mib * MiB
        # Budget against the configured 8 GiB target even on a bigger host
        # (simulates the target machine on a larger development box).
        target_total = c.total_physical_ram_target_mib * MiB
        if target_total and total > target_total:  # 0 disables the cap
            avail = max(0, avail - (total - target_total))

        def fits(n: int, slack: int = 0) -> bool:
            # Reserve a full guest allocation per active agent (the Phase 2 microVM size),
            # and require host headroom after starting the agents not yet running.
            extra = (max(0, n - active_now) + slack) * guest
            return app + (n + slack) * guest <= app_budget and avail - extra >= headroom

        if not c.enforce_limits:
            n, reason = c.default_active_agents, "limits not enforced"
        elif c.maximum_active_agents > c.default_active_agents and \
                fits(c.maximum_active_agents, slack=1):
            # Go above the default only with one more guest allocation of slack.
            n, reason = c.maximum_active_agents, "memory permits maximum"
        else:
            n = c.default_active_agents
            while n > 0 and not fits(n):
                n -= 1
            reason = "default" if n == c.default_active_agents else "memory pressure: reduced"
        self.last = MemorySample(total, avail, app, n, reason)
        return self.last

    def allowed_active(self, active_now: int = 0) -> int:
        return self.sample(active_now).allowed_active
