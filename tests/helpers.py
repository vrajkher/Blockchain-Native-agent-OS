import asyncio
import tempfile

from blockswarm.config import load_config
from blockswarm.governor import ResourceGovernor
from blockswarm.inference import MockBackend
from blockswarm.swarm import Swarm

MiB = 1024 * 1024


def fake_meminfo(total_mib=8192, avail_mib=6000):
    return lambda: {"MemTotal": total_mib * MiB, "MemAvailable": avail_mib * MiB}


class SwarmTestCase:
    """Mixin creating a fresh swarm (mock backend) in a temp directory."""

    agents = 2
    calculator_agents = 1

    def make_swarm(self, **overrides):
        self._tmp = tempfile.TemporaryDirectory()
        overrides.setdefault("inference", {"backend": "mock"})
        cfg = load_config(home=self._tmp.name, **overrides)
        gov = ResourceGovernor(cfg.governor, meminfo=fake_meminfo(), app_rss=lambda: 200 * MiB)
        swarm = Swarm(cfg, backend=MockBackend(delay=0.02), governor=gov)
        swarm.poll_interval = 0.01
        if self.calculator_agents:
            swarm.create_agents(self.calculator_agents, ["worker", "calculator"])
        if self.agents - self.calculator_agents > 0:
            swarm.create_agents(self.agents - self.calculator_agents, ["worker"])
        return swarm

    def close_swarm(self, swarm):
        asyncio.run(swarm.shutdown())
        self._tmp.cleanup()
