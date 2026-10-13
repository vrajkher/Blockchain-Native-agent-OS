"""Phase 2: sandboxes, broker, malicious guests."""

import asyncio
import os
import socket
import tempfile
import unittest

from blockswarm import rpc
from blockswarm.broker import BrokerLimits, SandboxBroker, SandboxFailure, SandboxJob
from blockswarm.demo import submit_demo_graph
from blockswarm.envelope import make_task_envelope
from blockswarm.sandbox import InProcessSandbox, ProcessSandbox, SandboxTimeout
from tests.helpers import SwarmTestCase

ROOT = os.geteuid() == 0


class ProcessSandboxTests(SwarmTestCase, unittest.TestCase):
    def setUp(self):
        self.swarm = self.make_swarm(security={"sandbox_backend": "process"})
        self.worker = [a for a in self.swarm.registry.list() if a.roles == ["worker"]][0]

    def tearDown(self):
        self.close_swarm(self.swarm)

    def attack(self, name, timeout=10, limits=None, **payload):
        s, aid = self.swarm, self.worker.agent_id
        cap = s.authority.issue(aid, self.worker.roles, {"inference", "memory"}, "t-attack")
        payload = {"text": f"ATTACK:{name}", **payload}
        env = make_task_envelope(s.signer, "t-attack", "classify_sentiment", payload, aid,
                                 cap.cap_id, 60)
        broker = SandboxBroker(SandboxJob(aid, "t-attack", s.host_pubkey, env, payload), cap,
                               s.gateway, s.inference, s.tools, s.memory.view(aid), limits)
        sandbox = ProcessSandbox(aid, s.cfg.security)
        sandbox.guest_module = "tests.malicious_guest"

        async def go():
            try:
                return await sandbox.run(broker, timeout)
            finally:
                self.last_returncode = sandbox._proc.returncode if sandbox._proc else None
        result = asyncio.run(go())
        return result.output.get("observations", {}), result, broker

    def test_demo_graph_in_separate_processes(self):
        s = self.swarm
        ids = submit_demo_graph(s)
        status = asyncio.run(s.run(timeout=60))
        self.assertEqual(status["tasks"], {"done": len(ids)})
        self.assertEqual(status["sandbox_backend"], "process")
        self.assertGreater(status["gateway"]["allow"], 0)
        self.assertGreater(status["guest_peak_rss_mib"], 5)
        for tid in ids.values():
            self.assertTrue(s.chain.verify_receipt(s.result(tid)["receipt"]))

    def test_guest_gets_no_secrets_and_runs_unprivileged(self):
        os.environ["ANTHROPIC_API_KEY"] = "sk-must-not-leak"
        self.addCleanup(os.environ.pop, "ANTHROPIC_API_KEY", None)
        obs, _, _ = self.attack("env")
        self.assertLessEqual(set(obs["env_keys"]), {"PATH", "LANG", "LC_CTYPE"})
        self.assertNotEqual(obs["pid"], os.getpid())
        if ROOT:
            self.assertEqual(obs["uid"], self.swarm.cfg.security.process_uid)

    @unittest.skipUnless(ROOT, "network namespace isolation needs root")
    def test_guest_has_no_network(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        self.addCleanup(listener.close)
        port = listener.getsockname()[1]
        obs, _, _ = self.attack("network", port=port)
        self.assertNotEqual(obs["1.1.1.1:443"], "connected")
        self.assertNotEqual(obs[f"127.0.0.1:{port}"], "connected")  # host loopback unreachable

    @unittest.skipUnless(ROOT, "uid drop needs root")
    def test_guest_cannot_read_keys_or_write_files(self):
        keystore = next(self.swarm.cfg.keystore_path.glob("*.pem"))
        with tempfile.TemporaryDirectory() as d:
            os.chmod(d, 0o777)
            obs, _, _ = self.attack("filesystem", keystore=str(keystore), writable_dir=d)
            for path in (str(keystore), "/etc/shadow"):
                self.assertEqual(obs["read:" + path], "PermissionError")
            self.assertNotEqual(obs["write:/tmp/bs-escape-test"], "ok")
            self.assertNotEqual(obs[f"write:{d}/bs-escape-test"], "ok")
            if os.path.exists(f"{d}/bs-escape-test"):
                self.assertEqual(os.path.getsize(f"{d}/bs-escape-test"), 0)
        if os.path.exists("/tmp/bs-escape-test") and os.stat("/tmp/bs-escape-test").st_size == 0:
            os.unlink("/tmp/bs-escape-test")

    def test_guest_cannot_escalate(self):
        other = [a for a in self.swarm.registry.list() if a.agent_id != self.worker.agent_id][0]
        self.swarm.memory.view(other.agent_id).put("task:secret", "other agent's private note")
        obs, _, broker = self.attack("privileges", victim_key="task:secret")
        self.assertFalse(obs["tool"]["ok"])
        self.assertIn("denied", obs["tool"]["error"])
        self.assertFalse(obs["unknown_op"]["ok"])
        self.assertIsNone(obs["other_memory"]["value"])  # own namespace only
        self.assertFalse(obs["task_has_capability"])  # capability stays on the host
        self.assertTrue(any("tool:calculator" in d for d in broker.stats.denied))

    def test_forged_evidence_ignored(self):
        _, result, _ = self.attack("forge")
        self.assertEqual(result.tool_calls, [])  # only host-recorded calls count

    def test_flood_oversize_and_hang_are_contained(self):
        with self.assertRaisesRegex(SandboxFailure, "call limit"):
            self.attack("flood", limits=BrokerLimits(max_calls=5))
        with self.assertRaisesRegex(rpc.ProtocolError, "too large"):
            self.attack("oversize")
        with self.assertRaises(SandboxTimeout):
            self.attack("hang", timeout=1)
        self.assertIsNotNone(self.last_returncode)  # the guest process was killed


class InProcessBrokerTests(SwarmTestCase, unittest.TestCase):
    def test_task_message_carries_no_capability_and_bad_output_fails(self):
        s = self.make_swarm()
        try:
            aid = s.registry.list()[1].agent_id
            cap = s.authority.issue(aid, ["worker"], {"inference", "memory"}, "t-1")
            payload = {"text": "fine"}
            env = make_task_envelope(s.signer, "t-1", "classify_sentiment", payload, aid, cap.cap_id, 60)
            broker = SandboxBroker(SandboxJob(aid, "t-1", s.host_pubkey, env, payload), cap,
                                   s.gateway, s.inference, s.tools, s.memory.view(aid))

            async def go():
                a, b = socket.socketpair()
                ra, wa = await asyncio.open_connection(sock=a)
                rb, wb = await asyncio.open_connection(sock=b)
                serve = asyncio.ensure_future(broker.serve(ra, wa))
                first = await rpc.recv(rb)
                await rpc.send(wb, {"t": "result", "output": ["not", "an", "object"]})
                try:
                    await serve
                finally:
                    wa.close()
                    wb.close()
                return first
            with self.assertRaisesRegex(SandboxFailure, "non-object"):
                first = asyncio.run(go())
            result = asyncio.run(InProcessSandbox(aid).run(broker, 10))
            self.assertIn(result.output["label"], ("positive", "negative", "neutral"))
        finally:
            self.close_swarm(s)


if __name__ == "__main__":
    unittest.main()
