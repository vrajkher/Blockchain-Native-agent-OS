import asyncio
import json
import unittest

from blockswarm import crypto
from blockswarm.config import load_config
from blockswarm.demo import submit_demo_graph
from blockswarm.envelope import RESULT_DOMAIN
from blockswarm.sandbox import SecurityPolicyError
from blockswarm.swarm import Swarm
from tests.helpers import SwarmTestCase


class TwoAgentPrototypeTests(SwarmTestCase, unittest.TestCase):
    def setUp(self):
        self.swarm = self.make_swarm()

    def tearDown(self):
        self.close_swarm(self.swarm)

    def test_demo_graph_completes_verified_and_committed(self):
        s = self.swarm
        ids = submit_demo_graph(s)
        status = asyncio.run(s.run(timeout=30))
        self.assertEqual(status["tasks"], {"done": len(ids)})
        self.assertLessEqual(status["max_active_seen"], 2)
        self.assertEqual(status["max_active_seen"], 2)  # independent tasks ran in parallel
        self.assertEqual(status["inference"]["max_concurrent"], 1)
        self.assertTrue(status["inference"]["mock"])
        used = set()
        for tid in ids.values():
            res = s.result(tid)
            used.add(res["agent_id"])
            self.assertTrue(res["verification"]["ok"])
            self.assertTrue(res["verification"]["mock_inference"] or tid == ids["arithmetic"])
            agent = s.registry.get(res["agent_id"])
            self.assertTrue(crypto.verify(agent.pubkey, res["signature"], RESULT_DOMAIN, res["record"]))
            self.assertEqual(res["record"]["output_commitment"], crypto.commitment(res["output"]))
            self.assertTrue(s.chain.verify_receipt(res["receipt"]))
        self.assertEqual(len(used), 2)
        self.assertTrue(s.result(ids["arithmetic"])["verification"]["proves_correctness"])
        commits = s.chain.ledger.entries("commit_result")
        self.assertEqual({e["task_id"] for e in commits}, set(ids.values()))
        self.assertEqual(len(s.chain.ledger.entries("attestation")), len(ids))
        self.assertTrue(s.chain.ledger.verify_chain())
        # Each agent's private memory holds only its own tasks.
        for aid in used:
            mine = {k.split(":", 1)[1] for k in s.memory.view(aid).keys()}
            self.assertEqual(mine, {t for t in ids.values() if s.result(t)["agent_id"] == aid})

    def test_agent_failure_is_survived_by_reassignment(self):
        s = self.swarm
        bad = s.registry.list()[1].agent_id

        def crash(agent_id, task):
            if agent_id == bad:
                raise RuntimeError("simulated agent crash")
        s.fault_injector = crash
        ids = [s.submit("summarize", {"text": f"Document {i}. It is fine."}) for i in range(4)]
        asyncio.run(s.run(timeout=30))
        for tid in ids:
            self.assertEqual(s.queue.get(tid).status, "done")
            self.assertNotEqual(s.result(tid)["agent_id"], bad)
        self.assertEqual(s.registry.get(bad).status, "quarantined")

    def test_model_service_outage_does_not_blame_agents(self):
        from blockswarm.inference import ServiceUnavailable
        s = self.swarm
        real = s.backend.complete
        calls = {"n": 0}

        def flaky(*args):
            calls["n"] += 1
            if calls["n"] <= 2:
                raise ServiceUnavailable("Anthropic API error 529")
            return real(*args)
        s.backend.complete = flaky
        tid = s.submit("classify_sentiment", {"text": "great"}, max_attempts=3)
        asyncio.run(s.run(timeout=10))
        self.assertEqual(s.queue.get(tid).status, "done")
        self.assertEqual(s.queue.get(tid).excluded, [])
        for a in s.registry.list():
            self.assertEqual((a.status, a.failures), ("idle", 0))

    def test_tampered_output_is_rejected_by_verifier(self):
        s = self.swarm
        original = s.signer.sign_as_agent

        def sign_then_tamper(agent_id, domain, payload):
            sig = original(agent_id, domain, payload)
            payload["output_commitment"] = "0x" + "00" * 32  # mutate after signing
            return sig
        s.signer.sign_as_agent = sign_then_tamper
        tid = s.submit("classify_sentiment", {"text": "great"}, max_attempts=1)
        asyncio.run(s.run(timeout=10))
        task = s.queue.get(tid)
        self.assertEqual(task.status, "failed")
        self.assertIn("VerificationFailed", task.error)
        self.assertIsNone(s.result(tid))
        self.assertEqual(s.chain.ledger.entries("commit_result"), [])

    def test_wrong_arithmetic_rejected_deterministically(self):
        s = self.swarm
        s.tools.tools["calculator"].fn = lambda args: {"value": 42}  # compromised tool
        tid = s.submit("arithmetic", {"expression": "2+2"}, max_attempts=1)
        asyncio.run(s.run(timeout=10))
        self.assertEqual(s.queue.get(tid).status, "failed")
        self.assertIn("answer 42 != 4", s.queue.get(tid).error)

    def test_revocation_terminates_and_blocks_agent(self):
        s = self.swarm
        victim = s.registry.list()[0].agent_id
        s.backend.delay = 0.3

        async def go():
            tids = [s.submit("summarize", {"text": f"Doc {i}."}) for i in range(4)]
            runner = asyncio.ensure_future(s.run(timeout=30))
            while victim not in s.running:
                await asyncio.sleep(0.01)
            receipt = s.revoke_agent(victim, "compromised")
            await runner
            return tids, receipt
        tids, receipt = asyncio.run(go())
        self.assertTrue(s.chain.verify_receipt(receipt))
        self.assertTrue(s.chain.resolve_agent(victim)["revoked"])
        for tid in tids:
            self.assertEqual(s.queue.get(tid).status, "done")
        late = [t for t in tids if s.result(t)["agent_id"] == victim]
        self.assertLessEqual(len(late), 1)  # only work finished before revocation
        with self.assertRaises(Exception):
            s.signer.sign_as_agent(victim, RESULT_DOMAIN, {})

    def test_crash_recovery_requeues_leased_work(self):
        s = self.swarm
        tid = s.submit("summarize", {"text": "Recover me."})
        agent = s.registry.list()[0].agent_id
        s.queue.claim(tid, agent, 600)
        s.registry.set_status(agent, "active")
        s._recover_after_crash()  # what a restarted process does
        self.assertEqual(s.queue.get(tid).status, "pending")
        asyncio.run(s.run(timeout=10))
        self.assertEqual(s.queue.get(tid).status, "done")


class ScaleTests(SwarmTestCase, unittest.TestCase):
    agents = 100

    def test_100_logical_identities_queue_within_active_limit(self):
        s = self.make_swarm()
        try:
            self.assertEqual(s.registry.count(), 100)
            self.assertEqual(len({a.pubkey for a in s.registry.list()}), 100)
            ids = [s.submit("classify_sentiment", {"text": f"item {i} is great"}) for i in range(30)]
            status = asyncio.run(s.run(timeout=60))
            self.assertEqual(status["tasks"], {"done": 30})
            self.assertLessEqual(status["max_active_seen"], s.cfg.governor.maximum_active_agents)
            self.assertGreater(len({s.result(t)["agent_id"] for t in ids}), 10)
        finally:
            self.close_swarm(s)


class SecurityModeTests(unittest.TestCase):
    def test_secure_mode_refuses_inprocess_sandbox(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            cfg = load_config(home=tmp, security={"mode": "secure"}, inference={"backend": "mock"})
            with self.assertRaises(SecurityPolicyError):
                Swarm(cfg)

    def test_secure_mode_without_kvm_refuses_to_dispatch(self):
        import tempfile
        from blockswarm.sandbox import SandboxUnavailable
        with tempfile.TemporaryDirectory() as tmp:
            cfg = load_config(home=tmp, inference={"backend": "mock"},
                              security={"mode": "secure", "sandbox_backend": "firecracker"},
                              firecracker={"kernel_image": "/nonexistent/vmlinux"})
            s = Swarm(cfg)
            s.create_agents(1)
            tid = s.submit("classify_sentiment", {"text": "x"}, max_attempts=1)
            with self.assertRaisesRegex(SandboxUnavailable, "kernel"):
                asyncio.run(s.run(timeout=10))
            # Nothing was dispatched: the task is untouched and can run once KVM exists.
            self.assertEqual((s.queue.get(tid).status, s.queue.get(tid).attempts), ("pending", 0))
            asyncio.run(s.shutdown())


class ApiTests(SwarmTestCase, unittest.TestCase):
    def test_auth_and_endpoints(self):
        from blockswarm.api import ApiServer
        s = self.make_swarm()

        async def req(port, method, path, body=None, token=None):
            r, w = await asyncio.open_connection("127.0.0.1", port)
            data = json.dumps(body).encode() if body is not None else b""
            hdr = f"{method} {path} HTTP/1.1\r\nHost: x\r\nContent-Length: {len(data)}\r\n"
            if token:
                hdr += f"Authorization: Bearer {token}\r\n"
            w.write(hdr.encode() + b"\r\n" + data)
            await w.drain()
            raw = await r.read()
            w.close()
            head, _, payload = raw.partition(b"\r\n\r\n")
            return int(head.split()[1]), json.loads(payload)

        async def go():
            server = await ApiServer(s, "s3cret").start("127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            out = {
                "health": await req(port, "GET", "/health"),
                "noauth": await req(port, "GET", "/v1/status"),
                "badauth": await req(port, "GET", "/v1/status", token="wrong"),
                "submit": await req(port, "POST", "/v1/tasks",
                                    {"kind": "classify_sentiment", "input": {"text": "good"}}, "s3cret"),
                "badkind": await req(port, "POST", "/v1/tasks", {"kind": "rm", "input": {}}, "s3cret"),
                "infer_nocap": await req(port, "POST", "/v1/inference",
                                         {"agent_id": "x", "capability": {"body": {}, "signature": ""},
                                          "messages": []}),
            }
            aid = s.registry.list()[0].agent_id
            cap = s.authority.issue(aid, ["worker"], {"inference"})
            out["infer_ok"] = await req(port, "POST", "/v1/inference", {
                "agent_id": aid, "capability": cap.to_dict(),
                "messages": [{"role": "system", "content": "TASK_KIND: classify_sentiment"},
                             {"role": "user", "content": '{"text": "great"}'}]})
            other = s.registry.list()[1].agent_id
            out["infer_stolen"] = await req(port, "POST", "/v1/inference", {
                "agent_id": other, "capability": cap.to_dict(), "messages": [
                    {"role": "user", "content": "x"}]})
            server.close()
            await server.wait_closed()
            return out
        try:
            out = asyncio.run(go())
            self.assertEqual(out["health"][0], 200)
            self.assertEqual(out["noauth"][0], 401)
            self.assertEqual(out["badauth"][0], 401)
            self.assertEqual(out["submit"][0], 201)
            self.assertEqual(out["badkind"][0], 400)
            self.assertEqual(out["infer_nocap"][0], 403)
            self.assertEqual(out["infer_ok"][0], 200)
            self.assertTrue(out["infer_ok"][1]["mock"])
            self.assertEqual(out["infer_stolen"][0], 403)
        finally:
            self.close_swarm(s)


if __name__ == "__main__":
    unittest.main()
