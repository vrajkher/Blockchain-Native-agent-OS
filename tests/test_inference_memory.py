import asyncio
import tempfile
import unittest

from blockswarm.capabilities import CapabilityAuthority, CapabilityError
from blockswarm.config import InferenceConfig, load_config
from blockswarm.db import Database
from blockswarm.inference import InferenceService, MockBackend, QuotaError, decoding_schema
from blockswarm.memory import AgentMemoryView, MemoryLimitError, MemoryStore
from blockswarm.signing import SigningService
from blockswarm.tasks import KINDS


def msgs(text, kind="classify_sentiment"):
    return [{"role": "system", "content": f"TASK_KIND: {kind}"},
            {"role": "user", "content": 'Input:\n{"text": "%s"}' % text}]


class InferenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        signer = SigningService(self.tmp.name)
        host = signer.ensure_host_key()
        self.a, _ = signer.create_agent_key()
        self.b, _ = signer.create_agent_key()
        self.auth = CapabilityAuthority(signer, host, lambda _a: False, 60)
        self.backend = MockBackend(delay=0.05)
        self.cfg = InferenceConfig(backend="mock", max_context_tokens_per_agent=200, max_output_tokens_per_request=64,
                                   token_budget_per_agent_window=400)
        self.svc = InferenceService(self.backend, self.auth, self.cfg, concurrency=1)
        self.cap_a = self.auth.issue(self.a, ["worker"], {"inference"})
        self.cap_b = self.auth.issue(self.b, ["worker"], {"inference"})

    def tearDown(self):
        self.tmp.cleanup()

    def test_requires_capability(self):
        with self.assertRaises(CapabilityError):
            asyncio.run(self.svc.infer(self.cap_a, self.b, msgs("x")))
        with self.assertRaises(CapabilityError):
            asyncio.run(self.svc.infer(None, self.a, msgs("x")))

    def test_single_model_concurrency_and_no_context_leak(self):
        async def go():
            return await asyncio.gather(
                *[self.svc.infer(self.cap_a, self.a, msgs("SECRET-A great")) for _ in range(2)],
                *[self.svc.infer(self.cap_b, self.b, msgs("plain B text")) for _ in range(2)])
        asyncio.run(go())
        self.assertEqual(self.svc.max_in_flight, 1)
        for req in self.backend.requests:
            joined = " ".join(m["content"] for m in req)
            self.assertFalse("SECRET-A" in joined and "plain B" in joined)
        b_reqs = [r for r in self.backend.requests if "plain B" in r[-1]["content"]]
        self.assertTrue(b_reqs and all("SECRET-A" not in m["content"] for r in b_reqs for m in r))

    def test_context_and_budget_limits(self):
        with self.assertRaisesRegex(QuotaError, "context"):
            asyncio.run(self.svc.infer(self.cap_a, self.a, msgs("x" * 2000)))
        with self.assertRaisesRegex(QuotaError, "budget"):
            for _ in range(20):
                asyncio.run(self.svc.infer(self.cap_a, self.a, msgs("y" * 300)))
        # B's budget is independent of A's.
        asyncio.run(self.svc.infer(self.cap_b, self.b, msgs("fine")))

    def test_malformed_messages_rejected(self):
        from blockswarm.inference import InferenceError
        for bad in [[], [{"role": "root", "content": "x"}], "text", [{"role": "user"}]]:
            with self.assertRaises(InferenceError):
                asyncio.run(self.svc.infer(self.cap_a, self.a, bad))

    def test_decoding_schema_drops_bounds_only(self):
        g = decoding_schema(KINDS["summarize"].output_schema)
        self.assertNotIn("maxLength", g["properties"]["summary"])
        self.assertNotIn("maxItems", g["properties"]["key_points"])
        self.assertEqual(g["required"], ["summary", "key_points"])
        self.assertIs(g["additionalProperties"], False)
        self.assertEqual(g["properties"]["key_points"]["items"], {"type": "string"})


class MemoryTests(unittest.TestCase):
    def setUp(self):
        db = Database(":memory:")
        self.addCleanup(db.close)
        self.store = MemoryStore(db, max_entries=3, max_value_bytes=4096)

    def test_views_are_isolated(self):
        a, b = self.store.view("agent-a"), self.store.view("agent-b")
        a.put("secret", "A's private data")
        self.assertIsNone(b.get("secret"))
        self.assertEqual(b.keys(), [])
        self.assertEqual(a.get("secret"), "A's private data")
        # The bound identity cannot be swapped through the public API.
        with self.assertRaises(AttributeError):
            b.agent_id = "agent-a"
        self.assertFalse(any("agent" in n.lower() and not n.startswith("_") for n in dir(b)
                             if n not in ("__class__",)))
        self.assertIsInstance(b, AgentMemoryView)

    def test_quota_compression_and_limits(self):
        a = self.store.view("agent-a")
        big = "word " * 300
        a.put("big", big)
        self.assertEqual(a.get("big"), big)
        for i in range(5):
            a.put(f"k{i}", "v")
        self.assertEqual(len(a.keys()), 3)
        with self.assertRaises(MemoryLimitError):
            a.put("huge", "x" * 5000)


if __name__ == "__main__":
    unittest.main()
