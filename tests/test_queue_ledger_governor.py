import time
import unittest

from blockswarm.config import GovernorConfig
from blockswarm.db import Database
from blockswarm.governor import ResourceGovernor
from blockswarm.ledger import BlockchainRuntime, SimulatedLedger, merkle_proof, merkle_root, verify_proof
from blockswarm.queue import QueueError, TaskQueue
from tests.helpers import MiB, fake_meminfo


class QueueTests(unittest.TestCase):
    def setUp(self):
        db = Database(":memory:")
        self.addCleanup(db.close)
        self.q = TaskQueue(db)

    def test_dependencies_gate_readiness(self):
        a = self.q.submit("summarize", {"text": "a"})
        b = self.q.submit("summarize", {"text": "b"})
        c = self.q.submit("report", {"title": "r"}, deps=[a, b])
        self.assertEqual({t.task_id for t in self.q.ready()}, {a, b})
        for t in (a, b):
            self.assertTrue(self.q.claim(t, "ag", 60))
            self.assertTrue(self.q.complete(t, "ag", "0x1"))
        self.assertEqual([t.task_id for t in self.q.ready()], [c])
        with self.assertRaises(QueueError):
            self.q.submit("report", {}, deps=["missing"])

    def test_claim_is_exclusive_and_complete_needs_lease(self):
        t = self.q.submit("summarize", {"text": "a"})
        self.assertTrue(self.q.claim(t, "ag1", 60))
        self.assertFalse(self.q.claim(t, "ag2", 60))
        self.assertFalse(self.q.complete(t, "ag2", "0x"))
        self.assertTrue(self.q.complete(t, "ag1", "0x"))

    def test_retry_excludes_failed_agent_and_gives_up(self):
        t = self.q.submit("summarize", {"text": "a"}, max_attempts=2)
        self.q.claim(t, "ag1", 60)
        self.assertEqual(self.q.fail(t, "ag1", "boom"), "pending")
        self.assertEqual(self.q.get(t).excluded, ["ag1"])
        self.q.claim(t, "ag2", 60)
        self.assertEqual(self.q.fail(t, "ag2", "boom"), "failed")

    def test_dependency_failure_propagates(self):
        a = self.q.submit("summarize", {"text": "a"}, max_attempts=1)
        c = self.q.submit("report", {"title": "r"}, deps=[a])
        self.q.claim(a, "ag", 60)
        self.q.fail(a, "ag", "boom")
        self.q.ready()
        self.assertEqual(self.q.get(c).status, "failed")

    def test_expired_lease_recovery(self):
        t = self.q.submit("summarize", {"text": "a"})
        self.q.claim(t, "ag1", 0.01)
        self.assertEqual(self.q.recover_expired(time.time() + 1), [(t, "pending")])

    def test_irreversible_never_executes_twice(self):
        t = self.q.submit("arithmetic", {"expression": "1"}, irreversible=True)
        self.q.claim(t, "ag1", 0.01)
        self.assertTrue(self.q.begin_execution(t, "ag1"))
        # Worker dies mid-execution; the lease expires.
        self.assertEqual(self.q.recover_expired(time.time() + 1), [(t, "needs_review")])
        self.assertEqual(self.q.ready(), [])
        self.assertFalse(self.q.begin_execution(t, "ag2"))
        self.q.requeue_review(t)  # explicit operator decision
        self.assertEqual(self.q.get(t).status, "pending")

    def test_irreversible_failure_before_execution_is_retryable(self):
        t = self.q.submit("arithmetic", {"expression": "1"}, irreversible=True)
        self.q.claim(t, "ag1", 60)
        self.assertEqual(self.q.fail(t, "ag1", "capability error"), "pending")


class LedgerTests(unittest.TestCase):
    def setUp(self):
        db = Database(":memory:")
        self.addCleanup(db.close)
        self.ledger = SimulatedLedger(db, batch_size=4)
        self.chain = BlockchainRuntime(self.ledger, "00")

    def test_merkle(self):
        leaves = ["0x" + f"{i:064x}" for i in range(7)]
        root = merkle_root(leaves)
        for i, leaf in enumerate(leaves):
            self.assertTrue(verify_proof(leaf, merkle_proof(leaves, i), root))
        self.assertFalse(verify_proof(leaves[0], merkle_proof(leaves, 1), root))

    def test_runtime_functions_and_receipts(self):
        r = self.chain.register_agent("bsa1x", "ab" * 32, ["worker"])
        self.assertTrue(self.chain.verify_receipt(r))
        self.assertEqual(r["finality"], "simulated-local")
        self.assertEqual(self.chain.resolve_agent("bsa1x")["revoked"], False)
        hashes = [self.chain.register_task(f"t{i}", "summarize", "0x00") for i in range(3)]
        self.assertIsNone(self.chain.receipt(hashes[0]))  # still batched
        e = self.chain.commit_result_hash("t0", "bsa1x", "0x01", "0x02", "sig")  # 4th => auto flush
        for h in hashes + [e]:
            self.assertTrue(self.chain.verify_receipt(self.chain.receipt(h)))
        self.chain.revoke_agent("bsa1x", "test")
        self.assertTrue(self.chain.resolve_agent("bsa1x")["revoked"])
        self.assertTrue(self.ledger.verify_chain())

    def test_tampering_detected(self):
        h = self.chain.register_task("t", "summarize", "0x00")
        self.chain.flush()
        rec = self.chain.receipt(h)
        bad = dict(rec, entry_hash="0x" + "11" * 32)
        self.assertFalse(self.chain.verify_receipt(bad))
        self.ledger.db.execute("UPDATE ledger_blocks SET entries=replace(entries, '\"t\"', '\"u\"')")
        self.assertFalse(self.chain.verify_receipt(rec))
        self.assertFalse(self.ledger.verify_chain())


class GovernorTests(unittest.TestCase):
    def gov(self, avail_mib, app_mib=400, **cfg):
        return ResourceGovernor(GovernorConfig(**cfg), meminfo=fake_meminfo(8192, avail_mib),
                                app_rss=lambda: app_mib * MiB)

    def test_default_two(self):
        self.assertEqual(self.gov(1800).allowed_active(), 2)

    def test_three_only_with_measured_room(self):
        self.assertEqual(self.gov(6000).allowed_active(), 3)
        self.assertEqual(self.gov(6000, app_mib=4500).allowed_active(), 2)

    def test_pressure_reduces_to_one_then_zero(self):
        self.assertEqual(self.gov(1400).allowed_active(), 1)
        self.assertEqual(self.gov(900).allowed_active(), 0)

    def test_budget_capped_at_8gb_target_on_bigger_host(self):
        g = ResourceGovernor(GovernorConfig(), meminfo=fake_meminfo(16384, 9000),
                             app_rss=lambda: 400 * MiB)
        s = g.sample()
        self.assertEqual(s.available, (9000 - 8192) * MiB)
        self.assertEqual(s.allowed_active, 0)


if __name__ == "__main__":
    unittest.main()
