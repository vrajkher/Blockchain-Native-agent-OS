import tempfile
import time
import unittest

from blockswarm import crypto
from blockswarm.db import Database
from blockswarm.envelope import (EnvelopeError, accept_task_envelope, check_task_envelope,
                                 make_task_envelope)
from blockswarm.nonces import NonceStore
from blockswarm.signing import HOST_KEY, SigningError, SigningService


class CryptoTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.revoked = set()
        self.signer = SigningService(self.tmp.name + "/keys", is_revoked=self.revoked.__contains__)
        self.host = self.signer.ensure_host_key()
        self.agent, self.agent_pub = self.signer.create_agent_key()

    def tearDown(self):
        self.tmp.cleanup()

    def test_sign_verify_and_domain_separation(self):
        sig = self.signer.sign_as_agent(self.agent, "task-result", {"a": 1})
        self.assertTrue(crypto.verify(self.agent_pub, sig, "task-result", {"a": 1}))
        self.assertFalse(crypto.verify(self.agent_pub, sig, "task-result", {"a": 2}))
        self.assertFalse(crypto.verify(self.agent_pub, sig, "capability", {"a": 1}))
        self.assertFalse(crypto.verify(self.host, sig, "task-result", {"a": 1}))
        self.assertFalse(crypto.verify("zz", "zz", "task-result", {}))

    def test_agent_id_derived_from_pubkey(self):
        self.assertEqual(self.agent, crypto.agent_id_from_pubkey(bytes.fromhex(self.agent_pub)))

    def test_key_files_private_and_revoked_agent_cannot_sign(self):
        import os, stat
        path = f"{self.tmp.name}/keys/{self.agent}.pem"
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.revoked.add(self.agent)
        with self.assertRaises(SigningError):
            self.signer.sign_as_agent(self.agent, "task-result", {})
        with self.assertRaises(SigningError):
            self.signer.sign_as_agent(HOST_KEY, "task-result", {})

    def test_insecure_key_permissions_refused(self):
        import os
        path = f"{self.tmp.name}/keys/{self.agent}.pem"
        os.chmod(path, 0o644)
        fresh = SigningService(self.tmp.name + "/keys")
        with self.assertRaises(SigningError):
            fresh.sign_as_agent(self.agent, "x", {})


class EnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.signer = SigningService(self.tmp.name + "/keys")
        self.host = self.signer.ensure_host_key()
        self.agent, _ = self.signer.create_agent_key()
        self.other, _ = self.signer.create_agent_key()
        self.db = Database(":memory:")
        self.addCleanup(self.db.close)
        self.nonces = NonceStore(self.db)
        self.payload = {"text": "hello"}
        self.env = make_task_envelope(self.signer, "t1", "summarize", self.payload, self.agent, "c", 60)

    def tearDown(self):
        self.tmp.cleanup()

    def test_valid_once_then_replay_rejected(self):
        accept_task_envelope(self.env, self.payload, self.host, self.agent, self.nonces)
        with self.assertRaisesRegex(EnvelopeError, "replayed"):
            accept_task_envelope(self.env, self.payload, self.host, self.agent, self.nonces)

    def test_wrong_agent_tampered_payload_expired_forged(self):
        with self.assertRaisesRegex(EnvelopeError, "different agent"):
            check_task_envelope(self.env, self.payload, self.host, self.other)
        with self.assertRaisesRegex(EnvelopeError, "payload"):
            check_task_envelope(self.env, {"text": "evil"}, self.host, self.agent)
        with self.assertRaisesRegex(EnvelopeError, "expired"):
            check_task_envelope(self.env, self.payload, self.host, self.agent, now=time.time() + 3600)
        forged = {"body": dict(self.env["body"], assignee=self.other), "signature": self.env["signature"]}
        with self.assertRaisesRegex(EnvelopeError, "signature"):
            check_task_envelope(forged, self.payload, self.host, self.other)
        with self.assertRaises(EnvelopeError):
            check_task_envelope({"junk": 1}, self.payload, self.host, self.agent)


if __name__ == "__main__":
    unittest.main()
