import asyncio
import tempfile
import time
import unittest

from blockswarm.capabilities import Capability, CapabilityAuthority, CapabilityError
from blockswarm.db import Database
from blockswarm.signing import SigningService
from blockswarm.tools import ToolError, ToolGateway, safe_eval


class CapabilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.revoked = set()
        signer = SigningService(self.tmp.name)
        host = signer.ensure_host_key()
        self.a, _ = signer.create_agent_key()
        self.b, _ = signer.create_agent_key()
        self.auth = CapabilityAuthority(signer, host, self.revoked.__contains__, 60)
        db = Database(":memory:")
        self.addCleanup(db.close)
        self.gw = ToolGateway(self.auth, db)

    def tearDown(self):
        self.tmp.cleanup()

    def test_policy_denies_unpermitted_scope(self):
        with self.assertRaises(CapabilityError):
            self.auth.issue(self.a, ["worker"], {"tool:calculator"})

    def test_check_fails_closed(self):
        cap = self.auth.issue(self.a, ["calculator"], {"inference", "tool:calculator"})
        self.auth.check(cap, self.a, "tool:calculator")
        for args in [(cap, self.b, "inference"),          # bound to another agent
                     (cap, self.a, "tool:shell"),         # scope not granted
                     (None, self.a, "inference")]:        # missing
            with self.assertRaises(CapabilityError):
                self.auth.check(*args)
        with self.assertRaisesRegex(CapabilityError, "expired"):
            self.auth.check(cap, self.a, "inference", now=time.time() + 120)
        tampered = Capability(dict(cap.body, scopes=["inference", "tool:shell"]), cap.signature)
        with self.assertRaisesRegex(CapabilityError, "signature"):
            self.auth.check(tampered, self.a, "tool:shell")
        with self.assertRaises(CapabilityError):
            self.auth.check(Capability({"v": 1}, "00"), self.a, "inference")
        self.auth.revoke(cap.cap_id)
        with self.assertRaisesRegex(CapabilityError, "revoked"):
            self.auth.check(cap, self.a, "inference")

    def test_revoked_agent_denied(self):
        cap = self.auth.issue(self.a, ["worker"], {"inference"})
        self.revoked.add(self.a)
        with self.assertRaises(CapabilityError):
            self.auth.check(cap, self.a, "inference")
        with self.assertRaises(CapabilityError):
            self.auth.issue(self.a, ["worker"], {"inference"})

    def test_tool_gateway_requires_capability(self):
        cap = self.auth.issue(self.a, ["calculator"], {"tool:calculator"})
        res = asyncio.run(self.gw.call(cap, self.a, "calculator", {"expression": "2*(3+4)"}))
        self.assertEqual(res, {"value": 14})
        weak = self.auth.issue(self.b, ["worker"], {"inference"})
        with self.assertRaises(CapabilityError):
            asyncio.run(self.gw.call(weak, self.b, "calculator", {"expression": "1"}))
        with self.assertRaises(CapabilityError):  # A's capability used by B
            asyncio.run(self.gw.call(cap, self.b, "calculator", {"expression": "1"}))
        with self.assertRaises(ToolError):
            asyncio.run(self.gw.call(cap, self.a, "shell", {"cmd": "id"}))

    def test_safe_eval_rejects_code(self):
        self.assertEqual(safe_eval("(40 + 20) * 3 / 4"), 45.0)
        for bad in ["__import__('os').system('id')", "open('/etc/passwd')", "9**9**9",
                    "[1]*10", "a+1", "1/0"]:
            with self.assertRaises((ToolError, SyntaxError)):
                safe_eval(bad)


if __name__ == "__main__":
    unittest.main()
