"""Phase 2: external authorization gateway and Firecracker sandbox."""

import asyncio
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from blockswarm import firecracker
from blockswarm.config import FirecrackerConfig, load_config
from blockswarm.gateway import DEFAULT_POLICY, AuthorizationGateway, Policy, RemoteGateway
from blockswarm.sandbox import SandboxFactory, SandboxUnavailable, SecurityPolicyError
from tests.helpers import SwarmTestCase

REPO = str(Path(__file__).resolve().parent.parent)


class GatewayTests(SwarmTestCase, unittest.TestCase):
    def setUp(self):
        self.s = self.make_swarm()
        self.agent = self.s.registry.list()[1]  # worker only

    def tearDown(self):
        self.close_swarm(self.s)

    def gw(self, policy: dict):
        def info(aid):
            r = self.s.registry.get(aid)
            return (r.status, r.roles) if r else None
        return AuthorizationGateway(Policy.from_dict(policy), self.s.authority, info)

    def cap(self, scopes=("inference", "memory")):
        return self.s.authority.issue(self.agent.agent_id, self.agent.roles, set(scopes)).to_dict()

    def decide(self, gw, action, cap=None, arg_bytes=10, agent=None):
        return asyncio.run(gw.authorize(agent or self.agent.agent_id,
                                        self.cap() if cap is None else cap, action, arg_bytes))

    def test_deny_by_default_and_limits(self):
        gw = self.gw({"roles": {"worker": {"inference": {"max_per_minute": 2, "max_arg_bytes": 100}}}})
        self.assertTrue(self.decide(gw, "inference").allowed)
        d = self.decide(gw, "memory.write")  # capability allows it; policy does not
        self.assertEqual((d.allowed, d.reason), (False, "not permitted by policy"))
        self.assertIn("exceed", self.decide(gw, "inference", arg_bytes=101).reason)
        self.assertTrue(self.decide(gw, "inference").allowed)
        self.assertEqual(self.decide(gw, "inference").reason, "rate limit")

    def test_capability_and_agent_status_checked(self):
        gw = self.gw(DEFAULT_POLICY)
        self.assertIn("capability", self.decide(gw, "tool:calculator").reason)
        self.assertIn("capability", self.decide(gw, "inference", cap={"body": {}, "signature": ""}).reason)
        self.assertEqual(self.decide(gw, "inference", agent="bsa1nobody").reason, "unknown agent")
        cap = self.cap()  # valid capability issued before revocation
        self.s.revoke_agent(self.agent.agent_id)
        self.assertEqual(self.decide(gw, "inference", cap=cap).reason, "agent revoked")

    def test_errors_fail_closed(self):
        gw = self.gw({"roles": {}})
        gw._agent_info = mock.Mock(side_effect=RuntimeError("db down"))
        d = self.decide(gw, "inference")
        self.assertFalse(d.allowed)
        self.assertIn("gateway error", d.reason)

    def test_policy_digest_is_anchored_on_ledger(self):
        self.s.chain.flush()
        entries = self.s.chain.ledger.entries("policy")
        self.assertEqual(entries[-1]["policy_digest"], self.s.gateway.policy.digest)

    def test_out_of_process_gateway(self):
        sock = os.path.join(self._tmp.name, "gw.sock")
        proc = subprocess.Popen([sys.executable, "-m", "blockswarm", "--home", self._tmp.name,
                                 "gateway", "--socket", sock,
                                 "--audit", os.path.join(self._tmp.name, "gw-audit.jsonl")],
                                cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            for _ in range(100):
                if os.path.exists(sock):
                    break
                time.sleep(0.05)
            self.assertEqual(os.stat(sock).st_mode & 0o777, 0o600)
            remote = RemoteGateway(sock)

            async def ask(action, cap):
                return await remote.authorize(self.agent.agent_id, cap, action, 10)
            ok = asyncio.run(ask("inference", self.cap()))
            denied = asyncio.run(ask("tool:calculator", self.cap()))
            self.assertTrue(ok.allowed)
            self.assertFalse(denied.allowed)
            audit = [json.loads(l) for l in open(os.path.join(self._tmp.name, "gw-audit.jsonl"))]
            self.assertEqual([a["event"] for a in audit], ["gateway_allow", "gateway_deny"])
            # The swarm itself can use the external gateway end to end.
            self.s.gateway = remote
            tid = self.s.submit("classify_sentiment", {"text": "great"})
            asyncio.run(self.s.run(timeout=20))
            self.assertEqual(self.s.queue.get(tid).status, "done")
        finally:
            proc.terminate()
            proc.wait(5)
            proc.stdout.close()
            proc.stderr.close()
        down = asyncio.run(RemoteGateway(sock, timeout=1).authorize(
            self.agent.agent_id, self.cap(), "inference", 10))
        self.assertFalse(down.allowed)  # unreachable gateway denies
        self.assertIn("unreachable", down.reason)


class FirecrackerTests(unittest.TestCase):
    def cfg(self, **kw):
        return FirecrackerConfig(**kw)

    def test_vm_config_denies_network_and_writes(self):
        vm = firecracker.vm_config(self.cfg())
        self.assertEqual(vm["network-interfaces"], [])
        self.assertTrue(vm["drives"][0]["is_read_only"])
        self.assertEqual(len(vm["drives"]), 1)
        self.assertEqual(vm["machine-config"]["mem_size_mib"], 256)
        self.assertEqual(vm["vsock"]["uds_path"], "/v.sock")
        self.assertIn("bs_port=5000", vm["boot-source"]["boot_args"])

    def test_jailer_argv(self):
        argv = firecracker.jailer_argv(self.cfg(), "bsabc")
        joined = " ".join(argv)
        for part in ("--uid 65534", "--gid 65534", "--cgroup memory.max=335544320",
                     "--cgroup cpu.max=100000 100000", "--cgroup pids.max=64",
                     "-- --config-file /vm.json --no-api"):
            self.assertIn(part, joined)
        v1 = " ".join(firecracker.jailer_argv(self.cfg(cgroup_version=1), "bsabc"))
        self.assertIn("memory.limit_in_bytes=335544320", v1)
        self.assertIn("cpu.cfs_quota_us=100000", v1)

    def test_preflight_fails_closed(self):
        with self.assertRaises(SandboxUnavailable) as ctx:
            firecracker.preflight(self.cfg(kernel_image="/nope/vmlinux"))
        self.assertIn("kernel", str(ctx.exception))
        if not os.path.exists("/dev/kvm"):
            self.assertIn("/dev/kvm", str(ctx.exception))
        with self.assertRaises(SandboxUnavailable):
            firecracker.preflight(None)

    def test_secure_mode_policy(self):
        for backend in ("inprocess", "process"):
            with self.assertRaises(SecurityPolicyError):
                SandboxFactory(load_config(security={"mode": "secure", "sandbox_backend": backend}))
        SandboxFactory(load_config(security={"mode": "secure", "sandbox_backend": "firecracker"}))

    @unittest.skipUnless(os.geteuid() == 0, "needs root")
    def test_prepare_jail_layout(self):
        with tempfile.TemporaryDirectory() as d:
            for name in ("k", "r"):
                Path(d, name).write_bytes(b"x")
            cfg = self.cfg(chroot_base=f"{d}/jail", kernel_image=f"{d}/k", rootfs_image=f"{d}/r",
                           firecracker_bin="/x/firecracker")
            root = firecracker.prepare_jail(cfg, "bsjail")
            self.assertEqual(root, Path(d, "jail", "firecracker", "bsjail", "root"))
            self.assertEqual(sorted(p.name for p in root.iterdir()), ["rootfs.ext4", "vm.json", "vmlinux"])
            for p in root.iterdir():
                self.assertEqual(p.stat().st_uid, 65534)
            self.assertEqual(oct(Path(root, "rootfs.ext4").stat().st_mode & 0o777), "0o400")

    @unittest.skipUnless(os.environ.get("BLOCKSWARM_FC_DIR"), "set BLOCKSWARM_FC_DIR to a dir "
                         "with firecracker, jailer, vmlinux and rootfs.ext4")
    def test_real_jailer_and_firecracker(self):
        """Runs the real jailer + firecracker. Without KVM the VMM must exit cleanly with a KVM
        error (proving the jail, cgroups, config and images were all accepted)."""
        from blockswarm.broker import SandboxBroker, SandboxJob
        d = os.environ["BLOCKSWARM_FC_DIR"]
        with tempfile.TemporaryDirectory() as jail:
            cfg = self.cfg(firecracker_bin=f"{d}/firecracker", jailer_bin=f"{d}/jailer",
                           kernel_image=f"{d}/vmlinux", rootfs_image=f"{d}/rootfs.ext4",
                           chroot_base=jail, boot_timeout_seconds=20,
                           cgroup_version=2 if os.path.exists("/sys/fs/cgroup/cgroup.controllers") else 1)
            broker = mock.Mock(spec=SandboxBroker)
            if os.path.exists("/dev/kvm"):
                self.skipTest("KVM present: covered by the full microVM run")
            with mock.patch.object(firecracker, "preflight"):
                sb = firecracker.FirecrackerSandbox("bsa1test", cfg)
            with self.assertRaises(SandboxUnavailable) as ctx:
                asyncio.run(sb.run(broker, 10))
            self.assertIn("KVM", str(ctx.exception))
            self.assertFalse(Path(jail, "firecracker", sb.jail_id).exists())  # cleaned up


@unittest.skipUnless(os.environ.get("BLOCKSWARM_GUEST_ROOT") and os.geteuid() == 0,
                     "set BLOCKSWARM_GUEST_ROOT to a mounted guest-rootfs.ext4 (needs root)")
class GuestImageTests(SwarmTestCase, unittest.TestCase):
    """Runs the demo graph with every agent executing inside the *guest image's* userland
    (its python3.12, its cryptography wheel, /opt/blockswarm) via chroot. This exercises
    everything in the microVM except the kernel/KVM boot and the vsock transport."""

    def test_demo_graph_inside_guest_image(self):
        from blockswarm.demo import submit_demo_graph
        from blockswarm.sandbox import ProcessSandbox
        root = os.environ["BLOCKSWARM_GUEST_ROOT"]

        class GuestImageSandbox(ProcessSandbox):
            isolation = "test: chroot into the guest image"
            python = "/usr/bin/python3"  # the guest image's interpreter
            package_parent = "/opt/blockswarm"

            def _preexec(self, timeout):
                inner = super()._preexec(timeout)

                def fn():
                    os.chroot(root)
                    os.chdir("/")
                    inner()
                return fn

        s = self.make_swarm(security={"sandbox_backend": "process"})
        try:
            s.sandboxes.create = lambda aid: GuestImageSandbox(aid, s.cfg.security)
            ids = submit_demo_graph(s)
            status = asyncio.run(s.run(timeout=120))
            self.assertEqual(status["tasks"], {"done": len(ids)})
            for tid in ids.values():
                self.assertTrue(s.result(tid)["verification"]["ok"])
        finally:
            self.close_swarm(s)


if __name__ == "__main__":
    unittest.main()
