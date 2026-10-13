"""Firecracker microVM sandbox (secure mode).

One microVM per agent run, launched through ``jailer`` (chroot, unprivileged
uid/gid, cgroup CPU/memory/pids limits, Firecracker's own seccomp filters):

* own guest kernel, **read-only** root filesystem, tmpfs scratch only
* **no network device**: the only channel is a virtio-vsock to the host
* the guest connects to CID 2 (host) port ``vsock_port``; Firecracker maps
  that to the Unix socket ``<jail>/v.sock_<port>``, where the host broker
  for *this* run listens. Sandboxes cannot reach each other.
* the VM is destroyed after the run (no reuse between tasks or agents)

Preflight fails closed when KVM, the binaries or the guest image are missing.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import shutil
import socket
from pathlib import Path

from .config import FirecrackerConfig
from .sandbox import Sandbox, SandboxTimeout, SandboxUnavailable

KERNEL_NAME = "vmlinux"
ROOTFS_NAME = "rootfs.ext4"
CONFIG_NAME = "vm.json"
VSOCK_NAME = "v.sock"


def preflight(cfg: FirecrackerConfig | None) -> None:
    if cfg is None:
        raise SandboxUnavailable("no firecracker configuration")
    problems = []
    if not os.path.exists("/dev/kvm"):
        problems.append("/dev/kvm not present (KVM / nested virtualization unavailable)")
    elif not os.access("/dev/kvm", os.R_OK | os.W_OK):
        problems.append("/dev/kvm not accessible")
    for label, path in (("firecracker", cfg.firecracker_bin), ("jailer", cfg.jailer_bin)):
        if not (os.path.isfile(path) and os.access(path, os.X_OK)):
            problems.append(f"{label} binary not found or not executable: {path}")
    for label, path in (("kernel", cfg.kernel_image), ("rootfs", cfg.rootfs_image)):
        if not os.path.isfile(path):
            problems.append(f"guest {label} not found: {path} (run scripts/build_guest_image.sh)")
    if os.geteuid() != 0:
        problems.append("jailer must be started as root (it drops to the configured uid/gid)")
    if problems:
        raise SandboxUnavailable("Firecracker sandbox unavailable: " + "; ".join(problems))


def vm_config(cfg: FirecrackerConfig) -> dict:
    """Firecracker --config-file contents. Paths are inside the jail's chroot."""
    return {
        "boot-source": {"kernel_image_path": f"/{KERNEL_NAME}",
                        "boot_args": f"{cfg.boot_args} bs_port={cfg.vsock_port}"},
        "drives": [{"drive_id": "rootfs", "path_on_host": f"/{ROOTFS_NAME}",
                    "is_root_device": True, "is_read_only": True}],
        "machine-config": {"vcpu_count": cfg.vcpus, "mem_size_mib": cfg.guest_mem_mib,
                           "smt": False},
        "vsock": {"guest_cid": 3, "uds_path": f"/{VSOCK_NAME}"},
        "network-interfaces": [],
    }


def cgroup_args(cfg: FirecrackerConfig) -> list[str]:
    mem = (cfg.guest_mem_mib + cfg.vmm_overhead_mib) * 1024 * 1024
    period = 100000
    quota = max(1000, period * cfg.cpu_quota_pct // 100)
    if cfg.cgroup_version == 2:
        limits = [f"cpu.max={quota} {period}", f"memory.max={mem}", f"pids.max={cfg.pids_max}"]
    else:
        limits = [f"cpu.cfs_period_us={period}", f"cpu.cfs_quota_us={quota}",
                  f"memory.limit_in_bytes={mem}", f"pids.max={cfg.pids_max}"]
    out = []
    for item in limits:
        out += ["--cgroup", item]
    return out


def jailer_argv(cfg: FirecrackerConfig, jail_id: str) -> list[str]:
    return [cfg.jailer_bin, "--id", jail_id, "--exec-file", cfg.firecracker_bin,
            "--uid", str(cfg.uid), "--gid", str(cfg.gid),
            "--chroot-base-dir", cfg.chroot_base, "--cgroup-version", str(cfg.cgroup_version),
            *cgroup_args(cfg), "--resource-limit", "no-file=128",
            "--", "--config-file", f"/{CONFIG_NAME}", "--no-api", "--level", "Error"]


def jail_root(cfg: FirecrackerConfig, jail_id: str) -> Path:
    # jailer layout: <chroot_base>/<exec file name>/<id>/root
    return Path(cfg.chroot_base) / Path(cfg.firecracker_bin).name / jail_id / "root"


def prepare_jail(cfg: FirecrackerConfig, jail_id: str) -> Path:
    root = jail_root(cfg, jail_id)
    root.mkdir(parents=True, mode=0o700)
    for src, name in ((cfg.kernel_image, KERNEL_NAME), (cfg.rootfs_image, ROOTFS_NAME)):
        dst = root / name
        try:
            os.link(src, dst)  # no copy when on the same filesystem
        except OSError:
            shutil.copyfile(src, dst)
        os.chmod(dst, 0o400)  # the VMM only needs to read them (rootfs is attached read-only)
    (root / CONFIG_NAME).write_text(json.dumps(vm_config(cfg), indent=2))
    for path in [root, *root.iterdir()]:
        os.chown(path, cfg.uid, cfg.gid)
    return root


class FirecrackerSandbox(Sandbox):
    isolation = ("firecracker microVM via jailer: own kernel, read-only rootfs, no network "
                 "device, vsock to this run's host broker only, cgroup CPU/memory/pids limits")
    secure = True

    def __init__(self, agent_id: str, cfg: FirecrackerConfig | None):
        super().__init__(agent_id)
        preflight(cfg)
        self.cfg = cfg
        self.jail_id = "bs" + secrets.token_hex(8)
        self._proc: asyncio.subprocess.Process | None = None

    async def run(self, broker, timeout):
        cfg = self.cfg
        root = prepare_jail(cfg, self.jail_id)
        log_path = root.parent / "vmm.log"
        listen_path = root / f"{VSOCK_NAME}_{cfg.vsock_port}"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(listen_path))
        os.chown(listen_path, cfg.uid, cfg.gid)
        listener.listen(1)
        listener.setblocking(False)
        loop = asyncio.get_running_loop()
        try:
            with open(log_path, "wb") as log:
                self._proc = await asyncio.create_subprocess_exec(
                    *jailer_argv(cfg, self.jail_id), stdin=asyncio.subprocess.DEVNULL,
                    stdout=log, stderr=log, start_new_session=True)
            accept = asyncio.ensure_future(loop.sock_accept(listener))
            exited = asyncio.ensure_future(self._proc.wait())
            done, _ = await asyncio.wait({accept, exited}, timeout=cfg.boot_timeout_seconds,
                                         return_when=asyncio.FIRST_COMPLETED)
            if accept not in done:
                accept.cancel()
                exited.cancel()
                if exited in done:
                    raise SandboxUnavailable(f"microVM exited before connecting "
                                             f"(code {self._proc.returncode}): "
                                             f"{self._log_tail(log_path)}")
                raise SandboxTimeout(f"microVM did not connect within {cfg.boot_timeout_seconds}s: "
                                     f"{self._log_tail(log_path)}")
            exited.cancel()
            conn, _ = accept.result()
            return await self._serve(broker, conn, timeout, self.agent_id)
        finally:
            listener.close()
            await self.kill()
            self._cleanup(root)

    @staticmethod
    def _log_tail(path: Path) -> str:
        try:
            return path.read_bytes()[-500:].decode(errors="replace")
        except OSError:
            return ""

    async def kill(self) -> None:
        proc = self._proc
        if proc is None or proc.returncode is not None:
            return
        try:
            os.killpg(proc.pid, 9)
        except ProcessLookupError:
            pass
        await proc.wait()

    def _cleanup(self, root: Path) -> None:
        shutil.rmtree(root.parent, ignore_errors=True)
        name = Path(self.cfg.firecracker_bin).name
        bases = (["/sys/fs/cgroup"] if self.cfg.cgroup_version == 2 else
                 [f"/sys/fs/cgroup/{c}" for c in ("cpu", "memory", "pids", "cpuset")])
        for base in bases:
            try:
                os.rmdir(os.path.join(base, name, self.jail_id))
            except OSError:
                pass
            try:
                os.rmdir(os.path.join(base, name))  # only succeeds once no VM uses it
            except OSError:
                pass
