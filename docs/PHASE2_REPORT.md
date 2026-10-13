# Phase 2 report: sandboxes and the external authorization gateway

**Goal:** independent Firecracker microVM sandboxes per agent, and an
external authorization gateway.

**Result:** implemented. The security architecture now runs end to end, with
one gap: **no microVM has actually booted**, because the build host is
itself a VM without KVM (`/dev/kvm` absent, no `vmx`/`svm` CPU flags).
Everything up to that point was run for real:

* the real **jailer** v1.12.1 built the chroot from our layout, applied
  cgroup limits, dropped to uid 65534 and exec'd Firecracker;
* the real **Firecracker** v1.12.1 accepted our VM config, the CI guest
  kernel and the rootfs, and stopped exactly at `Error creating KVM object`;
* the **guest image** we build (CI kernel 6.1.128 + Ubuntu 24.04 + guest
  agent) was mounted, and the full demo graph ran with every agent executing
  inside that image's own userland (its Python 3.12.3 and `cryptography`
  50.0.2) through chroot.

Not exercised: the guest kernel boot, `/sbin/blockswarm-init`, and the
virtio-vsock transport. A host with KVM is needed for those (see §5).

## 1. What was built

| Component | File | Notes |
|---|---|---|
| Guest agent | `blockswarm/guest/agent.py` | Runs the harness in the sandbox; connects via vsock (`2:5000`), an inherited fd, or a Unix socket. Holds no keys, capability or credentials. |
| Host broker | `blockswarm/broker.py` | One per run. Sends the task, serves `infer` / `tool` / `mem.*` through the gateway, keeps the capability host-side, records evidence itself, enforces call/frame limits. |
| RPC framing | `blockswarm/rpc.py` | 4-byte length + JSON, 256 KiB max, strict parsing. |
| Authorization gateway | `blockswarm/gateway.py` | Policy file (deny by default, per-role actions, rate and argument-size limits), capability + registry checks, audit, fail closed. Runs in-process or as `python -m blockswarm gateway` on a 0600 Unix socket with read-only registry access. Unreachable means deny. Policy digest anchored on the ledger. |
| Sandboxes | `blockswarm/sandbox.py` | `inprocess` (dev), `process` (dev: uid 65534, empty env, rlimits incl. zero file size, own netns), factory with secure-mode policy and startup preflight. |
| Firecracker | `blockswarm/firecracker.py` | Preflight (KVM, binaries, images, root), VM config (read-only root, no NIC, vsock), jailer argv (uid/gid, cgroup v1/v2 cpu/memory/pids, fd limit), jail preparation, vsock listener, early-exit detection, kill and cleanup. |
| Guest image | `scripts/build_guest_image.sh` | Pinned + SHA-256-checked Firecracker CI kernel and Ubuntu 24.04 squashfs; adds the package, `cryptography` wheels and `/sbin/blockswarm-init` (drops to uid 65534 via `setpriv`, powers off when done). Builds in about 13 s, 332 MiB ext4. |

## 2. Installation

```bash
pip install -e .
python -m blockswarm demo --fresh --sandbox process           # dev, separate processes
# secure mode (KVM host, root): see README "Secure mode setup"
sudo scripts/build_guest_image.sh /var/lib/blockswarm
sudo python -m blockswarm --config config/blockswarm.example.toml demo --fresh --sandbox firecracker
```

## 3. Test results

`python -m unittest discover -s tests -t .`: **71 tests pass** as root with
the integration environment (`BLOCKSWARM_FC_DIR`, `BLOCKSWARM_GUEST_ROOT`).
Without it: **69 pass, 2 skipped**. Three consecutive full runs were green.

New in Phase 2:

| Test | Shows |
|---|---|
| Demo graph with `process` sandbox | All 6 tasks done and verified with every agent in a separate unprivileged process via broker + gateway |
| **Malicious guest: secrets** | Guest environment has only `PATH`/`LANG`, even with `ANTHROPIC_API_KEY` set on the host; runs as uid 65534 in a separate PID |
| **Malicious guest: network** | Cannot reach 1.1.1.1:443 or a listening port on the host's loopback (own network namespace) |
| **Malicious guest: filesystem** | Cannot read the host keystore or `/etc/shadow` (`PermissionError`); cannot write file contents (`RLIMIT_FSIZE=0`) |
| **Malicious guest: escalation** | Tool call without the scope denied by the gateway; unknown op refused; reading another agent's memory key returns nothing (own namespace); the task message contains no capability |
| **Malicious guest: forged evidence** | Fake `tool_calls` in the guest's result are ignored; only broker-recorded calls are signed |
| **Malicious guest: flood / oversize / hang** | Call limit, frame-size limit and timeout end the run; the hung guest process is killed |
| Gateway policy | Deny by default, argument-size limit, rate limit, bad/missing capability, unknown agent, revoked agent (with a still-valid capability), internal errors deny |
| **External gateway process** | `python -m blockswarm gateway`: socket mode 0600, allow + deny decisions, JSONL audit, a swarm task completes through it, killed gateway denies |
| Policy on ledger | Policy digest recorded at startup |
| Firecracker unit | VM config (no NIC, single read-only drive, vsock), jailer argv (cgroup v1 and v2), preflight messages, jail layout (uid 65534, 0400 images), secure-mode backend policy |
| **Real jailer + Firecracker** (integration) | Real binaries, real kernel: fails only at KVM creation; jail directory cleaned up |
| **Guest image userland** (integration) | Full demo graph inside the built image's Python 3.12 + `cryptography` 50.0.2 |
| Secure mode without KVM | Refuses to dispatch; tasks stay `pending` with 0 attempts |

## 4. Measured memory and overhead

Same VM as before (4 vCPU, 16 GiB, governor capped at the 8 GiB target), MOCK
inference, 30 tasks, fresh process per row.

| Sandbox | Logical agents | Tasks done | Max active | Host peak RSS | **Guest peak RSS** | Time per task |
|---|---|---|---|---|---|---|
| inprocess | 2 / 3 / 10 / 100 | 30/30 each | 2 / 3 / 3 / 3 | 35.6–36.1 MiB | (none) | ~35 ms |
| process | 2 / 3 / 10 / 100 | 30/30 each | 2 / 3 / 3 / 3 | 35.7–36.1 MiB | **32.3 MiB per guest** | 63–93 ms |

* A process guest (Python + `cryptography` + the guest agent) peaks at
  32.3 MiB, and its startup adds about 30–60 ms per task.
* **Firecracker:** not measurable here. The budget reserves 256 MiB guest
  RAM + 64 MiB VMM overhead per active microVM (the cgroup memory limit is
  320 MiB). With the Anthropic API backend (about 87 MiB host) and 3 active
  VMs that is about 1.05 GiB, within the 5 GiB application target. Real VM
  RSS (guest pages actually touched) and boot latency must be measured on a
  KVM host.

Raw data: [`benchmarks/`](benchmarks/).

## 5. Remaining issues

1. **Boot a microVM.** Run on a KVM host (bare metal, or a cloud instance
   with nested virtualization): `scripts/build_guest_image.sh`, then the
   demo with `--sandbox firecracker`, then measure VM RSS and boot time.
   Unverified until then: guest kernel boot, `blockswarm-init`, vsock
   connect, power-off on exit.
2. **Pinned artifact hashes are trust-on-first-download** from Firecracker's
   official CI bucket. Cross-check them against Firecracker's published
   artifacts before production.
3. **The dev `process` sandbox is not a security boundary.** It shares the
   host kernel and can read world-readable host files. Without root there is
   no uid drop and no network namespace. Secure mode never uses it.
4. **Boot cost per task.** One fresh VM per run is the safest choice but adds
   boot latency. Firecracker snapshots (restore a pre-booted guest) are the
   planned optimization.
5. **Gateway rate-limit state is in memory** (per gateway process) and resets
   on restart. Capability revocations are still in memory too (agent
   revocation is durable).
6. **The external gateway trusts the swarm database for registry status**
   (read-only). An attacker with write access to the host database is out of
   scope.
7. **The guest can still spend its own budget:** within its call limit it
   can make inference requests, bounded by per-agent token budgets and the
   gateway's rate limits.
8. Earlier items still open: the ledger is simulated (Phase 3), there is a
   single deterministic verifier (Phase 4), and the live Anthropic API and a
   real 8 GB host are not yet measured (Phase 5).
