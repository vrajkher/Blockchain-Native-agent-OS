# BlockSwarm AI Lite

A lightweight, blockchain-native, parallel AI agent swarm runtime for small
Linux hosts (target: 8 GB RAM, no GPU).

Many **logical agent identities** (100+) share **one AI model served through
the Anthropic API** (Claude, default `claude-opus-5-5`). No model weights run
on the host. By default two agents are active at once, three only when
measured memory permits. Every agent has a cryptographic identity,
private scoped memory, short-lived scoped capabilities, signed task
envelopes and signed result commitments, and its results are batched into
Merkle-rooted ledger blocks.

> **Status: Phase 2 of 5. This is a development prototype, not production
> software.** Secure mode runs each agent in its own Firecracker microVM, but
> that path has **not booted a VM yet**: the build host has no KVM (see
> [Phase 2 report](docs/PHASE2_REPORT.md)). The dev sandboxes are **not
> security boundaries**. The ledger is a **local simulation with no
> consensus**. See [what is real and what is not](#what-is-real-and-what-is-not).

## What is real and what is not

| Area | Phase 1 status |
|---|---|
| Ed25519 identities, host-managed signing service (keys never reach agents) | **Implemented** |
| Signed task envelopes, replay protection (durable nonces), expiry | **Implemented** |
| Short-lived, scoped, host-signed capabilities; policy outside agent control | **Implemented** |
| External authorization gateway: policy file, deny by default, rate/size limits, audit; in-process or separate process | **Implemented** |
| Guest agent ↔ host broker RPC; capability never leaves the host; host-recorded evidence | **Implemented** |
| Tools executed host-side behind the gateway | **Implemented** (one tool: calculator) |
| One shared model via the Anthropic API (official SDK), structured outputs, refusal fallbacks | **Implemented**; tested against a local fake API, **not yet against the live API** |
| Per-agent context/token limits, request concurrency 1, startup credential preflight | **Implemented** |
| Asyncio scheduler, SQLite WAL durable queue, dependency graphs, leases, retries | **Implemented** |
| No duplicate irreversible execution (idempotency log → `needs_review`) | **Implemented** |
| Agent checkpoint / suspend / recycle, quarantine, revocation, emergency kill | **Implemented** |
| Resource governor (real RSS + `/proc/meminfo`, 2 → 3 → reduce → pause) | **Implemented** |
| Deterministic verification (signatures, commitments, schema, permissions, checkers) | **Implemented** |
| `register_agent` … `revoke_agent` runtime functions, Merkle receipts | **Implemented** over a **simulated local ledger** |
| Mock inference backend | **MOCK** (deterministic, labelled `mock: true` everywhere) |
| Dev sandboxes: in-process; separate process (unprivileged uid, empty env, rlimits, no network) | **Implemented**; **not** security boundaries |
| Firecracker microVM per run via jailer (read-only rootfs, no NIC, vsock only, cgroup limits) | **Implemented, not booted**: jailer + Firecracker validated up to KVM creation; no KVM on the build host |
| Guest image build (kernel + Ubuntu 24.04 rootfs + guest agent) | **Implemented**; guest userland tested via chroot |
| EVM chain (Anvil / remote RPC), Solidity registries | Phase 3 |
| Independent validators, quorum policies | Phase 4 |
| Benchmarks on a real 8 GB CPU-only host | Phase 5 |

## Install

Requires Python 3.11+ on Linux x86-64.

```bash
git clone <this repo> && cd Blockchain-Native-agent-OS
python3 -m venv .venv && . .venv/bin/activate
pip install -e .                       # runtime: `cryptography` + `anthropic`
export ANTHROPIC_API_KEY=sk-ant-...    # or: ant auth login
```

Credentials are resolved by the Anthropic SDK (`ANTHROPIC_API_KEY`,
`ANTHROPIC_AUTH_TOKEN`, or an `ant auth login` profile). They are never stored
in the swarm config, and agents never see them. `demo` and `serve` check
credentials and the model ID at startup and exit with a clear message if
either is wrong.

## Quick start

```bash
# Two-agent demo using Claude through the Anthropic API (the default; makes real API calls)
python -m blockswarm demo --fresh

# Pick a model / effort (defaults: claude-opus-5-5, effort low)
python -m blockswarm demo --fresh --model claude-opus-5-5 --effort medium

# Offline demo with the deterministic MOCK backend (no API calls)
python -m blockswarm demo --fresh --backend mock

python -m blockswarm status                  # swarm, queue, ledger, memory state
python -m blockswarm revoke <agent_id>       # revoke identity (sealed on the ledger)
python -m blockswarm --config config/blockswarm.example.toml serve --agents 10
```

The demo submits a dependency graph: two summaries, two sentiment
classifications and one calculator task run in parallel on two agents, then a
report task consumes their verified outputs. Every result is signed by its
agent identity, verified, committed and attested on the ledger, and the
receipt is checked against the block's Merkle root.

### HTTP API (`serve`)

Admin endpoints need `Authorization: Bearer $(cat .blockswarm/api_token)`.

| Method | Path | Auth |
|---|---|---|
| GET | `/health` | none |
| GET | `/v1/status` | admin token |
| POST | `/v1/tasks` `{"kind", "input", "deps"?, "priority"?, "irreversible"?}` | admin token |
| GET | `/v1/tasks/{id}` | admin token |
| POST | `/v1/agents/{id}/revoke` | admin token |
| POST | `/v1/inference` `{"agent_id", "capability", "messages"}` | agent capability (scope `inference`) |

## Sandboxes

All three backends run the same guest agent (`blockswarm/guest/agent.py`)
over the same broker protocol. Only the isolation differs:

| `security.sandbox_backend` | Isolation | Allowed in |
|---|---|---|
| `inprocess` | none: asyncio task in the host process | dev |
| `process` | separate process: uid 65534, empty environment (no API keys), rlimits, own network namespace (no network) when started as root | dev |
| `firecracker` | one microVM per run via jailer: own kernel, read-only rootfs, no network device, vsock only to its own broker, cgroup CPU/memory/pids limits | dev and **secure** |

`security.mode = "secure"` refuses every backend except `firecracker`, and
refuses to dispatch anything if KVM, the binaries or the guest image are
missing.

### Secure mode setup (Linux host with KVM, as root)

```bash
# 1. Firecracker + jailer (pinned release; check SHA256SUMS in the tarball)
curl -fsSL https://github.com/firecracker-microvm/firecracker/releases/download/v1.12.1/firecracker-v1.12.1-x86_64.tgz | tar xz
install release-v1.12.1-x86_64/firecracker-v1.12.1-x86_64 /usr/local/bin/firecracker
install release-v1.12.1-x86_64/jailer-v1.12.1-x86_64 /usr/local/bin/jailer
# 2. Guest kernel + read-only rootfs with the guest agent
scripts/build_guest_image.sh /var/lib/blockswarm
# 3. Run
python -m blockswarm --config config/blockswarm.example.toml demo --fresh --sandbox firecracker
```

### External authorization gateway

```bash
python -m blockswarm gateway --socket /run/blockswarm/gateway.sock \
    --policy config/policy.example.toml --audit /var/log/blockswarm-gateway.jsonl
# then set security.gateway = "unix:/run/blockswarm/gateway.sock"
```

The gateway process only needs the host's public key and read-only access to
the agent registry. It cannot issue capabilities or sign anything. If it is
unreachable, every request is denied.

## Tests

```bash
python -m unittest discover -s tests -t .     # or: pytest
# optional integration tests (root):
BLOCKSWARM_FC_DIR=<dir with firecracker, jailer, vmlinux, rootfs.ext4> \
BLOCKSWARM_GUEST_ROOT=<mounted guest-rootfs.ext4> python -m unittest discover -s tests -t .
```

## Benchmarks

```bash
python scripts/bench.py --backend mock --agents 2 3 10 100 --tasks 30
python scripts/bench.py --backend anthropic --agents 2 3 10 100 --tasks 6   # real API calls, costs money
```

Results are in [docs/PHASE1_REPORT.md](docs/PHASE1_REPORT.md).

## Layout

```
blockswarm/
  crypto.py        Ed25519 + SHA-256, canonical JSON, domain-separated signatures
  signing.py       host-managed signing service and 0700/0600 keystore
  registry.py      agent identities (off-chain view)
  capabilities.py  short-lived scoped capabilities, role → scope policy
  envelope.py      signed task envelopes, result records
  nonces.py        durable replay protection
  inference.py     one shared model: Anthropic API (Claude) / MOCK; limits; concurrency
  harness.py       per-agent lightweight AI harness (runs inside the sandbox)
  guest/agent.py   guest entry point: runs the harness, talks only to the broker
  broker.py        host side of one sandbox run: serves RPC through the gateway
  rpc.py           length-prefixed JSON framing (socketpair / vsock / Unix)
  gateway.py       external authorization gateway: policy, limits, audit, remote mode
  firecracker.py   microVM sandbox: preflight, VM config, jailer, vsock listener
  memory.py        private agent-scoped memory (zlib for large values)
  tools.py         external tool authorization gateway
  sandbox.py       sandbox backends: in-process, process (dev); factory + secure-mode policy
  queue.py         durable dependency-aware queue, leases, idempotency log
  governor.py      memory measurement and active-agent concurrency
  verifier.py      deterministic verification and verdicts
  ledger.py        blockchain runtime functions over a simulated Merkle ledger
  swarm.py         wiring + asyncio scheduler
  api.py           minimal authenticated HTTP API
  cli.py           command line
docs/              architecture and phase reports
scripts/           benchmark, guest image build
tests/             unit, integration and security tests
```

## Security notes

* Dev sandboxes are **not isolation**. `inprocess` shares the host process.
  `process` is a hardened separate process: it can still read world-readable
  host files and shares the host kernel. Do not run untrusted tasks in dev
  mode.
* `security.mode = "secure"` fails closed: it requires the Firecracker
  backend and refuses to dispatch when KVM, the binaries or the guest image
  are missing.
* Sandboxes never receive capabilities, keys or API credentials. The broker
  holds the capability and asks the gateway before every action.
* Task inputs (and dependency outputs fed into later tasks) are sent to the
  Anthropic API. Each request carries only the calling agent's own prompt;
  there is no shared conversation state between agents.
* Private keys stay in the host keystore (directory 0700, files 0600,
  optional passphrase encryption via `BLOCKSWARM_KEYSTORE_PASSPHRASE`).
* No sandbox technology guarantees absolute containment.
