# BlockSwarm AI Lite

A CPU-only, blockchain-native, parallel AI agent swarm runtime for small
Linux hosts (target: 8 GB RAM, no GPU).

Many **logical agent identities** (100+) share **one resident quantized
model** (llama.cpp GGUF). By default two agents are active at once, three
only when measured memory permits. Every agent has a cryptographic identity,
private scoped memory, short-lived scoped capabilities, signed task
envelopes and signed result commitments, and its results are batched into
Merkle-rooted ledger blocks.

> **Status: Phase 1 of 5. This is a development prototype, not production
> software.** Agents currently run in-process, which is **not a security
> boundary**. The ledger is a **local simulation with no consensus**. See
> [what is real and what is not](#what-is-real-and-what-is-not).

## What is real and what is not

| Area | Phase 1 status |
|---|---|
| Ed25519 identities, host-managed signing service (keys never reach agents) | **Implemented** |
| Signed task envelopes, replay protection (durable nonces), expiry | **Implemented** |
| Short-lived, scoped, host-signed capabilities; policy outside agent control | **Implemented** |
| Tool authorization gateway (fail-closed, rate-limited, audited) | **Implemented** (one tool: calculator) |
| One shared model via llama.cpp, per-agent context/token limits, concurrency 1 | **Implemented** (tested with a synthetic model, see below) |
| Optional remote / `llama-server` model adapter (OpenAI-compatible HTTP) | **Implemented**, not exercised in CI |
| Asyncio scheduler, SQLite WAL durable queue, dependency graphs, leases, retries | **Implemented** |
| No duplicate irreversible execution (idempotency log → `needs_review`) | **Implemented** |
| Agent checkpoint / suspend / recycle, quarantine, revocation, emergency kill | **Implemented** |
| Resource governor (real RSS + `/proc/meminfo`, 2 → 3 → reduce → pause) | **Implemented** |
| Deterministic verification (signatures, commitments, schema, permissions, checkers) | **Implemented** |
| `register_agent` … `revoke_agent` runtime functions, Merkle receipts | **Implemented** over a **simulated local ledger** |
| Mock inference backend | **MOCK** (deterministic, labelled `mock: true` everywhere) |
| Sandbox isolation | **NOT YET**: in-process only (dev mode). Secure mode refuses to start. |
| Firecracker microVMs + jailer, vsock RPC | Phase 2 |
| EVM chain (Anvil / remote RPC), Solidity registries | Phase 3 |
| Independent validators, quorum policies | Phase 4 |
| Benchmarks on a real 8 GB CPU-only host | Phase 5 |

## Install

Requires Python 3.11+ on Linux x86-64.

```bash
git clone <this repo> && cd Blockchain-Native-agent-OS
python3 -m venv .venv && . .venv/bin/activate
pip install -e .                       # runtime: only `cryptography`
pip install -e '.[llama]'              # + llama.cpp (builds from source, CPU only)
# optional, for a reproducible CPU-portable build:
# CMAKE_ARGS="-DGGML_NATIVE=OFF" pip install llama-cpp-python
```

Get a small GGUF model (0.5B to 1.5B, 4-bit), for example Qwen2.5-0.5B-Instruct Q4_K_M:

```bash
mkdir -p models
curl -L -o models/qwen2.5-0.5b-instruct-q4_k_m.gguf \
  https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/main/qwen2.5-0.5b-instruct-q4_k_m.gguf
```

## Quick start

```bash
# Two-agent demo with the deterministic MOCK backend (no model needed)
python -m blockswarm demo --fresh

# Same demo with a real model through llama.cpp
python -m blockswarm demo --fresh --backend llama-cpp \
    --model models/qwen2.5-0.5b-instruct-q4_k_m.gguf

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

## Tests

```bash
python -m unittest discover -s tests -t .     # or: pytest
```

## Benchmarks

```bash
python scripts/bench.py --backend mock --agents 2 3 10 100 --tasks 30
python scripts/bench.py --backend llama-cpp --model models/<model>.gguf --agents 2 3 10 100
```

No model weights could be downloaded in the environment used to build Phase
1, so `scripts/make_synthetic_gguf.py` generates a model with the exact
tensor shapes of Qwen2.5-0.5B, quantized to Q4_K_M by llama.cpp. Its
**weights are random, so its output text is meaningless**. It is useful only
to measure memory and CPU latency. Results are in
[docs/PHASE1_REPORT.md](docs/PHASE1_REPORT.md).

## Layout

```
blockswarm/
  crypto.py        Ed25519 + SHA-256, canonical JSON, domain-separated signatures
  signing.py       host-managed signing service and 0700/0600 keystore
  registry.py      agent identities (off-chain view)
  capabilities.py  short-lived scoped capabilities, role → scope policy
  envelope.py      signed task envelopes, result records
  nonces.py        durable replay protection
  inference.py     one shared model: llama.cpp / HTTP / MOCK; limits; concurrency
  harness.py       per-agent lightweight AI harness (runs inside the sandbox)
  memory.py        private agent-scoped memory (zlib for large values)
  tools.py         external tool authorization gateway
  sandbox.py       sandbox interface; in-process (dev); Firecracker placeholder
  queue.py         durable dependency-aware queue, leases, idempotency log
  governor.py      memory measurement and active-agent concurrency
  verifier.py      deterministic verification and verdicts
  ledger.py        blockchain runtime functions over a simulated Merkle ledger
  swarm.py         wiring + asyncio scheduler
  api.py           minimal authenticated HTTP API
  cli.py           command line
docs/              architecture and phase reports
scripts/           benchmark and synthetic-model tools
tests/             unit, integration and security tests
```

## Security notes

* `security.mode = "dev"` runs agents **in-process**. This gives API-level
  separation (bound memory views, capability checks), **not isolation**. A
  malicious harness in the same Python process could bypass it. Do not run
  untrusted tasks or models in dev mode.
* `security.mode = "secure"` fails closed: the runtime refuses to start
  unless a microVM sandbox backend is configured, and the Firecracker backend
  refuses to run until Phase 2 implements it.
* Private keys stay in the host keystore (directory 0700, files 0600,
  optional passphrase encryption via `BLOCKSWARM_KEYSTORE_PASSPHRASE`).
* No sandbox technology guarantees absolute containment.
