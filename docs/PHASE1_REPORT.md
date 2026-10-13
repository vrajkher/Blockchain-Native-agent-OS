# Phase 1 report: two-agent prototype

> Superseded in part by [PHASE2_REPORT.md](PHASE2_REPORT.md) (sandboxes, gateway).

**Goal:** a runnable two-agent prototype using one shared AI model, SQLite
and asyncio, with the security, identity and ledger interfaces of the full
architecture already in place.

**Model choice (revised):** inference uses **Claude through the Anthropic
API** (official `anthropic` SDK, default `claude-opus-5-5`) instead of a local
llama.cpp model. One model still serves every agent, but no weights run on
the host.

**Result:** the runtime, security primitives, scheduler, verifier, simulated
ledger and API inference backend are implemented and tested. The backend is
tested through the real SDK against a local fake Messages API. **No live API
call has been made yet** (no API key in the build environment), so output
quality, latency and cost are unmeasured.

## 1. Source code

See the [README](../README.md#layout) for the module map and
[ARCHITECTURE.md](ARCHITECTURE.md) for the design. Runtime dependencies are
`cryptography` and `anthropic`. Everything else is the Python standard
library: asyncio, sqlite3, tomllib, zlib.

## 2. Installation

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e .                       # runtime
pip install -e '.[dev]'                # pytest (optional; unittest works too)
export ANTHROPIC_API_KEY=sk-ant-...    # or: ant auth login
python -m blockswarm demo --fresh      # Claude via the Anthropic API
python -m blockswarm demo --fresh --backend mock   # offline, no API calls
```

## 3. Test results

`python -m unittest discover -s tests -t .`: **51 tests, all passing**
(about 6 s). The swarm tests use the deterministic MOCK backend. The
Anthropic backend tests run the real SDK against a local fake Messages API
(no network, no key). Governor tests use fake `/proc/meminfo` readings.

| Area | What is tested |
|---|---|
| Crypto / signing | Ed25519 sign/verify, domain separation, agent ID ↔ pubkey binding, keystore file mode 0600, refusal of insecure key files, revoked agents cannot sign, agents cannot sign as host |
| Envelopes | Valid once, then **replay rejected**; wrong assignee, tampered payload, expired, forged signature, malformed input all rejected |
| Capabilities / tools | Role policy denies unpermitted scopes; expired, wrong-agent, missing-scope, tampered, revoked and malformed capabilities all denied; tool gateway refuses calls without the scope or with another agent's capability; calculator rejects code injection and huge exponents |
| Anthropic backend | Wire request checked via the real SDK: `claude-opus-5-5`, `effort: low`, structured-output schema, `fallbacks: "default"` + `server-side-fallback-2026-07-01` header, system prompt separate, only the calling agent's turn sent, no sampling/thinking params; refusal, `max_tokens`, 400, 503 and connection errors raise; startup preflight detects bad credentials and unknown models; harness parses API replies end to end |
| Inference | Requires capability; **max 1 concurrent inference** under 4 parallel requests; **no cross-agent context** in backend requests; per-agent context limit and rolling token budget (independent per agent); malformed messages rejected |
| Memory | Agent views isolated; identity not rebindable; per-agent quota, compression, value-size limit |
| Queue | Dependency gating; exclusive claims; retries exclude the failed agent; dependency-failure propagation; expired-lease recovery; **irreversible task never re-executes** after a crash (`needs_review`; explicit operator requeue only) |
| Ledger | Merkle proofs; all runtime functions; batched sealing; receipts verify; tampered receipts and tampered blocks detected; revocation resolves |
| Governor | Default 2; 3 only with measured room; pressure → 1 → 0; 8 GiB target cap on a larger host |
| Swarm (end to end) | Demo graph done by **2 distinct agents in parallel**, all signatures/commitments/receipts verified, per-agent memory holds only own tasks; **agent crash survived** by reassignment + quarantine; **model-service outage** (e.g. 529) retried without blaming or quarantining agents; tampered result rejected and never committed; compromised tool's wrong answer rejected deterministically; **revocation terminates the running agent** and is sealed on the ledger; crash recovery requeues leased work; **100 identities**, never more than 3 active |
| Security mode | `secure` refuses the in-process sandbox; with `firecracker` configured, tasks fail closed (not implemented) |
| API | `/health` open; admin endpoints 401 without or with a wrong token; bad input 400; `/v1/inference` 403 without a valid capability and 403 with a capability stolen from another agent |

## 4. Measured memory usage

**Machine:** cloud VM, Intel Xeon @ 2.80 GHz, 4 vCPU, 16 GiB RAM, no GPU,
Linux 6.18, Python 3.13, `anthropic` 1.13.0. The governor capped its budget
at the 8 GiB target. This is **not** the Phase 5 real 8 GB host.

Workload: N logical identities, 30 tasks (20 LLM classification + 10
calculator), fresh process per row. RSS is from `/proc/self/status`.

**Anthropic backend:** real SDK and HTTP stack, pointed at a local fake
Messages API (canned replies, so run time excludes real API latency):

| Logical agents | Tasks done | Agents used | Max active | Max concurrent requests | RSS before init (MiB) | RSS after init | **Peak RSS (VmHWM)** |
|---|---|---|---|---|---|---|---|
| 2 | 30/30 | 2 | 2 | 1 | 31.8 | 81.6 | **87.3** |
| 3 | 30/30 | 3 | 3 | 1 | 31.8 | 81.7 | **87.4** |
| 10 | 30/30 | 10 | 3 | 1 | 31.7 | 81.6 | **87.3** |
| 100 | 30/30 | 20 | 3 | 1 | 31.7 | 81.5 | **87.5** |

**MOCK backend** (runtime only, no SDK loaded): peak RSS 36.7 to 37.1 MiB
for 2 to 100 identities.

Raw data: [`benchmarks/`](benchmarks/).

What the numbers show:

* **The whole application peaks at about 87 MiB.** Of that, about 50 MiB is
  the Anthropic SDK and its HTTP stack. With no local model, this is about
  1.7% of the 5 GiB application target. The earlier local llama.cpp
  measurement for a 0.5B model peaked at about 566 MiB.
* **Identities are nearly free.** Going from 2 to 100 identities adds under
  0.5 MiB.
* **The governor chose 3 active agents** in every row because measured
  memory permitted it. Most of the RAM budget is now free for the Phase 2
  microVMs (256 MiB each are already reserved in the governor's arithmetic).
* **Request concurrency is 1.** With a remote model this limits API rate and
  cost rather than host CPU, so it can be raised (`inference_concurrency`)
  to let active agents call the model in parallel.

## 5. Remaining issues

1. **No live API run yet.** Run `python -m blockswarm demo --fresh` with
   credentials to measure output quality, repair rate, latency and cost per
   task. `effort: low` is a starting point; raise it per task kind if quality
   needs it.
2. **Task data leaves the host.** Inputs and dependency outputs are sent to
   the Anthropic API. Each request carries only the calling agent's own
   prompt, but operators must treat task data as shared with the model
   provider.
3. **Offline operation needs the MOCK backend.** No local model is supported
   any more. Without network access only `--backend mock` runs.
4. **No sandbox isolation yet.** Agents run in-process (dev mode). Memory
   views and capability checks are API boundaries, not security boundaries.
   Phase 2: Firecracker + jailer, vsock RPC for `infer` / `call_tool`,
   deny-by-default network and filesystem, cgroup CPU/memory/disk quotas, no
   sandbox-to-sandbox networking.
5. **Ledger is simulated.** No consensus or finality. Phase 3: Solidity
   registries (agents, capabilities, task/result roots), Anvil for local
   development, remote RPC for real finality. Anchor each block's Merkle root
   in one transaction.
6. **Single verifier.** Only the host's deterministic verifier exists. Phase
   4: independent validators, quorum only across independent validators,
   sequential validation to save RAM.
7. **Summaries and reports are only structurally verified**
   (`proves_correctness: false`). Only the calculator task is deterministically
   proven.
8. **Per-agent CPU/disk/execution quotas** are limited today to task timeouts,
   API token budgets, memory-entry quotas and tool rate limits. Hard OS-level
   quotas come with the microVMs.
9. **Capability revocation list is in memory** (agent revocation is durable).
   Persist cap revocations when capabilities outlive a process.
10. **Keystore at rest** is encrypted only when
   `BLOCKSWARM_KEYSTORE_PASSPHRASE` is set. Consider a separate signing
   process or HSM/TPM in later phases.
11. **SQLite is used from the event-loop thread.** Fine at this scale (sub-ms
   queries). Revisit if the API serves heavy concurrent traffic.
12. **Phase 5 benchmarks on a real 8 GB CPU-only host** are still owed.
