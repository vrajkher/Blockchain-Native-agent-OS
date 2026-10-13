# Phase 1 report: two-agent prototype

**Goal:** a runnable two-agent prototype using one shared small model, SQLite
and asyncio, with the security, identity and ledger interfaces of the full
architecture already in place.

**Result:** done, with one caveat. The runtime, security primitives,
scheduler, verifier and simulated ledger are implemented and tested. The real
llama.cpp inference path is implemented and was exercised, but **only with a
synthetic random-weight model**, because no model weights could be downloaded
in the build environment. AI output quality has therefore **not** been
measured yet.

## 1. Source code

See the [README](../README.md#layout) for the module map and
[ARCHITECTURE.md](ARCHITECTURE.md) for the design. The runtime depends only on
`cryptography` (plus `llama-cpp-python` for real inference). Everything else
is the Python standard library: asyncio, sqlite3, urllib, tomllib, zlib.

## 2. Installation

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e .                      # runtime
pip install -e '.[llama]'             # llama.cpp CPU backend (compiles from source)
pip install -e '.[dev]'               # pytest, gguf, numpy (tests + synthetic model tool)
python -m blockswarm demo --fresh     # MOCK backend, no model needed
python -m blockswarm demo --fresh --backend llama-cpp --model models/<model>.gguf
```

## 3. Test results

`python -m unittest discover -s tests -t .`: **42 tests, all passing**
(about 2.7 s). The tests run with the deterministic MOCK backend, plus fake
`/proc/meminfo` readings for the governor tests.

| Area | What is tested |
|---|---|
| Crypto / signing | Ed25519 sign/verify, domain separation, agent ID ↔ pubkey binding, keystore file mode 0600, refusal of insecure key files, revoked agents cannot sign, agents cannot sign as host |
| Envelopes | Valid once, then **replay rejected**; wrong assignee, tampered payload, expired, forged signature, malformed input all rejected |
| Capabilities / tools | Role policy denies unpermitted scopes; expired, wrong-agent, missing-scope, tampered, revoked and malformed capabilities all denied; tool gateway refuses calls without the scope or with another agent's capability; calculator rejects code injection and huge exponents |
| Inference | Requires capability; **max 1 concurrent inference** under 4 parallel requests; **no cross-agent context** in backend requests; per-agent context limit and rolling token budget (independent per agent); malformed messages rejected |
| Memory | Agent views isolated; identity not rebindable; per-agent quota, compression, value-size limit |
| Queue | Dependency gating; exclusive claims; retries exclude the failed agent; dependency-failure propagation; expired-lease recovery; **irreversible task never re-executes** after a crash (`needs_review`; explicit operator requeue only) |
| Ledger | Merkle proofs; all runtime functions; batched sealing; receipts verify; tampered receipts and tampered blocks detected; revocation resolves |
| Governor | Default 2; 3 only with measured room; pressure → 1 → 0; 8 GiB target cap on a larger host |
| Swarm (end to end) | Demo graph done by **2 distinct agents in parallel**, all signatures/commitments/receipts verified, per-agent memory holds only own tasks; **agent crash survived** by reassignment + quarantine; tampered result rejected and never committed; compromised tool's wrong answer rejected deterministically; **revocation terminates the running agent** and is sealed on the ledger; crash recovery requeues leased work; **100 identities**, never more than 3 active |
| Security mode | `secure` refuses the in-process sandbox; with `firecracker` configured, tasks fail closed (not implemented) |
| API | `/health` open; admin endpoints 401 without or with a wrong token; bad input 400; `/v1/inference` 403 without a valid capability and 403 with a capability stolen from another agent |

## 4. Measured memory usage

**Machine:** cloud VM, Intel Xeon @ 2.80 GHz, 4 vCPU, 16 GiB RAM, no GPU,
Linux 6.18, Python 3.13, llama-cpp-python 0.3.36 (CPU build,
`GGML_NATIVE=OFF`). The governor capped its budget at the 8 GiB target. This
is **not** the Phase 5 real 8 GB host; those numbers are still owed.

**Model:** `scripts/make_synthetic_gguf.py`: exact Qwen2.5-0.5B tensor
shapes (494M params, 24 layers, vocab 151,936), quantized to **Q4_K_M by
llama.cpp** (377.7 MiB file). Random weights: memory and latency are
representative, **output text is meaningless**. n_ctx 2048, max 64 output
tokens, 4 threads.

Workload: N logical identities, 12 tasks (8 LLM classification + 4
calculator), fresh process per row. RSS is from `/proc/self/status`. Host Δ
is the drop in `MemAvailable` during the run.

| Backend | Logical agents | Tasks done | Agents used | Max active | Max concurrent inference | RSS before model (MiB) | RSS after model load | **Peak RSS (VmHWM)** | Host MemAvailable Δ | Run time |
|---|---|---|---|---|---|---|---|---|---|---|
| llama.cpp, synthetic 0.5B Q4_K_M | 2 | 12/12 | 2 | 2 | 1 | 35.6 | 525.7 | **565.5** | 125 MiB | 42.5 s |
| llama.cpp, synthetic 0.5B Q4_K_M | 3 | 12/12 | 3 | 3 | 1 | 35.7 | 525.7 | **567.6** | 130 MiB | 44.4 s |
| llama.cpp, synthetic 0.5B Q4_K_M | 10 | 12/12 | 8 | 3 | 1 | 35.6 | 525.8 | **567.6** | 143 MiB | 39.2 s |
| llama.cpp, synthetic 0.5B Q4_K_M | 100 | 12/12 | 8 | 3 | 1 | 35.6 | 525.6 | **564.3** | 132 MiB | 34.0 s |
| MOCK (runtime overhead only) | 2 | 30/30 | 2 | 2 | 1 | 33.2 | 35.4 | **36.7** | ≈0 | 1.0 s |
| MOCK | 3 | 30/30 | 3 | 3 | 1 | 33.3 | 35.5 | **36.8** | ≈0 | 1.1 s |
| MOCK | 10 | 30/30 | 10 | 3 | 1 | 33.3 | 35.5 | **36.8** | ≈0 | 1.0 s |
| MOCK | 100 | 30/30 | 20 | 3 | 1 | 33.4 | 35.6 | **37.1** | ≈0 | 1.1 s |

Raw data: [`benchmarks/`](benchmarks/).

What the numbers show:

* **One resident model.** Model load adds about 490 MiB once (mmap'd
  weights + 2048-token KV cache + compute buffers). Peak RSS does not grow
  with the number of identities: 100 identities used 564 MiB, the same as 2.
* **Identities are nearly free.** Going from 2 to 100 identities adds under
  0.5 MiB RSS. Each costs one key file, one registry row and one checkpoint
  row.
* **Inference is serialized** (max concurrent = 1). With 3 active agents the
  third overlaps only on non-LLM work (calculator, verification, ledger), so
  throughput is bounded by CPU inference: about 4–5 s per 64-token
  classification request on 4 vCPU.
* **The governor chose 3** in every row, because measured memory permitted it
  (7.5 GiB effective available after the 8 GiB cap). The prototype
  application total of about 0.6 GiB is far below the 5 GiB application
  target, leaving room for the Phase 2 microVMs (256 MiB each are already
  reserved in the governor's arithmetic).

End-to-end demo on the synthetic model
([log](benchmarks/phase1-demo-llama-cpp-synthetic-0.5b.txt)): sentiment and
calculator tasks completed and verified, with receipts valid. Both summaries
were **rejected** (random weights fill the token limit without closing the
JSON). The dependent report then failed cleanly. This is the expected
fail-closed behaviour. Peak RSS was 573 MiB.

## 5. Remaining issues

1. **No real-model quality measurement.** Re-run `scripts/bench.py` and the
   demo with real Qwen2.5-0.5B/1.5B-Instruct Q4_K_M weights. Expect a different
   repair rate and latency for long outputs.
2. **No sandbox isolation yet.** Agents run in-process (dev mode). Memory
   views and capability checks are API boundaries, not security boundaries.
   Phase 2: Firecracker + jailer, vsock RPC for `infer` / `call_tool`,
   deny-by-default network and filesystem, cgroup CPU/memory/disk quotas, no
   sandbox-to-sandbox networking.
3. **Ledger is simulated.** No consensus or finality. Phase 3: Solidity
   registries (agents, capabilities, task/result roots), Anvil for local
   development, remote RPC for real finality. Anchor each block's Merkle root
   in one transaction.
4. **Single verifier.** Only the host's deterministic verifier exists. Phase
   4: independent validators, quorum only across independent validators,
   sequential validation to save RAM.
5. **Summaries and reports are only structurally verified**
   (`proves_correctness: false`). Only the calculator task is deterministically
   proven.
6. **Per-agent CPU/disk/execution quotas** are limited today to task timeouts,
   token budgets, memory-entry quotas and tool rate limits. Hard OS-level
   quotas come with the microVMs.
7. **Capability revocation list is in memory** (agent revocation is durable).
   Persist cap revocations when capabilities outlive a process.
8. **Keystore at rest** is encrypted only when
   `BLOCKSWARM_KEYSTORE_PASSPHRASE` is set. Consider a separate signing
   process or HSM/TPM in later phases.
9. **SQLite is used from the event-loop thread.** Fine at this scale (sub-ms
   queries). Revisit if the API serves heavy concurrent traffic.
10. **Phase 5 benchmarks on a real 8 GB CPU-only host** are still owed.
