# Architecture

## Principles

* **One resident model, many identities.** Agents are cheap logical
  identities (a key pair, a registry row, a checkpoint, private memory).
  Only the *active* agents consume execution resources. Inference is
  centralized behind one authenticated service.
* **The host holds authority.** Keys, policy, capability issuance,
  verification and ledger writes live on the host. Agents receive signed
  artifacts and bound clients, never keys or database handles.
* **Fail closed.** Any malformed or unverifiable capability, envelope or
  signature is rejected. Secure mode refuses to run without microVMs.
* **Hashes on-chain, data off-chain.** Full task data stays in SQLite.
  Only hashes, signatures and Merkle roots are committed.
* **Agreement is not proof.** Verdicts record whether a check deterministically
  proved correctness (`proves_correctness`) or only validated structure.

## Components and trust boundaries

```
                     HOST (trusted)                                     │  AGENT (untrusted)
┌──────────────────────────────────────────────────────────────────┐   │  ┌───────────────────────┐
│ Scheduler (asyncio) ── TaskQueue (SQLite WAL, leases, deps)       │   │  │ AgentHarness           │
│   │        ResourceGovernor (/proc/meminfo, RSS → 0..3 active)    │   │  │  - verifies envelope   │
│   │                                                               │   │  │  - builds prompt       │
│   ├─ CapabilityAuthority ── policy: role → scopes (host-only)     │   │  │  - parses/normalizes   │
│   ├─ SigningService (keystore 0700; host + agent keys)            │   │  │  - private memory view │
│   ├─ envelope: sign task, consume nonce (replay gate)  ───────────┼──►│  │                        │
│   │                                                               │   │  │  infer(msgs) ──────────┼──┐
│   │  InferenceService ◄── capability check, per-agent limits ◄────┼───┼──┼────────────────────────┘  │
│   │   └─ one Backend: llama.cpp GGUF | HTTP (llama-server/remote) │   │  │  call_tool(name,args) ─┼──┐
│   │  ToolGateway ◄── capability check, rate limit, audit ◄────────┼───┼──┼────────────────────────┘  │
│   │                                                               │   │  └───────────────────────┘
│   ├─ sign result record AS the agent (key never leaves host)      │   │   Phase 1: in-process task
│   ├─ DeterministicVerifier (sigs, commitments, schema, perms,     │   │   Phase 2: Firecracker
│   │                         evidence, kind checkers)              │   │   microVM + jailer, vsock
│   └─ BlockchainRuntime → SimulatedLedger (Merkle-batched blocks)  │   │
└──────────────────────────────────────────────────────────────────┘
```

In Phase 1 the right-hand side runs as an asyncio task in the same process,
so the boundary is enforced only by the API surface. Phase 2 moves the
harness into a microVM and turns `infer` / `call_tool` into vsock RPC stubs
that reach `POST /v1/inference` and the tool gateway. The host-side checks
are already the ones that will be used then.

## Task lifecycle

1. `submit(kind, input, deps)`: input schema checked; task stored;
   `register_task(task_id, kind, H(input))` appended to the ledger.
2. Scheduler: governor sets `allowed` (0 to 3). Ready tasks (all deps `done`)
   are claimed atomically for an idle eligible agent (roles cover required
   scopes, not excluded by an earlier failure, not revoked or quarantined).
3. Host issues a capability (scopes = the kind's needs, TTL = task timeout +
   margin), records `authorize_capability`, signs the task envelope (binds
   task, kind, `H(payload)`, assignee, capability, nonce, expiry) and consumes
   the nonce.
4. Irreversible tasks insert an idempotency key first. If it already exists,
   the task goes to `needs_review` and is never executed twice automatically.
5. Harness runs in the sandbox with a timeout. LLM kinds use
   grammar-constrained JSON decoding and one repair round.
6. Host builds the result record (`H(envelope)`, `H(output)`,
   `H(tool_calls)`), signs it with the agent's key, and verifies everything
   deterministically.
7. On success: `commit_result_hash` + host `submit_attestation`; result row and
   `done` status written in one transaction guarded by lease ownership. After
   the batch is sealed, the Merkle receipt is attached to the result.
8. On failure: lease released; retry on a different agent up to
   `max_attempts`; agent failure counter incremented (quarantine at the
   threshold); dependents of permanently failed tasks fail.
9. Agent checkpointed and suspended (status `idle`, cached key dropped,
   sandbox discarded).

## Ledger and receipts

`SimulatedLedger` seals pending entries into blocks:
`block_hash = H(0x02 ‖ {height, prev_hash, merkle_root, created_at})`, with
sorted-pair SHA-256 Merkle trees (leaf prefix `0x00`, node prefix `0x01`). A
receipt is `{entry_hash, block_height, block_hash, merkle_root, proof,
finality: "simulated-local"}`. `verify_receipt` recomputes the header hash,
the Merkle root from stored entries, and the inclusion proof.

Phase 3 keeps this exact batching: each sealed block's `merkle_root` is
anchored by one EVM transaction (Anvil locally, remote RPC for real
finality). Receipts then carry the transaction hash and a finality level that
distinguishes `local-anvil` from confirmed public-chain consensus.

## Resource governor

* Memory is measured, not assumed: process RSS (plus optional external
  inference PIDs) and `MemAvailable`.
* On hosts larger than the 8 GiB target, available memory is reduced by the
  excess so the governor behaves as it would on the target machine (set
  `total_physical_ram_target_mib = 0` to disable this).
* `allowed = 3` only if three guests *plus one guest of slack* fit both the
  application budget and the host headroom. Otherwise 2, else fewer, down to
  0 (dispatch paused, tasks stay queued).
* Inference concurrency is a separate semaphore (default 1), independent of
  how many agents are active.

## Result consensus vs. blockchain consensus

They are different things and the code keeps them apart:

* **Result verification** (`verifier.py`) decides whether an output is
  acceptable. Deterministic checkers can *prove* some results (for example
  arithmetic). Schema checks only prove structure. Phase 4 adds independent
  validators and quorum, used only when validators are independent.
* **Ledger consensus** decides the order and immutability of commitments. In
  Phase 1 there is none (single-process simulation).
