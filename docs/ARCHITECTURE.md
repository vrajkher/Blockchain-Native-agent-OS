# Architecture

## Principles

* **One shared model, many identities.** Agents are cheap logical
  identities (a key pair, a registry row, a checkpoint, private memory).
  Only the *active* agents consume execution resources. Inference is
  centralized behind one authenticated service that calls Claude through
  the Anthropic API; no model weights run on the host.
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
                         HOST (trusted)                                    │ SANDBOX (untrusted)
┌─────────────────────────────────────────────────────────────────────┐    │ one per task run
│ Scheduler (asyncio) ─ TaskQueue (SQLite WAL) ─ ResourceGovernor     │    │ ┌──────────────────────┐
│   ├─ CapabilityAuthority: issue scoped, short-lived capability      │    │ │ guest agent          │
│   ├─ SigningService (keystore 0700): sign envelope / result         │    │ │  AgentHarness        │
│   │                                                                 │    │ │  - verifies envelope │
│   │  SandboxBroker (one per run) ◄══ framed JSON RPC ═══════════════╪════╪═╡  - prompt / parse    │
│   │   - sends task (envelope, payload, host pubkey); NO capability  │    │ │  RPC stubs:          │
│   │   - every request ─► AuthorizationGateway ─► allow / deny       │    │ │  infer, tool, memory │
│   │        (capability + registry status + policy file + limits)    │    │ └──────────────────────┘
│   │        in-process, or a separate process on a 0600 Unix socket  │    │ transport:
│   │   - inference ─► InferenceService ─► Anthropic API              │    │  inprocess: socketpair
│   │   - tools     ─► ToolGateway (host-side execution)              │    │  process:   inherited fd
│   │   - memory    ─► this agent's MemoryView only                   │    │  firecracker: virtio-vsock
│   │   - records evidence itself (tool calls, tokens, mock flag)     │    │   (host side: Unix socket
│   ├─ DeterministicVerifier                                          │    │    in this VM's jail)
│   └─ BlockchainRuntime ─► SimulatedLedger (Merkle-batched blocks)   │
└─────────────────────────────────────────────────────────────────────┘
```

The guest holds nothing of value: no keys, no capability, no API
credentials, no database handle. The host decides every action, and the
guest can only ask.

### Sandbox backends

| Backend | What separates the guest from the host |
|---|---|
| `inprocess` | Nothing but the RPC API (same process). Dev only. |
| `process` | Separate process: `setsid`, uid/gid 65534, no supplementary groups, empty environment, `-I` isolated Python, rlimits (CPU seconds, address space, 32 fds, **zero file-size**, no core dumps) and, when root, a fresh network namespace (no interfaces up, so no network). Shares the host kernel and can read world-readable files. Dev only. |
| `firecracker` | One microVM per run, started by `jailer` as uid/gid 65534 in a chroot with cgroup `cpu`/`memory`/`pids` limits and Firecracker's seccomp filters. Own guest kernel; root filesystem attached **read-only**; tmpfs scratch; **no network interface**. The only device to the outside is virtio-vsock: the guest connects to CID 2 port 5000, which Firecracker maps to `v.sock_5000` inside that VM's jail, where the broker for that run listens. VMs cannot reach each other (no NIC, separate vsock devices, separate jails). Destroyed after the run. |

### Broker protocol

Frames are a 4-byte big-endian length plus a UTF-8 JSON object (max 256 KiB).

```
host → guest   {"t":"task", agent_id, host_pubkey, envelope, payload}
guest → host   {"t":"call", id, op: infer|tool|mem.get|mem.recent|mem.put, args}
host → guest   {"t":"reply", id, ok, value | error}
guest → host   {"t":"result", output} | {"t":"fail", error}
```

Per-run limits are 32 calls by default, the frame size cap and the task
timeout. A denied action or an unknown op gets an error reply. A malformed
or oversized frame, an unexpected message type, a non-object output or
exceeding a limit ends the run as a failure attributed to the agent. A
model-service outage reported through the broker is not attributed to the
agent.

### Authorization gateway

Decision for (agent, action, argument size):

1. agent is registered and not revoked or quarantined;
2. the host-signed capability is valid, unexpired, bound to this agent and
   includes the action's scope;
3. the policy file grants the action to one of the agent's roles (deny by
   default);
4. the argument size is within the rule's limit;
5. the per-agent, per-action rate limit is not exceeded.

Any exception denies. Every decision is audited (SQLite audit table
in-process, JSONL file in the external process). The policy's digest is
anchored on the ledger when it changes.

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
5. A fresh sandbox is created for the run. The broker sends the task, and the
   guest harness verifies the envelope and does the work, asking the broker
   (and through it the gateway) for every inference call, tool call and
   memory access. LLM kinds call Claude with
   structured outputs (`output_config.format` = the task's JSON schema) and
   one repair round. Model-service failures (credentials, network, rate
   limits, 5xx) are retried without being counted against the agent.
6. Host builds the result record (`H(envelope)`, `H(output)`,
   `H(tool_calls)` where tool calls are the ones the *broker* executed), signs
   it with the agent's key, and verifies everything deterministically.
7. On success: `commit_result_hash` + host `submit_attestation`; result row and
   `done` status written in one transaction guarded by lease ownership. After
   the batch is sealed, the Merkle receipt is attached to the result.
8. On failure: lease released; retry on a different agent up to
   `max_attempts`; agent failure counter incremented (quarantine at the
   threshold); dependents of permanently failed tasks fail.
9. Sandbox destroyed (VM or process killed, jail removed). Agent checkpointed
   and suspended (status `idle`, cached key dropped).

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
* Inference concurrency is a separate semaphore (default 1 API request in
  flight), independent of how many agents are active. With a remote model it
  bounds API rate and cost, not host CPU, so it can be raised safely.

## Inference service

* One `AnthropicBackend` (official `anthropic` SDK) serves every agent.
  Default model `claude-opus-5-5`, `effort: low` for these short structured
  tasks.
* Each request is stateless and carries only the calling agent's system
  prompt and input. Agents never share a conversation.
* Replies are constrained by structured outputs. Length and range bounds are
  stripped from the schema sent to the API and enforced afterwards by
  normalization and the deterministic verifier.
* Server-side refusal fallbacks (`fallbacks: "default"`) are on by default.
  A final `refusal` or `max_tokens` stop is treated as a failed attempt.
* Credentials never enter config files or agents. `demo` and `serve` run a
  token-free preflight (`models.retrieve`) and refuse to start without valid
  credentials.

## Result consensus vs. blockchain consensus

They are different things and the code keeps them apart:

* **Result verification** (`verifier.py`) decides whether an output is
  acceptable. Deterministic checkers can *prove* some results (for example
  arithmetic). Schema checks only prove structure. Phase 4 adds independent
  validators and quorum, used only when validators are independent.
* **Ledger consensus** decides the order and immutability of commitments. In
  Phase 1 there is none (single-process simulation).
