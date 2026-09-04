# Protocol Foundation Prototype

This prototype is a real Solana/IPFS payment and execution foundation for kswarm.

## What Is Real

- `solana-validator`: Dockerized Solana localnet
- `kswarm_protocol`: deployed on-chain program for escrow, worker stake, claim, settlement, cancellation, stale-job slashing, staked verifier result attestation, and verifier-driven bad-receipt slashing
- payment mint: KAI (classic SPL Token, 6 decimals) on mainnet; a stand-in mint with the same layout on devnet/localnet, provided externally for shared environments
- `protocol-api`: thin Node artifact gateway backed by a private IPFS swarm
- `protocol-bootstrap`: the Python CLI initializes the protocol and writes `protocol.json`
- `protocol-watcher`: on-chain settlement/slash loop, including slashed payout completion
- `ipfs-bootstrap`, `ipfs-peer-1`, `ipfs-peer-2`: private Kubo swarm for artifacts
- the paid work runs in the Python stack: `branch-worker`, `verifier-worker`, `aggregator-runner`, and `cli` images from `docker/swarm/Dockerfile`, composed by `docker-compose.swarm.yml` (see [Containers](containers.md))

## Retired: Node worker

The Node worker (`protocol-worker-a`, `run-worker.mjs`), the Node verifier (`run-verifier.mjs`), the Node runtime bootstrap (`bootstrap-runtime.mjs`), and the three Node smoke tests were removed in PR-8 (owner decision 2026-09-03). Reasons:

- the Node branch compute was a stub (byte, line, and word counts plus a hash); the Python branch worker runs the real LLM branch and the Python verifier re-executes it;
- PR-3 changed the `initialize_protocol` and `cancel_aggregate_proof_job` layouts, and the hand-encoded Node builders for them were not ported;
- one stack to maintain, container-packaged and digest-pinned.

What stays in `protocol/`: `api.mjs` (artifact gateway), `run-watcher.mjs` (settle and stale-slash loop), the runtime keypair and local-mint helpers the deployer uses, the read-only `show-eval-state.mjs`, the manual `settle-job`, `cancel-open-job`, `slash-stale-job`, and `withdraw-unlocked-stake` helpers, and the swarm planning example. `protocol.mjs` keeps only the decoders and instruction builders those files reach. The Bonsol reducer guests and the proof code under `protocol/proofs` are unchanged.

### Behavior change: empty expected_result_hash is no longer trivially challengeable

Before the verifier-attestation extension, a job opened with `expected_result_hash == EMPTY_HASH` was trivially challengeable on the result-hash path because the worker's submitted hash is always non-zero. The Q1 change tightens that path: when `expected_result_hash == EMPTY_HASH`, challenge grounds now require either worker-eligibility mismatch or a verifier-attestation mismatch. Existing paid jobs that relied on the empty-expected short-circuit must move to the verifier-attestation flow.

## Trust Boundary

- Solana is the only authority for escrow, worker stake, claim rights, settlement, refunds, and slashing.
- IPFS stores artifacts only.
- Private artifacts should be encrypted before upload.
- A job does not exist unless `open_job` succeeds on-chain with funded escrow.
- A worker cannot claim without staked KAI at or above the configured tier floor.

## Token Handling

The repo no longer creates the shared-environment token mint as part of normal protocol bootstrap.

- Shared testnet or multi-machine eval: provide an existing payment mint with `PROTOCOL_PAYMENT_MINT`
- Local smoke test only: set `PROTOCOL_BOOTSTRAP_LOCAL_MINT=1` to create a disposable local classic SPL mint (6 decimals) and fund demo wallets

## Quick Start

Containerized swarm smoke test (Python stack, local profile):

```bash
cargo build-sbf --tools-version v1.51 --manifest-path solana/programs/kswarm_protocol/Cargo.toml -- --locked
LLM_BASE_URL=http://<host>:11434/v1 LLM_MODEL_NAME=llama3.2:3b-instruct-q5_K_M scripts/swarm-smoke.sh
```

This proves:

1. the protocol initializes only under the program's upgrade authority
2. customer escrow is funded on-chain before work exists (`predict open`)
3. worker stake is locked on-chain before claim
4. the branch worker runs the LLM branch and submits a receipt; the verifier re-executes and attests
5. the aggregator combines the attested branches and `predict report` returns the result
6. both branch jobs settle on-chain after the challenge window

Node control plane only (validator, program deploy, IPFS swarm, gateway, watcher):

```bash
PROTOCOL_BOOTSTRAP_LOCAL_MINT=1 docker compose -f docker-compose.protocol.yml up --build
```

`protocol-bootstrap` initializes the protocol with the Python CLI and writes `runtime/protocol/protocol.json`; `protocol-api` and `protocol-watcher` start after it. Workers for that control plane come from `docker-compose.swarm.yml` (`devnet` profile pointed at the control plane's RPC), see [Protocol Eval Runbook](protocol-eval-runbook.md).

## Bonsol Native zkVM Eval

The repo also includes a real Bonsol local evaluation stack for native Solana-side zkVM verification experiments.

Fresh zero-state Bonsol smoke test:

```bash
docker compose -f docker-compose.bonsol.yml build bonsol-builder bonsol-image-server bonsol-node bonsol-smoke-test
docker compose -f docker-compose.bonsol.yml down -v
docker compose -f docker-compose.bonsol.yml --profile test up --abort-on-container-exit --exit-code-from bonsol-smoke-test --force-recreate
```

This proves:

1. the Bonsol verifier program and callback example are built and loaded into a local validator
2. a real Bonsol reducer image is built from `protocol/bonsol-branch-reducer/Cargo.toml`
3. a real Bonsol node claims and executes the request
4. the smoke test deploys and executes that image successfully from a clean Docker state

The current Bonsol smoke path retries the first few execute attempts because a fresh local validator can briefly return `Invalid deployment account` immediately after deploy. That is a local visibility race, not a mocked path.

### Bonsol callback failure semantics (version-scoped, empirically verified)

At pinned Bonsol commit `25a590d09cca0404cc48ec028122df4d1a8c651b`, a failing callback program causes the entire StatusV1 transaction to fail with `Custom(28679)/0x7007`. This was empirically verified in Phase 0a against `anzaxyz/agave:v2.0.13`; see [phase0-bonsol-callback-findings.md](./phase0-bonsol-callback-findings.md). Earlier source-reading suggested callback errors might be swallowed at lines `onchain/bonsol/src/actions/status.rs:173-184` at the same commit; the empirical observation overrides that reading. kswarm settlement still uses an independent callback-written marker (the `BonsolAggregateVerification` PDA) rather than relying on Bonsol's exit code, so this correction does not weaken the gate; it strengthens the redundancy.

## Swarm Model

The current swarm implementation is intentionally minimal:

- one parent request exists as an off-chain manifest (`kswarm predict open` writes it)
- that parent expands into `N+` child branch jobs plus one aggregate-proof job
- each child branch is a real on-chain `Job` account using the existing escrow/stake flow
- branch aggregation runs off-chain in `aggregator-runner`, from attested (or settled) on-chain child jobs, and is submitted as the aggregate job's receipt

Proof relationships are split by layer:

- Solana: escrow, stake, claim, settle, refund, slash
- `EZKL`: proof-carrying small ONNX inference inside branch workers
- `zkVM`: proof-carrying deterministic reducers and aggregate logic
- `Bonsol`: native Solana evaluation path for the deterministic `zkVM` lane
- trust-by-verify: full higher-level AI simulation behavior outside the deterministic proof boundary

### What the proofs prove today

The full statement is in [docs/proof-layer-status.md](./proof-layer-status.md). In short:

- The zkVM guests commit the statistics the caller supplies. They hash `line_count`, `word_count`, and `score_hex` and commit the hash. They do not read the source text and do not recompute the counts. The reducer recompute is future work.
- The aggregate settlement is proof-gated on-chain. `settle_aggregate_proof_job` pays only when the Bonsol callback marker is `Verified` and the verifier attestation matches the worker result.
- The per-branch `EZKL` proof and `zkVM` receipt are verified off-chain by the swarm runner. Since PR `fix/proof-binding` they are bound to the claimed result: the EZKL public instances must equal the claimed counts and score, and every zkVM journal field must equal the manifest. A mismatch rejects the branch output.
- The per-branch proofs have no on-chain gate. `submit_receipt` stores the result hash only.
- The `EZKL` model is a fixed linear placeholder (`2 * line_count + 3 * word_count + 1`), not an ML submodel.
- The off-chain `zkvm-reducer` and the on-chain Bonsol guest both pin risc0 `3.0.3`. The two lanes still do not share receipts. Stable risc0 is 3.0.6; a bump must move the Bonsol prover and the on-chain verifier selector together (see `docs/proof-layer-status.md`).

## Files To Know

- Solana program: `solana/programs/kswarm_protocol/src/lib.rs`
- Container images: `docker/swarm/Dockerfile` and `docker-compose.swarm.yml`
- Swarm bootstrap: `cli/kswarm_cli/swarm.py` (`kswarm swarm bootstrap`)
- Control-plane bootstrap: `docker/swarm/protocol-bootstrap.sh`
- Optional local mint bootstrap: `protocol/scripts/bootstrap-local-mint.mjs`
- Branch worker: `worker/branch_worker/daemon.py`; verifier: `worker/verifier_worker/daemon.py`; aggregator: `worker/aggregator_runner/runner.py`
- Watcher loop: `protocol/scripts/run-watcher.mjs`
- Swarm planning example: `protocol/src/swarm.mjs`
- Swarm smoke test: `scripts/swarm-smoke.sh`
- Bonsol builder: `protocol/scripts/run-bonsol-builder.sh`
- Bonsol node: `protocol/scripts/run-bonsol-node.sh`
- Bonsol smoke test: `protocol/scripts/run-bonsol-smoke-test.sh`
- Bonsol compose stack: `docker-compose.bonsol.yml`
- Compose stack: `docker-compose.protocol.yml`
- Node role/stake policy: [node-requirements-matrix](https://github.com/agent-k-ai/kswarm/blob/main/docs/node-requirements-matrix.md), in the `kswarm` repository
- Multi-machine runbook: [protocol-eval-runbook](https://github.com/agent-k-ai/kswarm/blob/main/docs/protocol-eval-runbook.md), in the `kswarm` repository
- Swarm summary: `over-summary.md`
- Proof layer status: `docs/proof-layer-status.md`
