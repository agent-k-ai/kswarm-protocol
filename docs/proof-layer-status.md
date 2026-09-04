# Proof Layer Status

Last verified: 2026-09-03 (PR `fix/proof-binding`, follow-up commits included).

This page says what the proof layer proves today. It does not describe the
target design. For the target design see `over-summary.md` at the repository root.

## What Is Proven Today

| Layer | Where it runs | What the proof says | Gated on-chain? |
| --- | --- | --- | --- |
| Aggregate settlement | Solana + Bonsol | The Bonsol reducer image ran on the committed input and produced the committed journal. `settle_aggregate_proof_job` pays only when the `BonsolAggregateVerification` marker is `Verified` and the verifier attestation hash equals the worker result hash. | Yes |
| Branch EZKL proof | Worker (prove); **no runtime verifier** since the Node worker was retired | The fixed linear model `2 * line_count + 3 * word_count + 1` maps the public inputs to the public output. The public instances now must equal the claimed line count, word count, and score. | No. Off-chain only. |
| Branch zkVM receipt | Worker (prove); **no runtime verifier** since the Node worker was retired | The `zkvm-reducer` guest hashed the values it was given. Every journal field now must equal the claimed result. | No. Off-chain only. |

### The guests commit caller-supplied statistics

Both zkVM guests take `line_count`, `word_count`, and `score_hex` as inputs.
They hash those values and commit the hash. They do not read the source text.
They do not recompute the counts. A proof says "the guest saw these values",
not "these are the true statistics of the source document".

The reducer recompute (guest reads the source text and derives the counts) is
future work. The combiners in `protocol/bonsol-branch-reducer/src/lib.rs`
(`weighted_mean`, `trimmed_mean`, `majority_vote`, `sorted_branches_merkle_root`)
are tested but not called by the guest. The worker-trust PR will mirror their
semantics.

## Who Runs These Rules Today

**Nobody, at runtime.** The rules below are implemented and tested, and every one of
them is exercised by `protocol/test/proof-binding.test.mjs`,
`protocol/test/bonsol-journal.test.mjs` and `protocol/proofs/ezkl/tests/`, but the
one component that called them was `protocol/src/proofs.mjs`, reached from the Node
swarm runner. Both were deleted when the Node worker was retired (PR-8, owner
decision 2026-09-03), so no running process verifies an EZKL proof or a zkVM receipt
against a claim.

What replaced it is different in kind: the Python verifier
(`worker/verifier_worker`) re-executes the branch with the identical model, seed and
configuration and attests to its own canonical hash, and the on-chain program settles
an aggregate job only against a Bonsol marker. Re-execution catches a fabricated
result; it does not check a proof. Restoring proof checking means giving
`proof-binding.mjs` a caller again, or porting it to the Python verifier.

`verify_branch.py` is still a working command-line verifier and still binds a proof
to its claim; it simply has no daemon calling it.

## Binding Rules

A proof is accepted only when every rule below holds. Any failure rejects the
branch output.

### EZKL (`protocol/proofs/ezkl/verify_branch.py`, `binding.py`)

1. `ezkl.verify` passes against the pinned `vk.key`, `settings.json`, `kzg.srs`.
2. `bundle.proof_sha256` equals the SHA-256 of `proof.json`.
3. `bundle.vk_sha256` equals the SHA-256 of `vk.key`.
4. `settings.run_args` has `input_visibility = Public`, `output_visibility = Public`,
   `param_visibility = Fixed`. Private inputs cannot be bound, so they fail.
5. `settings.model_instance_shapes` is `[[1, 2], [1, 1]]`. `proof.instances` is
   one column of exactly 3 elements.
6. Element 0 equals `quantize(bundle.features.line_count, input_scale)`.
   Element 1 equals `quantize(bundle.features.word_count, input_scale)`.
   Element 2 equals `bundle.score_hex` as an exact string.
7. `bundle.public_instances` equals `proof.instances`.
8. When the caller passes `--expected-line-count`, `--expected-word-count`, and
   `--expected-score-hex`, the bound values must equal them. The swarm runner
   passes the values from the branch output manifest.

Encoding (ezkl 23.0.5): each instance element is a BN254 scalar field element,
64 lowercase hex characters of the little-endian canonical bytes, no `0x`.
Quantization is `round_half_away_from_zero(value * 2**scale)`.

### Off-chain zkVM (`protocol/src/proof-binding.mjs`)

1. `zkvm-reducer verify` passes. The receipt verifies against the verifier
   binary's own image id.
2. `manifest.proofs.zkvm.image_id_hex` equals the verifier's `image_id_hex`.
3. The journal has exactly the fields `branch_key`, `child_job_id`,
   `line_count`, `parent_request_id`, `reducer_digest`, `score_hex`, `word_count`.
4. `branch_key`, `child_job_id`, `parent_request_id`, `line_count`, `word_count`
   equal `manifest.result`.
5. `score_hex` equals `manifest.proofs.ezkl.score_hex`.
6. `reducer_digest` equals `sha256(branch_key || child_job_id || parent_request_id || score_hex || le32(line_count) || le32(word_count))`.
7. `manifest.proofs.zkvm.journal` equals the verified journal on every field.

### Manifest (`protocol/src/proof-binding.mjs`)

1. `manifest.bundle_version` is `kswarm-branch-output-v1`.
2. `manifest.branch_key`, `child_job_id`, `parent_request_id` equal `manifest.result`.
3. `manifest.result.line_count` and `word_count` are integers in `[0, 2^32)`.
4. The EZKL bundle's `features`, `score_hex`, `proof_sha256`, `vk_sha256` equal the manifest.
5. The SHA-256 of each fetched artifact equals the hash the manifest names.

The worker runs the same checks on its own output before it publishes a
manifest (`generateSwarmProofBundle`).

### Bonsol guest (`protocol/bonsol-branch-reducer`)

The guest journal is 104 bytes:

| Offset | Field | Encoding |
| --- | --- | --- |
| 0..32 | `input_digest` | risc0 SHA-256 of the framed public input (`len le64 || json`) |
| 32..64 | `reducer_digest` | SHA-256 of `"{branch_key}|{child_job_id}|{parent_request_id}|{score_hex}|{line_count}|{word_count}"` |
| 64..68 | `line_count` | u32 little-endian |
| 68..72 | `word_count` | u32 little-endian |
| 72..104 | `score` | the 32 little-endian bytes of `score_hex` |

Bonsol forwards bytes 32..104 (72 bytes, the "committed outputs") to the
callback. The on-chain program stores `output_digest = sha256(committed_outputs)`
and `journal_hash = sha256(input_digest || committed_outputs)`. It hashes the
bytes and never parses them, so the hashing rule did not change; only the
bytes did.

`score_hex` contract: exactly 64 lowercase hex digits, no prefix, the
little-endian bytes of a BN254 scalar field element, reduced modulo the
field. This is the encoding EZKL uses for its instances, so the EZKL output
instance can be passed through unchanged. Byte 0 of the committed score is
the least significant byte of the score.

- The guest aborts (no receipt) on a missing or malformed `score_hex`. The
  callback harness returns an error for the same input instead of predicting
  a journal the guest will never produce.
- One implementation of the layout: `decode_score_felt`,
  `reducer_canonical_bytes`, and `committed_outputs` in
  `protocol/bonsol-branch-reducer/src/lib.rs`, used by the guest and the
  harness. `binding.py` (`bonsol_committed_outputs`, `bonsol_journal_hash`)
  and `proof-binding.mjs` (`bonsolCommittedOutputs`, `bonsolJournalHash`)
  mirror it; `scripts/run-flagship-demo.py` imports the Python one. All four
  are pinned to the same golden vector
  (`output_digest = 76a8ed05...c1ea`, `journal_hash = c1bb642e...2363` for the
  harness default input).
- Fixed in this PR: the old journal carried one byte taken from the last two
  hex digits of `score_hex`. EZKL instance strings are little-endian, so that
  byte was the most significant byte and was `0` for every realistic score.
  The regression vector `3901...` (313 = 1.22 at scale 8) now commits `0x39`
  at byte 72; the old decoder committed `0`.
- The decoder works on bytes. Malformed input (`""`, `"a"`, `"zz"`, `"éa"`,
  `"deadbeef"`, `"0x..."`) is an error, never a panic.
- `sorted_branches_merkle_root` uses RFC 6962 style prefixes (`0x00` leaf,
  `0x01` node) and promotes an odd node unchanged. The old scheme paired the
  odd node with itself, so `[A, B, B]` and `[A, B, B, B]` gave the same root.
  Nothing on-chain or in JS computed the old root.

## RISC Zero Version

Every crate now pins risc0 `=3.0.3`:

| Crate | risc0 crates | Runs where |
| --- | --- | --- |
| `protocol/zkvm-reducer` (off-chain branch receipt) | `risc0-zkvm =3.0.3`, `risc0-build =3.0.3` | `docker/protocol-node` image (the binary is built into it) |
| `protocol/bonsol-branch-reducer` (on-chain aggregate guest) | `risc0-zkvm =3.0.3` | Bonsol node, Bonsol commit `25a590d09cca0404cc48ec028122df4d1a8c651b` |
| `protocol/bonsol-callback-harness` | `risc0-zkvm =3.0.3` (hash impl only) | Bonsol smoke test |

Before this PR `protocol/zkvm-reducer` pinned `^5.0.0-rc.1`, a release
candidate. The two lanes still do not share receipts: an off-chain
`zkvm-reducer` receipt is verified by the `zkvm-reducer` binary, and the
on-chain aggregate receipt is verified by the Bonsol verifier program.

The transitive risc0 crates matter. `risc0-zkvm 3.0.3` declares caret
requirements (`risc0-circuit-rv32im ^4.0.2`, `risc0-zkp ^3.0.2`, ...). The
newer point releases (`risc0-circuit-rv32im 4.0.4`/`4.0.5`, `risc0-zkp
3.0.4`/`3.0.5`) changed the `SyscallContext` trait, and `risc0-zkvm 3.0.3`
with the `prove` feature then fails to compile
(`error[E0038]: the trait risc0_circuit_rv32im::execute::SyscallContext is not dyn compatible`).
`protocol/zkvm-reducer/Cargo.lock` and `methods/guest/Cargo.lock` therefore
hold the set from the upstream risc0 v3.0.3 lockfile: `risc0-circuit-*
4.0.2`, `risc0-circuit-*-sys 4.0.1`, `risc0-zkp`/`binfmt`/`groth16 3.0.2`,
`risc0-zkos-v1compat 2.2.0`, `risc0-zkvm-platform 2.2.0`. Build with the
committed lockfiles. Do not `cargo update` these crates on their own.

Verified on a build host (cargo 1.91.1, no rzup toolchain):
`RISC0_SKIP_BUILD=1 cargo check -p host` finished (25m 19s, first build of
the risc0 C++ kernels) and `cargo check` of `methods/guest` on the host
target finished. The guest ELF was not built (needs the rzup toolchain).

Stable risc0 is 3.0.6 (2026-07-17). 3.0.5 carried security backports. A bump
to 3.0.6 must move the Bonsol prover (the Bonsol node image and its pinned
risc0) and the on-chain verifier selector together with these crates, so it is
a separate task. Do not bump one crate alone.

## Rollout Notes

- `prepare_assets.py` now sets the visibility flags explicitly. Existing
  EZKL asset directories must be regenerated. The verifier rejects assets
  with private inputs.
- The Bonsol guest binary changed twice in this PR (decoder, then journal
  layout), so its image id changes. Redeploy the reducer image before the
  next Bonsol smoke test. `protocol/scripts/run-bonsol-smoke-test.sh` and the
  harness default input now carry a 64-digit `score_hex`.
- `protocol/bonsol-callback-harness` depends on the reducer crate by path.
  `cargo build --locked` needs the updated `Cargo.lock` in this PR.
- `protocol/zkvm-reducer` lockfiles were regenerated for risc0 3.0.3. The
  guest ELF was not rebuilt here (needs the rzup toolchain). The
  protocol-node Dockerfile runs `rzup install` with no version, which
  installs the newest components; the first container build on 3.0.3 must
  confirm `risc0-build 3.0.3` accepts that toolchain, and pin
  `rzup install rust <version>` if it does not.

## How To Run The Checks

```bash
# EZKL binding (no ezkl binary needed; integration tests skip without it)
cd protocol/proofs/ezkl && uv venv .venv && uv pip install -p .venv/bin/python pytest && .venv/bin/python -m pytest -q

# Manifest and zkVM journal binding
cd protocol && npm test && for f in src/*.mjs; do node --check "$f"; done

# Reducer combiners, Merkle root, score decoder, journal layout, harness predictor
cd protocol/bonsol-branch-reducer && cargo test
cd protocol/bonsol-callback-harness && cargo test

# Off-chain zkVM host and guest crates against risc0 3.0.3 (no guest ELF build)
cd protocol/zkvm-reducer && RISC0_SKIP_BUILD=1 cargo check -p host
cd protocol/zkvm-reducer/methods/guest && cargo check
```
