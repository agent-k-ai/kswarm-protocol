# Proof Layer Status

Last verified: 2026-09-04, at the change that corrected what the Solana program
enforces about branch settlement. The change before it removed the per-branch model-proof
placeholder.

This page says what the proof layer proves today, which component proves it, and what
is not proven. It does not describe the target design; for that see `over-summary.md`
at the repository root.

## The Trust Split

kswarm has one step that cannot be proven and several that can.

**The LLM step is not proven, and no 2026 technology proves it.** No zero-knowledge proof
says a language model produced a particular forecast from a particular prompt. That step
is secured differently: a verifier re-executes the branch with the identical model, seed
and configuration, attests to its own canonical hash, and challenges a receipt whose hash
differs. A worker that fabricated a forecast is slashed. This is an economic guarantee,
not a cryptographic one, and it rests on determinism that has been measured on exactly
one model and one prompt family (`llama3.2:3b-instruct-q5_K_M`, the Tier 2 sample in
[LLM Bridge Honest Limits](llm-bridge-honest-limits.md)). A different model, prompt,
quantization or host needs its own trials before that guarantee means anything.

**Every deterministic step around it is proven.** The two are complementary, and both run:

| Layer | Where the proof is produced | Where it is checked | What it says | Gated on chain? |
| --- | --- | --- | --- | --- |
| Aggregate reduction | Bonsol node running `protocol/bonsol-aggregate-reducer` | Bonsol verifier program, then `settle_aggregate_proof_job` against the marker PDA | The guest read these branch receipts, rehashed each one, decoded the branch values out of those bytes, applied this combiner with these parameters, and got this value over this Merkle root of branch hashes | **Yes** |
| Branch canonicalization | Branch worker running `protocol/zkvm-reducer` | `worker/verifier_worker` before it attests | The branch output document published to IPFS encodes to exactly the `MFB2` receipt whose hash the chain accepted, and is this many bytes | No, in the strong sense: `settle_job` pays a branch without reading an attestation or a receipt. See "What the chain enforces about a branch" below |
| LLM inference | -- | `worker/verifier_worker` re-execution, `challenge_job`, slashing | Nothing is proven. A second party ran the same model and got the same canonical hash | No |

There is no fourth row. kswarm has no per-branch proof of a model, and the tree carries
no circuit that stands in for one.

### What The Chain Enforces About A Branch, And What It Does Not

Read the "Gated on chain?" column literally. For a branch job the answer is no in a
stronger sense than the phrase "off chain" usually carries, and an earlier version of
this page said the opposite.

`settle_job` requires three things and nothing else: the job is `Completed`, it is not an
`aggregate-proof` job, and its challenge deadline has passed
(`solana/programs/kswarm_protocol/src/lib.rs:563-609`). It does not read
`verifier_attestation_hash`, it does not read a zkVM receipt, and it does not know which
guest image produced one. Any signer may call it. So a branch that carries no
canonicalization receipt, or one whose receipt does not verify, is paid at the deadline
unless an authorized challenge landed inside the window first.

The aggregate path does not repair that for the branch. The aggregate guest is handed the
`MFB2` receipt **bytes**, rehashes them, decodes the branch values and combines them; it
is given no branch attestation and no branch zkVM receipt
(`protocol/bonsol-aggregate-reducer/src/aggregate.rs:238-344`). The verifier's own
aggregate check compares job class and `submitted_result_hash` and looks at neither a
branch attestation nor branch settlement status
(`worker/verifier_worker/daemon.py:456-475`). The aggregator runner does require every
branch the artifact names to be `settled` -- or `completed` with an attestation under
`--allow-completed-branches` (`worker/aggregator_runner/runner.py:300-332`) -- but that is
Python on one operator's host. It is policy, not enforcement, and a branch reaching
`settled` is by itself no evidence that anyone attested to it.

What is true in the other direction, and is not small:

- The canonicalization receipt **is** verified. The verifier checks it against its pinned
  image id and binds the journal to this job's rebuilt input frame, to the on-chain
  `submitted_result_hash` and to the length of the document it fetched, before it will
  attest (`worker/verifier_worker/daemon.py:283-327`).
- An attestation that disagrees with the receipt hash makes the receipt challengeable, and
  the assigned verifier can slash the worker inside the window (`receipt_is_challengeable`
  at `solana/programs/kswarm_protocol/src/lib.rs:2687`, then `challenge_job`).
- The aggregate reduction is genuinely gated on chain. `settle_aggregate_proof_job` pays
  only when the marker's `image_id`, `input_digest`, `output_digest` and `journal_hash`
  all match the job and the attestation equals the submitted receipt
  (`solana/programs/kswarm_protocol/src/lib.rs:2342-2380`).

Stated plainly: **the branch-level guarantee is economic and social, not enforced by the
chain.** It holds when a verifier is assigned, runs, disagrees, and challenges inside the
window. It does not hold by construction. The aggregate-level guarantee is the one the
program itself enforces.

**Open item, for the owner to decide.** Requiring a matching attestation in `settle_job`
before a branch is paid would close this. It is a protocol change with escrow
consequences and is recorded here as a recommendation, not as a change: a `Completed`
branch whose verifier never attests would then have no terminal path at all, because
`cancel_open_job` accepts only `Open` or `AwaitingArtifact` and `slash_stale_job` accepts
only `Claimed`, so neither reaches it, and the escrow would lock. Any such change needs a
branch-side counterpart to `cancel_aggregate_proof_job`. The Phase 1 architecture
decisions record already carries the same observation, as Q1 work.

### Why the LLM step is not proven

This is a limit of the field in 2026, not a gap in this repository.

- **The largest language model anyone can prove with released code is GPT-2 small, at
  124M parameters**, and the fastest published figure for it is at a **16-token
  sequence** -- short enough that it is not a like-for-like result against any useful
  input length. kswarm's branch model is `llama3.2:3b`, roughly **25 times larger**.
- **Every prover that can reach even that size is published under a proprietary,
  evaluation-only licence tied to the vendor's own proving network.** None of them can go
  into a worker image, and running proofs on a vendor's network would put a trusted third
  party back into the one layer that exists to remove it.
- **General-purpose zkVMs are further away, not closer.** A transformer forward pass
  inside a zkVM costs on the order of a billion cycles per token, and specialized systems
  are two to three orders of magnitude ahead of them on this workload.
- **Even a proof would have to publish its weights.** A valid proof of inference over
  *private* weights does not establish that the declared model ran: a prover can declare
  an architecture and parameter count and still embed structured weights that collapse
  the real computation (Hollow-LLM, IEEE S&P 2026). Any model proof kswarm ever ships
  will use public weights with their hash committed on chain, and will say so.

None of that changes what the aggregate and canonicalization proofs do. It bounds what a
reader should conclude from the phrase "zero-knowledge" anywhere near this project.

### Why the branch canonicalization receipt exists

Re-execution and the branch receipt catch different lies.

Re-execution catches a worker that invented a forecast: the verifier runs the model
itself and gets a different canonical hash. But both sides of that comparison are the
verifier's own bytes. It cannot catch a worker whose *published document* and *submitted
receipt* describe different values, because the Solana program stores only
`sha256(result_bytes)` and never sees the document.

The branch receipt closes that: the guest is handed the document and derives the receipt
from it. A worker cannot publish one document and settle another.

### Why the aggregate proof is the on-chain gate

An aggregate-proof job pays for one claim: *these branch receipts, combined by this
combiner with these parameters, give this value*. The artifact the guest reads carries
the branch receipt **bytes**, and `sha256(result_bytes)` is the `submitted_result_hash`
the program already stores for each branch job. So the Merkle root in the journal is a
root over hashes that are on chain, and any reader holding the artifact can look up each
named branch job and check that the guest reduced the receipt that job actually
submitted. That is a check a reader performs; the program does not perform it, and it
says nothing about whether those branches were attested.

### What the deferred binding costs, and what puts it back

`open_job` fixes `input_bundle_hash` and `expected_result_hash` for good, and both are
functions of the branch receipts, so the aggregate job cannot be opened until its
branches have settled. That is why `kswarm predict bind-aggregate` exists. The
consequence is that the combiner, its parameters and the branch set are chosen at a
moment when every branch result is already visible.

Nothing on chain fixes them. The Solana `Job` account has no parent-run field, and
`settle_aggregate_proof_job` reads no branch job account at all, so the chain does not
know which branch jobs were reduced -- a reader checking the artifact against the branch
PDAs does.
The nonce layout closes part of the gap and not all of it: branches take
`base .. base+N-1` and the aggregate takes `base+N`, so a reader can derive the branch
PDAs from the aggregate nonce and the journal's `branch_count` -- but dropping a
*prefix* of branches yields exactly the window that derivation produces for the smaller
count, and the combiner and its parameters are not derivable at all.

What puts it back is the plan. `predict open` pins `aggregate-plan.json` -- the branch
jobs, the combiner, its parameters and the reducer image -- to IPFS before any branch
runs, and the artifact carries that CID. The guest ignores the field, but `input_digest`
covers the whole artifact and the job's `input_bundle_hash` is fixed at open time, so
the plan is committed on chain transitively and cannot be swapped afterwards.
`predict bind-aggregate` refuses a binding whose combiner, parameters, reducer image or
branch set differ from the plan, and the aggregator runner makes the same comparison
before it agrees to prove anything -- so the check is made by a second party, not only
by the customer who chose.

An artifact with no plan CID still reduces: the field is provenance the chain carries,
not a value the guest reads. A run opened before the field existed therefore binds with
a warning rather than a refusal.

## What The Runtime Proof-Checking Work Closed

Before it, the release verification record carried three open items that were all the
same problem:

- "No runtime proof checking." No running process verified a zkVM receipt against a
  claim.
- "The aggregate Bonsol binding is inactive." The reducer the CLI named was the *branch*
  reducer, which rejects an aggregate artifact, so every aggregate job was opened UNBOUND
  and could never settle.
- "The zkVM guests hash what they are given." A proof said "the guest saw these values",
  not "these are the true statistics of the source".

All three are closed. The guests recompute, the aggregate job is opened bound, and both
daemons check proofs at runtime.

The change after that one removed the per-branch model-proof placeholder described under
"No per-branch model proof" below, and rewrote every claim on this page and in the
community documents to match what actually runs.

## The Aggregate Path, End To End

1. `kswarm predict open` opens the branch jobs and **plans** the aggregate job. It does
   not open it. `open_job` fixes `input_bundle_hash` and `expected_result_hash` for good,
   and both are functions of the branch receipts, which do not exist until the branches
   run. Opening it early is what forced the old UNBOUND path.
2. Branch workers execute, the verifier re-executes and attests, the branches settle.
   That is the intended order, not an enforced one: `settle_job` pays a `Completed` branch
   at its challenge deadline whether or not an attestation arrived (see "What the chain
   enforces about a branch").

3. `kswarm predict bind-aggregate <parent-run>` reads each branch job's on-chain
   `result_bytes`, builds the MFA3 artifact, reduces it with the Python mirror of the
   guest, pins it, and opens the aggregate job against the framed artifact digest and the
   predicted journal hash.
4. `worker/aggregator_runner` fetches the committed artifact, checks its framed digest
   against `input_bundle_hash`, re-reduces it, checks the journal against
   `expected_result_hash`, checks every branch receipt in it against that branch job on
   chain, claims, and submits the guest's committed outputs as the receipt.
5. The runner then runs `KSWARM_BONSOL_AGGREGATE_COMMAND`
   (`protocol/scripts/bonsol-aggregate-hook.py`), which funds the marker PDA, deploys the
   guest image, and asks a Bonsol node to prove the execution. The callback writes a
   `Verified` marker.
6. The verifier re-reduces the artifact and attests to the outputs the guest would commit.
7. `kswarm settle-aggregate` pays, but only when the marker's `image_id`, `input_digest`,
   `output_digest` and `journal_hash` all match the job and the attestation equals the
   receipt.

The receipt is submitted **before** the proof is requested, because
`record_aggregate_verification` requires the job to be `Completed` with
`submitted_result_hash == output_digest`. If the proof then fails, the job sits
`Completed` with no marker and `cancel_aggregate_proof_job` refunds the customer after
the marker timeout, with no slash. **An aggregate that cannot be proven does not settle.**

`KSWARM_ALLOW_UNBOUND_AGGREGATE=1` submits the receipt without requesting a proof. It
exists for a local stack with no Bonsol node, it warns on every run, and it is refused
outright on the `devnet` and `mainnet` cluster profiles.

## Journal Layouts

### Aggregate reducer (`protocol/bonsol-aggregate-reducer`), 105 bytes

| Offset | Field | Encoding |
| --- | --- | --- |
| 0..32 | `input_digest` | SHA-256 of the framed public input (`len le64 \|\| artifact`) |
| 32..33 | `combiner_id` | u8: 1 weighted-mean, 2 trimmed-mean, 3 majority-vote |
| 33..65 | `combiner_params_digest` | SHA-256 of `kswarm-combiner-params-v1\|combiner_id=N\|trim_bps=N\|category_dictionary_size=N` |
| 65..69 | `result_value` | u32 little-endian: basis points, or the label index for majority-vote |
| 69..73 | `branch_count` | u32 little-endian |
| 73..105 | `merkle_root` | sorted branch-hash Merkle root, RFC 6962 domain separation |

Bonsol forwards bytes 32..105 (73 bytes, the committed outputs) to the callback. The
program stores `output_digest = sha256(committed_outputs)` and
`journal_hash = sha256(input_digest || committed_outputs)`. It hashes the bytes and never
parses them.

The guest aborts, producing no receipt at all, on: a schema or version it does not know;
a combiner name that disagrees with its id; a branch whose declared `result_hash` is not
`sha256(result_bytes)`; a branch whose declared index is not the index inside its
receipt; branches that are not strictly increasing by index; a zero weight; a non-uniform
weight under `trimmed-mean` (which averages unweighted, so the weight would be a claim
the journal does not reflect); a categorical label outside the committed dictionary; a
scalar combiner over a categorical branch; hex that is not lowercase; and any malformed
`MFB2` encoding.

### Aggregate artifact (`MFA3`)

Canonical JSON: sorted keys, no whitespace, UTF-8.

```json
{
  "schema": "MFA3",
  "schema_version": 3,
  "parent_run": "<aggregate job pubkey>",
  "parent_manifest_cid": "<cid>",
  "output_schema_hash": "<64 lowercase hex>",
  "combiner": "trimmed-mean",
  "combiner_id": 2,
  "combiner_parameters": {"trim_bps": 1000},
  "branches": [
    {"branch_index": 0, "job": "<pubkey>", "output_cid": "<cid>",
     "result_bytes": "<lowercase hex of the MFB2 receipt>",
     "result_hash": "<64 lowercase hex>", "weight": 1}
  ]
}
```

The guest reads `combiner_id`, `combiner_parameters` and `branches`. Everything else is
provenance, and it is still covered, because `input_digest` is over the whole framed
artifact and the job was opened against that digest.

### Branch canonicalization guest (`protocol/zkvm-reducer`), 68 bytes

| Offset | Field | Encoding |
| --- | --- | --- |
| 0..32 | `input_digest` | SHA-256 of the framed guest input |
| 32..64 | `result_hash` | SHA-256 of the recomputed `MFB2` receipt bytes |
| 64..68 | `output_len` | u32 little-endian, the canonical byte length of the document |

Its input is the `MFBR1` frame:

```json
{
  "schema": "MFBR1",
  "schema_version": 1,
  "branch_input_sha256": "<64 lowercase hex>",
  "branch_output": { "...the document, without zkvm_receipt_cid..." }
}
```

`zkvm_receipt_cid` is the field on `BranchOutput` that names the receipt. It is excluded
from the frame and from the canonical hash preimage, because a receipt cannot be inside
the document it is a proof of. The other two exclusions are unchanged: `narrative_text`
(ADR Decision 6) and `completed_at_unix` (an honest verifier re-executes later).

### Legacy branch reducer (`protocol/bonsol-branch-reducer`), 104 bytes

Unchanged, and no longer on the aggregate path. Its guest commits the statistics its
caller supplied. It is kept because `protocol/bonsol-callback-harness` uses it to drive
the Bonsol callback, marker-PDA and replay smoke tests, and those semantics do not depend
on which guest ran. `cli/kswarm_cli/bonsol.py` still mirrors its rules for that harness,
and `cli/tests/test_bonsol_binding.py` still pins the mirror to the harness vectors.

## One Definition Of Every Rule

Every rule the proof layer depends on lives in `protocol/bonsol-aggregate-reducer/src/`:
the combiners, the Merkle root, the `MFB2` encoding, the canonical JSON rule, and both
journal layouts. The guest, the host verifier and the tests all call in.

The library shares a package with the guest on purpose. `bonsol build` runs the RISC Zero
docker build with the **guest directory** as the docker context (`risc0-build`'s
`DockerOptions::root_dir` defaults to the current directory and the Bonsol CLI chdirs
into `--zk-program-path` first), so a path dependency outside that directory is simply
absent from the build. The `zkvm-reducer` guest is a native `risc0-build` build with no
docker context, so it depends on the same crate by path.

`cli/kswarm_cli/aggregate.py` is the Python mirror. The two are pinned to one set of
vectors, `cli/tests/vectors/aggregate_journal_vectors.json`, generated from the Rust
crate: `protocol/bonsol-aggregate-reducer/tests/cross_language_vectors.rs` asserts the
Rust side and `cli/tests/test_aggregate_artifact.py` asserts the Python side. Neither
reduction can change without the other failing.

The committed value is computed in **exact integer arithmetic** on both sides:
round-half-up as `(2*numerator + denominator) / (2*denominator)` in 128-bit integers.
There is no rounding mode and no floating-point unit for the two languages to agree on.
The historical `f64` combiners are kept for the reported mean and are pinned against the
exact ones by property tests.

## Where Proving Runs

The two halves of the proof layer are packaged differently, because they need
different things.

**Branch receipts are proven and verified inside the worker containers.**
`docker/swarm/Dockerfile` builds the `zkvm-reducer` host in a stage of its own, through
`scripts/build-zkvm-guest.sh`, and installs it into the `branch-worker` and
`verifier-worker` images, along with the id of the guest compiled into it.
`docker/protocol-node/Dockerfile` calls the same script in a stage of its own, so the two
images carry the same guest. `KSWARM_ZKVM_HOST` and `KSWARM_ZKVM_IMAGE_ID_FILE` point at
both, so a worker proves and a verifier verifies with no extra configuration, and a
verifier refuses a receipt from a guest its own image did not build. The
`aggregator-runner` and `cli` images do not carry the binary: neither proves anything,
and it is 150 MB of attack surface.

**The aggregate proof is produced by a Bonsol node, and the aggregator only asks for
it.** Requesting a Bonsol execution needs the Bonsol CLI, a funded client keypair and a
docker socket. None of those belong in a hardened worker image, so they live in a
proving service:

```
aggregator-runner container                 proving service (operator infrastructure)
  KSWARM_BONSOL_AGGREGATE_COMMAND=            protocol/scripts/bonsol-hook-server.py
    python -m aggregator_runner.bonsol_http_hook       |
  KSWARM_BONSOL_HOOK_URL=http://host:38099/prove  -->  protocol/scripts/bonsol-aggregate-hook.py
                                                       |
                                                       Bonsol node, image server, validator
```

The client forwards the payload and returns the answer and interprets nothing. The
runner then checks every digest the service returned against its own reduction and
against the job account, so a proving service that proved a different claim is refused
by its caller rather than trusted by it. Nothing in that path authenticates the service,
because nothing needs to: it cannot forge a proof, it can only fail to produce one.

`scripts/swarm-smoke.sh` with `KSWARM_SMOKE_BONSOL=1` composes exactly that: the Bonsol
stack from `docker-compose.bonsol.yml`, the swarm stack from `docker-compose.swarm.yml`
pointed at the Bonsol validator, and one host process holding the proving credentials.

## Rebuilding And Re-Pinning A Guest

An image id is a property of the compiled ELF: the guest source, its dependencies, the
crate name and the RISC Zero toolchain all reach it. Nothing derives it; it is recorded
from a real build.

```bash
protocol/scripts/build-aggregate-reducer.sh            # build, print, rewrite the pin
protocol/scripts/build-aggregate-reducer.sh --check    # build and compare, change nothing
```

The script runs `bonsol build` inside the pinned `kswarm-bonsol-eval` builder image, the
same builder `docker-compose.bonsol.yml` uses, copies the manifest to
`runtime/bonsol/aggregate-reducer-manifest.json`, and rewrites
`AGGREGATE_REDUCER_IMAGE_ID` in `cli/kswarm_cli/reducer_image.py`. An unset pin fails
closed: `resolve_aggregate_image_id` refuses rather than opening an aggregate job against
an image id nobody built.

Current values, from real builds on 2026-09-04:

| Guest | Image id | Where it is pinned |
| --- | --- | --- |
| `protocol/bonsol-aggregate-reducer` (`kswarm_bonsol_aggregate_reducer`) | `785b584bc39a38d76e10fd0bb0c75cab62ae582497b577d03e6c1a9659204f4d` | `cli/kswarm_cli/reducer_image.py`, and every aggregate job's `required_software_digest` |
| `protocol/zkvm-reducer` branch canonicalization guest | `e73c537a5e92827fee6ba32c561c8d354230e94dc7d98214167b12076b9db367` | `protocol/zkvm-reducer/IMAGE_ID`, which `scripts/build-zkvm-guest.sh` asserts every build reproduces, and which is installed into the worker images as the default pin. The host binary verifies against its own built-in id either way; the pin is what makes a verifier refuse a receipt from a guest it did not expect |
| `protocol/bonsol-branch-reducer` (`mirofish_bonsol_branch_reducer`) | `6017b38ca12ad7fbc9b4f9db6005b726e292c5d8dc4022e3130fe6654f66ccfb` | Nothing. Smoke tests read the manifest the builder writes |

Every RISC Zero component is pinned to an exact version, and every version is declared
once, in `protocol/risc0-toolchain.env`. No Dockerfile repeats one:
`scripts/install-risc0-toolchain.sh` reads that file and installs exactly those
components, and `docker/swarm`, `docker/protocol-node` and `docker/bonsol-eval` all call
it. Four literals in three Dockerfiles is not a pin, it is three pins that agree until
someone edits one of them.

| Component | Version | Reaches |
| --- | --- | --- |
| `rust` (the guest toolchain) | `1.88.0` | every guest ELF; `risc0-build` sets `RUSTC` to it |
| `cpp` | `2024.1.5` | the guest ELF, through `CC` |
| `r0vm` | `3.0.3` | the id computation and local proving |
| `cargo-risczero` | `3.0.3` | the Bonsol build path |
| `risczero/risc0-guest-builder` | `sha256:3e12f71bacd27527a61dea96fa0e53e468c99aa261d3a1019b593f6dbd943eb3` | the Bonsol guest ELFs; applied by `protocol/scripts/run-bonsol-builder.sh`, which reads the digest from the same declaration |

Two things that are *not* on that list, because they were measured not to reach the
`zkvm-reducer` guest ELF at all: the Rust toolchain the workspace is built with, and
`CARGO_HOME`. Two things that are not versions but do reach it: the absolute path the
guest is compiled at, and the `$HOME` of the user compiling it. Both are declared in the
same file and enforced by `scripts/build-zkvm-guest.sh`, which is why
`protocol/zkvm-reducer/IMAGE_ID` now reproduces in every image that builds it. The
measurement is in `protocol/zkvm-reducer/IMAGE_ID.md`.

That last row is the one that actually decides a Bonsol guest ELF. `bonsol build` compiles
the guest inside `risczero/risc0-guest-builder:r0.1.88.0`, a tag `risc0-build 3.0.3`
hard-codes and upstream can move, so the builder script pulls it by digest, retags it
locally, and points `risc0-build` at the local tag with `RISC0_DOCKER_CONTAINER_TAG`.
Pinning `rzup` alone would not have been enough.

Both Bonsol guest ids above were confirmed by rebuilding them against those pins:

```
guest builder pinned to risczero/risc0-guest-builder@sha256:3e12f71b…43eb3 as :r0.1.88.0-pinned
Computed image_id: 785b584bc39a38d76e10fd0bb0c75cab62ae582497b577d03e6c1a9659204f4d
Computed image_id: 6017b38ca12ad7fbc9b4f9db6005b726e292c5d8dc4022e3130fe6654f66ccfb
```

The branch reducer's id differs from the `a41fa6df…4d39` recorded in the flagship demo
transcripts, and nothing in that guest's source changed: that id was produced before any
of this was pinned, when `rzup install` took the newest of everything. The transcripts
keep the id of the run they describe.

## RISC Zero Version And MSRV

Every crate pins risc0 `=3.0.3`:

| Crate | risc0 crates | Runs where |
| --- | --- | --- |
| `protocol/bonsol-aggregate-reducer` | `risc0-zkvm =3.0.3` | Bonsol node, Bonsol commit `25a590d09cca0404cc48ec028122df4d1a8c651b` |
| `protocol/zkvm-reducer` | `risc0-zkvm =3.0.3`, `risc0-build =3.0.3` | `docker/swarm` and `docker/protocol-node` images, both through `scripts/build-zkvm-guest.sh` |
| `protocol/bonsol-branch-reducer` | `risc0-zkvm =3.0.3` | Bonsol node (smoke tests only) |
| `protocol/bonsol-callback-harness` | `risc0-zkvm =3.0.3` (hash impl only) | Bonsol smoke test |

The transitive crates matter twice over.

**Host side.** `risc0-zkvm 3.0.3` declares caret requirements. The newer point releases
(`risc0-circuit-rv32im 4.0.4`/`4.0.5`, `risc0-zkp 3.0.4`/`3.0.5`) changed the
`SyscallContext` trait, and `risc0-zkvm 3.0.3` with the `prove` feature then fails to
compile. The committed lockfiles hold the set from the upstream risc0 v3.0.3 lockfile.

**Guest side.** The RISC Zero guest toolchain for the 3.0.3 line is rustc `1.88.0-dev`.
`ruint 1.20.0` needs 1.90 and `enum-ordinalize` / `-derive` 4.4.2 need 1.89, and
`bonsol build` fails outright on either:

```
error: rustc 1.88.0-dev is not supported by the following packages:
  enum-ordinalize@4.4.2 requires rustc 1.89
  ruint@1.20.0 requires rustc 1.90
```

`protocol/bonsol-aggregate-reducer/Cargo.lock` therefore holds `ruint 1.17.0` and
`enum-ordinalize` / `-derive 4.3.2`. Build with the committed lockfiles and raise them
only together with the rzup Rust toolchain.

## Configuration

| Variable | Component | Meaning |
| --- | --- | --- |
| `KSWARM_AGGREGATE_IMAGE_ID` | CLI | Override the pinned aggregate reducer image id for one run |
| `KSWARM_BONSOL_AGGREGATE_COMMAND` | aggregator runner | The Bonsol execution hook. Without it the runner refuses to claim an aggregate job |
| `KSWARM_BONSOL_HOOK_TIMEOUT_SECONDS` | aggregator runner | Hook timeout, default 1800 |
| `KSWARM_ALLOW_UNBOUND_AGGREGATE` | aggregator runner | `1` submits an aggregate receipt with no proof. Local clusters only; refused on devnet and mainnet |
| `KSWARM_ZKVM_HOST` | branch worker, verifier | Path to the `zkvm-reducer` host binary. The `branch-worker` and `verifier-worker` images default it to the binary they carry; unset means this worker proves no receipts and this verifier checks none |
| `KSWARM_ZKVM_TIMEOUT_SECONDS` | branch worker, verifier | Prove/verify timeout, default 1800 |
| `KSWARM_ZKVM_IMAGE_ID` | verifier | Pin the branch guest image id a receipt must name |
| `KSWARM_ZKVM_IMAGE_ID_FILE` | verifier | Where to read that pin when the variable is unset. The images point it at the id they were built with, so a container pins by default |
| `KSWARM_ZKVM_REQUIRE_RECEIPT` | verifier | `1` refuses to attest to a branch that carries no receipt. The swarm compose defaults it to `1`, because every worker in that stack proves |
| `KSWARM_BONSOL_HOOK_URL` | aggregator runner | The proving service `aggregator_runner.bonsol_http_hook` calls. See "Where proving runs" |

### What a verifier does when a receipt does not hold

- **Missing, and required.** The verifier does not attest. Nothing else follows on chain:
  the job reaches its challenge deadline unattested and `settle_job` pays the worker
  anyway, because settlement does not read the attestation. There is no branch cancel
  path. What refusal does buy is evidence -- no verifier put its name to the receipt --
  and the option to challenge instead, which the paragraph below covers.
- **Present but wrong, and re-execution also disagrees.** The verifier attests to its own
  re-execution hash. That makes the receipt challengeable and the daemon challenges: the
  worker is slashed. This is the only branch case in which the chain moves money against
  the worker, and it needs the verifier to be the one the customer or admin assigned.
- **Present but wrong, and re-execution agrees.** The verifier refuses to attest, because
  it will not put its name to a receipt whose proof does not hold. Refusing does not stop
  the job settling; it withholds the attestation and records why. An earlier version of
  this page said the job then could not settle. That was wrong.

Attesting is the act that arms the challenge path, so a verifier that refuses to attest
also gives up the only on-chain lever it has over that branch. Whether `settle_job` should
require a matching attestation before paying is the open item recorded above.

## Prove Cost

Measured on the build host (a 32-core x86-64 machine, CPU proving only, no GPU prover),
over a real branch of a two-branch run against `llama3.2:3b-instruct-q5_K_M`:

| Step | Input | Time | Output |
| --- | --- | --- | --- |
| `zkvm-reducer prove` | 967-byte guest input, 824-byte output document | **31.9 s** | 358 KB receipt bundle |
| `zkvm-reducer verify` | that bundle | **< 0.1 s** | the 68-byte journal |

Proving is tens of seconds per branch and verification is free, so the cost falls on the
worker, not the verifier.

A container proves by default: the `branch-worker` and `verifier-worker` images ship the
host binary and point `KSWARM_ZKVM_HOST` at it, and `docker-compose.swarm.yml` passes
that default through. Setting `KSWARM_ZKVM_HOST=` explicitly empty turns the proof path
off and the worker then publishes no receipt. Outside those images the variable is unset,
so a worker run from a checkout proves nothing until it is pointed at a binary.

The window still has to allow for it. A branch job whose execution window is shorter than
the prove time would be slashed for a proof it could not finish; the daemon will not start
an attempt inside `execute_deadline_margin_seconds` (120 by default, against a measured
31.9 s prove), and `docker-compose.swarm.yml` says so where the window is configured. The
358 KB bundle is pinned to IPFS next to a 824-byte output.

The aggregate proof is produced by the Bonsol node, which also compresses the receipt to
Groth16 for on-chain verification. That is the expensive half and it runs once per run,
not once per branch.

## No Per-Branch Model Proof

Until 2026-09-04 this tree carried a halo2/KZG circuit for a per-branch "score". Its
model was the fixed affine map `2 * line_count + 3 * word_count + 1` over two integers
read off the output document. It was never a submodel of anything kswarm runs, nothing on
the release path called it, and a valid proof of it said only that someone had evaluated
a two-term linear function on two public numbers. It has been taken out of the source
tree and out of the container image, along with the third-party proving package it needed
-- a package whose repository ships **no licence file** while its documentation asserts
that commercial use requires one.

Nothing replaces it, because nothing can yet. The conditions for a per-branch model proof
to enter the release path are unchanged and none of them is met:

1. a model that is genuinely part of branch execution, or a scorer whose verdict about a
   branch document is worth binding to that document;
2. a prover that can handle it, on a licence that permits shipping it in a worker image;
3. proving cost inside a branch's execution window; and
4. a verifier that binds the proof's public values to the branch output the way
   `worker/verifier_worker` binds the zkVM receipt today.

Condition 2 is the binding one, and it is commercial rather than technical. Until all
four hold, this page claims no model proof at all.

## How To Run The Checks

```bash
# Shared rules, both journal layouts, and the cross-language vectors
cd protocol/bonsol-aggregate-reducer && cargo test

# The Python mirror against the same vectors
cd cli && uv run pytest tests/test_aggregate_artifact.py -q

# Worker daemons: aggregate binding, receipt verification, binding failures
cd worker && uv run pytest -q

# Legacy branch reducer and the callback harness
cd protocol/bonsol-branch-reducer && cargo test
cd protocol/bonsol-callback-harness && cargo test

# Off-chain zkVM host and guest against risc0 3.0.3 (no guest ELF build)
cd protocol/zkvm-reducer && RISC0_SKIP_BUILD=1 cargo check -p host

# Guest images, and the pin
protocol/scripts/build-aggregate-reducer.sh --check
```
