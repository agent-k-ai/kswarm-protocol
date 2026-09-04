# kswarm — Escrow & Slashing Security Remediation Spec

**Status:** C1, H1, and H2-Interim shipped in PR #5 (`feat/consolidate-01.09.03`,
2026-09-03). PR-3 (`fix/slash-accounting`) extends H2-Interim to every job class and
closes the accounting findings listed in §12. H2-Full (§5.3) remains open.
**Target:** `solana/programs/kswarm_protocol/src/lib.rs` (3629 lines) on branch
`release-01.07.10a` (== `integration`, == phase0h program).
**Author:** verified against source 2026-07-11 (every line number, struct, field,
and constraint below was read from the current file, not from a prior summary).
**Companion:** the protocol review of 2026-07-10 (the review that
surfaced these findings).

---

## 0. Executive summary

Three authorization defects in the escrow/slashing program let a crafted
transaction steal rewards, slash innocent workers, and challenge honest receipts
at zero cost. They are masked in normal operation only because the honest
JS/Rust clients always pass the correct accounts; the on-chain program is the sole
trust boundary, so a hand-built transaction bypasses that masking.

| ID | Severity | One-line | Fix effort |
|----|----------|----------|-----------|
| **C1** | CRITICAL | Settlement/slash never bind the payout `worker` to `job.worker` → reward theft + slashing of innocent workers | Mechanical: 1 constraint × 6 structs + 1 error |
| **H1** | HIGH | `ChallengeJob` (and `SlashStaleJob`) `worker_stake_vault` unconstrained → force an honest receipt "challengeable" | Mechanical: 1 constraint × 2 structs + 1 error |
| **H2** | HIGH | Verifier posts no bond and bears no risk → free / self-dealing / false-positive slashing | Design: interim guard now + full dispute system next |
| **D1** (PR-3) | HIGH | `slash_stale_job` paid escrow + stake but set no settlement flag → `claim_customer_slash_compensation` drained a second `required_stake` | Set every flag; claims reject with `SlashAlreadySettled` |
| **D2** (PR-3) | MED/HIGH | Attested aggregate job with no Bonsol marker locked escrow and stake forever; the exhaustion cancel also never released the worker's stake | 24 h marker-timeout cancel; both cancel paths unlock stake |
| **D3** (PR-3) | MED | H2-Interim never applied to `DeterministicBasic` / `BranchProof` (`assign_verifier` rejected them) → free slash | Assigned verifier required for every class |
| **D4** (PR-3) | MED | `open_job` did not force `AggregateProof ⇔ AGGREGATE_PROOF_CAPABILITY_HASH` | Pairing check in `open_job` |
| **D5** (PR-3) | LOW | `initialize_protocol` permissionless (first caller = admin) | Admin must be the program upgrade authority |
| **D6** (PR-3) | LOW | Anchor-dispatched `record_aggregate_verification` unreachable | Deleted; raw `fallback` is the only path |

**Corrections to the 2026-07-10 review, found while re-reading source (details in §7):**
1. **C1 affects six account structs, not five** — the review's list omitted
   `SettleAggregateProofJob` (lib.rs:1151), which pays a worker with no `job.worker`
   binding via `pay_worker_for_job` (lib.rs:500).
2. **The "zero `expected_result_hash` footgun" (review M1) does NOT exist in this
   program** — `receipt_is_challengeable` already guards it with `!= EMPTY_HASH`
   (lib.rs:2456). The Q1 "empty expected_result_hash challenge-path tightening"
   already fixed it. It must not be re-listed as an open issue.
3. **Events partially exist (review M4 overstated).** `emit!` is present for
   attestation (lib.rs:375) and aggregate cancel (lib.rs:546), though not for
   settle/slash. Minor, out of scope here.
4. **`SlashStaleJob.worker_stake_vault` (lib.rs:1458) is also unconstrained** —
   an H1-class gap the review noted only for `ChallengeJob`. Folded into H1 (§4.3).

---

## 1. Scope, target, and verification method

In scope: C1, H1, H2 and the adversarial test coverage that would have caught
them. Everything else (see §7) is explicitly deferred, not silently dropped.

Every claim below cites a line verified in the current
`solana/programs/kswarm_protocol/src/lib.rs`. Test references are verified
against `tests/anchor_integration/src/lib.rs` (harness) and
`tests/anchor_integration/tests/tier1_q1_slash_flow.rs`.

---

## 2. Trust model each finding protects

- **C1** protects **fund custody**: the reward escrow must pay only the worker who
  performed the job, and a worker's stake must be slashable only for that worker's
  own misbehavior. C1 breaks the binding between a `Job` and the worker identity
  recorded on it.
- **H1** protects **challenge integrity**: whether a receipt is slashable must be a
  function of the *actual* on-chain state of the *actual* worker, not of
  attacker-supplied inputs. H1 lets an attacker feed a fake stake reading.
- **H2** protects **verifier accountability**: a party that triggers a slash must
  have something at stake, so that honest workers are not slashed by cost-free,
  mistaken, or self-dealing challenges — the failure mode the LLM-determinism work
  already flagged ([llm-bridge-honest-limits](https://github.com/agent-k-ai/kswarm/blob/main/docs/llm-bridge-honest-limits.md), in the `kswarm` repository).

---

## 3. Finding C1 — `job.worker` is never enforced in settlement/slash (CRITICAL)

### 3.1 Root cause (verified)

`job.worker` is written once, at claim (`claim_job`):

```
lib.rs:288   job.worker = ctx.accounts.authority.key();
```

and read for authorization in exactly two places — `submit_receipt`:

```
lib.rs:317-320   require!(job.worker == ctx.accounts.authority.key(),
                          ProtocolError::WrongWorker);
```

and the verifier self-attestation guard (`validate_verifier_attestation`,
`job_worker_authority` = `job.worker`, lib.rs:362 → 2429). It is **never** checked
in any settlement or slash instruction. In each of those, the `worker` account is
validated only against *itself*:

```
seeds = [b"worker", worker_authority.key().as_ref()],
constraint = worker.authority == worker_authority.key()   // self-referential
```

with `worker_authority` pinned to `worker.authority` (`address = worker.authority`).
Nothing ties that worker to the `job`.

### 3.2 What `job.worker` holds (decides the fix form)

`job.worker` stores the **worker's authority pubkey** (the signer/wallet key), not
the `Worker` PDA address — proven by the assignment `job.worker =
ctx.accounts.authority.key()` (lib.rs:288) and the field type `pub worker: Pubkey`
(lib.rs:1494). Therefore:

- `has_one = worker` would be **wrong** (it compares `job.worker` to the `worker`
  *PDA* key, but `job.worker` is the *authority*).
- The correct, minimal binding is **`worker.authority == job.worker`**, placed on
  the `worker` account. Because each struct already pins `worker_authority` to
  `worker.authority` and derives the payout ATA / stake vault from it, binding
  `worker.authority == job.worker` transitively pins the authority, the payment
  account, and the stake vault to the job's recorded worker.

### 3.3 Affected paths — completeness argument (SIX structs)

Every instruction that pays a worker from escrow **or** mutates/among a worker's
stake reads a caller-supplied `worker` with no `job.worker` binding. Enumerated:

| # | Instruction (handler) | Struct (worker acct line) | Worker-linked effect | Verified |
|---|---|---|---|---|
| 1 | `settle_job` (554) | `SettleJob` (worker @1357) | reward→worker ATA (583-596); stake unlock (598-609) | ✗ vuln |
| 2 | `settle_aggregate_proof_job` (486) | `SettleAggregateProofJob` (worker @1171) | `pay_worker_for_job` (500-511); stake unlock (513-524) | ✗ vuln **(review missed)** |
| 3 | `challenge_job` (614) | `ChallengeJob` (worker @1219) | challengeability judged on this worker (643-650); `active_claims` dec (656-661) | ✗ vuln |
| 4 | `claim_verifier_slash_reward` (695) | `ClaimVerifierSlashReward` (worker @1290) | drains `worker_stake_vault` (707-717) | ✗ vuln |
| 5 | `claim_customer_slash_compensation` (730) | `ClaimCustomerSlashCompensation` (worker @1330) | drains `worker_stake_vault` (748-758) | ✗ vuln |
| 6 | `slash_stale_job` (810) | `SlashStaleJob` (worker @1455) | drains `worker_stake_vault` (853-866); stake/claims dec (868-879) | ✗ vuln |

Paths deliberately **excluded** (verified safe, no `job.worker` relevance):
`deposit_worker_stake` and `withdraw_unlocked_stake` are self-service (the worker
authority signs; not job-linked); `claim_job` sets `job.worker` to the signer and
locks the signer's own stake; the customer-side `cancel_open_job` /
`cancel_aggregate_proof_job` / `refund_slashed_job_escrow` touch no worker account.

In all six affected structs, the `job` account is declared **before** the `worker`
account (job lines 1162, 1212, 1274, 1314, 1350, 1439; worker lines 1171, 1219,
1290, 1330, 1357, 1455), so an Anchor constraint on `worker` may reference
`job.worker`.

### 3.4 The fix

Add one constraint line to the `worker` account in each of the six structs. Example
— `SettleJob` (lib.rs:1351-1357):

```rust
// BEFORE
#[account(
    mut,
    seeds = [b"worker", worker_authority.key().as_ref()],
    bump = worker.bump,
    constraint = worker.authority == worker_authority.key() @ ProtocolError::WrongWorkerAuthority
)]
pub worker: Box<Account<'info, Worker>>,

// AFTER
#[account(
    mut,
    seeds = [b"worker", worker_authority.key().as_ref()],
    bump = worker.bump,
    constraint = worker.authority == worker_authority.key() @ ProtocolError::WrongWorkerAuthority,
    constraint = worker.authority == job.worker @ ProtocolError::JobWorkerMismatch
)]
pub worker: Box<Account<'info, Worker>>,
```

Apply the identical added line to the `worker` account in all six structs:
`SettleAggregateProofJob` (@1171), `ChallengeJob` (@1219),
`ClaimVerifierSlashReward` (@1290), `ClaimCustomerSlashCompensation` (@1330),
`SettleJob` (@1357), `SlashStaleJob` (@1455).

No handler-side `require!` is needed — the constraint fully expresses the binding.

### 3.5 New error variant

Add to `enum ProtocolError` (starts lib.rs:2498):

```rust
#[msg("worker account does not match the job's claimed worker")]
JobWorkerMismatch,
```

(Reusing the existing `WrongWorker` (lib.rs:319 msg "wrong worker") is acceptable,
but a distinct variant gives a precise audit signal that the *settlement/slash*
binding failed rather than the submit-time check. Recommendation: new variant.)

### 3.6 Before/after attack analysis

- **Reward theft (paths 1, 2).** *Before:* an attacker who owns any `Worker` with
  `locked_stake ≥ job.required_stake` and `active_claims ≥ 1` front-runs the honest
  settle, passing their own `worker`/`worker_payment_account`; the reward is paid to
  them and the honest worker's stake stays locked forever (the honest worker never
  reaches settle). *After:* `worker.authority == job.worker` fails →
  `JobWorkerMismatch`; only the job's worker can be settled.
- **Innocent-worker slashing (paths 4, 5, 6).** *Before:* once any job is `Slashed`,
  the attacker passes an unrelated victim `worker` (whose `stake_vault` is pinned by
  `address = worker.stake_vault`) and drains it. *After:* the victim's
  `worker.authority != job.worker` → `JobWorkerMismatch`.
- **Forced challenge (path 3), see also H1.** *Before:* the attacker passes a
  low-eligibility `worker` so `receipt_is_challengeable` trips on role/tier/etc.
  *After:* the worker is pinned to `job.worker`, so the predicate is evaluated on
  the real worker (and H1 pins the vault).

### 3.7 Regression safety

The honest clients already pass the job's worker (the tier1 suite calls
`settle_job(&job.customer, &worker, &job)` etc. with the same `worker` that
completed the job), so `worker.authority == job.worker` holds and every existing
test stays green. Verified against `tier1_q1_slash_flow.rs:48,94,100,103`.

---

## 4. Finding H1 — unconstrained `worker_stake_vault` in the challenge path (HIGH)

### 4.1 Root cause

`ChallengeJob.worker_stake_vault` (lib.rs:1222-1223) is declared with only
`#[account(mut)]` — no `address = worker.stake_vault`:

```rust
#[account(mut)]
pub worker_stake_vault: InterfaceAccount<'info, TokenAccount>,
```

Contrast `ClaimVerifierSlashReward` (lib.rs:1293) and
`ClaimCustomerSlashCompensation` (lib.rs:1333), which correctly pin it with
`#[account(mut, address = worker.stake_vault)]`.

### 4.2 Data flow into the tier decision

`challenge_job` passes `worker_stake_vault.amount` straight into the predicate:

```
lib.rs:643-648   receipt_is_challengeable(job, &ctx.accounts.worker,
                                          ctx.accounts.worker_stake_vault.amount)
```

and inside it (lib.rs:2476):

```
if derive_stake_tier(worker_stake_amount) < job.required_tier { return true; }
```

`derive_stake_tier(0)` returns `0` (lib.rs:1689-1699), which is `< 1` (any real
tier), so a **zero/low-balance token account forces the predicate `true`** even for
a fully-honest, correct receipt — the challenge succeeds and the honest worker is
moved to `Slashed` (lib.rs:662).

### 4.3 The fix

Pin the vault to the worker's registered stake vault in both structs that read/spend
it without a pin:

```rust
// ChallengeJob (lib.rs:1222-1223)  — vault is only READ here; `mut` may also be dropped
#[account(mut, address = worker.stake_vault @ ProtocolError::WrongWorkerStakeVault)]
pub worker_stake_vault: InterfaceAccount<'info, TokenAccount>,

// SlashStaleJob (lib.rs:1458-1459)  — vault is the transfer source (853-866); keep `mut`
#[account(mut, address = worker.stake_vault @ ProtocolError::WrongWorkerStakeVault)]
pub worker_stake_vault: InterfaceAccount<'info, TokenAccount>,
```

Add the error variant:

```rust
#[msg("stake vault does not match the worker's registered stake vault")]
WrongWorkerStakeVault,
```

`Worker.stake_vault` is the canonical field (lib.rs:1478), set at registration. The
`claim_*` structs already pin against it, so this simply makes `ChallengeJob` and
`SlashStaleJob` consistent. (Optionally upgrade the two `claim_*` bare pins to the
same `@ WrongWorkerStakeVault` for uniform diagnostics — not required for
correctness.)

### 4.4 Interaction with C1 — both are required

H1 pins the *vault amount* to the real worker; C1 pins the *worker* to the job.
Only together do they guarantee the challenge predicate is evaluated on the genuine
`(job.worker, its real stake)`. With C1 fixed but not H1, an attacker still feeds a
fake vault for the *correct* worker; with H1 fixed but not C1, an attacker still
supplies a different low-eligibility worker. Land them together.

### 4.5 Note: legitimate post-claim tier drop (not a bug, keep in mind)

Even after the fix, the tier branch (lib.rs:2476) can legitimately fire if a worker
withdrew stake after claiming: `withdraw_unlocked_stake` allows withdrawal down to
`locked_stake`, and if `required_stake < TIER_n_STAKE_FLOOR` the vault can drop
below the tier it claimed at. That makes the receipt genuinely challengeable, which
is arguably correct (the worker no longer meets the job's tier). No change proposed;
documented so reviewers don't mistake it for a regression.

---

## 5. Finding H2 — the verifier has no bond at risk (HIGH; design decision)

### 5.1 What C1 + H1 already close, and what remains

After C1 + H1, `receipt_is_challengeable` can only return `true` for the genuine
`job.worker` evaluated against its real state, and `challenge_job` reverts if the
predicate is `false` (lib.rs:643-650). So an attacker **can no longer force a
challenge on an honest, correct, deterministic receipt.** That removes the sharpest
edge. Three residual risks survive:

### 5.2 The residual risk (why H2 still matters)

1. **False-positive slashing of honest workers on non-deterministic jobs.** For
   jobs whose correctness is *not* on-chain-decidable (Tier A scalars snapped to
   basis points, Tier B narratives), a challenge fires via an attestation-hash
   mismatch (lib.rs:2462-2468). [llm-bridge-honest-limits](https://github.com/agent-k-ai/kswarm/blob/main/docs/llm-bridge-honest-limits.md), in the `kswarm` repository, documents that an
   honest worker and honest verifier can land in different basis-point buckets — a
   genuine false positive. Today the challenging verifier risks **nothing**
   (`challenge_job` checks `verifier_available >= FLOOR && >= challenge_bond` at
   lib.rs:640 but never locks or transfers it), and there is no counterslash, so the
   honest worker is slashed with the verifier bearing no cost.
2. **Self-dealing.** An operator running a worker identity and a verifier identity
   can have the worker submit a deliberately bad receipt and the verifier reclaim
   its stake (`verifier_reward = min(required_stake, challenge_bond)`, lib.rs:705).
   Net loss to the operator ≈ gas; the customer's compute cycle is wasted.
3. **No skin-in-the-game.** Nothing rate-limits or prices challenges.

Note the customer-set `challenge_bond` (lib.rs:129,182) is **not** a verifier bond —
it only *caps the verifier's reward* (lib.rs:705,742) and gates
`customer_slash_paid` (lib.rs:651). The verifier's own stake is never locked. This
is exactly the deferred work flagged in-code:

```
lib.rs:2424-2425   // Phase 2 TODO: lock verifier stake during the attestation
                   // window and add counterslash handling. Phase 1 only checks
                   // available stake.
```

### 5.3 Recommended full design (H2-Full) — bond lock + dispute window + counterslash

A genuine fix requires the challenger to stake a bond that is forfeited when a
challenge is adjudicated wrong. Because challenge validity is on-chain-decidable for
deterministic jobs but not for attestation-based ones, treat them differently.

**State additions.**
- `enum JobStatus` (lib.rs, `JobStatus`): add `Challenged`.
- `struct Job` (lib.rs:1490): add `challenger_authority: Pubkey`,
  `challenger_bond_locked: u64`, `dispute_deadline: i64` (+~48 bytes; re-query
  `getMinimumBalanceForRentExemption` and bump `#[derive(InitSpace)]` accordingly).
- New constant `DISPUTE_WINDOW_SECONDS: i64` and `CHALLENGER_BOND_FLOOR: u64` (or
  reuse `job.required_stake` as the required bond — see §5.6).

**Flow.**
1. `challenge_job` (rewrite): require `verifier_available >= CHALLENGER_BOND` and
   **lock it** (`verifier.locked_stake += bond`); record `challenger_authority`,
   `challenger_bond_locked`; set `status = Challenged`, `dispute_deadline = now +
   DISPUTE_WINDOW_SECONDS`. Do **not** pay out yet.
   - Deterministic job (`expected_result_hash != EMPTY`): validity is provable
     on-chain (`submitted != expected`), so it MAY skip the window and settle the
     slash immediately, returning the bond to the challenger.
2. New `defend_receipt` (callable by `job.worker`, before `dispute_deadline`, for
   attestation-based jobs): triggers a **second independent verifier** attestation
   (a different authority than both the worker and the original challenger). If the
   second verifier's recomputed hash matches the worker's submission, the challenge
   is ruled **invalid**.
3. New `resolve_challenge` (permissionless, after `dispute_deadline`):
   - Challenge upheld (or no valid defense) → `status = Slashed`; challenger bond
     released; proceed to the existing `refund/claim_verifier_slash_reward/
     claim_customer_slash_compensation` payout path.
   - Challenge ruled invalid → **counterslash**: `challenger_bond_locked` is
     forfeited from the challenger (split worker/protocol per policy) and the job
     returns to `Completed` for normal settlement.

**Interactions.** This composes with the R3 assignment flow (lib.rs:442-484): the
`assigned_verifier_authority` is the natural challenger and the second-opinion
verifier is the natural adjudicator. It does **not** touch the aggregate/Bonsol
settlement path (`settle_aggregate_proof_job`), which is proof-gated, not
challenge-gated.

**Economic reasoning.** A challenger now risks `CHALLENGER_BOND` on every challenge;
an honest challenge costs nothing (bond returned), a wrong one forfeits the bond to
the wronged worker. That prices out false-positive and self-dealing challenges while
preserving cheap honest verification.

H2-Full is a real protocol change (new state, two new instructions, a rewrite of
`challenge_job`, new tests). **It must ship as its own PR with its own test suite,
separate from the C1/H1 critical fix.**

### 5.4 Interim (H2-Interim) — ship alongside C1/H1

Two additive guards in `challenge_job` (lib.rs:614), no new state:

```rust
// after the existing role/status/bond checks, before receipt_is_challengeable:
require!(ctx.accounts.caller.key() != job.worker, ProtocolError::SelfChallengeForbidden);
if let Some(assigned) = job.assigned_verifier_authority {
    require!(ctx.accounts.caller.key() == assigned, ProtocolError::VerifierNotAssigned);
}
```

- The first blocks the same-key self-challenge.
- The second ties a challenge on an assigned job to the customer/protocol-assigned
  verifier (reusing the existing `VerifierNotAssigned`, lib.rs:2434), so a worker's
  operator cannot self-challenge unless it also controls the assigned-verifier slot.

Add the error:

```rust
#[msg("a worker cannot challenge its own job")]
SelfChallengeForbidden,
```

Interim limits: it does **not** give the verifier skin-in-the-game and does **not**
stop a two-identity operator on an *unassigned* job. Full mitigation of
false-positive slashing needs H2-Full; complete self-deal prevention additionally
needs operator-identity binding (the PoDI `DeviceSlotCounter` work,
the PoDI integration spec, §8) — out of scope here.

**PR-3 amendment (2026-09-03).** The guard above only fired when a verifier was
assigned, and `assign_verifier` rejected every class except `AggregateProof`, so for
`DeterministicBasic` and `BranchProof` jobs any verifier with the floor stake could
post a false attestation and challenge at zero cost (`tier1_q1_full_slash_mismatch`
codified this). PR-3 makes the rule unconditional:

```rust
// challenge_job, for every job class:
validate_challenge_authorization(caller, job.worker, job.assigned_verifier_authority)?;
//   caller == job.worker            -> SelfChallengeForbidden
//   assigned_verifier is None       -> ChallengeRequiresAssignedVerifier
//   assigned_verifier != caller     -> VerifierNotAssigned
```

`assign_verifier` and `reassign_verifier` now accept every job class (the class check
is gone; `assign_verifier` additionally rejects terminal jobs). Attestation stays
permissionless: an attestation alone moves no funds. On a non-aggregate job a false
attestation does not block `settle_job`; on an aggregate job settlement needs a
matching attestation plus the Bonsol marker, and the customer can recover through the
marker-timeout cancel (§12, D2). Residual: a rogue attestation can occupy the single
attestation slot of an aggregate job (liveness griefing, no fund loss); H2-Full or a
multi-attestation design closes it.

H2-Full was not attempted in PR-3 because no sound vindication rule exists without a
re-execution oracle: a "second verifier" or "customer confirms" adjudicator lets a
worker/verifier or worker/customer sybil pair forfeit an honest challenger's bond, which
is worse than no bond. It stays a separate milestone after PR-6 (`feat/worker-trust`).

### 5.5 Resolving the in-code "Phase 2 TODO"

Replace the bare comment at lib.rs:2424-2425 with a pointer to this spec (§5.3) and
ship H2-Interim now. The TODO becomes a tracked plan rather than a dangling note.

### 5.6 Judgment calls (user decisions — override as you see fit)

- **Recommended:** ship **C1 + H1 + H2-Interim** in the critical-fix PR; schedule
  **H2-Full** as the next protocol milestone with its own spec + tests. Rationale:
  C1/H1 are the exploitable defects and are mechanical; H2-Full is a redesign that
  should not be rushed into the same PR.
- **Open parameters for H2-Full:** the challenger bond amount (`= job.required_stake`
  vs a new `CHALLENGER_BOND_FLOOR`), `DISPUTE_WINDOW_SECONDS`, and the counterslash
  split (worker vs protocol). These are economic-policy choices for you/governance.

---

## 6. Adversarial test plan

All tests are `#[serial]`, `#![cfg(feature = "tier1")]`, in a new file
`tests/anchor_integration/tests/tier1_authz_adversarial.rs`, using the existing
harness idioms (`run_tier1_test`, `register_participant`, `complete_job`,
`assert_anchor_error`, verified in `tests/anchor_integration/src/lib.rs`). Each test
below **fails on current code (proving the bug) and passes after the fix** — stated
per test.

### 6.1 New harness helpers required

The existing `challenge_job` helper (src/lib.rs:605) derives `worker_stake_vault`
from the worker, so the H1 fake-vault attack cannot be expressed with it. Add one
helper that takes an explicit vault:

```rust
pub async fn challenge_job_with_stake_vault(
    &mut self, verifier: &Participant, worker: &Participant,
    job: &TestJob, worker_stake_vault: Pubkey,
) -> Result<(), BanksClientError>   // identical body to challenge_job (605-631),
                                    // but `worker_stake_vault` is the passed arg
```

Everything else (worker substitution) is expressible today because `settle_job`
(549), `settle_aggregate_proof_job` (576), `challenge_job` (605),
`claim_verifier_slash_reward` (658), `claim_customer_slash_compensation` (687) all
already take an explicit `worker: &Participant`.

### 6.2 Test matrix

**C1-1 `settle_job` reward theft.** Setup: `victim` completes a default job to
`Completed`; `attacker` registers and claims its *own* job so
`attacker.locked_stake ≥ required_stake, active_claims ≥ 1` (required, else the
current code fails with `MathOverflow` and masks the bug). Warp past the victim
job's challenge deadline. Call `settle_job(&attacker.authority, &attacker,
&victim_job)`. **Assert** `assert_anchor_error(err, ProtocolError::JobWorkerMismatch)`.
*Current:* returns `Ok` (reward paid to attacker) → test fails. *Fixed:* `Err(JobWorkerMismatch)`.

**C1-2 `settle_aggregate_proof_job` reward theft.** Setup: build an aggregate job
(`JobSpec::aggregate()`) to `Completed` with a valid marker
(`valid_bonsol_marker_for_job` + `store_bonsol_marker`, src/lib.rs:807,902); attacker
worker with locked stake as in C1-1. Call `settle_aggregate_proof_job(&attacker.authority,
&attacker, &agg_job, marker)`. **Assert** `JobWorkerMismatch`. *Current:* `Ok`. *Fixed:* `Err`.

**C1-3 `claim_verifier_slash_reward` drains an innocent worker.** Setup: legitimately
slash `victimA`'s job (reuse the `tier1_q1_full_slash_mismatch` sequence up to
`challenge_job`); register unrelated `victimB` with stake. Call
`claim_verifier_slash_reward(&verifier.authority, &verifier, &victimB, &job)`.
**Assert** `JobWorkerMismatch`. *Current:* `Ok` (drains victimB's `stake_vault`) →
fails. *Fixed:* `Err`.

**C1-4 `claim_customer_slash_compensation` drains an innocent worker.** As C1-3 but
call `claim_customer_slash_compensation(&job.customer, &victimB, &job)`. **Assert**
`JobWorkerMismatch`.

**C1-5 `slash_stale_job` slashes an innocent worker.** Setup: `victimA` claims a job
and lets `execute_deadline` pass (warp); register `victimB` with stake. Call
`slash_stale_job` with `worker = victimB` (add a harness helper mirroring the others
if none exists — `slash_stale_job` is currently exercised only via JS/watcher, so
this is also the first Rust coverage of that path). **Assert** `JobWorkerMismatch`.
*Current:* `Ok` (drains victimB). *Fixed:* `Err`.

**H1-1 fake-vault forces an honest challenge.** Setup: `worker` (WorkerBasic,
`WORKER_STAKE_DEPOSIT`) completes a `JobSpec::default()` job with the correct result
— note `expected_result_hash == ZERO_HASH` (src/lib.rs:97) so the hash branch is
skipped, and with the *real* vault the receipt is **not** challengeable. Register a
`verifier`. Create a zero-balance mswim token account `fake = env.create_ata(some_owner)`
(src/lib.rs:203). Call `challenge_job_with_stake_vault(&verifier, &worker, &job,
fake)`. **Assert** `ProtocolError::WrongWorkerStakeVault`. *Current:* `Ok` — job
goes to `Slashed`, an honest worker is slashed (the core H1 proof) → test fails.
*Fixed:* `Err(WrongWorkerStakeVault)`.

**H1-2 `slash_stale_job` fake vault.** Setup: a claimed job past `execute_deadline`;
call `slash_stale_job` with a `fake` zero vault for the real worker. **Assert**
`WrongWorkerStakeVault`. *Current:* transfers `required_stake` from an
attacker-chosen account / desyncs accounting; *Fixed:* `Err`.

**H2i-1 self-challenge blocked.** Setup: a worker that is *also* registered as role
`Verifier` cannot exist (single `role`), so model the same-key case by having the
job's worker authority attempt `challenge_job` as caller (construct the ix with
`caller = worker.authority`, `verifier = worker.worker`). **Assert**
`SelfChallengeForbidden`. *Current (interim not yet applied):* would proceed past the
self-check; *Fixed:* `Err`. (Only meaningful once H2-Interim lands.)

**H2i-2 non-assigned verifier blocked.** Setup: an aggregate/assigned job with
`assign_verifier(V1)` (src/lib.rs:509); a different verifier `V2` calls
`challenge_job`. **Assert** `VerifierNotAssigned`. *Fixed:* `Err`; *Current:* `Ok`.

### 6.3 Positive regressions (must stay green)

Re-run and keep passing, unmodified: `tier1_q1_full_slash_happy` and
`tier1_q1_full_slash_mismatch` (`tier1_q1_slash_flow.rs:9,67`) — they pass the
correct worker and (for mismatch) an unassigned job with a distinct verifier, so
neither the C1 constraint nor the H2-Interim guards trip. Add one explicit positive:
**settle with the correct worker still succeeds** after the C1 constraint (a focused
duplicate of the happy path asserting `JobStatus::Settled`).

---

## 7. Adjacent observations — NOT silently dropped (out of scope for this spec)

1. **Corrections to the 2026-07-10 review** (already itemized in §0): C1 is 6
   structs not 5; the zero-`expected_result_hash` footgun is already fixed
   (lib.rs:2456 has the `!= EMPTY_HASH` guard); some `emit!` events exist
   (lib.rs:375,546); `SlashStaleJob` vault gap folded into H1.
2. **Escrow-vault accounts are not explicitly constrained** (defense-in-depth).
   `job_escrow_vault` in `SettleJob` (1360), `SettleAggregateProofJob` (1174),
   `cancel_open_job` (1390), `slash_stale_job` — `#[account(mut)]` only. They are
   bounded today by the job-PDA transfer authority + `transfer_checked` mint pinning,
   so not directly exploitable, but should get an explicit
   `associated_token::authority = job` (or equivalent) in a hardening pass.
3. **No account closing / rent reclamation, no worker deactivation** (review M2/M3)
   — real pre-testnet items, tracked separately.
4. **H2-Full** (§5.3) is the deferred design PR.

---

## 8. Implementation order

1. Add error variants `JobWorkerMismatch`, `WrongWorkerStakeVault`,
   `SelfChallengeForbidden` to `ProtocolError` (lib.rs:2498).
2. **C1:** add `constraint = worker.authority == job.worker @ JobWorkerMismatch` to
   the `worker` account in all six structs (§3.4).
3. **H1:** add `address = worker.stake_vault @ WrongWorkerStakeVault` to
   `ChallengeJob.worker_stake_vault` (1222) and `SlashStaleJob.worker_stake_vault`
   (1458).
4. **H2-Interim:** add the two guards to `challenge_job` (§5.4); repoint the
   lib.rs:2424 comment to this spec.
5. Add the harness helper `challenge_job_with_stake_vault` (+ a `slash_stale_job`
   helper if absent) and the `tier1_authz_adversarial.rs` suite (§6).
6. Build; run tier1; confirm the new tests pass and the existing suite is green.

Steps 2–4 are independent edits to the same file; do them together. H2-Full is a
separate, later PR.

## 9. Verification steps

```bash
# from repo root, on release-01.07.10a / integration
anchor build                                   # or: cargo build-sbf
cargo test --package anchor_integration --features tier1 -- --test-threads=1
```

Definition of done for the run:
- The eight new adversarial tests (§6.2) pass.
- The full existing tier1 suite (26 integration + in-file unit tests) stays green.
- To *prove the bugs first*: check out the fix commit's parent, run the new suite,
  and confirm C1-*/H1-* **fail** (attack succeeds) — this demonstrates the tests are
  real, not vacuous. Documented, not automated.

## 10. Acceptance criteria (per finding)

- **C1 — done when:** all six settle/slash structs reject a `worker` whose
  `authority != job.worker` with `JobWorkerMismatch`; C1-1..C1-5 pass; happy/mismatch
  regressions green.
- **H1 — done when:** `ChallengeJob` and `SlashStaleJob` reject any
  `worker_stake_vault != worker.stake_vault` with `WrongWorkerStakeVault`; H1-1/H1-2
  pass; an honest correct receipt is provably un-challengeable via a fake vault.
- **H2-Interim — done when:** `challenge_job` rejects a self-challenge
  (`SelfChallengeForbidden`) and a non-assigned challenger on an assigned job
  (`VerifierNotAssigned`); H2i-1/H2i-2 pass; the lib.rs:2424 TODO points to §5.3.
- **H2-Full — tracked separately** with its own acceptance criteria.

## 12. PR-3 `fix/slash-accounting` status (2026-09-03)

| Item | Finding | Rule shipped | Tests |
|------|---------|--------------|-------|
| D1 | Double slash after `slash_stale_job` | `finalize_stale_slash` sets `escrow_refunded`, `verifier_reward_paid`, `customer_slash_paid`, `slash_settled`; the three claim contexts add `constraint = !job.slash_settled @ SlashAlreadySettled`; event `StaleJobSlashed` | `tier1_slash_accounting::slash_accounting_stale_slash_*` (4), unit `test_finalize_stale_slash_sets_every_settlement_flag` |
| D2 | Permanent fund lock on the aggregate path | `cancel_aggregate_proof_job` accepts a second reason: `now > challenge_deadline + AGGREGATE_MARKER_TIMEOUT_SECONDS` (24 h) while the job is still `Completed`, regardless of attestation or registry state. Status `CancelledOnTimeout`, event `AggregateProofJobCancelledOnTimeout`. Both cancel reasons now bind the worker (`JobWorkerMismatch`) and call `release_worker_claim`. The program cannot observe marker absence (the marker PDA is keyed by an off-chain execution id); the time rule gives the worker the whole grace period after settlement first becomes possible. | `tier1_slash_accounting::slash_accounting_timeout_cancel_*` (5), `tier1_r3_cancel_after_exhaustion` (stake unlock), unit `test_cancel_aggregate_proof_job_timeout_path` |
| D3 | Free slash on non-aggregate classes | Assigned verifier required for every class (§5.4 amendment) | `authz_h2i_unassigned_challenge_rejected_for_basic_job`, `authz_h2i_assigned_verifier_challenges_branch_proof`, `authz_h2i_verifier_cannot_self_assign`; `tier1_q1_full_slash_mismatch` now assigns first; unit `test_validate_challenge_authorization_requires_assigned_verifier` |
| D4 | `open_job` class/capability pairing | `validate_job_class_capability`: `AggregateProof ⇔ AGGREGATE_PROOF_CAPABILITY_HASH`, error `AggregateCapabilityMismatch` | `tier1_lifecycle_gaps::lifecycle_open_job_*` (2), unit `test_validate_job_class_capability_requires_matching_pair` |
| D5 | Permissionless `initialize_protocol` | Context takes `program: Program<KswarmProtocol>` and `program_data: Account<ProgramData>`; `validate_upgrade_authority` requires `program.programdata_address() == Some(program_data)` (`ProgramDataMismatch`) and `program_data.upgrade_authority_address == Some(admin)` (`AdminNotUpgradeAuthority`). Unconditional: no feature flag, no optional account. The tier1 harness loads the compiled `kswarm_protocol.so` as a genuine upgradeable-loader program (`Program` + `ProgramData` with the ELF, upgrade authority = payer), so the deployable artifact runs the real check in every tier1 test; the CLI validator test deploys with `--upgradeable-program` and checks the rejection of a non-authority wallet. | `tier1_initialize_authority` (5), unit `test_validate_upgrade_authority_*` (4) |
| D6 | Unreachable Anchor `record_aggregate_verification` | Instruction, context, `current_instruction_data`, and the instructions-sysvar import deleted. Raw `fallback` unchanged (tier2 harness path). CLI keeps only the raw builder. IDL entry left for PR-7. | existing `test_record_*` unit tests cover the shared validation |
| Coverage | No tests for `slash_stale_job`, `cancel_open_job`, `withdraw_unlocked_stake`, claim-window expiry | Added | `tier1_lifecycle_gaps` (9), `tier1_slash_accounting` (9) |

Client-visible layout changes: `initialize_protocol` appends `program`, `program_data`;
`cancel_aggregate_proof_job` appends `worker`, `worker_authority`; `JobStatus` adds
`CancelledOnTimeout = 9`; four errors appended. The Python CLI is updated; the Node
stack (`protocol/src/protocol.mjs` `initializeProtocol`, `cancelAggregateProofJob`) is
not, and is retired by PR-8.

## 11. Verified file/line reference index

`solana/programs/kswarm_protocol/src/lib.rs`:
- `job.worker` set 288, read 318 / 362→2429; `Job.worker` field 1494.
- `Worker` fields: authority 1477, stake_vault 1478, locked_stake 1479, active_claims 1480.
- Handlers: open_job 126 (challenge_bond 182, expected_result_hash 189), claim_job 224,
  submit_receipt 296, settle_aggregate_proof_job 486 (pay 500, stake 513),
  settle_job 554 (transfer 583, stake 598), challenge_job 614 (bond check 640,
  predicate 643, active_claims 656, →Slashed 662), refund_slashed_job_escrow 667,
  claim_verifier_slash_reward 695 (transfer 707, reward 705),
  claim_customer_slash_compensation 730 (transfer 748), slash_stale_job 810
  (stake transfer 853, dec 868).
- Structs (worker acct / worker_stake_vault): SettleAggregateProofJob 1151 (w1171),
  ChallengeJob 1187 (w1219, vault 1222 **unpinned**), ClaimVerifierSlashReward 1259
  (w1290, vault 1293 pinned), ClaimCustomerSlashCompensation 1299 (w1330, vault 1333
  pinned), SettleJob 1339 (w1357), SlashStaleJob 1428 (w1455, vault 1458 **unpinned**).
- Predicate `receipt_is_challengeable` 2454 (expected-hash guard 2456, tier branch
  2476); `validate_verifier_attestation` 2409 (Phase 2 TODO 2424, self-attest 2429,
  assigned 2432); `derive_stake_tier` 1689; `maybe_finalize_slash_settlement` 1818;
  helpers `pay_worker_for_job` 1733, `transfer_worker_stake_with_pda` 1764.
- Constants: TIER floors 20-22, VERIFIER_STAKE_FLOOR 23, ATTESTATION_WINDOW_SECONDS
  24, MAX_REASSIGNMENTS 25, EMPTY_HASH 19; `ProtocolError` enum 2498.

`tests/anchor_integration/src/lib.rs`: JobSpec 76 (default 93, aggregate 115,
branch_proof 127), run_tier1_test 138, register_participant 255, complete_job 462,
submit_verifier_attestation 477, assign_verifier 509, settle_job 549,
settle_aggregate_proof_job 576, challenge_job 605, refund_slashed_job_escrow 633,
claim_verifier_slash_reward 658, claim_customer_slash_compensation 687,
store_bonsol_marker 807, valid_bonsol_marker_for_job 902, assert_anchor_error 937.
`tests/anchor_integration/tests/tier1_q1_slash_flow.rs`: happy 9, mismatch 67.
