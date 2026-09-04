#![cfg(feature = "tier1")]
//! Adversarial coverage for the escrow/slashing authorization remediation
//! (docs/protocol-security-remediation-spec.md): C1 (worker↔job binding), H1
//! (stake-vault pinning) and H2-Interim (self-challenge / assigned-verifier
//! guards). Every test fails on the pre-fix program and passes on the fixed one.

use anchor_integration::*;
use kswarm_protocol::{JobStatus, NodeRole, ProtocolError, StakeTier};
use serial_test::serial;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signer;

/// Registers a worker and gives it one live claim on its own job, so its
/// `locked_stake`/`active_claims` are non-zero. Without this, the settle/slash
/// handlers underflow (`MathOverflow`) and mask the authorization bug under
/// attack — with it, the pre-fix attack completes cleanly (`Ok`).
async fn worker_with_active_claim(env: &mut Tier1Context, role: u8) -> Participant {
    let participant = env
        .register_participant(role, ZERO_HASH, ZERO_HASH, WORKER_STAKE_DEPOSIT)
        .await;
    let own_job = env.open_job(JobSpec::default()).await;
    env.commit_input_artifact(&own_job).await;
    env.claim_job(&participant, &own_job)
        .await
        .expect("participant claims its own job to lock stake");
    participant
}

// ---------------------------------------------------------------------------
// C1 — settlement/slash must bind the payout `worker` to `job.worker`.
// ---------------------------------------------------------------------------

/// C1-1: `settle_job` must not pay a worker other than `job.worker`.
#[test]
#[serial]
fn authz_c1_settle_job_rejects_foreign_worker() {
    run_tier1_test(|mut env| async move {
        let victim = env
            .register_participant(
                NodeRole::WorkerBasic as u8,
                ZERO_HASH,
                ZERO_HASH,
                WORKER_STAKE_DEPOSIT,
            )
            .await;
        let victim_job = env
            .complete_job(&victim, JobSpec::default(), b"result-ok".to_vec())
            .await;

        let attacker = worker_with_active_claim(&mut env, NodeRole::WorkerBasic as u8).await;
        env.warp_past_challenge_deadline(&victim_job).await;

        let err = env
            .settle_job(&attacker.authority, &attacker, &victim_job)
            .await
            .expect_err("settling with a foreign worker must be rejected");
        assert_anchor_error(err, ProtocolError::JobWorkerMismatch);
    });
}

/// C1-2: `settle_aggregate_proof_job` must not pay a worker other than `job.worker`.
#[test]
#[serial]
fn authz_c1_settle_aggregate_rejects_foreign_worker() {
    run_tier1_test(|mut env| async move {
        let victim = env
            .register_participant(
                NodeRole::WorkerProof as u8,
                kswarm_protocol::AGGREGATE_PROOF_CAPABILITY_HASH,
                IMAGE_ID,
                WORKER_STAKE_DEPOSIT,
            )
            .await;
        let verifier = env
            .register_participant(
                NodeRole::Verifier as u8,
                ZERO_HASH,
                IMAGE_ID,
                VERIFIER_STAKE_DEPOSIT,
            )
            .await;

        let result_bytes = b"aggregate-result".to_vec();
        let submitted = result_hash(&result_bytes);
        let victim_job = env
            .complete_job(&victim, JobSpec::aggregate(), result_bytes)
            .await;
        env.submit_verifier_attestation(&verifier, &victim_job, submitted, IMAGE_ID)
            .await
            .expect("submit matching aggregate attestation");
        let (marker_key, marker) = valid_bonsol_marker_for_job(&victim_job, [7u8; 32]);
        env.store_bonsol_marker(marker_key, marker);
        env.warp_past_challenge_deadline(&victim_job).await;

        let attacker = worker_with_active_claim(&mut env, NodeRole::WorkerBasic as u8).await;

        let err = env
            .settle_aggregate_proof_job(&attacker.authority, &attacker, &victim_job, marker_key)
            .await
            .expect_err("settling an aggregate job with a foreign worker must be rejected");
        assert_anchor_error(err, ProtocolError::JobWorkerMismatch);
    });
}

/// C1-3: `claim_verifier_slash_reward` must not drain an unrelated worker's stake.
#[test]
#[serial]
fn authz_c1_verifier_slash_reward_rejects_foreign_worker() {
    run_tier1_test(|mut env| async move {
        let victim_a = env
            .register_participant(
                NodeRole::WorkerBasic as u8,
                ZERO_HASH,
                ZERO_HASH,
                WORKER_STAKE_DEPOSIT,
            )
            .await;
        let verifier = env
            .register_participant(
                NodeRole::Verifier as u8,
                ZERO_HASH,
                ZERO_HASH,
                VERIFIER_STAKE_DEPOSIT,
            )
            .await;
        let job = env
            .complete_job(&victim_a, JobSpec::default(), b"result-ok".to_vec())
            .await;
        env.assign_verifier(&job.customer, &job, verifier.authority.pubkey())
            .await
            .expect("customer assigns the verifier");
        env.submit_verifier_attestation(&verifier, &job, [0x9a; 32], ZERO_HASH)
            .await
            .expect("submit mismatched attestation");
        env.challenge_job(&verifier, &victim_a, &job)
            .await
            .expect("challenge slashes victim_a's job");

        let victim_b = worker_with_active_claim(&mut env, NodeRole::WorkerBasic as u8).await;

        let err = env
            .claim_verifier_slash_reward(&verifier.authority, &verifier, &victim_b, &job)
            .await
            .expect_err("draining an unrelated worker must be rejected");
        assert_anchor_error(err, ProtocolError::JobWorkerMismatch);
    });
}

/// C1-4: `claim_customer_slash_compensation` must not drain an unrelated worker.
#[test]
#[serial]
fn authz_c1_customer_slash_comp_rejects_foreign_worker() {
    run_tier1_test(|mut env| async move {
        let victim_a = env
            .register_participant(
                NodeRole::WorkerBasic as u8,
                ZERO_HASH,
                ZERO_HASH,
                WORKER_STAKE_DEPOSIT,
            )
            .await;
        let verifier = env
            .register_participant(
                NodeRole::Verifier as u8,
                ZERO_HASH,
                ZERO_HASH,
                VERIFIER_STAKE_DEPOSIT,
            )
            .await;
        let job = env
            .complete_job(&victim_a, JobSpec::default(), b"result-ok".to_vec())
            .await;
        env.assign_verifier(&job.customer, &job, verifier.authority.pubkey())
            .await
            .expect("customer assigns the verifier");
        env.submit_verifier_attestation(&verifier, &job, [0x9a; 32], ZERO_HASH)
            .await
            .expect("submit mismatched attestation");
        env.challenge_job(&verifier, &victim_a, &job)
            .await
            .expect("challenge slashes victim_a's job");

        let victim_b = worker_with_active_claim(&mut env, NodeRole::WorkerBasic as u8).await;

        let err = env
            .claim_customer_slash_compensation(&job.customer, &victim_b, &job)
            .await
            .expect_err("draining an unrelated worker must be rejected");
        assert_anchor_error(err, ProtocolError::JobWorkerMismatch);
    });
}

/// C1-5: `slash_stale_job` must not slash a worker other than `job.worker`.
#[test]
#[serial]
fn authz_c1_slash_stale_rejects_foreign_worker() {
    run_tier1_test(|mut env| async move {
        let victim_a = env
            .register_participant(
                NodeRole::WorkerBasic as u8,
                ZERO_HASH,
                ZERO_HASH,
                WORKER_STAKE_DEPOSIT,
            )
            .await;
        // Claim but never submit a receipt, then let the execution window lapse.
        let job = env.open_job(JobSpec::default()).await;
        env.commit_input_artifact(&job).await;
        env.claim_job(&victim_a, &job)
            .await
            .expect("victim_a claims job");
        env.warp_past_execute_deadline(&job).await;

        let victim_b = worker_with_active_claim(&mut env, NodeRole::WorkerBasic as u8).await;

        let err = env
            .slash_stale_job(&job.customer, &victim_b, victim_b.stake_vault, &job)
            .await
            .expect_err("slashing an unrelated worker must be rejected");
        assert_anchor_error(err, ProtocolError::JobWorkerMismatch);
    });
}

// ---------------------------------------------------------------------------
// H1 — the read/spent stake vault must be the worker's registered vault.
// ---------------------------------------------------------------------------

/// H1-1: a fake stake vault must not be able to force an honest receipt
/// "challengeable". With the worker's real vault the receipt is not
/// challengeable; a zero-balance foreign vault is now rejected outright.
#[test]
#[serial]
fn authz_h1_challenge_rejects_foreign_stake_vault() {
    run_tier1_test(|mut env| async move {
        let worker = env
            .register_participant(
                NodeRole::WorkerBasic as u8,
                ZERO_HASH,
                ZERO_HASH,
                WORKER_STAKE_DEPOSIT,
            )
            .await;
        let verifier = env
            .register_participant(
                NodeRole::Verifier as u8,
                ZERO_HASH,
                ZERO_HASH,
                VERIFIER_STAKE_DEPOSIT,
            )
            .await;
        let job = env
            .complete_job(&worker, JobSpec::default(), b"result-ok".to_vec())
            .await;
        env.assign_verifier(&job.customer, &job, verifier.authority.pubkey())
            .await
            .expect("customer assigns the verifier");

        // With the genuine vault the honest receipt is not challengeable.
        let honest = env
            .challenge_job(&verifier, &worker, &job)
            .await
            .expect_err("an honest receipt must not be challengeable");
        assert_anchor_error(honest, ProtocolError::ChallengeRejected);

        // A zero-balance vault that is not the worker's registered vault.
        let fake_vault = env.create_ata(Pubkey::new_unique()).await;
        let err = env
            .challenge_job_with_stake_vault(&verifier, &worker, &job, fake_vault)
            .await
            .expect_err("a foreign stake vault must be rejected");
        assert_anchor_error(err, ProtocolError::WrongWorkerStakeVault);
    });
}

/// H1-2: `slash_stale_job` must reject a stake vault that is not the worker's.
#[test]
#[serial]
fn authz_h1_slash_stale_rejects_foreign_stake_vault() {
    run_tier1_test(|mut env| async move {
        let worker = env
            .register_participant(
                NodeRole::WorkerBasic as u8,
                ZERO_HASH,
                ZERO_HASH,
                WORKER_STAKE_DEPOSIT,
            )
            .await;
        let job = env.open_job(JobSpec::default()).await;
        env.commit_input_artifact(&job).await;
        env.claim_job(&worker, &job)
            .await
            .expect("worker claims job");
        env.warp_past_execute_deadline(&job).await;

        let fake_vault = env.create_ata(Pubkey::new_unique()).await;
        let err = env
            .slash_stale_job(&job.customer, &worker, fake_vault, &job)
            .await
            .expect_err("a foreign stake vault must be rejected");
        assert_anchor_error(err, ProtocolError::WrongWorkerStakeVault);
    });
}

// ---------------------------------------------------------------------------
// H2-Interim — self-challenge ban and assigned-verifier gate.
// ---------------------------------------------------------------------------

/// H2i-1: a worker may not challenge its own job (same-key operator).
#[test]
#[serial]
fn authz_h2i_self_challenge_rejected() {
    run_tier1_test(|mut env| async move {
        // Registered as Verifier so it can both perform the (Verifier-role) job
        // and clear challenge_job's verifier-role gate — the same-key case.
        let worker = env
            .register_participant(
                NodeRole::Verifier as u8,
                ZERO_HASH,
                ZERO_HASH,
                VERIFIER_STAKE_DEPOSIT,
            )
            .await;
        let job = env
            .complete_job(
                &worker,
                JobSpec {
                    required_role: NodeRole::Verifier as u8,
                    required_tier: StakeTier::TierOne as u8,
                    ..JobSpec::default()
                },
                b"result-ok".to_vec(),
            )
            .await;

        let err = env
            .challenge_job(&worker, &worker, &job)
            .await
            .expect_err("a worker must not be able to challenge its own job");
        assert_anchor_error(err, ProtocolError::SelfChallengeForbidden);
    });
}

/// H2i-2: on an assigned job, only the assigned verifier may challenge.
#[test]
#[serial]
fn authz_h2i_unassigned_verifier_challenge_rejected() {
    run_tier1_test(|mut env| async move {
        let worker = env
            .register_participant(
                NodeRole::WorkerProof as u8,
                kswarm_protocol::AGGREGATE_PROOF_CAPABILITY_HASH,
                IMAGE_ID,
                WORKER_STAKE_DEPOSIT,
            )
            .await;
        let assigned_verifier = env
            .register_participant(
                NodeRole::Verifier as u8,
                ZERO_HASH,
                IMAGE_ID,
                VERIFIER_STAKE_DEPOSIT,
            )
            .await;
        let other_verifier = env
            .register_participant(
                NodeRole::Verifier as u8,
                ZERO_HASH,
                IMAGE_ID,
                VERIFIER_STAKE_DEPOSIT,
            )
            .await;

        let job = env
            .complete_job(&worker, JobSpec::aggregate(), b"aggregate-result".to_vec())
            .await;
        env.assign_verifier(&job.customer, &job, assigned_verifier.authority.pubkey())
            .await
            .expect("assign verifier");

        let err = env
            .challenge_job(&other_verifier, &worker, &job)
            .await
            .expect_err("only the assigned verifier may challenge an assigned job");
        assert_anchor_error(err, ProtocolError::VerifierNotAssigned);
    });
}

/// H2i-3: on a `DeterministicBasic` job with no assigned verifier, a verifier with the
/// floor stake can still post a false attestation, but it cannot challenge, so the
/// attestation moves no funds and the worker settles normally. Before PR-3 this was a
/// free slash: `assign_verifier` rejected non-aggregate classes, so the assigned-verifier
/// guard never applied and `tier1_q1_full_slash_mismatch` codified the attack.
#[test]
#[serial]
fn authz_h2i_unassigned_challenge_rejected_for_basic_job() {
    run_tier1_test(|mut env| async move {
        let worker = env
            .register_participant(
                NodeRole::WorkerBasic as u8,
                ZERO_HASH,
                ZERO_HASH,
                WORKER_STAKE_DEPOSIT,
            )
            .await;
        let rogue_verifier = env
            .register_participant(
                NodeRole::Verifier as u8,
                ZERO_HASH,
                ZERO_HASH,
                VERIFIER_STAKE_DEPOSIT,
            )
            .await;
        let job = env
            .complete_job(&worker, JobSpec::default(), b"result-ok".to_vec())
            .await;
        env.submit_verifier_attestation(&rogue_verifier, &job, [0x9a; 32], ZERO_HASH)
            .await
            .expect("an unassigned verifier may still attest");

        let err = env
            .challenge_job(&rogue_verifier, &worker, &job)
            .await
            .expect_err("a challenge without an assigned verifier must be rejected");
        assert_anchor_error(err, ProtocolError::ChallengeRequiresAssignedVerifier);

        let job_state = env.read_job(job.job).await;
        let worker_state = env.read_worker(worker.worker).await;
        assert_eq!(job_state.status, JobStatus::Completed as u8);
        assert_eq!(worker_state.locked_stake, REQUIRED_STAKE);
        assert_eq!(worker_state.active_claims, 1);
        assert_eq!(
            env.read_token_balance(worker.stake_vault).await,
            WORKER_STAKE_DEPOSIT
        );

        env.warp_past_challenge_deadline(&job).await;
        env.settle_job(&job.customer, &worker, &job)
            .await
            .expect("the false attestation does not block settlement");
        assert_eq!(
            env.read_token_balance(worker.token_account).await,
            REWARD_AMOUNT
        );
        let worker_state = env.read_worker(worker.worker).await;
        assert_eq!(worker_state.locked_stake, 0);
        assert_eq!(
            env.read_token_balance(rogue_verifier.token_account).await,
            0
        );
    });
}

/// H2i-4: `assign_verifier` now covers every job class, and the assigned verifier can
/// challenge a `BranchProof` receipt whose attestation mismatches.
#[test]
#[serial]
fn authz_h2i_assigned_verifier_challenges_branch_proof() {
    run_tier1_test(|mut env| async move {
        let worker = env
            .register_participant(
                NodeRole::WorkerProof as u8,
                ZERO_HASH,
                ZERO_HASH,
                WORKER_STAKE_DEPOSIT,
            )
            .await;
        let verifier = env
            .register_participant(
                NodeRole::Verifier as u8,
                ZERO_HASH,
                ZERO_HASH,
                VERIFIER_STAKE_DEPOSIT,
            )
            .await;
        let job = env
            .complete_job(&worker, JobSpec::branch_proof(), b"result-ok".to_vec())
            .await;
        env.assign_verifier(&job.customer, &job, verifier.authority.pubkey())
            .await
            .expect("assign_verifier accepts a branch-proof job");
        let job_state = env.read_job(job.job).await;
        assert_eq!(
            job_state.assigned_verifier_authority,
            Some(verifier.authority.pubkey())
        );

        env.submit_verifier_attestation(&verifier, &job, [0x9a; 32], ZERO_HASH)
            .await
            .expect("assigned verifier attests");
        env.challenge_job(&verifier, &worker, &job)
            .await
            .expect("assigned verifier challenges");

        let job_state = env.read_job(job.job).await;
        assert_eq!(job_state.status, JobStatus::Slashed as u8);
        assert_eq!(job_state.challenger, verifier.authority.pubkey());
    });
}

/// H2i-5: only the customer or the admin may assign; a third party (the verifier
/// itself) cannot self-assign to open a challenge.
#[test]
#[serial]
fn authz_h2i_verifier_cannot_self_assign() {
    run_tier1_test(|mut env| async move {
        let worker = env
            .register_participant(
                NodeRole::WorkerBasic as u8,
                ZERO_HASH,
                ZERO_HASH,
                WORKER_STAKE_DEPOSIT,
            )
            .await;
        let verifier = env
            .register_participant(
                NodeRole::Verifier as u8,
                ZERO_HASH,
                ZERO_HASH,
                VERIFIER_STAKE_DEPOSIT,
            )
            .await;
        let job = env
            .complete_job(&worker, JobSpec::default(), b"result-ok".to_vec())
            .await;

        let err = env
            .assign_verifier(&verifier.authority, &job, verifier.authority.pubkey())
            .await
            .expect_err("a verifier must not assign itself");
        assert_anchor_error(err, ProtocolError::VerifierAssignmentUnauthorized);
        assert_eq!(env.read_job(job.job).await.assigned_verifier_authority, None);
    });
}

// ---------------------------------------------------------------------------
// Positive regression — the C1 binding must not break the honest path.
// ---------------------------------------------------------------------------

/// Settling with the correct `job.worker` still succeeds after the C1 constraint.
#[test]
#[serial]
fn authz_positive_settle_correct_worker_succeeds() {
    run_tier1_test(|mut env| async move {
        let worker = env
            .register_participant(
                NodeRole::WorkerBasic as u8,
                ZERO_HASH,
                ZERO_HASH,
                WORKER_STAKE_DEPOSIT,
            )
            .await;
        let job = env
            .complete_job(&worker, JobSpec::default(), b"result-ok".to_vec())
            .await;
        env.warp_past_challenge_deadline(&job).await;

        env.settle_job(&job.customer, &worker, &job)
            .await
            .expect("settling with the correct worker still succeeds");

        let job_state = env.read_job(job.job).await;
        assert_eq!(job_state.status, JobStatus::Settled as u8);
    });
}
