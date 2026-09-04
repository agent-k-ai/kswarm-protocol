#![cfg(feature = "tier1")]
//! Coverage for instructions and windows that had no Rust tests before PR-3:
//! `cancel_open_job`, `withdraw_unlocked_stake`, claim-window expiry, and the
//! `open_job` job-class / capability pairing check.

use anchor_integration::*;
use kswarm_protocol::{JobClass, JobStatus, NodeRole, ProtocolError, AGGREGATE_PROOF_CAPABILITY_HASH};
use serial_test::serial;
use solana_sdk::signature::{Keypair, Signer};

/// Anchor framework error `ConstraintSeeds`: the job PDA does not derive from the signer.
const ANCHOR_CONSTRAINT_SEEDS: u32 = 2006;

fn basic_worker(env: &mut Tier1Context) -> impl std::future::Future<Output = Participant> + '_ {
    env.register_participant(
        NodeRole::WorkerBasic as u8,
        ZERO_HASH,
        ZERO_HASH,
        WORKER_STAKE_DEPOSIT,
    )
}

// ---------------------------------------------------------------------------
// cancel_open_job
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn lifecycle_cancel_open_job_refunds_awaiting_artifact_job() {
    run_tier1_test(|mut env| async move {
        let job = env.open_job(JobSpec::default()).await;
        assert_eq!(
            env.read_job(job.job).await.status,
            JobStatus::AwaitingArtifact as u8
        );

        env.cancel_open_job(&job.customer, job.customer_token, &job)
            .await
            .expect("cancel a job that has no input artifact yet");

        let job_state = env.read_job(job.job).await;
        assert_eq!(job_state.status, JobStatus::Cancelled as u8);
        assert_eq!(
            env.read_token_balance(job.customer_token).await,
            job.customer_funding_amount
        );
        assert_eq!(env.read_token_balance(job.escrow).await, 0);
    });
}

#[test]
#[serial]
fn lifecycle_cancel_open_job_refunds_open_job() {
    run_tier1_test(|mut env| async move {
        let job = env.open_job(JobSpec::default()).await;
        env.commit_input_artifact(&job).await;
        assert_eq!(env.read_job(job.job).await.status, JobStatus::Open as u8);

        env.cancel_open_job(&job.customer, job.customer_token, &job)
            .await
            .expect("cancel an open job");

        let job_state = env.read_job(job.job).await;
        assert_eq!(job_state.status, JobStatus::Cancelled as u8);
        assert_eq!(
            env.read_token_balance(job.customer_token).await,
            job.customer_funding_amount
        );
        assert_eq!(env.read_token_balance(job.escrow).await, 0);

        let err = env
            .cancel_open_job(&job.customer, job.customer_token, &job)
            .await
            .expect_err("a cancelled job cannot be cancelled again");
        assert_anchor_error(err, ProtocolError::InvalidJobState);
    });
}

#[test]
#[serial]
fn lifecycle_cancel_open_job_rejected_once_claimed() {
    run_tier1_test(|mut env| async move {
        let worker = basic_worker(&mut env).await;
        let job = env.open_job(JobSpec::default()).await;
        env.commit_input_artifact(&job).await;
        env.claim_job(&worker, &job).await.expect("claim job");

        let err = env
            .cancel_open_job(&job.customer, job.customer_token, &job)
            .await
            .expect_err("a claimed job cannot be cancelled by the customer");
        assert_anchor_error(err, ProtocolError::InvalidJobState);

        assert_eq!(env.read_job(job.job).await.status, JobStatus::Claimed as u8);
        assert_eq!(env.read_token_balance(job.escrow).await, REWARD_AMOUNT);
        assert_eq!(env.read_worker(worker.worker).await.locked_stake, REQUIRED_STAKE);
    });
}

#[test]
#[serial]
fn lifecycle_cancel_open_job_rejected_for_wrong_customer() {
    run_tier1_test(|mut env| async move {
        let job = env.open_job(JobSpec::default()).await;
        env.commit_input_artifact(&job).await;

        let intruder = Keypair::new();
        env.fund_keypair(&intruder).await;
        let intruder_token = env.create_ata(intruder.pubkey()).await;
        let err = env
            .cancel_open_job(&intruder, intruder_token, &job)
            .await
            .expect_err("only the customer may cancel");
        assert_custom_error_code(err, ANCHOR_CONSTRAINT_SEEDS);

        assert_eq!(env.read_job(job.job).await.status, JobStatus::Open as u8);
        assert_eq!(env.read_token_balance(job.escrow).await, REWARD_AMOUNT);
        assert_eq!(env.read_token_balance(intruder_token).await, 0);
    });
}

// ---------------------------------------------------------------------------
// withdraw_unlocked_stake
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn lifecycle_withdraw_unlocked_stake_respects_locked_stake() {
    run_tier1_test(|mut env| async move {
        let worker = basic_worker(&mut env).await;
        let job = env.open_job(JobSpec::default()).await;
        env.commit_input_artifact(&job).await;
        env.claim_job(&worker, &job).await.expect("claim job");
        assert_eq!(env.read_worker(worker.worker).await.locked_stake, REQUIRED_STAKE);
        let unlocked = WORKER_STAKE_DEPOSIT - REQUIRED_STAKE;

        let err = env
            .withdraw_unlocked_stake(&worker, 0)
            .await
            .expect_err("zero withdrawal must be rejected");
        assert_anchor_error(err, ProtocolError::InvalidAmount);

        let err = env
            .withdraw_unlocked_stake(&worker, unlocked + 1)
            .await
            .expect_err("locked stake must not be withdrawable");
        assert_anchor_error(err, ProtocolError::InsufficientAvailableStake);
        assert_eq!(
            env.read_token_balance(worker.stake_vault).await,
            WORKER_STAKE_DEPOSIT
        );

        env.withdraw_unlocked_stake(&worker, unlocked)
            .await
            .expect("withdraw every unlocked token");
        assert_eq!(
            env.read_token_balance(worker.stake_vault).await,
            REQUIRED_STAKE
        );
        assert_eq!(env.read_token_balance(worker.token_account).await, unlocked);

        let err = env
            .withdraw_unlocked_stake(&worker, 1)
            .await
            .expect_err("nothing is left to withdraw while the claim is live");
        assert_anchor_error(err, ProtocolError::InsufficientAvailableStake);

        // Once the claim settles the remaining stake is withdrawable.
        env.submit_receipt(&worker, &job, b"result-ok".to_vec())
            .await
            .expect("submit receipt");
        env.warp_past_challenge_deadline(&job).await;
        env.settle_job(&job.customer, &worker, &job)
            .await
            .expect("settle job");
        env.withdraw_unlocked_stake(&worker, REQUIRED_STAKE)
            .await
            .expect("withdraw the rest after settlement");
        assert_eq!(env.read_token_balance(worker.stake_vault).await, 0);
        assert_eq!(
            env.read_token_balance(worker.token_account).await,
            WORKER_STAKE_DEPOSIT + REWARD_AMOUNT
        );
    });
}

// ---------------------------------------------------------------------------
// claim window
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn lifecycle_claim_after_claim_window_rejected() {
    run_tier1_test(|mut env| async move {
        let worker = basic_worker(&mut env).await;
        let job = env.open_job(JobSpec::default()).await;
        env.commit_input_artifact(&job).await;
        env.warp_past_claim_deadline(&job).await;

        let err = env
            .claim_job(&worker, &job)
            .await
            .expect_err("claim after the claim window must be rejected");
        assert_anchor_error(err, ProtocolError::ClaimWindowExpired);

        let job_state = env.read_job(job.job).await;
        assert_eq!(job_state.status, JobStatus::Open as u8);
        assert_eq!(job_state.worker, solana_sdk::pubkey::Pubkey::default());
        let worker_state = env.read_worker(worker.worker).await;
        assert_eq!(worker_state.locked_stake, 0);
        assert_eq!(worker_state.active_claims, 0);

        // The customer recovers the escrow through cancel_open_job.
        env.cancel_open_job(&job.customer, job.customer_token, &job)
            .await
            .expect("cancel the unclaimed job");
        assert_eq!(
            env.read_token_balance(job.customer_token).await,
            job.customer_funding_amount
        );
    });
}

#[test]
#[serial]
fn lifecycle_claim_at_claim_deadline_accepted() {
    run_tier1_test(|mut env| async move {
        let worker = basic_worker(&mut env).await;
        let job = env.open_job(JobSpec::default()).await;
        env.commit_input_artifact(&job).await;
        let job_state = env.read_job(job.job).await;
        let now = env.current_clock().await.unix_timestamp;
        env.warp_seconds(job_state.claim_deadline - now).await;
        assert_eq!(
            env.current_clock().await.unix_timestamp,
            job_state.claim_deadline
        );

        env.claim_job(&worker, &job)
            .await
            .expect("claim exactly at the deadline is inside the window");
        assert_eq!(env.read_job(job.job).await.status, JobStatus::Claimed as u8);
    });
}

// ---------------------------------------------------------------------------
// open_job: job class and capability must agree
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn lifecycle_open_job_aggregate_class_requires_aggregate_capability() {
    run_tier1_test(|mut env| async move {
        for capability in [ZERO_HASH, [0x5a; 32]] {
            let spec = JobSpec {
                required_capability_class_hash: capability,
                ..JobSpec::aggregate()
            };
            let err = env
                .try_open_job(spec)
                .await
                .expect_err("aggregate class without the aggregate capability must be rejected");
            assert_anchor_error(err, ProtocolError::AggregateCapabilityMismatch);
        }

        let job = env.open_job(JobSpec::aggregate()).await;
        let job_state = env.read_job(job.job).await;
        assert_eq!(job_state.job_class, JobClass::AggregateProof as u8);
        assert_eq!(
            job_state.required_capability_class_hash,
            AGGREGATE_PROOF_CAPABILITY_HASH
        );
    });
}

#[test]
#[serial]
fn lifecycle_open_job_aggregate_capability_requires_aggregate_class() {
    run_tier1_test(|mut env| async move {
        for spec in [JobSpec::default(), JobSpec::branch_proof()] {
            let spec = JobSpec {
                required_capability_class_hash: AGGREGATE_PROOF_CAPABILITY_HASH,
                ..spec
            };
            let err = env
                .try_open_job(spec)
                .await
                .expect_err("aggregate capability on a non-aggregate class must be rejected");
            assert_anchor_error(err, ProtocolError::AggregateCapabilityMismatch);
        }

        let job = env.open_job(JobSpec::branch_proof()).await;
        assert_eq!(
            env.read_job(job.job).await.job_class,
            JobClass::BranchProof as u8
        );
    });
}
