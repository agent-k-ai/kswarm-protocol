#![cfg(feature = "tier1")]
//! PR-3 `fix/slash-accounting`: the stale-slash path finalizes every settlement flag
//! (no second slash through the claim instructions), and a `Completed` aggregate-proof
//! job that never receives a Bonsol marker can be cancelled after
//! `AGGREGATE_MARKER_TIMEOUT_SECONDS` with a refund and a stake unlock, no slash.

use anchor_integration::*;
use kswarm_protocol::{JobStatus, NodeRole, ProtocolError};
use serial_test::serial;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};

const AGGREGATE_RESULT: &[u8] = b"aggregate-result";

fn basic_worker(env: &mut Tier1Context) -> impl std::future::Future<Output = Participant> + '_ {
    env.register_participant(
        NodeRole::WorkerBasic as u8,
        ZERO_HASH,
        ZERO_HASH,
        WORKER_STAKE_DEPOSIT,
    )
}

fn aggregate_worker(env: &mut Tier1Context) -> impl std::future::Future<Output = Participant> + '_ {
    env.register_participant(
        NodeRole::WorkerProof as u8,
        kswarm_protocol::AGGREGATE_PROOF_CAPABILITY_HASH,
        IMAGE_ID,
        WORKER_STAKE_DEPOSIT,
    )
}

fn verifier(env: &mut Tier1Context) -> impl std::future::Future<Output = Participant> + '_ {
    env.register_participant(
        NodeRole::Verifier as u8,
        ZERO_HASH,
        IMAGE_ID,
        VERIFIER_STAKE_DEPOSIT,
    )
}

/// Opens, commits, and claims a job that the worker never completes.
async fn claimed_job(env: &mut Tier1Context, worker: &Participant) -> TestJob {
    let job = env.open_job(JobSpec::default()).await;
    env.commit_input_artifact(&job).await;
    env.claim_job(worker, &job).await.expect("claim job");
    job
}

/// A completed aggregate job with a matching attestation and no Bonsol marker.
async fn attested_aggregate_without_marker(
    env: &mut Tier1Context,
    worker: &Participant,
    verifier: &Participant,
) -> TestJob {
    let job = env
        .complete_job(worker, JobSpec::aggregate(), AGGREGATE_RESULT.to_vec())
        .await;
    env.submit_verifier_attestation(verifier, &job, result_hash(AGGREGATE_RESULT), IMAGE_ID)
        .await
        .expect("submit matching aggregate attestation");
    job
}

// ---------------------------------------------------------------------------
// Item 1 — stale slash pays once.
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn slash_accounting_stale_slash_pays_once_and_closes_every_claim() {
    run_tier1_test(|mut env| async move {
        let worker = basic_worker(&mut env).await;
        let verifier = verifier(&mut env).await;
        let job = claimed_job(&mut env, &worker).await;
        env.warp_past_execute_deadline(&job).await;

        env.slash_stale_job(&job.customer, &worker, worker.stake_vault, &job)
            .await
            .expect("slash stale job");

        let job_state = env.read_job(job.job).await;
        assert_eq!(job_state.status, JobStatus::Slashed as u8);
        assert!(job_state.escrow_refunded);
        assert!(job_state.verifier_reward_paid);
        assert!(job_state.customer_slash_paid);
        assert!(job_state.slash_settled);
        assert_eq!(job_state.challenger, Pubkey::default());

        let worker_state = env.read_worker(worker.worker).await;
        assert_eq!(worker_state.locked_stake, 0);
        assert_eq!(worker_state.active_claims, 0);
        let vault_after_slash = WORKER_STAKE_DEPOSIT - REQUIRED_STAKE;
        assert_eq!(
            env.read_token_balance(worker.stake_vault).await,
            vault_after_slash
        );
        let customer_after_slash = job.customer_funding_amount + REQUIRED_STAKE;
        assert_eq!(
            env.read_token_balance(job.customer_token).await,
            customer_after_slash
        );
        assert_eq!(env.read_token_balance(job.escrow).await, 0);

        // Before PR-3 this call drained a second `required_stake` from the vault.
        let err = env
            .claim_customer_slash_compensation(&job.customer, &worker, &job)
            .await
            .expect_err("customer compensation after a stale slash must be rejected");
        assert_anchor_error(err, ProtocolError::SlashAlreadySettled);

        let err = env
            .claim_verifier_slash_reward(&verifier.authority, &verifier, &worker, &job)
            .await
            .expect_err("verifier reward after a stale slash must be rejected");
        assert_anchor_error(err, ProtocolError::SlashAlreadySettled);

        let err = env
            .refund_slashed_job_escrow(&job.customer, &job)
            .await
            .expect_err("escrow refund after a stale slash must be rejected");
        assert_anchor_error(err, ProtocolError::SlashAlreadySettled);

        let err = env
            .slash_stale_job(&job.customer, &worker, worker.stake_vault, &job)
            .await
            .expect_err("a second stale slash must be rejected");
        assert_anchor_error(err, ProtocolError::InvalidJobState);

        let worker_state = env.read_worker(worker.worker).await;
        assert_eq!(worker_state.locked_stake, 0);
        assert_eq!(worker_state.active_claims, 0);
        assert_eq!(
            env.read_token_balance(worker.stake_vault).await,
            vault_after_slash
        );
        assert_eq!(
            env.read_token_balance(job.customer_token).await,
            customer_after_slash
        );
        assert_eq!(env.read_token_balance(verifier.token_account).await, 0);
    });
}

/// A stale slash and a challenge slash leave the same accounting invariants: the
/// worker's `locked_stake` matches its remaining claims exactly, so a second job on
/// the same worker still settles cleanly afterwards.
#[test]
#[serial]
fn slash_accounting_stale_slash_keeps_other_claims_consistent() {
    run_tier1_test(|mut env| async move {
        let worker = basic_worker(&mut env).await;
        let stale = claimed_job(&mut env, &worker).await;
        let live = env
            .complete_job(&worker, JobSpec::default(), b"result-ok".to_vec())
            .await;
        let worker_state = env.read_worker(worker.worker).await;
        assert_eq!(worker_state.locked_stake, 2 * REQUIRED_STAKE);
        assert_eq!(worker_state.active_claims, 2);

        env.warp_past_execute_deadline(&stale).await;
        env.slash_stale_job(&stale.customer, &worker, worker.stake_vault, &stale)
            .await
            .expect("slash stale job");
        let worker_state = env.read_worker(worker.worker).await;
        assert_eq!(worker_state.locked_stake, REQUIRED_STAKE);
        assert_eq!(worker_state.active_claims, 1);

        env.warp_past_challenge_deadline(&live).await;
        env.settle_job(&live.customer, &worker, &live)
            .await
            .expect("settle the live job");
        let worker_state = env.read_worker(worker.worker).await;
        assert_eq!(worker_state.locked_stake, 0);
        assert_eq!(worker_state.active_claims, 0);
        assert_eq!(
            env.read_token_balance(worker.stake_vault).await,
            WORKER_STAKE_DEPOSIT - REQUIRED_STAKE
        );
        assert_eq!(
            env.read_token_balance(worker.token_account).await,
            REWARD_AMOUNT
        );
    });
}

#[test]
#[serial]
fn slash_accounting_stale_slash_rejected_while_execution_window_open() {
    run_tier1_test(|mut env| async move {
        let worker = basic_worker(&mut env).await;
        let job = claimed_job(&mut env, &worker).await;

        let err = env
            .slash_stale_job(&job.customer, &worker, worker.stake_vault, &job)
            .await
            .expect_err("stale slash inside the execution window must be rejected");
        assert_anchor_error(err, ProtocolError::ExecutionWindowOpen);

        let worker_state = env.read_worker(worker.worker).await;
        assert_eq!(worker_state.locked_stake, REQUIRED_STAKE);
        assert_eq!(
            env.read_token_balance(worker.stake_vault).await,
            WORKER_STAKE_DEPOSIT
        );
    });
}

#[test]
#[serial]
fn slash_accounting_stale_slash_rejected_after_receipt() {
    run_tier1_test(|mut env| async move {
        let worker = basic_worker(&mut env).await;
        let job = env
            .complete_job(&worker, JobSpec::default(), b"result-ok".to_vec())
            .await;
        env.warp_past_execute_deadline(&job).await;

        let err = env
            .slash_stale_job(&job.customer, &worker, worker.stake_vault, &job)
            .await
            .expect_err("a completed job is not stale");
        assert_anchor_error(err, ProtocolError::InvalidJobState);
    });
}

// ---------------------------------------------------------------------------
// Item 2 — aggregate marker timeout escape.
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn slash_accounting_timeout_cancel_rejected_before_timeout() {
    run_tier1_test(|mut env| async move {
        let worker = aggregate_worker(&mut env).await;
        let verifier = verifier(&mut env).await;
        let job = attested_aggregate_without_marker(&mut env, &worker, &verifier).await;

        // Attested, registry not exhausted, challenge window still open.
        let err = env
            .cancel_aggregate_proof_job(&job.customer, job.customer_token, &worker, &job)
            .await
            .expect_err("cancel inside the challenge window must be rejected");
        assert_anchor_error(err, ProtocolError::RegistryNotExhausted);

        // Challenge window closed, no marker, but the grace period has not elapsed.
        env.warp_past_challenge_deadline(&job).await;
        let err = env
            .cancel_aggregate_proof_job(&job.customer, job.customer_token, &worker, &job)
            .await
            .expect_err("cancel before the marker timeout must be rejected");
        assert_anchor_error(err, ProtocolError::RegistryNotExhausted);

        // Exactly at the boundary the timeout is not reached (strict comparison).
        env.warp_to_aggregate_marker_timeout(&job).await;
        let err = env
            .cancel_aggregate_proof_job(&job.customer, job.customer_token, &worker, &job)
            .await
            .expect_err("cancel at the exact timeout instant must be rejected");
        assert_anchor_error(err, ProtocolError::RegistryNotExhausted);

        let job_state = env.read_job(job.job).await;
        assert_eq!(job_state.status, JobStatus::Completed as u8);
        assert_eq!(env.read_token_balance(job.escrow).await, REWARD_AMOUNT);
        assert_eq!(env.read_worker(worker.worker).await.locked_stake, REQUIRED_STAKE);
    });
}

#[test]
#[serial]
fn slash_accounting_timeout_cancel_refunds_escrow_and_unlocks_stake() {
    run_tier1_test(|mut env| async move {
        let worker = aggregate_worker(&mut env).await;
        let verifier = verifier(&mut env).await;
        let job = attested_aggregate_without_marker(&mut env, &worker, &verifier).await;
        env.warp_past_aggregate_marker_timeout(&job).await;

        env.cancel_aggregate_proof_job(&job.customer, job.customer_token, &worker, &job)
            .await
            .expect("cancel after the marker timeout");

        let job_state = env.read_job(job.job).await;
        assert_eq!(job_state.status, JobStatus::CancelledOnTimeout as u8);
        assert_eq!(
            env.read_token_balance(job.customer_token).await,
            job.customer_funding_amount
        );
        assert_eq!(env.read_token_balance(job.escrow).await, 0);
        // No slash: the worker keeps its whole stake and its claim is released.
        let worker_state = env.read_worker(worker.worker).await;
        assert_eq!(worker_state.locked_stake, 0);
        assert_eq!(worker_state.active_claims, 0);
        assert_eq!(
            env.read_token_balance(worker.stake_vault).await,
            WORKER_STAKE_DEPOSIT
        );
        assert_eq!(env.read_token_balance(worker.token_account).await, 0);

        // Terminal: neither settlement nor a second cancel is possible.
        let (marker_key, marker) = valid_bonsol_marker_for_job(&job, [9u8; 32]);
        env.store_bonsol_marker(marker_key, marker);
        let err = env
            .settle_aggregate_proof_job(&worker.authority, &worker, &job, marker_key)
            .await
            .expect_err("a cancelled job cannot settle");
        assert_anchor_error(err, ProtocolError::InvalidJobState);
        let err = env
            .cancel_aggregate_proof_job(&job.customer, job.customer_token, &worker, &job)
            .await
            .expect_err("a cancelled job cannot be cancelled again");
        assert_anchor_error(err, ProtocolError::InvalidJobState);
    });
}

/// The timeout path also frees an unattested job whose registry is not exhausted,
/// so a customer never has to run the assign/reassign cycle to recover escrow.
#[test]
#[serial]
fn slash_accounting_timeout_cancel_serves_unattested_job() {
    run_tier1_test(|mut env| async move {
        let worker = aggregate_worker(&mut env).await;
        let job = env
            .complete_job(&worker, JobSpec::aggregate(), AGGREGATE_RESULT.to_vec())
            .await;
        env.warp_past_aggregate_marker_timeout(&job).await;

        env.cancel_aggregate_proof_job(&job.customer, job.customer_token, &worker, &job)
            .await
            .expect("cancel unattested job after the marker timeout");

        let job_state = env.read_job(job.job).await;
        assert_eq!(job_state.status, JobStatus::CancelledOnTimeout as u8);
        assert_eq!(job_state.verifier_attestation_hash, None);
        assert_eq!(env.read_worker(worker.worker).await.locked_stake, 0);
    });
}

#[test]
#[serial]
fn slash_accounting_timeout_cancel_rejected_after_settlement() {
    run_tier1_test(|mut env| async move {
        let worker = aggregate_worker(&mut env).await;
        let verifier = verifier(&mut env).await;
        let job = attested_aggregate_without_marker(&mut env, &worker, &verifier).await;
        let (marker_key, marker) = valid_bonsol_marker_for_job(&job, [3u8; 32]);
        env.store_bonsol_marker(marker_key, marker);
        env.warp_past_challenge_deadline(&job).await;

        env.settle_aggregate_proof_job(&worker.authority, &worker, &job, marker_key)
            .await
            .expect("settle with the marker inside the grace period");
        env.warp_past_aggregate_marker_timeout(&job).await;

        let err = env
            .cancel_aggregate_proof_job(&job.customer, job.customer_token, &worker, &job)
            .await
            .expect_err("a settled job cannot be cancelled on timeout");
        assert_anchor_error(err, ProtocolError::InvalidJobState);

        assert_eq!(
            env.read_token_balance(worker.token_account).await,
            REWARD_AMOUNT
        );
        assert_eq!(
            env.read_token_balance(job.customer_token).await,
            job.customer_funding_amount - REWARD_AMOUNT
        );
    });
}

#[test]
#[serial]
fn slash_accounting_timeout_cancel_rejects_wrong_customer_and_foreign_worker() {
    run_tier1_test(|mut env| async move {
        let worker = aggregate_worker(&mut env).await;
        let verifier = verifier(&mut env).await;
        let job = attested_aggregate_without_marker(&mut env, &worker, &verifier).await;
        env.warp_past_aggregate_marker_timeout(&job).await;

        let wrong_customer = Keypair::new();
        env.fund_keypair(&wrong_customer).await;
        let wrong_customer_token = env.create_ata(wrong_customer.pubkey()).await;
        let err = env
            .cancel_aggregate_proof_job(&wrong_customer, wrong_customer_token, &worker, &job)
            .await
            .expect_err("only the customer may cancel");
        assert_anchor_error(err, ProtocolError::WrongCustomer);

        let other_worker = aggregate_worker(&mut env).await;
        let err = env
            .cancel_aggregate_proof_job(&job.customer, job.customer_token, &other_worker, &job)
            .await
            .expect_err("the released worker must be the job's worker");
        assert_anchor_error(err, ProtocolError::JobWorkerMismatch);

        let job_state = env.read_job(job.job).await;
        assert_eq!(job_state.status, JobStatus::Completed as u8);
        assert_eq!(env.read_token_balance(job.escrow).await, REWARD_AMOUNT);
        assert_eq!(env.read_worker(worker.worker).await.locked_stake, REQUIRED_STAKE);
        assert_eq!(env.read_worker(other_worker.worker).await.locked_stake, 0);
    });
}
