#![cfg(feature = "tier1")]

use anchor_integration::*;
use kswarm_protocol::{
    JobStatus, NodeRole, ProtocolError, ATTESTATION_WINDOW_SECONDS, MAX_REASSIGNMENTS,
};
use serial_test::serial;
use solana_sdk::signature::{Keypair, Signer};

const AGGREGATE_RESULT_BYTES: &[u8] = b"aggregate-result";

async fn register_aggregate_worker(env: &mut Tier1Context) -> Participant {
    env.register_participant(
        NodeRole::WorkerProof as u8,
        kswarm_protocol::AGGREGATE_PROOF_CAPABILITY_HASH,
        IMAGE_ID,
        WORKER_STAKE_DEPOSIT,
    )
    .await
}

async fn register_verifier(env: &mut Tier1Context) -> Participant {
    env.register_participant(
        NodeRole::Verifier as u8,
        ZERO_HASH,
        IMAGE_ID,
        VERIFIER_STAKE_DEPOSIT,
    )
    .await
}

async fn completed_aggregate_job(
    env: &mut Tier1Context,
    worker: &Participant,
    spec: JobSpec,
) -> TestJob {
    env.complete_job(worker, spec, AGGREGATE_RESULT_BYTES.to_vec())
        .await
}

#[test]
#[serial]
fn tier1_r3_initial_assignment() {
    run_tier1_test(|mut env| async move {
        let worker = register_aggregate_worker(&mut env).await;
        let verifier = register_verifier(&mut env).await;
        let job = completed_aggregate_job(&mut env, &worker, JobSpec::aggregate()).await;

        env.assign_verifier(&job.customer, &job, verifier.authority.pubkey())
            .await
            .expect("assign verifier");

        let job_state = env.read_job(job.job).await;
        assert_eq!(
            job_state.assigned_verifier_authority,
            Some(verifier.authority.pubkey())
        );
        assert!(job_state.assigned_verifier_unix.is_some());
        assert_eq!(job_state.reassignment_counter, 0);
    });
}

#[test]
#[serial]
fn tier1_r3_reassignment_after_window() {
    run_tier1_test(|mut env| async move {
        let worker = register_aggregate_worker(&mut env).await;
        let verifier = register_verifier(&mut env).await;
        let job = completed_aggregate_job(&mut env, &worker, JobSpec::aggregate()).await;
        env.assign_verifier(&job.customer, &job, verifier.authority.pubkey())
            .await
            .expect("assign verifier");
        let assigned_unix = env
            .read_job(job.job)
            .await
            .assigned_verifier_unix
            .expect("assigned unix");

        env.warp_past_attestation_window().await;
        env.reassign_verifier(&job.customer, &job)
            .await
            .expect("reassign verifier");

        let job_state = env.read_job(job.job).await;
        assert_eq!(job_state.assigned_verifier_authority, None);
        assert!(job_state.assigned_verifier_unix.unwrap() > assigned_unix);
        assert_eq!(job_state.reassignment_counter, 1);
    });
}

#[test]
#[serial]
fn tier1_r3_reassignment_in_window_rejected() {
    run_tier1_test(|mut env| async move {
        let worker = register_aggregate_worker(&mut env).await;
        let verifier = register_verifier(&mut env).await;
        let job = completed_aggregate_job(&mut env, &worker, JobSpec::aggregate()).await;
        env.assign_verifier(&job.customer, &job, verifier.authority.pubkey())
            .await
            .expect("assign verifier");

        let err = env
            .reassign_verifier(&job.customer, &job)
            .await
            .expect_err("reassignment inside window must fail");
        assert_anchor_error(err, ProtocolError::VerifierStillInWindow);
    });
}

#[test]
#[serial]
fn tier1_r3_reassignment_limit_reached() {
    run_tier1_test(|mut env| async move {
        let worker = register_aggregate_worker(&mut env).await;
        let job = completed_aggregate_job(&mut env, &worker, JobSpec::aggregate()).await;
        env.exhaust_reassignments(&job.customer, &worker, &job)
            .await;

        env.assign_verifier(&job.customer, &job, Keypair::new().pubkey())
            .await
            .expect("assign after third reassignment");
        env.warp_past_attestation_window().await;
        let err = env
            .reassign_verifier(&job.customer, &job)
            .await
            .expect_err("fourth reassignment must fail");
        assert_anchor_error(err, ProtocolError::ReassignmentLimitReached);
    });
}

#[test]
#[serial]
fn tier1_r3_cancel_after_exhaustion() {
    run_tier1_test(|mut env| async move {
        let worker = register_aggregate_worker(&mut env).await;
        let job = completed_aggregate_job(&mut env, &worker, JobSpec::aggregate()).await;
        env.exhaust_reassignments(&job.customer, &worker, &job)
            .await;

        let worker_before = env.read_worker(worker.worker).await;
        assert_eq!(worker_before.locked_stake, REQUIRED_STAKE);
        assert_eq!(worker_before.active_claims, 1);

        env.cancel_aggregate_proof_job(&job.customer, job.customer_token, &worker, &job)
            .await
            .expect("cancel exhausted aggregate job");

        let job_state = env.read_job(job.job).await;
        assert_eq!(job_state.status, JobStatus::CancelledOnExhaustion as u8);
        assert_eq!(job_state.reassignment_counter, MAX_REASSIGNMENTS);
        assert_eq!(
            env.read_token_balance(job.customer_token).await,
            job.customer_funding_amount
        );
        assert_eq!(env.read_token_balance(job.escrow).await, 0);
        // The worker did submit; cancellation releases its claim without a slash.
        let worker_after = env.read_worker(worker.worker).await;
        assert_eq!(worker_after.locked_stake, 0);
        assert_eq!(worker_after.active_claims, 0);
        assert_eq!(
            env.read_token_balance(worker.stake_vault).await,
            WORKER_STAKE_DEPOSIT
        );
    });
}

#[test]
#[serial]
fn tier1_r3_cancel_with_attestation_rejected() {
    run_tier1_test(|mut env| async move {
        let worker = register_aggregate_worker(&mut env).await;
        let verifier = register_verifier(&mut env).await;
        let mut spec = JobSpec::aggregate();
        spec.challenge_window_seconds = (ATTESTATION_WINDOW_SECONDS as u32 * 4) + 60;
        let job = completed_aggregate_job(&mut env, &worker, spec).await;
        env.exhaust_reassignments(&job.customer, &worker, &job)
            .await;
        env.assign_verifier(&job.customer, &job, verifier.authority.pubkey())
            .await
            .expect("assign final verifier");
        env.submit_verifier_attestation(
            &verifier,
            &job,
            result_hash(AGGREGATE_RESULT_BYTES),
            IMAGE_ID,
        )
        .await
        .expect("submit final verifier attestation");

        let err = env
            .cancel_aggregate_proof_job(&job.customer, job.customer_token, &worker, &job)
            .await
            .expect_err("cancel with attestation must fail");
        assert_anchor_error(err, ProtocolError::AttestationAlreadyPresent);
    });
}

#[test]
#[serial]
fn tier1_r3_cancel_before_exhaustion_rejected() {
    run_tier1_test(|mut env| async move {
        let worker = register_aggregate_worker(&mut env).await;
        let job = completed_aggregate_job(&mut env, &worker, JobSpec::aggregate()).await;

        let err = env
            .cancel_aggregate_proof_job(&job.customer, job.customer_token, &worker, &job)
            .await
            .expect_err("cancel before exhaustion must fail");
        assert_anchor_error(err, ProtocolError::RegistryNotExhausted);
    });
}

#[test]
#[serial]
fn tier1_r3_cancel_wrong_customer_rejected() {
    run_tier1_test(|mut env| async move {
        let worker = register_aggregate_worker(&mut env).await;
        let job = completed_aggregate_job(&mut env, &worker, JobSpec::aggregate()).await;
        env.exhaust_reassignments(&job.customer, &worker, &job)
            .await;

        let wrong_customer = Keypair::new();
        env.fund_keypair(&wrong_customer).await;
        let wrong_customer_token = env.create_ata(wrong_customer.pubkey()).await;
        let err = env
            .cancel_aggregate_proof_job(&wrong_customer, wrong_customer_token, &worker, &job)
            .await
            .expect_err("wrong customer cancel must fail");
        assert_anchor_error(err, ProtocolError::WrongCustomer);
    });
}
