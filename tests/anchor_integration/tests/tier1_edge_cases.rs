#![cfg(feature = "tier1")]

use anchor_integration::*;
use kswarm_protocol::{JobClass, JobStatus, NodeRole, ProtocolError};
use serial_test::serial;
use solana_sdk::pubkey::Pubkey;

const AGGREGATE_RESULT: &[u8] = b"aggregate-result";
const BRANCH_RESULT: &[u8] = b"result-ok";

fn aggregate_worker(env: &mut Tier1Context) -> impl std::future::Future<Output = Participant> + '_ {
    env.register_participant(
        NodeRole::WorkerProof as u8,
        kswarm_protocol::AGGREGATE_PROOF_CAPABILITY_HASH,
        IMAGE_ID,
        WORKER_STAKE_DEPOSIT,
    )
}

fn branch_worker(env: &mut Tier1Context) -> impl std::future::Future<Output = Participant> + '_ {
    env.register_participant(
        NodeRole::WorkerProof as u8,
        ZERO_HASH,
        ZERO_HASH,
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

async fn completed_aggregate(env: &mut Tier1Context, worker: &Participant) -> TestJob {
    env.complete_job(worker, JobSpec::aggregate(), AGGREGATE_RESULT.to_vec())
        .await
}

async fn completed_attested_aggregate(
    env: &mut Tier1Context,
    worker: &Participant,
    verifier: &Participant,
) -> TestJob {
    let job = completed_aggregate(env, worker).await;
    env.submit_verifier_attestation(verifier, &job, result_hash(AGGREGATE_RESULT), IMAGE_ID)
        .await
        .expect("submit aggregate verifier attestation");
    job
}

fn store_valid_marker(env: &mut Tier1Context, job: &TestJob, byte: u8) -> Pubkey {
    let (marker_key, marker) = valid_bonsol_marker_for_job(job, [byte; 32]);
    env.store_bonsol_marker(marker_key, marker);
    marker_key
}

#[test]
#[serial]
fn tier1_edge_settle_aggregate_without_marker() {
    run_tier1_test(|mut env| async move {
        let worker = aggregate_worker(&mut env).await;
        let verifier = verifier(&mut env).await;
        let job = completed_attested_aggregate(&mut env, &worker, &verifier).await;
        env.warp_past_challenge_deadline(&job).await;

        let (marker_key, _) = valid_bonsol_marker_for_job(&job, [1; 32]);
        env.store_empty_system_account(marker_key);
        let err = env
            .settle_aggregate_proof_job(&worker.authority, &worker, &job, marker_key)
            .await
            .expect_err("settle without marker must fail");

        assert_anchor_error(err, ProtocolError::BonsolMarkerMissing);
    });
}

#[test]
#[serial]
fn tier1_edge_settle_aggregate_marker_keys_mismatch() {
    run_tier1_test(|mut env| async move {
        let worker = aggregate_worker(&mut env).await;
        let verifier = verifier(&mut env).await;
        let job = completed_attested_aggregate(&mut env, &worker, &verifier).await;
        env.warp_past_challenge_deadline(&job).await;

        let wrong_key = Pubkey::new_unique();
        let (_, marker) = valid_bonsol_marker_for_job(&job, [2; 32]);
        env.store_bonsol_marker(wrong_key, marker);
        let err = env
            .settle_aggregate_proof_job(&worker.authority, &worker, &job, wrong_key)
            .await
            .expect_err("settle with mismatched marker key must fail");

        assert_anchor_error(err, ProtocolError::BonsolMarkerMismatch);
    });
}

#[test]
#[serial]
fn tier1_edge_settle_aggregate_without_verifier_attestation() {
    run_tier1_test(|mut env| async move {
        let worker = aggregate_worker(&mut env).await;
        let job = completed_aggregate(&mut env, &worker).await;
        let marker_key = store_valid_marker(&mut env, &job, 3);
        env.warp_past_challenge_deadline(&job).await;

        let err = env
            .settle_aggregate_proof_job(&worker.authority, &worker, &job, marker_key)
            .await
            .expect_err("settle without attestation must fail");

        assert_anchor_error(err, ProtocolError::VerifierAttestationRequired);
    });
}

#[test]
#[serial]
fn tier1_edge_double_settle_rejected() {
    run_tier1_test(|mut env| async move {
        let worker = aggregate_worker(&mut env).await;
        let verifier = verifier(&mut env).await;
        let job = completed_attested_aggregate(&mut env, &worker, &verifier).await;
        let marker_key = store_valid_marker(&mut env, &job, 4);
        env.warp_past_challenge_deadline(&job).await;

        env.settle_aggregate_proof_job(&worker.authority, &worker, &job, marker_key)
            .await
            .expect("first aggregate settle");
        let err = env
            .settle_aggregate_proof_job(&worker.authority, &worker, &job, marker_key)
            .await
            .expect_err("second aggregate settle must fail");

        assert_anchor_error(err, ProtocolError::InvalidJobState);
    });
}

#[test]
#[serial]
fn tier1_edge_settle_before_challenge_window_rejected() {
    run_tier1_test(|mut env| async move {
        let worker = aggregate_worker(&mut env).await;
        let verifier = verifier(&mut env).await;
        let job = completed_attested_aggregate(&mut env, &worker, &verifier).await;
        let marker_key = store_valid_marker(&mut env, &job, 5);

        let err = env
            .settle_aggregate_proof_job(&worker.authority, &worker, &job, marker_key)
            .await
            .expect_err("settle before challenge window closes must fail");

        assert_anchor_error(err, ProtocolError::ChallengeWindowOpen);
    });
}

#[test]
#[serial]
fn tier1_edge_branch_proof_class_uses_settle_job_not_settle_aggregate() {
    run_tier1_test(|mut env| async move {
        let worker = branch_worker(&mut env).await;
        let aggregate_worker = aggregate_worker(&mut env).await;
        let verifier = verifier(&mut env).await;

        let branch_job = env
            .complete_job(&worker, JobSpec::branch_proof(), BRANCH_RESULT.to_vec())
            .await;
        let (marker_key, marker) = valid_bonsol_marker_for_job(&branch_job, [6; 32]);
        env.store_bonsol_marker(marker_key, marker);
        env.warp_past_challenge_deadline(&branch_job).await;

        let aggregate_err = env
            .settle_aggregate_proof_job(&worker.authority, &worker, &branch_job, marker_key)
            .await
            .expect_err("branch proof must not use aggregate settlement");
        assert_anchor_error(aggregate_err, ProtocolError::JobNotAggregateProof);

        env.settle_job(&worker.authority, &worker, &branch_job)
            .await
            .expect("branch proof settles through generic settle_job");
        let branch_state = env.read_job(branch_job.job).await;
        assert_eq!(branch_state.status, JobStatus::Settled as u8);
        assert_eq!(branch_state.job_class, JobClass::BranchProof as u8);

        let aggregate_job =
            completed_attested_aggregate(&mut env, &aggregate_worker, &verifier).await;
        env.warp_past_challenge_deadline(&aggregate_job).await;
        let generic_err = env
            .settle_job(
                &aggregate_worker.authority,
                &aggregate_worker,
                &aggregate_job,
            )
            .await
            .expect_err("aggregate proof must use aggregate settlement");
        assert_anchor_error(
            generic_err,
            ProtocolError::AggregateProofRequiresAggregateSettlement,
        );
    });
}
