#![cfg(feature = "tier1")]

use anchor_integration::*;
use kswarm_protocol::{JobStatus, NodeRole, ProtocolError, StakeTier};
use serial_test::serial;
use solana_sdk::signature::Signer;

#[test]
#[serial]
fn tier1_q1_full_slash_happy() {
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

        let result_bytes = b"result-ok".to_vec();
        let submitted_hash = result_hash(&result_bytes);
        let job = env
            .complete_job(&worker, JobSpec::default(), result_bytes)
            .await;
        env.submit_verifier_attestation(&verifier, &job, submitted_hash, ZERO_HASH)
            .await
            .expect("submit matching verifier attestation");

        assert_eq!(
            env.read_token_balance(job.customer_token).await,
            job.customer_funding_amount - job.args.reward_amount
        );
        assert_eq!(
            env.read_token_balance(job.escrow).await,
            job.args.reward_amount
        );
        assert_eq!(env.read_token_balance(worker.token_account).await, 0);

        env.warp_past_challenge_deadline(&job).await;
        env.settle_job(&job.customer, &worker, &job)
            .await
            .expect("settle job");

        let job_state = env.read_job(job.job).await;
        let worker_state = env.read_worker(worker.worker).await;
        assert_eq!(job_state.status, JobStatus::Settled as u8);
        assert_eq!(worker_state.locked_stake, 0);
        assert_eq!(worker_state.active_claims, 0);
        assert_eq!(
            env.read_token_balance(worker.token_account).await,
            job.args.reward_amount
        );
        assert_eq!(env.read_token_balance(job.escrow).await, 0);
    });
}

#[test]
#[serial]
fn tier1_q1_full_slash_mismatch() {
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

        let result_bytes = b"result-ok".to_vec();
        let job = env
            .complete_job(&worker, JobSpec::default(), result_bytes)
            .await;
        // H2-Interim rule (PR-3): a challenge is accepted only from the verifier the
        // customer (or admin) assigned to the job, for every job class. Without this
        // assignment the challenge below is rejected and no stake moves.
        env.assign_verifier(&job.customer, &job, verifier.authority.pubkey())
            .await
            .expect("customer assigns the challenging verifier");
        env.submit_verifier_attestation(&verifier, &job, [0x9a; 32], ZERO_HASH)
            .await
            .expect("submit mismatched verifier attestation");

        env.challenge_job(&verifier, &worker, &job)
            .await
            .expect("challenge mismatched attestation");
        env.refund_slashed_job_escrow(&job.customer, &job)
            .await
            .expect("refund slashed escrow");
        env.claim_verifier_slash_reward(&verifier.authority, &verifier, &worker, &job)
            .await
            .expect("claim verifier slash reward");
        env.claim_customer_slash_compensation(&job.customer, &worker, &job)
            .await
            .expect("claim customer slash compensation");

        let job_state = env.read_job(job.job).await;
        let worker_state = env.read_worker(worker.worker).await;
        assert_eq!(job_state.status, JobStatus::Slashed as u8);
        assert!(job_state.escrow_refunded);
        assert!(job_state.verifier_reward_paid);
        assert!(job_state.customer_slash_paid);
        assert!(job_state.slash_settled);
        assert_eq!(worker_state.locked_stake, 0);
        assert_eq!(worker_state.active_claims, 0);
        assert_eq!(
            env.read_token_balance(job.customer_token).await,
            job.customer_funding_amount + job.args.required_stake - job.args.challenge_bond
        );
        assert_eq!(
            env.read_token_balance(verifier.token_account).await,
            job.args.challenge_bond
        );
        assert_eq!(
            env.read_token_balance(worker.stake_vault).await,
            WORKER_STAKE_DEPOSIT - job.args.required_stake
        );
        assert_eq!(env.read_token_balance(job.escrow).await, 0);
    });
}

#[test]
#[serial]
fn tier1_q1_self_attestation_rejected() {
    run_tier1_test(|mut env| async move {
        let worker = env
            .register_participant(
                NodeRole::Verifier as u8,
                ZERO_HASH,
                ZERO_HASH,
                VERIFIER_STAKE_DEPOSIT,
            )
            .await;
        let result_bytes = b"result-ok".to_vec();
        let submitted_hash = result_hash(&result_bytes);
        let job = env
            .complete_job(
                &worker,
                JobSpec {
                    required_role: NodeRole::Verifier as u8,
                    required_tier: StakeTier::TierOne as u8,
                    ..JobSpec::default()
                },
                result_bytes,
            )
            .await;

        let err = env
            .submit_verifier_attestation(&worker, &job, submitted_hash, ZERO_HASH)
            .await
            .expect_err("self attestation must be rejected");
        assert_anchor_error(err, ProtocolError::SelfAttestationForbidden);
    });
}

#[test]
#[serial]
fn tier1_q1_attestation_one_per_job() {
    run_tier1_test(|mut env| async move {
        let worker = env
            .register_participant(
                NodeRole::WorkerBasic as u8,
                ZERO_HASH,
                ZERO_HASH,
                WORKER_STAKE_DEPOSIT,
            )
            .await;
        let verifier_one = env
            .register_participant(
                NodeRole::Verifier as u8,
                ZERO_HASH,
                ZERO_HASH,
                VERIFIER_STAKE_DEPOSIT,
            )
            .await;
        let verifier_two = env
            .register_participant(
                NodeRole::Verifier as u8,
                ZERO_HASH,
                ZERO_HASH,
                VERIFIER_STAKE_DEPOSIT,
            )
            .await;
        let result_bytes = b"result-ok".to_vec();
        let submitted_hash = result_hash(&result_bytes);
        let job = env
            .complete_job(&worker, JobSpec::default(), result_bytes)
            .await;
        env.submit_verifier_attestation(&verifier_one, &job, submitted_hash, ZERO_HASH)
            .await
            .expect("first attestation");

        let err = env
            .submit_verifier_attestation(&verifier_two, &job, submitted_hash, ZERO_HASH)
            .await
            .expect_err("second attestation must be rejected");
        assert_anchor_error(err, ProtocolError::AttestationAlreadyExists);
    });
}

#[test]
#[serial]
fn tier1_q1_stake_floor_enforced() {
    run_tier1_test(|mut env| async move {
        let worker = env
            .register_participant(
                NodeRole::WorkerBasic as u8,
                ZERO_HASH,
                ZERO_HASH,
                WORKER_STAKE_DEPOSIT,
            )
            .await;
        let low_stake_verifier = env
            .register_participant(
                NodeRole::Verifier as u8,
                ZERO_HASH,
                ZERO_HASH,
                LOW_VERIFIER_STAKE_DEPOSIT,
            )
            .await;
        let result_bytes = b"result-ok".to_vec();
        let submitted_hash = result_hash(&result_bytes);
        let job = env
            .complete_job(&worker, JobSpec::default(), result_bytes)
            .await;

        let err = env
            .submit_verifier_attestation(&low_stake_verifier, &job, submitted_hash, ZERO_HASH)
            .await
            .expect_err("low-stake verifier must be rejected");
        assert_anchor_error(err, ProtocolError::AttestationStakeTooLow);
    });
}

#[test]
#[serial]
fn tier1_q1_software_digest_match_required() {
    run_tier1_test(|mut env| async move {
        let worker = env
            .register_participant(
                NodeRole::WorkerBasic as u8,
                ZERO_HASH,
                SOFTWARE_DIGEST,
                WORKER_STAKE_DEPOSIT,
            )
            .await;
        let verifier = env
            .register_participant(
                NodeRole::Verifier as u8,
                ZERO_HASH,
                ALT_SOFTWARE_DIGEST,
                VERIFIER_STAKE_DEPOSIT,
            )
            .await;
        let result_bytes = b"result-ok".to_vec();
        let submitted_hash = result_hash(&result_bytes);
        let job = env
            .complete_job(
                &worker,
                JobSpec {
                    required_software_digest: SOFTWARE_DIGEST,
                    ..JobSpec::default()
                },
                result_bytes,
            )
            .await;

        let err = env
            .submit_verifier_attestation(&verifier, &job, submitted_hash, ALT_SOFTWARE_DIGEST)
            .await
            .expect_err("wrong verifier digest must be rejected");
        assert_anchor_error(err, ProtocolError::AttestationDigestMismatch);
    });
}

#[test]
#[serial]
fn tier1_q1_attestation_window_closed() {
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
        let result_bytes = b"result-ok".to_vec();
        let submitted_hash = result_hash(&result_bytes);
        let job = env
            .complete_job(&worker, JobSpec::default(), result_bytes)
            .await;
        env.warp_past_challenge_deadline(&job).await;

        let err = env
            .submit_verifier_attestation(&verifier, &job, submitted_hash, ZERO_HASH)
            .await
            .expect_err("late attestation must be rejected");
        assert_anchor_error(err, ProtocolError::AttestationWindowClosed);
    });
}
