#![cfg(feature = "tier1")]

//! `open_job` must refuse a challenge window in which verification cannot happen.
//!
//! `open_job` once validated only `challenge_window_seconds > 0`, so a customer could open
//! a job with a one-second window. `challenge_deadline` bounds both
//! `submit_verifier_attestation` and `challenge_job`, so such a job disables the branch
//! layer's economic protection at the customer's sole discretion.
//!
//! The bound is a `ProtocolConfig` value rather than a constant because the smallest
//! window in which verification is genuinely reachable differs by cluster: this suite and
//! the local validator run whole jobs in a few simulated seconds, while a deployment
//! sizes the window in `ATTESTATION_WINDOW_SECONDS` rungs.

use anchor_integration::*;
use kswarm_protocol::ProtocolError;
use serial_test::serial;

/// A floor unrelated to the harness default, so a test that passes under it can only be
/// reading the configured value.
const RAISED_FLOOR_SECONDS: u32 = 120;

#[test]
#[serial]
fn tier1_open_job_below_the_configured_floor_is_rejected() {
    run_tier1_test(|mut env| async move {
        let mut spec = JobSpec::branch_proof();
        spec.challenge_window_seconds = MIN_CHALLENGE_WINDOW_SECONDS - 1;

        let err = env
            .try_open_job(spec)
            .await
            .expect_err("a challenge window below the floor must be refused");
        assert_anchor_error(err, ProtocolError::ChallengeWindowBelowFloor);
    });
}

#[test]
#[serial]
fn tier1_open_job_with_a_one_second_challenge_window_is_rejected() {
    run_tier1_test(|mut env| async move {
        let mut spec = JobSpec::branch_proof();
        spec.challenge_window_seconds = 1;

        let err = env
            .try_open_job(spec)
            .await
            .expect_err("a one-second window must be refused");
        assert_anchor_error(err, ProtocolError::ChallengeWindowBelowFloor);
    });
}

#[test]
#[serial]
fn tier1_open_job_at_the_configured_floor_succeeds() {
    run_tier1_test(|mut env| async move {
        assert_eq!(
            env.read_config().await.min_challenge_window_seconds,
            MIN_CHALLENGE_WINDOW_SECONDS
        );
        let mut spec = JobSpec::branch_proof();
        spec.challenge_window_seconds = MIN_CHALLENGE_WINDOW_SECONDS;

        let job = env
            .try_open_job(spec)
            .await
            .expect("a challenge window exactly at the floor must be accepted");
        assert_eq!(
            env.read_job(job.job).await.challenge_window_seconds,
            MIN_CHALLENGE_WINDOW_SECONDS
        );
    });
}

/// The bound is the configured value, not a constant: under a raised floor a window the
/// harness default would accept is refused, and the raised floor itself is accepted.
#[test]
#[serial]
fn tier1_open_job_floor_follows_the_initialized_configuration() {
    run_uninitialized_tier1_test(TokenProgramKind::Token2022, |mut env| async move {
        let mut args = default_protocol_args();
        args.min_challenge_window_seconds = RAISED_FLOOR_SECONDS;
        env.initialize_protocol(args)
            .await
            .expect("initialize with a raised challenge-window floor");
        assert_eq!(
            env.read_config().await.min_challenge_window_seconds,
            RAISED_FLOOR_SECONDS
        );

        let mut below = JobSpec::branch_proof();
        below.challenge_window_seconds = RAISED_FLOOR_SECONDS - 1;
        let err = env
            .try_open_job(below)
            .await
            .expect_err("below the raised floor must be refused");
        assert_anchor_error(err, ProtocolError::ChallengeWindowBelowFloor);

        let mut at_floor = JobSpec::branch_proof();
        at_floor.challenge_window_seconds = RAISED_FLOOR_SECONDS;
        env.try_open_job(at_floor)
            .await
            .expect("at the raised floor must be accepted");
    });
}

#[test]
#[serial]
fn tier1_initialize_rejects_a_zero_challenge_window_floor() {
    run_uninitialized_tier1_test(TokenProgramKind::Token2022, |mut env| async move {
        let mut args = default_protocol_args();
        args.min_challenge_window_seconds = 0;
        let err = env
            .initialize_protocol(args)
            .await
            .expect_err("a zero floor restores the unbounded behaviour and must be refused");
        assert_anchor_error(err, ProtocolError::InvalidChallengeWindowFloor);

        // The config PDA was not created, so a valid initialization still works.
        env.initialize_protocol(default_protocol_args())
            .await
            .expect("initialize with a valid floor");
        assert_eq!(
            env.read_config().await.min_challenge_window_seconds,
            MIN_CHALLENGE_WINDOW_SECONDS
        );
    });
}

/// A zero window is still `InvalidDeadline`, not the new error: the pre-existing
/// non-zero rule is unchanged and keeps its own code.
#[test]
#[serial]
fn tier1_open_job_zero_windows_keep_invalid_deadline() {
    run_tier1_test(|mut env| async move {
        let mut zero_challenge = JobSpec::branch_proof();
        zero_challenge.challenge_window_seconds = 0;
        let err = env
            .try_open_job(zero_challenge)
            .await
            .expect_err("a zero challenge window must be refused");
        assert_anchor_error(err, ProtocolError::InvalidDeadline);

        let mut zero_execution = JobSpec::branch_proof();
        zero_execution.execution_window_seconds = 0;
        let err = env
            .try_open_job(zero_execution)
            .await
            .expect_err("a zero execution window must be refused");
        assert_anchor_error(err, ProtocolError::InvalidDeadline);
    });
}
