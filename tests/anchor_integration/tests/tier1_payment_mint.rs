#![cfg(feature = "tier1")]
//! Payment-mint coverage (PR-2 `feat/kai-payment-mint`): the protocol must work
//! with a classic SPL Token mint (KAI's program), pin the token program in
//! config, read stake floors from config, and validate `initialize_protocol`
//! arguments.

use anchor_integration::*;
use kswarm_protocol::{JobStatus, NodeRole, ProtocolError, StakeTier};
use serial_test::serial;
use solana_program_test::BanksClientError;
use solana_sdk::transaction::TransactionError;

fn basic_worker(
    env: &mut Tier1Context,
    stake: u64,
) -> impl std::future::Future<Output = Participant> + '_ {
    env.register_participant(NodeRole::WorkerBasic as u8, ZERO_HASH, ZERO_HASH, stake)
}

/// register -> stake -> open -> claim -> submit -> settle on a classic SPL mint.
#[test]
#[serial]
fn payment_mint_classic_spl_full_flow() {
    run_tier1_test_with(TokenProgramKind::Classic, |mut env| async move {
        let config = env.read_config().await;
        assert_eq!(config.token_program, TokenProgramKind::Classic.program_id());
        assert_eq!(config.payment_mint, env.mint);
        assert_eq!(config.payment_decimals, TOKEN_DECIMALS);
        assert_eq!(config.tier_one_stake_floor, TIER_ONE_STAKE_FLOOR);
        assert_eq!(config.tier_two_stake_floor, TIER_TWO_STAKE_FLOOR);
        assert_eq!(config.tier_three_stake_floor, TIER_THREE_STAKE_FLOOR);
        assert_eq!(config.verifier_stake_floor, VERIFIER_STAKE_FLOOR);

        let worker = basic_worker(&mut env, WORKER_STAKE_DEPOSIT).await;
        assert_eq!(
            env.read_token_balance(worker.stake_vault).await,
            WORKER_STAKE_DEPOSIT
        );

        let job = env
            .complete_job(&worker, JobSpec::default(), b"result-ok".to_vec())
            .await;
        assert_eq!(env.read_token_balance(job.escrow).await, REWARD_AMOUNT);
        let worker_state = env.read_worker(worker.worker).await;
        assert_eq!(worker_state.locked_stake, REQUIRED_STAKE);

        env.warp_past_challenge_deadline(&job).await;
        let paid_before = env.read_token_balance(worker.token_account).await;
        env.settle_job(&worker.authority, &worker, &job)
            .await
            .expect("settle job on classic SPL mint");

        let job_state = env.read_job(job.job).await;
        assert_eq!(job_state.status, JobStatus::Settled as u8);
        assert_eq!(
            env.read_token_balance(worker.token_account).await,
            paid_before + REWARD_AMOUNT
        );
        assert_eq!(env.read_token_balance(job.escrow).await, 0);
        let worker_state = env.read_worker(worker.worker).await;
        assert_eq!(worker_state.locked_stake, 0);
    });
}

#[test]
#[serial]
fn payment_mint_token_2022_config_pins_token_program() {
    run_tier1_test(|mut env| async move {
        let config = env.read_config().await;
        assert_eq!(config.token_program, TokenProgramKind::Token2022.program_id());
        assert_eq!(config.payment_mint, env.mint);
        assert_eq!(config.payment_decimals, TOKEN_DECIMALS);
        assert_eq!(config.tier_one_stake_floor, TIER_ONE_STAKE_FLOOR);
        assert_eq!(config.verifier_stake_floor, VERIFIER_STAKE_FLOOR);
    });
}

#[test]
#[serial]
fn payment_mint_initialize_rejects_mint_owner_mismatch() {
    run_uninitialized_tier1_test(TokenProgramKind::Classic, |mut env| async move {
        let classic_mint = env.mint;
        let err = env
            .initialize_protocol_with(
                classic_mint,
                TokenProgramKind::Token2022.program_id(),
                default_protocol_args(),
            )
            .await
            .expect_err("classic mint with Token-2022 program must be rejected");
        assert_anchor_error(err, ProtocolError::PaymentMintOwnerMismatch);

        let token_2022_mint = env
            .create_payment_mint(TokenProgramKind::Token2022, false)
            .await;
        let err = env
            .initialize_protocol_with(
                token_2022_mint,
                TokenProgramKind::Classic.program_id(),
                default_protocol_args(),
            )
            .await
            .expect_err("Token-2022 mint with classic program must be rejected");
        assert_anchor_error(err, ProtocolError::PaymentMintOwnerMismatch);

        env.initialize_protocol(default_protocol_args())
            .await
            .expect("matching mint owner initializes");
        let config = env.read_config().await;
        assert_eq!(config.payment_mint, classic_mint);
        assert_eq!(config.token_program, TokenProgramKind::Classic.program_id());
    });
}

#[test]
#[serial]
fn payment_mint_initialize_rejects_non_monotonic_floors() {
    run_uninitialized_tier1_test(TokenProgramKind::Token2022, |mut env| async move {
        let mut equal_tiers = default_protocol_args();
        equal_tiers.tier_two_stake_floor = equal_tiers.tier_one_stake_floor;
        let err = env
            .initialize_protocol(equal_tiers)
            .await
            .expect_err("equal tier floors must be rejected");
        assert_anchor_error(err, ProtocolError::InvalidStakeFloors);

        let mut zero_tier_one = default_protocol_args();
        zero_tier_one.tier_one_stake_floor = 0;
        let err = env
            .initialize_protocol(zero_tier_one)
            .await
            .expect_err("zero tier-one floor must be rejected");
        assert_anchor_error(err, ProtocolError::InvalidStakeFloors);

        let mut descending = default_protocol_args();
        descending.tier_three_stake_floor = descending.tier_two_stake_floor - 1;
        let err = env
            .initialize_protocol(descending)
            .await
            .expect_err("descending tier floors must be rejected");
        assert_anchor_error(err, ProtocolError::InvalidStakeFloors);

        let mut zero_verifier = default_protocol_args();
        zero_verifier.verifier_stake_floor = 0;
        let err = env
            .initialize_protocol(zero_verifier)
            .await
            .expect_err("zero verifier floor must be rejected");
        assert_anchor_error(err, ProtocolError::InvalidVerifierStakeFloor);

        env.initialize_protocol(default_protocol_args())
            .await
            .expect("valid floors initialize");
    });
}

#[test]
#[serial]
fn payment_mint_initialize_rejects_transfer_fee_mint() {
    run_uninitialized_tier1_test(TokenProgramKind::Token2022, |mut env| async move {
        let fee_mint = env
            .create_payment_mint(TokenProgramKind::Token2022, true)
            .await;
        let err = env
            .initialize_protocol_with(
                fee_mint,
                TokenProgramKind::Token2022.program_id(),
                default_protocol_args(),
            )
            .await
            .expect_err("transfer-fee mint must be rejected");
        assert_anchor_error(err, ProtocolError::ForbiddenMintExtension);

        env.initialize_protocol(default_protocol_args())
            .await
            .expect("plain Token-2022 mint initializes");
    });
}

#[test]
#[serial]
fn payment_mint_initialize_is_one_shot() {
    run_tier1_test(|mut env| async move {
        let mut other_floors = default_protocol_args();
        other_floors.tier_one_stake_floor += UNIT;
        let err = env
            .initialize_protocol(other_floors)
            .await
            .expect_err("second initialize must fail");
        assert!(
            matches!(
                err,
                BanksClientError::TransactionError(TransactionError::InstructionError(0, _))
            ),
            "expected the init constraint to fail, got {err:?}"
        );
        let config = env.read_config().await;
        assert_eq!(config.tier_one_stake_floor, TIER_ONE_STAKE_FLOOR);
    });
}

#[test]
#[serial]
fn payment_mint_wrong_token_program_rejected() {
    run_tier1_test(|mut env| async move {
        let worker = basic_worker(&mut env, 0).await;
        env.mint_to(worker.token_account, WORKER_STAKE_DEPOSIT).await;

        let err = env
            .deposit_stake_with_token_program(
                &worker.authority,
                worker.worker,
                worker.stake_vault,
                worker.token_account,
                WORKER_STAKE_DEPOSIT,
                TokenProgramKind::Classic.program_id(),
            )
            .await
            .expect_err("classic token program must be rejected under a Token-2022 config");
        assert_anchor_error(err, ProtocolError::WrongTokenProgram);
        assert_eq!(env.read_token_balance(worker.stake_vault).await, 0);

        env.deposit_stake(
            &worker.authority,
            worker.worker,
            worker.stake_vault,
            worker.token_account,
            WORKER_STAKE_DEPOSIT,
        )
        .await
        .expect("pinned token program deposits");
        assert_eq!(
            env.read_token_balance(worker.stake_vault).await,
            WORKER_STAKE_DEPOSIT
        );
    });
}

#[test]
#[serial]
fn payment_mint_stake_floors_come_from_config() {
    run_uninitialized_tier1_test(TokenProgramKind::Classic, |mut env| async move {
        let mut floors = default_protocol_args();
        floors.tier_one_stake_floor = 10 * UNIT;
        floors.tier_two_stake_floor = 20 * UNIT;
        floors.tier_three_stake_floor = 30 * UNIT;
        floors.verifier_stake_floor = 5 * UNIT;
        env.initialize_protocol(floors)
            .await
            .expect("initialize with custom floors");

        let below_floor = basic_worker(&mut env, 10 * UNIT - 1).await;
        let at_floor = basic_worker(&mut env, 10 * UNIT).await;
        let tier_two = basic_worker(&mut env, 20 * UNIT).await;

        let tier_one_spec = JobSpec {
            required_stake: UNIT,
            challenge_bond: UNIT,
            ..JobSpec::default()
        };
        let tier_one_job = env.open_job(tier_one_spec).await;
        env.commit_input_artifact(&tier_one_job).await;
        let err = env
            .claim_job(&below_floor, &tier_one_job)
            .await
            .expect_err("stake below the configured tier-one floor cannot claim");
        assert_anchor_error(err, ProtocolError::InsufficientStakeTier);
        env.claim_job(&at_floor, &tier_one_job)
            .await
            .expect("stake at the configured tier-one floor claims");

        let tier_two_spec = JobSpec {
            required_tier: StakeTier::TierTwo as u8,
            required_stake: UNIT,
            challenge_bond: UNIT,
            ..JobSpec::default()
        };
        let tier_two_job = env.open_job(tier_two_spec).await;
        env.commit_input_artifact(&tier_two_job).await;
        let err = env
            .claim_job(&at_floor, &tier_two_job)
            .await
            .expect_err("tier-one stake cannot claim a tier-two job");
        assert_anchor_error(err, ProtocolError::InsufficientStakeTier);
        env.claim_job(&tier_two, &tier_two_job)
            .await
            .expect("stake at the configured tier-two floor claims");
    });
}
