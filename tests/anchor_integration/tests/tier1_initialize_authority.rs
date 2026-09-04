#![cfg(feature = "tier1")]
//! `initialize_protocol` is one-shot and names the admin, so it must be callable only
//! by the program's upgrade authority. The harness models a real upgradeable
//! deployment (`Program` + `ProgramData` accounts under the upgradeable loader, upgrade
//! authority = the test payer), so these tests run the program's real check.

use anchor_integration::*;
use kswarm_protocol::ProtocolError;
use serial_test::serial;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Keypair;

/// Anchor framework error `AccountOwnedByWrongProgram`.
const ANCHOR_ACCOUNT_OWNED_BY_WRONG_PROGRAM: u32 = 3007;

#[test]
#[serial]
fn initialize_authority_upgrade_authority_becomes_admin() {
    run_uninitialized_tier1_test(TokenProgramKind::Classic, |mut env| async move {
        assert_eq!(env.program_data, program_data_pda());
        env.initialize_protocol(default_stake_floors())
            .await
            .expect("the upgrade authority initializes");
        let config = env.read_config().await;
        assert_eq!(config.admin, env.upgrade_authority());
    });
}

#[test]
#[serial]
fn initialize_authority_rejects_signer_that_is_not_upgrade_authority() {
    run_uninitialized_tier1_test(TokenProgramKind::Classic, |mut env| async move {
        let intruder = Keypair::new();
        env.fund_keypair(&intruder).await;
        let (mint, token_program, program_data) = (env.mint, env.token_program, env.program_data);

        let err = env
            .initialize_protocol_as(&intruder, program_data, mint, token_program, default_stake_floors())
            .await
            .expect_err("a signer that is not the upgrade authority must be rejected");
        assert_anchor_error(err, ProtocolError::AdminNotUpgradeAuthority);

        env.initialize_protocol(default_stake_floors())
            .await
            .expect("the real upgrade authority still initializes");
        assert_eq!(env.read_config().await.admin, env.upgrade_authority());
    });
}

#[test]
#[serial]
fn initialize_authority_rejects_program_data_that_is_not_the_programs() {
    run_uninitialized_tier1_test(TokenProgramKind::Classic, |mut env| async move {
        // A well-formed ProgramData account naming the payer, at the wrong address.
        let forged = Pubkey::new_unique();
        let payer = env.payer();
        env.store_program_data_account(forged, Some(payer));
        let admin = env.ctx.payer.insecure_clone();
        let (mint, token_program) = (env.mint, env.token_program);

        let err = env
            .initialize_protocol_as(&admin, forged, mint, token_program, default_stake_floors())
            .await
            .expect_err("a ProgramData account that is not the program's must be rejected");
        assert_anchor_error(err, ProtocolError::ProgramDataMismatch);

        env.initialize_protocol(default_stake_floors())
            .await
            .expect("the real ProgramData account initializes");
    });
}

#[test]
#[serial]
fn initialize_authority_rejects_account_that_is_not_program_data() {
    run_uninitialized_tier1_test(TokenProgramKind::Classic, |mut env| async move {
        let admin = env.ctx.payer.insecure_clone();
        let (mint, token_program) = (env.mint, env.token_program);

        // The mint is owned by the token program, not the upgradeable loader.
        let err = env
            .initialize_protocol_as(&admin, mint, mint, token_program, default_stake_floors())
            .await
            .expect_err("a non-ProgramData account must be rejected");
        assert_custom_error_code(err, ANCHOR_ACCOUNT_OWNED_BY_WRONG_PROGRAM);
    });
}

#[test]
#[serial]
fn initialize_authority_rejects_immutable_program() {
    run_uninitialized_tier1_test(TokenProgramKind::Classic, |mut env| async move {
        env.set_upgrade_authority(None);
        let err = env
            .initialize_protocol(default_stake_floors())
            .await
            .expect_err("an immutable program has no upgrade authority");
        assert_anchor_error(err, ProtocolError::AdminNotUpgradeAuthority);

        // A different upgrade authority also locks out the payer.
        let other = Pubkey::new_unique();
        env.set_upgrade_authority(Some(other));
        let err = env
            .initialize_protocol(default_stake_floors())
            .await
            .expect_err("the payer is no longer the upgrade authority");
        assert_anchor_error(err, ProtocolError::AdminNotUpgradeAuthority);

        let payer = env.payer();
        env.set_upgrade_authority(Some(payer));
        env.initialize_protocol(default_stake_floors())
            .await
            .expect("restored upgrade authority initializes");
    });
}
