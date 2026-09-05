use anchor_lang::prelude::*;
use anchor_lang::solana_program::account_info::next_account_info;
use anchor_lang::solana_program::hash::hash;
use anchor_lang::solana_program::hash::hashv;
use anchor_lang::solana_program::program::invoke_signed;
use anchor_lang::solana_program::system_instruction;
use anchor_spl::associated_token::AssociatedToken;
use anchor_spl::token_2022::spl_token_2022;
use anchor_spl::token_interface::{
    transfer_checked, Mint, TokenAccount, TokenInterface, TransferChecked,
};
use spl_token_2022::extension::{BaseStateWithExtensions, ExtensionType, StateWithExtensions};
use spl_token_2022::state::Mint as SplMintState;

use crate::program::KswarmProtocol;

declare_id!("ERNzRcYhX6UYboXAAP7vwzbCKsULYu21R4RFNvDD8CkM");

const MAX_CID_LEN: usize = 96;
const MAX_RESULT_BYTES: usize = 512;
const EMPTY_HASH: [u8; 32] = [0u8; 32];
/// One rung of the verifier-assignment ladder: how long the assigned verifier has to
/// attest before `reassign_verifier` may clear the slot. The rung measures a verifier's
/// responsiveness *to a receipt*, so its clock starts at the later of assignment and
/// receipt submission, not at assignment alone; `submit_receipt` restamps
/// `assigned_verifier_unix` for exactly that reason.
pub const ATTESTATION_WINDOW_SECONDS: i64 = 7200;
/// Grace period after an aggregate-proof job's challenge window closes. If the job is
/// still `Completed` when the grace period ends (no Bonsol marker landed, or nobody
/// settled), the customer may cancel it: escrow is refunded and the worker's stake is
/// unlocked with no slash. The program cannot observe marker absence directly, because
/// the marker PDA is keyed by an off-chain execution id; the grace period is the rule.
pub const AGGREGATE_MARKER_TIMEOUT_SECONDS: i64 = 86_400;
pub const MAX_REASSIGNMENTS: u8 = 3;
/// How many `ATTESTATION_WINDOW_SECONDS` rungs a challenge window has to hold for the
/// whole ladder to be usable: one rung for the initial assignment, one for each of the
/// `MAX_REASSIGNMENTS` replacements, and one further window as the tail in which a
/// challenge can still land after the last rung closes. `MAX_REASSIGNMENTS + 2 = 5`.
///
/// The multiple comes from the design review that proposed requiring a verifier
/// attestation before branch settlement: it derives the same figure and proposes
/// enforcing `challenge_window_seconds >= multiple * attestation_window_seconds` at open,
/// against a per-job attestation window. **That gate is not adopted here, and this
/// constant enforces nothing.** It is the reasoning behind the value an operator should
/// pass as `InitializeProtocolArgs::min_challenge_window_seconds`; the program compares
/// only against that configured floor, which a local cluster deliberately sets far below
/// one rung so its jobs finish in seconds.
pub const CHALLENGE_WINDOW_LADDER_MULTIPLE: u32 = MAX_REASSIGNMENTS as u32 + 2;
pub const BONSOL_VERIFIER_PROGRAM_ID: Pubkey =
    pubkey!("BoNsHRcyLLNdtnoDf8hiCNZpyehMC4FDMxs6NTxFi3ew");
pub const AGGREGATE_PROOF_CAPABILITY_HASH: [u8; 32] = [
    0x15, 0xba, 0x06, 0xea, 0xc1, 0x2f, 0x0d, 0xe3, 0x83, 0x4c, 0x5a, 0xec, 0x15, 0x34, 0x37, 0x7d,
    0xa6, 0x74, 0x44, 0x5c, 0x2f, 0x5f, 0xa1, 0xd0, 0xce, 0x69, 0x83, 0x99, 0xe9, 0xe8, 0xd7, 0x89,
];

const BONSOL_EXECUTION_FIELD_EXECUTION_ID: usize = 1;
const BONSOL_EXECUTION_FIELD_IMAGE_ID: usize = 2;
const BONSOL_EXECUTION_FIELD_INPUT_DIGEST: usize = 8;
const MAX_BONSOL_EXECUTION_ID_LEN: usize = 32;
const RECORD_AGGREGATE_VERIFICATION_ARGS_LEN: usize = 32 * 5;
const RECORD_AGGREGATE_VERIFICATION_RAW_IX: u8 = 1;
const RECORD_AGGREGATE_VERIFICATION_RAW_PREFIX_LEN: usize =
    1 + RECORD_AGGREGATE_VERIFICATION_ARGS_LEN;
const BONSOL_FORWARDED_INPUT_DIGEST_LEN: usize = 32;

#[program]
pub mod kswarm_protocol {
    use super::*;

    pub fn initialize_protocol(
        ctx: Context<InitializeProtocol>,
        args: InitializeProtocolArgs,
    ) -> Result<()> {
        validate_upgrade_authority(UpgradeAuthorityCheck {
            programdata_address: ctx.accounts.program.programdata_address()?,
            program_data_key: ctx.accounts.program_data.key(),
            upgrade_authority_address: ctx.accounts.program_data.upgrade_authority_address,
            admin: ctx.accounts.admin.key(),
        })?;
        let token_program = ctx.accounts.token_program.key();
        let mint_info = ctx.accounts.payment_mint.to_account_info();
        require_keys_eq!(
            *mint_info.owner,
            token_program,
            ProtocolError::PaymentMintOwnerMismatch
        );
        validate_stake_floors(&args)?;
        validate_min_challenge_window(&args)?;
        if token_program == spl_token_2022::ID {
            let mint_data = mint_info.try_borrow_data()?;
            validate_token_2022_mint_extensions(&mint_data)?;
        }

        let config = &mut ctx.accounts.config;
        config.bump = ctx.bumps.config;
        config.admin = ctx.accounts.admin.key();
        config.payment_mint = ctx.accounts.payment_mint.key();
        config.token_program = token_program;
        config.payment_decimals = ctx.accounts.payment_mint.decimals;
        config.tier_one_stake_floor = args.tier_one_stake_floor;
        config.tier_two_stake_floor = args.tier_two_stake_floor;
        config.tier_three_stake_floor = args.tier_three_stake_floor;
        config.verifier_stake_floor = args.verifier_stake_floor;
        config.min_challenge_window_seconds = args.min_challenge_window_seconds;
        Ok(())
    }

    pub fn register_worker(ctx: Context<RegisterWorker>, args: RegisterWorkerArgs) -> Result<()> {
        require!(is_valid_role(args.role), ProtocolError::InvalidWorkerRole);
        let worker = &mut ctx.accounts.worker;
        worker.bump = ctx.bumps.worker;
        worker.authority = ctx.accounts.authority.key();
        worker.stake_vault = ctx.accounts.worker_stake_vault.key();
        worker.locked_stake = 0;
        worker.active_claims = 0;
        worker.registered_at = Clock::get()?.unix_timestamp;
        worker.status = WorkerStatus::Active as u8;
        worker.role = args.role;
        worker.capability_class_hash = args.capability_class_hash;
        worker.software_digest = args.software_digest;
        Ok(())
    }

    pub fn deposit_worker_stake(ctx: Context<DepositWorkerStake>, amount: u64) -> Result<()> {
        require!(amount > 0, ProtocolError::InvalidAmount);
        transfer_checked(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.worker_funding_account.to_account_info(),
                    mint: ctx.accounts.payment_mint.to_account_info(),
                    to: ctx.accounts.worker_stake_vault.to_account_info(),
                    authority: ctx.accounts.authority.to_account_info(),
                },
            ),
            amount,
            ctx.accounts.payment_mint.decimals,
        )?;
        Ok(())
    }

    pub fn withdraw_unlocked_stake(ctx: Context<WithdrawUnlockedStake>, amount: u64) -> Result<()> {
        require!(amount > 0, ProtocolError::InvalidAmount);
        let available = ctx
            .accounts
            .worker_stake_vault
            .amount
            .checked_sub(ctx.accounts.worker.locked_stake)
            .ok_or(ProtocolError::MathOverflow)?;
        require!(
            available >= amount,
            ProtocolError::InsufficientAvailableStake
        );

        let authority_key = ctx.accounts.authority.key();
        let worker = &ctx.accounts.worker;
        let worker_bump = [worker.bump];
        let signer_seeds: &[&[u8]] = &[b"worker", authority_key.as_ref(), &worker_bump];

        transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.worker_stake_vault.to_account_info(),
                    mint: ctx.accounts.payment_mint.to_account_info(),
                    to: ctx.accounts.worker_destination_account.to_account_info(),
                    authority: ctx.accounts.worker.to_account_info(),
                },
                &[signer_seeds],
            ),
            amount,
            ctx.accounts.payment_mint.decimals,
        )?;
        Ok(())
    }

    pub fn open_job(ctx: Context<OpenJob>, args: OpenJobArgs) -> Result<()> {
        require!(args.reward_amount > 0, ProtocolError::InvalidAmount);
        require!(args.required_stake > 0, ProtocolError::InvalidAmount);
        require!(args.challenge_bond > 0, ProtocolError::InvalidAmount);
        require!(args.job_class > 0, ProtocolError::InvalidJobClass);
        validate_job_class_capability(args.job_class, args.required_capability_class_hash)?;
        require!(
            is_valid_role(args.required_role),
            ProtocolError::InvalidWorkerRole
        );
        require!(
            matches!(args.required_tier, 1..=3),
            ProtocolError::InvalidStakeTier
        );
        validate_job_windows(&args, ctx.accounts.config.min_challenge_window_seconds)?;

        transfer_checked(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.customer_payment_account.to_account_info(),
                    mint: ctx.accounts.payment_mint.to_account_info(),
                    to: ctx.accounts.job_escrow_vault.to_account_info(),
                    authority: ctx.accounts.customer.to_account_info(),
                },
            ),
            args.reward_amount,
            ctx.accounts.payment_mint.decimals,
        )?;

        let now = Clock::get()?.unix_timestamp;
        let job = &mut ctx.accounts.job;
        job.bump = ctx.bumps.job;
        job.nonce = args.job_nonce;
        job.customer = ctx.accounts.customer.key();
        job.worker = Pubkey::default();
        job.status = JobStatus::AwaitingArtifact as u8;
        job.reward_amount = args.reward_amount;
        job.required_stake = args.required_stake;
        job.job_class = args.job_class;
        job.required_role = args.required_role;
        job.required_tier = args.required_tier;
        job.required_capability_class_hash = args.required_capability_class_hash;
        job.required_software_digest = args.required_software_digest;
        job.created_at = now;
        job.claim_deadline = now
            .checked_add(i64::from(args.claim_window_seconds))
            .ok_or(ProtocolError::MathOverflow)?;
        job.execution_window_seconds = args.execution_window_seconds;
        job.execute_deadline = 0;
        job.challenge_window_seconds = args.challenge_window_seconds;
        job.challenge_deadline = 0;
        job.challenge_bond = args.challenge_bond;
        job.challenger = Pubkey::default();
        job.slash_settled = false;
        job.escrow_refunded = false;
        job.verifier_reward_paid = false;
        job.customer_slash_paid = false;
        job.input_bundle_hash = args.input_bundle_hash;
        job.expected_result_hash = args.expected_result_hash;
        job.submitted_result_hash = [0u8; 32];
        job.input_cid = String::new();
        job.output_cid = String::new();
        job.result_bytes = Vec::new();
        job.verifier_authority = None;
        job.verifier_attestation_hash = None;
        job.verifier_evidence_cid = None;
        job.verifier_attestation_unix = None;
        job.assigned_verifier_authority = None;
        job.assigned_verifier_unix = None;
        job.reassignment_counter = 0;
        Ok(())
    }

    pub fn commit_input_artifact(
        ctx: Context<CommitInputArtifact>,
        input_cid: String,
    ) -> Result<()> {
        require!(!input_cid.is_empty(), ProtocolError::EmptyArtifactLocator);
        require!(
            input_cid.len() <= MAX_CID_LEN,
            ProtocolError::ArtifactLocatorTooLong
        );

        let job = &mut ctx.accounts.job;
        require!(
            job.status == JobStatus::AwaitingArtifact as u8,
            ProtocolError::InvalidJobState
        );
        job.input_cid = input_cid;
        job.status = JobStatus::Open as u8;
        Ok(())
    }

    pub fn claim_job(ctx: Context<ClaimJob>) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let job = &mut ctx.accounts.job;
        require!(
            job.status == JobStatus::Open as u8,
            ProtocolError::InvalidJobState
        );
        require!(job.claim_deadline >= now, ProtocolError::ClaimWindowExpired);

        let available = ctx
            .accounts
            .worker_stake_vault
            .amount
            .checked_sub(ctx.accounts.worker.locked_stake)
            .ok_or(ProtocolError::MathOverflow)?;
        require!(
            ctx.accounts.worker.status == WorkerStatus::Active as u8,
            ProtocolError::InactiveWorker
        );
        require!(
            available >= job.required_stake,
            ProtocolError::InsufficientAvailableStake
        );
        require!(
            worker_role_satisfies(ctx.accounts.worker.role, job.required_role),
            ProtocolError::WorkerRoleMismatch
        );
        require!(
            derive_stake_tier(&ctx.accounts.config, ctx.accounts.worker_stake_vault.amount) >= job.required_tier,
            ProtocolError::InsufficientStakeTier
        );
        require!(
            ctx.accounts.worker.active_claims
                < max_concurrent_claims_for_role_tier(
                    ctx.accounts.worker.role,
                    derive_stake_tier(&ctx.accounts.config, ctx.accounts.worker_stake_vault.amount),
                ),
            ProtocolError::MaxConcurrentClaimsReached
        );
        if job.required_capability_class_hash != EMPTY_HASH {
            require!(
                ctx.accounts.worker.capability_class_hash == job.required_capability_class_hash,
                ProtocolError::CapabilityClassMismatch
            );
        }
        if job.required_software_digest != EMPTY_HASH {
            require!(
                ctx.accounts.worker.software_digest == job.required_software_digest,
                ProtocolError::SoftwareDigestMismatch
            );
        }

        ctx.accounts.worker.locked_stake = ctx
            .accounts
            .worker
            .locked_stake
            .checked_add(job.required_stake)
            .ok_or(ProtocolError::MathOverflow)?;
        ctx.accounts.worker.active_claims = ctx
            .accounts
            .worker
            .active_claims
            .checked_add(1)
            .ok_or(ProtocolError::MathOverflow)?;
        job.worker = ctx.accounts.authority.key();
        job.execute_deadline = now
            .checked_add(i64::from(job.execution_window_seconds))
            .ok_or(ProtocolError::MathOverflow)?;
        job.status = JobStatus::Claimed as u8;
        Ok(())
    }

    pub fn submit_receipt(
        ctx: Context<SubmitReceipt>,
        output_cid: String,
        result_bytes: Vec<u8>,
    ) -> Result<()> {
        require!(
            output_cid.len() <= MAX_CID_LEN,
            ProtocolError::ArtifactLocatorTooLong
        );
        require!(!output_cid.is_empty(), ProtocolError::EmptyArtifactLocator);
        require!(
            result_bytes.len() <= MAX_RESULT_BYTES,
            ProtocolError::ResultTooLarge
        );

        let now = Clock::get()?.unix_timestamp;
        let job = &mut ctx.accounts.job;
        require!(
            job.status == JobStatus::Claimed as u8,
            ProtocolError::InvalidJobState
        );
        require!(
            job.worker == ctx.accounts.authority.key(),
            ProtocolError::WrongWorker
        );
        require!(
            job.execute_deadline >= now,
            ProtocolError::ExecutionWindowExpired
        );

        let result_hash = hash(&result_bytes).to_bytes();

        job.output_cid = output_cid;
        job.result_bytes = result_bytes;
        job.submitted_result_hash = result_hash;
        job.challenge_deadline = now
            .checked_add(i64::from(job.challenge_window_seconds))
            .ok_or(ProtocolError::MathOverflow)?;
        job.status = JobStatus::Completed as u8;
        // Start the attestation clock here, not at assignment. `validate_assign_verifier`
        // accepts any non-terminal job, so a verifier can be assigned while the job is
        // still `Open` or `Claimed` -- and there is nothing to attest until this
        // instruction has run. Stamping at assignment let the whole reassignment ladder
        // (`MAX_REASSIGNMENTS` rungs of `ATTESTATION_WINDOW_SECONDS`) burn during a long
        // execution, so a job could arrive at `Completed` unable to replace whichever
        // verifier it held. Restamping makes the clock the later of assignment and
        // receipt: a verifier assigned before the receipt gets a full window from here,
        // and one assigned afterwards keeps the stamp `assign_verifier` wrote, which is
        // already later. The slot is not cleared; the same verifier keeps the job.
        if job.assigned_verifier_authority.is_some() {
            job.assigned_verifier_unix = Some(now);
        }
        Ok(())
    }

    pub fn submit_verifier_attestation(
        ctx: Context<SubmitVerifierAttestation>,
        args: VerifierAttestationArgs,
    ) -> Result<()> {
        let verifier_available = ctx
            .accounts
            .verifier_stake_vault
            .amount
            .checked_sub(ctx.accounts.verifier.locked_stake)
            .ok_or(ProtocolError::MathOverflow)?;
        let clock = Clock::get()?;
        let job = &mut ctx.accounts.job;
        let matched_submitted_hash = validate_verifier_attestation(AttestationValidation {
            verifier_result_hash: args.verifier_result_hash,
            verifier_evidence_cid_len: args.verifier_evidence_cid.len(),
            verifier_role: ctx.accounts.verifier.role,
            verifier_status: ctx.accounts.verifier.status,
            verifier_available_stake: verifier_available,
            verifier_stake_floor: ctx.accounts.config.verifier_stake_floor,
            job_status: job.status,
            now_unix: clock.unix_timestamp,
            challenge_deadline: job.challenge_deadline,
            required_software_digest: job.required_software_digest,
            verifier_software_digest: args.verifier_software_digest,
            verifier_authority: ctx.accounts.verifier.authority,
            job_worker_authority: job.worker,
            assigned_verifier_authority: job.assigned_verifier_authority,
            attestation_exists: job.verifier_authority.is_some(),
            submitted_result_hash: job.submitted_result_hash,
        })?;

        let job_key = job.key();
        let verifier_key = ctx.accounts.verifier_authority.key();
        job.verifier_authority = Some(verifier_key);
        job.verifier_attestation_hash = Some(args.verifier_result_hash);
        job.verifier_evidence_cid = Some(args.verifier_evidence_cid);
        job.verifier_attestation_unix = Some(clock.unix_timestamp);

        emit!(VerifierAttestationSubmitted {
            job: job_key,
            verifier: verifier_key,
            verifier_result_hash: args.verifier_result_hash,
            matched_submitted_hash,
            timestamp: clock.unix_timestamp,
        });
        Ok(())
    }

    /// The Bonsol callback path. Bonsol invokes this program with a raw instruction
    /// (tag byte `RECORD_AGGREGATE_VERIFICATION_RAW_IX`, then the five 32-byte
    /// commitments, then the forwarded input digest and committed outputs). There is
    /// no Anchor-dispatched variant: under CPI the instructions sysvar exposes the
    /// outer Bonsol instruction, and at top level the execution account cannot sign.
    pub fn fallback<'info>(
        program_id: &Pubkey,
        accounts: &'info [AccountInfo<'info>],
        data: &[u8],
    ) -> Result<()> {
        if data.first().copied() != Some(RECORD_AGGREGATE_VERIFICATION_RAW_IX) {
            return Err(anchor_lang::error::ErrorCode::InstructionFallbackNotFound.into());
        }
        record_aggregate_verification_raw(program_id, accounts, data)
    }

    pub fn assign_verifier(ctx: Context<AssignVerifier>, verifier_authority: Pubkey) -> Result<()> {
        let clock = Clock::get()?;
        let job_key = ctx.accounts.job.key();
        validate_assign_verifier(
            &ctx.accounts.job,
            ctx.accounts.caller.key(),
            ctx.accounts.config.admin,
            verifier_authority,
        )?;
        ctx.accounts.job.assigned_verifier_authority = Some(verifier_authority);
        ctx.accounts.job.assigned_verifier_unix = Some(clock.unix_timestamp);

        emit!(VerifierAssigned {
            job: job_key,
            verifier: verifier_authority,
            assigned_unix: clock.unix_timestamp,
            reassignment_counter: ctx.accounts.job.reassignment_counter,
        });
        Ok(())
    }

    pub fn reassign_verifier(ctx: Context<ReassignVerifier>) -> Result<()> {
        let clock = Clock::get()?;
        let job_key = ctx.accounts.job.key();
        let previous_verifier = ctx.accounts.job.assigned_verifier_authority;
        validate_reassign_verifier(&ctx.accounts.job, clock.unix_timestamp)?;
        ctx.accounts.job.reassignment_counter = ctx
            .accounts
            .job
            .reassignment_counter
            .checked_add(1)
            .ok_or(ProtocolError::MathOverflow)?;
        ctx.accounts.job.assigned_verifier_authority = None;
        ctx.accounts.job.assigned_verifier_unix = Some(clock.unix_timestamp);

        emit!(VerifierReassignmentNeeded {
            job: job_key,
            previous_verifier,
            reassignment_counter: ctx.accounts.job.reassignment_counter,
            timestamp: clock.unix_timestamp,
        });
        Ok(())
    }

    pub fn settle_aggregate_proof_job(ctx: Context<SettleAggregateProofJob>) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let job_key = ctx.accounts.job.key();
        let marker = load_bonsol_marker_for_settlement(
            &ctx.accounts.bonsol_aggregate_verification.to_account_info(),
        )?;
        validate_settle_aggregate_proof_job(SettleAggregateProofValidation {
            job_key,
            job: &ctx.accounts.job,
            marker_key: ctx.accounts.bonsol_aggregate_verification.key(),
            marker: &marker,
            now_unix: now,
        })?;

        pay_worker_for_job(
            ctx.accounts.job.to_account_info(),
            ctx.accounts.job_escrow_vault.to_account_info(),
            ctx.accounts.worker_payment_account.to_account_info(),
            ctx.accounts.payment_mint.to_account_info(),
            ctx.accounts.token_program.to_account_info(),
            ctx.accounts.job.customer,
            ctx.accounts.job.nonce.to_le_bytes(),
            ctx.accounts.job.bump,
            ctx.accounts.job.reward_amount,
            ctx.accounts.payment_mint.decimals,
        )?;

        release_worker_claim(&mut ctx.accounts.worker, ctx.accounts.job.required_stake)?;
        ctx.accounts.job.status = JobStatus::Settled as u8;
        Ok(())
    }

    /// Customer escape for a `Completed` aggregate-proof job that cannot settle. Two
    /// reasons are accepted: the verifier registry is exhausted with no attestation, or
    /// `AGGREGATE_MARKER_TIMEOUT_SECONDS` have passed since the challenge window closed
    /// (see `validate_cancel_aggregate_proof_job`). Both refund the escrow and release
    /// the worker's locked stake; neither slashes, because the worker did submit.
    pub fn cancel_aggregate_proof_job(ctx: Context<CancelAggregateProofJob>) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let reason = validate_cancel_aggregate_proof_job(
            &ctx.accounts.job,
            ctx.accounts.customer.key(),
            now,
        )?;

        refund_job_escrow_to_customer(
            ctx.accounts.job.to_account_info(),
            ctx.accounts.job_escrow_vault.to_account_info(),
            ctx.accounts.customer_payment_account.to_account_info(),
            ctx.accounts.payment_mint.to_account_info(),
            ctx.accounts.token_program.to_account_info(),
            ctx.accounts.job.customer,
            ctx.accounts.job.nonce.to_le_bytes(),
            ctx.accounts.job.bump,
            ctx.accounts.job.reward_amount,
            ctx.accounts.payment_mint.decimals,
        )?;
        release_worker_claim(&mut ctx.accounts.worker, ctx.accounts.job.required_stake)?;

        let job_key = ctx.accounts.job.key();
        let customer = ctx.accounts.customer.key();
        match reason {
            AggregateCancelReason::RegistryExhausted => {
                ctx.accounts.job.status = JobStatus::CancelledOnExhaustion as u8;
                emit!(AggregateProofJobCancelled {
                    job: job_key,
                    customer,
                    reassignment_counter: ctx.accounts.job.reassignment_counter,
                });
            }
            AggregateCancelReason::MarkerTimeout => {
                ctx.accounts.job.status = JobStatus::CancelledOnTimeout as u8;
                msg!("cancel: aggregate marker timeout, escrow refunded, stake unlocked");
                emit!(AggregateProofJobCancelledOnTimeout {
                    job: job_key,
                    customer,
                    worker: ctx.accounts.worker.authority,
                    attested: ctx.accounts.job.verifier_attestation_hash.is_some(),
                    challenge_deadline: ctx.accounts.job.challenge_deadline,
                    timestamp: now,
                });
            }
        }
        Ok(())
    }

    pub fn settle_job(ctx: Context<SettleJob>) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let job = &ctx.accounts.job;
        require!(
            job.status == JobStatus::Completed as u8,
            ProtocolError::InvalidJobState
        );
        require!(
            job.job_class != JobClass::AggregateProof as u8,
            ProtocolError::AggregateProofRequiresAggregateSettlement
        );
        require!(
            job.challenge_deadline <= now,
            ProtocolError::ChallengeWindowOpen
        );

        let customer_key = job.customer;
        let nonce_bytes = job.nonce.to_le_bytes();
        let reward_amount = job.reward_amount;
        let required_stake = job.required_stake;
        let job_info = ctx.accounts.job.to_account_info();
        let job_bump = [job.bump];
        let signer_seeds: &[&[u8]] = &[
            b"job",
            customer_key.as_ref(),
            nonce_bytes.as_ref(),
            &job_bump,
        ];

        transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.job_escrow_vault.to_account_info(),
                    mint: ctx.accounts.payment_mint.to_account_info(),
                    to: ctx.accounts.worker_payment_account.to_account_info(),
                    authority: job_info,
                },
                &[signer_seeds],
            ),
            reward_amount,
            ctx.accounts.payment_mint.decimals,
        )?;

        release_worker_claim(&mut ctx.accounts.worker, required_stake)?;
        ctx.accounts.job.status = JobStatus::Settled as u8;
        Ok(())
    }

    pub fn challenge_job(ctx: Context<ChallengeJob>) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let job = &ctx.accounts.job;
        require!(
            job.status == JobStatus::Completed as u8,
            ProtocolError::InvalidJobState
        );
        require!(
            job.challenge_deadline > now,
            ProtocolError::ChallengeWindowExpired
        );
        require!(
            ctx.accounts.verifier.status == WorkerStatus::Active as u8,
            ProtocolError::InactiveWorker
        );
        require!(
            ctx.accounts.verifier.role == NodeRole::Verifier as u8,
            ProtocolError::InvalidVerifierRole
        );
        let verifier_available = ctx
            .accounts
            .verifier_stake_vault
            .amount
            .checked_sub(ctx.accounts.verifier.locked_stake)
            .ok_or(ProtocolError::MathOverflow)?;
        require!(
            verifier_available >= ctx.accounts.config.verifier_stake_floor
                && verifier_available >= job.challenge_bond,
            ProtocolError::InsufficientVerifierBond
        );
        // H2-Interim rule (docs/protocol-security-remediation-spec.md §5.4): only the
        // verifier assigned to the job by its customer or the admin may challenge, and a
        // worker may never challenge its own job. Permissionless challenge is closed for
        // every job class until H2-Full (§5.3) adds a bonded dispute path.
        validate_challenge_authorization(
            ctx.accounts.caller.key(),
            job.worker,
            job.assigned_verifier_authority,
        )?;
        require!(
            receipt_is_challengeable(
                &ctx.accounts.config,
                job,
                &ctx.accounts.worker,
                ctx.accounts.worker_stake_vault.amount
            ),
            ProtocolError::ChallengeRejected
        );
        let customer_slash_paid = job.challenge_bond >= job.required_stake;
        ctx.accounts.job.challenger = ctx.accounts.caller.key();
        ctx.accounts.job.escrow_refunded = false;
        ctx.accounts.job.verifier_reward_paid = false;
        ctx.accounts.job.customer_slash_paid = customer_slash_paid;
        ctx.accounts.worker.active_claims = ctx
            .accounts
            .worker
            .active_claims
            .checked_sub(1)
            .ok_or(ProtocolError::MathOverflow)?;
        ctx.accounts.job.status = JobStatus::Slashed as u8;
        ctx.accounts.job.slash_settled = false;
        Ok(())
    }

    pub fn refund_slashed_job_escrow(ctx: Context<RefundSlashedJobEscrow>) -> Result<()> {
        let job = &ctx.accounts.job;
        require!(
            job.status == JobStatus::Slashed as u8,
            ProtocolError::InvalidJobState
        );
        require!(
            !job.escrow_refunded,
            ProtocolError::SlashEscrowAlreadyRefunded
        );

        refund_job_escrow_to_customer(
            ctx.accounts.job.to_account_info(),
            ctx.accounts.job_escrow_vault.to_account_info(),
            ctx.accounts.customer_payment_account.to_account_info(),
            ctx.accounts.payment_mint.to_account_info(),
            ctx.accounts.token_program.to_account_info(),
            job.customer,
            job.nonce.to_le_bytes(),
            job.bump,
            job.reward_amount,
            ctx.accounts.payment_mint.decimals,
        )?;
        ctx.accounts.job.escrow_refunded = true;
        maybe_finalize_slash_settlement(&mut ctx.accounts.job);
        Ok(())
    }

    pub fn claim_verifier_slash_reward(ctx: Context<ClaimVerifierSlashReward>) -> Result<()> {
        let job = &ctx.accounts.job;
        require!(
            job.status == JobStatus::Slashed as u8,
            ProtocolError::InvalidJobState
        );
        require!(
            !job.verifier_reward_paid,
            ProtocolError::SlashVerifierRewardAlreadyPaid
        );
        let verifier_reward = job.required_stake.min(job.challenge_bond);
        if verifier_reward > 0 {
            transfer_worker_stake_with_pda(
                ctx.accounts.worker.to_account_info(),
                ctx.accounts.worker_stake_vault.to_account_info(),
                ctx.accounts.verifier_reward_account.to_account_info(),
                ctx.accounts.payment_mint.to_account_info(),
                ctx.accounts.token_program.to_account_info(),
                ctx.accounts.worker.authority,
                ctx.accounts.worker.bump,
                verifier_reward,
                ctx.accounts.payment_mint.decimals,
            )?;
        }
        ctx.accounts.worker.locked_stake = ctx
            .accounts
            .worker
            .locked_stake
            .checked_sub(verifier_reward)
            .ok_or(ProtocolError::MathOverflow)?;
        ctx.accounts.job.verifier_reward_paid = true;
        maybe_finalize_slash_settlement(&mut ctx.accounts.job);
        Ok(())
    }

    pub fn claim_customer_slash_compensation(
        ctx: Context<ClaimCustomerSlashCompensation>,
    ) -> Result<()> {
        let job = &ctx.accounts.job;
        require!(
            job.status == JobStatus::Slashed as u8,
            ProtocolError::InvalidJobState
        );
        require!(
            !job.customer_slash_paid,
            ProtocolError::SlashCustomerCompAlreadyPaid
        );
        let verifier_reward = job.required_stake.min(job.challenge_bond);
        let customer_slash_amount = job
            .required_stake
            .checked_sub(verifier_reward)
            .ok_or(ProtocolError::MathOverflow)?;
        if customer_slash_amount > 0 {
            transfer_worker_stake_with_pda(
                ctx.accounts.worker.to_account_info(),
                ctx.accounts.worker_stake_vault.to_account_info(),
                ctx.accounts.customer_payment_account.to_account_info(),
                ctx.accounts.payment_mint.to_account_info(),
                ctx.accounts.token_program.to_account_info(),
                ctx.accounts.worker.authority,
                ctx.accounts.worker.bump,
                customer_slash_amount,
                ctx.accounts.payment_mint.decimals,
            )?;
        }

        ctx.accounts.worker.locked_stake = ctx
            .accounts
            .worker
            .locked_stake
            .checked_sub(customer_slash_amount)
            .ok_or(ProtocolError::MathOverflow)?;
        ctx.accounts.job.customer_slash_paid = true;
        maybe_finalize_slash_settlement(&mut ctx.accounts.job);
        Ok(())
    }

    pub fn cancel_open_job(ctx: Context<CancelOpenJob>) -> Result<()> {
        let job = &ctx.accounts.job;
        require!(
            job.status == JobStatus::AwaitingArtifact as u8 || job.status == JobStatus::Open as u8,
            ProtocolError::InvalidJobState
        );

        let customer_key = job.customer;
        let nonce_bytes = job.nonce.to_le_bytes();
        let reward_amount = job.reward_amount;
        let job_info = ctx.accounts.job.to_account_info();
        let job_bump = [job.bump];
        let signer_seeds: &[&[u8]] = &[
            b"job",
            customer_key.as_ref(),
            nonce_bytes.as_ref(),
            &job_bump,
        ];

        transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.job_escrow_vault.to_account_info(),
                    mint: ctx.accounts.payment_mint.to_account_info(),
                    to: ctx.accounts.customer_payment_account.to_account_info(),
                    authority: job_info,
                },
                &[signer_seeds],
            ),
            reward_amount,
            ctx.accounts.payment_mint.decimals,
        )?;

        ctx.accounts.job.status = JobStatus::Cancelled as u8;
        Ok(())
    }

    pub fn slash_stale_job(ctx: Context<SlashStaleJob>) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let job = &ctx.accounts.job;
        require!(
            job.status == JobStatus::Claimed as u8,
            ProtocolError::InvalidJobState
        );
        require!(
            job.execute_deadline < now,
            ProtocolError::ExecutionWindowOpen
        );

        let job_customer_key = job.customer;
        let nonce_bytes = job.nonce.to_le_bytes();
        let reward_amount = job.reward_amount;
        let required_stake = job.required_stake;
        let job_info = ctx.accounts.job.to_account_info();
        let job_bump = [job.bump];
        let job_signer_seeds: &[&[u8]] = &[
            b"job",
            job_customer_key.as_ref(),
            nonce_bytes.as_ref(),
            &job_bump,
        ];
        transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.job_escrow_vault.to_account_info(),
                    mint: ctx.accounts.payment_mint.to_account_info(),
                    to: ctx.accounts.customer_payment_account.to_account_info(),
                    authority: job_info,
                },
                &[job_signer_seeds],
            ),
            reward_amount,
            ctx.accounts.payment_mint.decimals,
        )?;

        let worker_authority_key = ctx.accounts.worker.authority;
        let worker_bump = [ctx.accounts.worker.bump];
        let worker_signer_seeds: &[&[u8]] =
            &[b"worker", worker_authority_key.as_ref(), &worker_bump];
        transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.worker_stake_vault.to_account_info(),
                    mint: ctx.accounts.payment_mint.to_account_info(),
                    to: ctx.accounts.customer_payment_account.to_account_info(),
                    authority: ctx.accounts.worker.to_account_info(),
                },
                &[worker_signer_seeds],
            ),
            required_stake,
            ctx.accounts.payment_mint.decimals,
        )?;

        release_worker_claim(&mut ctx.accounts.worker, required_stake)?;
        finalize_stale_slash(&mut ctx.accounts.job);

        emit!(StaleJobSlashed {
            job: ctx.accounts.job.key(),
            worker: worker_authority_key,
            customer: job_customer_key,
            reward_refunded: reward_amount,
            stake_slashed: required_stake,
            timestamp: now,
        });
        Ok(())
    }
}

#[derive(Accounts)]
pub struct InitializeProtocol<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    #[account(
        init,
        payer = admin,
        seeds = [b"config"],
        bump,
        space = 8 + ProtocolConfig::INIT_SPACE
    )]
    pub config: Account<'info, ProtocolConfig>,
    pub payment_mint: InterfaceAccount<'info, Mint>,
    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
    /// The protocol program itself. It must be an upgradeable-loader program; the
    /// handler checks that `program_data` is its `ProgramData` account.
    pub program: Program<'info, KswarmProtocol>,
    /// The program's `ProgramData` account. Its upgrade authority must be `admin`.
    pub program_data: Account<'info, ProgramData>,
}

#[derive(Accounts)]
pub struct RegisterWorker<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(
        seeds = [b"config"],
        bump = config.bump,
        has_one = payment_mint,
        has_one = token_program @ ProtocolError::WrongTokenProgram
    )]
    pub config: Account<'info, ProtocolConfig>,
    pub payment_mint: InterfaceAccount<'info, Mint>,
    #[account(
        init,
        payer = authority,
        seeds = [b"worker", authority.key().as_ref()],
        bump,
        space = 8 + Worker::INIT_SPACE
    )]
    pub worker: Account<'info, Worker>,
    #[account(
        init,
        payer = authority,
        associated_token::mint = payment_mint,
        associated_token::authority = worker,
        associated_token::token_program = token_program
    )]
    pub worker_stake_vault: InterfaceAccount<'info, TokenAccount>,
    pub token_program: Interface<'info, TokenInterface>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct DepositWorkerStake<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(
        seeds = [b"config"],
        bump = config.bump,
        has_one = payment_mint,
        has_one = token_program @ ProtocolError::WrongTokenProgram
    )]
    pub config: Account<'info, ProtocolConfig>,
    pub payment_mint: InterfaceAccount<'info, Mint>,
    #[account(
        seeds = [b"worker", authority.key().as_ref()],
        bump = worker.bump,
        has_one = authority
    )]
    pub worker: Account<'info, Worker>,
    #[account(mut, address = worker.stake_vault)]
    pub worker_stake_vault: InterfaceAccount<'info, TokenAccount>,
    #[account(
        mut,
        associated_token::mint = payment_mint,
        associated_token::authority = authority,
        associated_token::token_program = token_program
    )]
    pub worker_funding_account: InterfaceAccount<'info, TokenAccount>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct WithdrawUnlockedStake<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(
        seeds = [b"config"],
        bump = config.bump,
        has_one = payment_mint,
        has_one = token_program @ ProtocolError::WrongTokenProgram
    )]
    pub config: Account<'info, ProtocolConfig>,
    pub payment_mint: InterfaceAccount<'info, Mint>,
    #[account(
        mut,
        seeds = [b"worker", authority.key().as_ref()],
        bump = worker.bump,
        has_one = authority
    )]
    pub worker: Account<'info, Worker>,
    #[account(mut, address = worker.stake_vault)]
    pub worker_stake_vault: InterfaceAccount<'info, TokenAccount>,
    #[account(
        mut,
        associated_token::mint = payment_mint,
        associated_token::authority = authority,
        associated_token::token_program = token_program
    )]
    pub worker_destination_account: InterfaceAccount<'info, TokenAccount>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
#[instruction(args: OpenJobArgs)]
pub struct OpenJob<'info> {
    #[account(mut)]
    pub customer: Signer<'info>,
    #[account(
        seeds = [b"config"],
        bump = config.bump,
        has_one = payment_mint,
        has_one = token_program @ ProtocolError::WrongTokenProgram
    )]
    pub config: Account<'info, ProtocolConfig>,
    pub payment_mint: InterfaceAccount<'info, Mint>,
    #[account(
        init,
        payer = customer,
        seeds = [b"job", customer.key().as_ref(), &args.job_nonce.to_le_bytes()],
        bump,
        space = 8 + Job::INIT_SPACE
    )]
    pub job: Box<Account<'info, Job>>,
    #[account(
        init,
        payer = customer,
        associated_token::mint = payment_mint,
        associated_token::authority = job,
        associated_token::token_program = token_program
    )]
    pub job_escrow_vault: InterfaceAccount<'info, TokenAccount>,
    #[account(
        mut,
        associated_token::mint = payment_mint,
        associated_token::authority = customer,
        associated_token::token_program = token_program
    )]
    pub customer_payment_account: InterfaceAccount<'info, TokenAccount>,
    pub token_program: Interface<'info, TokenInterface>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CommitInputArtifact<'info> {
    #[account(mut)]
    pub customer: Signer<'info>,
    #[account(
        mut,
        seeds = [b"job", customer.key().as_ref(), &job.nonce.to_le_bytes()],
        bump = job.bump,
        has_one = customer
    )]
    pub job: Box<Account<'info, Job>>,
}

#[derive(Accounts)]
pub struct ClaimJob<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(
        seeds = [b"config"],
        bump = config.bump,
        has_one = payment_mint,
        has_one = token_program @ ProtocolError::WrongTokenProgram
    )]
    pub config: Account<'info, ProtocolConfig>,
    pub payment_mint: InterfaceAccount<'info, Mint>,
    #[account(
        mut,
        seeds = [b"worker", authority.key().as_ref()],
        bump = worker.bump,
        has_one = authority
    )]
    pub worker: Box<Account<'info, Worker>>,
    #[account(
        mut,
        associated_token::mint = payment_mint,
        associated_token::authority = worker,
        associated_token::token_program = token_program
    )]
    pub worker_stake_vault: InterfaceAccount<'info, TokenAccount>,
    #[account(mut)]
    pub job: Account<'info, Job>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct SubmitReceipt<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(
        mut,
        seeds = [b"worker", authority.key().as_ref()],
        bump = worker.bump,
        has_one = authority
    )]
    pub worker: Account<'info, Worker>,
    #[account(mut)]
    pub job: Account<'info, Job>,
}

#[derive(Accounts)]
pub struct SubmitVerifierAttestation<'info> {
    #[account(mut)]
    pub verifier_authority: Signer<'info>,
    #[account(
        seeds = [b"config"],
        bump = config.bump,
        has_one = payment_mint,
        has_one = token_program @ ProtocolError::WrongTokenProgram
    )]
    pub config: Account<'info, ProtocolConfig>,
    pub payment_mint: InterfaceAccount<'info, Mint>,
    #[account(
        seeds = [b"worker", verifier_authority.key().as_ref()],
        bump = verifier.bump,
        constraint = verifier.authority == verifier_authority.key() @ ProtocolError::WrongWorkerAuthority
    )]
    pub verifier: Box<Account<'info, Worker>>,
    #[account(
        associated_token::mint = payment_mint,
        associated_token::authority = verifier,
        associated_token::token_program = token_program
    )]
    pub verifier_stake_vault: InterfaceAccount<'info, TokenAccount>,
    #[account(mut)]
    pub job: Box<Account<'info, Job>>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct AssignVerifier<'info> {
    #[account(mut)]
    pub caller: Signer<'info>,
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, ProtocolConfig>,
    #[account(mut)]
    pub job: Account<'info, Job>,
}

#[derive(Accounts)]
pub struct ReassignVerifier<'info> {
    #[account(mut)]
    pub caller: Signer<'info>,
    #[account(mut)]
    pub job: Account<'info, Job>,
}

#[derive(Accounts)]
pub struct SettleAggregateProofJob<'info> {
    #[account(mut)]
    pub caller: Signer<'info>,
    #[account(
        seeds = [b"config"],
        bump = config.bump,
        has_one = payment_mint,
        has_one = token_program @ ProtocolError::WrongTokenProgram
    )]
    pub config: Account<'info, ProtocolConfig>,
    pub payment_mint: InterfaceAccount<'info, Mint>,
    #[account(mut)]
    pub job: Box<Account<'info, Job>>,
    /// CHECK: Marker may be absent or malformed; handler returns marker-specific errors.
    pub bonsol_aggregate_verification: UncheckedAccount<'info>,
    #[account(
        mut,
        seeds = [b"worker", worker_authority.key().as_ref()],
        bump = worker.bump,
        constraint = worker.authority == worker_authority.key() @ ProtocolError::WrongWorkerAuthority,
        constraint = worker.authority == job.worker @ ProtocolError::JobWorkerMismatch
    )]
    pub worker: Box<Account<'info, Worker>>,
    #[account(address = worker.authority)]
    pub worker_authority: SystemAccount<'info>,
    #[account(mut)]
    pub job_escrow_vault: InterfaceAccount<'info, TokenAccount>,
    #[account(
        mut,
        associated_token::mint = payment_mint,
        associated_token::authority = worker_authority,
        associated_token::token_program = token_program
    )]
    pub worker_payment_account: InterfaceAccount<'info, TokenAccount>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct ChallengeJob<'info> {
    #[account(mut)]
    pub caller: Signer<'info>,
    #[account(
        seeds = [b"config"],
        bump = config.bump,
        has_one = payment_mint,
        has_one = token_program @ ProtocolError::WrongTokenProgram
    )]
    pub config: Account<'info, ProtocolConfig>,
    pub payment_mint: InterfaceAccount<'info, Mint>,
    #[account(
        mut,
        seeds = [b"worker", caller.key().as_ref()],
        bump = verifier.bump,
        constraint = verifier.authority == caller.key() @ ProtocolError::WrongWorkerAuthority
    )]
    pub verifier: Box<Account<'info, Worker>>,
    #[account(
        mut,
        associated_token::mint = payment_mint,
        associated_token::authority = verifier,
        associated_token::token_program = token_program
    )]
    pub verifier_stake_vault: InterfaceAccount<'info, TokenAccount>,
    #[account(mut)]
    pub job: Box<Account<'info, Job>>,
    #[account(
        mut,
        seeds = [b"worker", worker_authority.key().as_ref()],
        bump = worker.bump,
        constraint = worker.authority == worker_authority.key() @ ProtocolError::WrongWorkerAuthority,
        constraint = worker.authority == job.worker @ ProtocolError::JobWorkerMismatch
    )]
    pub worker: Box<Account<'info, Worker>>,
    #[account(address = worker.authority)]
    pub worker_authority: SystemAccount<'info>,
    #[account(mut, address = worker.stake_vault @ ProtocolError::WrongWorkerStakeVault)]
    pub worker_stake_vault: InterfaceAccount<'info, TokenAccount>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct RefundSlashedJobEscrow<'info> {
    #[account(mut)]
    pub caller: Signer<'info>,
    #[account(
        seeds = [b"config"],
        bump = config.bump,
        has_one = payment_mint,
        has_one = token_program @ ProtocolError::WrongTokenProgram
    )]
    pub config: Account<'info, ProtocolConfig>,
    pub payment_mint: InterfaceAccount<'info, Mint>,
    #[account(
        mut,
        constraint = job.status == JobStatus::Slashed as u8 @ ProtocolError::InvalidJobState,
        constraint = !job.slash_settled @ ProtocolError::SlashAlreadySettled,
        constraint = !job.escrow_refunded @ ProtocolError::SlashEscrowAlreadyRefunded
    )]
    pub job: Box<Account<'info, Job>>,
    #[account(address = job.customer)]
    pub customer_authority: SystemAccount<'info>,
    #[account(
        mut,
        associated_token::mint = payment_mint,
        associated_token::authority = customer_authority,
        associated_token::token_program = token_program
    )]
    pub customer_payment_account: InterfaceAccount<'info, TokenAccount>,
    #[account(mut)]
    pub job_escrow_vault: InterfaceAccount<'info, TokenAccount>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct ClaimVerifierSlashReward<'info> {
    #[account(mut)]
    pub caller: Signer<'info>,
    #[account(
        seeds = [b"config"],
        bump = config.bump,
        has_one = payment_mint,
        has_one = token_program @ ProtocolError::WrongTokenProgram
    )]
    pub config: Account<'info, ProtocolConfig>,
    pub payment_mint: InterfaceAccount<'info, Mint>,
    #[account(
        mut,
        constraint = job.status == JobStatus::Slashed as u8 @ ProtocolError::InvalidJobState,
        constraint = !job.slash_settled @ ProtocolError::SlashAlreadySettled,
        constraint = !job.verifier_reward_paid @ ProtocolError::SlashVerifierRewardAlreadyPaid
    )]
    pub job: Box<Account<'info, Job>>,
    #[account(address = job.challenger)]
    pub verifier_authority: SystemAccount<'info>,
    #[account(
        mut,
        associated_token::mint = payment_mint,
        associated_token::authority = verifier_authority,
        associated_token::token_program = token_program
    )]
    pub verifier_reward_account: InterfaceAccount<'info, TokenAccount>,
    #[account(
        mut,
        seeds = [b"worker", worker_authority.key().as_ref()],
        bump = worker.bump,
        constraint = worker.authority == worker_authority.key() @ ProtocolError::WrongWorkerAuthority,
        constraint = worker.authority == job.worker @ ProtocolError::JobWorkerMismatch
    )]
    pub worker: Box<Account<'info, Worker>>,
    #[account(address = worker.authority)]
    pub worker_authority: SystemAccount<'info>,
    #[account(mut, address = worker.stake_vault)]
    pub worker_stake_vault: InterfaceAccount<'info, TokenAccount>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct ClaimCustomerSlashCompensation<'info> {
    #[account(mut)]
    pub caller: Signer<'info>,
    #[account(
        seeds = [b"config"],
        bump = config.bump,
        has_one = payment_mint,
        has_one = token_program @ ProtocolError::WrongTokenProgram
    )]
    pub config: Account<'info, ProtocolConfig>,
    pub payment_mint: InterfaceAccount<'info, Mint>,
    #[account(
        mut,
        constraint = job.status == JobStatus::Slashed as u8 @ ProtocolError::InvalidJobState,
        constraint = !job.slash_settled @ ProtocolError::SlashAlreadySettled,
        constraint = !job.customer_slash_paid @ ProtocolError::SlashCustomerCompAlreadyPaid
    )]
    pub job: Box<Account<'info, Job>>,
    #[account(address = job.customer)]
    pub customer_authority: SystemAccount<'info>,
    #[account(
        mut,
        associated_token::mint = payment_mint,
        associated_token::authority = customer_authority,
        associated_token::token_program = token_program
    )]
    pub customer_payment_account: InterfaceAccount<'info, TokenAccount>,
    #[account(
        mut,
        seeds = [b"worker", worker_authority.key().as_ref()],
        bump = worker.bump,
        constraint = worker.authority == worker_authority.key() @ ProtocolError::WrongWorkerAuthority,
        constraint = worker.authority == job.worker @ ProtocolError::JobWorkerMismatch
    )]
    pub worker: Box<Account<'info, Worker>>,
    #[account(address = worker.authority)]
    pub worker_authority: SystemAccount<'info>,
    #[account(mut, address = worker.stake_vault)]
    pub worker_stake_vault: InterfaceAccount<'info, TokenAccount>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct SettleJob<'info> {
    #[account(mut)]
    pub caller: Signer<'info>,
    #[account(
        seeds = [b"config"],
        bump = config.bump,
        has_one = payment_mint,
        has_one = token_program @ ProtocolError::WrongTokenProgram
    )]
    pub config: Account<'info, ProtocolConfig>,
    pub payment_mint: InterfaceAccount<'info, Mint>,
    #[account(mut)]
    pub job: Box<Account<'info, Job>>,
    #[account(
        mut,
        seeds = [b"worker", worker_authority.key().as_ref()],
        bump = worker.bump,
        constraint = worker.authority == worker_authority.key() @ ProtocolError::WrongWorkerAuthority,
        constraint = worker.authority == job.worker @ ProtocolError::JobWorkerMismatch
    )]
    pub worker: Box<Account<'info, Worker>>,
    #[account(address = worker.authority)]
    pub worker_authority: SystemAccount<'info>,
    #[account(mut)]
    pub job_escrow_vault: InterfaceAccount<'info, TokenAccount>,
    #[account(
        mut,
        associated_token::mint = payment_mint,
        associated_token::authority = worker_authority,
        associated_token::token_program = token_program
    )]
    pub worker_payment_account: InterfaceAccount<'info, TokenAccount>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct CancelOpenJob<'info> {
    #[account(mut)]
    pub customer: Signer<'info>,
    #[account(
        seeds = [b"config"],
        bump = config.bump,
        has_one = payment_mint,
        has_one = token_program @ ProtocolError::WrongTokenProgram
    )]
    pub config: Account<'info, ProtocolConfig>,
    pub payment_mint: InterfaceAccount<'info, Mint>,
    #[account(
        mut,
        seeds = [b"job", customer.key().as_ref(), &job.nonce.to_le_bytes()],
        bump = job.bump,
        has_one = customer
    )]
    pub job: Box<Account<'info, Job>>,
    #[account(mut)]
    pub job_escrow_vault: InterfaceAccount<'info, TokenAccount>,
    #[account(
        mut,
        associated_token::mint = payment_mint,
        associated_token::authority = customer,
        associated_token::token_program = token_program
    )]
    pub customer_payment_account: InterfaceAccount<'info, TokenAccount>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct CancelAggregateProofJob<'info> {
    #[account(mut)]
    pub customer: Signer<'info>,
    #[account(
        seeds = [b"config"],
        bump = config.bump,
        has_one = payment_mint,
        has_one = token_program @ ProtocolError::WrongTokenProgram
    )]
    pub config: Account<'info, ProtocolConfig>,
    pub payment_mint: InterfaceAccount<'info, Mint>,
    #[account(mut)]
    pub job: Box<Account<'info, Job>>,
    #[account(mut)]
    pub job_escrow_vault: InterfaceAccount<'info, TokenAccount>,
    #[account(
        mut,
        associated_token::mint = payment_mint,
        associated_token::authority = customer,
        associated_token::token_program = token_program
    )]
    pub customer_payment_account: InterfaceAccount<'info, TokenAccount>,
    pub token_program: Interface<'info, TokenInterface>,
    #[account(
        mut,
        seeds = [b"worker", worker_authority.key().as_ref()],
        bump = worker.bump,
        constraint = worker.authority == worker_authority.key() @ ProtocolError::WrongWorkerAuthority,
        constraint = worker.authority == job.worker @ ProtocolError::JobWorkerMismatch
    )]
    pub worker: Box<Account<'info, Worker>>,
    #[account(address = worker.authority)]
    pub worker_authority: SystemAccount<'info>,
}

#[derive(Accounts)]
pub struct SlashStaleJob<'info> {
    #[account(mut)]
    pub caller: Signer<'info>,
    #[account(
        seeds = [b"config"],
        bump = config.bump,
        has_one = payment_mint,
        has_one = token_program @ ProtocolError::WrongTokenProgram
    )]
    pub config: Account<'info, ProtocolConfig>,
    pub payment_mint: InterfaceAccount<'info, Mint>,
    #[account(mut)]
    pub job: Box<Account<'info, Job>>,
    #[account(address = job.customer)]
    pub customer_authority: SystemAccount<'info>,
    #[account(
        mut,
        associated_token::mint = payment_mint,
        associated_token::authority = customer_authority,
        associated_token::token_program = token_program
    )]
    pub customer_payment_account: InterfaceAccount<'info, TokenAccount>,
    #[account(
        mut,
        seeds = [b"worker", worker_authority.key().as_ref()],
        bump = worker.bump,
        constraint = worker.authority == worker_authority.key() @ ProtocolError::WrongWorkerAuthority,
        constraint = worker.authority == job.worker @ ProtocolError::JobWorkerMismatch
    )]
    pub worker: Box<Account<'info, Worker>>,
    #[account(address = worker.authority)]
    pub worker_authority: SystemAccount<'info>,
    #[account(mut, address = worker.stake_vault @ ProtocolError::WrongWorkerStakeVault)]
    pub worker_stake_vault: InterfaceAccount<'info, TokenAccount>,
    #[account(mut)]
    pub job_escrow_vault: InterfaceAccount<'info, TokenAccount>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[account]
#[derive(InitSpace)]
pub struct ProtocolConfig {
    pub bump: u8,
    pub admin: Pubkey,
    /// Payment and stake mint (KAI on mainnet; a stand-in SPL mint on devnet/localnet).
    pub payment_mint: Pubkey,
    /// Token program that owns `payment_mint`; every token CPI is pinned to it.
    pub token_program: Pubkey,
    /// Decimals of `payment_mint`, cached at initialization.
    pub payment_decimals: u8,
    /// Stake floors in base units of `payment_mint`. Set once at initialization.
    pub tier_one_stake_floor: u64,
    pub tier_two_stake_floor: u64,
    pub tier_three_stake_floor: u64,
    pub verifier_stake_floor: u64,
    /// Smallest `challenge_window_seconds` `open_job` will accept, in seconds. Set once
    /// at initialization, like the stake floors, because the value that makes
    /// verification reachable differs by cluster: a local validator runs jobs end to end
    /// in seconds, while a real deployment needs at least one
    /// `ATTESTATION_WINDOW_SECONDS` rung plus a tail for the challenge, and
    /// `CHALLENGE_WINDOW_LADDER_MULTIPLE` rungs for the whole reassignment ladder.
    /// Without a floor a customer can open a job with a one-second window on which
    /// attestation and challenge are unreachable by construction.
    pub min_challenge_window_seconds: u32,
}

#[account]
#[derive(InitSpace)]
pub struct Worker {
    pub bump: u8,
    pub authority: Pubkey,
    pub stake_vault: Pubkey,
    pub locked_stake: u64,
    pub active_claims: u16,
    pub registered_at: i64,
    pub status: u8,
    pub role: u8,
    pub capability_class_hash: [u8; 32],
    pub software_digest: [u8; 32],
}

#[account]
#[derive(InitSpace)]
pub struct Job {
    pub bump: u8,
    pub nonce: u64,
    pub customer: Pubkey,
    pub worker: Pubkey,
    pub status: u8,
    pub reward_amount: u64,
    pub required_stake: u64,
    pub job_class: u8,
    pub required_role: u8,
    pub required_tier: u8,
    pub required_capability_class_hash: [u8; 32],
    pub required_software_digest: [u8; 32],
    pub created_at: i64,
    pub claim_deadline: i64,
    pub execution_window_seconds: u32,
    pub execute_deadline: i64,
    pub challenge_window_seconds: u32,
    pub challenge_deadline: i64,
    pub challenge_bond: u64,
    pub challenger: Pubkey,
    pub slash_settled: bool,
    pub escrow_refunded: bool,
    pub verifier_reward_paid: bool,
    pub customer_slash_paid: bool,
    pub input_bundle_hash: [u8; 32],
    pub expected_result_hash: [u8; 32],
    pub submitted_result_hash: [u8; 32],
    #[max_len(MAX_CID_LEN)]
    pub input_cid: String,
    #[max_len(MAX_CID_LEN)]
    pub output_cid: String,
    #[max_len(MAX_RESULT_BYTES)]
    pub result_bytes: Vec<u8>,
    pub verifier_authority: Option<Pubkey>,
    pub verifier_attestation_hash: Option<[u8; 32]>,
    #[max_len(MAX_CID_LEN)]
    pub verifier_evidence_cid: Option<String>,
    pub verifier_attestation_unix: Option<i64>,
    pub assigned_verifier_authority: Option<Pubkey>,
    pub assigned_verifier_unix: Option<i64>,
    pub reassignment_counter: u8,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitializeProtocolArgs {
    pub tier_one_stake_floor: u64,
    pub tier_two_stake_floor: u64,
    pub tier_three_stake_floor: u64,
    pub verifier_stake_floor: u64,
    pub min_challenge_window_seconds: u32,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct RegisterWorkerArgs {
    pub role: u8,
    pub capability_class_hash: [u8; 32],
    pub software_digest: [u8; 32],
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct OpenJobArgs {
    pub job_nonce: u64,
    pub input_bundle_hash: [u8; 32],
    pub expected_result_hash: [u8; 32],
    pub reward_amount: u64,
    pub required_stake: u64,
    pub job_class: u8,
    pub required_role: u8,
    pub required_tier: u8,
    pub required_capability_class_hash: [u8; 32],
    pub required_software_digest: [u8; 32],
    pub claim_window_seconds: u32,
    pub execution_window_seconds: u32,
    pub challenge_window_seconds: u32,
    pub challenge_bond: u64,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct VerifierAttestationArgs {
    pub verifier_result_hash: [u8; 32],
    pub verifier_evidence_cid: String,
    pub verifier_software_digest: [u8; 32],
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct RecordAggregateVerificationArgs {
    pub execution_id: [u8; 32],
    pub image_id: [u8; 32],
    pub input_digest: [u8; 32],
    pub output_digest: [u8; 32],
    pub journal_hash: [u8; 32],
}

#[account]
#[derive(InitSpace)]
pub struct BonsolAggregateVerification {
    pub bump: u8,
    pub aggregate_job: Pubkey,
    pub execution_id: [u8; 32],
    pub image_id: [u8; 32],
    pub input_digest: [u8; 32],
    pub output_digest: [u8; 32],
    pub journal_hash: [u8; 32],
    pub callback_unix: i64,
    pub status: u8,
}

#[event]
pub struct VerifierAttestationSubmitted {
    pub job: Pubkey,
    pub verifier: Pubkey,
    pub verifier_result_hash: [u8; 32],
    pub matched_submitted_hash: bool,
    pub timestamp: i64,
}

#[event]
pub struct BonsolAggregateVerificationRecorded {
    pub aggregate_job: Pubkey,
    pub marker: Pubkey,
    pub execution_id: [u8; 32],
    pub image_id: [u8; 32],
    pub input_digest: [u8; 32],
    pub output_digest: [u8; 32],
    pub journal_hash: [u8; 32],
    pub callback_unix: i64,
}

#[event]
pub struct VerifierAssigned {
    pub job: Pubkey,
    pub verifier: Pubkey,
    pub assigned_unix: i64,
    pub reassignment_counter: u8,
}

#[event]
pub struct VerifierReassignmentNeeded {
    pub job: Pubkey,
    pub previous_verifier: Option<Pubkey>,
    pub reassignment_counter: u8,
    pub timestamp: i64,
}

#[event]
pub struct AggregateProofJobCancelled {
    pub job: Pubkey,
    pub customer: Pubkey,
    pub reassignment_counter: u8,
}

#[event]
pub struct AggregateProofJobCancelledOnTimeout {
    pub job: Pubkey,
    pub customer: Pubkey,
    pub worker: Pubkey,
    pub attested: bool,
    pub challenge_deadline: i64,
    pub timestamp: i64,
}

#[event]
pub struct StaleJobSlashed {
    pub job: Pubkey,
    pub worker: Pubkey,
    pub customer: Pubkey,
    pub reward_refunded: u64,
    pub stake_slashed: u64,
    pub timestamp: i64,
}

#[repr(u8)]
pub enum NodeRole {
    WorkerBasic = 1,
    WorkerProof = 2,
    WorkerPremium = 3,
    Verifier = 10,
    ArtifactPeer = 20,
    Watcher = 30,
}

#[repr(u8)]
pub enum WorkerStatus {
    Active = 1,
}

#[repr(u8)]
pub enum StakeTier {
    TierOne = 1,
    TierTwo = 2,
    TierThree = 3,
}

#[repr(u8)]
pub enum JobStatus {
    AwaitingArtifact = 1,
    Open = 2,
    Claimed = 3,
    Completed = 4,
    Settled = 5,
    Cancelled = 6,
    Slashed = 7,
    CancelledOnExhaustion = 8,
    CancelledOnTimeout = 9,
}

#[repr(u8)]
pub enum JobClass {
    DeterministicBasic = 1,
    BranchProof = 2,
    BranchReplicated = 3,
    AggregateProof = 4,
    ArtifactRetention = 5,
}

#[repr(u8)]
pub enum BonsolVerificationStatus {
    Verified = 1,
}

fn worker_role_satisfies(actual_role: u8, required_role: u8) -> bool {
    if matches!(actual_role, 1..=3) && matches!(required_role, 1..=3) {
        actual_role >= required_role
    } else {
        actual_role == required_role
    }
}

fn derive_stake_tier(config: &ProtocolConfig, total_stake: u64) -> u8 {
    if total_stake >= config.tier_three_stake_floor {
        StakeTier::TierThree as u8
    } else if total_stake >= config.tier_two_stake_floor {
        StakeTier::TierTwo as u8
    } else if total_stake >= config.tier_one_stake_floor {
        StakeTier::TierOne as u8
    } else {
        0
    }
}

/// `open_job` window validation.
///
/// Every window must be non-zero, and the challenge window must reach the configured
/// floor. The floor is what stops a customer opening a job on which verification cannot
/// happen: `challenge_deadline` bounds both `submit_verifier_attestation` and
/// `challenge_job`, so a one-second window disables, at the customer's sole discretion,
/// the economic protection the branch layer rests on. It is a `ProtocolConfig` value
/// rather than a constant because the reachable minimum differs by cluster; see
/// `CHALLENGE_WINDOW_LADDER_MULTIPLE` for the multiple a real deployment should use.
fn validate_job_windows(
    args: &OpenJobArgs,
    min_challenge_window_seconds: u32,
) -> std::result::Result<(), ProtocolError> {
    if args.claim_window_seconds == 0
        || args.execution_window_seconds == 0
        || args.challenge_window_seconds == 0
    {
        return Err(ProtocolError::InvalidDeadline);
    }
    if args.challenge_window_seconds < min_challenge_window_seconds {
        return Err(ProtocolError::ChallengeWindowBelowFloor);
    }
    Ok(())
}

/// The challenge-window floor must itself be non-zero, so that an initialization cannot
/// silently restore the unbounded behaviour the floor exists to remove.
fn validate_min_challenge_window(
    args: &InitializeProtocolArgs,
) -> std::result::Result<(), ProtocolError> {
    if args.min_challenge_window_seconds == 0 {
        return Err(ProtocolError::InvalidChallengeWindowFloor);
    }
    Ok(())
}

fn validate_stake_floors(args: &InitializeProtocolArgs) -> std::result::Result<(), ProtocolError> {
    let tiers_ascending = args.tier_one_stake_floor > 0
        && args.tier_one_stake_floor < args.tier_two_stake_floor
        && args.tier_two_stake_floor < args.tier_three_stake_floor;
    if !tiers_ascending {
        return Err(ProtocolError::InvalidStakeFloors);
    }
    if args.verifier_stake_floor == 0 {
        return Err(ProtocolError::InvalidVerifierStakeFloor);
    }
    Ok(())
}

/// Token-2022 mint extensions that break escrow accounting or custody.
/// A transfer fee makes `transfer_checked` deliver less than the escrowed amount,
/// a transfer hook can veto settlement, a permanent delegate can drain vaults,
/// and a non-transferable mint cannot be escrowed at all.
const FORBIDDEN_MINT_EXTENSIONS: [ExtensionType; 4] = [
    ExtensionType::TransferFeeConfig,
    ExtensionType::TransferHook,
    ExtensionType::PermanentDelegate,
    ExtensionType::NonTransferable,
];

fn forbidden_mint_extension(extension_types: &[ExtensionType]) -> Option<ExtensionType> {
    extension_types
        .iter()
        .copied()
        .find(|extension| FORBIDDEN_MINT_EXTENSIONS.contains(extension))
}

fn token_2022_mint_extension_types(mint_data: &[u8]) -> Result<Vec<ExtensionType>> {
    let mint = StateWithExtensions::<SplMintState>::unpack(mint_data)?;
    Ok(mint.get_extension_types()?)
}

fn validate_token_2022_mint_extensions(mint_data: &[u8]) -> Result<()> {
    let extension_types = token_2022_mint_extension_types(mint_data)?;
    require!(
        forbidden_mint_extension(&extension_types).is_none(),
        ProtocolError::ForbiddenMintExtension
    );
    Ok(())
}

fn refund_job_escrow_to_customer<'info>(
    job_authority: AccountInfo<'info>,
    job_escrow_vault: AccountInfo<'info>,
    customer_account: AccountInfo<'info>,
    mint: AccountInfo<'info>,
    token_program: AccountInfo<'info>,
    customer_key: Pubkey,
    nonce_bytes: [u8; 8],
    job_bump: u8,
    reward_amount: u64,
    decimals: u8,
) -> Result<()> {
    let bump = [job_bump];
    let signer_seeds: &[&[u8]] = &[b"job", customer_key.as_ref(), nonce_bytes.as_ref(), &bump];
    msg!("challenge: refunding escrow");
    transfer_checked(
        CpiContext::new_with_signer(
            token_program,
            TransferChecked {
                from: job_escrow_vault,
                mint,
                to: customer_account,
                authority: job_authority,
            },
            &[signer_seeds],
        ),
        reward_amount,
        decimals,
    )?;
    Ok(())
}

fn pay_worker_for_job<'info>(
    job_authority: AccountInfo<'info>,
    job_escrow_vault: AccountInfo<'info>,
    worker_payment_account: AccountInfo<'info>,
    mint: AccountInfo<'info>,
    token_program: AccountInfo<'info>,
    customer_key: Pubkey,
    nonce_bytes: [u8; 8],
    job_bump: u8,
    reward_amount: u64,
    decimals: u8,
) -> Result<()> {
    let bump = [job_bump];
    let signer_seeds: &[&[u8]] = &[b"job", customer_key.as_ref(), nonce_bytes.as_ref(), &bump];
    transfer_checked(
        CpiContext::new_with_signer(
            token_program,
            TransferChecked {
                from: job_escrow_vault,
                mint,
                to: worker_payment_account,
                authority: job_authority,
            },
            &[signer_seeds],
        ),
        reward_amount,
        decimals,
    )?;
    Ok(())
}

fn transfer_worker_stake_with_pda<'info>(
    worker_authority: AccountInfo<'info>,
    worker_stake_vault: AccountInfo<'info>,
    destination_account: AccountInfo<'info>,
    mint: AccountInfo<'info>,
    token_program: AccountInfo<'info>,
    worker_key: Pubkey,
    worker_bump: u8,
    amount: u64,
    decimals: u8,
) -> Result<()> {
    let bump = [worker_bump];
    let signer_seeds: &[&[u8]] = &[b"worker", worker_key.as_ref(), &bump];
    transfer_checked(
        CpiContext::new_with_signer(
            token_program,
            TransferChecked {
                from: worker_stake_vault,
                mint,
                to: destination_account,
                authority: worker_authority,
            },
            &[signer_seeds],
        ),
        amount,
        decimals,
    )?;
    Ok(())
}

fn is_valid_role(role: u8) -> bool {
    matches!(
        role,
        x if x == NodeRole::WorkerBasic as u8
            || x == NodeRole::WorkerProof as u8
            || x == NodeRole::WorkerPremium as u8
            || x == NodeRole::Verifier as u8
            || x == NodeRole::ArtifactPeer as u8
            || x == NodeRole::Watcher as u8
    )
}

fn max_concurrent_claims_for_role_tier(role: u8, tier: u8) -> u16 {
    if role == NodeRole::Watcher as u8 {
        return 0;
    }
    match tier {
        x if x == StakeTier::TierOne as u8 => 2,
        x if x == StakeTier::TierTwo as u8 => 5,
        x if x == StakeTier::TierThree as u8 => 10,
        _ => 0,
    }
}

fn maybe_finalize_slash_settlement(job: &mut Job) {
    job.slash_settled = job.escrow_refunded && job.verifier_reward_paid && job.customer_slash_paid;
}

/// Releases one claim on `worker`: unlocks `required_stake` and decrements the active
/// claim count. Every terminal path that leaves the worker's stake in place (settle,
/// cancel) or has already moved it (stale slash) goes through here.
fn release_worker_claim(worker: &mut Worker, required_stake: u64) -> Result<()> {
    worker.locked_stake = worker
        .locked_stake
        .checked_sub(required_stake)
        .ok_or(ProtocolError::MathOverflow)?;
    worker.active_claims = worker
        .active_claims
        .checked_sub(1)
        .ok_or(ProtocolError::MathOverflow)?;
    Ok(())
}

/// A stale slash pays the escrow refund and the full `required_stake` to the customer
/// in one instruction. Every settlement flag is set so the three claim instructions
/// (`refund_slashed_job_escrow`, `claim_verifier_slash_reward`,
/// `claim_customer_slash_compensation`) reject the job and cannot pay a second time.
fn finalize_stale_slash(job: &mut Job) {
    job.status = JobStatus::Slashed as u8;
    job.challenger = Pubkey::default();
    job.escrow_refunded = true;
    job.verifier_reward_paid = true;
    job.customer_slash_paid = true;
    maybe_finalize_slash_settlement(job);
}

fn job_is_terminal(status: u8) -> bool {
    status == JobStatus::Settled as u8
        || status == JobStatus::Cancelled as u8
        || status == JobStatus::Slashed as u8
        || status == JobStatus::CancelledOnExhaustion as u8
        || status == JobStatus::CancelledOnTimeout as u8
}

/// Aggregate-proof jobs and the Bonsol aggregate capability imply each other. The
/// marker gate (`validate_aggregate_job_for_bonsol_marker`) requires both, so a job
/// that carried only one of them could never settle.
fn validate_job_class_capability(
    job_class: u8,
    required_capability_class_hash: [u8; 32],
) -> std::result::Result<(), ProtocolError> {
    let is_aggregate = job_class == JobClass::AggregateProof as u8;
    let has_aggregate_capability =
        required_capability_class_hash == AGGREGATE_PROOF_CAPABILITY_HASH;
    if is_aggregate != has_aggregate_capability {
        return Err(ProtocolError::AggregateCapabilityMismatch);
    }
    Ok(())
}

/// Only the assigned verifier may challenge, and a worker may never challenge its own
/// job. There is no permissionless challenge for any job class (H2-Interim rule).
fn validate_challenge_authorization(
    caller: Pubkey,
    job_worker: Pubkey,
    assigned_verifier_authority: Option<Pubkey>,
) -> std::result::Result<(), ProtocolError> {
    if caller == job_worker {
        return Err(ProtocolError::SelfChallengeForbidden);
    }
    match assigned_verifier_authority {
        None => Err(ProtocolError::ChallengeRequiresAssignedVerifier),
        Some(assigned) if assigned != caller => Err(ProtocolError::VerifierNotAssigned),
        Some(_) => Ok(()),
    }
}

struct UpgradeAuthorityCheck {
    programdata_address: Option<Pubkey>,
    program_data_key: Pubkey,
    upgrade_authority_address: Option<Pubkey>,
    admin: Pubkey,
}

/// `initialize_protocol` names the protocol admin once. Only the program's upgrade
/// authority may call it: the program account must be an upgradeable-loader program
/// whose `ProgramData` is the supplied account, and that account's upgrade authority
/// must be the signing `admin`. A non-upgradeable or immutable program has no upgrade
/// authority and can never be initialized.
fn validate_upgrade_authority(
    input: UpgradeAuthorityCheck,
) -> std::result::Result<(), ProtocolError> {
    if input.programdata_address != Some(input.program_data_key) {
        return Err(ProtocolError::ProgramDataMismatch);
    }
    if input.upgrade_authority_address != Some(input.admin) {
        return Err(ProtocolError::AdminNotUpgradeAuthority);
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum AggregateCancelReason {
    RegistryExhausted,
    MarkerTimeout,
}

fn aggregate_marker_timeout_reached(
    challenge_deadline: i64,
    now_unix: i64,
) -> std::result::Result<bool, ProtocolError> {
    let timeout_unix = challenge_deadline
        .checked_add(AGGREGATE_MARKER_TIMEOUT_SECONDS)
        .ok_or(ProtocolError::MathOverflow)?;
    Ok(now_unix > timeout_unix)
}

struct BonsolExecutionCommitments {
    execution_id: [u8; 32],
    image_id: [u8; 32],
    input_digest: [u8; 32],
}

struct BonsolForwardedCommitments {
    input_digest: [u8; 32],
    output_digest: [u8; 32],
    journal_hash: [u8; 32],
}

struct RecordAggregateVerificationValidation<'a> {
    bonsol_execution_owner: Pubkey,
    bonsol_execution_is_signer: bool,
    bonsol_execution_data: &'a [u8],
    bonsol_forwarded_payload: &'a [u8],
    aggregate_job_key: Pubkey,
    aggregate_job: &'a Job,
    aggregate_verification_key: Pubkey,
    aggregate_verification_owner: Pubkey,
    aggregate_verification_data_len: usize,
    args: &'a RecordAggregateVerificationArgs,
}

struct ValidatedRecordAggregateVerification {
    bump: u8,
}

struct SettleAggregateProofValidation<'a> {
    job_key: Pubkey,
    job: &'a Job,
    marker_key: Pubkey,
    marker: &'a BonsolAggregateVerification,
    now_unix: i64,
}

fn record_aggregate_verification_raw<'info>(
    program_id: &Pubkey,
    accounts: &'info [AccountInfo<'info>],
    data: &[u8],
) -> Result<()> {
    if program_id != &ID {
        return Err(ProgramError::IncorrectProgramId.into());
    }
    let (args, bonsol_forwarded_payload) = parse_raw_record_aggregate_verification(data)?;
    let mut account_iter = accounts.iter();
    let bonsol_execution_account = next_account_info(&mut account_iter)
        .map_err(|_| error!(ProtocolError::InvalidBonsolExecutionAccount))?;
    let aggregate_verification = next_account_info(&mut account_iter)
        .map_err(|_| error!(ProtocolError::InvalidBonsolMarkerAccount))?;
    let aggregate_job_info =
        next_account_info(&mut account_iter).map_err(|_| error!(ProtocolError::InvalidJobState))?;
    let system_program = next_account_info(&mut account_iter)
        .map_err(|_| error!(ProtocolError::InvalidBonsolMarkerAccount))?;
    if system_program.key != &System::id() {
        return Err(error!(ProtocolError::InvalidBonsolMarkerAccount));
    }

    let aggregate_job = Account::<Job>::try_from(aggregate_job_info)?;
    let validation =
        validate_record_aggregate_verification(RecordAggregateVerificationValidation {
            bonsol_execution_owner: *bonsol_execution_account.owner,
            bonsol_execution_is_signer: bonsol_execution_account.is_signer,
            bonsol_execution_data: &bonsol_execution_account.try_borrow_data()?,
            bonsol_forwarded_payload,
            aggregate_job_key: *aggregate_job_info.key,
            aggregate_job: &aggregate_job,
            aggregate_verification_key: *aggregate_verification.key,
            aggregate_verification_owner: *aggregate_verification.owner,
            aggregate_verification_data_len: aggregate_verification.data_len(),
            args: &args,
        })?;

    let clock = Clock::get()?;
    initialize_bonsol_aggregate_verification(
        aggregate_verification.clone(),
        system_program.clone(),
        validation.bump,
        *aggregate_job_info.key,
        args.clone(),
        clock.unix_timestamp,
    )?;

    emit!(BonsolAggregateVerificationRecorded {
        aggregate_job: *aggregate_job_info.key,
        marker: *aggregate_verification.key,
        execution_id: args.execution_id,
        image_id: args.image_id,
        input_digest: args.input_digest,
        output_digest: args.output_digest,
        journal_hash: args.journal_hash,
        callback_unix: clock.unix_timestamp,
    });
    Ok(())
}

fn parse_raw_record_aggregate_verification(
    data: &[u8],
) -> Result<(RecordAggregateVerificationArgs, &[u8])> {
    if data.len()
        <= RECORD_AGGREGATE_VERIFICATION_RAW_PREFIX_LEN + BONSOL_FORWARDED_INPUT_DIGEST_LEN
    {
        return Err(error!(ProtocolError::BonsolCommittedOutputMissing));
    }
    if data.first().copied() != Some(RECORD_AGGREGATE_VERIFICATION_RAW_IX) {
        return Err(ProgramError::InvalidInstructionData.into());
    }
    let args = RecordAggregateVerificationArgs {
        execution_id: array_32(
            data.get(1..33)
                .ok_or(ProtocolError::BonsolCommittedOutputMissing)?,
        )?,
        image_id: array_32(
            data.get(33..65)
                .ok_or(ProtocolError::BonsolCommittedOutputMissing)?,
        )?,
        input_digest: array_32(
            data.get(65..97)
                .ok_or(ProtocolError::BonsolCommittedOutputMissing)?,
        )?,
        output_digest: array_32(
            data.get(97..129)
                .ok_or(ProtocolError::BonsolCommittedOutputMissing)?,
        )?,
        journal_hash: array_32(
            data.get(129..161)
                .ok_or(ProtocolError::BonsolCommittedOutputMissing)?,
        )?,
    };
    Ok((args, &data[RECORD_AGGREGATE_VERIFICATION_RAW_PREFIX_LEN..]))
}

fn validate_record_aggregate_verification(
    input: RecordAggregateVerificationValidation,
) -> std::result::Result<ValidatedRecordAggregateVerification, ProtocolError> {
    validate_bonsol_execution_origin(
        input.bonsol_execution_owner,
        input.bonsol_execution_is_signer,
    )?;
    let execution = parse_bonsol_execution_commitments(input.bonsol_execution_data)?;
    if execution.execution_id != input.args.execution_id {
        return Err(ProtocolError::BonsolExecutionIdMismatch);
    }
    if execution.image_id != input.args.image_id {
        return Err(ProtocolError::BonsolImageIdMismatch);
    }
    if execution.input_digest != input.args.input_digest {
        return Err(ProtocolError::BonsolInputDigestMismatch);
    }

    let forwarded = parse_bonsol_forwarded_commitments(input.bonsol_forwarded_payload)?;
    if forwarded.input_digest != input.args.input_digest {
        return Err(ProtocolError::BonsolInputDigestMismatch);
    }
    if forwarded.output_digest != input.args.output_digest {
        return Err(ProtocolError::BonsolOutputDigestMismatch);
    }
    if forwarded.journal_hash != input.args.journal_hash {
        return Err(ProtocolError::BonsolJournalHashMismatch);
    }

    validate_aggregate_job_for_bonsol_marker(input.aggregate_job, input.args)?;
    if input.aggregate_verification_owner == ID {
        return Err(ProtocolError::BonsolMarkerAlreadyExists);
    }
    if input.aggregate_verification_owner != System::id()
        || input.aggregate_verification_data_len != 0
    {
        return Err(ProtocolError::InvalidBonsolMarkerAccount);
    }

    let (expected_marker, bump) = bonsol_aggregate_verification_pda(
        input.aggregate_job_key,
        input.args.execution_id,
        input.args.image_id,
        input.args.input_digest,
        input.args.journal_hash,
    );
    if expected_marker != input.aggregate_verification_key {
        return Err(ProtocolError::BonsolMarkerMismatch);
    }

    Ok(ValidatedRecordAggregateVerification { bump })
}

fn validate_bonsol_execution_origin(
    owner: Pubkey,
    is_signer: bool,
) -> std::result::Result<(), ProtocolError> {
    if owner != BONSOL_VERIFIER_PROGRAM_ID {
        return Err(ProtocolError::InvalidBonsolVerifierProgram);
    }
    if !is_signer {
        return Err(ProtocolError::InvalidBonsolExecutionSigner);
    }
    Ok(())
}

fn validate_aggregate_job_for_bonsol_marker(
    job: &Job,
    args: &RecordAggregateVerificationArgs,
) -> std::result::Result<(), ProtocolError> {
    if job.status != JobStatus::Completed as u8 {
        return Err(ProtocolError::InvalidJobState);
    }
    if job.job_class != JobClass::AggregateProof as u8 {
        return Err(ProtocolError::JobNotAggregateProof);
    }
    if job.required_capability_class_hash != AGGREGATE_PROOF_CAPABILITY_HASH {
        return Err(ProtocolError::AggregateCapabilityMismatch);
    }
    if job.required_software_digest != args.image_id {
        return Err(ProtocolError::BonsolImageIdMismatch);
    }
    if job.input_bundle_hash != args.input_digest {
        return Err(ProtocolError::BonsolInputDigestMismatch);
    }
    if job.submitted_result_hash != args.output_digest {
        return Err(ProtocolError::BonsolOutputDigestMismatch);
    }
    if job.expected_result_hash != args.journal_hash {
        return Err(ProtocolError::BonsolJournalHashMismatch);
    }
    Ok(())
}

fn initialize_bonsol_aggregate_verification<'info>(
    marker: AccountInfo<'info>,
    system_program: AccountInfo<'info>,
    bump: u8,
    aggregate_job: Pubkey,
    args: RecordAggregateVerificationArgs,
    callback_unix: i64,
) -> Result<()> {
    let marker_space = 8 + BonsolAggregateVerification::INIT_SPACE;
    let rent_lamports = Rent::get()?.minimum_balance(marker_space);
    require!(
        marker.lamports() >= rent_lamports,
        ProtocolError::InvalidBonsolMarkerAccount
    );

    let bump_seed = [bump];
    let signer_seeds: &[&[u8]] = &[
        b"bonsol_aggregate_verification",
        aggregate_job.as_ref(),
        args.execution_id.as_ref(),
        args.image_id.as_ref(),
        args.input_digest.as_ref(),
        args.journal_hash.as_ref(),
        &bump_seed,
    ];
    invoke_signed(
        &system_instruction::allocate(marker.key, marker_space as u64),
        &[marker.clone(), system_program.clone()],
        &[signer_seeds],
    )?;
    invoke_signed(
        &system_instruction::assign(marker.key, &ID),
        &[marker.clone(), system_program],
        &[signer_seeds],
    )?;

    let verification = BonsolAggregateVerification {
        bump,
        aggregate_job,
        execution_id: args.execution_id,
        image_id: args.image_id,
        input_digest: args.input_digest,
        output_digest: args.output_digest,
        journal_hash: args.journal_hash,
        callback_unix,
        status: BonsolVerificationStatus::Verified as u8,
    };
    let mut data = marker.try_borrow_mut_data()?;
    let mut writer: &mut [u8] = &mut data;
    verification.try_serialize(&mut writer)?;
    Ok(())
}

fn load_bonsol_marker_for_settlement(
    marker: &AccountInfo,
) -> std::result::Result<BonsolAggregateVerification, ProtocolError> {
    if marker.owner != &ID || marker.data_is_empty() {
        return Err(ProtocolError::BonsolMarkerMissing);
    }
    let data = marker
        .try_borrow_data()
        .map_err(|_| ProtocolError::BonsolMarkerMismatch)?;
    let mut reader: &[u8] = &data;
    BonsolAggregateVerification::try_deserialize(&mut reader)
        .map_err(|_| ProtocolError::BonsolMarkerMismatch)
}

fn validate_settle_aggregate_proof_job(
    input: SettleAggregateProofValidation,
) -> std::result::Result<(), ProtocolError> {
    if input.job.status != JobStatus::Completed as u8 {
        return Err(ProtocolError::InvalidJobState);
    }
    if input.job.job_class != JobClass::AggregateProof as u8 {
        return Err(ProtocolError::JobNotAggregateProof);
    }
    if input.job.challenge_deadline > input.now_unix {
        return Err(ProtocolError::ChallengeWindowOpen);
    }
    if input.job.verifier_attestation_hash != Some(input.job.submitted_result_hash) {
        return Err(ProtocolError::VerifierAttestationRequired);
    }
    if input.marker.status != BonsolVerificationStatus::Verified as u8 {
        return Err(ProtocolError::BonsolMarkerMismatch);
    }
    if input.marker.aggregate_job != input.job_key
        || input.marker.image_id != input.job.required_software_digest
        || input.marker.input_digest != input.job.input_bundle_hash
        || input.marker.output_digest != input.job.submitted_result_hash
        || input.marker.journal_hash != input.job.expected_result_hash
    {
        return Err(ProtocolError::BonsolMarkerMismatch);
    }

    let (expected_marker, bump) = bonsol_aggregate_verification_pda(
        input.job_key,
        input.marker.execution_id,
        input.marker.image_id,
        input.marker.input_digest,
        input.marker.journal_hash,
    );
    if expected_marker != input.marker_key || bump != input.marker.bump {
        return Err(ProtocolError::BonsolMarkerMismatch);
    }
    Ok(())
}

fn validate_assign_verifier(
    job: &Job,
    caller: Pubkey,
    admin: Pubkey,
    verifier_authority: Pubkey,
) -> std::result::Result<(), ProtocolError> {
    if caller != job.customer && caller != admin {
        return Err(ProtocolError::VerifierAssignmentUnauthorized);
    }
    if job_is_terminal(job.status) {
        return Err(ProtocolError::InvalidJobState);
    }
    if job.verifier_attestation_hash.is_some() {
        return Err(ProtocolError::AttestationAlreadySubmitted);
    }
    if job.assigned_verifier_authority.is_some() {
        return Err(ProtocolError::VerifierAssignmentPendingRequired);
    }
    if verifier_authority == job.worker {
        return Err(ProtocolError::VerifierCannotBeWorker);
    }
    Ok(())
}

fn validate_reassign_verifier(job: &Job, now_unix: i64) -> std::result::Result<(), ProtocolError> {
    // Reassignment is a timeout on the attestation rung, and nothing can be attested
    // before a receipt exists. Without this guard any signer -- the instruction is
    // deliberately permissionless -- could exhaust the ladder while the worker was still
    // executing. It also keeps a terminal job out, which no other check here did.
    if job.status != JobStatus::Completed as u8 {
        return Err(ProtocolError::InvalidJobState);
    }
    if job.verifier_attestation_hash.is_some() {
        return Err(ProtocolError::AttestationAlreadySubmitted);
    }
    if job.reassignment_counter >= MAX_REASSIGNMENTS {
        return Err(ProtocolError::ReassignmentLimitReached);
    }
    let assigned_unix = job
        .assigned_verifier_unix
        .ok_or(ProtocolError::AssignedVerifierRequired)?;
    if job.assigned_verifier_authority.is_none() {
        return Err(ProtocolError::AssignedVerifierRequired);
    }
    let window_close = assigned_unix
        .checked_add(ATTESTATION_WINDOW_SECONDS)
        .ok_or(ProtocolError::MathOverflow)?;
    if now_unix < window_close {
        return Err(ProtocolError::VerifierStillInWindow);
    }
    Ok(())
}

/// Decides whether the customer may cancel a `Completed` aggregate-proof job, and why.
///
/// - `MarkerTimeout`: more than `AGGREGATE_MARKER_TIMEOUT_SECONDS` have passed since
///   the challenge window closed and the job is still `Completed`. Settlement first
///   becomes possible at `challenge_deadline`, so the worker (or any watcher) had the
///   whole grace period to settle with a valid marker. Attestation state is irrelevant.
/// - `RegistryExhausted`: the verifier registry is exhausted and no attestation exists.
///   This path is available before the timeout.
fn validate_cancel_aggregate_proof_job(
    job: &Job,
    caller: Pubkey,
    now_unix: i64,
) -> std::result::Result<AggregateCancelReason, ProtocolError> {
    if caller != job.customer {
        return Err(ProtocolError::WrongCustomer);
    }
    if job.job_class != JobClass::AggregateProof as u8 {
        return Err(ProtocolError::JobNotAggregateProof);
    }
    if job.status != JobStatus::Completed as u8 {
        return Err(ProtocolError::InvalidJobState);
    }
    if aggregate_marker_timeout_reached(job.challenge_deadline, now_unix)? {
        return Ok(AggregateCancelReason::MarkerTimeout);
    }
    if job.reassignment_counter < MAX_REASSIGNMENTS {
        return Err(ProtocolError::RegistryNotExhausted);
    }
    if job.verifier_attestation_hash.is_some() {
        return Err(ProtocolError::AttestationAlreadyPresent);
    }
    Ok(AggregateCancelReason::RegistryExhausted)
}

fn bonsol_aggregate_verification_pda(
    aggregate_job: Pubkey,
    execution_id: [u8; 32],
    image_id: [u8; 32],
    input_digest: [u8; 32],
    journal_hash: [u8; 32],
) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            b"bonsol_aggregate_verification",
            aggregate_job.as_ref(),
            execution_id.as_ref(),
            image_id.as_ref(),
            input_digest.as_ref(),
            journal_hash.as_ref(),
        ],
        &ID,
    )
}

fn parse_bonsol_execution_commitments(
    data: &[u8],
) -> std::result::Result<BonsolExecutionCommitments, ProtocolError> {
    if data.len() < 2 {
        return Err(ProtocolError::InvalidBonsolExecutionAccount);
    }
    let execution_id = flatbuffer_string(data, BONSOL_EXECUTION_FIELD_EXECUTION_ID)
        .ok_or(ProtocolError::InvalidBonsolExecutionAccount)
        .and_then(fixed_bonsol_execution_id)?;
    let image_id = flatbuffer_string(data, BONSOL_EXECUTION_FIELD_IMAGE_ID)
        .ok_or(ProtocolError::InvalidBonsolExecutionAccount)
        .and_then(decode_hex_32)?;
    let input_digest = flatbuffer_vector(data, BONSOL_EXECUTION_FIELD_INPUT_DIGEST)
        .ok_or(ProtocolError::InvalidBonsolExecutionAccount)
        .and_then(array_32)?;
    Ok(BonsolExecutionCommitments {
        execution_id,
        image_id,
        input_digest,
    })
}

fn parse_bonsol_forwarded_commitments(
    forwarded_payload: &[u8],
) -> std::result::Result<BonsolForwardedCommitments, ProtocolError> {
    let input_end = BONSOL_FORWARDED_INPUT_DIGEST_LEN;
    if forwarded_payload.len() <= input_end {
        return Err(ProtocolError::BonsolCommittedOutputMissing);
    }
    let input_digest = array_32(
        forwarded_payload
            .get(..input_end)
            .ok_or(ProtocolError::BonsolCommittedOutputMissing)?,
    )?;
    let committed_outputs = forwarded_payload
        .get(input_end..)
        .ok_or(ProtocolError::BonsolCommittedOutputMissing)?;
    if committed_outputs.is_empty() {
        return Err(ProtocolError::BonsolCommittedOutputMissing);
    }
    let output_digest = hash(committed_outputs).to_bytes();
    let journal_hash = hashv(&[input_digest.as_ref(), committed_outputs]).to_bytes();
    Ok(BonsolForwardedCommitments {
        input_digest,
        output_digest,
        journal_hash,
    })
}

fn fixed_bonsol_execution_id(input: &str) -> std::result::Result<[u8; 32], ProtocolError> {
    if input.is_empty() || input.len() > MAX_BONSOL_EXECUTION_ID_LEN {
        return Err(ProtocolError::InvalidBonsolExecutionAccount);
    }
    let mut output = [0u8; 32];
    output[..input.len()].copy_from_slice(input.as_bytes());
    Ok(output)
}

fn array_32(input: &[u8]) -> std::result::Result<[u8; 32], ProtocolError> {
    input
        .try_into()
        .map_err(|_| ProtocolError::InvalidBonsolExecutionAccount)
}

fn decode_hex_32(input: &str) -> std::result::Result<[u8; 32], ProtocolError> {
    if input.len() != 64 {
        return Err(ProtocolError::InvalidBonsolExecutionAccount);
    }
    let mut output = [0u8; 32];
    for (idx, chunk) in input.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_hex_nibble(chunk[0])?;
        let low = decode_hex_nibble(chunk[1])?;
        output[idx] = (high << 4) | low;
    }
    Ok(output)
}

fn decode_hex_nibble(byte: u8) -> std::result::Result<u8, ProtocolError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(ProtocolError::InvalidBonsolExecutionAccount),
    }
}

fn flatbuffer_string(data: &[u8], field_index: usize) -> Option<&str> {
    let (location, len) = flatbuffer_vector_location(data, field_index)?;
    core::str::from_utf8(data.get(location..location.checked_add(len)?)?).ok()
}

fn flatbuffer_vector(data: &[u8], field_index: usize) -> Option<&[u8]> {
    let (location, len) = flatbuffer_vector_location(data, field_index)?;
    data.get(location..location.checked_add(len)?)
}

fn flatbuffer_vector_location(data: &[u8], field_index: usize) -> Option<(usize, usize)> {
    let table = read_u32(data, 0)? as usize;
    let vtable_offset = read_i32(data, table)?;
    let vtable = table.checked_sub(vtable_offset as usize)?;
    let vtable_len = read_u16(data, vtable)? as usize;
    let field_entry = vtable
        .checked_add(4)?
        .checked_add(field_index.checked_mul(2)?)?;
    if field_entry.checked_add(2)? > vtable.checked_add(vtable_len)? {
        return None;
    }
    let field_offset = read_u16(data, field_entry)? as usize;
    if field_offset == 0 {
        return None;
    }
    let field_location = table.checked_add(field_offset)?;
    let vector_relative = read_u32(data, field_location)? as usize;
    let vector_length_location = field_location.checked_add(vector_relative)?;
    let vector_len = read_u32(data, vector_length_location)? as usize;
    let vector_start = vector_length_location.checked_add(4)?;
    Some((vector_start, vector_len))
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes: [u8; 2] = data.get(offset..offset.checked_add(2)?)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn read_i32(data: &[u8], offset: usize) -> Option<i32> {
    let bytes: [u8; 4] = data.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    let value = i32::from_le_bytes(bytes);
    if value < 0 {
        return None;
    }
    Some(value)
}

struct AttestationValidation {
    verifier_result_hash: [u8; 32],
    verifier_evidence_cid_len: usize,
    verifier_role: u8,
    verifier_status: u8,
    verifier_available_stake: u64,
    verifier_stake_floor: u64,
    job_status: u8,
    now_unix: i64,
    challenge_deadline: i64,
    required_software_digest: [u8; 32],
    verifier_software_digest: [u8; 32],
    verifier_authority: Pubkey,
    job_worker_authority: Pubkey,
    assigned_verifier_authority: Option<Pubkey>,
    attestation_exists: bool,
    submitted_result_hash: [u8; 32],
}

fn validate_verifier_attestation(
    input: AttestationValidation,
) -> std::result::Result<bool, ProtocolError> {
    if input.verifier_result_hash == EMPTY_HASH {
        return Err(ProtocolError::AttestationEmptyResultHash);
    }
    if input.verifier_evidence_cid_len > MAX_CID_LEN {
        return Err(ProtocolError::ArtifactLocatorTooLong);
    }
    if input.verifier_role != NodeRole::Verifier as u8 {
        return Err(ProtocolError::AttestationRoleRequired);
    }
    if input.verifier_status != WorkerStatus::Active as u8 {
        return Err(ProtocolError::InactiveWorker);
    }
    // Verifier bond-lock during the attestation window plus counterslash handling
    // is finding H2-Full, specified in docs/protocol-security-remediation-spec.md §5.3
    // and tracked as its own protocol milestone. This validation only checks available
    // stake. An attestation alone moves no funds: a slash needs `challenge_job`, which
    // accepts only the verifier assigned to the job (`validate_challenge_authorization`).
    if input.verifier_available_stake < input.verifier_stake_floor {
        return Err(ProtocolError::AttestationStakeTooLow);
    }
    if input.verifier_authority == input.job_worker_authority {
        return Err(ProtocolError::SelfAttestationForbidden);
    }
    if let Some(assigned_verifier_authority) = input.assigned_verifier_authority {
        if input.verifier_authority != assigned_verifier_authority {
            return Err(ProtocolError::VerifierNotAssigned);
        }
    }
    if input.job_status != JobStatus::Completed as u8 {
        return Err(ProtocolError::AttestationJobNotAttestable);
    }
    if input.now_unix >= input.challenge_deadline {
        return Err(ProtocolError::AttestationWindowClosed);
    }
    if input.required_software_digest != EMPTY_HASH
        && input.verifier_software_digest != input.required_software_digest
    {
        return Err(ProtocolError::AttestationDigestMismatch);
    }
    if input.attestation_exists {
        return Err(ProtocolError::AttestationAlreadyExists);
    }
    Ok(input.submitted_result_hash == input.verifier_result_hash)
}

fn receipt_is_challengeable(
    config: &ProtocolConfig,
    job: &Job,
    worker: &Worker,
    worker_stake_amount: u64,
) -> bool {
    msg!("challenge-check: enter");
    if job.expected_result_hash != EMPTY_HASH
        && job.submitted_result_hash != job.expected_result_hash
    {
        msg!("challenge-check: expected hash mismatch");
        return true;
    }
    if let Some(verifier_attestation_hash) = job.verifier_attestation_hash {
        if job.submitted_result_hash != EMPTY_HASH
            && job.submitted_result_hash != verifier_attestation_hash
        {
            msg!("challenge-check: verifier attestation mismatch");
            return true;
        }
    }
    msg!("challenge-check: comparing worker role");
    if !worker_role_satisfies(worker.role, job.required_role) {
        msg!("challenge-check: role mismatch");
        return true;
    }
    msg!("challenge-check: comparing stake tier");
    if derive_stake_tier(config, worker_stake_amount) < job.required_tier {
        msg!("challenge-check: stake tier mismatch");
        return true;
    }
    msg!("challenge-check: comparing capability");
    if job.required_capability_class_hash != EMPTY_HASH
        && worker.capability_class_hash != job.required_capability_class_hash
    {
        msg!("challenge-check: capability mismatch");
        return true;
    }
    msg!("challenge-check: comparing software digest");
    if job.required_software_digest != EMPTY_HASH
        && worker.software_digest != job.required_software_digest
    {
        msg!("challenge-check: software digest mismatch");
        return true;
    }
    msg!("challenge-check: receipt not challengeable");
    false
}

#[error_code]
pub enum ProtocolError {
    #[msg("invalid amount")]
    InvalidAmount,
    #[msg("invalid deadline")]
    InvalidDeadline,
    #[msg("math overflow")]
    MathOverflow,
    #[msg("invalid job state")]
    InvalidJobState,
    #[msg("claim window expired")]
    ClaimWindowExpired,
    #[msg("execution window expired")]
    ExecutionWindowExpired,
    #[msg("execution window is still open")]
    ExecutionWindowOpen,
    #[msg("challenge window is still open")]
    ChallengeWindowOpen,
    #[msg("challenge window expired")]
    ChallengeWindowExpired,
    #[msg("insufficient available stake")]
    InsufficientAvailableStake,
    #[msg("invalid worker role")]
    InvalidWorkerRole,
    #[msg("invalid job class")]
    InvalidJobClass,
    #[msg("invalid stake tier")]
    InvalidStakeTier,
    #[msg("worker role does not satisfy job role")]
    WorkerRoleMismatch,
    #[msg("worker stake tier does not satisfy job tier")]
    InsufficientStakeTier,
    #[msg("worker capability class does not satisfy job requirement")]
    CapabilityClassMismatch,
    #[msg("worker software digest does not satisfy job requirement")]
    SoftwareDigestMismatch,
    #[msg("worker has reached the maximum concurrent claims for its tier")]
    MaxConcurrentClaimsReached,
    #[msg("worker is inactive")]
    InactiveWorker,
    #[msg("invalid verifier role")]
    InvalidVerifierRole,
    #[msg("insufficient verifier bond or verifier stake")]
    InsufficientVerifierBond,
    #[msg("challenge rejected")]
    ChallengeRejected,
    #[msg("wrong worker")]
    WrongWorker,
    #[msg("wrong worker authority")]
    WrongWorkerAuthority,
    #[msg("unexpected result hash")]
    UnexpectedResultHash,
    #[msg("artifact locator too long")]
    ArtifactLocatorTooLong,
    #[msg("empty artifact locator")]
    EmptyArtifactLocator,
    #[msg("result too large")]
    ResultTooLarge,
    #[msg("slashed escrow already refunded")]
    SlashEscrowAlreadyRefunded,
    #[msg("slashed verifier reward already paid")]
    SlashVerifierRewardAlreadyPaid,
    #[msg("slashed customer compensation already paid")]
    SlashCustomerCompAlreadyPaid,
    #[msg("verifier role required for attestation")]
    AttestationRoleRequired,
    #[msg("verifier stake below the configured verifier stake floor")]
    AttestationStakeTooLow,
    #[msg("verifier software digest mismatch with job requirement")]
    AttestationDigestMismatch,
    #[msg("job already attested by a verifier")]
    AttestationAlreadyExists,
    #[msg("job not in attestable state")]
    AttestationJobNotAttestable,
    #[msg("attestation submitted after challenge deadline")]
    AttestationWindowClosed,
    #[msg("attestation result hash cannot be empty")]
    AttestationEmptyResultHash,
    #[msg("verifier authority cannot equal the target job worker authority")]
    SelfAttestationForbidden,
    #[msg("Bonsol execution account is not owned by the pinned verifier program")]
    InvalidBonsolVerifierProgram,
    #[msg("Bonsol execution account did not sign the callback")]
    InvalidBonsolExecutionSigner,
    #[msg("invalid Bonsol execution account")]
    InvalidBonsolExecutionAccount,
    #[msg("Bonsol execution id does not match callback arguments")]
    BonsolExecutionIdMismatch,
    #[msg("Bonsol image id does not match aggregate job or callback arguments")]
    BonsolImageIdMismatch,
    #[msg("Bonsol input digest does not match aggregate job or forwarded callback data")]
    BonsolInputDigestMismatch,
    #[msg("Bonsol output digest does not match aggregate job or forwarded callback data")]
    BonsolOutputDigestMismatch,
    #[msg("Bonsol journal hash does not match aggregate job or forwarded callback data")]
    BonsolJournalHashMismatch,
    #[msg("Bonsol committed output was not forwarded to the callback")]
    BonsolCommittedOutputMissing,
    #[msg("invalid Bonsol aggregate verification marker account")]
    InvalidBonsolMarkerAccount,
    #[msg("Bonsol aggregate verification marker already exists")]
    BonsolMarkerAlreadyExists,
    #[msg("Bonsol aggregate verification marker is missing")]
    BonsolMarkerMissing,
    #[msg("Bonsol aggregate verification marker does not bind to the aggregate job")]
    BonsolMarkerMismatch,
    #[msg("job is not an aggregate-proof job")]
    JobNotAggregateProof,
    #[msg("aggregate-proof job does not require the configured Bonsol aggregate capability")]
    AggregateCapabilityMismatch,
    #[msg("matching verifier attestation is required for aggregate-proof settlement")]
    VerifierAttestationRequired,
    #[msg("assigned verifier is still inside the attestation window")]
    VerifierStillInWindow,
    #[msg("verifier reassignment limit reached")]
    ReassignmentLimitReached,
    #[msg("assigned verifier already submitted an attestation")]
    AttestationAlreadySubmitted,
    #[msg("job has no active assigned verifier")]
    AssignedVerifierRequired,
    #[msg("customer escrow cancellation requires exhausted verifier registry")]
    RegistryNotExhausted,
    #[msg("verifier attestation is already present")]
    AttestationAlreadyPresent,
    #[msg("caller is not the job customer")]
    WrongCustomer,
    #[msg("caller is not authorized to assign verifier")]
    VerifierAssignmentUnauthorized,
    #[msg("job already has an assigned verifier")]
    VerifierAssignmentPendingRequired,
    #[msg("aggregate worker cannot be assigned as verifier")]
    VerifierCannotBeWorker,
    #[msg("attestation signer is not the assigned verifier")]
    VerifierNotAssigned,
    #[msg("aggregate-proof jobs must use settle_aggregate_proof_job")]
    AggregateProofRequiresAggregateSettlement,
    // Appended at the end of the enum so existing Anchor error codes are preserved.
    #[msg("worker account does not match the job's claimed worker")]
    JobWorkerMismatch,
    #[msg("stake vault does not match the worker's registered stake vault")]
    WrongWorkerStakeVault,
    #[msg("a worker cannot challenge its own job")]
    SelfChallengeForbidden,
    #[msg("token program does not match the protocol config")]
    WrongTokenProgram,
    #[msg("payment mint is not owned by the supplied token program")]
    PaymentMintOwnerMismatch,
    #[msg("stake floors must satisfy 0 < tier one < tier two < tier three")]
    InvalidStakeFloors,
    #[msg("verifier stake floor must be greater than zero")]
    InvalidVerifierStakeFloor,
    #[msg("payment mint carries a forbidden Token-2022 extension")]
    ForbiddenMintExtension,
    #[msg("slashed job is already fully settled")]
    SlashAlreadySettled,
    #[msg("challenge requires a verifier assigned with assign_verifier")]
    ChallengeRequiresAssignedVerifier,
    #[msg("program_data is not the ProgramData account of an upgradeable program")]
    ProgramDataMismatch,
    #[msg("admin signer is not the program upgrade authority")]
    AdminNotUpgradeAuthority,
    #[msg("challenge window is below the protocol's configured minimum")]
    ChallengeWindowBelowFloor,
    #[msg("minimum challenge window must be greater than zero")]
    InvalidChallengeWindowFloor,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_hash(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    const TEST_TIER_ONE_FLOOR: u64 = 50_000_000_000;
    const TEST_TIER_TWO_FLOOR: u64 = 250_000_000_000;
    const TEST_TIER_THREE_FLOOR: u64 = 1_000_000_000_000;
    const TEST_VERIFIER_FLOOR: u64 = 100_000_000_000;
    const TEST_MIN_CHALLENGE_WINDOW_SECONDS: u32 = 30;

    fn base_floors() -> InitializeProtocolArgs {
        InitializeProtocolArgs {
            tier_one_stake_floor: TEST_TIER_ONE_FLOOR,
            tier_two_stake_floor: TEST_TIER_TWO_FLOOR,
            tier_three_stake_floor: TEST_TIER_THREE_FLOOR,
            verifier_stake_floor: TEST_VERIFIER_FLOOR,
            min_challenge_window_seconds: TEST_MIN_CHALLENGE_WINDOW_SECONDS,
        }
    }

    fn base_config() -> ProtocolConfig {
        ProtocolConfig {
            bump: 1,
            admin: Pubkey::new_unique(),
            payment_mint: Pubkey::new_unique(),
            token_program: spl_token_2022::ID,
            payment_decimals: 6,
            tier_one_stake_floor: TEST_TIER_ONE_FLOOR,
            tier_two_stake_floor: TEST_TIER_TWO_FLOOR,
            tier_three_stake_floor: TEST_TIER_THREE_FLOOR,
            verifier_stake_floor: TEST_VERIFIER_FLOOR,
            min_challenge_window_seconds: TEST_MIN_CHALLENGE_WINDOW_SECONDS,
        }
    }

    fn base_worker() -> Worker {
        Worker {
            bump: 1,
            authority: Pubkey::new_unique(),
            stake_vault: Pubkey::new_unique(),
            locked_stake: 0,
            active_claims: 0,
            registered_at: 1,
            status: WorkerStatus::Active as u8,
            role: NodeRole::WorkerBasic as u8,
            capability_class_hash: EMPTY_HASH,
            software_digest: EMPTY_HASH,
        }
    }

    fn base_job() -> Job {
        Job {
            bump: 1,
            nonce: 1,
            customer: Pubkey::new_unique(),
            worker: Pubkey::new_unique(),
            status: JobStatus::Completed as u8,
            reward_amount: 25,
            required_stake: 50,
            job_class: 1,
            required_role: NodeRole::WorkerBasic as u8,
            required_tier: StakeTier::TierOne as u8,
            required_capability_class_hash: EMPTY_HASH,
            required_software_digest: EMPTY_HASH,
            created_at: 1,
            claim_deadline: 2,
            execution_window_seconds: 30,
            execute_deadline: 3,
            challenge_window_seconds: 30,
            challenge_deadline: 100,
            challenge_bond: 50,
            challenger: Pubkey::default(),
            slash_settled: false,
            escrow_refunded: false,
            verifier_reward_paid: false,
            customer_slash_paid: false,
            input_bundle_hash: EMPTY_HASH,
            expected_result_hash: EMPTY_HASH,
            submitted_result_hash: test_hash(1),
            input_cid: "bafkreibaseinput".to_string(),
            output_cid: "bafkreibaseoutput".to_string(),
            result_bytes: vec![1, 2, 3],
            verifier_authority: None,
            verifier_attestation_hash: None,
            verifier_evidence_cid: None,
            verifier_attestation_unix: None,
            assigned_verifier_authority: None,
            assigned_verifier_unix: None,
            reassignment_counter: 0,
        }
    }

    fn base_attestation_validation() -> AttestationValidation {
        AttestationValidation {
            verifier_result_hash: test_hash(1),
            verifier_evidence_cid_len: "bafkreiverifierevidence".len(),
            verifier_role: NodeRole::Verifier as u8,
            verifier_status: WorkerStatus::Active as u8,
            verifier_available_stake: TEST_VERIFIER_FLOOR,
            verifier_stake_floor: TEST_VERIFIER_FLOOR,
            job_status: JobStatus::Completed as u8,
            now_unix: 50,
            challenge_deadline: 100,
            required_software_digest: EMPTY_HASH,
            verifier_software_digest: EMPTY_HASH,
            verifier_authority: Pubkey::new_unique(),
            job_worker_authority: Pubkey::new_unique(),
            assigned_verifier_authority: None,
            attestation_exists: false,
            submitted_result_hash: test_hash(1),
        }
    }

    fn assert_attestation_error(
        result: std::result::Result<bool, ProtocolError>,
        expected: ProtocolError,
    ) {
        assert_protocol_error(result, expected);
    }

    fn assert_protocol_error<T>(
        result: std::result::Result<T, ProtocolError>,
        expected: ProtocolError,
    ) {
        let Err(actual) = result else {
            panic!("expected validation error");
        };
        assert_eq!(
            std::mem::discriminant(&actual),
            std::mem::discriminant(&expected)
        );
    }

    fn execution_id_bytes(value: &str) -> [u8; 32] {
        fixed_bonsol_execution_id(value).unwrap()
    }

    fn hex_32(value: [u8; 32]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(64);
        for byte in value {
            output.push(HEX[(byte >> 4) as usize] as char);
            output.push(HEX[(byte & 0x0f) as usize] as char);
        }
        output
    }

    fn bonsol_execution_data(
        execution_id: &str,
        image_id: [u8; 32],
        input_digest: [u8; 32],
    ) -> Vec<u8> {
        let mut fbb = flatbuffers::FlatBufferBuilder::new();
        let execution_id = fbb.create_string(execution_id);
        let image_id = fbb.create_string(&hex_32(image_id));
        let input_digest = fbb.create_vector(&input_digest);
        let table = fbb.start_table();
        fbb.push_slot::<u64>(4, 12_000, 0);
        fbb.push_slot_always(6, execution_id);
        fbb.push_slot_always(8, image_id);
        fbb.push_slot_always(20, input_digest);
        let execution_request = fbb.end_table(table);
        fbb.finish(execution_request, None);
        fbb.finished_data().to_vec()
    }

    fn aggregate_args() -> (RecordAggregateVerificationArgs, Vec<u8>) {
        let input_digest = test_hash(10);
        let committed_outputs = vec![4, 8, 15, 16, 23, 42];
        let output_digest = hash(&committed_outputs).to_bytes();
        let journal_hash = hashv(&[input_digest.as_ref(), committed_outputs.as_ref()]).to_bytes();
        (
            RecordAggregateVerificationArgs {
                execution_id: execution_id_bytes("phase0b-record"),
                image_id: test_hash(11),
                input_digest,
                output_digest,
                journal_hash,
            },
            committed_outputs,
        )
    }

    fn callback_instruction_data(
        _args: &RecordAggregateVerificationArgs,
        forwarded_input_digest: [u8; 32],
        committed_outputs: &[u8],
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&forwarded_input_digest);
        data.extend_from_slice(committed_outputs);
        data
    }

    fn aggregate_job_for_args(args: &RecordAggregateVerificationArgs) -> Job {
        let mut job = base_job();
        job.status = JobStatus::Completed as u8;
        job.job_class = JobClass::AggregateProof as u8;
        job.required_capability_class_hash = AGGREGATE_PROOF_CAPABILITY_HASH;
        job.required_software_digest = args.image_id;
        job.input_bundle_hash = args.input_digest;
        job.submitted_result_hash = args.output_digest;
        job.expected_result_hash = args.journal_hash;
        job.verifier_attestation_hash = Some(args.output_digest);
        job
    }

    fn valid_record_validation<'a>(
        job_key: Pubkey,
        job: &'a Job,
        args: &'a RecordAggregateVerificationArgs,
        execution_data: &'a [u8],
        bonsol_forwarded_payload: &'a [u8],
    ) -> RecordAggregateVerificationValidation<'a> {
        let (marker_key, _) = bonsol_aggregate_verification_pda(
            job_key,
            args.execution_id,
            args.image_id,
            args.input_digest,
            args.journal_hash,
        );
        RecordAggregateVerificationValidation {
            bonsol_execution_owner: BONSOL_VERIFIER_PROGRAM_ID,
            bonsol_execution_is_signer: true,
            bonsol_execution_data: execution_data,
            bonsol_forwarded_payload,
            aggregate_job_key: job_key,
            aggregate_job: job,
            aggregate_verification_key: marker_key,
            aggregate_verification_owner: System::id(),
            aggregate_verification_data_len: 0,
            args,
        }
    }

    fn marker_for_job(
        job_key: Pubkey,
        job: &Job,
        args: &RecordAggregateVerificationArgs,
    ) -> BonsolAggregateVerification {
        let (_, bump) = bonsol_aggregate_verification_pda(
            job_key,
            args.execution_id,
            args.image_id,
            args.input_digest,
            args.journal_hash,
        );
        BonsolAggregateVerification {
            bump,
            aggregate_job: job_key,
            execution_id: args.execution_id,
            image_id: job.required_software_digest,
            input_digest: job.input_bundle_hash,
            output_digest: job.submitted_result_hash,
            journal_hash: job.expected_result_hash,
            callback_unix: 10,
            status: BonsolVerificationStatus::Verified as u8,
        }
    }

    #[test]
    fn test_attestation_happy_path_match() {
        let submitted_hash = test_hash(7);
        let mut validation = base_attestation_validation();
        validation.submitted_result_hash = submitted_hash;
        validation.verifier_result_hash = submitted_hash;
        assert!(validate_verifier_attestation(validation).unwrap());

        let mut job = base_job();
        job.submitted_result_hash = submitted_hash;
        job.verifier_attestation_hash = Some(submitted_hash);
        assert!(!receipt_is_challengeable(
            &base_config(),
            &job,
            &base_worker(),
            TEST_TIER_ONE_FLOOR
        ));
    }

    #[test]
    fn test_attestation_triggers_slash_on_mismatch() {
        let mut validation = base_attestation_validation();
        validation.submitted_result_hash = test_hash(7);
        validation.verifier_result_hash = test_hash(8);
        assert!(!validate_verifier_attestation(validation).unwrap());

        let mut job = base_job();
        job.submitted_result_hash = test_hash(7);
        job.verifier_attestation_hash = Some(test_hash(8));
        assert!(receipt_is_challengeable(
            &base_config(),
            &job,
            &base_worker(),
            TEST_TIER_ONE_FLOOR
        ));
    }

    #[test]
    fn test_attestation_requires_verifier_role() {
        let mut validation = base_attestation_validation();
        validation.verifier_role = NodeRole::WorkerBasic as u8;
        assert_attestation_error(
            validate_verifier_attestation(validation),
            ProtocolError::AttestationRoleRequired,
        );
    }

    #[test]
    fn test_attestation_requires_stake_floor() {
        let mut validation = base_attestation_validation();
        validation.verifier_available_stake = TEST_VERIFIER_FLOOR - 1;
        assert_attestation_error(
            validate_verifier_attestation(validation),
            ProtocolError::AttestationStakeTooLow,
        );
    }

    #[test]
    fn test_attestation_rejects_self_attestation() {
        let shared_authority = Pubkey::new_unique();
        let mut validation = base_attestation_validation();
        validation.verifier_authority = shared_authority;
        validation.job_worker_authority = shared_authority;
        assert_attestation_error(
            validate_verifier_attestation(validation),
            ProtocolError::SelfAttestationForbidden,
        );
    }

    #[test]
    fn test_attestation_one_per_job() {
        let mut validation = base_attestation_validation();
        validation.attestation_exists = true;
        assert_attestation_error(
            validate_verifier_attestation(validation),
            ProtocolError::AttestationAlreadyExists,
        );
    }

    #[test]
    fn test_attestation_software_digest_must_match() {
        let mut validation = base_attestation_validation();
        validation.required_software_digest = test_hash(11);
        validation.verifier_software_digest = test_hash(12);
        assert_attestation_error(
            validate_verifier_attestation(validation),
            ProtocolError::AttestationDigestMismatch,
        );
    }

    #[test]
    fn test_attestation_window_closed() {
        let mut validation = base_attestation_validation();
        validation.now_unix = validation.challenge_deadline;
        assert_attestation_error(
            validate_verifier_attestation(validation),
            ProtocolError::AttestationWindowClosed,
        );
    }

    #[test]
    fn test_attestation_empty_hash_rejected() {
        let mut validation = base_attestation_validation();
        validation.verifier_result_hash = EMPTY_HASH;
        assert_attestation_error(
            validate_verifier_attestation(validation),
            ProtocolError::AttestationEmptyResultHash,
        );
    }

    #[test]
    fn test_existing_paths_still_work() {
        let mut job = base_job();
        job.expected_result_hash = test_hash(3);
        job.submitted_result_hash = test_hash(4);
        assert!(receipt_is_challengeable(
            &base_config(),
            &job,
            &base_worker(),
            TEST_TIER_ONE_FLOOR
        ));
    }

    #[test]
    fn test_attestation_requires_active_verifier() {
        let mut validation = base_attestation_validation();
        validation.verifier_status = 0;
        assert_attestation_error(
            validate_verifier_attestation(validation),
            ProtocolError::InactiveWorker,
        );
    }

    #[test]
    fn test_attestation_requires_completed_job_status() {
        let mut validation = base_attestation_validation();
        validation.job_status = JobStatus::Claimed as u8;
        assert_attestation_error(
            validate_verifier_attestation(validation),
            ProtocolError::AttestationJobNotAttestable,
        );
    }

    #[test]
    fn test_attestation_rejects_long_evidence_cid() {
        let mut validation = base_attestation_validation();
        validation.verifier_evidence_cid_len = MAX_CID_LEN + 1;
        assert_attestation_error(
            validate_verifier_attestation(validation),
            ProtocolError::ArtifactLocatorTooLong,
        );
    }

    #[test]
    fn test_paid_job_without_expected_hash_needs_attestation_or_eligibility_ground() {
        let mut job = base_job();
        job.expected_result_hash = EMPTY_HASH;
        job.submitted_result_hash = test_hash(5);
        job.verifier_attestation_hash = None;
        assert!(!receipt_is_challengeable(
            &base_config(),
            &job,
            &base_worker(),
            TEST_TIER_ONE_FLOOR
        ));
    }

    #[test]
    fn test_attestation_requires_assigned_verifier_when_present() {
        let assigned = Pubkey::new_unique();
        let mut validation = base_attestation_validation();
        validation.assigned_verifier_authority = Some(assigned);
        validation.verifier_authority = Pubkey::new_unique();
        assert_attestation_error(
            validate_verifier_attestation(validation),
            ProtocolError::VerifierNotAssigned,
        );
    }

    #[test]
    fn test_record_aggregate_verification_validates_happy_path() {
        let (args, committed_outputs) = aggregate_args();
        let job_key = Pubkey::new_unique();
        let job = aggregate_job_for_args(&args);
        let execution_data =
            bonsol_execution_data("phase0b-record", args.image_id, args.input_digest);
        let instruction_data =
            callback_instruction_data(&args, args.input_digest, &committed_outputs);
        let validation =
            valid_record_validation(job_key, &job, &args, &execution_data, &instruction_data);
        let result = validate_record_aggregate_verification(validation).unwrap();
        let (_, expected_bump) = bonsol_aggregate_verification_pda(
            job_key,
            args.execution_id,
            args.image_id,
            args.input_digest,
            args.journal_hash,
        );
        assert_eq!(result.bump, expected_bump);
    }

    #[test]
    fn test_record_rejects_wrong_bonsol_program_owner() {
        let (args, committed_outputs) = aggregate_args();
        let job_key = Pubkey::new_unique();
        let job = aggregate_job_for_args(&args);
        let execution_data =
            bonsol_execution_data("phase0b-record", args.image_id, args.input_digest);
        let instruction_data =
            callback_instruction_data(&args, args.input_digest, &committed_outputs);
        let mut validation =
            valid_record_validation(job_key, &job, &args, &execution_data, &instruction_data);
        validation.bonsol_execution_owner = Pubkey::new_unique();
        assert_protocol_error(
            validate_record_aggregate_verification(validation),
            ProtocolError::InvalidBonsolVerifierProgram,
        );
    }

    #[test]
    fn test_record_rejects_unsigned_bonsol_execution_account() {
        let (args, committed_outputs) = aggregate_args();
        let job_key = Pubkey::new_unique();
        let job = aggregate_job_for_args(&args);
        let execution_data =
            bonsol_execution_data("phase0b-record", args.image_id, args.input_digest);
        let instruction_data =
            callback_instruction_data(&args, args.input_digest, &committed_outputs);
        let mut validation =
            valid_record_validation(job_key, &job, &args, &execution_data, &instruction_data);
        validation.bonsol_execution_is_signer = false;
        assert_protocol_error(
            validate_record_aggregate_verification(validation),
            ProtocolError::InvalidBonsolExecutionSigner,
        );
    }

    #[test]
    fn test_record_rejects_invalid_bonsol_execution_account() {
        let (args, committed_outputs) = aggregate_args();
        let job_key = Pubkey::new_unique();
        let job = aggregate_job_for_args(&args);
        let execution_data = vec![0u8];
        let instruction_data =
            callback_instruction_data(&args, args.input_digest, &committed_outputs);
        let validation =
            valid_record_validation(job_key, &job, &args, &execution_data, &instruction_data);
        assert_protocol_error(
            validate_record_aggregate_verification(validation),
            ProtocolError::InvalidBonsolExecutionAccount,
        );
    }

    #[test]
    fn test_record_rejects_execution_id_mismatch() {
        let (args, committed_outputs) = aggregate_args();
        let job_key = Pubkey::new_unique();
        let job = aggregate_job_for_args(&args);
        let execution_data =
            bonsol_execution_data("wrong-execution", args.image_id, args.input_digest);
        let instruction_data =
            callback_instruction_data(&args, args.input_digest, &committed_outputs);
        let validation =
            valid_record_validation(job_key, &job, &args, &execution_data, &instruction_data);
        assert_protocol_error(
            validate_record_aggregate_verification(validation),
            ProtocolError::BonsolExecutionIdMismatch,
        );
    }

    #[test]
    fn test_record_rejects_image_id_mismatch() {
        let (args, committed_outputs) = aggregate_args();
        let job_key = Pubkey::new_unique();
        let job = aggregate_job_for_args(&args);
        let execution_data =
            bonsol_execution_data("phase0b-record", test_hash(99), args.input_digest);
        let instruction_data =
            callback_instruction_data(&args, args.input_digest, &committed_outputs);
        let validation =
            valid_record_validation(job_key, &job, &args, &execution_data, &instruction_data);
        assert_protocol_error(
            validate_record_aggregate_verification(validation),
            ProtocolError::BonsolImageIdMismatch,
        );
    }

    #[test]
    fn test_record_rejects_execution_input_digest_mismatch() {
        let (args, committed_outputs) = aggregate_args();
        let job_key = Pubkey::new_unique();
        let job = aggregate_job_for_args(&args);
        let execution_data = bonsol_execution_data("phase0b-record", args.image_id, test_hash(77));
        let instruction_data =
            callback_instruction_data(&args, args.input_digest, &committed_outputs);
        let validation =
            valid_record_validation(job_key, &job, &args, &execution_data, &instruction_data);
        assert_protocol_error(
            validate_record_aggregate_verification(validation),
            ProtocolError::BonsolInputDigestMismatch,
        );
    }

    #[test]
    fn test_record_rejects_forwarded_input_digest_mismatch() {
        let (args, committed_outputs) = aggregate_args();
        let job_key = Pubkey::new_unique();
        let job = aggregate_job_for_args(&args);
        let execution_data =
            bonsol_execution_data("phase0b-record", args.image_id, args.input_digest);
        let instruction_data = callback_instruction_data(&args, test_hash(88), &committed_outputs);
        let validation =
            valid_record_validation(job_key, &job, &args, &execution_data, &instruction_data);
        assert_protocol_error(
            validate_record_aggregate_verification(validation),
            ProtocolError::BonsolInputDigestMismatch,
        );
    }

    #[test]
    fn test_record_rejects_output_digest_mismatch() {
        let (mut args, committed_outputs) = aggregate_args();
        let job_key = Pubkey::new_unique();
        args.output_digest = test_hash(1);
        let mut job = aggregate_job_for_args(&args);
        job.submitted_result_hash = args.output_digest;
        let execution_data =
            bonsol_execution_data("phase0b-record", args.image_id, args.input_digest);
        let instruction_data =
            callback_instruction_data(&args, args.input_digest, &committed_outputs);
        let validation =
            valid_record_validation(job_key, &job, &args, &execution_data, &instruction_data);
        assert_protocol_error(
            validate_record_aggregate_verification(validation),
            ProtocolError::BonsolOutputDigestMismatch,
        );
    }

    #[test]
    fn test_record_rejects_journal_hash_mismatch() {
        let (mut args, committed_outputs) = aggregate_args();
        let job_key = Pubkey::new_unique();
        args.journal_hash = test_hash(2);
        let mut job = aggregate_job_for_args(&args);
        job.expected_result_hash = args.journal_hash;
        let execution_data =
            bonsol_execution_data("phase0b-record", args.image_id, args.input_digest);
        let instruction_data =
            callback_instruction_data(&args, args.input_digest, &committed_outputs);
        let validation =
            valid_record_validation(job_key, &job, &args, &execution_data, &instruction_data);
        assert_protocol_error(
            validate_record_aggregate_verification(validation),
            ProtocolError::BonsolJournalHashMismatch,
        );
    }

    #[test]
    fn test_record_rejects_missing_committed_output() {
        let (args, _) = aggregate_args();
        let mut instruction_data = Vec::new();
        instruction_data.extend_from_slice(&args.input_digest);
        assert_protocol_error(
            parse_bonsol_forwarded_commitments(&instruction_data),
            ProtocolError::BonsolCommittedOutputMissing,
        );
    }

    #[test]
    fn test_record_rejects_wrong_job_state() {
        let (args, committed_outputs) = aggregate_args();
        let job_key = Pubkey::new_unique();
        let mut job = aggregate_job_for_args(&args);
        job.status = JobStatus::Claimed as u8;
        let execution_data =
            bonsol_execution_data("phase0b-record", args.image_id, args.input_digest);
        let instruction_data =
            callback_instruction_data(&args, args.input_digest, &committed_outputs);
        let validation =
            valid_record_validation(job_key, &job, &args, &execution_data, &instruction_data);
        assert_protocol_error(
            validate_record_aggregate_verification(validation),
            ProtocolError::InvalidJobState,
        );
    }

    #[test]
    fn test_record_rejects_non_aggregate_job() {
        let (args, committed_outputs) = aggregate_args();
        let job_key = Pubkey::new_unique();
        let mut job = aggregate_job_for_args(&args);
        job.job_class = JobClass::BranchProof as u8;
        let execution_data =
            bonsol_execution_data("phase0b-record", args.image_id, args.input_digest);
        let instruction_data =
            callback_instruction_data(&args, args.input_digest, &committed_outputs);
        let validation =
            valid_record_validation(job_key, &job, &args, &execution_data, &instruction_data);
        assert_protocol_error(
            validate_record_aggregate_verification(validation),
            ProtocolError::JobNotAggregateProof,
        );
    }

    #[test]
    fn test_record_rejects_aggregate_capability_mismatch() {
        let (args, committed_outputs) = aggregate_args();
        let job_key = Pubkey::new_unique();
        let mut job = aggregate_job_for_args(&args);
        job.required_capability_class_hash = test_hash(55);
        let execution_data =
            bonsol_execution_data("phase0b-record", args.image_id, args.input_digest);
        let instruction_data =
            callback_instruction_data(&args, args.input_digest, &committed_outputs);
        let validation =
            valid_record_validation(job_key, &job, &args, &execution_data, &instruction_data);
        assert_protocol_error(
            validate_record_aggregate_verification(validation),
            ProtocolError::AggregateCapabilityMismatch,
        );
    }

    #[test]
    fn test_record_rejects_existing_marker() {
        let (args, committed_outputs) = aggregate_args();
        let job_key = Pubkey::new_unique();
        let job = aggregate_job_for_args(&args);
        let execution_data =
            bonsol_execution_data("phase0b-record", args.image_id, args.input_digest);
        let instruction_data =
            callback_instruction_data(&args, args.input_digest, &committed_outputs);
        let mut validation =
            valid_record_validation(job_key, &job, &args, &execution_data, &instruction_data);
        validation.aggregate_verification_owner = ID;
        assert_protocol_error(
            validate_record_aggregate_verification(validation),
            ProtocolError::BonsolMarkerAlreadyExists,
        );
    }

    #[test]
    fn test_record_rejects_invalid_marker_account() {
        let (args, committed_outputs) = aggregate_args();
        let job_key = Pubkey::new_unique();
        let job = aggregate_job_for_args(&args);
        let execution_data =
            bonsol_execution_data("phase0b-record", args.image_id, args.input_digest);
        let instruction_data =
            callback_instruction_data(&args, args.input_digest, &committed_outputs);
        let mut validation =
            valid_record_validation(job_key, &job, &args, &execution_data, &instruction_data);
        validation.aggregate_verification_owner = Pubkey::new_unique();
        assert_protocol_error(
            validate_record_aggregate_verification(validation),
            ProtocolError::InvalidBonsolMarkerAccount,
        );
    }

    #[test]
    fn test_record_rejects_marker_pda_mismatch() {
        let (args, committed_outputs) = aggregate_args();
        let job_key = Pubkey::new_unique();
        let job = aggregate_job_for_args(&args);
        let execution_data =
            bonsol_execution_data("phase0b-record", args.image_id, args.input_digest);
        let instruction_data =
            callback_instruction_data(&args, args.input_digest, &committed_outputs);
        let mut validation =
            valid_record_validation(job_key, &job, &args, &execution_data, &instruction_data);
        validation.aggregate_verification_key = Pubkey::new_unique();
        assert_protocol_error(
            validate_record_aggregate_verification(validation),
            ProtocolError::BonsolMarkerMismatch,
        );
    }

    #[test]
    fn test_settle_aggregate_proof_happy_path() {
        let (args, _) = aggregate_args();
        let job_key = Pubkey::new_unique();
        let job = aggregate_job_for_args(&args);
        let marker = marker_for_job(job_key, &job, &args);
        let (marker_key, _) = bonsol_aggregate_verification_pda(
            job_key,
            args.execution_id,
            args.image_id,
            args.input_digest,
            args.journal_hash,
        );
        validate_settle_aggregate_proof_job(SettleAggregateProofValidation {
            job_key,
            job: &job,
            marker_key,
            marker: &marker,
            now_unix: job.challenge_deadline,
        })
        .unwrap();
    }

    #[test]
    fn test_settle_rejects_missing_marker_account() {
        let marker_key = Pubkey::new_unique();
        let owner = System::id();
        let mut lamports = 0;
        let mut data = Vec::new();
        let marker = AccountInfo::new(
            &marker_key,
            false,
            false,
            &mut lamports,
            &mut data,
            &owner,
            false,
            0,
        );
        assert_protocol_error(
            load_bonsol_marker_for_settlement(&marker),
            ProtocolError::BonsolMarkerMissing,
        );
    }

    #[test]
    fn test_settle_rejects_marker_mismatch() {
        let (args, _) = aggregate_args();
        let job_key = Pubkey::new_unique();
        let job = aggregate_job_for_args(&args);
        let mut marker = marker_for_job(job_key, &job, &args);
        marker.output_digest = test_hash(100);
        let (marker_key, _) = bonsol_aggregate_verification_pda(
            job_key,
            args.execution_id,
            args.image_id,
            args.input_digest,
            args.journal_hash,
        );
        assert_protocol_error(
            validate_settle_aggregate_proof_job(SettleAggregateProofValidation {
                job_key,
                job: &job,
                marker_key,
                marker: &marker,
                now_unix: job.challenge_deadline,
            }),
            ProtocolError::BonsolMarkerMismatch,
        );
    }

    #[test]
    fn test_settle_requires_matching_verifier_attestation() {
        let (args, _) = aggregate_args();
        let job_key = Pubkey::new_unique();
        let mut job = aggregate_job_for_args(&args);
        job.verifier_attestation_hash = None;
        let marker = marker_for_job(job_key, &job, &args);
        let (marker_key, _) = bonsol_aggregate_verification_pda(
            job_key,
            args.execution_id,
            args.image_id,
            args.input_digest,
            args.journal_hash,
        );
        assert_protocol_error(
            validate_settle_aggregate_proof_job(SettleAggregateProofValidation {
                job_key,
                job: &job,
                marker_key,
                marker: &marker,
                now_unix: job.challenge_deadline,
            }),
            ProtocolError::VerifierAttestationRequired,
        );

        job.verifier_attestation_hash = Some(test_hash(99));
        assert_protocol_error(
            validate_settle_aggregate_proof_job(SettleAggregateProofValidation {
                job_key,
                job: &job,
                marker_key,
                marker: &marker,
                now_unix: job.challenge_deadline,
            }),
            ProtocolError::VerifierAttestationRequired,
        );
    }

    #[test]
    fn test_settle_rejects_open_challenge_window_and_wrong_class() {
        let (args, _) = aggregate_args();
        let job_key = Pubkey::new_unique();
        let mut job = aggregate_job_for_args(&args);
        let marker = marker_for_job(job_key, &job, &args);
        let (marker_key, _) = bonsol_aggregate_verification_pda(
            job_key,
            args.execution_id,
            args.image_id,
            args.input_digest,
            args.journal_hash,
        );
        assert_protocol_error(
            validate_settle_aggregate_proof_job(SettleAggregateProofValidation {
                job_key,
                job: &job,
                marker_key,
                marker: &marker,
                now_unix: job.challenge_deadline - 1,
            }),
            ProtocolError::ChallengeWindowOpen,
        );
        job.job_class = JobClass::BranchProof as u8;
        assert_protocol_error(
            validate_settle_aggregate_proof_job(SettleAggregateProofValidation {
                job_key,
                job: &job,
                marker_key,
                marker: &marker,
                now_unix: job.challenge_deadline,
            }),
            ProtocolError::JobNotAggregateProof,
        );
    }

    #[test]
    fn test_assign_verifier_validations() {
        let (args, _) = aggregate_args();
        let mut job = aggregate_job_for_args(&args);
        let admin = Pubkey::new_unique();
        let verifier = Pubkey::new_unique();
        job.verifier_attestation_hash = None;
        validate_assign_verifier(&job, job.customer, admin, verifier).unwrap();

        assert_protocol_error(
            validate_assign_verifier(&job, Pubkey::new_unique(), admin, verifier),
            ProtocolError::VerifierAssignmentUnauthorized,
        );
        validate_assign_verifier(&job, admin, admin, verifier).unwrap();
    }

    #[test]
    fn test_assign_verifier_accepts_every_job_class() {
        let admin = Pubkey::new_unique();
        let verifier = Pubkey::new_unique();
        for job_class in [
            JobClass::DeterministicBasic,
            JobClass::BranchProof,
            JobClass::BranchReplicated,
            JobClass::AggregateProof,
            JobClass::ArtifactRetention,
        ] {
            let mut job = base_job();
            job.job_class = job_class as u8;
            validate_assign_verifier(&job, job.customer, admin, verifier).unwrap();
        }
    }

    #[test]
    fn test_assign_verifier_rejects_terminal_job() {
        let admin = Pubkey::new_unique();
        let verifier = Pubkey::new_unique();
        for status in [
            JobStatus::Settled,
            JobStatus::Cancelled,
            JobStatus::Slashed,
            JobStatus::CancelledOnExhaustion,
            JobStatus::CancelledOnTimeout,
        ] {
            let mut job = base_job();
            job.status = status as u8;
            assert_protocol_error(
                validate_assign_verifier(&job, job.customer, admin, verifier),
                ProtocolError::InvalidJobState,
            );
        }
        for status in [
            JobStatus::AwaitingArtifact,
            JobStatus::Open,
            JobStatus::Claimed,
            JobStatus::Completed,
        ] {
            let mut job = base_job();
            job.status = status as u8;
            validate_assign_verifier(&job, job.customer, admin, verifier).unwrap();
        }
    }

    #[test]
    fn test_assign_verifier_rejects_attested_pending_and_worker_self_assignment() {
        let (args, _) = aggregate_args();
        let mut job = aggregate_job_for_args(&args);
        let admin = Pubkey::new_unique();
        let verifier = Pubkey::new_unique();

        job.verifier_attestation_hash = Some(args.output_digest);
        assert_protocol_error(
            validate_assign_verifier(&job, job.customer, admin, verifier),
            ProtocolError::AttestationAlreadySubmitted,
        );

        job.verifier_attestation_hash = None;
        job.assigned_verifier_authority = Some(verifier);
        assert_protocol_error(
            validate_assign_verifier(&job, job.customer, admin, Pubkey::new_unique()),
            ProtocolError::VerifierAssignmentPendingRequired,
        );

        job.assigned_verifier_authority = None;
        assert_protocol_error(
            validate_assign_verifier(&job, job.customer, admin, job.worker),
            ProtocolError::VerifierCannotBeWorker,
        );
    }

    #[test]
    fn test_reassign_verifier_happy_path_and_window() {
        let (args, _) = aggregate_args();
        let mut job = aggregate_job_for_args(&args);
        job.verifier_attestation_hash = None;
        job.assigned_verifier_authority = Some(Pubkey::new_unique());
        job.assigned_verifier_unix = Some(100);
        validate_reassign_verifier(&job, 100 + ATTESTATION_WINDOW_SECONDS).unwrap();
        assert_protocol_error(
            validate_reassign_verifier(&job, 100 + ATTESTATION_WINDOW_SECONDS - 1),
            ProtocolError::VerifierStillInWindow,
        );
    }

    #[test]
    fn test_reassign_verifier_accepts_non_aggregate_class() {
        let mut job = base_job();
        job.job_class = JobClass::DeterministicBasic as u8;
        job.verifier_attestation_hash = None;
        job.assigned_verifier_authority = Some(Pubkey::new_unique());
        job.assigned_verifier_unix = Some(100);
        validate_reassign_verifier(&job, 100 + ATTESTATION_WINDOW_SECONDS).unwrap();
    }

    #[test]
    fn test_reassign_verifier_rejects_limit_attested_and_unassigned() {
        let (args, _) = aggregate_args();
        let mut job = aggregate_job_for_args(&args);
        job.verifier_attestation_hash = None;
        job.assigned_verifier_authority = Some(Pubkey::new_unique());
        job.assigned_verifier_unix = Some(100);
        job.reassignment_counter = MAX_REASSIGNMENTS;
        assert_protocol_error(
            validate_reassign_verifier(&job, 100 + ATTESTATION_WINDOW_SECONDS),
            ProtocolError::ReassignmentLimitReached,
        );

        job.reassignment_counter = 0;
        job.verifier_attestation_hash = Some(args.output_digest);
        assert_protocol_error(
            validate_reassign_verifier(&job, 100 + ATTESTATION_WINDOW_SECONDS),
            ProtocolError::AttestationAlreadySubmitted,
        );

        job.verifier_attestation_hash = None;
        job.assigned_verifier_authority = None;
        assert_protocol_error(
            validate_reassign_verifier(&job, 100 + ATTESTATION_WINDOW_SECONDS),
            ProtocolError::AssignedVerifierRequired,
        );
    }

    #[test]
    fn test_cancel_aggregate_proof_job_happy_path() {
        let (args, _) = aggregate_args();
        let mut job = aggregate_job_for_args(&args);
        job.verifier_attestation_hash = None;
        job.reassignment_counter = MAX_REASSIGNMENTS;
        let before_timeout = job.challenge_deadline;
        assert_eq!(
            validate_cancel_aggregate_proof_job(&job, job.customer, before_timeout).unwrap(),
            AggregateCancelReason::RegistryExhausted
        );
    }

    #[test]
    fn test_cancel_aggregate_proof_job_rejects_each_failure_branch() {
        let (args, _) = aggregate_args();
        let mut job = aggregate_job_for_args(&args);
        job.verifier_attestation_hash = None;
        job.reassignment_counter = MAX_REASSIGNMENTS;
        let now = job.challenge_deadline;

        assert_protocol_error(
            validate_cancel_aggregate_proof_job(&job, Pubkey::new_unique(), now),
            ProtocolError::WrongCustomer,
        );

        job.job_class = JobClass::BranchProof as u8;
        assert_protocol_error(
            validate_cancel_aggregate_proof_job(&job, job.customer, now),
            ProtocolError::JobNotAggregateProof,
        );

        job.job_class = JobClass::AggregateProof as u8;
        job.status = JobStatus::Settled as u8;
        assert_protocol_error(
            validate_cancel_aggregate_proof_job(&job, job.customer, now),
            ProtocolError::InvalidJobState,
        );

        job.status = JobStatus::Completed as u8;
        job.reassignment_counter = MAX_REASSIGNMENTS - 1;
        assert_protocol_error(
            validate_cancel_aggregate_proof_job(&job, job.customer, now),
            ProtocolError::RegistryNotExhausted,
        );

        job.reassignment_counter = MAX_REASSIGNMENTS;
        job.verifier_attestation_hash = Some(args.output_digest);
        assert_protocol_error(
            validate_cancel_aggregate_proof_job(&job, job.customer, now),
            ProtocolError::AttestationAlreadyPresent,
        );
    }

    #[test]
    fn test_cancel_aggregate_proof_job_timeout_path() {
        let (args, _) = aggregate_args();
        // Attested, not exhausted: the exhaustion path is closed.
        let mut job = aggregate_job_for_args(&args);
        assert!(job.verifier_attestation_hash.is_some());
        assert_eq!(job.reassignment_counter, 0);
        let timeout_unix = job.challenge_deadline + AGGREGATE_MARKER_TIMEOUT_SECONDS;

        assert_protocol_error(
            validate_cancel_aggregate_proof_job(&job, job.customer, job.challenge_deadline),
            ProtocolError::RegistryNotExhausted,
        );
        // The timeout is strict: exactly at the boundary the job is still not cancellable.
        assert_protocol_error(
            validate_cancel_aggregate_proof_job(&job, job.customer, timeout_unix),
            ProtocolError::RegistryNotExhausted,
        );
        assert_eq!(
            validate_cancel_aggregate_proof_job(&job, job.customer, timeout_unix + 1).unwrap(),
            AggregateCancelReason::MarkerTimeout
        );

        // The timeout path also serves an unattested, unexhausted job.
        job.verifier_attestation_hash = None;
        assert_eq!(
            validate_cancel_aggregate_proof_job(&job, job.customer, timeout_unix + 1).unwrap(),
            AggregateCancelReason::MarkerTimeout
        );

        // Customer, class, and status checks still apply after the timeout.
        assert_protocol_error(
            validate_cancel_aggregate_proof_job(&job, Pubkey::new_unique(), timeout_unix + 1),
            ProtocolError::WrongCustomer,
        );
        job.status = JobStatus::Settled as u8;
        assert_protocol_error(
            validate_cancel_aggregate_proof_job(&job, job.customer, timeout_unix + 1),
            ProtocolError::InvalidJobState,
        );
        job.status = JobStatus::Completed as u8;
        job.job_class = JobClass::BranchProof as u8;
        assert_protocol_error(
            validate_cancel_aggregate_proof_job(&job, job.customer, timeout_unix + 1),
            ProtocolError::JobNotAggregateProof,
        );
    }

    #[test]
    fn test_aggregate_marker_timeout_overflow_is_an_error() {
        assert_protocol_error(
            aggregate_marker_timeout_reached(i64::MAX, 0),
            ProtocolError::MathOverflow,
        );
        assert!(!aggregate_marker_timeout_reached(100, 100 + AGGREGATE_MARKER_TIMEOUT_SECONDS).unwrap());
        assert!(aggregate_marker_timeout_reached(100, 101 + AGGREGATE_MARKER_TIMEOUT_SECONDS).unwrap());
    }

    #[test]
    fn test_validate_job_class_capability_requires_matching_pair() {
        validate_job_class_capability(
            JobClass::AggregateProof as u8,
            AGGREGATE_PROOF_CAPABILITY_HASH,
        )
        .unwrap();
        validate_job_class_capability(JobClass::DeterministicBasic as u8, EMPTY_HASH).unwrap();
        validate_job_class_capability(JobClass::BranchProof as u8, test_hash(9)).unwrap();

        assert_protocol_error(
            validate_job_class_capability(JobClass::AggregateProof as u8, EMPTY_HASH),
            ProtocolError::AggregateCapabilityMismatch,
        );
        assert_protocol_error(
            validate_job_class_capability(JobClass::AggregateProof as u8, test_hash(9)),
            ProtocolError::AggregateCapabilityMismatch,
        );
        assert_protocol_error(
            validate_job_class_capability(
                JobClass::BranchProof as u8,
                AGGREGATE_PROOF_CAPABILITY_HASH,
            ),
            ProtocolError::AggregateCapabilityMismatch,
        );
    }

    #[test]
    fn test_validate_challenge_authorization_requires_assigned_verifier() {
        let worker = Pubkey::new_unique();
        let assigned = Pubkey::new_unique();
        let other = Pubkey::new_unique();

        validate_challenge_authorization(assigned, worker, Some(assigned)).unwrap();
        assert_protocol_error(
            validate_challenge_authorization(other, worker, None),
            ProtocolError::ChallengeRequiresAssignedVerifier,
        );
        assert_protocol_error(
            validate_challenge_authorization(other, worker, Some(assigned)),
            ProtocolError::VerifierNotAssigned,
        );
        // Self-challenge is rejected first, even when the worker is the assigned verifier.
        assert_protocol_error(
            validate_challenge_authorization(worker, worker, Some(worker)),
            ProtocolError::SelfChallengeForbidden,
        );
        assert_protocol_error(
            validate_challenge_authorization(worker, worker, None),
            ProtocolError::SelfChallengeForbidden,
        );
    }

    #[test]
    fn test_finalize_stale_slash_sets_every_settlement_flag() {
        let mut job = base_job();
        job.status = JobStatus::Claimed as u8;
        job.challenger = Pubkey::new_unique();
        finalize_stale_slash(&mut job);
        assert_eq!(job.status, JobStatus::Slashed as u8);
        assert_eq!(job.challenger, Pubkey::default());
        assert!(job.escrow_refunded);
        assert!(job.verifier_reward_paid);
        assert!(job.customer_slash_paid);
        assert!(job.slash_settled);
    }

    #[test]
    fn test_release_worker_claim_unlocks_stake_and_decrements_claims() {
        let mut worker = base_worker();
        worker.locked_stake = 70;
        worker.active_claims = 2;
        release_worker_claim(&mut worker, 50).unwrap();
        assert_eq!(worker.locked_stake, 20);
        assert_eq!(worker.active_claims, 1);

        let err = release_worker_claim(&mut worker, 21).expect_err("stake underflow");
        assert_anchor_error_code(err, ProtocolError::MathOverflow);
        let mut idle = base_worker();
        let err = release_worker_claim(&mut idle, 0).expect_err("claims underflow");
        assert_anchor_error_code(err, ProtocolError::MathOverflow);
    }

    #[test]
    fn test_job_is_terminal_classifies_every_status() {
        for status in [
            JobStatus::AwaitingArtifact,
            JobStatus::Open,
            JobStatus::Claimed,
            JobStatus::Completed,
        ] {
            assert!(!job_is_terminal(status as u8));
        }
        for status in [
            JobStatus::Settled,
            JobStatus::Cancelled,
            JobStatus::Slashed,
            JobStatus::CancelledOnExhaustion,
            JobStatus::CancelledOnTimeout,
        ] {
            assert!(job_is_terminal(status as u8));
        }
    }

    fn upgrade_authority_check() -> UpgradeAuthorityCheck {
        let program_data = Pubkey::new_unique();
        let admin = Pubkey::new_unique();
        UpgradeAuthorityCheck {
            programdata_address: Some(program_data),
            program_data_key: program_data,
            upgrade_authority_address: Some(admin),
            admin,
        }
    }

    #[test]
    fn test_validate_upgrade_authority_accepts_matching_authority() {
        validate_upgrade_authority(upgrade_authority_check()).unwrap();
    }

    #[test]
    fn test_validate_upgrade_authority_rejects_non_upgradeable_program() {
        let mut check = upgrade_authority_check();
        check.programdata_address = None;
        assert_protocol_error(
            validate_upgrade_authority(check),
            ProtocolError::ProgramDataMismatch,
        );
    }

    #[test]
    fn test_validate_upgrade_authority_rejects_foreign_program_data() {
        let mut check = upgrade_authority_check();
        check.program_data_key = Pubkey::new_unique();
        assert_protocol_error(
            validate_upgrade_authority(check),
            ProtocolError::ProgramDataMismatch,
        );
    }

    #[test]
    fn test_validate_upgrade_authority_rejects_wrong_admin_and_immutable_program() {
        let mut check = upgrade_authority_check();
        check.admin = Pubkey::new_unique();
        assert_protocol_error(
            validate_upgrade_authority(check),
            ProtocolError::AdminNotUpgradeAuthority,
        );

        let mut check = upgrade_authority_check();
        check.upgrade_authority_address = None;
        assert_protocol_error(
            validate_upgrade_authority(check),
            ProtocolError::AdminNotUpgradeAuthority,
        );
    }

    fn assert_anchor_error_code(err: anchor_lang::error::Error, expected: ProtocolError) {
        let expected_code: u32 = expected.into();
        match err {
            anchor_lang::error::Error::AnchorError(inner) => {
                assert_eq!(inner.error_code_number, expected_code)
            }
            other => panic!("expected anchor error {expected_code}, got {other:?}"),
        }
    }

    fn plain_mint_state() -> SplMintState {
        use anchor_lang::solana_program::program_option::COption;
        SplMintState {
            mint_authority: COption::None,
            supply: 0,
            decimals: 6,
            is_initialized: true,
            freeze_authority: COption::None,
        }
    }

    fn plain_token_2022_mint_data() -> Vec<u8> {
        use anchor_lang::solana_program::program_pack::Pack;
        let mut data = vec![0u8; SplMintState::LEN];
        SplMintState::pack(plain_mint_state(), &mut data).unwrap();
        data
    }

    fn transfer_fee_mint_data() -> Vec<u8> {
        use spl_token_2022::extension::transfer_fee::TransferFeeConfig;
        use spl_token_2022::extension::{BaseStateWithExtensionsMut, StateWithExtensionsMut};
        let len = ExtensionType::try_calculate_account_len::<SplMintState>(&[
            ExtensionType::TransferFeeConfig,
        ])
        .unwrap();
        let mut data = vec![0u8; len];
        {
            let mut state =
                StateWithExtensionsMut::<SplMintState>::unpack_uninitialized(&mut data).unwrap();
            state.init_extension::<TransferFeeConfig>(true).unwrap();
            state.base = plain_mint_state();
            state.pack_base();
            state.init_account_type().unwrap();
        }
        data
    }

    fn mint_close_authority_mint_data() -> Vec<u8> {
        use spl_token_2022::extension::mint_close_authority::MintCloseAuthority;
        use spl_token_2022::extension::{BaseStateWithExtensionsMut, StateWithExtensionsMut};
        let len = ExtensionType::try_calculate_account_len::<SplMintState>(&[
            ExtensionType::MintCloseAuthority,
        ])
        .unwrap();
        let mut data = vec![0u8; len];
        {
            let mut state =
                StateWithExtensionsMut::<SplMintState>::unpack_uninitialized(&mut data).unwrap();
            state.init_extension::<MintCloseAuthority>(true).unwrap();
            state.base = plain_mint_state();
            state.pack_base();
            state.init_account_type().unwrap();
        }
        data
    }

    #[test]
    fn test_derive_stake_tier_reads_config_floors() {
        let config = base_config();
        assert_eq!(derive_stake_tier(&config, 0), 0);
        assert_eq!(derive_stake_tier(&config, TEST_TIER_ONE_FLOOR - 1), 0);
        assert_eq!(
            derive_stake_tier(&config, TEST_TIER_ONE_FLOOR),
            StakeTier::TierOne as u8
        );
        assert_eq!(
            derive_stake_tier(&config, TEST_TIER_TWO_FLOOR - 1),
            StakeTier::TierOne as u8
        );
        assert_eq!(
            derive_stake_tier(&config, TEST_TIER_TWO_FLOOR),
            StakeTier::TierTwo as u8
        );
        assert_eq!(
            derive_stake_tier(&config, TEST_TIER_THREE_FLOOR - 1),
            StakeTier::TierTwo as u8
        );
        assert_eq!(
            derive_stake_tier(&config, TEST_TIER_THREE_FLOOR),
            StakeTier::TierThree as u8
        );
        assert_eq!(
            derive_stake_tier(&config, u64::MAX),
            StakeTier::TierThree as u8
        );
    }

    #[test]
    fn test_derive_stake_tier_follows_custom_floors() {
        let mut config = base_config();
        config.tier_one_stake_floor = 10;
        config.tier_two_stake_floor = 20;
        config.tier_three_stake_floor = 30;
        assert_eq!(derive_stake_tier(&config, 9), 0);
        assert_eq!(derive_stake_tier(&config, 10), StakeTier::TierOne as u8);
        assert_eq!(derive_stake_tier(&config, 25), StakeTier::TierTwo as u8);
        assert_eq!(derive_stake_tier(&config, 30), StakeTier::TierThree as u8);
    }

    #[test]
    fn test_receipt_challengeable_when_stake_below_config_tier_floor() {
        let job = base_job();
        assert!(receipt_is_challengeable(
            &base_config(),
            &job,
            &base_worker(),
            TEST_TIER_ONE_FLOOR - 1
        ));
        assert!(!receipt_is_challengeable(
            &base_config(),
            &job,
            &base_worker(),
            TEST_TIER_ONE_FLOOR
        ));
    }

    #[test]
    fn test_attestation_stake_floor_comes_from_config() {
        let mut validation = base_attestation_validation();
        validation.verifier_stake_floor = 10;
        validation.verifier_available_stake = 10;
        assert!(validate_verifier_attestation(validation).unwrap());

        let mut validation = base_attestation_validation();
        validation.verifier_stake_floor = 10;
        validation.verifier_available_stake = 9;
        assert_attestation_error(
            validate_verifier_attestation(validation),
            ProtocolError::AttestationStakeTooLow,
        );
    }

    fn base_open_job_args() -> OpenJobArgs {
        OpenJobArgs {
            job_nonce: 1,
            input_bundle_hash: EMPTY_HASH,
            expected_result_hash: EMPTY_HASH,
            reward_amount: 25,
            required_stake: 50,
            job_class: JobClass::BranchProof as u8,
            required_role: NodeRole::WorkerProof as u8,
            required_tier: StakeTier::TierOne as u8,
            required_capability_class_hash: EMPTY_HASH,
            required_software_digest: EMPTY_HASH,
            claim_window_seconds: 60,
            execution_window_seconds: 60,
            challenge_window_seconds: TEST_MIN_CHALLENGE_WINDOW_SECONDS,
            challenge_bond: 50,
        }
    }

    #[test]
    fn test_validate_job_windows_accepts_the_configured_floor() {
        let args = base_open_job_args();
        validate_job_windows(&args, TEST_MIN_CHALLENGE_WINDOW_SECONDS).unwrap();
    }

    #[test]
    fn test_validate_job_windows_rejects_a_challenge_window_below_the_floor() {
        let mut args = base_open_job_args();
        args.challenge_window_seconds = TEST_MIN_CHALLENGE_WINDOW_SECONDS - 1;
        assert_protocol_error(
            validate_job_windows(&args, TEST_MIN_CHALLENGE_WINDOW_SECONDS),
            ProtocolError::ChallengeWindowBelowFloor,
        );
        // The one-second window: legal before the floor existed, unattestable by construction.
        args.challenge_window_seconds = 1;
        assert_protocol_error(
            validate_job_windows(&args, TEST_MIN_CHALLENGE_WINDOW_SECONDS),
            ProtocolError::ChallengeWindowBelowFloor,
        );
    }

    #[test]
    fn test_validate_job_windows_still_rejects_zero_windows() {
        for mutate in [
            |args: &mut OpenJobArgs| args.claim_window_seconds = 0,
            |args: &mut OpenJobArgs| args.execution_window_seconds = 0,
            |args: &mut OpenJobArgs| args.challenge_window_seconds = 0,
        ] {
            let mut args = base_open_job_args();
            mutate(&mut args);
            assert_protocol_error(
                validate_job_windows(&args, 1),
                ProtocolError::InvalidDeadline,
            );
        }
    }

    #[test]
    fn test_validate_min_challenge_window_rejects_zero() {
        let mut args = base_floors();
        args.min_challenge_window_seconds = 0;
        assert_protocol_error(
            validate_min_challenge_window(&args),
            ProtocolError::InvalidChallengeWindowFloor,
        );
        args.min_challenge_window_seconds = 1;
        validate_min_challenge_window(&args).unwrap();
    }

    #[test]
    fn test_challenge_window_ladder_multiple_covers_every_rung_and_a_tail() {
        // One rung per verifier the ladder can hold, plus one window of challenge tail.
        assert_eq!(
            CHALLENGE_WINDOW_LADDER_MULTIPLE,
            u32::from(MAX_REASSIGNMENTS) + 2
        );
        assert_eq!(CHALLENGE_WINDOW_LADDER_MULTIPLE, 5);
    }

    #[test]
    fn test_reassign_verifier_rejects_a_job_without_a_receipt() {
        let mut job = base_job();
        job.verifier_attestation_hash = None;
        job.assigned_verifier_authority = Some(Pubkey::new_unique());
        job.assigned_verifier_unix = Some(100);
        // Assignment is allowed at any non-terminal status, so these are all reachable
        // states in which the attestation ladder must not run.
        for status in [
            JobStatus::AwaitingArtifact,
            JobStatus::Open,
            JobStatus::Claimed,
            JobStatus::Settled,
            JobStatus::Cancelled,
        ] {
            job.status = status as u8;
            assert_protocol_error(
                validate_reassign_verifier(&job, 100 + ATTESTATION_WINDOW_SECONDS),
                ProtocolError::InvalidJobState,
            );
        }
        job.status = JobStatus::Completed as u8;
        validate_reassign_verifier(&job, 100 + ATTESTATION_WINDOW_SECONDS).unwrap();
    }

    #[test]
    fn test_validate_stake_floors_accepts_ascending_floors() {
        assert!(validate_stake_floors(&base_floors()).is_ok());
        let mut floors = base_floors();
        floors.verifier_stake_floor = 1;
        assert!(validate_stake_floors(&floors).is_ok());
    }

    #[test]
    fn test_validate_stake_floors_rejects_zero_tier_one() {
        let mut floors = base_floors();
        floors.tier_one_stake_floor = 0;
        assert_protocol_error(
            validate_stake_floors(&floors),
            ProtocolError::InvalidStakeFloors,
        );
    }

    #[test]
    fn test_validate_stake_floors_rejects_equal_tiers() {
        let mut floors = base_floors();
        floors.tier_two_stake_floor = floors.tier_one_stake_floor;
        assert_protocol_error(
            validate_stake_floors(&floors),
            ProtocolError::InvalidStakeFloors,
        );

        let mut floors = base_floors();
        floors.tier_three_stake_floor = floors.tier_two_stake_floor;
        assert_protocol_error(
            validate_stake_floors(&floors),
            ProtocolError::InvalidStakeFloors,
        );
    }

    #[test]
    fn test_validate_stake_floors_rejects_descending_tiers() {
        let mut floors = base_floors();
        floors.tier_three_stake_floor = floors.tier_two_stake_floor - 1;
        assert_protocol_error(
            validate_stake_floors(&floors),
            ProtocolError::InvalidStakeFloors,
        );
    }

    #[test]
    fn test_validate_stake_floors_rejects_zero_verifier_floor() {
        let mut floors = base_floors();
        floors.verifier_stake_floor = 0;
        assert_protocol_error(
            validate_stake_floors(&floors),
            ProtocolError::InvalidVerifierStakeFloor,
        );
    }

    #[test]
    fn test_forbidden_mint_extension_flags_each_forbidden_type() {
        for extension in FORBIDDEN_MINT_EXTENSIONS {
            assert_eq!(
                forbidden_mint_extension(&[ExtensionType::MintCloseAuthority, extension]),
                Some(extension)
            );
        }
    }

    #[test]
    fn test_forbidden_mint_extension_allows_benign_types() {
        assert_eq!(forbidden_mint_extension(&[]), None);
        assert_eq!(
            forbidden_mint_extension(&[
                ExtensionType::MintCloseAuthority,
                ExtensionType::MetadataPointer
            ]),
            None
        );
    }

    #[test]
    fn test_token_2022_mint_extension_types_reads_plain_mint() {
        let extensions = token_2022_mint_extension_types(&plain_token_2022_mint_data()).unwrap();
        assert!(extensions.is_empty());
    }

    #[test]
    fn test_token_2022_mint_extension_types_reads_transfer_fee_mint() {
        let extensions = token_2022_mint_extension_types(&transfer_fee_mint_data()).unwrap();
        assert_eq!(extensions, vec![ExtensionType::TransferFeeConfig]);
    }

    #[test]
    fn test_token_2022_mint_extension_types_rejects_malformed_data() {
        assert!(token_2022_mint_extension_types(&[0u8; 10]).is_err());
    }

    #[test]
    fn test_validate_token_2022_mint_extensions_accepts_plain_mint() {
        assert!(validate_token_2022_mint_extensions(&plain_token_2022_mint_data()).is_ok());
    }

    #[test]
    fn test_validate_token_2022_mint_extensions_accepts_benign_extension() {
        assert!(validate_token_2022_mint_extensions(&mint_close_authority_mint_data()).is_ok());
    }

    #[test]
    fn test_validate_token_2022_mint_extensions_rejects_transfer_fee() {
        let err = validate_token_2022_mint_extensions(&transfer_fee_mint_data())
            .expect_err("transfer fee mint must be rejected");
        assert_anchor_error_code(err, ProtocolError::ForbiddenMintExtension);
    }
}
