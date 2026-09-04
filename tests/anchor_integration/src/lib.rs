//! Shared test infrastructure for `kswarm_protocol` integration tests.
//!
//! Tier 1 tests use `solana_program_test` for fast state-machine coverage. The
//! protocol program is loaded from the compiled SBF artifact (`cargo build-sbf`) as a
//! genuine upgradeable-loader program whose upgrade authority is the test payer, so
//! `initialize_protocol`'s upgrade-authority check runs unchanged. See
//! `program_artifact_path` for where the artifact is looked up.
//! Tier 2 tests are feature-gated and drive the real Bonsol verifier/prover stack.

use anchor_lang::{AccountDeserialize, AccountSerialize, InstructionData, Space, ToAccountMetas};
use kswarm_protocol::{
    accounts as miro_accounts, instruction as miro_ix, BonsolAggregateVerification,
    InitializeProtocolArgs, Job, JobClass, NodeRole, OpenJobArgs, ProtocolConfig, ProtocolError,
    RegisterWorkerArgs, StakeTier, VerifierAttestationArgs, Worker,
    AGGREGATE_MARKER_TIMEOUT_SECONDS, AGGREGATE_PROOF_CAPABILITY_HASH,
    ATTESTATION_WINDOW_SECONDS, MAX_REASSIGNMENTS,
};
use solana_program_test::{processor, BanksClientError, ProgramTest, ProgramTestContext};
use solana_sdk::{
    account::{Account, AccountSharedData},
    bpf_loader_upgradeable::{self, UpgradeableLoaderState},
    clock::Clock,
    hash::{hash, hashv},
    instruction::{Instruction, InstructionError},
    pubkey::Pubkey,
    rent::Rent,
    signature::{Keypair, Signer},
    system_instruction, system_program,
    transaction::{Transaction, TransactionError},
};
use spl_associated_token_account::{
    get_associated_token_address_with_program_id, instruction as ata_instruction,
};
use spl_token_2022::{
    extension::{transfer_fee, ExtensionType, StateWithExtensions},
    instruction as token_instruction,
    state::{Account as TokenAccount, Mint},
};
use std::path::PathBuf;

/// Compute budget for every test transaction. The SBF build of the program runs under
/// the real loader, so the budget is set explicitly rather than relying on the
/// per-instruction default.
const TEST_COMPUTE_UNIT_LIMIT: u64 = 1_400_000;

pub const BONSOL_PROGRAM_ID: &str = "BoNsHRcyLLNdtnoDf8hiCNZpyehMC4FDMxs6NTxFi3ew";
pub const CALLBACK_EXAMPLE_ID: &str = "exay1T7QqsJPNcwzMiWubR6vZnqrgM16jZRraHgqBGG";

/// Stand-in payment mints use the KAI layout: 6 decimals, so `UNIT` is one token.
pub const TOKEN_DECIMALS: u8 = 6;
pub const UNIT: u64 = 1_000_000;
/// Default stake floors (owner decision 2026-09-03), in base units of a 6-decimal mint.
pub const TIER_ONE_STAKE_FLOOR: u64 = 50_000 * UNIT;
pub const TIER_TWO_STAKE_FLOOR: u64 = 250_000 * UNIT;
pub const TIER_THREE_STAKE_FLOOR: u64 = 1_000_000 * UNIT;
pub const VERIFIER_STAKE_FLOOR: u64 = 100_000 * UNIT;
pub const REWARD_AMOUNT: u64 = 2_500 * UNIT;
pub const REQUIRED_STAKE: u64 = 20_000 * UNIT;
pub const CHALLENGE_BOND: u64 = 5_000 * UNIT;
/// Tier one, below tier two.
pub const WORKER_STAKE_DEPOSIT: u64 = 100_000 * UNIT;
/// Above the verifier floor.
pub const VERIFIER_STAKE_DEPOSIT: u64 = 150_000 * UNIT;
/// One token below the verifier floor.
pub const LOW_VERIFIER_STAKE_DEPOSIT: u64 = VERIFIER_STAKE_FLOOR - UNIT;

pub fn default_stake_floors() -> InitializeProtocolArgs {
    InitializeProtocolArgs {
        tier_one_stake_floor: TIER_ONE_STAKE_FLOOR,
        tier_two_stake_floor: TIER_TWO_STAKE_FLOOR,
        tier_three_stake_floor: TIER_THREE_STAKE_FLOOR,
        verifier_stake_floor: VERIFIER_STAKE_FLOOR,
    }
}

/// Which token program owns the stand-in payment mint under test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenProgramKind {
    /// Classic SPL Token (`Tokenkeg...`), the program that owns KAI on mainnet.
    Classic,
    /// Token-2022 (`TokenzQd...`).
    Token2022,
}

impl TokenProgramKind {
    pub fn program_id(self) -> Pubkey {
        match self {
            TokenProgramKind::Classic => spl_token::ID,
            TokenProgramKind::Token2022 => spl_token_2022::ID,
        }
    }
}
pub const ZERO_HASH: [u8; 32] = [0u8; 32];
pub const SOFTWARE_DIGEST: [u8; 32] = [0x41; 32];
pub const ALT_SOFTWARE_DIGEST: [u8; 32] = [0x42; 32];
pub const IMAGE_ID: [u8; 32] = [0x51; 32];
pub const INPUT_DIGEST: [u8; 32] = [0x61; 32];
pub const JOURNAL_HASH: [u8; 32] = [0x71; 32];

pub struct Tier1Context {
    pub ctx: ProgramTestContext,
    pub config: Pubkey,
    pub mint: Pubkey,
    pub token_program: Pubkey,
    /// `ProgramData` account of the protocol program. Its upgrade authority is the
    /// payer, which is therefore the only key that may call `initialize_protocol`.
    pub program_data: Pubkey,
    /// The program ELF, kept so `ProgramData` can be rewritten without losing it.
    program_elf: Vec<u8>,
}

pub struct Participant {
    pub authority: Keypair,
    pub worker: Pubkey,
    pub stake_vault: Pubkey,
    pub token_account: Pubkey,
}

pub struct TestJob {
    pub customer: Keypair,
    pub customer_token: Pubkey,
    pub job: Pubkey,
    pub escrow: Pubkey,
    pub nonce: u64,
    pub args: OpenJobArgs,
    pub customer_funding_amount: u64,
}

impl std::fmt::Debug for TestJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestJob")
            .field("customer", &self.customer.pubkey())
            .field("job", &self.job)
            .field("escrow", &self.escrow)
            .field("nonce", &self.nonce)
            .field("job_class", &self.args.job_class)
            .finish()
    }
}

#[derive(Clone)]
pub struct JobSpec {
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
    pub customer_funding_amount: u64,
}

impl Default for JobSpec {
    fn default() -> Self {
        Self {
            input_bundle_hash: [0x11; 32],
            expected_result_hash: ZERO_HASH,
            reward_amount: REWARD_AMOUNT,
            required_stake: REQUIRED_STAKE,
            job_class: JobClass::DeterministicBasic as u8,
            required_role: NodeRole::WorkerBasic as u8,
            required_tier: StakeTier::TierOne as u8,
            required_capability_class_hash: ZERO_HASH,
            required_software_digest: ZERO_HASH,
            claim_window_seconds: 60,
            execution_window_seconds: 60,
            challenge_window_seconds: 5,
            challenge_bond: CHALLENGE_BOND,
            customer_funding_amount: REWARD_AMOUNT * 4,
        }
    }
}

impl JobSpec {
    pub fn aggregate() -> Self {
        Self {
            input_bundle_hash: INPUT_DIGEST,
            expected_result_hash: JOURNAL_HASH,
            job_class: JobClass::AggregateProof as u8,
            required_role: NodeRole::WorkerProof as u8,
            required_capability_class_hash: AGGREGATE_PROOF_CAPABILITY_HASH,
            required_software_digest: IMAGE_ID,
            ..Self::default()
        }
    }

    pub fn branch_proof() -> Self {
        Self {
            job_class: JobClass::BranchProof as u8,
            required_role: NodeRole::WorkerProof as u8,
            required_capability_class_hash: ZERO_HASH,
            required_software_digest: ZERO_HASH,
            ..Self::default()
        }
    }
}

pub fn run_tier1_test<F, Fut>(test: F)
where
    F: FnOnce(Tier1Context) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    run_tier1_test_with(TokenProgramKind::Token2022, test);
}

/// Runs `test` against an initialized protocol whose payment mint is owned by `kind`.
pub fn run_tier1_test_with<F, Fut>(kind: TokenProgramKind, test: F)
where
    F: FnOnce(Tier1Context) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    tokio::runtime::Runtime::new()
        .expect("tokio runtime")
        .block_on(async move {
            let env = Tier1Context::new_with(kind).await;
            test(env).await;
        });
}

/// Runs `test` with the programs loaded and a payment mint created, but with
/// `initialize_protocol` NOT yet called, so tests can exercise its validation.
pub fn run_uninitialized_tier1_test<F, Fut>(kind: TokenProgramKind, test: F)
where
    F: FnOnce(Tier1Context) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    tokio::runtime::Runtime::new()
        .expect("tokio runtime")
        .block_on(async move {
            let env = Tier1Context::start(kind).await;
            test(env).await;
        });
}

impl Tier1Context {
    /// Token-2022 payment mint, default floors, protocol initialized.
    pub async fn new() -> Self {
        Self::new_with(TokenProgramKind::Token2022).await
    }

    /// Payment mint owned by `kind`, default floors, protocol initialized.
    pub async fn new_with(kind: TokenProgramKind) -> Self {
        let mut env = Self::start(kind).await;
        env.initialize_protocol(default_stake_floors())
            .await
            .expect("initialize protocol");
        env
    }

    /// Loads the protocol (from its SBF artifact, as an upgradeable program), both
    /// token programs, and the ATA program, then creates a payment mint owned by
    /// `kind`. Does NOT call `initialize_protocol`.
    pub async fn start(kind: TokenProgramKind) -> Self {
        let program_elf = load_program_elf();
        let mut program_test = ProgramTest::default();
        program_test.set_compute_max_units(TEST_COMPUTE_UNIT_LIMIT);
        program_test.add_program(
            "spl_token",
            spl_token::ID,
            processor!(spl_token::processor::Processor::process),
        );
        program_test.add_program(
            "spl_token_2022",
            spl_token_2022::ID,
            processor!(spl_token_2022::processor::Processor::process),
        );
        program_test.add_program(
            "spl_associated_token_account",
            spl_associated_token_account::ID,
            processor!(spl_associated_token_account::processor::process_instruction),
        );

        let mut ctx = program_test.start_with_context().await;
        let upgrade_authority = ctx.payer.pubkey();
        let program_data = install_upgradeable_program(&mut ctx, &program_elf, upgrade_authority);
        let token_program = kind.program_id();
        let mint = create_mint(&mut ctx, token_program, false).await;
        Self {
            ctx,
            config: config_pda(),
            mint,
            token_program,
            program_data,
            program_elf,
        }
    }

    /// The key that owns the program's upgrade authority (the test payer).
    pub fn upgrade_authority(&self) -> Pubkey {
        self.ctx.payer.pubkey()
    }

    /// Rewrites the program's `ProgramData` account with a new upgrade authority.
    /// `None` models an immutable program (`solana program set-upgrade-authority --final`).
    pub fn set_upgrade_authority(&mut self, upgrade_authority: Option<Pubkey>) {
        let elf = self.program_elf.clone();
        write_program_data_account(&mut self.ctx, program_data_pda(), upgrade_authority, &elf);
    }

    /// Writes a well-formed `ProgramData` account (metadata only) at an arbitrary
    /// `key`, so tests can hand `initialize_protocol` a ProgramData account that is not
    /// the program's own.
    pub fn store_program_data_account(&mut self, key: Pubkey, upgrade_authority: Option<Pubkey>) {
        write_program_data_account(&mut self.ctx, key, upgrade_authority, &[]);
    }

    /// Creates an additional mint owned by `kind`. With `with_transfer_fee` the mint
    /// carries a Token-2022 `TransferFeeConfig` extension (Token-2022 only).
    pub async fn create_payment_mint(
        &mut self,
        kind: TokenProgramKind,
        with_transfer_fee: bool,
    ) -> Pubkey {
        create_mint(&mut self.ctx, kind.program_id(), with_transfer_fee).await
    }

    /// Calls `initialize_protocol` with the context's mint and token program.
    pub async fn initialize_protocol(
        &mut self,
        args: InitializeProtocolArgs,
    ) -> Result<(), BanksClientError> {
        let mint = self.mint;
        let token_program = self.token_program;
        self.initialize_protocol_with(mint, token_program, args)
            .await
    }

    /// Calls `initialize_protocol` with an explicit mint and token program, so tests
    /// can pass a mismatched pair. The payer (the upgrade authority) signs as admin.
    pub async fn initialize_protocol_with(
        &mut self,
        payment_mint: Pubkey,
        token_program: Pubkey,
        args: InitializeProtocolArgs,
    ) -> Result<(), BanksClientError> {
        let admin = self.ctx.payer.insecure_clone();
        let program_data = self.program_data;
        self.initialize_protocol_as(&admin, program_data, payment_mint, token_program, args)
            .await
    }

    /// Calls `initialize_protocol` with an explicit admin signer and `program_data`
    /// account, so tests can exercise the upgrade-authority check.
    pub async fn initialize_protocol_as(
        &mut self,
        admin: &Keypair,
        program_data: Pubkey,
        payment_mint: Pubkey,
        token_program: Pubkey,
        args: InitializeProtocolArgs,
    ) -> Result<(), BanksClientError> {
        let extra_signers: Vec<&Keypair> = if admin.pubkey() == self.payer() {
            Vec::new()
        } else {
            vec![admin]
        };
        send_tx(
            &mut self.ctx,
            vec![miro_instruction(
                miro_accounts::InitializeProtocol {
                    admin: admin.pubkey(),
                    config: self.config,
                    payment_mint,
                    token_program,
                    system_program: system_program::ID,
                    program: kswarm_protocol::ID,
                    program_data,
                },
                miro_ix::InitializeProtocol { args },
            )],
            &extra_signers,
        )
        .await
    }

    pub fn payer(&self) -> Pubkey {
        self.ctx.payer.pubkey()
    }

    pub fn token_ata(&self, owner: &Pubkey) -> Pubkey {
        get_associated_token_address_with_program_id(owner, &self.mint, &self.token_program)
    }

    pub async fn create_ata(&mut self, owner: Pubkey) -> Pubkey {
        let ata = self.token_ata(&owner);
        let payer = self.payer();
        send_tx(
            &mut self.ctx,
            vec![ata_instruction::create_associated_token_account_idempotent(
                &payer,
                &owner,
                &self.mint,
                &self.token_program,
            )],
            &[],
        )
        .await
        .expect("create ata");
        ata
    }

    pub async fn mint_to(&mut self, destination: Pubkey, amount: u64) {
        let payer = self.payer();
        send_tx(
            &mut self.ctx,
            vec![token_instruction::mint_to(
                &self.token_program,
                &self.mint,
                &destination,
                &payer,
                &[],
                amount,
            )
            .expect("mint_to ix")],
            &[],
        )
        .await
        .expect("mint tokens");
    }

    pub async fn fund_keypair(&mut self, keypair: &Keypair) {
        let payer = self.payer();
        send_tx(
            &mut self.ctx,
            vec![system_instruction::transfer(
                &payer,
                &keypair.pubkey(),
                2 * solana_sdk::native_token::LAMPORTS_PER_SOL,
            )],
            &[],
        )
        .await
        .expect("fund keypair");
    }

    pub async fn register_participant(
        &mut self,
        role: u8,
        capability_class_hash: [u8; 32],
        software_digest: [u8; 32],
        stake_amount: u64,
    ) -> Participant {
        let authority = Keypair::new();
        self.fund_keypair(&authority).await;
        let token_account = self.create_ata(authority.pubkey()).await;
        if stake_amount > 0 {
            self.mint_to(token_account, stake_amount).await;
        }

        let worker = worker_pda(&authority.pubkey());
        let stake_vault = self.token_ata(&worker);
        send_tx(
            &mut self.ctx,
            vec![miro_instruction(
                miro_accounts::RegisterWorker {
                    authority: authority.pubkey(),
                    config: self.config,
                    payment_mint: self.mint,
                    worker,
                    worker_stake_vault: stake_vault,
                    token_program: self.token_program,
                    associated_token_program: spl_associated_token_account::ID,
                    system_program: system_program::ID,
                },
                miro_ix::RegisterWorker {
                    args: RegisterWorkerArgs {
                        role,
                        capability_class_hash,
                        software_digest,
                    },
                },
            )],
            &[&authority],
        )
        .await
        .expect("register participant");

        if stake_amount > 0 {
            self.deposit_stake(&authority, worker, stake_vault, token_account, stake_amount)
                .await
                .expect("deposit stake");
        }

        Participant {
            authority,
            worker,
            stake_vault,
            token_account,
        }
    }

    pub async fn deposit_stake(
        &mut self,
        authority: &Keypair,
        worker: Pubkey,
        stake_vault: Pubkey,
        funding_account: Pubkey,
        amount: u64,
    ) -> Result<(), BanksClientError> {
        let token_program = self.token_program;
        self.deposit_stake_with_token_program(
            authority,
            worker,
            stake_vault,
            funding_account,
            amount,
            token_program,
        )
        .await
    }

    /// Like `deposit_stake`, but with an explicit `token_program` account so tests can
    /// pass a program that does not match `config.token_program`.
    pub async fn deposit_stake_with_token_program(
        &mut self,
        authority: &Keypair,
        worker: Pubkey,
        stake_vault: Pubkey,
        funding_account: Pubkey,
        amount: u64,
        token_program: Pubkey,
    ) -> Result<(), BanksClientError> {
        send_tx(
            &mut self.ctx,
            vec![miro_instruction(
                miro_accounts::DepositWorkerStake {
                    authority: authority.pubkey(),
                    config: self.config,
                    payment_mint: self.mint,
                    worker,
                    worker_stake_vault: stake_vault,
                    worker_funding_account: funding_account,
                    token_program,
                },
                miro_ix::DepositWorkerStake { amount },
            )],
            &[authority],
        )
        .await
    }

    pub async fn open_job(&mut self, spec: JobSpec) -> TestJob {
        self.try_open_job(spec).await.expect("open job")
    }

    /// Like `open_job`, but returns the program's verdict so tests can assert on
    /// `open_job` validation failures.
    pub async fn try_open_job(&mut self, spec: JobSpec) -> Result<TestJob, BanksClientError> {
        let customer = Keypair::new();
        self.fund_keypair(&customer).await;
        let customer_token = self.create_ata(customer.pubkey()).await;
        self.mint_to(customer_token, spec.customer_funding_amount)
            .await;

        let nonce = unique_nonce();
        let args = OpenJobArgs {
            job_nonce: nonce,
            input_bundle_hash: spec.input_bundle_hash,
            expected_result_hash: spec.expected_result_hash,
            reward_amount: spec.reward_amount,
            required_stake: spec.required_stake,
            job_class: spec.job_class,
            required_role: spec.required_role,
            required_tier: spec.required_tier,
            required_capability_class_hash: spec.required_capability_class_hash,
            required_software_digest: spec.required_software_digest,
            claim_window_seconds: spec.claim_window_seconds,
            execution_window_seconds: spec.execution_window_seconds,
            challenge_window_seconds: spec.challenge_window_seconds,
            challenge_bond: spec.challenge_bond,
        };
        let job = job_pda(&customer.pubkey(), nonce);
        let escrow = self.token_ata(&job);
        send_tx(
            &mut self.ctx,
            vec![miro_instruction(
                miro_accounts::OpenJob {
                    customer: customer.pubkey(),
                    config: self.config,
                    payment_mint: self.mint,
                    job,
                    job_escrow_vault: escrow,
                    customer_payment_account: customer_token,
                    token_program: self.token_program,
                    associated_token_program: spl_associated_token_account::ID,
                    system_program: system_program::ID,
                },
                miro_ix::OpenJob { args: args.clone() },
            )],
            &[&customer],
        )
        .await?;

        Ok(TestJob {
            customer,
            customer_token,
            job,
            escrow,
            nonce,
            args,
            customer_funding_amount: spec.customer_funding_amount,
        })
    }

    /// `cancel_open_job` signed by `customer`; `customer_token` is the refund account.
    pub async fn cancel_open_job(
        &mut self,
        customer: &Keypair,
        customer_token: Pubkey,
        job: &TestJob,
    ) -> Result<(), BanksClientError> {
        send_tx(
            &mut self.ctx,
            vec![miro_instruction(
                miro_accounts::CancelOpenJob {
                    customer: customer.pubkey(),
                    config: self.config,
                    payment_mint: self.mint,
                    job: job.job,
                    job_escrow_vault: job.escrow,
                    customer_payment_account: customer_token,
                    token_program: self.token_program,
                },
                miro_ix::CancelOpenJob {},
            )],
            &[customer],
        )
        .await
    }

    pub async fn withdraw_unlocked_stake(
        &mut self,
        worker: &Participant,
        amount: u64,
    ) -> Result<(), BanksClientError> {
        send_tx(
            &mut self.ctx,
            vec![miro_instruction(
                miro_accounts::WithdrawUnlockedStake {
                    authority: worker.authority.pubkey(),
                    config: self.config,
                    payment_mint: self.mint,
                    worker: worker.worker,
                    worker_stake_vault: worker.stake_vault,
                    worker_destination_account: worker.token_account,
                    token_program: self.token_program,
                },
                miro_ix::WithdrawUnlockedStake { amount },
            )],
            &[&worker.authority],
        )
        .await
    }

    pub async fn commit_input_artifact(&mut self, job: &TestJob) {
        send_tx(
            &mut self.ctx,
            vec![miro_instruction(
                miro_accounts::CommitInputArtifact {
                    customer: job.customer.pubkey(),
                    job: job.job,
                },
                miro_ix::CommitInputArtifact {
                    input_cid: "bafkreiinputartifactv1".to_string(),
                },
            )],
            &[&job.customer],
        )
        .await
        .expect("commit input artifact");
    }

    pub async fn claim_job(
        &mut self,
        worker: &Participant,
        job: &TestJob,
    ) -> Result<(), BanksClientError> {
        send_tx(
            &mut self.ctx,
            vec![miro_instruction(
                miro_accounts::ClaimJob {
                    authority: worker.authority.pubkey(),
                    config: self.config,
                    payment_mint: self.mint,
                    worker: worker.worker,
                    worker_stake_vault: worker.stake_vault,
                    job: job.job,
                    token_program: self.token_program,
                },
                miro_ix::ClaimJob {},
            )],
            &[&worker.authority],
        )
        .await
    }

    pub async fn submit_receipt(
        &mut self,
        worker: &Participant,
        job: &TestJob,
        result_bytes: Vec<u8>,
    ) -> Result<(), BanksClientError> {
        send_tx(
            &mut self.ctx,
            vec![miro_instruction(
                miro_accounts::SubmitReceipt {
                    authority: worker.authority.pubkey(),
                    worker: worker.worker,
                    job: job.job,
                },
                miro_ix::SubmitReceipt {
                    output_cid: "bafkreioutputartifactv1".to_string(),
                    result_bytes,
                },
            )],
            &[&worker.authority],
        )
        .await
    }

    pub async fn complete_job(
        &mut self,
        worker: &Participant,
        spec: JobSpec,
        result_bytes: Vec<u8>,
    ) -> TestJob {
        let job = self.open_job(spec).await;
        self.commit_input_artifact(&job).await;
        self.claim_job(worker, &job).await.expect("claim job");
        self.submit_receipt(worker, &job, result_bytes)
            .await
            .expect("submit receipt");
        job
    }

    pub async fn submit_verifier_attestation(
        &mut self,
        verifier: &Participant,
        job: &TestJob,
        verifier_result_hash: [u8; 32],
        verifier_software_digest: [u8; 32],
    ) -> Result<(), BanksClientError> {
        send_tx(
            &mut self.ctx,
            vec![miro_instruction(
                miro_accounts::SubmitVerifierAttestation {
                    verifier_authority: verifier.authority.pubkey(),
                    config: self.config,
                    payment_mint: self.mint,
                    verifier: verifier.worker,
                    verifier_stake_vault: verifier.stake_vault,
                    job: job.job,
                    token_program: self.token_program,
                },
                miro_ix::SubmitVerifierAttestation {
                    args: VerifierAttestationArgs {
                        verifier_result_hash,
                        verifier_evidence_cid: "bafkreiverifierevidencev1".to_string(),
                        verifier_software_digest,
                    },
                },
            )],
            &[&verifier.authority],
        )
        .await
    }

    pub async fn assign_verifier(
        &mut self,
        caller: &Keypair,
        job: &TestJob,
        verifier_authority: Pubkey,
    ) -> Result<(), BanksClientError> {
        send_tx(
            &mut self.ctx,
            vec![miro_instruction(
                miro_accounts::AssignVerifier {
                    caller: caller.pubkey(),
                    config: self.config,
                    job: job.job,
                },
                miro_ix::AssignVerifier { verifier_authority },
            )],
            &[caller],
        )
        .await
    }

    pub async fn reassign_verifier(
        &mut self,
        caller: &Keypair,
        job: &TestJob,
    ) -> Result<(), BanksClientError> {
        send_tx(
            &mut self.ctx,
            vec![miro_instruction(
                miro_accounts::ReassignVerifier {
                    caller: caller.pubkey(),
                    job: job.job,
                },
                miro_ix::ReassignVerifier {},
            )],
            &[caller],
        )
        .await
    }

    pub async fn settle_job(
        &mut self,
        caller: &Keypair,
        worker: &Participant,
        job: &TestJob,
    ) -> Result<(), BanksClientError> {
        send_tx(
            &mut self.ctx,
            vec![miro_instruction(
                miro_accounts::SettleJob {
                    caller: caller.pubkey(),
                    config: self.config,
                    payment_mint: self.mint,
                    job: job.job,
                    worker: worker.worker,
                    worker_authority: worker.authority.pubkey(),
                    job_escrow_vault: job.escrow,
                    worker_payment_account: worker.token_account,
                    token_program: self.token_program,
                },
                miro_ix::SettleJob {},
            )],
            &[caller],
        )
        .await
    }

    pub async fn settle_aggregate_proof_job(
        &mut self,
        caller: &Keypair,
        worker: &Participant,
        job: &TestJob,
        marker: Pubkey,
    ) -> Result<(), BanksClientError> {
        send_tx(
            &mut self.ctx,
            vec![miro_instruction(
                miro_accounts::SettleAggregateProofJob {
                    caller: caller.pubkey(),
                    config: self.config,
                    payment_mint: self.mint,
                    job: job.job,
                    bonsol_aggregate_verification: marker,
                    worker: worker.worker,
                    worker_authority: worker.authority.pubkey(),
                    job_escrow_vault: job.escrow,
                    worker_payment_account: worker.token_account,
                    token_program: self.token_program,
                },
                miro_ix::SettleAggregateProofJob {},
            )],
            &[caller],
        )
        .await
    }

    pub async fn challenge_job(
        &mut self,
        verifier: &Participant,
        worker: &Participant,
        job: &TestJob,
    ) -> Result<(), BanksClientError> {
        send_tx(
            &mut self.ctx,
            vec![miro_instruction(
                miro_accounts::ChallengeJob {
                    caller: verifier.authority.pubkey(),
                    config: self.config,
                    payment_mint: self.mint,
                    verifier: verifier.worker,
                    verifier_stake_vault: verifier.stake_vault,
                    job: job.job,
                    worker: worker.worker,
                    worker_authority: worker.authority.pubkey(),
                    worker_stake_vault: worker.stake_vault,
                    token_program: self.token_program,
                },
                miro_ix::ChallengeJob {},
            )],
            &[&verifier.authority],
        )
        .await
    }

    /// Like `challenge_job`, but the caller supplies an explicit
    /// `worker_stake_vault` instead of deriving it from `worker`. Needed to
    /// express the H1 fake-vault attack, which `challenge_job` cannot.
    pub async fn challenge_job_with_stake_vault(
        &mut self,
        verifier: &Participant,
        worker: &Participant,
        job: &TestJob,
        worker_stake_vault: Pubkey,
    ) -> Result<(), BanksClientError> {
        send_tx(
            &mut self.ctx,
            vec![miro_instruction(
                miro_accounts::ChallengeJob {
                    caller: verifier.authority.pubkey(),
                    config: self.config,
                    payment_mint: self.mint,
                    verifier: verifier.worker,
                    verifier_stake_vault: verifier.stake_vault,
                    job: job.job,
                    worker: worker.worker,
                    worker_authority: worker.authority.pubkey(),
                    worker_stake_vault,
                    token_program: self.token_program,
                },
                miro_ix::ChallengeJob {},
            )],
            &[&verifier.authority],
        )
        .await
    }

    pub async fn refund_slashed_job_escrow(
        &mut self,
        caller: &Keypair,
        job: &TestJob,
    ) -> Result<(), BanksClientError> {
        send_tx(
            &mut self.ctx,
            vec![miro_instruction(
                miro_accounts::RefundSlashedJobEscrow {
                    caller: caller.pubkey(),
                    config: self.config,
                    payment_mint: self.mint,
                    job: job.job,
                    customer_authority: job.customer.pubkey(),
                    customer_payment_account: job.customer_token,
                    job_escrow_vault: job.escrow,
                    token_program: self.token_program,
                },
                miro_ix::RefundSlashedJobEscrow {},
            )],
            &[caller],
        )
        .await
    }

    pub async fn claim_verifier_slash_reward(
        &mut self,
        caller: &Keypair,
        verifier: &Participant,
        worker: &Participant,
        job: &TestJob,
    ) -> Result<(), BanksClientError> {
        send_tx(
            &mut self.ctx,
            vec![miro_instruction(
                miro_accounts::ClaimVerifierSlashReward {
                    caller: caller.pubkey(),
                    config: self.config,
                    payment_mint: self.mint,
                    job: job.job,
                    verifier_authority: verifier.authority.pubkey(),
                    verifier_reward_account: verifier.token_account,
                    worker: worker.worker,
                    worker_authority: worker.authority.pubkey(),
                    worker_stake_vault: worker.stake_vault,
                    token_program: self.token_program,
                },
                miro_ix::ClaimVerifierSlashReward {},
            )],
            &[caller],
        )
        .await
    }

    pub async fn claim_customer_slash_compensation(
        &mut self,
        caller: &Keypair,
        worker: &Participant,
        job: &TestJob,
    ) -> Result<(), BanksClientError> {
        send_tx(
            &mut self.ctx,
            vec![miro_instruction(
                miro_accounts::ClaimCustomerSlashCompensation {
                    caller: caller.pubkey(),
                    config: self.config,
                    payment_mint: self.mint,
                    job: job.job,
                    customer_authority: job.customer.pubkey(),
                    customer_payment_account: job.customer_token,
                    worker: worker.worker,
                    worker_authority: worker.authority.pubkey(),
                    worker_stake_vault: worker.stake_vault,
                    token_program: self.token_program,
                },
                miro_ix::ClaimCustomerSlashCompensation {},
            )],
            &[caller],
        )
        .await
    }

    /// First Rust coverage of `slash_stale_job` (previously exercised only via the
    /// JS watcher). Takes explicit `worker` and `worker_stake_vault` so both the
    /// C1 wrong-worker and H1 fake-vault attacks are expressible.
    pub async fn slash_stale_job(
        &mut self,
        caller: &Keypair,
        worker: &Participant,
        worker_stake_vault: Pubkey,
        job: &TestJob,
    ) -> Result<(), BanksClientError> {
        send_tx(
            &mut self.ctx,
            vec![miro_instruction(
                miro_accounts::SlashStaleJob {
                    caller: caller.pubkey(),
                    config: self.config,
                    payment_mint: self.mint,
                    job: job.job,
                    customer_authority: job.customer.pubkey(),
                    customer_payment_account: job.customer_token,
                    worker: worker.worker,
                    worker_authority: worker.authority.pubkey(),
                    worker_stake_vault,
                    job_escrow_vault: job.escrow,
                    token_program: self.token_program,
                },
                miro_ix::SlashStaleJob {},
            )],
            &[caller],
        )
        .await
    }

    /// `cancel_aggregate_proof_job` signed by `customer`. `worker` must be the job's
    /// worker: the instruction releases its locked stake.
    pub async fn cancel_aggregate_proof_job(
        &mut self,
        customer: &Keypair,
        customer_token: Pubkey,
        worker: &Participant,
        job: &TestJob,
    ) -> Result<(), BanksClientError> {
        send_tx(
            &mut self.ctx,
            vec![miro_instruction(
                miro_accounts::CancelAggregateProofJob {
                    customer: customer.pubkey(),
                    config: self.config,
                    payment_mint: self.mint,
                    job: job.job,
                    job_escrow_vault: job.escrow,
                    customer_payment_account: customer_token,
                    token_program: self.token_program,
                    worker: worker.worker,
                    worker_authority: worker.authority.pubkey(),
                },
                miro_ix::CancelAggregateProofJob {},
            )],
            &[customer],
        )
        .await
    }

    pub async fn read_job(&mut self, job: Pubkey) -> Job {
        let account = self
            .ctx
            .banks_client
            .get_account(job)
            .await
            .expect("get job account")
            .expect("job account exists");
        let mut data: &[u8] = &account.data;
        Job::try_deserialize(&mut data).expect("deserialize job")
    }

    pub async fn read_config(&mut self) -> ProtocolConfig {
        let account = self
            .ctx
            .banks_client
            .get_account(self.config)
            .await
            .expect("get config account")
            .expect("config account exists");
        let mut data: &[u8] = &account.data;
        ProtocolConfig::try_deserialize(&mut data).expect("deserialize config")
    }

    pub async fn read_worker(&mut self, worker: Pubkey) -> Worker {
        let account = self
            .ctx
            .banks_client
            .get_account(worker)
            .await
            .expect("get worker account")
            .expect("worker account exists");
        let mut data: &[u8] = &account.data;
        Worker::try_deserialize(&mut data).expect("deserialize worker")
    }

    pub async fn read_token_balance(&mut self, account: Pubkey) -> u64 {
        let account = self
            .ctx
            .banks_client
            .get_account(account)
            .await
            .expect("get token account")
            .expect("token account exists");
        StateWithExtensions::<TokenAccount>::unpack(&account.data)
            .expect("unpack token account")
            .base
            .amount
    }

    pub async fn current_clock(&mut self) -> Clock {
        self.ctx
            .banks_client
            .get_sysvar::<Clock>()
            .await
            .expect("clock sysvar")
    }

    pub async fn warp_seconds(&mut self, seconds: i64) {
        let clock = self.current_clock().await;
        let unix_timestamp = clock.unix_timestamp;
        let slots = seconds.max(0) as u64 * 3 + 20;
        let mut warped_clock = clock;
        warped_clock.slot = warped_clock.slot.saturating_add(slots);
        warped_clock.unix_timestamp = unix_timestamp.saturating_add(seconds.max(0));
        self.ctx.set_sysvar(&warped_clock);
    }

    pub async fn warp_past_challenge_deadline(&mut self, job: &TestJob) {
        let job_state = self.read_job(job.job).await;
        let now = self.current_clock().await.unix_timestamp;
        let delta = job_state.challenge_deadline.saturating_sub(now) + 2;
        self.warp_seconds(delta).await;
    }

    pub async fn warp_past_execute_deadline(&mut self, job: &TestJob) {
        let job_state = self.read_job(job.job).await;
        let now = self.current_clock().await.unix_timestamp;
        let delta = job_state.execute_deadline.saturating_sub(now) + 2;
        self.warp_seconds(delta).await;
    }

    pub async fn warp_past_attestation_window(&mut self) {
        self.warp_seconds(ATTESTATION_WINDOW_SECONDS + 2).await;
    }

    /// Warps to just past `challenge_deadline + AGGREGATE_MARKER_TIMEOUT_SECONDS`.
    pub async fn warp_past_aggregate_marker_timeout(&mut self, job: &TestJob) {
        let job_state = self.read_job(job.job).await;
        let now = self.current_clock().await.unix_timestamp;
        let timeout_unix = job_state.challenge_deadline + AGGREGATE_MARKER_TIMEOUT_SECONDS;
        self.warp_seconds(timeout_unix.saturating_sub(now) + 2).await;
    }

    /// Warps to `challenge_deadline + AGGREGATE_MARKER_TIMEOUT_SECONDS` exactly (the
    /// timeout is strict, so cancellation is still rejected at this instant).
    pub async fn warp_to_aggregate_marker_timeout(&mut self, job: &TestJob) {
        let job_state = self.read_job(job.job).await;
        let now = self.current_clock().await.unix_timestamp;
        let timeout_unix = job_state.challenge_deadline + AGGREGATE_MARKER_TIMEOUT_SECONDS;
        self.warp_seconds(timeout_unix.saturating_sub(now)).await;
    }

    pub async fn warp_past_claim_deadline(&mut self, job: &TestJob) {
        let job_state = self.read_job(job.job).await;
        let now = self.current_clock().await.unix_timestamp;
        let delta = job_state.claim_deadline.saturating_sub(now) + 2;
        self.warp_seconds(delta).await;
    }

    pub fn store_bonsol_marker(&mut self, marker_key: Pubkey, marker: BonsolAggregateVerification) {
        let mut data = Vec::with_capacity(8 + BonsolAggregateVerification::INIT_SPACE);
        marker
            .try_serialize(&mut data)
            .expect("serialize bonsol marker");
        let lamports = Rent::default().minimum_balance(data.len());
        let account: AccountSharedData = Account {
            lamports,
            data,
            owner: kswarm_protocol::ID,
            executable: false,
            rent_epoch: 0,
        }
        .into();
        self.ctx.set_account(&marker_key, &account);
    }

    pub fn store_empty_system_account(&mut self, key: Pubkey) {
        let account: AccountSharedData = Account {
            lamports: Rent::default().minimum_balance(0),
            data: Vec::new(),
            owner: system_program::ID,
            executable: false,
            rent_epoch: 0,
        }
        .into();
        self.ctx.set_account(&key, &account);
    }

    pub async fn exhaust_reassignments(
        &mut self,
        caller: &Keypair,
        worker: &Participant,
        job: &TestJob,
    ) {
        for idx in 0..MAX_REASSIGNMENTS {
            let verifier = Pubkey::new_unique();
            assert_ne!(verifier, worker.authority.pubkey());
            self.assign_verifier(caller, job, verifier)
                .await
                .unwrap_or_else(|err| panic!("assign verifier {idx}: {err:?}"));
            self.warp_past_attestation_window().await;
            self.reassign_verifier(caller, job)
                .await
                .unwrap_or_else(|err| panic!("reassign verifier {idx}: {err:?}"));
        }
    }
}

pub fn config_pda() -> Pubkey {
    Pubkey::find_program_address(&[b"config"], &kswarm_protocol::ID).0
}

/// `ProgramData` address of the protocol program under the upgradeable loader.
pub fn program_data_pda() -> Pubkey {
    Pubkey::find_program_address(
        &[kswarm_protocol::ID.as_ref()],
        &bpf_loader_upgradeable::id(),
    )
    .0
}

/// Where the compiled program is looked up, first match wins:
/// `KSWARM_PROGRAM_SO` (a file), `SBF_OUT_DIR` / `BPF_OUT_DIR`,
/// `CARGO_TARGET_DIR/deploy`, then `solana/target/deploy` in the repo.
/// Build it with
/// `cargo build-sbf --tools-version v1.51 --manifest-path solana/programs/kswarm_protocol/Cargo.toml -- --locked`.
pub fn program_artifact_path() -> PathBuf {
    let file_name = "kswarm_protocol.so";
    let mut candidates = Vec::new();
    if let Ok(path) = std::env::var("KSWARM_PROGRAM_SO") {
        candidates.push(PathBuf::from(path));
    }
    for var in ["SBF_OUT_DIR", "BPF_OUT_DIR"] {
        if let Ok(dir) = std::env::var(var) {
            candidates.push(PathBuf::from(dir).join(file_name));
        }
    }
    if let Ok(dir) = std::env::var("CARGO_TARGET_DIR") {
        candidates.push(PathBuf::from(dir).join("deploy").join(file_name));
    }
    candidates.push(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../solana/target/deploy")
            .join(file_name),
    );
    candidates
        .iter()
        .find(|path| path.is_file())
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "{file_name} not found; run cargo build-sbf for solana/programs/kswarm_protocol first. Searched: {}",
                candidates
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
}

fn load_program_elf() -> Vec<u8> {
    let path = program_artifact_path();
    std::fs::read(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

/// Installs the protocol program the way `solana program deploy` does: an
/// upgradeable-loader `Program` account pointing at a `ProgramData` account that holds
/// the ELF and names `upgrade_authority`. `initialize_protocol` therefore runs its
/// real upgrade-authority check inside the test harness.
fn install_upgradeable_program(
    ctx: &mut ProgramTestContext,
    program_elf: &[u8],
    upgrade_authority: Pubkey,
) -> Pubkey {
    let program_data = program_data_pda();
    let program_state = bincode::serialize(&UpgradeableLoaderState::Program {
        programdata_address: program_data,
    })
    .expect("serialize upgradeable program state");
    let program_account: AccountSharedData = Account {
        lamports: Rent::default().minimum_balance(program_state.len()),
        data: program_state,
        owner: bpf_loader_upgradeable::id(),
        executable: true,
        rent_epoch: 0,
    }
    .into();
    ctx.set_account(&kswarm_protocol::ID, &program_account);
    write_program_data_account(ctx, program_data, Some(upgrade_authority), program_elf);
    program_data
}

/// Writes a `ProgramData` account: the loader metadata (slot 0, the given upgrade
/// authority) padded to its fixed 45-byte size, followed by `program_elf`. The loader
/// always reads the ELF from offset 45; with `None` bincode emits only 13 bytes, so
/// the padding is required for the program to stay loadable.
fn write_program_data_account(
    ctx: &mut ProgramTestContext,
    key: Pubkey,
    upgrade_authority: Option<Pubkey>,
    program_elf: &[u8],
) {
    let metadata_len = UpgradeableLoaderState::size_of_programdata_metadata();
    let mut data = bincode::serialize(&UpgradeableLoaderState::ProgramData {
        slot: 0,
        upgrade_authority_address: upgrade_authority,
    })
    .expect("serialize program data state");
    assert!(data.len() <= metadata_len, "program data metadata exceeds {metadata_len} bytes");
    data.resize(metadata_len, 0);
    data.extend_from_slice(program_elf);
    let account: AccountSharedData = Account {
        lamports: Rent::default().minimum_balance(data.len()),
        data,
        owner: bpf_loader_upgradeable::id(),
        executable: false,
        rent_epoch: 0,
    }
    .into();
    ctx.set_account(&key, &account);
}

pub fn worker_pda(authority: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"worker", authority.as_ref()], &kswarm_protocol::ID).0
}

pub fn job_pda(customer: &Pubkey, nonce: u64) -> Pubkey {
    Pubkey::find_program_address(
        &[b"job", customer.as_ref(), &nonce.to_le_bytes()],
        &kswarm_protocol::ID,
    )
    .0
}

pub fn bonsol_marker_pda(
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
        &kswarm_protocol::ID,
    )
}

pub fn result_hash(result_bytes: &[u8]) -> [u8; 32] {
    hash(result_bytes).to_bytes()
}

pub fn aggregate_output_commitments(committed_outputs: &[u8]) -> ([u8; 32], [u8; 32]) {
    let output_digest = hash(committed_outputs).to_bytes();
    let journal_hash = hashv(&[INPUT_DIGEST.as_ref(), committed_outputs]).to_bytes();
    (output_digest, journal_hash)
}

pub fn valid_bonsol_marker_for_job(
    job: &TestJob,
    execution_id: [u8; 32],
) -> (Pubkey, BonsolAggregateVerification) {
    let (marker_key, bump) = bonsol_marker_pda(
        job.job,
        execution_id,
        job.args.required_software_digest,
        job.args.input_bundle_hash,
        job.args.expected_result_hash,
    );
    (
        marker_key,
        BonsolAggregateVerification {
            bump,
            aggregate_job: job.job,
            execution_id,
            image_id: job.args.required_software_digest,
            input_digest: job.args.input_bundle_hash,
            output_digest: result_hash_for_job(job),
            journal_hash: job.args.expected_result_hash,
            callback_unix: 1,
            status: 1,
        },
    )
}

pub fn result_hash_for_job(job: &TestJob) -> [u8; 32] {
    if job.args.job_class == JobClass::AggregateProof as u8 {
        hash(b"aggregate-result").to_bytes()
    } else {
        hash(b"result-ok").to_bytes()
    }
}

pub fn assert_anchor_error(err: BanksClientError, expected: ProtocolError) {
    assert_custom_error_code(err, expected.into());
}

/// Asserts a raw custom error code. Anchor framework errors (for example
/// `ConstraintSeeds` = 2006, `ConstraintHasOne` = 2001) are not `ProtocolError`s.
pub fn assert_custom_error_code(err: BanksClientError, expected_code: u32) {
    match err {
        BanksClientError::TransactionError(TransactionError::InstructionError(
            _,
            InstructionError::Custom(actual),
        )) => assert_eq!(actual, expected_code, "unexpected custom error code"),
        other => panic!("expected custom error {expected_code}, got {other:?}"),
    }
}

pub async fn send_tx(
    ctx: &mut ProgramTestContext,
    instructions: Vec<Instruction>,
    signers: &[&Keypair],
) -> Result<(), BanksClientError> {
    let blockhash = ctx
        .get_new_latest_blockhash()
        .await
        .expect("new latest blockhash");
    let mut all_signers: Vec<&dyn Signer> = Vec::with_capacity(signers.len() + 1);
    all_signers.push(&ctx.payer);
    for signer in signers {
        all_signers.push(*signer);
    }
    let tx = Transaction::new_signed_with_payer(
        &instructions,
        Some(&ctx.payer.pubkey()),
        &all_signers,
        blockhash,
    );
    ctx.banks_client.process_transaction(tx).await
}

pub fn miro_instruction<A, D>(accounts: A, data: D) -> Instruction
where
    A: ToAccountMetas,
    D: InstructionData,
{
    Instruction {
        program_id: kswarm_protocol::ID,
        accounts: accounts.to_account_metas(None),
        data: data.data(),
    }
}

/// Creates a `TOKEN_DECIMALS` mint owned by `token_program` with the payer as mint
/// authority. `with_transfer_fee` adds a Token-2022 `TransferFeeConfig` extension and
/// requires `token_program == spl_token_2022::ID`.
async fn create_mint(
    ctx: &mut ProgramTestContext,
    token_program: Pubkey,
    with_transfer_fee: bool,
) -> Pubkey {
    assert!(
        !with_transfer_fee || token_program == spl_token_2022::ID,
        "transfer fee extension requires Token-2022"
    );
    let mint = Keypair::new();
    let extensions: &[ExtensionType] = if with_transfer_fee {
        &[ExtensionType::TransferFeeConfig]
    } else {
        &[]
    };
    let mint_space = ExtensionType::try_calculate_account_len::<Mint>(extensions).expect("mint space");
    let lamports = Rent::default().minimum_balance(mint_space);
    let payer = ctx.payer.pubkey();
    let mut instructions = vec![system_instruction::create_account(
        &payer,
        &mint.pubkey(),
        lamports,
        mint_space as u64,
        &token_program,
    )];
    if with_transfer_fee {
        instructions.push(
            transfer_fee::instruction::initialize_transfer_fee_config(
                &token_program,
                &mint.pubkey(),
                Some(&payer),
                Some(&payer),
                100,
                UNIT,
            )
            .expect("initialize transfer fee config ix"),
        );
    }
    instructions.push(
        token_instruction::initialize_mint2(&token_program, &mint.pubkey(), &payer, None, TOKEN_DECIMALS)
            .expect("initialize mint ix"),
    );
    send_tx(ctx, instructions, &[&mint])
        .await
        .expect("create token mint");
    mint.pubkey()
}

fn unique_nonce() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT_NONCE: AtomicU64 = AtomicU64::new(1);
    NEXT_NONCE.fetch_add(1, Ordering::Relaxed)
}
