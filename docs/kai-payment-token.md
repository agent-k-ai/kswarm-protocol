# KAI Payment Token

kswarm pays workers and locks stake in one SPL token: **KAI**. There is no protocol-specific token. This page records the mint facts, the base-unit math, the stake floors, and the per-cluster mint policy that the program, the CLI, the Python workers, and the Node stack all follow.

Decision: owner, 2026-09-03, recorded in section 1 of the release readiness review.

## Mint Facts

| Field | Value |
| --- | --- |
| Mint address | `CZHcDHQZerSch8Fhhi2KgV4cLiD2KtdwjJBrb8fypump` |
| Cluster | Solana mainnet-beta |
| Owner program | `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` (classic SPL Token, not Token-2022) |
| Decimals | 6 |
| Supply | 999,973,330.880971 KAI, fixed |
| Mint authority | none (revoked) |
| Freeze authority | none (revoked) |
| Extensions | none |

Verified on-chain 2026-09-03 with `getAccountInfo` and `getTokenSupply` against `api.mainnet-beta.solana.com`.

## Base-Unit Math

The program stores every amount as a `u64` in base units of the payment mint. It never stores decimals in an amount field. It reads the mint's `decimals` once at `initialize_protocol`, caches the value in `ProtocolConfig.payment_decimals`, and passes it to every `transfer_checked` CPI.

- 1 KAI = 10^6 base units = `1_000_000`.
- 0.000001 KAI = 1 base unit. Smaller fractions are truncated by the CLI.
- 50,000 KAI = `50_000_000_000` base units.
- The full KAI supply is about 10^15 base units. `u64` holds up to 1.8 x 10^19, so no protocol amount can overflow.

Human-unit inputs (`--reward 25`, `worker stake 100000`, `1KAI`) are converted with the mint's on-chain decimals. Nothing in the stack assumes 9 decimals any more.

## Stake Floors Are Config Values

The four stake floors are arguments to `initialize_protocol` and live in `ProtocolConfig`. They are not program constants. `derive_stake_tier` and the verifier floor check read them from the config account on every call.

Defaults (owner decision 2026-09-03, "50,000 for now"; the other floors keep the old 1 : 5 : 20 ratio and verifier = 2 x tier one):

| Floor | KAI | Base units |
| --- | ---: | ---: |
| Tier one | 50,000 | 50,000,000,000 |
| Tier two | 250,000 | 250,000,000,000 |
| Tier three | 1,000,000 | 1,000,000,000,000 |
| Verifier | 100,000 | 100,000,000,000 |

Rules enforced by the program at `initialize_protocol`:

- `0 < tier one < tier two < tier three` (error `InvalidStakeFloors`).
- `verifier floor > 0` (error `InvalidVerifierStakeFloor`).

The config PDA is created once with `init`. To run with different floors, initialize a fresh protocol config (a new deployment); no program upgrade is needed.

The CLI ships these defaults for every cluster profile. Override them at initialization:

```bash
kswarm protocol initialize --admin admin --payment-mint <mint> \
  --tier-floors 50000,250000,1000000 --verifier-floor 100000
```

## The Challenge-Window Floor Is A Config Value Too

`ProtocolConfig.min_challenge_window_seconds` is the fifth `initialize_protocol`
argument. It is not a stake floor and not a token amount -- it is seconds -- but it
follows the same rule and sits here because it is set at the same moment, from the same
command, and is likewise not a program constant.

`open_job` refuses any job whose `challenge_window_seconds` is below it (error
`ChallengeWindowBelowFloor`). Before the floor existed, `open_job` validated only
`challenge_window_seconds > 0`, so a customer could open a job with a one-second window.
`challenge_deadline` bounds `submit_verifier_attestation` and `challenge_job` alike, so
such a job cannot be attested or challenged by construction: the customer could disable
the branch layer's economic protection per job, at its sole discretion.

The unit is one attestation rung, `ATTESTATION_WINDOW_SECONDS` = 7200 s: the time an
assigned verifier has to attest before `reassign_verifier` may replace it. That clock
starts when the receipt lands, so a usable window has to hold at least one whole rung,
plus a tail in which the resulting challenge can still land.

| Cluster | Default | Rungs | Why |
| --- | ---: | ---: | --- |
| `local` | 5 s | -- | Not a real bound. The tier-1 suite, `scripts/swarm-smoke.sh` and the demos run whole jobs in seconds; a real floor would make every local run wait hours. |
| `devnet` | 14,400 s | 2 | One full rung for the assigned verifier plus one full window of challenge tail. Verification is genuinely reachable; the whole reassignment ladder is not guaranteed to fit, which is the price of devnet turnaround. |
| `mainnet` | 36,000 s | 5 | `MAX_REASSIGNMENTS + 2`: one rung per verifier the ladder can hold (the initial assignment plus three replacements) and one window of tail. |

The mainnet multiple is the one the design review for requiring a verifier attestation
before branch settlement derives. That review proposes enforcing the multiple inside the
program, against a per-job attestation window; **that gate is not implemented**. The
program compares only against the configured floor, and
`CHALLENGE_WINDOW_LADDER_MULTIPLE` carries the reasoning for whoever chooses the value.

Rules enforced by the program: `min_challenge_window_seconds > 0` at
`initialize_protocol` (error `InvalidChallengeWindowFloor`), and
`challenge_window_seconds >= min_challenge_window_seconds` at `open_job`. A cluster whose
name is none of the three above gets the mainnet value: a floor that is too high fails
loudly at `open_job`, while one that is too low silently reopens the hole.

```bash
kswarm --cluster devnet protocol initialize --payment-mint <mint> --min-challenge-window 14400
```

## Token Program Pinning

`ProtocolConfig.token_program` stores the program that owns the payment mint. Every instruction that carries a `token_program` account checks it against the config (`has_one = token_program`, error `WrongTokenProgram`). `initialize_protocol` checks that the mint account is owned by the passed token program (error `PaymentMintOwnerMismatch`).

The program keeps `anchor_spl::token_interface`, so a Token-2022 mint still works for local tests. If the token program is Token-2022, `initialize_protocol` rejects mints that carry any of these extensions (error `ForbiddenMintExtension`), because they break escrow accounting or custody:

- `TransferFeeConfig`: the vault would receive less than the escrowed amount.
- `TransferHook`: a hook program could veto settlement.
- `PermanentDelegate`: a delegate could drain vaults.
- `NonTransferable`: the mint cannot be escrowed.

KAI is a classic SPL Token mint, so the extension check does not apply on mainnet.

Associated token accounts are derived with the mint's owner program as a seed. An ATA derived with the wrong token program is a different, empty address. The CLI (`spl_token.py`) and the Node stack (`tokenAta(..., tokenProgramId)`) take the token program from the cluster profile or `protocol.json`, which is populated from chain.

## Mint Policy By Cluster

| Cluster | Payment mint | Who creates it | Notes |
| --- | --- | --- | --- |
| `mainnet` | KAI `CZHc...pump` | nobody; it exists | Real funds. `protocol initialize` requires `--i-understand-real-funds`. No `program_id` in the profile until the mainnet program keypair exists (PR-4). An external audit is required before any mainnet deployment. |
| `devnet` | stand-in classic SPL mint, 6 decimals | `kswarm token create-mint --authority <wallet>` | Operator-controlled test mint. |
| `local` | stand-in classic SPL mint, 6 decimals | `token create-mint`, or `PROTOCOL_BOOTSTRAP_LOCAL_MINT=1` for the Node compose stack | Recreated on every validator reset. |

`token create-mint` and `token mint` refuse to run on any cluster other than `local` and `devnet`. `token create-mint --token-2022` creates a Token-2022 mint for tests only.

## Where The Values Live

CLI cluster profile (`~/.config/kswarm/clusters/<name>.json`):

| Key | Meaning |
| --- | --- |
| `rpc_url` | RPC endpoint. For `mainnet`, env `SOLANA_RPC_URL` overrides it (`rpc_url_env`). |
| `program_id` | Protocol program. Absent on `mainnet` until PR-4; commands that need it fail with a clear message. |
| `payment_mint` | Mint address. |
| `payment_decimals` | Mint decimals, read from chain and cached. |
| `token_program` | Mint owner program, read from chain and cached. |

Once the protocol is initialized, the on-chain `ProtocolConfig` is authoritative and the CLI reads mint, token program, and decimals from it.

Node control plane (`docker-compose.protocol.yml`; the `protocol-bootstrap` service runs `docker/swarm/protocol-bootstrap.sh` in the Python `cli` image):

| Variable | Meaning |
| --- | --- |
| `PROTOCOL_PAYMENT_MINT` | Existing mint to bind at bootstrap. |
| `PROTOCOL_BOOTSTRAP_LOCAL_MINT=1` | Deployer creates a disposable local classic SPL mint with 6 decimals and writes `runtime/protocol/payment-mint.json`, which the bootstrap reads when `PROTOCOL_PAYMENT_MINT` is unset. |
| `PROTOCOL_STAKE_FLOORS` | `tier1,tier2,tier3` in human units; default `50000,250000,1000000`. |
| `PROTOCOL_VERIFIER_STAKE_FLOOR` | Human units; default `100000`. |

`runtime/protocol/protocol.json` (written by `kswarm protocol runtime-config`) mirrors the on-chain config: `paymentMint`, `tokenProgramId`, `paymentDecimals`, `stakeFloors.{tierOne,tierTwo,tierThree,verifier}` (base units, as strings). The Python swarm stack (`docker-compose.swarm.yml`) reads the same values from chain and needs no file; `kswarm swarm bootstrap` creates the stand-in mint and initializes with the floors above.

## Where Escrow And Stake Go On Each Terminal Path

Every job locks `reward_amount` in escrow at `open_job` and `required_stake` in the worker's vault at `claim_job`. The table lists, in base units of the payment mint, where those amounts go when the job ends. Nothing else moves.

| Terminal path | Status | Escrow (`reward_amount`) | Worker stake (`required_stake`) |
| --- | --- | --- | --- |
| `settle_job`, `settle_aggregate_proof_job` | `settled` | to the worker | unlocked, stays in the vault |
| `cancel_open_job` | `cancelled` | back to the customer | never locked |
| `slash_stale_job` | `slashed` (all flags set) | back to the customer | all of it to the customer, in the same instruction |
| `challenge_job` then the three claims | `slashed` | back to the customer (`refund_slashed_job_escrow`) | `min(required_stake, challenge_bond)` to the challenging verifier (`claim_verifier_slash_reward`); `required_stake - min(...)` to the customer (`claim_customer_slash_compensation`) |
| `cancel_aggregate_proof_job`, registry exhausted | `cancelled-on-exhaustion` | back to the customer | unlocked, stays in the vault |
| `cancel_aggregate_proof_job`, marker timeout | `cancelled-on-timeout` | back to the customer | unlocked, stays in the vault |

Rules that bound these amounts:

- A stale slash pays once. `slash_stale_job` sets `escrow_refunded`, `verifier_reward_paid`, `customer_slash_paid`, and `slash_settled`, and the claim instructions reject the job with `SlashAlreadySettled`.
- `challenge_bond` is set by the customer at `open_job`. It caps the verifier's reward; it is not a bond that the verifier posts. No verifier stake is locked or forfeited in this release (H2-Interim). Only the assigned verifier may challenge.
- The marker timeout is `AGGREGATE_MARKER_TIMEOUT_SECONDS = 86_400` (24 h), counted from `challenge_deadline`. Cancellation is allowed strictly after that instant while the job is still `completed`.
- Both cancel paths release the worker's claim (`locked_stake`, `active_claims`) without a slash; the worker did submit a receipt.

## Program Config Layout

```text
ProtocolConfig
  bump: u8
  admin: Pubkey
  payment_mint: Pubkey
  token_program: Pubkey
  payment_decimals: u8
  tier_one_stake_floor: u64
  tier_two_stake_floor: u64
  tier_three_stake_floor: u64
  verifier_stake_floor: u64
  min_challenge_window_seconds: u32
```

`InitializeProtocolArgs { tier_one_stake_floor, tier_two_stake_floor, tier_three_stake_floor, verifier_stake_floor, min_challenge_window_seconds }`: four `u64` base units, then a `u32` of seconds.
