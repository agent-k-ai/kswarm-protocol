# kswarm-protocol

The Solana program behind [kswarm](https://github.com/agent-k-ai/kswarm): escrow,
worker stake, job claim rights, receipts, verifier attestation, settlement,
cancellation, and slashing for a decentralised prediction swarm.

This repository is the audit scope. It imports nothing from the MiroFish
simulation engine and nothing from Bonsol, so it carries a permissive licence
while the swarm repository carries AGPL-3.0.

> **Status: pre-release.** Not deployed to mainnet. **Not audited.** Do not put
> real funds behind this program. See [Security](#security).

## Program

| | |
|---|---|
| Program id | `ERNzRcYhX6UYboXAAP7vwzbCKsULYu21R4RFNvDD8CkM` |
| Framework | Anchor 0.31 |
| Payment and stake mint | KAI, `CZHcDHQZerSch8Fhhi2KgV4cLiD2KtdwjJBrb8fypump` (classic SPL Token, 6 decimals, mint and freeze authority revoked) |
| Deployed clusters | none yet |

The program id is fixed across clusters. The payment mint, the stake floors, and
the token program are configuration written at `initialize_protocol`, not
constants, so a cluster without KAI runs against a stand-in mint of the same
shape. See [docs/kai-payment-token.md](docs/kai-payment-token.md).

## Build

Toolchain: Rust with `cargo-build-sbf`, Solana CLI 2.1.x, Anchor 0.31.0.

```bash
cargo build-sbf --tools-version v1.51 \
  --manifest-path solana/programs/kswarm_protocol/Cargo.toml -- --locked
```

The artifact lands in `solana/target/deploy/kswarm_protocol.so`.

## Verify

Tier 1 runs the integration suite against the built program on an in-process
validator. It is the same command the CI runs on every push.

```bash
cargo test --package anchor_integration --features tier1 -- --test-threads=1
```

Tier 2 exercises the Bonsol callback path and needs a local Bonsol stack, which
lives in the swarm repository:

```bash
cargo test --package anchor_integration --features tier2-bonsol -- --nocapture
```

`Anchor.toml` wires both as `anchor run tier1` and `anchor run tier2`.

## What is in here

| Path | What |
|---|---|
| `solana/programs/kswarm_protocol/` | the program |
| `tests/anchor_integration/` | tier-1 and tier-2 integration tests |
| `docs/architecture-overview.md` | how jobs, escrow, stake, and settlement fit together |
| `docs/kai-payment-token.md` | the payment mint, base-unit maths, stake floors |
| `docs/proof-layer-status.md` | what the proof layer does and does not prove today |
| `docs/protocol-security-remediation-spec.md` | the open security work, written down |
| `scripts/check-no-secrets.sh` | the key-material gate the CI runs first |

There is no IDL in this repository. The clients derive account layouts from
`lib.rs` and assert them in tests, which is checked in CI on the swarm side.

## Security

**This program has not been audited.** An external audit is a prerequisite for
mainnet, alongside a devnet deployment with recorded operation.

`docs/protocol-security-remediation-spec.md` is the current, honest list of what
is fixed and what is not. Read it before integrating.

Report a vulnerability privately: see [SECURITY.md](SECURITY.md).

## Contributing

Development happens on a private tree and is exported here per release, so pull
requests are triaged and re-applied rather than merged directly. Issues and pull
requests are still the right way to raise things. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## Licence

Apache-2.0. See [LICENSE](LICENSE).
