# Contributing to kswarm-protocol

## How this repository works

Development happens on a private tree. Each release is exported here as one
commit by the tooling described in `PROVENANCE.md`, so this repository has no
day-to-day history and pull requests cannot be merged into it directly.

That does not make contributions unwelcome. A pull request here is read, and an
accepted change is applied to the source tree and appears in the next export
with attribution. An issue with a failing test is often faster than a patch.

## Before you open something

Run the two commands the CI runs:

```bash
cargo build-sbf --tools-version v1.51 \
  --manifest-path solana/programs/kswarm_protocol/Cargo.toml -- --locked
cargo test --package anchor_integration --features tier1 -- --test-threads=1
```

Toolchain: Rust with `cargo-build-sbf`, Solana CLI 2.1.x, Anchor 0.31.0.

## What makes a change easy to accept

- **A test that fails before and passes after.** `tests/anchor_integration/` is
  organised by theme (`tier1_authz_adversarial`, `tier1_slash_accounting`,
  `tier1_lifecycle_gaps`, ...). Put the test where it belongs.
- **An adversarial test, if the change is about authority.** State the attack
  the test forbids in its name.
- **Arithmetic that cannot silently wrap.** The program uses checked arithmetic
  throughout; keep it that way.
- **No new constants for cluster-dependent values.** Mints, floors, and program
  ids are configuration written at `initialize_protocol`.
- **A commit message that says what changed and why**, in plain sentences.

## Security

Do not report a vulnerability in a pull request or a public issue. See
[SECURITY.md](SECURITY.md).

## Licence

Contributions to this repository are accepted under Apache-2.0, the licence of
this repository.
