# Security policy

## Status

The kswarm Solana program is **pre-release and has not been audited**. It is not
deployed to mainnet. Do not put real funds behind it.

`docs/protocol-security-remediation-spec.md` records the known open issues in
the program and their intended fixes. It is deliberately public: an integrator
should be able to see what is unfinished without reading the whole program.

## Reporting a vulnerability

Report vulnerabilities through GitHub private vulnerability reporting on this
repository (Security tab -> Report a vulnerability). Do not open a public issue
for a security problem.

Include, as far as you have it:

- the instruction or account context involved, with a line reference into
  `solana/programs/kswarm_protocol/src/lib.rs`;
- the preconditions an attacker needs (role, stake tier, job class, timing);
- what the attacker gains: funds moved, stake released, a state transition that
  should be impossible;
- a failing test against `tests/anchor_integration/`, if you have one. That is
  the fastest possible report.

## What to expect

- Acknowledgement that the report arrived, and whether it is being treated as a
  vulnerability.
- An assessment, and a fix or a written reason for not fixing.
- Credit in the release notes if you want it.

There is no bug bounty.

## Scope

In scope: the program in `solana/programs/kswarm_protocol/`, and its tests.

Out of scope here, but reportable the same way: the worker daemons, the operator
CLI, the Node control plane, and the container images, which live in the
[kswarm](https://github.com/agent-k-ai/kswarm) repository.
