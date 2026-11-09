# Release Audit

Scope: the state of `main` after Phase 10, audited by re-running the checks and reading the code. The audit compares the master build instruction's Definition of Done (section 21) with the repository.

## Verdict

**Not ready for production or external release.** Suitable for internal review as a reference implementation.

Blocking gaps: no durable storage, no CLI, no OpenAPI description, the specification is incomplete, no threat model document, no independent conformance run, no external security review, and the patent-risk review is open.

## Checks run for this audit

| Check                                                                              | Result                                                                                                    |
| ---------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| Authorization outcome values (no third outcome in engine, SDK or API)              | None found                                                                                                |
| Nondeterministic calls in protocol logic (`Date.now`, `Math.random`, `new Date()`) | None found                                                                                                |
| Floating-point arithmetic in money paths                                           | None found (one millisecond conversion for decision age)                                                  |
| Parmana forbidden claim phrases in DIP files                                       | None found                                                                                                |
| Private key files or PEM private-key markers in tracked files                      | None found                                                                                                |
| Matrix citations pointing at paths that do not exist                               | None found                                                                                                |
| Examples on a fresh build                                                          | 4/4 pass                                                                                                  |
| Full gate (`pnpm check`)                                                           | Passes                                                                                                    |
| Verifier source imports                                                            | `@dip/crypto` and Node built-ins only                                                                     |
| Duplicate package names in the workspace                                           | **Found**: `@dip/api` used by an empty placeholder and by `apps/api`. Fixed by removing the placeholders. |
| Stale matrix row for S-01 contradicting its split rows                             | **Found and fixed**                                                                                       |

## Definition of Done (master §21)

| #   | Requirement                                            | Status                          | Evidence or gap                                                                                                              |
| --- | ------------------------------------------------------ | ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| 1   | Protocol formally specified                            | **Not met**                     | Only spec section 3 exists. Sections 1–2 and 4–21 are missing.                                                               |
| 2   | Authority declarations implemented                     | Met                             | `packages/authority`                                                                                                         |
| 3   | Authority declarations cryptographically authenticated | Met                             | Ed25519 with domain separation; tests                                                                                        |
| 4   | Requests normalized deterministically                  | Met                             | `packages/authorization/src/normalize.ts`; tests                                                                             |
| 5   | Authorization has exactly two outcomes                 | Met                             | Engine type and tests; checked by grep above                                                                                 |
| 6   | Approval is a separate workflow                        | Met                             | `packages/approval`; tests                                                                                                   |
| 7   | Approval cannot grant or expand authority              | Met                             | Mandatory test 16; adversarial tests                                                                                         |
| 8   | Approved requests undergo re-evaluation                | Met                             | Engine re-evaluates; tests 17                                                                                                |
| 9   | Execution requires a valid ALLOW                       | Met                             | `packages/execution`; tests 18                                                                                               |
| 10  | Execution bound to the exact request                   | Met                             | Digest and reference checks; tests 19                                                                                        |
| 11  | Replay and duplicate execution controlled              | Met, in memory only             | Replay refused; idempotency; tests 20                                                                                        |
| 12  | Evidence generated                                     | Met                             | `packages/evidence`; tests                                                                                                   |
| 13  | Evidence cryptographically signed                      | Met                             | Ed25519; tests                                                                                                               |
| 14  | Evidence tamper-evident                                | Met, in memory only             | Chain and signature checks; tests                                                                                            |
| 15  | Ledger independently checkable                         | Met                             | `verifyChain`; tests                                                                                                         |
| 16  | Verifier works independently                           | Met                             | Depends only on `@dip/crypto`                                                                                                |
| 17  | SDK works                                              | Met                             | `packages/sdk`; 7 tests                                                                                                      |
| 18  | CLI works                                              | **Not met**                     | Only `dip-verify` exists. The `dip` command set is missing.                                                                  |
| 19  | REST API works                                         | Partly met                      | Endpoints tested. No OpenAPI. No persistence.                                                                                |
| 20  | Connectors work                                        | Partly met                      | Tested with fake transports only. No live system verified.                                                                   |
| 21  | Conformance tests pass                                 | Met for self-generated fixtures | Not run by an independent implementation                                                                                     |
| 22  | Adversarial tests pass                                 | Met for the listed cases        | Not an external review                                                                                                       |
| 23  | Documentation matches implementation                   | Partly met                      | Matrix stale row fixed. Several required guides are missing.                                                                 |
| 24  | Clean installation reproduces examples                 | Met                             | `examples/run.mjs` passes; CI `examples` job is green                                                                        |
| 25  | CI validates the complete system                       | Partly met                      | Lint, format, typecheck, build, tests, examples, image build and audit run. No live-integration or external conformance job. |
| 26  | Known limitations and residual risks documented        | Met                             | `docs/BUILD_STATUS.md` and deployment docs                                                                                   |

Met: 16 of 26. Partly met: 5. Not met: 2 (items 1 and 18). Item 21 is met only for the fixtures this project generated.

## Blocking gaps before any release

1. Durable storage with append-only enforcement, migrations, backups and recovery (R-06).
2. The `dip` CLI and an OpenAPI description (R-03, R-04).
3. Specification sections 1–2 and 4–21, and the threat model (R-01, R-02).
4. A pluggable key-management interface with a KMS adapter (R-05).
5. An independent implementation running the conformance fixtures (R-08).
6. An external security review (R-09).
7. The patent-risk review of the approval and evidence designs (R-10).
8. Live integration verification for at least one connector, using sandbox credentials (K-02).

## Residual risks (protocol-level)

- A caller in the same process can call a connector's `execute` directly. JavaScript offers no isolation for this.
- Tail truncation of the ledger cannot be detected without an external anchor.
- Approval and authority are keyed by identifiers chosen by their issuers. Nothing prevents an issuer from publishing a misleading declaration, which is a policy matter, not a protocol defect.
- The verifier checks that recorded decisions are authentic and bound. It does not re-evaluate policy.
- The request digest excludes `approvalRef` by design (ADR-0015). An approval for identical content can therefore be referenced by a different request that has the same content.

## What this audit did not do

It did not perform an external review, a penetration test, a formal proof, or a cryptographic review by a specialist. The checks above were run by the same process that built the code, so they are not independent.
