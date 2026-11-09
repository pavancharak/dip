# Build Status

Last updated: 2026-11-09. Branch: `claude/loving-babbage-m3gl20`. `main` mirrors this branch.

## Phase report

### Phase 0: Repository audit

- Repository: `pavancharak/dip` (created by owner, empty at start).
- Parmana reference reviewed: DECISIONS.md and 04-INCIDENTS-LOG.md (see `docs/PARMANA-LEARNINGS.md`).
- Parmana's `package.json`/`Dockerfile` were read for build conventions (npm workspaces, TypeScript 7 build, pinned Docker digests). DIP does not copy them.
- Gap: DIP has no database, API, SDK, CLI, connectors, deployment or CI run on GitHub yet.

### Phase 1: Protocol foundation (partial)

Implemented and tested:

- Canonical JSON encoder (integer-only numbers, sorted keys, no whitespace). Not yet validated against RFC 8785 official vectors.
- SHA-256 hashing; domain-separated digests and Ed25519 signatures (`DIP-*-V1` separators).
- Ed25519 JWK import/export for trust roots.
- Spec section 3 (canonical encoding) drafted.

Not done: schemas as machine-readable JSON Schema files; specs 1, 2, 4–21; cross-language test vectors; versioning policy document.

### Phase 2: Authority and authorization (implemented, not complete)

Implemented and tested:

- Authority declaration: strict parser, integer money in minor units, validity window, delegation reference, signed with Ed25519.
- Trust roots with key revocation.
- Append-only authority registry: contiguous versions, immutable publication, signed revocation.
- Request normalization with rejection of ambiguous input, and digest over the canonical body.
- Two-outcome authorization engine (`ALLOW` | `DENY`) with stable reason codes, a fixed check order, an injected clock, and signed decisions.
- Delegation with parent-bound checks, depth limit 8.

Not done: a persistent store (registry is in memory); approval-required paths beyond "approval reference not verified"; decision verification at the execution boundary.

### Phases 3–11: NOT STARTED

Approval workflow, execution control, evidence, ledger, independent verifier, SDK, CLI, REST API, connectors, conformance suite, adversarial tests, deployment and release audit are not started.

## Commands and results (local)

- `pnpm check` (build, typecheck, ESLint, Prettier, Vitest): exit 0.
- Tests: 59 passed in 4 files (crypto 9, authority 14, authorization 36 across the suites).

## Known limitations

- The "invalid authority" test covers publication rejection and unknown-key behaviour, not on-disk corruption, because there is no persistent store yet.
- No public API, SDK or CLI exists yet.
- The engine signing key is passed in; there is no key management.
- No security claim beyond the tested behaviour is made.
