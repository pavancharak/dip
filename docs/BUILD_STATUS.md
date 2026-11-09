# Build Status

Last updated: 2026-11-09. Phase 2 is on `main`; Phases 2 and 3 are merged; Phase 7 is on branch `phase7-sdk-api`.

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

### Phase 3: Approval workflow (implemented and tested)

- Approval store with states PENDING, APPROVED, REJECTED, EXPIRED, REVOKED. These are workflow states only; the engine never returns them as outcomes.
- Approvals bind to the request digest, organization, authority version, policy version and one approver key. Decisions are signed by that key.
- Expiry is computed from the clock. Decisions are single-transition and replay-safe. Audit history is kept per approval.
- The engine re-evaluates the request after approval. An approval never grants authority.
- Mandatory tests 11–17 pass. Test results: 79 passed (79).
- Not done: persistence, approver groups, approval requests over an API.

### Phase 4: Execution control (implemented and tested)

- `ExecutionBoundary` is the only path to a connector. It refuses unless the decision is signed by a trusted, non-revoked engine key, its result is ALLOW, and it matches the exact request digest, authority version and policy version.
- Freshness window, approval recheck at execution time, single-use decisions (replay refused), and idempotency per key (completed actions are returned, not repeated; key reuse with different content is a conflict).
- Every attempt is recorded in order, including refusals. Connector failure, exception and timeout are recorded as FAILED or TIMED_OUT, never as success.
- Mandatory tests 18–20 pass. Test results: 98 passed.
- Not done: durable attempt log, real connectors (payments, refunds, ERP, CRM, generic HTTP), evidence records (Phase 5).

### Phase 5: Evidence and ledger (implemented and tested)

- Evidence envelope keeps authorization and execution in separate sections. Execution may appear only with ALLOW, or as a refusal. Invariants are enforced before signing and during verification.
- Ledger is append-only in code: entries are stored as canonical signed lines, hash-chained, with contiguous sequence numbers and unique evidence IDs.
- `verifyChain` takes exported lines and trust roots, and needs nothing from the writing ledger. It detects tampering, deletion, reordering, duplicate IDs, unknown keys, malformed lines, and (given an anchored head) tail truncation.
- Mandatory cryptographic tests from the master list are covered: invalid signatures, wrong keys, unknown keys, modified evidence, broken chain, duplicate sequence, missing records. Not covered: key rotation and revoked-key ledger behaviour beyond the signature check.
- Limitations: storage is in memory. Tail truncation is undetectable without an external head anchor, and the ledger does not provide one. PostgreSQL append-only enforcement is not built.

### Phase 6: Independent verifier (implemented and tested)

- `@dip/verifier` depends only on `@dip/crypto`. It has its own parser, digest re-derivation, approval replay and chain check, and does not import the engine, ledger, execution boundary or registry.
- Trust roots are supplied by the caller. They are never read from the bundle.
- Results: VALID, INVALID (a check failed), UNVERIFIABLE (a signing key is unknown or cannot be verified), INCOMPLETE (a record needed for a check is missing, or no head anchor was given). Precedence: INVALID over UNVERIFIABLE over INCOMPLETE over VALID.
- The CLI `dip-verify --bundle <file> --trust <file>` exits 0 VALID, 1 INVALID, 2 INCOMPLETE or UNVERIFIABLE, 3 usage or input error.
- Limitation: the verifier confirms that the recorded decision is authentic and bound to the request. It does not re-evaluate policy against the authority.

### Phase 7: SDK and REST API (partially implemented)

- `@dip/sdk`: `DipClient` wraps the packages. Authorization returns only ALLOW or DENY. Approval states are returned only by approval methods. Execution records evidence through the ledger. Tests: 7 passed.
- `@dip/api` (apps/api): handler for the listed endpoints, Bearer API keys, scopes (`admin` for ledger, `approver` for approval decisions), tenant checks on request and authority paths, in-memory rate limiting, typed error mapping, and a node:http adapter. Tests cover auth, routing, tenant and scope rules, execute refusal and success, approvals, ledger, verification, rate limit, and a real socket round trip.
- Not done: the CLI (master §11), an OpenAPI document, persistent storage (all state is in memory), API-level idempotency keys, tenant filtering on evidence and ledger reads (evidence carries no tenant field), and production-grade authentication (keys are configured in code).

### Phases 8–11: NOT STARTED

Approval workflow, execution control, evidence, ledger, independent verifier, SDK, CLI, REST API, connectors, conformance suite, adversarial tests, deployment and release audit are not started.

## Commands and results (local)

- `pnpm check` (build, typecheck, ESLint, Prettier, Vitest): exit 0.
- Tests: 142 passed (all packages).

## Known limitations

- The "invalid authority" test covers publication rejection and unknown-key behaviour, not on-disk corruption, because there is no persistent store yet.
- No public API, SDK or CLI exists yet.
- The engine signing key is passed in; there is no key management.
- No security claim beyond the tested behaviour is made.
