# Build Status

Last updated: 2026-11-09. Phase 2 is on `main`; Phases 2 and 3 are merged; Phase 10 is on branch `phase10-deploy`.

## Phase report

### Phase 19: Specification (21 sections, drafts)

- `docs/spec/01` to `21` cover the sections the master instruction lists. Thirteen match the implementation, seven are drafts with their gaps stated, and section 20 points to the threat model.
- Canonical encoding moves from section 3 to section 5. Active references were updated.
- Not done: review of the drafts by someone other than the author, and completing the seven drafts.

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

### Phase 8: Connectors (implemented; live integrations not verified)

- `@dip/connectors`: a contract that every connector follows. A connector never decides authorization, and it runs only through `ExecutionBoundary`. Each call carries the idempotency key. Money comes from the authorized request amount, and a conflicting parameter is refused before any network call. A 2xx without an external reference is FAILED. 429 and 5xx are transient failures. Other 4xx are permanent.
- Adapters: payments, refunds, vendor payouts, ERP (allowed document types only), CRM (field values restricted), generic HTTP (HTTPS only, host allowlist, POST/PUT/PATCH only).
- Tests: 155 passed across all packages. The connector tests use fake transports, and verify that a DENY decision never reaches the transport and an ALLOW decision reaches it exactly once.
- Not verified: the adapters' endpoints are placeholders on `*.example.invalid`. No live vendor was called, because no credentials or network access were available. The default transport for production is not built. Each vendor's real request and response formats still need to be checked against its documentation.

### Phase 9: Conformance and security testing (completed for the scope listed; defects fixed)

- Conformance suite: `conformance/` holds JSON fixtures: 6 canonical cases (sorted keys, nested values, string escapes, Unicode, digest with domain separation, float rejection) and 10 bundle cases (valid, tampered, modified request, duplicate entries, altered approval, non-canonical entry, missing request, unknown key). `packages/conformance` runs them against an implementation. The fixtures contain public keys, signed records and expected verdicts only. Regeneration is deterministic and is checked by a test.
- Adversarial suite: 18 tests in `packages/conformance/test/adversarial.test.ts`, plus API tests for cross-tenant reads.
- Defects found by this phase and fixed:
  1. HIGH: an authority revoked after an ALLOW decision still executed. Execution now re-authorizes against current authority state.
  2. HIGH: evidence could be read across tenants through the API. Evidence reads now check the owning tenant, and other tenants get 404.
  3. MEDIUM: Ed25519 signatures had non-canonical base64url encodings that verified (malleability). Verification now rejects them.
  4. MEDIUM: an approval decision was not checked against the approval window. Decisions before the request or after expiry are now refused.
  5. PROCESS: `pnpm test` did not run the API tests, because the Vitest config included only `packages/*`. The config now includes `apps/*`, and four API test contract errors were corrected. Earlier Phase 7 test counts did not include the API suite.
- Residual risks: an in-process caller can still call a connector's `execute` directly, since JavaScript cannot restrict that without a capability design. Tail truncation is undetectable without an external anchor. The API keys are configured in code. No external security review has been done. The conformance fixtures have not been run by an independent implementation.

### Phase 10: Documentation and deployment (partially implemented)

- Runnable examples: `examples/run.mjs` runs four scenarios on a fresh install (authorized payment verified as VALID, refused payment over the limit, tampered evidence detected, revoked authority stopping execution). It passes 4/4 locally.
- Server: `apps/api` starts from a configuration file, loads keys and API keys from files, and fails closed on any invalid setting. `apps/api/dist/keygen.js` generates signing keys. Startup was checked locally: health returns 200, unauthenticated requests get 401, and a missing configuration exits with status 1.
- Container: a multi-stage Dockerfile runs as a non-root user with no secrets in the image. `docker-compose.yml` mounts secrets read-only and drops capabilities. **The image has not been built here**, because no Docker daemon is available in this environment. The CI `docker` job will be the first build.
- CI: jobs for examples, image build, and production dependency audit have been added. They have not yet run on GitHub.
- Documentation: `docs/deployment/README.md` covers installation, keys, configuration, running, independent verification, key rotation, and limits. `ENVIRONMENT.md` lists every variable and field.
- Not done (audit scope, now partly addressed in Phase 12): durable storage, migrations, backups and recovery, a release workflow that publishes anything (packages are private), and operations monitoring.

### Phase 11: NOT STARTED

Approval workflow, execution control, evidence, ledger, independent verifier, SDK, CLI, REST API, connectors, conformance suite, adversarial tests, deployment and release audit are not started.

## Commands and results (local)

- `pnpm check` (build, typecheck, ESLint, Prettier, Vitest): exit 0.
- Tests: 205 passed (all packages, including apps/api).

## Known limitations

- The "invalid authority" test covers publication rejection and unknown-key behaviour, not on-disk corruption, because there is no persistent store yet.
- No public API, SDK or CLI exists yet.
- The engine signing key is passed in; there is no key management.
- No security claim beyond the tested behaviour is made.
