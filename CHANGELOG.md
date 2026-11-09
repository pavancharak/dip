# Changelog

## Unreleased

### Added

- `@dip/crypto`: canonical JSON encoder, SHA-256, domain-separated Ed25519 signatures, JWK key import/export.
- `@dip/authority`: authority declaration parser, trust roots, signed authority publication, immutable versioned registry, signed revocation.
- `@dip/authorization`: request normalization with digest, two-outcome evaluation (ALLOW | DENY) with reason codes, delegation checks, signed decisions.
- Spec section 3 (canonical encoding).
- CI workflow definition.

- `@dip/approval`: approval workflow with signed transitions, request binding, expiry, rejection, revocation and audit history.
- Authorization now consults approvals; mandatory approval tests 11–17.

### Changed

- Authority declarations include `approverKeyIds`.
- Request digest excludes `approvalRef`.

- `@dip/execution`: protected execution boundary with decision verification, freshness, approval recheck, single-use decisions, idempotency, connector contract, and an attempt log that includes refusals.

- `@dip/evidence`: evidence envelope with separate authorization and execution sections, enforced invariants, Ed25519 signatures.
- `@dip/ledger`: append-only hash-chained evidence ledger and standalone chain verifier with head anchoring.

- `@dip/verifier`: independent evidence verifier and `dip-verify` CLI. Depends only on `@dip/crypto`. Returns VALID, INVALID, INCOMPLETE or UNVERIFIABLE with per-check detail.

- `@dip/sdk`: developer client with strict ALLOW/DENY authorization, separate approval methods, evidence recording and verification.
- `@dip/api`: versioned REST API (handler and node:http adapter) with API-key auth, scopes, tenant checks, rate limiting and typed errors.

- `@dip/conformance`: language-neutral JSON conformance suite with a reference runner, and adversarial tests.
- `@dip/connectors`: connector contract and adapters for payments, refunds, vendor payouts, ERP, CRM and generic HTTP. Tested with fake transports. Endpoints are placeholders, not live integrations.

### Fixed

- Execution re-checks authority standing, so a revoked or expired authority stops execution even after an ALLOW decision.
- Signature verification rejects non-canonical base64url encodings.
- Approval decisions must fall inside the approval window.
- API evidence reads are restricted to the owning tenant.
- `pnpm test` now runs the `apps/` test suites.

- Runnable examples (`examples/run.mjs`), server entry point with fail-closed configuration, key generator, Dockerfile, Compose file, and deployment documentation.
- CI jobs for examples, Docker image build, and production dependency audit.

- `@dip/storage`: PostgreSQL evidence ledger and authority registry with append-only triggers, serialized appends, and migrations. Tested on PGlite.
- `infrastructure/postgres/README.md`: operations, least privilege, tamper-evidence limits, and recovery.

- Server wired to durable storage: a journal of state changes in PostgreSQL, replayed at startup, with responses returned only after their changes are written.

- OpenAPI description generated from the route table, and a threat model covering 21 threats.
- `dip` command-line tool with all commands in the build instruction, documented exit codes, and JSON output.

### Fixed

- Removed five empty placeholder packages that duplicated the `@dip/api` name.
- Removed a stale matrix row that contradicted the split API rows.

- node-postgres adapter for the storage interface, with a real-server test that runs in CI against PostgreSQL 16.

- `dip backup create|verify|restore`: backups of the stopped file-backed database with a manifest, chain verification and restore.
- Specification documents 1 to 21, drafted to match the implementation. Canonical encoding is renumbered from section 3 to section 5.

### Notes

- No approval workflow, execution boundary, evidence, ledger, verifier, SDK, CLI, API or connectors yet.
