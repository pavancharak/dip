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

### Notes

- No approval workflow, execution boundary, evidence, ledger, verifier, SDK, CLI, API or connectors yet.
