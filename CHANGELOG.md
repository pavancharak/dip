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

### Notes

- No approval workflow, execution boundary, evidence, ledger, verifier, SDK, CLI, API or connectors yet.
