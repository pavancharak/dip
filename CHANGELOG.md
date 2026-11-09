# Changelog

## Unreleased

### Added

- `@dip/crypto`: canonical JSON encoder, SHA-256, domain-separated Ed25519 signatures, JWK key import/export.
- `@dip/authority`: authority declaration parser, trust roots, signed authority publication, immutable versioned registry, signed revocation.
- `@dip/authorization`: request normalization with digest, two-outcome evaluation (ALLOW | DENY) with reason codes, delegation checks, signed decisions.
- Spec section 3 (canonical encoding).
- CI workflow definition.

### Notes

- No approval workflow, execution boundary, evidence, ledger, verifier, SDK, CLI, API or connectors yet.
