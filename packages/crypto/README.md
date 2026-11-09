# @dip/crypto

Phase 1 cryptographic foundation:

- `canonicalize`: deterministic JSON encoding (spec section 3).
- `sha256Hex`: SHA-256 digests.
- `generateSigningKeyPair`, `signBytes`, `verifyBytes`: Ed25519 signatures.

Only Node's built-in `node:crypto` is used. No third-party crypto code.
