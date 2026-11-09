# 12. Cryptography

Status: draft, matches `packages/crypto`.

## 12.1 Algorithms

- Digests: SHA-256.
- Signatures: Ed25519 (RFC 8032), via Node's built-in `crypto`.
- Canonical JSON: section 5.

No other algorithm is defined in protocol version 1.0.

## 12.2 Domain separation

Every digest and signature input begins with a domain separator, followed by `0x00`, followed by the canonical body. Separators have the form `DIP-<TYPE>-V<n>`:

| Separator                  | Used for                       |
| -------------------------- | ------------------------------ |
| `DIP-REQUEST-V1`           | Request digest                 |
| `DIP-DECISION-ID-V1`       | Decision identifier            |
| `DIP-DECISION-V1`          | Decision signature             |
| `DIP-AUTHORITY-V1`         | Authority signature            |
| `DIP-REVOCATION-V1`        | Authority revocation signature |
| `DIP-APPROVAL-DECISION-V1` | Approval decision signature    |
| `DIP-EVIDENCE-V1`          | Evidence signature             |
| `DIP-LEDGER-ENTRY-V1`      | Ledger entry digest            |

A signature made under one separator MUST NOT verify under another.

## 12.3 Signature encoding

A signature is 64 bytes, encoded as base64url without padding: exactly 86 characters. Verification MUST reject any other string, including a different string that decodes to the same bytes. The final character of a base64url encoding carries padding bits, so this rule is needed to prevent malleability.

## 12.4 Keys

Keys are Ed25519. Public keys are carried as JWK (`{kty: "OKP", crv: "Ed25519", x}`). A key is identified by a `keyId`. Keys MUST NOT be generated implicitly by a component. Private keys MUST NOT be committed to source control.

## 12.5 Monetary values

Amounts are integers in minor units. Floating-point arithmetic MUST NOT be used for any monetary value.

## 12.6 Rotation and migration

Adding a key is done by adding a trust root. Retiring a key is done by setting it to REVOKED, which invalidates everything it signed. A future algorithm would be introduced under a new protocol version with its own domain separators; no such version exists.

## 12.7 Limits

The reference implementation holds keys in memory or in files. No KMS or HSM is implemented (see G-02 in the implementation matrix).
