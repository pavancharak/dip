# 10. Evidence Envelope

Status: draft, matches `packages/evidence/src/envelope.ts`.

## 10.1 Purpose

Evidence records what was authorized and, separately, what was executed, in a form a third party can verify.

## 10.2 Fields

| Field                                | Rule                                                                                            |
| ------------------------------------ | ----------------------------------------------------------------------------------------------- |
| `evidenceId`                         | Unique within the ledger. Duplicates MUST be refused.                                           |
| `sequence`                           | Position in the chain, starting at 1.                                                           |
| `previousDigest`                     | Digest of the previous entry, or 64 zeros for the first.                                        |
| `transactionId`                      |                                                                                                 |
| `protocolVersion`                    | `"1.0"`                                                                                         |
| `recordedAt`                         | UTC, whole seconds                                                                              |
| `request`                            | `{requestId, requestDigest, idempotencyKey}`                                                    |
| `authorization`                      | `{decisionId, result, reasonCodes, authorityRef, policyRef, evaluatedAt, decisionSigningKeyId}` |
| `approvalRef`                        | Identifier or null                                                                              |
| `execution`                          | Null, or `{state, connectorId, reasonCode, externalRef, attemptedAt}`                           |
| `signingKeyId`, `signatureAlgorithm` | `Ed25519`                                                                                       |

## 10.3 Invariants

Enforced before signing and again during verification:

- `DENY` MUST carry at least one reason code. `ALLOW` MUST NOT.
- An execution other than `REFUSED` MUST NOT accompany a `DENY`.
- `SUCCEEDED` and `DUPLICATE` MUST carry an external reference. No other state may.

## 10.4 Signature

`Ed25519(domain "DIP-EVIDENCE-V1" ‖ canonical(body))`.

## 10.5 Separation

Authorization and execution are distinct. `ALLOW` does not prove execution succeeded. Evidence MUST NOT claim success unless the connector reported success and the reference was recorded.
