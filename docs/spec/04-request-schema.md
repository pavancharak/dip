# 4. Request Schema

Status: draft, matches `packages/authorization/src/normalize.ts`.

## 4.1 Fields

All fields are required. `amount` and `approvalRef` may be null. Unknown fields MUST be rejected.

| Field                        | Type                        | Rule                                                                   |
| ---------------------------- | --------------------------- | ---------------------------------------------------------------------- |
| `requestId`                  | identifier                  |                                                                        |
| `transactionId`              | identifier                  | Links the request to a business transaction                            |
| `organizationId`, `tenantId` | identifier                  |                                                                        |
| `actor`                      | identifier                  | Must be the authority's principal or agent                             |
| `operation`                  | identifier                  | Must be in the authority's `permittedActions`                          |
| `resource`                   | identifier                  | Must be in `resourceScope`, or the scope is `*`                        |
| `amount`                     | `{minor, currency}` or null | `minor` is an integer ≥ 0; `currency` is ISO 4217                      |
| `parameters`                 | object                      | Values MUST be canonically encodable (section 5). Floats are rejected. |
| `authorityRef`               | `{authorityId, version}`    |                                                                        |
| `policyRef`                  | `{policyId, version}`       |                                                                        |
| `approvalRef`                | identifier or null          | An approval record, if any                                             |
| `idempotencyKey`             | identifier                  | Same key, same content, means the same action                          |
| `protocolVersion`            | `"1.0"`                     |                                                                        |

## 4.2 Digest

`requestDigest = SHA-256("DIP-REQUEST-V1" ‖ 0x00 ‖ canonical(request without approvalRef))`.

`approvalRef` is excluded because an approval must be created for the content before its reference exists. A change to any other field changes the digest and invalidates any approval for it.

## 4.3 Normalization

Normalization MUST reject ambiguous input rather than correct it. Equivalent requests MUST produce identical canonical bodies and digests. Parameter order MUST NOT affect the digest.

## 4.4 Errors

Malformed input raises a typed error with a stable code (`INVALID_FIELD`, `UNKNOWN_FIELD`, `MISSING_FIELD`, `INVALID_PARAMETERS`, `UNSUPPORTED_PROTOCOL_VERSION`). Malformed input never produces a decision.
