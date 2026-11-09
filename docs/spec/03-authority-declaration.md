# 3. Authority Declaration

Status: draft, matches `packages/authority/src/body.ts`.

## 3.1 Purpose

An authority declaration states what a principal, or an agent acting for them, may do, within limits, for a period. It is the only source of authority.

## 3.2 Fields

All fields are required. Unknown fields MUST be rejected.

| Field                        | Type                             | Rule                                                              |
| ---------------------------- | -------------------------------- | ----------------------------------------------------------------- |
| `authorityId`                | identifier                       | 1–128 characters from `A-Za-z0-9._:-`                             |
| `version`                    | integer                          | ≥ 1, contiguous per `authorityId`                                 |
| `organizationId`, `tenantId` | identifier                       |                                                                   |
| `issuer`                     | identifier                       | Descriptive. Not a trust input.                                   |
| `principal`                  | identifier                       |                                                                   |
| `agent`                      | identifier or null               | Agent acting under the principal                                  |
| `permittedActions`           | list of identifiers              | Strictly ascending, no duplicates                                 |
| `resourceScope`              | list of identifiers, or `["*"]`  | `*` MUST be the only entry                                        |
| `maxAmountMinor`             | integer                          | 0 ≤ value ≤ 2^53−1, in minor units                                |
| `currencies`                 | list of ISO 4217 codes           | Strictly ascending                                                |
| `approvalAboveMinor`         | integer or null                  | Amounts strictly above need approval                              |
| `approvalActions`            | list of identifiers              | Operations that always need approval                              |
| `approverKeyIds`             | list of identifiers              | Keys allowed to approve this authority's requests                 |
| `validFrom`, `validUntil`    | UTC time, `YYYY-MM-DDTHH:MM:SSZ` | `validFrom` MUST precede `validUntil`. `validUntil` is exclusive. |
| `delegatedFrom`              | `{authorityId, version}` or null | See 3.5                                                           |
| `delegationAllowed`          | boolean                          | Whether this authority may be a delegation parent                 |
| `policyId`, `policyVersion`  | identifier, integer ≥ 1          | Policy this authority is bound to                                 |
| `protocolVersion`            | `"1.0"`                          |                                                                   |
| `signatureAlgorithm`         | `"Ed25519"`                      |                                                                   |
| `signingKeyId`               | identifier                       | Must name a trust root                                            |

## 3.3 Signature

The declaration is signed as `Ed25519(domain "DIP-AUTHORITY-V1" ‖ canonical(body))`. The signature is a 86-character base64url string without padding (see section 12).

## 3.4 Publication

Versions are published in order. A version MUST NOT be replaced. Publication MUST fail if the signature does not verify under a trust root that is ACTIVE.

## 3.5 Delegation

A declaration with `delegatedFrom` is valid only while its parent is in good standing, and only if it is within the parent's bounds: same organization, tenant and principal; `maxAmountMinor` ≤ parent's; `permittedActions`, `currencies`, `resourceScope` and `approverKeyIds` each a subset of the parent's; validity window inside the parent's. The parent MUST have `delegationAllowed` true. Delegation depth MUST NOT exceed 8.

## 3.6 Revocation

A revocation is a signed record, `Ed25519(domain "DIP-REVOCATION-V1" ‖ canonical({authorityId, version, revokedAt, signingKeyId}))`. A version can be revoked once. Revoking a version does not affect later versions.

## 3.7 Semantics

| State                                       | Authorization result          |
| ------------------------------------------- | ----------------------------- |
| Missing                                     | DENY (`AUTHORITY_NOT_FOUND`)  |
| Invalid signature or unknown key            | DENY                          |
| Revoked version or revoked signing key      | DENY                          |
| Superseded by a later version               | DENY (`AUTHORITY_SUPERSEDED`) |
| Before `validFrom` or at/after `validUntil` | DENY                          |
| Insufficient for the request                | DENY (see section 6)          |
