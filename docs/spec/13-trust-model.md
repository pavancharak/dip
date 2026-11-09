# 13. Trust Model

Status: draft.

## 13.1 Trust roots

A trust root is a public key with an identifier and a status, `ACTIVE` or `REVOKED`. Trust roots are supplied by the operator. A verifier or server MUST NOT take trust roots from the data it is checking.

## 13.2 What is trusted

| Object                 | Trusted because                                  |
| ---------------------- | ------------------------------------------------ |
| Authority declarations | Signed by an ACTIVE issuer key                   |
| Authority revocations  | Signed by an ACTIVE key                          |
| Approval decisions     | Signed by the approver key named in the approval |
| Decisions              | Signed by an ACTIVE engine key                   |
| Evidence entries       | Signed by an ACTIVE evidence key                 |

## 13.3 Revocation of keys

Revoking a key makes every object it signed fail verification. This is intentional: a revoked key MUST NOT be trusted for anything, including earlier records.

## 13.4 Rotation

Add the new key as ACTIVE before using it. Keep the old key ACTIVE for as long as records it signed must still be verified. Duplicate key identifiers MUST be refused.

## 13.5 What the protocol does not establish

The protocol proves that a record was signed by a key the operator trusted. It does not establish that the key holder is who they claim to be, that the policy is wise, or that a connector's report is accurate. These are operational and identity responsibilities.
