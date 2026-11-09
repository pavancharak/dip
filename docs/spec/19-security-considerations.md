# 19. Security Considerations

Status: draft. The detailed threat analysis is in `docs/THREAT-MODEL.md`.

## 19.1 Guarantees the protocol provides

- Authorization is deterministic and has two outcomes.
- A connector runs only for a verified ALLOW decision for the exact request, and at most once per decision.
- Recorded authority, decisions, approvals and evidence are signed. Changes are detected by verification.
- The ledger detects deletion, modification and reordering of entries, given a valid chain and trust roots.
- Tail truncation is detected only when the head is anchored outside the system.

## 19.2 Guarantees the protocol does not provide

- Protection against a compromised trusted key, before it is revoked.
- Protection against an in-process caller bypassing the boundary.
- Verification of what an external system actually did.
- Identity verification of principals.
- Protection of the host, database, or configuration file.

## 19.3 Responsibilities

| Area                       | Responsible party                  |
| -------------------------- | ---------------------------------- |
| Key custody and rotation   | Operator (KMS or HSM is not built) |
| Trust-root file            | Operator                           |
| Database access and backup | Operator                           |
| Principal identity         | Issuer and identity provider       |
| Connector credentials      | Operator                           |
| Clock accuracy             | Operator                           |
| Code review of connectors  | Operator                           |

## 19.4 Known gaps

No external security review has been performed. Storage encryption at rest is not implemented. Rate limiting is per process.
