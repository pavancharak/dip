# DIP Protocol Specification

Status: draft. Normative keywords follow RFC 2119.

The numbering follows the master build instruction, section 7. Each document states whether it describes the implementation or is still a draft.

| #   | Document                                                     | Status                                             |
| --- | ------------------------------------------------------------ | -------------------------------------------------- |
| 1   | [Overview](01-overview.md)                                   | Draft                                              |
| 2   | [Architecture](02-architecture.md)                           | Matches implementation                             |
| 3   | [Authority declaration](03-authority-declaration.md)         | Matches implementation                             |
| 4   | [Request schema](04-request-schema.md)                       | Matches implementation                             |
| 5   | [Canonicalization](05-canonicalization.md)                   | Matches implementation                             |
| 6   | [Authorization evaluation](06-authorization-evaluation.md)   | Matches implementation                             |
| 7   | [Authorization state model](07-authorization-states.md)      | Draft                                              |
| 8   | [Approval workflow](08-approval-workflow.md)                 | Matches implementation                             |
| 9   | [Execution boundary](09-execution-boundary.md)               | Matches implementation                             |
| 10  | [Evidence envelope](10-evidence-envelope.md)                 | Matches implementation                             |
| 11  | [Ledger](11-ledger.md)                                       | Matches implementation                             |
| 12  | [Cryptography](12-cryptography.md)                           | Matches implementation                             |
| 13  | [Trust model](13-trust-model.md)                             | Draft                                              |
| 14  | [Independent verification](14-independent-verification.md)   | Matches implementation                             |
| 15  | [Connectors](15-connectors.md)                               | Matches implementation; endpoints are placeholders |
| 16  | [Error and reason codes](16-error-codes.md)                  | Matches implementation                             |
| 17  | [Protocol versioning](17-versioning.md)                      | Draft                                              |
| 18  | [Compatibility and migration](18-compatibility-migration.md) | Draft                                              |
| 19  | [Security considerations](19-security-considerations.md)     | Draft                                              |
| 20  | [Threat model](20-threat-model.md)                           | Points to `docs/THREAT-MODEL.md`                   |
| 21  | [Conformance](21-conformance.md)                             | Draft; no independent implementation yet           |

## Renumbering

Canonical encoding was section 3 in an earlier draft. It is now section 5, to match the master instruction. Code comments and the implementation matrix were updated. Historical entries in `CHANGELOG.md` and `docs/BUILD_STATUS.md` keep the old number.
