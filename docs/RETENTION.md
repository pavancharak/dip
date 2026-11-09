# Retention Policy

Status: **draft for owner and counsel review.** The protocol behaviour described here is implemented. The policy choices, especially the personal-data points in section 4, are decisions the owner must confirm. This document is not legal advice.

## 1. What the protocol keeps

| Record                                 | Where                                                        | Contains personal data?                                                                                                                  |
| -------------------------------------- | ------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------- |
| Evidence entries                       | `evidence_ledger`, and `dip_event_log` (`evidence.appended`) | Identifiers only: request, transaction and approval identifiers, digests, and reason codes. Raw request bodies are not part of evidence. |
| Authority declarations and revocations | `dip_event_log`, `authority_versions`                        | Principal and agent identifiers, organization and tenant identifiers.                                                                    |
| Approval requests and decisions        | `dip_event_log`                                              | Approver key identifiers and approval identifiers.                                                                                       |
| Execution attempts                     | `dip_event_log`                                              | Connector identifiers, outcome states, and external references returned by the connector.                                                |
| Tenant index for evidence              | `dip_event_log` (`evidence.tenant`)                          | Tenant identifiers.                                                                                                                      |

The protocol does not store request parameters in evidence. Connectors may store them in their own systems. Those systems have their own retention.

## 2. Principle: append-only, so no deletion

The evidence chain links each entry to the one before it. Deleting or editing any entry breaks the signature or chain check for every later entry, and the server refuses to start on a broken chain (see `docs/THREAT-MODEL.md`, T11 and T12). Retention therefore cannot be enforced by deleting rows in place.

The protocol supports two retention actions, and no others:

1. **Keep** the full chain. This is the default and is what the system does now.
2. **Archive** a verified segment: export it with `dip backup create` (while the server is stopped) or as a bundle, record its head outside the system, and keep the archive for the period the owner chooses.

## 3. Retention periods (owner to decide)

| Record           | Proposed default                                                   | Reason                                                               |
| ---------------- | ------------------------------------------------------------------ | -------------------------------------------------------------------- |
| Evidence chain   | Indefinite                                                         | Evidence must stay verifiable. Deleting part of it is not an option. |
| Backups          | Owner-defined. Keep at least as long as the evidence they contain. | A backup of a shorter chain would not cover the evidence.            |
| Operational logs | 30 to 90 days                                                      | Not part of the protocol. Contains no evidence.                      |

## 4. Personal data (requires counsel review)

Evidence is intentionally hard to change. That conflicts with rights such as erasure under data-protection law. The protocol does not provide erasure. Instead:

- **Minimize.** Keep identifiers short-lived where possible. Use pseudonymous principal identifiers in authority declarations, rather than names.
- **Separate.** Map pseudonyms to people in a system outside DIP, which can be changed or erased without touching evidence.
- **Assess.** Counsel should decide whether an evidence chain that contains only pseudonymous identifiers is personal data in the relevant jurisdictions, and what that means for erasure requests.

Until counsel has reviewed this, do not record real names or contact details in authority declarations, approvals or tenant identifiers.

## 5. Enforcement

- The server has **no retention configuration** and does not delete anything. The append-only triggers in the database refuse UPDATE, DELETE and TRUNCATE on evidence tables.
- The owner who runs the database can disable those triggers. The chain check then detects any change. A deletion made this way is still detected, but it is not prevented.
- Archives and backups are kept and deleted by the operator. The CLI does not delete them.

## 6. Open decisions

1. Confirm the backup and archive periods in section 3.
2. Counsel to review section 4, including whether pseudonymous identifiers are personal data for the jurisdictions where DIP will run.
3. Decide whether a future version should support archival with a deletion of the live database after anchoring. That would need its own design and review.
