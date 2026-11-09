# 16. Error and Reason Code Registry

Status: draft. The list covers the codes in use. Codes are stable: a code MUST NOT change meaning. New codes may be added in a compatible version.

## 16.1 Errors (thrown)

| Code                                                                                                                                                         | Meaning                                               |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------- |
| `INVALID_FIELD`, `UNKNOWN_FIELD`, `MISSING_FIELD`, `NOT_CANONICAL`                                                                                           | Input does not match the schema                       |
| `INVALID_PARAMETERS`                                                                                                                                         | Request parameters are not canonically encodable      |
| `UNSUPPORTED_PROTOCOL_VERSION`, `UNSUPPORTED_ALGORITHM`, `UNSUPPORTED_BUNDLE`                                                                                | Version or format not supported                       |
| `AUTHORITY_SIGNATURE_INVALID`, `AUTHORITY_KEY_UNKNOWN`, `AUTHORITY_KEY_REVOKED`                                                                              | Authority rejected at publication                     |
| `AUTHORITY_ALREADY_PUBLISHED`, `AUTHORITY_VERSION_GAP`, `AUTHORITY_NOT_FOUND`, `AUTHORITY_ALREADY_REVOKED`                                                   | Registry rules                                        |
| `KEY_ALREADY_TRUSTED`, `KEY_UNKNOWN`, `INVALID_TRUST_ROOT`                                                                                                   | Trust root management                                 |
| `APPROVAL_ALREADY_EXISTS`, `APPROVAL_NOT_FOUND`, `APPROVAL_INVALID_TRANSITION`, `APPROVAL_EXPIRED`, `APPROVAL_SIGNATURE_INVALID`, `APPROVAL_ACTION_MISMATCH` | Approval workflow                                     |
| `APPROVER_NOT_AUTHORIZED`, `APPROVER_KEY_UNKNOWN`, `APPROVER_KEY_REVOKED`                                                                                    | Approver checks                                       |
| `EVIDENCE_DUPLICATE`, `EVIDENCE_INVARIANT_VIOLATED`, `EVIDENCE_KEY_UNKNOWN`, `EVIDENCE_KEY_REVOKED`, `EVIDENCE_SIGNATURE_INVALID`                            | Evidence                                              |
| `LEDGER_INVALID_ON_OPEN`                                                                                                                                     | Server refuses to start: stored chain does not verify |
| `UNKNOWN_JOURNAL_RECORD`                                                                                                                                     | Journal contains an unknown record kind               |
| `CONFIG_UNREADABLE`, `INVALID_CONFIG`, `INVALID_KEY`, `WEAK_API_KEY`                                                                                         | Server configuration                                  |
| `OPERATION_MISMATCH`, `AMOUNT_REQUIRED`, `AMOUNT_MISMATCH`, `CONNECTOR_VALIDATION`                                                                           | Connector input                                       |

## 16.2 Authorization reason codes

`REQUEST_DIGEST_MISMATCH`; `AUTHORITY_NOT_FOUND`; `AUTHORITY_SIGNATURE_INVALID`; `AUTHORITY_KEY_UNKNOWN`; `AUTHORITY_KEY_REVOKED`; `AUTHORITY_REVOKED`; `AUTHORITY_SUPERSEDED`; `AUTHORITY_NOT_YET_VALID`; `AUTHORITY_EXPIRED`; `DELEGATION_NOT_PERMITTED`; `DELEGATION_EXCEEDS_PARENT`; `DELEGATION_DEPTH_EXCEEDED`; `ORGANIZATION_MISMATCH`; `TENANT_MISMATCH`; `POLICY_VERSION_MISMATCH`; `ACTOR_NOT_AUTHORIZED`; `ACTION_NOT_PERMITTED`; `RESOURCE_OUT_OF_SCOPE`; `CURRENCY_NOT_PERMITTED`; `AMOUNT_EXCEEDS_LIMIT`; `APPROVAL_REQUIRED`; `APPROVAL_NOT_FOUND`; `APPROVAL_PENDING`; `APPROVAL_REJECTED`; `APPROVAL_EXPIRED`; `APPROVAL_REVOKED`; `APPROVAL_BINDING_MISMATCH`; `APPROVER_NOT_AUTHORIZED`; `APPROVER_KEY_REVOKED`.

## 16.3 Execution reason codes

`REQUEST_MALFORMED`; `DECISION_MALFORMED`; `DECISION_KEY_UNKNOWN`; `DECISION_KEY_REVOKED`; `DECISION_SIGNATURE_INVALID`; `DECISION_NOT_ALLOW`; `DECISION_REF_MISMATCH`; `DECISION_IN_FUTURE`; `DECISION_STALE`; `APPROVAL_RECHECK_UNAVAILABLE`; `DECISION_REPLAYED`; `IDEMPOTENCY_CONFLICT`; `EXECUTION_IN_PROGRESS`; `CONNECTOR_NOT_FOUND`; `CONNECTOR_ERROR`; `EXECUTION_TIMEOUT`; `RESPONSE_MISSING_REFERENCE`; `UPSTREAM_TRANSIENT`; `UPSTREAM_<status>`.

## 16.4 Verification codes

`MALFORMED`, `SCHEMA`, `PROTOCOL_VERSION`, `CANONICAL`, `SEQUENCE_MISMATCH`, `CHAIN_BROKEN`, `DUPLICATE_EVIDENCE_ID`, signature codes, `INVARIANT_*`, `HEAD_MISMATCH`, and the check identifiers in section 14.3.

## 16.5 HTTP status mapping

The API maps codes to statuses: not-found codes to 404; conflicts (already exists, invalid transition, replay) to 409; protocol rejections (signature, binding, state) to 422; other input errors to 400; scope and tenant violations to 403; unauthenticated requests to 401; unexpected failures to 500.
