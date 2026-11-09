# 14. Independent Verification

Status: draft, matches `packages/verifier`.

## 14.1 Purpose

A third party MUST be able to check an exported evidence bundle without trusting the service that produced it, and without access to its database.

## 14.2 Inputs

A bundle containing `entries` (canonical evidence lines, in order), optionally `expectedHead`, `requests`, `decisions`, `authorities` and `approvals`; and the operator's trust roots. The bundle format is `dip-evidence-bundle`, version 1.

## 14.3 Checks

| Check               | Failure means                                                                              |
| ------------------- | ------------------------------------------------------------------------------------------ |
| `CANONICAL`         | An entry is not in canonical form                                                          |
| `SCHEMA`            | An entry does not match the evidence schema                                                |
| `PROTOCOL_VERSION`  | Not `1.0`                                                                                  |
| `SEQUENCE`, `CHAIN` | Position or link is wrong                                                                  |
| `DUPLICATE_ID`      | An evidence identifier repeats                                                             |
| `SIGNATURE`         | Signature does not verify, or the key is revoked                                           |
| `INVARIANT`         | A section 10.3 rule is violated                                                            |
| `REQUEST`           | The request body does not match its digest or the evidence                                 |
| `DECISION`          | The decision is not authentic or does not match the evidence                               |
| `AUTHORITY`         | The authority is not authentic or does not match the policy reference                      |
| `APPROVAL`          | The approval is not bound, not from a named approver, or was not APPROVED at decision time |
| `EXECUTION_ORDER`   | Execution is recorded before the decision                                                  |
| `HEAD`              | The head does not match `expectedHead`                                                     |

## 14.4 Verdicts

| Verdict        | When                                                                                                             |
| -------------- | ---------------------------------------------------------------------------------------------------------------- |
| `INVALID`      | Any check failed                                                                                                 |
| `UNVERIFIABLE` | No failure, but a signing key is not among the trust roots                                                       |
| `INCOMPLETE`   | No failure and nothing unverifiable, but a needed record is absent, the bundle is empty, or no head was supplied |
| `VALID`        | Every check passed                                                                                               |

Precedence: `INVALID` over `UNVERIFIABLE` over `INCOMPLETE` over `VALID`.

## 14.5 Scope

The verifier confirms that the recorded decision is authentic and bound to the request. It does not re-run the policy.

## 14.6 Exit codes

`dip verify` exits 0 for VALID, 1 for INVALID, 2 for INCOMPLETE or UNVERIFIABLE, and 3 for input errors.
