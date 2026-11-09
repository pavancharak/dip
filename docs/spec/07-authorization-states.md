# 7. Authorization State Model

Status: draft.

## 7.1 Authorization outcomes

| Value   | Meaning                                                                                     |
| ------- | ------------------------------------------------------------------------------------------- |
| `ALLOW` | All checks passed for this request, at this time, with these authority and approval states. |
| `DENY`  | At least one check failed.                                                                  |

These are the only authorization outcomes. A request that needs an approval which is absent, pending, rejected, expired or revoked is `DENY`.

## 7.2 Authority states

| State      | Transitions                                                                |
| ---------- | -------------------------------------------------------------------------- |
| Published  | Revoked (by signed revocation). Superseded (by a later published version). |
| Revoked    | Terminal for that version.                                                 |
| Superseded | Terminal for that version. The version is retained.                        |

Time-based states (not yet valid, expired) are derived from the clock; they are not stored.

## 7.3 Execution attempt states

`REFUSED`, `STARTED`, `SUCCEEDED`, `FAILED`, `TIMED_OUT`, `DUPLICATE`. See section 9 for transitions.

## 7.4 Approval states

Approval workflow states are listed in section 8. They are workflow states and MUST NOT be returned as authorization outcomes.

## 7.5 Invariants

- A decision that is `DENY` MUST NOT lead to a `SUCCEEDED`, `FAILED`, `TIMED_OUT` or `STARTED` attempt.
- An `ALLOW` decision MUST NOT carry reason codes.
- A `DENY` decision MUST carry at least one reason code.
