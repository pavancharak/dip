# 8. Approval Workflow

Status: draft, matches `packages/approval/src/store.ts`.

## 8.1 Purpose

Some requests need a human to approve them before they can be authorized. The approval workflow records that decision. It is separate from authorization and grants no authority.

## 8.2 Binding

An approval request binds: `approvalId`, `organizationId`, `requestDigest`, `authorityRef` (`{authorityId, version}`), `policyRef`, `approverKeyId`, `requestedAt` and `expiresAt`. `requestedAt` MUST precede `expiresAt`.

An approval applies only to a request with exactly that digest, authority version and policy version. A change to the request content invalidates it.

## 8.3 States

`PENDING`, `APPROVED`, `REJECTED`, `EXPIRED`, `REVOKED`.

| From                    | Action                   | To                  |
| ----------------------- | ------------------------ | ------------------- |
| `PENDING`               | `APPROVE`                | `APPROVED`          |
| `PENDING`               | `REJECT`                 | `REJECTED`          |
| `PENDING` or `APPROVED` | `REVOKE`                 | `REVOKED`           |
| `PENDING` or `APPROVED` | time reaches `expiresAt` | `EXPIRED` (derived) |

No other transition is permitted. Terminal states do not change.

## 8.4 Decisions

A decision is signed by `approverKeyId` as `Ed25519(domain "DIP-APPROVAL-DECISION-V1" ‖ canonical({approvalId, action, approverKeyId, decidedAt}))`. A decision MUST be signed by the designated approver key. It MUST fall inside the approval window: at or after `requestedAt`, and before `expiresAt`.

## 8.5 Use by authorization

The engine accepts an approval only when it is `APPROVED` at evaluation time, bound to the exact request, authority version and policy version, and its approver key is named by the authority (`approverKeyIds`). Otherwise the `APPROVAL` check fails with a reason code from section 16.

The execution boundary re-checks the approval at execution time. An approval revoked after an ALLOW decision stops execution.

## 8.6 Audit

Each approval keeps an ordered history of transitions, with the time of each.
