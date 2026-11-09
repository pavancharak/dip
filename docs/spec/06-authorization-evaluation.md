# 6. Authorization Evaluation

Status: draft, matches `packages/authorization/src/evaluate.ts`.

## 6.1 Outcomes

The engine MUST return exactly one of `ALLOW` or `DENY`. No other result is permitted, and no other state may be returned under another name.

`ALLOW` means every check passed. `DENY` means at least one check failed. Missing, invalid, expired, revoked, ambiguous or insufficient authority MUST produce `DENY`.

## 6.2 Inputs

A normalized request (section 4), the authority registry, the approval store, a clock, and the engine's signing key. Evaluation is deterministic: the same request, authority state, approval state and time MUST produce the same result and reason codes.

## 6.3 Checks

Checks run in this order. Each failed check adds a reason code, and evaluation continues where it can.

1. `REQUEST_DIGEST`: the digest matches the canonical body.
2. `AUTHORITY_STANDING`: the referenced authority exists, its signature verifies under an ACTIVE trust root, it is not revoked or superseded, the time is inside its window, and any delegation is within bounds. If this fails, no further checks run.
3. `ORGANIZATION`, `TENANT`, `POLICY_VERSION`.
4. `ACTOR`: the actor is the principal or the agent.
5. `ACTION`: the operation is permitted.
6. `RESOURCE`: the resource is in scope.
7. `CURRENCY`, `AMOUNT_LIMIT`: when an amount is present.
8. `APPROVAL`: required when the amount is above `approvalAboveMinor`, or the operation is in `approvalActions`. Satisfied only by an approval that passes section 8.

## 6.4 Reason codes

Reason codes are stable identifiers, listed in section 16. Multiple failures are all reported, in check order.

## 6.5 Decision record

A decision contains: `decisionId` (a digest of request digest, authority, policy, result and evaluation time), `requestDigest`, `authorityRef`, `policyRef`, `result`, `reasonCodes`, `checks` (each with `passed` and a reason code), `evaluatedAt` (whole seconds, UTC), and `protocolVersion`. It is signed as `Ed25519(domain "DIP-DECISION-V1" ‖ canonical(body))`.

## 6.6 Amounts

Amounts are integers in minor units. Comparisons are integer comparisons. No floating-point arithmetic is permitted in any monetary check.

## 6.7 Approval behaviour

An approval MUST NOT grant, expand or override authority. An approval MUST NOT be considered if the authority or the amount check fails. Evaluation after a valid approval is the same evaluation as without one; only the `APPROVAL` check changes.
