# 9. Execution Boundary

Status: draft, matches `packages/execution/src/boundary.ts`.

## 9.1 Rule

A connector MUST be invoked only through the execution boundary, and only for a request with a valid `ALLOW` decision. Connectors MUST NOT make authorization decisions.

## 9.2 Checks, in order

Each refusal records an attempt with state `REFUSED` and a reason code. No connector is called for a refusal.

1. The request parses (`REQUEST_MALFORMED`) and the decision parses (`DECISION_MALFORMED`).
2. The decision's signing key is trusted (`DECISION_KEY_UNKNOWN`, `DECISION_KEY_REVOKED`).
3. The signature verifies (`DECISION_SIGNATURE_INVALID`).
4. The result is `ALLOW` (`DECISION_NOT_ALLOW`).
5. The digest recomputed from the request matches the decision (`REQUEST_DIGEST_MISMATCH`).
6. The authority and policy references match (`DECISION_REF_MISMATCH`).
7. The decision is not in the future (`DECISION_IN_FUTURE`) and not older than `maxDecisionAgeSeconds` (`DECISION_STALE`).
8. The authority is still in good standing at execution time (its reason code).
9. A referenced approval still holds (its reason code).
10. Idempotency: a completed action with the same key and digest returns the original result as `DUPLICATE`. The same key with different content is `IDEMPOTENCY_CONFLICT`. A key with an action in progress is `EXECUTION_IN_PROGRESS`.
11. The decision has not been consumed (`DECISION_REPLAYED`).
12. A connector is registered for the operation (`CONNECTOR_NOT_FOUND`).

## 9.3 Execution

The decision is consumed before the connector runs. The connector is called with the request and the idempotency key. Its outcome is recorded:

- `SUCCEEDED` with an external reference, when the connector reports success with a reference.
- `FAILED` with the connector's reason, when it reports failure.
- `FAILED` with `CONNECTOR_ERROR`, when it throws.
- `TIMED_OUT` with `EXECUTION_TIMEOUT`, when it does not answer within `timeoutMs`. The outcome is unknown and MUST NOT be recorded as success or failure.

## 9.4 Replay and retries

A decision authorizes at most one execution. A retry after failure requires a new decision, which requires a new evaluation at a later time, and reuses the idempotency key.

## 9.5 Records

Every attempt is recorded in order, including refusals. The journal records each attempt, each consumption and each completion.

## 9.6 Limits

JavaScript does not isolate an in-process caller from a connector's `execute` method. This is a deployment and code-review control. See section 19.
