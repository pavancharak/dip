# 4. Authorize and execute

## 1. Write the request

```json
{
  "requestId": "req-1",
  "transactionId": "txn-1",
  "organizationId": "org-acme",
  "tenantId": "tenant-1",
  "actor": "payments-agent",
  "operation": "payment.create",
  "resource": "vendor-42",
  "amount": { "minor": 400000, "currency": "INR" },
  "parameters": { "payeeAccount": "acc-9" },
  "authorityRef": { "authorityId": "auth-vendor-payments", "version": 1 },
  "policyRef": { "policyId": "policy-payments", "version": 1 },
  "approvalRef": null,
  "idempotencyKey": "idem-1",
  "protocolVersion": "1.0"
}
```

Field notes:

- `requestId` identifies this request. Use a new one each time you ask.
- `idempotencyKey` identifies the action. Re-sending the same key with the same content returns the original result, and does not run the action again. Re-sending the same key with different content is a conflict.
- `approvalRef` is `null` unless an approval exists for this exact request. See [05](05-approvals.md).
- `amount.minor` is an integer. `400000` means 4,000.00 INR.

## 2. Check the request shape (optional)

```bash
dip request normalize request.json
```

This prints the canonical form and its digest without contacting the server. Use it to catch typos before sending.

## 3. Authorize

```bash
curl -sS -X POST "$DIP_URL/v1/authorize" \
  -H "Authorization: Bearer $DIP_API_KEY" \
  -H "Content-Type: application/json" \
  --data @request.json
```

The response contains `result` (ALLOW or DENY), `decisionId`, `reasonCodes` and the signed `decision`. The reason codes say why, for example `AMOUNT_EXCEEDS_LIMIT`, `ACTION_NOT_PERMITTED` or `AUTHORITY_REVOKED`.

**Keep the whole `decision` object.** The execution step needs it, unchanged.

## 4. Execute

Only a valid ALLOW decision can run an action. Send the request and the decision together:

```bash
curl -sS -X POST "$DIP_URL/v1/execute" \
  -H "Authorization: Bearer $DIP_API_KEY" \
  -H "Content-Type: application/json" \
  --data '{"request": <request.json>, "decision": <decision from step 3>}'
```

The boundary re-checks everything before it runs: the decision's signature, that it is ALLOW, that it matches this request, that it is fresh, and that the authority and any approval still hold. Then it runs the connector once.

## Attempt states

| State       | Meaning                                                     | Is the action done?                                             |
| ----------- | ----------------------------------------------------------- | --------------------------------------------------------------- |
| `SUCCEEDED` | The connector confirmed the action and returned a reference | Yes                                                             |
| `FAILED`    | The connector reported a failure                            | No                                                              |
| `TIMED_OUT` | No answer in time                                           | **Unknown.** Reconcile with the external system before retrying |
| `REFUSED`   | A check failed before anything ran                          | No                                                              |
| `DUPLICATE` | This idempotency key already completed                      | Yes, earlier                                                    |

## Retrying

- After `FAILED` or `REFUSED`, request a **new decision** (new `requestId`), then execute again with the same `idempotencyKey`. The external system can then deduplicate.
- After `TIMED_OUT`, do not retry blindly. Check the external system first. A timeout is neither a success nor a failure.
- Decisions are single-use. A second execution with the same decision is refused.

## Freshness

A decision is valid for a limited time, set by the server (`maxDecisionAgeSeconds`, default 300 seconds). If you wait too long between authorize and execute, the decision is refused as stale. Request a new one.
