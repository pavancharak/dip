# Integration guide

This guide describes how an application uses DIP for a consequential action, such as a vendor payment. The protocol's rules are in the [specification](spec/README.md). This guide covers the flow.

## The flow

1. **Declare authority.** An issuer (for example, the finance office) writes a declaration: who may act, which operations, what limits, for how long. It signs the declaration with its key and publishes it.
2. **Propose.** The application (or an AI system) proposes an action as a request. Nothing executes yet.
3. **Normalize.** The request is canonicalized and digested. Ambiguous input is rejected.
4. **Authorize.** DIP returns `ALLOW` or `DENY`, with reason codes.
5. **Approve if needed.** If the decision needs a person, the approval is requested and decided by its designated approver. Then the request is authorized again.
6. **Execute.** Only an ALLOW decision for the exact request can execute. The application calls the connector through the boundary.
7. **Record.** Every attempt is recorded as signed evidence.
8. **Verify.** Anyone holding the bundle and the public trust roots can check the evidence.

## Rules to follow in the application

- **Use `ALLOW` as the only gate.** Do not treat an approval as permission. Do not treat `DENY` as a retry hint.
- **Send the same request you authorized.** If anything changes, normalize and authorize again. A changed request has a different digest and cannot reuse a decision.
- **Keep the idempotency key stable** for one business action. A retry with the same key returns the original result.
- **Store decisions and evidence references** in your own system. They are what you show an auditor.
- **Do not put personal data in identifiers** that become part of the evidence. See [docs/RETENTION.md](RETENTION.md).
- **Treat `TIMED_OUT` as unknown.** Reconcile with the external system before retrying.

## Example request

```json
{
  "requestId": "req-2041",
  "transactionId": "txn-881",
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
  "idempotencyKey": "pay-881-attempt-1",
  "protocolVersion": "1.0"
}
```

Amounts are integers in minor units (paise for INR). Floating-point amounts are rejected.

## Over HTTP

The server exposes the flow as a REST API. The full list is in [api/openapi.json](api/openapi.json). Authentication is a bearer API key. Scopes: `admin` for ledger reads and `approver` for approval decisions.

| Step              | Endpoint                                                |
| ----------------- | ------------------------------------------------------- |
| Publish authority | `POST /v1/authorities`                                  |
| Normalize         | `POST /v1/requests/normalize`                           |
| Authorize         | `POST /v1/authorize`                                    |
| Request approval  | `POST /v1/approvals`                                    |
| Decide approval   | `POST /v1/approvals/{id}/approve`, `/reject`, `/revoke` |
| Execute           | `POST /v1/execute` (body: `{request, decision}`)        |
| Read evidence     | `GET /v1/evidence/{id}`                                 |
| Verify a bundle   | `POST /v1/verify`                                       |

Responses to protocol rejections use status 422, conflicts 409, and input errors 400. Each error body has a stable `error` code.

## Connectors

Write a connector for each external system, following the [connector guide](CONNECTORS.md). A connector receives only requests that already passed authorization.

## Verify later

Export the evidence and verify it independently. See [VERIFICATION.md](VERIFICATION.md).
