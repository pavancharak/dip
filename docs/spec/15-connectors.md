# 15. Connectors

Status: draft, matches `packages/connectors/src/contract.ts`.

## 15.1 Contract

A connector implements `execute(request, idempotencyKey)` and returns `SUCCEEDED` with an external reference, or `FAILED` with a reason. A connector MUST NOT make an authorization decision and MUST NOT be invoked outside the execution boundary (section 9).

## 15.2 Requirements

- Every outbound call MUST carry the idempotency key.
- Money MUST come from the authorized request amount. A parameter that repeats the amount MUST agree with it, or the call is refused before any network call.
- A 2xx response without an external reference is a failure (`RESPONSE_MISSING_REFERENCE`).
- A 429 or 5xx response is a transient failure (`UPSTREAM_TRANSIENT`).
- Any other 4xx response is a permanent failure (`UPSTREAM_<status>`).
- A connector MUST refuse an operation it was not built for (`OPERATION_MISMATCH`).

## 15.3 Adapters

Reference adapters exist for payments, refunds, vendor payouts, ERP (fixed document types), CRM (restricted field values) and generic HTTP (HTTPS only, allowlisted hosts, POST, PUT and PATCH).

## 15.4 Status

Adapter endpoints are placeholders. No live integration has been verified. See the implementation matrix, row K-02 and G-09.
