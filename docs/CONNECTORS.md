# Connector guide

A connector sends an authorized action to an external system. It is the only part of DIP that talks to the outside world, so it is also where mistakes are costly. Read the [specification section 15](spec/15-connectors.md) first.

## Rules

1. **A connector decides nothing about authority.** It receives a request that has already been authorized and executed through the boundary. It must not read authority, call the engine, or skip the boundary.
2. **Use the authorized amount.** Money comes from `request.amount`. If a parameter repeats the amount, it must match, or the call is refused before any network call.
3. **Send the idempotency key on every call**, using whatever mechanism the external system provides. This is what prevents a retry from doing the action twice.
4. **Report success only with a reference.** A success without an external reference is treated as a failure.
5. **Classify failures.** Transient failures (timeouts, 429, 5xx) should be reported as such. Permanent failures (other 4xx) should not be retried automatically.
6. **Never log secrets.** Credentials come from the operator's configuration, not from the request.

## Shape of a connector

```js
import { createConnector, ConnectorValidationError } from "@dip/connectors";

const definition = {
  id: "payments",
  operation: "payment.create",
  build(request) {
    const amount = request.amount;
    if (amount === null)
      throw new ConnectorValidationError("AMOUNT_REQUIRED", "amount is required");
    return {
      method: "POST",
      url: "https://payments.example.com/v1/transfers",
      headers: {},
      body: { amountMinor: amount.minor, currency: amount.currency, reference: request.requestId },
    };
  },
  reference: (body) => (typeof body?.id === "string" ? body.id : null),
};

const connector = createConnector(definition, { transport, timeoutMs: 5000 });
```

`transport` is an object with a `send` method. It performs the HTTP call. The reference implementation provides a transport seam; production transports must use HTTPS and enforce their own allowlists.

## Testing

- Test `build` with fixed requests. Check the body, the URL and the rejections.
- Test the response mapping with a fake transport: 2xx with and without a reference, 429, 5xx, 4xx.
- Test through `ExecutionBoundary` that a DENY decision never reaches the transport. The reference tests show how.

## Shipped adapters

The repository includes adapters for payments, refunds, vendor payouts, ERP, CRM and generic HTTP. Their endpoints are **placeholders** (`*.example.invalid`). Before using one, set the real endpoint, check the request and response formats against the vendor's documentation, and test against the vendor's sandbox.

## Review checklist

- Does the connector accept only the operations it is built for?
- Is every amount taken from the authorized request?
- Is the idempotency key sent?
- Are timeouts and transient failures handled without a blind retry?
- Is the URL fixed or allowlisted?
- Do logs avoid secrets and personal data?
