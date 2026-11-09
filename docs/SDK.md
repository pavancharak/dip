# SDK

Package: `@dip/sdk`. The client wraps the protocol packages. It is the recommended entry point for applications.

The complete example is [examples/sdk-quickstart.mjs](../examples/sdk-quickstart.mjs).

## Create a client

```js
import { DipClient } from "@dip/sdk";

const client = new DipClient({
  trustRoots: [
    /* public keys: issuer, engine, evidence, approvers */
  ],
  engine: { keyId: "engine-1", privateKey }, // signs decisions
  evidenceSigner: { keyId: "evidence-1", privateKey }, // signs evidence
  connectors: new Map([["payment.create", connector]]), // operation → connector
  now: () => new Date(), // injected clock
  maxDecisionAgeSeconds: 300, // optional
  executionTimeoutMs: 5000, // optional
  eventLog, // optional: durable journal
});
```

`trustRoots` is the only source of trust. Nothing in a declaration, request or bundle can add a key.

For durable state, use `DipClient.open(config)` with an `eventLog`. It replays the journal and refuses to start if the stored evidence chain does not verify.

## Authority

```js
const declaration = client.createAuthorityDeclaration({
  /* fields: see docs/spec/03 */
});
client.publishAuthority(signAuthority(declaration, issuerPrivateKey));
client.revokeAuthority(
  signRevocation({ authorityId, version, revokedAt, signingKeyId }, issuerPrivateKey),
);
client.getAuthority(authorityId, version);
client.latestAuthorityVersion(authorityId);
```

Publication fails for a bad signature, an unknown or revoked key, a tampered body, or a version that is already published or skips a number.

## Authorize

```js
const request = client.normalizeRequest(rawRequest); // canonical body + digest; rejects ambiguous input
const { result, decision } = client.authorize(request);
// result is exactly "ALLOW" or "DENY". Nothing else is returned.
```

`authorize` never executes anything. Reason codes are in `decision.body.reasonCodes`.

## Approvals

Approvals have their own states (`PENDING`, `APPROVED`, `REJECTED`, `EXPIRED`, `REVOKED`). These are not authorization results.

```js
client.requestApproval({ approvalId, organizationId, requestDigest, authorityRef, policyRef,
  approverKeyId, requestedAt, expiresAt });
client.approve(signApprovalDecision({ approvalId, action: "APPROVE", approverKeyId, decidedAt }, approverPrivateKey));
client.reject(...);          // action REJECT
client.revokeApproval(...);  // action REVOKE
client.approvalStatus(approvalId);
```

After an approval, call `authorize` again. Only the new decision permits execution.

## Execute and record

```js
const attempt = await client.execute(request, decision);
// attempt.state: SUCCEEDED, FAILED, TIMED_OUT, REFUSED or DUPLICATE
client.record({ normalized: request, decision, attempt }); // evidence for every attempt
```

`execute` re-checks the authority and any approval at execution time. A refused attempt is still recorded as evidence.

## Verify

```js
client.verifyLedger(expectedHead); // this client's ledger
client.verifyBundle(bundle); // an exported bundle, against this client's trust roots
```

`expectedHead` is a head recorded outside the system. Without it, a truncated tail cannot be detected.

## Read evidence

```js
client.ledgerSize();
client.ledgerHead();
client.ledgerLines(); // canonical lines, in order
client.findEvidence(evidenceId);
client.evidenceAt(index);
```

## Errors

Errors are `DipError` instances with a stable `code` (see [spec 16](spec/16-error-codes.md)). Match on `code`, not on the message.

```js
import { DipError } from "@dip/sdk";
try {
  client.publishAuthority(input);
} catch (err) {
  if (err instanceof DipError && err.code === "AUTHORITY_SIGNATURE_INVALID") {
    /* … */
  }
}
```

## Stability

The SDK follows the protocol version (`1.0`). Breaking changes require a new protocol version and an entry in [CHANGELOG.md](../CHANGELOG.md).
