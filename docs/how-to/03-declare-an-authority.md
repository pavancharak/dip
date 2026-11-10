# 3. Declare an authority

An authority is the rule book for one agent. It is written by an issuer, signed with the issuer's private key, and published to the engine. Once published, a version never changes.

## The fields

| Field                                                   | Meaning                                                                                    | Example                               |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------------ | ------------------------------------- |
| `authorityId`                                           | Stable name for this authority                                                             | `auth-vendor-payments`                |
| `version`                                               | Starts at 1. Each change is a new version                                                  | `1`                                   |
| `organizationId`, `tenantId`                            | Who the authority belongs to. Requests must match both                                     | `org-acme`, `tenant-1`                |
| `issuer`, `principal`, `agent`                          | Who granted it, on whose behalf, and which agent may use it                                | `cfo-office`, `cfo`, `payments-agent` |
| `permittedActions`                                      | The only operations allowed                                                                | `["payment.create"]`                  |
| `resourceScope`                                         | The only resources allowed                                                                 | `["vendor-42"]`                       |
| `maxAmountMinor`                                        | Upper limit, in minor units (integer)                                                      | `5000000` (50,000.00 INR)             |
| `currencies`                                            | Allowed currencies                                                                         | `["INR"]`                             |
| `approvalAboveMinor`                                    | Amounts above this need approval. `null` means none                                        | `null`                                |
| `approvalActions`                                       | Operations that always need approval                                                       | `[]`                                  |
| `approverKeyIds`                                        | Keys allowed to approve requests under this authority                                      | `[]`                                  |
| `validFrom`, `validUntil`                               | When the authority is in force, in UTC                                                     | `2026-01-01T00:00:00Z`                |
| `delegatedFrom`, `delegationAllowed`                    | Whether this authority was delegated from another, and whether it may be delegated further | `null`, `false`                       |
| `policyId`, `policyVersion`                             | The policy this authority follows                                                          | `policy-payments`, `1`                |
| `protocolVersion`, `signatureAlgorithm`, `signingKeyId` | Fixed for now: `"1.0"`, `"Ed25519"`, and the issuer's key ID                               | `1.0`, `Ed25519`, `issuer-key-1`      |

## Write the declaration

Save this as `declaration.json`, changing the values for your case:

```json
{
  "authorityId": "auth-vendor-payments",
  "version": 1,
  "organizationId": "org-acme",
  "tenantId": "tenant-1",
  "issuer": "cfo-office",
  "principal": "cfo",
  "agent": "payments-agent",
  "permittedActions": ["payment.create"],
  "resourceScope": ["vendor-42"],
  "maxAmountMinor": 5000000,
  "currencies": ["INR"],
  "approvalAboveMinor": null,
  "approvalActions": [],
  "approverKeyIds": [],
  "validFrom": "2026-01-01T00:00:00Z",
  "validUntil": "2027-01-01T00:00:00Z",
  "delegatedFrom": null,
  "delegationAllowed": false,
  "policyId": "policy-payments",
  "policyVersion": 1,
  "protocolVersion": "1.0",
  "signatureAlgorithm": "Ed25519",
  "signingKeyId": "issuer-key-1"
}
```

## Sign it

The issuer signs with its Ed25519 private key. With the CLI:

```bash
dip authority sign declaration.json --key issuer.pem > authority.json
```

The signature covers the canonical form of every field. Changing any field after signing makes the signature invalid, and the engine refuses it.

## Publish it

With the API (any valid API key for your tenant; see `07-use-the-api.md`):

```bash
curl -sS -X POST "$DIP_URL/v1/authorities" \
  -H "Authorization: Bearer $DIP_API_KEY" \
  -H "Content-Type: application/json" \
  --data @authority.json
```

With the SDK, call `client.publishAuthority(signedAuthority)`. See `examples/sdk-quickstart.mjs` for a complete call.

## Rules to remember

- **Versions are immutable.** To change a limit, publish version 2. Version 1 stays on record.
- **Versions must be contiguous.** Publish 1, then 2, then 3. Skipping a number is refused.
- **Revoke, do not edit.** To withdraw an authority, publish a signed revocation (`dip authority revoke`). Requests after that are DENY.
- **Keep the issuer key safe.** Anyone with it can grant authority.
