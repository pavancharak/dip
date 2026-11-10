# 6. Evidence and verification

Every decision, refusal and execution is recorded as evidence. Records form a hash chain: each one includes the digest of the one before it. Changing, deleting or reordering any record breaks the chain, and that is detectable.

## Read a record

```bash
curl -sS "$DIP_URL/v1/evidence/<evidence-id>" -H "Authorization: Bearer $DIP_API_KEY"
```

A record shows the request digest, the decision and its reason codes, the approval reference if any, the execution state, and the signature.

Records are private to the tenant that made them. A key from another tenant gets "not found", so existence is not revealed.

## Check the whole ledger (admin key)

```bash
curl -sS -X POST "$DIP_URL/v1/ledger/verify" -H "Authorization: Bearer $ADMIN_KEY"
```

Send the head you recorded elsewhere as `expectedHead` to detect truncation of the tail. The server does not know what head you expect, so keep that value outside the system:

```bash
curl -sS -X POST "$DIP_URL/v1/ledger/verify" -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" --data '{"expectedHead":"<head>"}'
```

## Export and verify a bundle

A bundle is a self-contained file: the entries, the requests, the decisions, the authorities and the approvals. Anyone can verify it, without the server:

```bash
dip verify bundle.json --trust trust.json
```

`trust.json` holds the public keys you trust: the issuer, the engine, the evidence signer and any approvers. Verification uses only those keys and the bundle.

## Reading the verdict

| Verdict        | Meaning                                                      | What to do                      |
| -------------- | ------------------------------------------------------------ | ------------------------------- |
| `VALID`        | Every check passed                                           | Nothing                         |
| `INCOMPLETE`   | Something is missing, but nothing contradicts the record     | Obtain the missing pieces       |
| `UNVERIFIABLE` | A signature could not be checked, usually an unknown key     | Check the trust file            |
| `INVALID`      | A check failed. The record was changed, or a rule was broken | Treat as tampering. Investigate |

When several problems exist, the most serious verdict is reported. `INVALID` outranks `UNVERIFIABLE`, which outranks `INCOMPLETE`, which outranks `VALID`. A tampered record is never hidden by a missing key elsewhere.

## Test it yourself

The example `node examples/run.mjs` changes one evidence entry and shows the verifier reporting `INVALID`. Try it to see what a failure looks like.
