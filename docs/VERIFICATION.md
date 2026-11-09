# Verification guide

Verification lets someone check that an action was authorized and recorded, without trusting the service that recorded it. The verifier needs three things: the evidence bundle, the public trust roots, and nothing else. It does not need the database, the server, or the people who ran them.

## What you need

- **An evidence bundle** (`dip-evidence-bundle`, version 1). It contains the evidence entries in order, plus the requests, decisions, authorities and approvals they refer to.
- **Trust roots**: the public keys you choose to trust (issuer, engine, evidence, approvers), each with a status. The verifier never reads trust roots from the bundle.
- **An expected head** (optional but recommended): the ledger head, recorded outside the system at the time you were given the bundle. Without it, a truncated tail cannot be detected.

## Run it

```bash
node apps/cli/dist/bin.js verify bundle.json --trust trust.json
node apps/cli/dist/bin.js verify bundle.json --trust trust.json --json
```

Exit codes: `0` VALID, `1` INVALID, `2` INCOMPLETE or UNVERIFIABLE, `3` input error.

## What each verdict means

| Verdict      | Meaning                                                                                                           | What to do                                            |
| ------------ | ----------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| VALID        | Every check passed.                                                                                               | Accept the evidence.                                  |
| INVALID      | A check failed: a signature does not verify, the chain is broken, a record does not match its request, and so on. | Do not accept. The per-check detail says which check. |
| UNVERIFIABLE | No failure, but a signing key is not among your trust roots.                                                      | Add the correct public key, if you trust it.          |
| INCOMPLETE   | No failure, but a needed record is missing, the bundle is empty, or no head was supplied.                         | Ask for the missing records, or supply the head.      |

When several conditions hold, the verdict is the most serious: INVALID outranks UNVERIFIABLE, which outranks INCOMPLETE.

## Checks

The `--json` output lists each check with its outcome. The check names are in [spec 14](spec/14-independent-verification.md#143-checks). The most useful ones:

- `SIGNATURE`: a signature verifies under a trusted key.
- `CHAIN`, `SEQUENCE`: entries link to each other in order.
- `REQUEST`: the request body matches its digest.
- `DECISION`: the recorded decision is authentic and matches the evidence.
- `APPROVAL`: the approval was in force at the decision time.
- `HEAD`: the chain ends at the expected head.

## What verification does not prove

- It proves that the recorded decision was signed by a trusted key and matches the request. It does not re-run the policy.
- It proves what the connector reported. It does not prove what the external system did.
- It cannot detect a truncated tail unless you supply the head.
- A compromised trusted key can create valid records until it is revoked.

## Test it yourself

The conformance fixtures include a valid bundle and tampered bundles, with their expected verdicts:

```bash
node apps/cli/dist/bin.js conformance run conformance
```
