# 2. Run the example

This runs the full protocol on your machine, in memory. It needs no server and no cloud account. It creates throwaway keys, so it is safe to run anywhere.

## Requirements

- Node.js 22 or later
- pnpm (`corepack enable` activates it)
- Git

## Steps

```bash
git clone https://github.com/pavancharak/dip.git
cd dip
pnpm install --frozen-lockfile
pnpm -r run build
node examples/sdk-quickstart.mjs
```

## What you should see

```
authorization: ALLOW
execution: SUCCEEDED demo-1
ledger valid: true entries: 1
```

If any line differs, check `09-troubleshooting.md`.

## What the example does

The script in `examples/sdk-quickstart.mjs` does four things:

1. **Declares and publishes an authority.** It allows payments up to 50,000 INR to one resource.
2. **Authorizes a request** for 4,000 INR. The result is ALLOW.
3. **Executes** the action through the boundary and records the evidence.
4. **Verifies the ledger** it holds.

Read the file. Each numbered comment matches one step of [03](03-declare-an-authority.md), [04](04-authorize-and-execute.md) and [06](06-evidence-and-verification.md).

## Run the full set of scenarios

```bash
node examples/run.mjs
```

This runs four scenarios: an allowed payment, a payment over the limit (DENY), tampered evidence (INVALID), and an authority revoked after an earlier ALLOW.
