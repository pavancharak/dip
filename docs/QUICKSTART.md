# Quick start

This takes about ten minutes. Everything here runs locally, and nothing contacts an external service.

## 1. Install

```bash
pnpm install --frozen-lockfile
pnpm -r run build
```

## 2. Run the examples

```bash
node examples/run.mjs
```

Four scenarios run and should print `4/4 examples passed`:

1. A ₹40,000 payment is ALLOW, executes once, and its evidence verifies.
2. A ₹80,000 payment is DENY, and the connector is never called.
3. Altered evidence is detected as INVALID.
4. After an authority is revoked, a previously ALLOW decision no longer executes.

## 3. Walk through the SDK

```bash
node examples/sdk-quickstart.mjs
```

Read [examples/sdk-quickstart.mjs](../examples/sdk-quickstart.mjs). It declares an authority, authorizes a request, executes it through the boundary, records evidence, and verifies the ledger. [SDK guide](SDK.md) explains each step.

## 4. Run the conformance suite

```bash
node apps/cli/dist/bin.js conformance run conformance
```

Expected: `16/16 cases passed`. These fixtures define what a correct implementation must produce.

## 5. Try the CLI

```bash
node apps/cli/dist/bin.js help
node apps/api/dist/keygen.js ./keys engine    # writes keys/engine.pem (private) and keys/engine.public.json
```

Keep private keys out of version control. `./keys` is not ignored by default; add it to your own `.gitignore`.

## 6. Run the server (optional)

See [Installation](INSTALL.md#running-the-server) for configuration and Docker. The server starts with no connectors, so executions are refused until you wire one in.

## Next

- [Integration guide](INTEGRATION.md): how an application uses DIP.
- [Verification](VERIFICATION.md): checking evidence on its own.
