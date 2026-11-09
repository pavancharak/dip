# Deploying DIP

This guide covers installing DIP, running its examples, configuring the API, and verifying evidence independently.
Read the limits section before any production use.

## Requirements

- Node.js 22 and pnpm 10 (the repository pins pnpm through `packageManager`).
- Docker, optional, for the container image.

## 1. Install and reproduce the examples

```bash
pnpm install --frozen-lockfile
pnpm -r run build
node examples/run.mjs
```

Expected output: four `PASS` lines and `4/4 examples passed`. The examples cover an authorized payment, a refused payment over the limit, tampered evidence detected by the verifier, and a revoked authority stopping execution. They generate fresh keys on each run and do not connect to any external system.

## 2. Create signing keys

Keys are Ed25519. Generate one pair per role. Keep the private keys out of the repository.

```bash
node apps/api/dist/keygen.js secrets engine
node apps/api/dist/keygen.js secrets evidence
node apps/api/dist/keygen.js secrets issuer
```

Each command writes `<id>.pem` (private, mode 0600) and `<id>.public.json` (public JWK). Copy the public JWKs into the trust roots in your configuration. Create one API key file per principal. Each must be at least 32 characters.

## 3. Write the configuration

Start from [`config.example.json`](config.example.json). The configuration names the trust roots, the signing keys by path, and the principals by API-key file path. It never contains secret values. See [ENVIRONMENT.md](ENVIRONMENT.md) for every setting.

The loader fails closed. Missing trust roots, a non-Ed25519 key, a short or duplicate API key, or an unknown scope stops the server at startup, and the error names the setting without printing any key material.

## 4. Run the server

Local, without Docker:

```bash
DIP_CONFIG=secrets/dip-config.json node apps/api/dist/server.js
```

With Docker:

```bash
docker build -t dip-api:local .
docker compose up
```

Compose mounts `./secrets` read-only at `/run/secrets`, runs the container as a non-root user, with a read-only root filesystem, no capabilities, and `no-new-privileges`. Health is at `GET /v1/health`.

## 5. Verify evidence independently

Export a bundle from your own code with the SDK (`ledgerLines()` and `ledgerHead()`), or list the ledger with `GET /v1/ledger` using an admin key. Then:

```bash
node packages/verifier/dist/bin.js --bundle bundle.json --trust trust.json
```

Exit codes: `0` VALID, `1` INVALID, `2` INCOMPLETE or UNVERIFIABLE, `3` usage or input error. The verifier needs only the bundle and the public trust roots.

## Operations

**Key rotation.** Add the new public key to the trust roots with status `ACTIVE`, and start signing with it. Keep the old key `ACTIVE` while records it signed still need verifying. To retire a compromised key, set its status to `REVOKED`. Every object it signed then fails verification, which is intended.

**Revocation.** Authorities are revoked with a signed revocation. A revoked authority stops execution at once, including for decisions made earlier.

**Durable state.** With `storage.dataDir` set, the server keeps every change in a PostgreSQL event log (PGlite, file-backed). It replays that log at startup and refuses to start if the stored evidence chain does not verify. Every response is sent only after its changes are written. Without `storage.dataDir`, state is held in memory and a restart discards everything.

**Backups and recovery: not automated.** Back up the data directory while the server is stopped (or use a consistent copy), and test a restore. After a restore, check the ledger head against the head you recorded outside the system.

**Connectors: none configured.** The server starts with no connectors, so every execution is refused with `CONNECTOR_NOT_FOUND`. Connectors are wired in code. The included adapters use placeholder endpoints.

## Versioning and releases

DIP follows semantic versioning from `0.0.0`. Packages are `private` and are not published to a registry. A release is a git tag `vMAJOR.MINOR.PATCH` on `main`. Before tagging, the `check` job and the examples must pass on `main`.

## Limits

- Backups and recovery are not automated, and no retention policy is implemented.
- The data directory may be opened by one process at a time.
- No `node-postgres` adapter yet: the server uses PGlite, which is file-backed PostgreSQL 16.
- No tenant-scoped ledger. Ledger reads are admin-only and show all tenants.
- API keys are supplied as files. There is no key-management integration.
- No live vendor integrations have been verified.
- The container image is built in CI. It was not built on the machine where this guide was written, because no Docker daemon was available there.
- No external security review has been performed.
