# Installation

## Requirements

- Node.js 22 (see `.nvmrc`)
- pnpm 10 (the repository pins it through `packageManager`; `corepack enable` provides it)
- Docker, optional, for the container image

## From source

```bash
git clone https://github.com/pavancharak/dip.git
cd dip
pnpm install --frozen-lockfile
pnpm -r run build
pnpm check        # build, typecheck, lint, format check, tests
```

`pnpm check` should pass before you rely on a build.

## Packages are not published

All packages are marked `private` and are not on npm. Use them from the repository. Publishing would need a separate decision.

## Running the server

1. Generate keys (one pair per role):
   ```bash
   node apps/api/dist/keygen.js secrets issuer
   node apps/api/dist/keygen.js secrets engine
   node apps/api/dist/keygen.js secrets evidence
   ```
2. Create an API key file per principal, at least 32 characters.
3. Write a configuration file based on [docs/deployment/config.example.json](deployment/config.example.json). The fields are listed in [docs/deployment/ENVIRONMENT.md](deployment/ENVIRONMENT.md).
4. Start:
   ```bash
   DIP_CONFIG=secrets/dip-config.json node apps/api/dist/server.js
   ```
5. Check it is up: `curl localhost:3000/v1/health`.

Keep state across restarts with one of two settings. Without either, state is in memory and a restart discards it.

- `storage.postgresUrlPath`: a secret file containing a `postgres://` connection string. The server uses PostgreSQL, applies its schema on start, and writes every change before answering. The connection string is never written to logs or error messages.
- `storage.dataDir`: a local directory for the embedded file-backed database. Use this for a single host with no PostgreSQL.

Set one or the other, not both. The server refuses to start if the stored evidence chain does not verify. If a write cannot be persisted, the server stops rather than answer from state the log no longer matches.

## Docker

```bash
docker build -t dip-api:local .
docker compose up
```

The image runs as a non-root user with a read-only root filesystem. Mount your `secrets/` directory read-only. Details are in [docs/deployment/README.md](deployment/README.md).

## Database

File-backed PostgreSQL (PGlite) needs no separate server. For a networked PostgreSQL 14+ server, the storage package provides a node-postgres adapter (`openPostgres`). Its tests run in CI against PostgreSQL 16. See [infrastructure/postgres/README.md](../infrastructure/postgres/README.md).
