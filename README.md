# DIP: Decision Integrity Protocol

[![CI](https://github.com/pavancharak/dip/actions/workflows/ci.yml/badge.svg)](https://github.com/pavancharak/dip/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Node.js 22](https://img.shields.io/badge/node-22-339933.svg)

DIP is an open protocol and reference implementation that answers one question for every action an automated system takes: **was it authorized, and can anyone check that it was?**

- **Authority is declared, not inferred.** Each agent's permissions are a signed, versioned declaration.
- **Decisions are deterministic.** Every request is authorized as **ALLOW or DENY** by explicit rules. No model makes the decision.
- **Approvals are separate.** A human approval is one input to a decision. It never grants authority on its own.
- **Execution is gated.** An action runs only through an execution boundary, and only for a verified ALLOW decision for that exact request.
- **Evidence is independent.** Every attempt, including every refusal, is recorded in a signed, hash-chained ledger. An independent verifier checks it without trusting the service that wrote it.

```
DECLARED ──▶ AUTHORIZED ──▶ EXECUTED ──▶ PROVEN
```

AI systems may propose actions. The business declares what is allowed. DIP decides, controls execution, and produces proof.

## Contents

- [Status](#status)
- [What DIP guarantees](#what-dip-guarantees)
- [What DIP does not do](#what-dip-does-not-do)
- [Quick start](#quick-start)
- [Using DIP](#using-dip)
- [Deploying DIP](#deploying-dip)
- [Repository layout](#repository-layout)
- [Documentation](#documentation)
- [Development](#development)
- [Contributing and security](#contributing-and-security)
- [License](#license)

## Status

**Reference implementation. Not yet independently reviewed.**

- The protocol, SDK, REST API, CLI, verifier, conformance fixtures, storage and deployment files are implemented and tested in this repository. See [docs/BUILD_STATUS.md](docs/BUILD_STATUS.md).
- Connectors in this repository use placeholder endpoints. No live payment or ERP integration has been verified here.
- The conformance fixtures were written by this project. No independent implementation has run them yet.
- No external security review has been performed. The open gaps are listed in [docs/RELEASE-AUDIT.md](docs/RELEASE-AUDIT.md) and [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

Protocol version: `1.0`. Changes are recorded in [CHANGELOG.md](CHANGELOG.md).

## What DIP guarantees

Each guarantee below has tests in the repository. The threat model says which attacks each one addresses.

| Guarantee                | In practice                                                                         |
| ------------------------ | ----------------------------------------------------------------------------------- |
| Two outcomes only        | Authorization returns ALLOW or DENY. Malformed input is refused, never allowed      |
| Exact binding            | A decision matches one request digest, one authority version and one policy version |
| Single use               | A decision authorizes at most one execution. Retries need a new decision            |
| Idempotency              | The same idempotency key with the same content returns the original result          |
| Tamper evidence          | Changing, deleting or reordering any evidence record breaks the hash chain          |
| Tenant isolation         | Requests, authorities and evidence are scoped to a tenant                           |
| Independent verification | The verifier depends only on the public trust roots and the exported bundle         |

## What DIP does not do

Be clear about these before you rely on DIP:

- **It does not make a connector honest.** A connector that ignores the idempotency key can still duplicate an action outside DIP. Connectors must pass the key through.
- **It does not verify identity beyond the API key.** Who the principal is comes from the issuer's declaration.
- **It cannot resolve an unknown outcome.** A timeout is recorded as `TIMED_OUT`, not as success or failure. Reconciliation with the external system is the operator's job.
- **It does not protect against a compromised signing key.** Records signed with a compromised key remain valid until the key is revoked.
- **It cannot detect tail truncation alone.** Keep the ledger head somewhere outside the system and check it.
- **The server runs as one writer.** The evidence chain has one writer on purpose. See [ADR-0022](docs/ARCHITECTURE_DECISIONS.md).
- **It is not a model safety system.** DIP decides whether an action is permitted. It does not judge whether a model's output is correct.

## Quick start

Requires **Node.js 22** and **pnpm 10**.

```bash
git clone https://github.com/pavancharak/dip.git
cd dip
pnpm install --frozen-lockfile
pnpm -r run build
node examples/run.mjs              # 4 end-to-end scenarios: expect "4/4 examples passed"
node examples/sdk-quickstart.mjs   # minimal SDK walkthrough
node apps/cli/dist/bin.js conformance run conformance   # expect "16/16 cases passed"
```

The examples run in memory with throwaway keys. They need no server and no cloud account.

For a step-by-step walkthrough, see [docs/how-to/02-run-the-example.md](docs/how-to/02-run-the-example.md).

## Using DIP

The how-to guides in [docs/how-to/](docs/how-to/) cover each task:

| Task                                   | Guide                                                                    |
| -------------------------------------- | ------------------------------------------------------------------------ |
| Understand the model                   | [Concepts](docs/how-to/01-concepts.md)                                   |
| Declare and publish an authority       | [Declare an authority](docs/how-to/03-declare-an-authority.md)           |
| Authorize a request and run the action | [Authorize and execute](docs/how-to/04-authorize-and-execute.md)         |
| Send high-value requests to a person   | [Approvals](docs/how-to/05-approvals.md)                                 |
| Record, export and verify evidence     | [Evidence and verification](docs/how-to/06-evidence-and-verification.md) |
| Call the HTTP API                      | [Use the API](docs/how-to/07-use-the-api.md)                             |
| Use the `dip` command                  | [Use the CLI](docs/how-to/08-use-the-cli.md)                             |

A minimal SDK call looks like this. The full setup, including keys and trust roots, is in [examples/sdk-quickstart.mjs](examples/sdk-quickstart.mjs):

```js
const { result, decision } = await client.authorize(client.normalizeRequest(request));
if (result === "ALLOW") {
  const attempt = await client.execute(request, decision);
  await client.record({ normalized: request, decision, attempt });
}
```

Only ALLOW lets an action run. Treat every other outcome, including an error, as a refusal.

## Deploying DIP

- [Deployment overview](docs/deployment/README.md): environment variables, configuration and the single-writer model.
- [AWS guide](docs/deployment/aws/README.md): a complete walkthrough for running the server on ECS Fargate with AWS KMS signing keys, RDS PostgreSQL and Secrets Manager.
- [Container image](Dockerfile): a multi-stage build that runs as a non-root user with a read-only root filesystem in Compose and ECS.

## Repository layout

| Path                                   | What it is                                                                               |
| -------------------------------------- | ---------------------------------------------------------------------------------------- |
| `packages/crypto`                      | Canonical JSON, SHA-256, domain-separated Ed25519, signing providers                     |
| `packages/authority`                   | Authority declarations, trust roots, signed publication and revocation                   |
| `packages/authorization`               | Request normalization and the two-outcome engine                                         |
| `packages/approval`                    | The approval workflow, kept separate from authorization                                  |
| `packages/execution`                   | The protected execution boundary                                                         |
| `packages/evidence`, `packages/ledger` | The signed evidence envelope and the hash-chained ledger                                 |
| `packages/verifier`                    | The independent verifier. Depends only on `@dip/crypto`                                  |
| `packages/connectors`                  | The connector contract and adapters                                                      |
| `packages/sdk`                         | The developer client                                                                     |
| `packages/storage`                     | PostgreSQL storage: event log, stores, the embedded engine and the node-postgres adapter |
| `packages/conformance`                 | The runner for the conformance fixtures                                                  |
| `packages/kms`                         | AWS KMS signing provider                                                                 |
| `apps/api`                             | The REST API server                                                                      |
| `apps/cli`                             | The `dip` command                                                                        |
| `conformance/`                         | Language-neutral JSON conformance fixtures                                               |
| `examples/`                            | Runnable examples                                                                        |
| `docs/`                                | Specification, guides, deployment and threat model                                       |

## Documentation

Start at [docs/README.md](docs/README.md), which indexes everything. The most useful entries:

- [Quick start](docs/QUICKSTART.md) and [installation](docs/INSTALL.md)
- [Integration guide](docs/INTEGRATION.md): how an application uses DIP end to end
- [SDK](docs/SDK.md), [CLI](docs/CLI.md) and the [REST API (OpenAPI)](docs/api/openapi.json)
- [Verification guide](docs/VERIFICATION.md): checking evidence without trusting the service
- [Connector guide](docs/CONNECTORS.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Specification](docs/spec/README.md): 21 sections, some of them drafts
- [Threat model](docs/THREAT-MODEL.md) and [architecture decisions](docs/ARCHITECTURE_DECISIONS.md)

## Development

```bash
pnpm check    # build, typecheck, lint, format check and tests
```

The PostgreSQL integration test runs when `DIP_TEST_PG_URL` points at a reachable server. Without it, the test is skipped, not faked. The CI `postgres` job runs it against PostgreSQL 16.

The repository uses TypeScript in strict mode, ESLint with type-aware rules, Prettier, and Vitest. See [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow and the expectations for pull requests.

## Contributing and security

- Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) first.
- **Do not report vulnerabilities in public issues.** Follow [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
