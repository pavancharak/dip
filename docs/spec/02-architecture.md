# 2. Architecture

Status: draft, matches the implementation.

## 2.1 Components

| Component                           | Package              | Responsibility                                               |
| ----------------------------------- | -------------------- | ------------------------------------------------------------ |
| Canonical encoding and cryptography | `@dip/crypto`        | Deterministic JSON, SHA-256, domain-separated Ed25519        |
| Authority                           | `@dip/authority`     | Declarations, trust roots, signed publication and revocation |
| Authorization                       | `@dip/authorization` | Request normalization and the two-outcome engine             |
| Approval                            | `@dip/approval`      | Approval workflow, separate from authorization               |
| Execution                           | `@dip/execution`     | Protected boundary to connectors                             |
| Evidence                            | `@dip/evidence`      | Signed evidence envelope                                     |
| Ledger                              | `@dip/ledger`        | Append-only hash chain                                       |
| Verifier                            | `@dip/verifier`      | Independent verification; depends only on `@dip/crypto`      |
| Connectors                          | `@dip/connectors`    | Adapters for external systems                                |
| SDK                                 | `@dip/sdk`           | Developer client                                             |
| REST API                            | `apps/api`           | HTTP interface over the SDK                                  |
| CLI                                 | `apps/cli`           | `dip` command                                                |
| Storage                             | `@dip/storage`       | PostgreSQL event log, stores, backup                         |

## 2.2 Dependencies

The verifier MUST depend only on the cryptography package. It MUST NOT import the engine, the ledger, the boundary or the registry. No component below the API MAY depend on the API.

## 2.3 Data flow

Request → normalization (digest) → authorization (ALLOW or DENY) → execution boundary (verifies ALLOW for the same digest, then calls a connector) → evidence (signed, chained) → ledger. Verification reads only the exported bundle and trust roots.

## 2.4 State

Authority, approval, execution and evidence state is journaled. The server replays the journal at startup and MUST refuse to start if the evidence chain does not verify. Persistence is described in `infrastructure/postgres/README.md`.
