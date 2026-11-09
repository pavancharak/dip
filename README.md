# DIP: Decision Integrity Protocol

DIP is an independent protocol and reference implementation for authorizing,
executing and evidencing consequential decisions. It is a standalone project:
it does not depend on Parmana to operate or to verify its evidence.

## Status

Early foundation. See [BUILD_STATUS.md](BUILD_STATUS.md) and
[IMPLEMENTATION_MATRIX.md](IMPLEMENTATION_MATRIX.md). No protocol behaviour is
implemented yet.

## Layout

| Path                                           | Purpose                            |
| ---------------------------------------------- | ---------------------------------- |
| `docs/spec/`                                   | Protocol specification (normative) |
| `packages/crypto`                              | Cryptographic foundation           |
| `packages/authority`                           | Authority model                    |
| `packages/authz`                               | Authorization engine               |
| `packages/approval`                            | Separate approval workflow         |
| `packages/execution`                           | Execution boundary                 |
| `packages/evidence`                            | Evidence generation                |
| `packages/ledger`                              | Append-only ledger                 |
| `packages/verifier`                            | Independent verifier               |
| `packages/sdk`, `packages/cli`, `packages/api` | Developer and service surfaces     |
| `packages/connectors`                          | Connector framework                |
| `packages/conformance`                         | Conformance suite                  |

## Development

Requires Node 22 and pnpm 10.

```bash
pnpm install
pnpm check
```

## Documents

- [SECURITY.md](SECURITY.md): vulnerability reporting
- [CONTRIBUTING.md](CONTRIBUTING.md): contribution process
- [docs/ARCHITECTURE_DECISIONS.md](docs/ARCHITECTURE_DECISIONS.md)

## License

Apache-2.0. See [LICENSE](LICENSE).
