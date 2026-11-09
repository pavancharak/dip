# The `dip` command

`dip` is a client for the DIP REST API, plus local tools for signing, normalizing, verifying and conformance testing. It never holds state: anything that changes state goes through the API.

## Configuration

| Setting                 | Flag        | Environment   | Required for    |
| ----------------------- | ----------- | ------------- | --------------- |
| Server base URL         | `--url`     | `DIP_URL`     | server commands |
| API key                 | `--api-key` | `DIP_API_KEY` | server commands |
| Machine-readable output | `--json`    |               | all commands    |

## Commands

| Command                                       | Needs server   | Purpose                                                            |
| --------------------------------------------- | -------------- | ------------------------------------------------------------------ |
| `dip authority create <file>`                 | no             | Validate a declaration and print it canonically.                   |
| `dip authority sign <file> --key <pem>`       | no             | Sign a declaration with an Ed25519 key.                            |
| `dip authority inspect <id> [--version N]`    | yes            | Read a published authority.                                        |
| `dip authority revoke <signed-revocation>`    | yes            | Publish a signed revocation.                                       |
| `dip request normalize <file>`                | no             | Canonicalize a request and compute its digest.                     |
| `dip authorize <request>`                     | yes            | Authorize. Prints ALLOW or DENY.                                   |
| `dip approval create <file>`                  | yes            | Request an approval.                                               |
| `dip approval approve <decision>` / `reject`  | yes            | Record an approver's signed decision.                              |
| `dip approval inspect <id>`                   | yes            | Read an approval's state.                                          |
| `dip execute <{request, decision}>`           | yes            | Run through the protected boundary.                                |
| `dip evidence inspect <id>`                   | yes            | Read an evidence record.                                           |
| `dip verify <bundle> --trust <file>`          | no             | Verify an exported bundle independently.                           |
| `dip ledger inspect [--offset N] [--limit N]` | yes, admin key | List evidence.                                                     |
| `dip ledger verify [--head H]`                | yes, admin key | Verify the server's ledger.                                        |
| `dip conformance run <suite-dir>`             | no             | Run the conformance fixtures against the reference implementation. |

## Exit codes

| Code | Meaning                                                                                  |
| ---- | ---------------------------------------------------------------------------------------- |
| 0    | Success, ALLOW, VALID, executed (or duplicate), all conformance cases pass               |
| 1    | DENY, INVALID, refused or failed execution, a conformance failure                        |
| 2    | INCOMPLETE or UNVERIFIABLE                                                               |
| 3    | Usage error, or input rejected (validation failed, unknown command, missing credentials) |
| 4    | Server unreachable, or the server returned 5xx                                           |

Scripts should treat 1 as a business outcome and 3 or 4 as a fault.

## Examples

```bash
dip authority sign declaration.json --key issuer.pem > authority.json
dip request normalize request.json > normalized.json
DIP_URL=https://dip.example.com DIP_API_KEY="$KEY" dip authorize request.json
dip verify bundle.json --trust trust.json --json
dip conformance run conformance/
```

## Limits

- Key files are read from disk. Keep them out of version control.
- The CLI does not retry. A 5xx or unreachable server returns exit 4.
