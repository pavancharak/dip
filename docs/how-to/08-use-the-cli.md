# 8. Use the CLI

The `dip` command is a client for the API, plus local tools for signing, normalizing, verifying and conformance testing. It never stores state. Anything that changes state goes through the server.

The full reference is in `docs/CLI.md`. This guide shows the workflows.

## Configure it

Set the server and your key once:

```bash
export DIP_URL="https://<your-dip-server>"
export DIP_API_KEY="<your-api-key>"
```

Or pass `--url` and `--api-key` on each command. Add `--json` for machine-readable output.

Key files are read from disk. Keep them out of version control.

## Commands

| Command                                       | Needs the server  | Purpose                                                       |
| --------------------------------------------- | ----------------- | ------------------------------------------------------------- |
| `dip authority create <file>`                 | no                | Check a declaration and print it in canonical form            |
| `dip authority sign <file> --key <pem>`       | no                | Sign a declaration with an Ed25519 key                        |
| `dip authority inspect <id> [--version N]`    | yes               | Read a published authority                                    |
| `dip authority revoke <signed-revocation>`    | yes               | Publish a signed revocation                                   |
| `dip request normalize <file>`                | no                | Canonicalize a request and print its digest                   |
| `dip authorize <request>`                     | yes               | Authorize. Prints ALLOW or DENY                               |
| `dip approval create <file>`                  | yes               | Request an approval                                           |
| `dip approval approve <decision>` / `reject`  | yes               | Record an approver's signed decision                          |
| `dip approval inspect <id>`                   | yes               | Read an approval's state                                      |
| `dip execute <{request, decision}>`           | yes               | Run through the protected boundary                            |
| `dip evidence inspect <id>`                   | yes               | Read an evidence record                                       |
| `dip verify <bundle> --trust <file>`          | no                | Verify an exported bundle independently                       |
| `dip ledger inspect [--offset N] [--limit N]` | yes, admin key    | List evidence                                                 |
| `dip ledger verify [--head H]`                | yes, admin key    | Verify the server's ledger                                    |
| `dip conformance run <suite-dir>`             | no                | Run conformance fixtures against the reference implementation |
| `dip backup`                                  | see `docs/CLI.md` | Back up the data directory                                    |

## Workflow: authorize a request from a file

```bash
dip request normalize request.json > normalized.json
dip authorize request.json
```

Exit code `0` means ALLOW. Exit code `1` means DENY.

## Workflow: sign and publish an authority

```bash
dip authority create declaration.json
dip authority sign declaration.json --key issuer.pem > authority.json
```

Then publish it through the API, as described in [03](03-declare-an-authority.md).

## Workflow: check an exported bundle

```bash
dip verify bundle.json --trust trust.json --json
```

The verdict is in the output. Exit code `0` means `VALID`.

## Exit codes

| Code | Meaning                                                                                            |
| ---- | -------------------------------------------------------------------------------------------------- |
| 0    | Success. ALLOW, VALID, executed (or a duplicate of an earlier success), all conformance cases pass |
| 1    | DENY, INVALID, refused or failed execution, a conformance failure                                  |
| 2    | Verification is INCOMPLETE or UNVERIFIABLE                                                         |
| 3    | Usage error or rejected input. Check the command and the file                                      |
| 4    | Server error, or the server could not be reached                                                   |

The CLI does not retry. A 5xx or an unreachable server returns exit 4. Retry in your script, with a delay.

## Scripts

Check the exit code, never the printed text, when a script decides something:

```bash
if dip authorize request.json > /dev/null; then
  echo "allowed"
else
  echo "refused or failed"
fi
```
