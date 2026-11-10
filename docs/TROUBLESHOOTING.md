# Troubleshooting

Errors carry stable codes. Match on the code. Full definitions are in [spec 16](spec/16-error-codes.md).

## The server will not start

| Message                  | Cause                                                      | Fix                                                                                                                |
| ------------------------ | ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `CONFIG_UNREADABLE`      | The configuration file is missing or not JSON.             | Check `DIP_CONFIG` and the file's syntax.                                                                          |
| `INVALID_CONFIG`         | A field is missing or has the wrong type.                  | Compare with [config.example.json](deployment/config.example.json).                                                |
| `INVALID_KEY`            | A private key file is missing, unreadable, or not Ed25519. | Regenerate with `keygen`, and check the path.                                                                      |
| `WEAK_API_KEY`           | An API key is shorter than 32 characters.                  | Generate a longer key.                                                                                             |
| `LEDGER_INVALID_ON_OPEN` | The stored evidence chain does not verify.                 | Do not force a start. Investigate the database, and restore a verified backup if needed. See the operations notes. |

## Authorization is DENY

Read `reasonCodes` in the response. Common causes:

| Reason code                                                                     | Meaning                                                                                        |
| ------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `AUTHORITY_NOT_FOUND`                                                           | No such authority or version. Check `authorityRef`.                                            |
| `AUTHORITY_EXPIRED`, `AUTHORITY_NOT_YET_VALID`                                  | The request time is outside the authority's window.                                            |
| `AUTHORITY_REVOKED`, `AUTHORITY_SUPERSEDED`                                     | A newer version exists, or this version was revoked. Use the current version.                  |
| `ACTION_NOT_PERMITTED`                                                          | The operation is not in `permittedActions`.                                                    |
| `RESOURCE_OUT_OF_SCOPE`                                                         | The resource is not in `resourceScope`.                                                        |
| `AMOUNT_EXCEEDS_LIMIT`                                                          | The amount is above `maxAmountMinor`. Approval cannot override this.                           |
| `CURRENCY_NOT_PERMITTED`                                                        | The currency is not in `currencies`.                                                           |
| `ACTOR_NOT_AUTHORIZED`                                                          | The actor is neither the principal nor the agent.                                              |
| `APPROVAL_REQUIRED`                                                             | Approval is needed. Request one.                                                               |
| `APPROVAL_PENDING`, `APPROVAL_REJECTED`, `APPROVAL_EXPIRED`, `APPROVAL_REVOKED` | The approval is not in the `APPROVED` state.                                                   |
| `APPROVAL_BINDING_MISMATCH`                                                     | The approval was made for a different request. Request a new approval for the current content. |
| `POLICY_VERSION_MISMATCH`                                                       | The request names a policy version the authority does not use.                                 |

## Execution is refused

| Attempt reason                                                               | Meaning                                                                 |
| ---------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| `DECISION_NOT_ALLOW`                                                         | The decision is DENY. Authorize first.                                  |
| `REQUEST_DIGEST_MISMATCH`                                                    | The request changed after authorization. Normalize and authorize again. |
| `DECISION_STALE`                                                             | The decision is older than `maxDecisionAgeSeconds`. Authorize again.    |
| `DECISION_IN_FUTURE`                                                         | The decision time is ahead of the server clock. Check the clock.        |
| `DECISION_REPLAYED`                                                          | The decision already ran. Do not reuse it; authorize again.             |
| `IDEMPOTENCY_CONFLICT`                                                       | The same key was used with different content. Use a new key.            |
| `EXECUTION_IN_PROGRESS`                                                      | The same key is running. Wait, then check the result.                   |
| `CONNECTOR_NOT_FOUND`                                                        | No connector is wired for this operation.                               |
| `DECISION_SIGNATURE_INVALID`, `DECISION_KEY_UNKNOWN`, `DECISION_KEY_REVOKED` | The decision is not from a trusted engine key.                          |

## Execution failed or timed out

- `FAILED` with a connector reason: check that reason and the external system.
- `TIMED_OUT`: the outcome is **unknown**. Do not retry blindly. Check the external system with the idempotency key, then decide.
- `FAILED` with `CONNECTOR_ERROR`: the connector threw. Check its logs and configuration.

## Verification fails

Use the per-check detail from `dip verify --json`. See [VERIFICATION.md](VERIFICATION.md) for what each verdict means.

| Check                           | Likely cause                                                                                   |
| ------------------------------- | ---------------------------------------------------------------------------------------------- |
| `SIGNATURE` with `UNVERIFIABLE` | The signing key is not in your trust roots.                                                    |
| `SIGNATURE` with `FAIL`         | The record was changed, or the wrong public key is in the trust roots.                         |
| `CANONICAL`                     | The entries were re-formatted (for example, pretty-printed). Use the exported lines unchanged. |
| `CHAIN` or `SEQUENCE`           | Entries are missing, reordered, or changed.                                                    |
| `HEAD`                          | The head differs from the one you recorded.                                                    |

## Backups

| Message                                     | Fix                                                                           |
| ------------------------------------------- | ----------------------------------------------------------------------------- |
| `DESTINATION_NOT_EMPTY`, `TARGET_NOT_EMPTY` | Choose an empty or new directory.                                             |
| `DIGEST_MISMATCH`                           | The backup files changed after creation. Restore from another copy.           |
| `ANCHOR_MISMATCH`                           | The manifest head differs from the head you recorded. Investigate before use. |
| `LEDGER_INVALID`                            | The source database's chain does not verify. Do not back it up as good.       |

## Database

- **Locked data directory:** only one process may open a file-backed database. Stop the other process.
- **`relation ... does not exist`:** the schema has not been migrated. The server migrates at startup; run `migrate` if you use the storage package directly.
- **Append-only errors** (`DIP records are append-only`): the application tried to change evidence. This is intended. Do not disable the triggers to make it pass.

## Still stuck

Open an issue with the code, the reason, the command you ran, and the version (`CHANGELOG.md`). Do not include private keys, API keys, or personal data. For security problems, follow [SECURITY.md](https://github.com/pavancharak/dip/blob/main/SECURITY.md).
