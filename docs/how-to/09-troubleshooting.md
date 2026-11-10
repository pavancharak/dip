# 9. Troubleshooting

## The example prints something different

- **`ERR_MODULE_NOT_FOUND` or `Cannot find package`:** run `pnpm install --frozen-lockfile` and `pnpm -r run build` from the repository root, then run the example again.
- **Node version too old:** the project needs Node 22 or later. Check with `node --version`.

## Authorize returns DENY and you expected ALLOW

Read `reasonCodes` in the response. Common ones:

| Reason                    | Usual cause                                                                                                 |
| ------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `AUTHORITY_NOT_FOUND`     | The `authorityId` or `version` in the request does not match a published authority                          |
| `AUTHORITY_REVOKED`       | The authority was revoked                                                                                   |
| `AMOUNT_EXCEEDS_LIMIT`    | The amount is above `maxAmountMinor`                                                                        |
| `ACTION_NOT_PERMITTED`    | The `operation` is not in `permittedActions`                                                                |
| `APPROVAL_REQUIRED`       | The amount is above `approvalAboveMinor`, or the operation is in `approvalActions`, and no approval applies |
| `REQUEST_DIGEST_MISMATCH` | The request was changed after an approval was made for it                                                   |
| `DECISION_STALE`          | An older decision was used for execution                                                                    |

Check the request against the authority: the currency, the resource, the dates in `validFrom` and `validUntil`, and the tenant and organization IDs.

## Execute is refused

- **`DECISION_STALE`:** the decision is too old. Authorize again to get a new one.
- **A refusal after a successful authorize:** the authority or approval changed in between. Authorize again and read the new reason.
- **The same decision used twice:** decisions are single-use. Authorize again.

## An attempt shows `TIMED_OUT`

The outcome is unknown. The action may or may not have happened. Check the external system before retrying. Do not retry blindly.

## Verification says INVALID

Treat it as tampering until shown otherwise. Do not edit the bundle to make it pass. Keep the bundle, and compare it with the copy you exported first.

## Verification says UNVERIFIABLE

The trust file does not contain the key that signed a record. Add the correct public key, if you trust it, and verify again.

## Verification says INCOMPLETE

Something needed for the check is missing from the bundle, for example an authority or an approval. Re-export the bundle with everything it references.

## 401 UNAUTHORIZED

The key is missing, misspelled, or revoked. Check that the `Authorization` header reads `Bearer <key>` with one space.

## 403 FORBIDDEN

The key is valid but lacks the scope. Approval decisions need `approver`. Ledger reads need `admin`.

## 429 RATE_LIMITED

Slow down. Wait for the window to pass, and add a delay between retries.

## The CLI exits with 3

The command or its input was rejected. Run the command with `--help`, check the file is valid JSON, and check the required flags.

## The CLI exits with 4

The server is unreachable or failed. Check `DIP_URL`, then `curl "$DIP_URL/v1/health"`.

## Still stuck

Collect the request (without keys), the response, the time, and the exit code. Open an issue on the repository and include them. Do not include API keys or key files.
