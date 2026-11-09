# Environment and configuration reference

## Environment variables

| Variable     | Default                                                | Meaning                                                                                       |
| ------------ | ------------------------------------------------------ | --------------------------------------------------------------------------------------------- |
| `DIP_CONFIG` | `/run/secrets/dip-config.json`                         | Path to the JSON configuration file.                                                          |
| `PORT`       | `3000` (used by the Compose file and the health check) | Port the server listens on. The configuration file's `port` takes precedence for the process. |
| `NODE_ENV`   | unset                                                  | Set to `production` in the image.                                                             |

No other variables are read. Secrets are never read from the environment, so they cannot leak through process listings or logs.

## Configuration file

| Field                     | Required                      | Meaning                                                                                                                                                                          |
| ------------------------- | ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `port`                    | no (3000)                     | Listen port, 1 to 65535.                                                                                                                                                         |
| `maxDecisionAgeSeconds`   | no (300)                      | A decision older than this cannot execute.                                                                                                                                       |
| `executionTimeoutMs`      | no (5000)                     | Connector time limit before the attempt is recorded as TIMED_OUT.                                                                                                                |
| `storage.dataDir`         | no (absent = in memory)       | Directory for the embedded file-backed database. Only one process may open it at a time. Mutually exclusive with `storage.postgresUrlPath`.                                      |
| `storage.postgresUrlPath` | no                            | Path to a secret file holding a `postgres://` connection string. The server uses PostgreSQL and writes every change before answering. Mutually exclusive with `storage.dataDir`. |
| `rateLimit.max`           | no (600)                      | Requests per principal per window.                                                                                                                                               |
| `rateLimit.windowMs`      | no (60000)                    | Window length in milliseconds.                                                                                                                                                   |
| `trustRoots[]`            | yes                           | Public keys: `keyId`, `jwk` (Ed25519 OKP), `status` (`ACTIVE` or `REVOKED`). At least one.                                                                                       |
| `engine`                  | yes                           | `keyId` plus either `privateKeyPath` (local key, development only) or `kmsKeyId` (AWS KMS Ed25519 key; production). Setting both is refused.                                     |
| `evidenceSigner`          | yes                           | Same as `engine`, for the evidence-signing key.                                                                                                                                  |
| `kms.region`              | when a signer uses `kmsKeyId` | AWS region of the KMS keys, for example `us-east-1`. Credentials come from the AWS SDK default chain (an IAM role in production), never from this file.                          |
| `principals[]`            | yes                           | `name`, `tenantId` (string, or null for cross-tenant), `scopes` (`admin`, `approver`), `apiKeyPath`. At least one.                                                               |

## Error codes at startup

| Code                | Cause                                                       |
| ------------------- | ----------------------------------------------------------- |
| `CONFIG_UNREADABLE` | The configuration file is missing or is not JSON.           |
| `INVALID_CONFIG`    | A field is missing or has the wrong type.                   |
| `INVALID_KEY`       | A private key file is missing, unparseable, or not Ed25519. |
| `WEAK_API_KEY`      | An API key is shorter than 32 characters.                   |

The process exits with status `1` and prints the code and the field name. It never prints key material.
