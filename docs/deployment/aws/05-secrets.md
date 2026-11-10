# 05. Secrets

Four secrets live in AWS Secrets Manager, region `us-east-1`. Each is a plain secret string, not a key-value secret.

| Secret name             | Contents                                                 | Read by                                          |
| ----------------------- | -------------------------------------------------------- | ------------------------------------------------ |
| `dip/prod/config`       | The server's configuration file as JSON (see below)      | The task, at start                               |
| `dip/prod/pg-url`       | The PostgreSQL connection string, including the password | The task, at start                               |
| `dip/prod/operator-key` | The operator API key (at least 32 characters)            | The task, at start                               |
| `dip/prod/db-master`    | The database master username and password                | Administrators only. The server does not read it |

## How the container reads them

1. The task definition lists the three secrets under `secrets`. ECS fetches them before the container starts, using the execution role, and places each value in an environment variable: `DIP_CONFIG_JSON`, `DIP_PG_URL`, `DIP_OPERATOR_KEY`.
2. The entrypoint (`deployment/aws/entrypoint.sh`) writes each value to a file in `/dev/shm/dip-secrets`, which is memory-backed. Permissions are owner-only.
3. The entrypoint rewrites the configuration's `/run/secrets/` paths to point at those files, unsets the three environment variables, and starts the server.

The secrets never touch the image or the container's disk, and the variables are gone before the server starts.

## The configuration document

`dip/prod/config` holds the same JSON structure as `docs/deployment/config.example.json`, with these production values:

- `storage.postgresUrlPath`: `/run/secrets/pg-url` (rewritten by the entrypoint)
- `kms.region`: `us-east-1`
- `engine` and `evidenceSigner`: each has a `keyId` and a `kmsKeyId` (the key's ARN)
- `trustRoots`: one ACTIVE entry per signer, with the pinned public key as a JWK
- `principals`: one entry for the operator, with `apiKeyPath` = `/run/secrets/operator.key` and `scopes` = `["admin"]`

Update it with the CLI. Write the JSON to a file outside the repository, then:

```bash
aws secretsmanager put-secret-value --region us-east-1 \
  --secret-id dip/prod/config --secret-string file:///secure/path/config.json
```

Delete the local file afterwards. Every update needs a new task deployment to take effect, because secrets are read at start.

## Creating a new secret safely

Generate values in the shell and pass them straight to Secrets Manager. Do not print them.

```bash
PW=$(python3 -c 'import secrets,string; a=string.ascii_letters+string.digits; print("".join(secrets.choice(a) for _ in range(48)))')
aws secretsmanager create-secret --region us-east-1 \
  --name dip/prod/operator-key --secret-string "$PW" --query Name --output text
unset PW
```

## Retrieving the operator key

Open the console, go to **Secrets Manager → dip/prod/operator-key → Retrieve secret value**. Use it as the Bearer token. Do not paste it into tickets or chat.

## Rotating a secret

1. Create the new value with `put-secret-value`.
2. Redeploy the service (see `08-deploy.md`, "Force a new deployment").
3. Check the logs, then remove any old copies you saved.

Rotating the operator key invalidates every client that uses the old value.
