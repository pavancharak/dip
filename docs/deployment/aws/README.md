# DIP on AWS: developer guide

This folder explains how the DIP API runs in production on AWS, and how to set it up or change it. Read the files in order the first time.

| File                                           | What it covers                                                 |
| ---------------------------------------------- | -------------------------------------------------------------- |
| [01-overview.md](01-overview.md)               | What runs where, and why                                       |
| [02-prerequisites.md](02-prerequisites.md)     | Tools, accounts and access you need                            |
| [03-kms-keys.md](03-kms-keys.md)               | The two signing keys and their key policies                    |
| [04-iam-roles.md](04-iam-roles.md)             | The roles the service and the deployer use                     |
| [05-secrets.md](05-secrets.md)                 | Secrets Manager: what is stored and how the container reads it |
| [06-database.md](06-database.md)               | The PostgreSQL database and its network rules                  |
| [07-build-and-push.md](07-build-and-push.md)   | Building the container image and pushing it to ECR             |
| [08-deploy.md](08-deploy.md)                   | Task definition, cluster, service and logs                     |
| [09-verify.md](09-verify.md)                   | Checking that a deployment works                               |
| [10-troubleshooting.md](10-troubleshooting.md) | Errors we have seen, and their fixes                           |
| [11-operations.md](11-operations.md)           | Routine tasks: rotation, scaling, cost, cleanup                |

## Conventions used in these files

- `<ACCOUNT_ID>`, `<REGION>`, and ARNs in angle brackets are placeholders. Replace them with your values. Do not commit real account IDs or ARNs to this public repository.
- The region is `us-east-1` throughout.
- Every production resource is tagged `project=dip-production`.
- Secret values never appear in commands, logs, chat, or the repository. Store them in Secrets Manager and read them there.

## Related files

- `docs/deployment/AWS-KMS.md`: the original KMS notes, kept for history.
- `docs/deployment/ENVIRONMENT.md`: every environment variable the server reads.
- `docs/deployment/config.example.json`: the shape of the server's configuration file.
- `docs/KEY-MANAGEMENT.md`: the key-management plan and the sandbox test results.
