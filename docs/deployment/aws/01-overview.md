# 01. Overview

## What runs in production

One container, the DIP API, runs as a single task on AWS Fargate. The task is the only process that signs decisions and evidence, so there is exactly one writer for the evidence chain (see ADR-0022 in `docs/ARCHITECTURE_DECISIONS.md`).

```
Client ──HTTP──▶ [ECS task: dip-api]  ──KMS Sign──▶ AWS KMS (engine and evidence keys)
                       │
                       ├──SQL (TLS)──▶ [RDS PostgreSQL: dip-postgres]
                       │
                       └──reads──▶ [Secrets Manager: config, DB URL, operator key]
```

## Pieces and what they do

| Piece                     | Name                                                                                | Purpose                                                                                    |
| ------------------------- | ----------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| KMS key                   | `dip-engine-prod`                                                                   | Signs authorization decisions                                                              |
| KMS key                   | `dip-evidence-prod`                                                                 | Signs evidence records                                                                     |
| IAM role (task role)      | `dip-api-signer-prod`                                                               | What the running server may do: sign with the two keys                                     |
| IAM role (execution role) | `dip-ecs-execution-prod`                                                            | What ECS may do on the server's behalf: pull the image, write logs, read the three secrets |
| IAM user                  | `dip-deployer`                                                                      | Used by people and scripts to deploy. It cannot sign with production keys                  |
| ECR repository            | `dip-api`                                                                           | Holds the container images, tagged by commit                                               |
| ECS cluster               | `dip-prod`                                                                          | Groups the service                                                                         |
| ECS service               | `dip-api`                                                                           | Keeps one task running                                                                     |
| Log group                 | `/ecs/dip-api`                                                                      | Container output                                                                           |
| RDS instance              | `dip-postgres`                                                                      | PostgreSQL 16, private, in the default VPC                                                 |
| Security groups           | `dip-db`, `dip-api-service`                                                         | Database accepts port 5432 only from the service                                           |
| Secrets                   | `dip/prod/config`, `dip/prod/pg-url`, `dip/prod/operator-key`, `dip/prod/db-master` | Configuration and credentials                                                              |

## Why it is built this way

- **Keys never leave KMS.** The server asks KMS to sign and never sees the private key.
- **Startup refuses bad keys.** At start, the server compares each KMS public key with the trust root pinned in the configuration. A mismatch stops startup.
- **Secrets are not in the image.** The container reads them from Secrets Manager at start and keeps them in memory-backed files.
- **One task.** More than one writer would break the single evidence chain. Scaling out is a design change, not a setting.

## Known gaps (as of this writing)

- **No public entry point.** The service has no load balancer, and its security group allows no inbound traffic. Nothing outside the VPC can call the API yet. Adding an Application Load Balancer is the next step.
- **Log retention is not set.** The deployer may not change log-group retention. Ask an administrator to set 30 days on `/ecs/dip-api`.
- **Backup retention is 1 day.** This is the free-plan limit. Raise it when the account is on a paid plan.
- **Storage encryption is not confirmed.** The database was created without an explicit encryption flag. Check it (see `06-database.md`).
