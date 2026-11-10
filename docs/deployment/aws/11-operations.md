# 11. Operations

## Routine checks

| Check                 | How often | Command or place                               |
| --------------------- | --------- | ---------------------------------------------- |
| Service running       | Daily     | `describe-services` (see `09-verify.md`)       |
| Logs free of errors   | Daily     | Log group `/ecs/dip-api`                       |
| Database available    | Weekly    | `describe-db-instances`                        |
| Backups exist         | Weekly    | Database console, Automated backups            |
| Deployer key age      | Quarterly | IAM, `dip-deployer`, Security credentials      |
| RDS CA bundle current | Yearly    | Refresh `deployment/aws/rds-global-bundle.pem` |

## Rotating the deployer access key

1. Create a second access key for `dip-deployer`.
2. Store it in your environment, and check the new identity with `aws sts get-caller-identity`.
3. Deactivate the old key, confirm deployments still work, then delete it.

## Costs

The main recurring costs are the database instance, its storage and backups, the Fargate task, KMS keys (about $1 per key per month), and ECR storage. Check the **Billing** console monthly. On the free plan, credits cover this setup for a while, and it ends when they run out.

## Scaling

The service runs one task on purpose. The evidence chain has one writer (ADR-0022). Do not raise the desired count without first reading that decision. Rate limits are shared through the database, so they hold across tasks, but the signing path is still single-writer.

## Cleaning up a test environment

Sandbox resources are not production. To remove them:

1. Scale the service to 0, then delete it and the cluster.
2. Schedule test KMS keys for deletion (30 days is the maximum window).
3. Delete the test secrets with a recovery window, not an immediate delete.
4. Delete the database only after taking a final snapshot, and only after deletion protection is turned off by an administrator.

Never delete a production KMS key that signed evidence.

## Backups and restore

RDS keeps automated backups for the retention period. To restore, use **Restore to point in time** into a new instance, check it, then point the `pg-url` secret at it and force a new deployment. Do not overwrite the existing instance.

## Who to ask

- IAM changes and new roles: an AWS administrator
- Key policy changes: an AWS administrator
- Code changes and deployment decisions: the project owner, through a pull request
