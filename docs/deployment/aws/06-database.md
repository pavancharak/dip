# 06. Database

## What exists

| Item                | Value                                                               |
| ------------------- | ------------------------------------------------------------------- |
| Instance            | `dip-postgres`                                                      |
| Engine              | PostgreSQL 16                                                       |
| Class and storage   | `db.t4g.micro`, 20 GB, gp3                                          |
| Network             | Default VPC, subnet group `dip-db-subnets`, not publicly accessible |
| Security group      | `dip-db`: no inbound rules except port 5432 from `dip-api-service`  |
| Master user         | `dipadmin` (password in `dip/prod/db-master`)                       |
| Backups             | 1 day (free-plan limit)                                             |
| Deletion protection | On                                                                  |
| Tags                | `project=dip-production`                                            |

The application connects as the master user through the URL in `dip/prod/pg-url`. Create a dedicated application user for production when the account plan allows it, and update the URL secret.

## Encryption at rest

The instance was created without an explicit `--storage-encrypted` flag. Check it:

```bash
aws rds describe-db-instances --region us-east-1 --db-instance-identifier dip-postgres \
  --query 'DBInstances[0].StorageEncrypted' --output text
```

If it prints `False`, encryption cannot be turned on in place. Plan a snapshot-and-restore into an encrypted instance.

## Encryption in transit

The server connects with TLS. `sslmode=require` is treated as full verification by the driver, so the AWS RDS CA bundle must be trusted. It ships in the image at `/app/rds-global-bundle.pem`, and `NODE_EXTRA_CA_CERTS` points at it. The bundle is public, from `https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem`. Refresh it when AWS publishes a new one.

## Network rules

- The database accepts port 5432 only from the `dip-api-service` security group.
- Nothing else reaches it: not the internet, not other security groups, not your laptop.
- To run a one-off query from your machine, use a bastion or the ECS Exec path your administrator has approved. Do not open port 5432 to your IP.

## Connecting for maintenance

Get the password from Secrets Manager inside your shell, without printing it, and connect with `psql` from a host inside the VPC. Do not write the password in shell history.

## Schema

The application applies its own schema at start (`migrate` in `packages/storage/src/schema.ts`). The migration is idempotent. There is no separate migration step to run by hand.
