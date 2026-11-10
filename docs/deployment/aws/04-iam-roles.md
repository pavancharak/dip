# 04. IAM roles and users

There are three identities. Keep them separate.

| Identity                 | Type | Used by                           | Can do                                                         |
| ------------------------ | ---- | --------------------------------- | -------------------------------------------------------------- |
| `dip-api-signer-prod`    | Role | The running server (task role)    | Sign with the two production keys                              |
| `dip-ecs-execution-prod` | Role | ECS itself                        | Pull the image, write logs, read three DIP secrets             |
| `dip-deployer`           | User | Developers and deployment scripts | Deploy services, build images, manage DIP secrets. Cannot sign |

The running task has no access key at all: its permissions come from its role. `dip-deployer` has a long-lived access key, which should be rotated on a schedule (see `11-operations.md`). The sandbox user `dip-sandbox` also has one, and it must never be used for production.

## 1. The task role: `dip-api-signer-prod`

- **Trust:** `ecs-tasks.amazonaws.com`, through the **Elastic Container Service Task** use case.
- **Permissions:** an inline policy `dip-signing-kms`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DipSigningKeysOnly",
      "Effect": "Allow",
      "Action": ["kms:Sign", "kms:GetPublicKey"],
      "Resource": [
        "arn:aws:kms:us-east-1:<ACCOUNT_ID>:key/<ENGINE_KEY_ID>",
        "arn:aws:kms:us-east-1:<ACCOUNT_ID>:key/<EVIDENCE_KEY_ID>"
      ]
    }
  ]
}
```

- **No managed policies.** Do not attach `AdministratorAccess` or any other broad policy.

## 2. The execution role: `dip-ecs-execution-prod`

- **Trust:** `ecs-tasks.amazonaws.com`.
- **Managed policy:** `AmazonECSTaskExecutionRolePolicy`, which lets ECS pull the image and write logs.
- **Inline policy** `dip-read-secrets`: read-only access to exactly the three DIP secrets.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadDipSecretsOnly",
      "Effect": "Allow",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": [
        "arn:aws:secretsmanager:us-east-1:<ACCOUNT_ID>:secret:dip/prod/config-<SUFFIX>",
        "arn:aws:secretsmanager:us-east-1:<ACCOUNT_ID>:secret:dip/prod/pg-url-<SUFFIX>",
        "arn:aws:secretsmanager:us-east-1:<ACCOUNT_ID>:secret:dip/prod/operator-key-<SUFFIX>"
      ]
    }
  ]
}
```

Replace `<SUFFIX>` with the suffix Secrets Manager appends to each secret's ARN. Get it with `aws secretsmanager describe-secret --secret-id <NAME> --query ARN --output text`.

## 3. The deployer user: `dip-deployer`

- **Permissions:** the customer-managed policy `dip-deploy-ecs`. It allows ECS deployment, ECR image pushes, the DIP secrets, the database and its network rules, the two service-linked roles, and creating the execution role only.
- **Not allowed:** KMS signing, reading the operator key from the console, or changing another project's resources.

The current full policy document is kept in the administrator's records, not in the repository, because it names the account. Ask an administrator for the current version when you need a change.

Required statements, by purpose:

| Purpose              | Actions                                                                                                                                                                                                                                                                                  |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Run the service      | `ecs:CreateCluster`, `ecs:DescribeClusters`, `ecs:RegisterTaskDefinition`, `ecs:DescribeTaskDefinition`, `ecs:CreateService`, `ecs:UpdateService`, `ecs:DescribeServices`, `ecs:ListTasks`, `ecs:DescribeTasks`                                                                          |
| Hand roles to ECS    | `iam:PassRole` on the task role and the execution role only, with `iam:PassedToService` = `ecs-tasks.amazonaws.com`                                                                                                                                                                      |
| Networking           | `ec2:DescribeSubnets`, `ec2:DescribeSecurityGroups`, `ec2:DescribeVpcs`, `ec2:CreateSecurityGroup`, `ec2:AuthorizeSecurityGroupIngress`                                                                                                                                                  |
| Logs                 | `logs:CreateLogGroup`, `logs:DescribeLogGroups`, `logs:DescribeLogStreams`, `logs:GetLogEvents`                                                                                                                                                                                          |
| Images               | `ecr:CreateRepository`, `ecr:DescribeRepositories`, `ecr:GetAuthorizationToken`, `ecr:BatchCheckLayerAvailability`, `ecr:BatchGetImage`, `ecr:DescribeImages`, `ecr:GetDownloadUrlForLayer`, `ecr:InitiateLayerUpload`, `ecr:UploadLayerPart`, `ecr:CompleteLayerUpload`, `ecr:PutImage` |
| Secrets              | `secretsmanager:CreateSecret`, `secretsmanager:DescribeSecret`, `secretsmanager:PutSecretValue`, `secretsmanager:GetSecretValue`                                                                                                                                                         |
| Database             | `rds:CreateDBInstance`, `rds:DescribeDBInstances`, `rds:CreateDBSubnetGroup`, `rds:DescribeDBSubnetGroups`, `rds:AddTagsToResource`, `rds:RemoveTagsFromResource`                                                                                                                        |
| Service-linked roles | `iam:CreateServiceLinkedRole` for `rds.amazonaws.com` and for `ecs.amazonaws.com` only                                                                                                                                                                                                   |
| Execution role       | `iam:CreateRole`, `iam:GetRole`, `iam:AttachRolePolicy`, `iam:PutRolePolicy` on `dip-ecs-execution-prod` only                                                                                                                                                                            |

Scope every `Resource` to the DIP names where AWS supports it. The inline statements above use `*` only where the action has no resource-level permission.

## Creating a service-linked role

ECS and RDS need their service-linked roles once per account. If `CreateService` says it cannot assume the service-linked role, create it:

```bash
aws iam create-service-linked-role --aws-service-name ecs.amazonaws.com
aws iam create-service-linked-role --aws-service-name rds.amazonaws.com
```

Wait about a minute before retrying. New IAM roles take a short time to become usable.
