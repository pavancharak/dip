# 02. Prerequisites

## Accounts and access

- An AWS account with the production resources in region `us-east-1`. The account must be on a plan that allows what you deploy. The free plan limits backup retention to 1 day.
- A GitHub account with write access to `pavancharak/dip`.
- An administrator who can create IAM users and roles, and who can edit KMS key policies. Developers usually do not have these rights.

## Tools on your machine

| Tool                 | Why                               | Check                              |
| -------------------- | --------------------------------- | ---------------------------------- |
| AWS CLI v2           | Deploy and inspect resources      | `aws --version`                    |
| Docker (with buildx) | Build the image for `linux/amd64` | `docker version`                   |
| Node.js 22 and pnpm  | Build and test the code           | `node --version`, `pnpm --version` |
| Git                  | Branches and pull requests        | `git --version`                    |

Install the AWS CLI from the official AWS instructions. Do not use an older package from a system repository.

## Configure the CLI with the deployer identity

Use the `dip-deployer` identity for deployment work. Do not use the `dip-sandbox` identity or any administrator identity for routine deployment.

```bash
aws configure --profile dip-deployer
# AWS Access Key ID: <the deployer key ID>
# AWS Secret Access Key: <the deployer secret>
# Default region name: us-east-1
# Default output format: json
export AWS_PROFILE=dip-deployer
```

Confirm which identity you are using:

```bash
aws sts get-caller-identity --region us-east-1
```

The `Arn` should end in `user/dip-deployer`. If it does not, stop and fix the profile before you deploy anything.

## Things to never do

- Do not paste keys or secrets into chat, tickets, or the repository.
- Do not use `dip-sandbox` credentials against production resources. Its policy is limited to sandbox-tagged keys, so it will be refused anyway.
- Do not set `AWS_ACCESS_KEY_ID` inside the container. The running task gets its permissions from its role.
