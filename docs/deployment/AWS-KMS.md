# Running the server with AWS KMS keys

Status: guide. The server path was verified once against a sandbox key (see docs/KEY-MANAGEMENT.md section 10). The IAM policies below have not yet been applied to a production account.

## What the server needs from AWS

Two KMS keys, both Ed25519 (`ECC_NIST_EDWARDS25519`, `SIGN_VERIFY`):

- the **engine** key, which signs decisions;
- the **evidence** key, which signs ledger entries.

The server calls exactly two operations on these keys: `kms:Sign` (with `RAW` messages and `ED25519_SHA_512`) and `kms:GetPublicKey`. At startup it calls `GetPublicKey` and refuses to start unless the result matches the trust root pinned in configuration.

## Credentials: use a role, never access keys

The server reads credentials from the AWS SDK default chain. In production, that chain should resolve to an IAM role attached to the workload (an ECS task role, an EC2 instance profile, or an EKS IAM role for service accounts). No access key should be stored in configuration, in the environment, or in a container image.

Do not put `AWS_ACCESS_KEY_ID` or `AWS_SECRET_ACCESS_KEY` in the production environment. The `dip-sandbox` user used for testing is for sandbox work only and should be deleted or rotated before any production use.

### Role trust policy (example: ECS tasks)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "ecs-tasks.amazonaws.com" },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

### Role permissions (least privilege)

Replace the key ARNs with the production key ARNs. Do not use `"Resource": "*"`.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DipSigningKeysOnly",
      "Effect": "Allow",
      "Action": ["kms:Sign", "kms:GetPublicKey"],
      "Resource": [
        "arn:aws:kms:us-east-1:ACCOUNT_ID:key/ENGINE_KEY_ID",
        "arn:aws:kms:us-east-1:ACCOUNT_ID:key/EVIDENCE_KEY_ID"
      ]
    }
  ]
}
```

The role gets no `kms:Create*`, `kms:Schedule*`, `kms:Disable*`, or `kms:PutKeyPolicy` permissions. Key lifecycle is an operator task, performed with a separate, more restricted identity.

## Key policy

The KMS key policy must also allow the role. An IAM policy alone is not enough if the key policy does not name the principal. Keep the key administrators separate from the role that signs.

## Configuration

```json
{
  "engine": {
    "keyId": "engine-1",
    "kmsKeyId": "arn:aws:kms:us-east-1:ACCOUNT_ID:key/ENGINE_KEY_ID"
  },
  "evidenceSigner": {
    "keyId": "evidence-1",
    "kmsKeyId": "arn:aws:kms:us-east-1:ACCOUNT_ID:key/EVIDENCE_KEY_ID"
  },
  "kms": { "region": "us-east-1" }
}
```

The `keyId` values must match the ACTIVE trust roots, and each trust root's public key must equal the KMS key's public key. Otherwise the server refuses to start with `SIGNER_KEY_MISMATCH`.

## Failure behaviour

- If `kms:Sign` is denied, the request fails with a 500 and no decision is issued. The engine never returns ALLOW without a signature (covered by the signing-failure tests).
- If the server cannot read the public key at startup, it refuses to start with `KMS_PUBLIC_KEY_FAILED`.

## Before production

1. Create the production keys with the tag `project=dip-production` or your organization's equivalent, and record their ARNs.
2. Pin the production public keys as ACTIVE trust roots.
3. Attach the role and the key policy above. Confirm with a sign-and-verify run before routing traffic.
4. Run the IAM denial drill in the production account using a separate identity, and confirm the engine returns no ALLOW.
5. Rotate or delete the sandbox access key.
