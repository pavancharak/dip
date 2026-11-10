# 03. KMS keys

The engine signs authorization decisions. The evidence key signs ledger records. Both are asymmetric Ed25519 keys that never leave KMS.

## Settings (both keys)

| Setting             | Value                                                              |
| ------------------- | ------------------------------------------------------------------ |
| Key type            | Asymmetric                                                         |
| Key usage           | Sign and verify                                                    |
| Key spec            | `ECC_NIST_EDWARDS25519` (Ed25519). Not any other ECC or RSA option |
| Key material origin | KMS                                                                |
| Regionality         | Single-Region                                                      |
| Region              | `us-east-1`                                                        |
| Alias               | `dip-engine-prod` and `dip-evidence-prod`                          |
| Tag                 | `project` = `dip-production`                                       |

Create them in the console: **Key Management Service → Customer managed keys → Create key**.

## Key policy

Each key's policy must contain two statements:

1. **Account root.** The default statement that lets the account manage the key through IAM.
2. **The workload role.** Lets `dip-api-signer-prod` sign and read the public key.

```json
{
  "Sid": "DipWorkloadSign",
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::<ACCOUNT_ID>:role/dip-api-signer-prod" },
  "Action": ["kms:Sign", "kms:GetPublicKey"],
  "Resource": "*"
}
```

Save the policy with the root statement first, then the workload statement, in one `Statement` array. If you save only the new statement, the policy becomes invalid or loses root access. Check that the editor shows no error markers before saving.

Do not name any developer identity, the sandbox user, or another project's roles as key administrators.

## Pinning the public keys

The server refuses to start unless each KMS public key matches the trust root pinned in configuration. To get a key's public key:

1. Open the key in the console.
2. Find the **Public key** section and choose **Download public key**. It is a PEM file.
3. Convert the PEM to the JWK format used in configuration. The base64 value between the PEM lines is a DER structure of 44 bytes, and the last 32 bytes are the raw key. Encode those 32 bytes as base64url (no padding) to get the `x` value.

The JWK for each key is:

```json
{ "kty": "OKP", "crv": "Ed25519", "x": "<base64url of the raw 32-byte key>" }
```

Check the PEM header before converting. It must be `BEGIN PUBLIC KEY`, and the DER must be 44 bytes starting with `302a300506032b6570032100`. Any other length or prefix means the key is not Ed25519.

## Verifying a key

With the deployer identity:

```bash
aws kms describe-key --region us-east-1 --key-id alias/dip-engine-prod \
  --query 'KeyMetadata.[KeyState,KeySpec,KeyUsage]' --output text
```

Expected: `Enabled  ECC_NIST_EDWARDS25519  SIGN_VERIFY`.

## Lifecycle rules

- Never delete a production key that signed evidence. Verification of old records needs its public key.
- Rotation means a new key with a new pinned trust root. Old records keep their old key ID.
- Deletion is scheduled with a 7 to 30 day window and can be cancelled. Use the longest window that is practical.
