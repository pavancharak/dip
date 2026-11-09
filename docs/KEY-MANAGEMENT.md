# Key Management Plan

Status: **adapter built, and sandbox checks run against real AWS KMS** (see section 10). The signing interface, a local provider, and `AwsKmsSigningProvider` (`packages/kms`) exist and are tested. The sandbox run confirmed the signing parameters and the `GetPublicKey` format. Section 7 items not yet run: the access-denied drill and the rotation procedure from section 5 as a documented runbook.

## 10. Sandbox results (AWS account, us-east-1)

Run with an IAM user limited to KMS on keys tagged `project=dip-sandbox`.

| Check                                                          | Result                                                                                                  |
| -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| Create `ECC_NIST_EDWARDS25519` / `SIGN_VERIFY` key             | Passed. Signing algorithms offered: `ED25519_SHA_512`, `ED25519_PH_SHA_512`                             |
| `GetPublicKey` format                                          | Passed. DER SubjectPublicKeyInfo, 44 bytes, Ed25519 OID. Confirms the adapter assumption                |
| Sign a DIP domain-separated message (`RAW`, `ED25519_SHA_512`) | Passed. 64-byte signature                                                                               |
| Protocol verifier accepts the real KMS signature               | Passed. A tampered canonical body is rejected                                                           |
| Revocation: sign after `DisableKey`                            | Passed. Refused with `DisabledException`. The adapter maps this to `KMS_SIGN_FAILED` (unit-tested)      |
| Rotation: new key, old and new public keys differ              | Passed. Each key signs independently                                                                    |
| Cleanup                                                        | Both test keys scheduled for deletion after a 30-day window (the maximum), so the sandbox can be re-run |

Not run: the denied-`kms:Sign` drill against Parmana's own key. That needs a key outside the sandbox tag, and the engine refusal behavior from section 7 item 4 still needs an end-to-end test.

## 1. Why this matters

Every trust in DIP rests on private keys: issuers sign authority, the engine signs decisions, the evidence signer signs the ledger, and approvers sign approvals. A stolen key lets someone produce records the system will accept until the key is revoked (threat T9 in [THREAT-MODEL.md](THREAT-MODEL.md)). Keys held as files on a server are the largest single risk to the protocol's guarantees.

## 2. Requirements

1. **Non-exportable keys.** Production private keys never leave the key service. Signing happens inside it.
2. **Separation of duties.** Each role has its own key: issuer, engine, evidence signer, each approver. No role can sign as another.
3. **Least privilege.** The service that signs decisions can sign with the engine key only. It cannot read the evidence key or change trust roots.
4. **Auditable use.** Every signature is logged by the key service, with the caller and time.
5. **Rotation without downtime.** A new key can be added to the trust roots before it is used, and the old key stays valid for records it signed.
6. **Fast revocation.** Revoking a key in the trust roots invalidates everything it signed (section 5).
7. **Fail closed.** If the key service is unavailable, the engine must not produce ALLOW decisions, because they could not be signed. Execution stops.
8. **Ed25519 support.** The protocol uses Ed25519. The key service must support it for signing.

## 3. Architecture

Protocol code signs through the `SigningProvider` interface in `@dip/crypto`:

```ts
interface SigningProvider {
  readonly keyId: string;
  publicJwk(): Promise<Ed25519PublicJwk>;
  sign(message: Uint8Array): Promise<Uint8Array>; // pure Ed25519 over domain-separated bytes
}
```

Providers:

| Provider               | Status           | Use                                                                 |
| ---------------------- | ---------------- | ------------------------------------------------------------------- |
| `LocalSigningProvider` | Built and tested | Development and tests. Holds the key in memory. Not for production. |
| Cloud KMS provider     | Not built        | Production. Keys are non-exportable.                                |
| HSM provider           | Not planned yet  | Only if a customer requires it. Same interface.                     |

Where the engine, the evidence signer and the approval code call `sign` today with local keys, the cloud provider replaces the key object. The protocol code and the signed formats do not change. The move from synchronous to asynchronous signing affects the engine, the boundary and the evidence path, and must be done in one change with the tests updated.

## 4. Cloud KMS adapter (to build)

Planned for AWS KMS. Items marked **verify** must be checked against current AWS documentation before implementation.

- **Key type:** asymmetric, `ECC_NIST_EDWARDS25519` (Ed25519). **Verify** that the signing algorithm and message type match pure Ed25519 over the full message (`RAW` message type), so that signatures verify with the protocol's verifier unchanged.
- **Public key:** retrieved once with `GetPublicKey`, converted to a raw 32-byte key and then to JWK for the trust roots.
- **Signing:** `Sign` with the key identifier, the message as raw bytes, and `MessageType` `RAW`. The provider checks that the returned signature is 64 bytes.
- **Failure handling:** throttling and transient errors are retried with a bounded backoff. Any other error fails the signing call. The caller refuses the operation. No fallback to a local key.
- **Latency:** each signature is a network call. Measure it in the target region. Decisions and evidence are signed per request, so this is on the request path. Batching evidence is an option to evaluate, not a current design.

## 5. Lifecycle

**Generation.** Create each key in the key service, with a description naming its role and owner. Record its identifier and public key in the trust roots, with status `ACTIVE`. Never generate keys in application code for production.

**Use.** The service identity has `kms:Sign` on its key and `kms:GetPublicKey` if needed. It has no other key permissions.

**Rotation.** Create a new key. Add its public key to the trust roots as `ACTIVE`. Switch signing to the new key. Keep the old key `ACTIVE` in the trust roots for as long as records it signed must still be verified. Then retire it (disable signing in the key service) without revoking it, if verification of its records must continue.

**Revocation.** If a key is compromised, set its trust root to `REVOKED`. Every record it signed then fails verification (intended). Disable the key in the key service. Investigate the records it signed, using the audit trail, to decide what to do with actions taken under the compromised key.

**Retirement.** After records are archived or no longer needed, schedule the key for deletion according to the key service's waiting period. Keep the public key in the trust roots as `REVOKED` so old records are still identified correctly.

## 6. Access and audit

- Separate AWS roles for: the engine service, the evidence service, each approver's signing tool, and the operators who manage trust roots. No role has more than one of these.
- Enable CloudTrail (or the equivalent) for the key service, and alert on any signing by an unexpected role, and on any key policy change.
- Key policies deny all principals except the listed roles. Changes to key policies require two people (enforced by process, and by alerting).
- Approver keys should be held by the approver's own tooling, or by a per-approver key in the service. A shared approver key defeats the approval design.

## 7. Testing plan

1. **Unit tests** (done for the interface): the provider contract, rejection of malformed signatures, domain separation.
2. **Adapter tests with a fake KMS client**: the request shape, retry behaviour, error propagation, the check that a 64-byte signature is returned.
3. **Sandbox tests against real KMS** in a non-production AWS account: create an Ed25519 key, sign, verify the signature with the protocol's verifier, rotate, revoke, and confirm that a revoked key's records fail verification. These need credentials (section 8).
4. **Failure drills**: deny `kms:Sign` and confirm the engine refuses to decide ALLOW and the boundary refuses to execute. Confirm no unsigned decision is ever accepted.
5. **Latency measurement** in the target region, recorded in the implementation matrix.

## 8. Decisions and inputs needed from you

1. **Provider.** AWS KMS, or another provider? If AWS: which account, which region, and whether one account per environment is acceptable.
2. **Credentials for sandbox testing.** A role with permission to create and use Ed25519 keys in a non-production account. Please do not paste long-lived access keys into the chat. Use a role the test environment can assume.
3. **Key ownership.** Who holds the issuer, engine, evidence and approver roles, and who may change trust roots.
4. **Approver keys.** Whether approvers use KMS keys, or sign with their own devices. This changes the approval workflow's key distribution.
5. **HSM requirement.** Whether any customer needs an HSM. Not needed for the first production release if KMS is accepted.

## 9. Acceptance criteria for "KMS-held keys"

- Every production role signs through a KMS provider, and no private key for a production role exists on any server.
- The sandbox tests in section 7 pass against real KMS, and their results are recorded in `docs/IMPLEMENTATION_MATRIX.md`.
- The failure drills pass: a key service outage stops decisions and execution.
- The rotation and revocation procedures in section 5 have been carried out once in the sandbox.
- The access policies in section 6 are in place and reviewed.
