# Threat Model

Status: reviewed against the implementation at the time of writing. Every threat lists its test, or says that none exists. "Residual" means what remains after the mitigation. This document is not a security review by an independent party.

Protocol guarantees are distinct from infrastructure, identity, operations and application responsibilities. Each entry states which applies.

## Assets

- Authority declarations and their signing keys.
- Approval records.
- The execution boundary and the connectors behind it.
- The evidence ledger and its signing key.
- Tenant data.

## Threats

### T1 Forged authority declaration

- **Scenario:** an attacker publishes a declaration granting itself a large limit.
- **Preconditions:** the attacker can call the API with a valid API key.
- **Impact:** unauthorized execution within the forged limits.
- **Mitigation:** declarations must carry an Ed25519 signature from a trusted issuer key. The registry rejects unknown keys, bad signatures and tampered bodies.
- **Residual:** a compromised trusted issuer key can still issue valid declarations (see T9).
- **Test:** `packages/conformance/test/adversarial.test.ts` ("a forged authority…"); `packages/authority/test/authority.test.ts`.

### T2 Unauthorized actor

- **Scenario:** a principal acts for an authority it was not named on.
- **Mitigation:** the engine checks the actor against the principal and agent named in the authority.
- **Residual:** who the principal is comes from the issuer's declaration. The protocol does not verify identity beyond the API key.
- **Test:** `packages/authorization/test/authorization.test.ts` (ACTOR_NOT_AUTHORIZED).

### T3 Policy manipulation

- **Scenario:** a policy version is changed after a decision so that the decision appears to satisfy a different policy.
- **Mitigation:** decisions and evidence carry the exact policy identifier and version. Requests must reference the authority's policy version; the verifier checks the policy reference against the authority.
- **Residual:** the policy's contents live outside the protocol. The protocol binds to a version, not to what the version says.
- **Test:** POLICY_VERSION_MISMATCH in the authorization tests; the verifier's AUTHORITY check.

### T4 Request tampering

- **Scenario:** an approved or authorized request is altered between authorization and execution.
- **Mitigation:** the digest covers the canonical request body. The boundary recomputes it and refuses any mismatch.
- **Residual:** `approvalRef` is excluded from the digest by design (ADR-0015).
- **Test:** `packages/execution/test/execution.test.ts` (REQUEST_DIGEST_MISMATCH); `packages/conformance/test/adversarial.test.ts` (substitution).

### T5 Replay of an authorization

- **Scenario:** an ALLOW decision is submitted again to execute twice.
- **Mitigation:** a decision is consumed before the connector runs. Replays are refused, and the completed result is returned for an identical idempotency key. The consumed set is journaled and survives restarts.
- **Residual:** replay protection is per process only if the server runs without `storage.dataDir`.
- **Test:** `adversarial.test.ts` ("replayed after execution"); `apps/api/test/durable.test.ts` (replay after restart).

### T6 Approval substitution

- **Scenario:** an approval for one request is attached to a different request.
- **Mitigation:** an approval is bound to the request digest, organization, authority version and policy version. Any change fails the binding check.
- **Residual:** requests with identical content can share an approval, which is intended.
- **Test:** `adversarial.test.ts` ("an approval for one request…"); the approval-workflow tests in `authorization.test.ts`.

### T7 Approval replay

- **Scenario:** an approver's decision is submitted again, or the approval is used after it expired or was revoked.
- **Mitigation:** each approval accepts one terminal transition. Decisions outside the approval window are refused, and the engine re-checks the state at evaluation and execution time.
- **Residual:** an approver who keeps a valid signing key can approve again only for a new approval record.
- **Test:** `adversarial.test.ts` ("cannot be decided twice", "outside the approval window").

### T8 Signature forgery

- **Scenario:** a valid signature is re-encoded to pass a string-based check, or a signature from another key is presented.
- **Mitigation:** Ed25519 verification under the trust root. Non-canonical base64url encodings are rejected.
- **Residual:** the Ed25519 implementation is Node's. Its correctness is assumed.
- **Test:** `packages/crypto/test/domain.test.ts` (malleability); `adversarial.test.ts` (non-canonical encoding).

### T9 Key compromise

- **Scenario:** a signing key (issuer, engine, evidence or approver) is stolen.
- **Mitigation:** keys are set to REVOKED in the trust roots, and every object they signed then fails verification. Keys are never committed (`.gitignore` covers key files).
- **Residual:** before revocation, a stolen key can create valid records. Records already made stay valid until they are checked against the revoked key. No KMS or HSM protection is implemented (see R-05).
- **Test:** `packages/authority/test/authority.test.ts` (revoked key); `packages/verifier/test/verifier.test.ts` (revoked signing key).

### T10 Key rotation error

- **Scenario:** a key is removed from the trust roots while records it signed still need checking, or a new key is added with the wrong identifier.
- **Mitigation:** the trust roots are explicit. Rotation adds a key and keeps the old one ACTIVE until its records are no longer needed. Duplicate key identifiers are refused.
- **Residual:** no tooling enforces the rotation procedure. It is documented in `docs/deployment/README.md`.
- **Test:** `packages/authority/test/authority.test.ts` (duplicate trust root); the verifier's UNVERIFIABLE check for unknown keys.

### T11 Ledger deletion

- **Scenario:** evidence records are removed from the ledger.
- **Mitigation:** the hash chain and sequence numbers detect a missing entry. The database triggers reject DELETE and TRUNCATE.
- **Residual:** deleting the tail of the chain is undetectable without an external anchor of the head. Operators must record the head outside the system.
- **Test:** `packages/ledger/test/ledger.test.ts` and `adversarial.test.ts` (deletion, truncation with an anchor); `packages/storage/test/storage.test.ts` (triggers, deletion with triggers disabled).

### T12 Ledger modification

- **Scenario:** a stored evidence record is edited.
- **Mitigation:** each entry is signed and linked to its predecessor. Modification fails the signature and chain checks.
- **Residual:** a party with the evidence key can re-sign. Protect that key (T9).
- **Test:** `adversarial.test.ts` (modified recorded time); `apps/api/test/durable.test.ts` (altered stored record refuses startup).

### T13 Cross-tenant access

- **Scenario:** a principal reads another tenant's authority or evidence.
- **Mitigation:** request and authority operations check the tenant. Evidence reads are limited to the owning tenant; other tenants receive 404, which does not reveal that the record exists.
- **Residual:** the ledger listing (`GET /v1/ledger`) is admin-only and shows all tenants. The protocol does not isolate tenants at the storage layer.
- **Test:** `apps/api/test/api.test.ts` (cross-tenant authorize and evidence reads); `apps/api/test/durable.test.ts`.

### T14 Connector bypass

- **Scenario:** code calls a connector directly, skipping authorization.
- **Mitigation:** the server exposes execution only through the boundary, and connectors are wired in code. Connectors hold no authorization logic.
- **Residual:** in-process code can call a connector's `execute` directly. JavaScript offers no isolation for this. This is a deployment and code-review control, not a protocol guarantee.
- **Test:** `packages/connectors/test/connectors.test.ts` (DENY never reaches the transport).

### T15 Time manipulation

- **Scenario:** a decision is dated in the future to extend its life, or an old decision is replayed much later.
- **Mitigation:** decisions dated in the future are refused, and decisions older than the freshness window are refused. The authority is re-checked at execution time.
- **Residual:** the server clock is trusted. Clock drift or manipulation of the host clock is not defended against.
- **Test:** `adversarial.test.ts` ("dated in the future", "older than the freshness window").

### T16 Duplicate execution

- **Scenario:** a retry or a race executes the same action twice.
- **Mitigation:** idempotency keys, in-flight tracking, and a completed-result cache, all journaled.
- **Residual:** a connector that does not honour the idempotency key can still duplicate an action externally. Connectors must pass the key through.
- **Test:** `packages/execution/test/execution.test.ts` (duplicate, conflict, retry); `apps/cli/test/cli.test.ts` (execute once).

### T17 Privilege escalation

- **Scenario:** a principal without the approver or admin scope calls approval or ledger endpoints.
- **Mitigation:** scopes are checked per route, and the route table is the source of the OpenAPI description, so the documentation matches the check.
- **Residual:** scopes are fixed in the configuration file. There is no role management.
- **Test:** `apps/api/test/api.test.ts` (approval scope, ledger admin scope).

### T18 Partial execution failure

- **Scenario:** the connector fails halfway, times out, or returns a success without a reference.
- **Mitigation:** each is recorded as FAILED or TIMED_OUT. A success without a reference is a failure. Timeouts are not claimed as success or failure.
- **Residual:** a timed-out action may have happened externally. Resolving it needs reconciliation with the external system, which is not built.
- **Test:** `packages/execution/test/execution.test.ts` (failure, exception, timeout); `packages/connectors/test/connectors.test.ts` (reference missing).

### T19 Database compromise

- **Scenario:** an attacker with database access edits or deletes rows, or disables triggers.
- **Mitigation:** the chain and signatures detect edits and deletions. The server refuses to start on a broken chain.
- **Residual:** an attacker who also holds the evidence key can rewrite the chain consistently. Anchoring the head outside the database limits this (see T11).
- **Test:** `packages/storage/test/storage.test.ts` ("trigger disabled" cases); `apps/api/test/durable.test.ts`.

### T20 Malicious integrations

- **Scenario:** a connector or an external system returns false results.
- **Mitigation:** results are recorded as the connector reported them. The generic HTTP connector allows only HTTPS to allowlisted hosts. Money comes from the authorized amount.
- **Residual:** the protocol records what the connector claimed, not what happened. Verification of external outcomes needs the external system.
- **Test:** `packages/connectors/test/connectors.test.ts` (allowlist, amount mismatch).

### T21 Trust-root compromise

- **Scenario:** an attacker changes the trust roots the verifier or server uses.
- **Mitigation:** trust roots are supplied by the operator and are never read from a bundle. The server refuses to start without valid roots.
- **Residual:** whoever controls the trust-root file controls what is trusted. Protect the configuration file (see deployment docs).
- **Test:** `packages/verifier/test/verifier.test.ts` (wrong key, revoked key, bundle without trust roots); `apps/api/test/config.test.ts`.

## Summary of residual risks

- Records signed with a compromised key remain valid until the key is revoked.
- Tail truncation needs an external head anchor.
- In-process code can bypass a connector's authorization path.
- Connector outcomes are only as reliable as the connector's reports.
- No external security review has been performed.
