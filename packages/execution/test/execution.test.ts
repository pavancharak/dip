import { describe, expect, it } from "vitest";
import { ApprovalStore, signApprovalDecision } from "@dip/approval";
import {
  AuthorityRegistry,
  TrustRootSet,
  parseAuthorityBody,
  signAuthority,
  type AuthorityBody,
} from "@dip/authority";
import {
  evaluate,
  normalizeRequest,
  type EvaluationContext,
  type NormalizedRequest,
  type SignedDecision,
} from "@dip/authorization";
import {
  canonicalize,
  exportEd25519PublicJwk,
  generateSigningKeyPair,
  type SigningKeyPair,
} from "@dip/crypto";
import { ExecutionBoundary, type Connector, type ConnectorResult } from "../src/index.js";

const NOW = new Date("2026-06-01T12:00:00Z");
const PAISE_40K = 4_000_000;
const PAISE_80K = 8_000_000;

interface World {
  trust: TrustRootSet;
  issuer: SigningKeyPair;
  engine: SigningKeyPair;
  approver: SigningKeyPair;
  registry: AuthorityRegistry;
  approvals: ApprovalStore;
  ctx: EvaluationContext;
}

function world(now: Date = NOW): World {
  const issuer = generateSigningKeyPair();
  const engine = generateSigningKeyPair();
  const approver = generateSigningKeyPair();
  const trust = new TrustRootSet();
  trust.add({
    keyId: "issuer-key-1",
    jwk: exportEd25519PublicJwk(issuer.publicKey),
    status: "ACTIVE",
  });
  trust.add({
    keyId: "approver-key-1",
    jwk: exportEd25519PublicJwk(approver.publicKey),
    status: "ACTIVE",
  });
  trust.add({ keyId: "engine-1", jwk: exportEd25519PublicJwk(engine.publicKey), status: "ACTIVE" });
  const registry = new AuthorityRegistry(trust);
  const approvals = new ApprovalStore(trust);
  const ctx: EvaluationContext = {
    registry,
    now: () => now,
    signer: { keyId: "engine-1", privateKey: engine.privateKey },
    approvals,
  };
  return { trust, issuer, engine, approver, registry, approvals, ctx };
}

function authorityBody(overrides: Partial<AuthorityBody> = {}): AuthorityBody {
  return parseAuthorityBody({
    authorityId: "auth-vendor-payments",
    version: 1,
    organizationId: "org-acme",
    tenantId: "tenant-1",
    issuer: "cfo-office",
    principal: "cfo",
    agent: "payments-agent",
    permittedActions: ["payment.create"],
    resourceScope: ["vendor-42"],
    maxAmountMinor: 5_000_000,
    currencies: ["INR"],
    approvalAboveMinor: null,
    approvalActions: [],
    approverKeyIds: ["approver-key-1"],
    validFrom: "2026-01-01T00:00:00Z",
    validUntil: "2027-01-01T00:00:00Z",
    delegatedFrom: null,
    delegationAllowed: false,
    policyId: "policy-payments",
    policyVersion: 1,
    protocolVersion: "1.0",
    signatureAlgorithm: "Ed25519",
    signingKeyId: "issuer-key-1",
    ...overrides,
  });
}

function requestInput(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    requestId: "req-1",
    transactionId: "txn-1",
    organizationId: "org-acme",
    tenantId: "tenant-1",
    actor: "payments-agent",
    operation: "payment.create",
    resource: "vendor-42",
    amount: { minor: PAISE_40K, currency: "INR" },
    parameters: { invoice: "INV-7" },
    authorityRef: { authorityId: "auth-vendor-payments", version: 1 },
    policyRef: { policyId: "policy-payments", version: 1 },
    approvalRef: null,
    idempotencyKey: "idem-1",
    protocolVersion: "1.0",
    ...overrides,
  };
}

function req(overrides: Record<string, unknown> = {}): NormalizedRequest {
  return normalizeRequest(requestInput(overrides));
}

function publish(w: World, body: AuthorityBody): void {
  w.registry.publish(signAuthority(body, w.issuer.privateKey));
}

function allow(w: World, input: NormalizedRequest): SignedDecision {
  return evaluate(input, w.ctx);
}

function countingConnector(
  behaviour: (n: number) => Promise<ConnectorResult> = async () => ({
    status: "SUCCEEDED",
    externalRef: "pay-001",
  }),
): { connector: Connector; calls: () => number } {
  let n = 0;
  return {
    connector: {
      id: "payments-test",
      execute: async () => {
        n += 1;
        return behaviour(n);
      },
    },
    calls: () => n,
  };
}

function boundary(
  w: World,
  connector: Connector,
  extra: { now?: Date; timeoutMs?: number; maxAge?: number; recheck?: () => string | null } = {},
): ExecutionBoundary {
  const now = extra.now ?? NOW;
  return new ExecutionBoundary({
    trust: w.trust,
    connectors: new Map([["payment.create", connector]]),
    now: () => now,
    maxDecisionAgeSeconds: extra.maxAge ?? 300,
    timeoutMs: extra.timeoutMs ?? 1000,
    ...(extra.recheck ? { approvalRecheck: extra.recheck } : {}),
  });
}

describe("protected execution boundary", () => {
  it("executes once when given a valid ALLOW decision", async () => {
    const w = world();
    publish(w, authorityBody());
    const input = req();
    const { connector, calls } = countingConnector();
    const b = boundary(w, connector);
    const attempt = await b.execute(input, allow(w, input));
    expect(attempt.state).toBe("SUCCEEDED");
    expect(attempt.externalRef).toBe("pay-001");
    expect(calls()).toBe(1);
  });

  it("refuses a DENY decision and never calls the connector", async () => {
    const w = world();
    publish(w, authorityBody());
    const input = req({ amount: { minor: PAISE_80K, currency: "INR" } });
    const decision = allow(w, input);
    expect(decision.body.result).toBe("DENY");
    const { connector, calls } = countingConnector();
    const attempt = await boundary(w, connector).execute(input, decision);
    expect(attempt.state).toBe("REFUSED");
    expect(attempt.reasonCode).toBe("DECISION_NOT_ALLOW");
    expect(calls()).toBe(0);
  });

  it("refuses a decision whose body was altered after signing (DENY flipped to ALLOW)", async () => {
    const w = world();
    publish(w, authorityBody());
    const input = req({ amount: { minor: PAISE_80K, currency: "INR" } });
    const denied = allow(w, input);
    const forged = { ...denied, body: { ...denied.body, result: "ALLOW" } };
    const { connector, calls } = countingConnector();
    const attempt = await boundary(w, connector).execute(input, forged);
    expect(attempt.reasonCode).toBe("DECISION_SIGNATURE_INVALID");
    expect(calls()).toBe(0);
  });

  it("refuses a decision signed by an untrusted key", async () => {
    const w = world();
    publish(w, authorityBody());
    const input = req();
    const rogue = generateSigningKeyPair();
    const ctx = { ...w.ctx, signer: { keyId: "engine-1", privateKey: rogue.privateKey } };
    const decision = evaluate(input, ctx);
    const { connector, calls } = countingConnector();
    const attempt = await boundary(w, connector).execute(input, decision);
    expect(attempt.reasonCode).toBe("DECISION_SIGNATURE_INVALID");
    expect(calls()).toBe(0);
  });

  it("refuses a decision signed by a revoked engine key", async () => {
    const w = world();
    publish(w, authorityBody());
    const input = req();
    const decision = allow(w, input);
    w.trust.revoke("engine-1");
    const { connector, calls } = countingConnector();
    const attempt = await boundary(w, connector).execute(input, decision);
    expect(attempt.reasonCode).toBe("DECISION_KEY_REVOKED");
    expect(calls()).toBe(0);
  });

  it("mandatory 19: a modified request cannot reuse an ALLOW decision", async () => {
    const w = world();
    publish(w, authorityBody());
    const original = req();
    const decision = allow(w, original);
    const modified = req({ amount: { minor: 4_500_000, currency: "INR" } });
    const { connector, calls } = countingConnector();
    const attempt = await boundary(w, connector).execute(modified, decision);
    expect(attempt.reasonCode).toBe("REQUEST_DIGEST_MISMATCH");
    expect(calls()).toBe(0);
  });

  it("refuses a decision for a different authority version", async () => {
    const w = world();
    publish(w, authorityBody());
    publish(w, authorityBody({ version: 2 }));
    const input = req();
    const decision = allow(
      w,
      req({ authorityRef: { authorityId: "auth-vendor-payments", version: 2 } }),
    );
    const { connector, calls } = countingConnector();
    const attempt = await boundary(w, connector).execute(input, decision);
    expect(attempt.reasonCode).toBe("REQUEST_DIGEST_MISMATCH");
    expect(calls()).toBe(0);
  });

  it("refuses a stale decision", async () => {
    const w = world();
    publish(w, authorityBody());
    const input = req();
    const decision = allow(w, input);
    const { connector, calls } = countingConnector();
    const later = new Date("2026-06-01T12:10:00Z");
    const attempt = await boundary(w, connector, { now: later, maxAge: 300 }).execute(
      input,
      decision,
    );
    expect(attempt.reasonCode).toBe("DECISION_STALE");
    expect(calls()).toBe(0);
  });

  it("mandatory 20: a replayed decision cannot execute twice", async () => {
    const w = world();
    publish(w, authorityBody());
    const input = req();
    const decision = allow(w, input);
    const { connector, calls } = countingConnector();
    const b = boundary(w, connector);
    expect((await b.execute(input, decision)).state).toBe("SUCCEEDED");
    // The decision binds the full request, including the idempotency key, so a replay can only
    // arrive with that same key. The completed action is returned, not executed again.
    const replay = await b.execute(input, decision);
    expect(replay.state).toBe("DUPLICATE");
    expect(calls()).toBe(1);
  });

  it("duplicate request with the same idempotency key returns the original result without re-executing", async () => {
    const w = world();
    publish(w, authorityBody());
    const input = req();
    const { connector, calls } = countingConnector();
    const b = boundary(w, connector);
    await b.execute(input, allow(w, input));
    const second = await b.execute(input, allow(w, input));
    expect(second.state).toBe("DUPLICATE");
    expect(second.externalRef).toBe("pay-001");
    expect(calls()).toBe(1);
  });

  it("same idempotency key with different content is a conflict", async () => {
    const w = world();
    publish(w, authorityBody());
    const first = req();
    const { connector, calls } = countingConnector();
    const b = boundary(w, connector);
    await b.execute(first, allow(w, first));
    const other = req({ parameters: { invoice: "INV-8" } });
    const attempt = await b.execute(other, allow(w, other));
    expect(attempt.reasonCode).toBe("IDEMPOTENCY_CONFLICT");
    expect(calls()).toBe(1);
  });

  it("connector failure is recorded as FAILED, not success", async () => {
    const w = world();
    publish(w, authorityBody());
    const input = req();
    const { connector } = countingConnector(async () => ({
      status: "FAILED",
      reasonCode: "BANK_REJECTED",
    }));
    const attempt = await boundary(w, connector).execute(input, allow(w, input));
    expect(attempt.state).toBe("FAILED");
    expect(attempt.reasonCode).toBe("BANK_REJECTED");
    expect(attempt.externalRef).toBeNull();
  });

  it("connector exception is recorded as FAILED with CONNECTOR_ERROR", async () => {
    const w = world();
    publish(w, authorityBody());
    const input = req();
    const { connector } = countingConnector(async () => {
      throw new Error("network reset");
    });
    const attempt = await boundary(w, connector).execute(input, allow(w, input));
    expect(attempt.state).toBe("FAILED");
    expect(attempt.reasonCode).toBe("CONNECTOR_ERROR");
  });

  it("connector timeout is recorded as TIMED_OUT, outcome not claimed", async () => {
    const w = world();
    publish(w, authorityBody());
    const input = req();
    const { connector } = countingConnector(() => new Promise<ConnectorResult>(() => undefined));
    const attempt = await boundary(w, connector, { timeoutMs: 5 }).execute(input, allow(w, input));
    expect(attempt.state).toBe("TIMED_OUT");
    expect(attempt.externalRef).toBeNull();
  });

  it("retry after failure uses a new decision and the same idempotency key", async () => {
    const w = world();
    publish(w, authorityBody());
    const input = req();
    const { connector, calls } = countingConnector(async (n) =>
      n === 1
        ? { status: "FAILED", reasonCode: "TEMPORARY" }
        : { status: "SUCCEEDED", externalRef: "pay-retry" },
    );
    let clock = NOW;
    const b = new ExecutionBoundary({
      trust: w.trust,
      connectors: new Map([["payment.create", connector]]),
      now: () => clock,
      maxDecisionAgeSeconds: 300,
      timeoutMs: 1000,
    });
    expect((await b.execute(input, allow(w, input))).state).toBe("FAILED");
    clock = new Date("2026-06-01T12:00:05Z");
    const laterCtx = { ...w.ctx, now: () => clock };
    const retry = await b.execute(input, evaluate(input, laterCtx));
    expect(retry.state).toBe("SUCCEEDED");
    expect(calls()).toBe(2);
  });

  it("refuses when no connector is registered for the operation", async () => {
    const w = world();
    publish(w, authorityBody());
    const input = req({ operation: "payment.create" });
    const b = new ExecutionBoundary({
      trust: w.trust,
      connectors: new Map(),
      now: () => NOW,
      maxDecisionAgeSeconds: 300,
      timeoutMs: 100,
    });
    expect((await b.execute(input, allow(w, input))).reasonCode).toBe("CONNECTOR_NOT_FOUND");
  });

  it("re-checks approval at execution time and refuses if it no longer holds", async () => {
    const w = world();
    publish(w, authorityBody({ approvalAboveMinor: 1_000_000 }));
    const requested = "2026-06-01T11:00:00Z";
    const digest = req().requestDigest;
    w.approvals.request(
      {
        approvalId: "appr-1",
        organizationId: "org-acme",
        requestDigest: digest,
        authorityRef: { authorityId: "auth-vendor-payments", version: 1 },
        policyRef: { policyId: "policy-payments", version: 1 },
        approverKeyId: "approver-key-1",
        requestedAt: requested,
        expiresAt: "2026-06-01T13:00:00Z",
      },
      new Date(requested),
    );
    w.approvals.decide(
      signApprovalDecision(
        {
          approvalId: "appr-1",
          action: "APPROVE",
          approverKeyId: "approver-key-1",
          decidedAt: "2026-06-01T11:30:00Z",
        },
        w.approver.privateKey,
      ),
      new Date("2026-06-01T11:30:00Z"),
    );
    const input = req({ approvalRef: "appr-1" });
    const decision = allow(w, input);
    expect(decision.body.result).toBe("ALLOW");
    w.approvals.decide(
      signApprovalDecision(
        {
          approvalId: "appr-1",
          action: "REVOKE",
          approverKeyId: "approver-key-1",
          decidedAt: "2026-06-01T11:40:00Z",
        },
        w.approver.privateKey,
      ),
      new Date("2026-06-01T11:40:00Z"),
    );
    const { connector, calls } = countingConnector();
    const b = new ExecutionBoundary({
      trust: w.trust,
      connectors: new Map([["payment.create", connector]]),
      now: () => NOW,
      maxDecisionAgeSeconds: 300,
      timeoutMs: 100,
      approvalRecheck: () =>
        w.approvals.verifyFor(
          "appr-1",
          {
            organizationId: "org-acme",
            requestDigest: digest,
            authorityRef: { authorityId: "auth-vendor-payments", version: 1 },
            policyRef: { policyId: "policy-payments", version: 1 },
            approverKeyIds: ["approver-key-1"],
          },
          NOW,
        ),
    });
    const attempt = await b.execute(input, decision);
    expect(attempt.reasonCode).toBe("APPROVAL_REVOKED");
    expect(calls()).toBe(0);
  });

  it("refuses an approval-referenced request when no approval recheck is configured", async () => {
    const w = world();
    publish(w, authorityBody());
    const input = req({ approvalRef: "appr-1" });
    const { connector, calls } = countingConnector();
    const attempt = await boundary(w, connector).execute(input, allow(w, input));
    expect(attempt.reasonCode).toBe("APPROVAL_RECHECK_UNAVAILABLE");
    expect(calls()).toBe(0);
  });

  it("records every attempt, including refusals, in order", async () => {
    const w = world();
    publish(w, authorityBody());
    const input = req();
    const decision = allow(w, input);
    const { connector } = countingConnector();
    const b = boundary(w, connector);
    await b.execute(input, decision);
    await b.execute(input, decision);
    expect(b.attempts().map((a) => a.state)).toEqual(["STARTED", "SUCCEEDED", "DUPLICATE"]);
    expect(canonicalize(b.attempts().map((a) => a.sequence))).toBe("[1,2,3]");
  });
});
