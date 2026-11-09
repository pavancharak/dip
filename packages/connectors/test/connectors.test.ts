import { describe, expect, it } from "vitest";
import { ApprovalStore } from "@dip/approval";
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
  type RequestBody,
} from "@dip/authorization";
import { exportEd25519PublicJwk, generateSigningKeyPair } from "@dip/crypto";
import { ExecutionBoundary, type Connector } from "@dip/execution";
import {
  ConnectorValidationError,
  createConnector,
  crmUpdate,
  erpPost,
  genericHttpAction,
  paymentsCreate,
  payoutsCreate,
  refundsCreate,
  type ConnectorDefinition,
  type OutboundRequest,
  type Transport,
} from "../src/index.js";

const NOW = new Date("2026-06-01T12:00:00Z");

interface Fake extends Transport {
  readonly calls: (OutboundRequest & { timeoutMs: number })[];
}

function fakeTransport(status: number, body: unknown = { id: "ext-1" }): Fake {
  const calls: (OutboundRequest & { timeoutMs: number })[] = [];
  return {
    calls,
    send: async (r) => {
      calls.push(r);
      return { status, body };
    },
  };
}

function request(
  op: string,
  parameters: Record<string, unknown>,
  amountMinor: number | null = 4_000_000,
): RequestBody {
  return normalizeRequest({
    requestId: "req-1",
    transactionId: "txn-1",
    organizationId: "org-acme",
    tenantId: "tenant-1",
    actor: "payments-agent",
    operation: op,
    resource: "vendor-42",
    amount: amountMinor === null ? null : { minor: amountMinor, currency: "INR" },
    parameters,
    authorityRef: { authorityId: "auth-1", version: 1 },
    policyRef: { policyId: "policy-1", version: 1 },
    approvalRef: null,
    idempotencyKey: "idem-1",
    protocolVersion: "1.0",
  }).request;
}

function build(def: ConnectorDefinition, transport: Transport): Connector {
  return createConnector(def, { transport, timeoutMs: 1000 });
}

describe("money is taken from the authorized request", () => {
  it("payments sends the authorized amount, not a parameter that disagrees", async () => {
    const t = fakeTransport(200);
    const c = build(paymentsCreate, t);
    const bad = await c.execute(
      request("payment.create", { payeeAccount: "acc-9", amountMinor: 9_999_999 }),
      "k",
    );
    expect(bad).toEqual({ status: "FAILED", reasonCode: "AMOUNT_MISMATCH" });
    expect(t.calls).toHaveLength(0);
    const ok = await c.execute(request("payment.create", { payeeAccount: "acc-9" }), "k");
    expect(ok).toEqual({ status: "SUCCEEDED", externalRef: "ext-1" });
    expect((t.calls[0]?.body as { amountMinor: number }).amountMinor).toBe(4_000_000);
  });

  it("an operation that needs an amount refuses a request without one", async () => {
    const t = fakeTransport(200);
    const r = await build(refundsCreate, t).execute(
      request("refund.create", { paymentExternalRef: "p-1" }, null),
      "k",
    );
    expect(r).toEqual({ status: "FAILED", reasonCode: "AMOUNT_REQUIRED" });
    expect(t.calls).toHaveLength(0);
  });
});

describe("every outbound call carries the idempotency key", () => {
  it("sets Idempotency-Key on payouts, refunds, ERP and CRM", async () => {
    const cases: [ConnectorDefinition, string, Record<string, unknown>][] = [
      [payoutsCreate, "payout.create", { vendorId: "v-1" }],
      [refundsCreate, "refund.create", { paymentExternalRef: "p-1" }],
      [erpPost, "erp.post", { documentType: "INVOICE", documentId: "inv-1" }],
      [crmUpdate, "crm.update", { objectType: "deal", objectId: "d-1", fields: { stage: "won" } }],
    ];
    for (const [def, op, params] of cases) {
      const t = fakeTransport(200);
      const r = await build(def, t).execute(request(op, params), "idem-key-7");
      expect(r.status).toBe("SUCCEEDED");
      expect(t.calls[0]?.headers["Idempotency-Key"]).toBe("idem-key-7");
    }
  });
});

describe("response handling", () => {
  it("a 2xx without a reference is FAILED, not success", async () => {
    const r = await build(paymentsCreate, fakeTransport(200, {})).execute(
      request("payment.create", { payeeAccount: "a" }),
      "k",
    );
    expect(r).toEqual({ status: "FAILED", reasonCode: "RESPONSE_MISSING_REFERENCE" });
  });

  it("5xx and 429 are transient failures", async () => {
    for (const status of [429, 500, 503]) {
      const r = await build(paymentsCreate, fakeTransport(status)).execute(
        request("payment.create", { payeeAccount: "a" }),
        "k",
      );
      expect(r).toEqual({ status: "FAILED", reasonCode: "UPSTREAM_TRANSIENT" });
    }
  });

  it("4xx is a permanent failure with its status code", async () => {
    const r = await build(paymentsCreate, fakeTransport(422)).execute(
      request("payment.create", { payeeAccount: "a" }),
      "k",
    );
    expect(r).toEqual({ status: "FAILED", reasonCode: "UPSTREAM_422" });
  });

  it("the connector refuses an operation it was not built for", async () => {
    const t = fakeTransport(200);
    const r = await build(paymentsCreate, t).execute(
      request("refund.create", { paymentExternalRef: "p" }),
      "k",
    );
    expect(r.status).toBe("FAILED");
    expect(t.calls).toHaveLength(0);
  });
});

describe("ERP, CRM and validation", () => {
  it("ERP rejects document types outside the allowed set", () => {
    expect(() =>
      erpPost.build(request("erp.post", { documentType: "PAYROLL", documentId: "x" })),
    ).toThrow(ConnectorValidationError);
  });

  it("CRM rejects nested field values", () => {
    expect(() =>
      crmUpdate.build(
        request("crm.update", { objectType: "deal", objectId: "d", fields: { owner: { id: 1 } } }),
      ),
    ).toThrow("strings or integers");
  });
});

describe("generic HTTP", () => {
  const def = genericHttpAction(["hooks.partner.example"]);

  it("allows an https call to an allowlisted host", async () => {
    const t = fakeTransport(200);
    const r = await build(def, t).execute(
      request("http.action", {
        method: "POST",
        url: "https://hooks.partner.example/v1/event",
        payload: { a: 1 },
      }),
      "k",
    );
    expect(r.status).toBe("SUCCEEDED");
    expect(t.calls[0]?.url).toBe("https://hooks.partner.example/v1/event");
  });

  it("refuses plain http, other hosts and other methods without a network call", async () => {
    const t = fakeTransport(200);
    const c = build(def, t);
    const cases = [
      { method: "POST", url: "http://hooks.partner.example/x" },
      { method: "POST", url: "https://evil.example/x" },
      { method: "DELETE", url: "https://hooks.partner.example/x" },
    ];
    for (const params of cases) {
      const r = await c.execute(request("http.action", params), "k");
      expect(r.status).toBe("FAILED");
    }
    expect(t.calls).toHaveLength(0);
  });
});

describe("only the execution boundary reaches a connector", () => {
  function world(): {
    trust: TrustRootSet;
    ctx: EvaluationContext;
    issuer: ReturnType<typeof generateSigningKeyPair>;
  } {
    const issuer = generateSigningKeyPair();
    const engine = generateSigningKeyPair();
    const trust = new TrustRootSet();
    trust.add({
      keyId: "issuer-key-1",
      jwk: exportEd25519PublicJwk(issuer.publicKey),
      status: "ACTIVE",
    });
    trust.add({
      keyId: "engine-1",
      jwk: exportEd25519PublicJwk(engine.publicKey),
      status: "ACTIVE",
    });
    const registry = new AuthorityRegistry(trust);
    const ctx: EvaluationContext = {
      registry,
      now: () => NOW,
      signer: { keyId: "engine-1", privateKey: engine.privateKey },
      approvals: new ApprovalStore(trust),
    };
    const body: AuthorityBody = parseAuthorityBody({
      authorityId: "auth-1",
      version: 1,
      organizationId: "org-acme",
      tenantId: "tenant-1",
      issuer: "cfo",
      principal: "cfo",
      agent: "payments-agent",
      permittedActions: ["payment.create"],
      resourceScope: ["vendor-42"],
      maxAmountMinor: 5_000_000,
      currencies: ["INR"],
      approvalAboveMinor: null,
      approvalActions: [],
      approverKeyIds: [],
      validFrom: "2026-01-01T00:00:00Z",
      validUntil: "2027-01-01T00:00:00Z",
      delegatedFrom: null,
      delegationAllowed: false,
      policyId: "policy-1",
      policyVersion: 1,
      protocolVersion: "1.0",
      signatureAlgorithm: "Ed25519",
      signingKeyId: "issuer-key-1",
    });
    registry.publish(signAuthority(body, issuer.privateKey));
    return { trust, ctx, issuer };
  }

  function raw(amount: number): NormalizedRequest {
    return normalizeRequest({
      requestId: "req-1",
      transactionId: "txn-1",
      organizationId: "org-acme",
      tenantId: "tenant-1",
      actor: "payments-agent",
      operation: "payment.create",
      resource: "vendor-42",
      amount: { minor: amount, currency: "INR" },
      parameters: { payeeAccount: "acc-9" },
      authorityRef: { authorityId: "auth-1", version: 1 },
      policyRef: { policyId: "policy-1", version: 1 },
      approvalRef: null,
      idempotencyKey: `idem-${String(amount)}`,
      protocolVersion: "1.0",
    });
  }

  it("a DENY decision never reaches the transport", async () => {
    const w = world();
    const t = fakeTransport(200);
    const input = raw(80_000_000);
    const decision = evaluate(input, w.ctx);
    expect(decision.body.result).toBe("DENY");
    const boundary = new ExecutionBoundary({
      trust: w.trust,
      connectors: new Map([["payment.create", build(paymentsCreate, t)]]),
      now: () => NOW,
      maxDecisionAgeSeconds: 300,
      timeoutMs: 1000,
    });
    const attempt = await boundary.execute(input, decision);
    expect(attempt.state).toBe("REFUSED");
    expect(t.calls).toHaveLength(0);
  });

  it("an ALLOW decision reaches the transport exactly once", async () => {
    const w = world();
    const t = fakeTransport(200);
    const input = raw(4_000_000);
    const decision = evaluate(input, w.ctx);
    const boundary = new ExecutionBoundary({
      trust: w.trust,
      connectors: new Map([["payment.create", build(paymentsCreate, t)]]),
      now: () => NOW,
      maxDecisionAgeSeconds: 300,
      timeoutMs: 1000,
    });
    const attempt = await boundary.execute(input, decision);
    expect(attempt.state).toBe("SUCCEEDED");
    expect(t.calls).toHaveLength(1);
    await boundary.execute(input, decision);
    expect(t.calls).toHaveLength(1);
  });
});
