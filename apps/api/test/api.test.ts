import { describe, expect, it } from "vitest";
import { parseAuthorityBody, signAuthority, type AuthorityBody } from "@dip/authority";
import { exportEd25519PublicJwk, generateSigningKeyPair } from "@dip/crypto";
import { signApprovalDecision } from "@dip/approval";
import { DipClient, type Principal } from "@dip/sdk";
import { createApi, createHttpServer, type ApiRequest } from "../src/index.js";

const NOW = new Date("2026-06-01T12:00:00Z");

function world(rateMax = 1000) {
  const keys = {
    issuer: generateSigningKeyPair(),
    engine: generateSigningKeyPair(),
    evidence: generateSigningKeyPair(),
    approver: generateSigningKeyPair(),
  };
  const client = new DipClient({
    trustRoots: [
      {
        keyId: "issuer-key-1",
        jwk: exportEd25519PublicJwk(keys.issuer.publicKey),
        status: "ACTIVE",
      },
      { keyId: "engine-1", jwk: exportEd25519PublicJwk(keys.engine.publicKey), status: "ACTIVE" },
      {
        keyId: "evidence-1",
        jwk: exportEd25519PublicJwk(keys.evidence.publicKey),
        status: "ACTIVE",
      },
      {
        keyId: "approver-key-1",
        jwk: exportEd25519PublicJwk(keys.approver.publicKey),
        status: "ACTIVE",
      },
    ],
    engine: { keyId: "engine-1", privateKey: keys.engine.privateKey },
    evidenceSigner: { keyId: "evidence-1", privateKey: keys.evidence.privateKey },
    connectors: new Map([
      [
        "payment.create",
        {
          id: "payments",
          execute: async () => ({ status: "SUCCEEDED" as const, externalRef: "pay-1" }),
        },
      ],
    ]),
    now: () => NOW,
  });
  const principals = new Map<string, Principal>([
    ["key-operator", { name: "operator", tenantId: "tenant-1", scopes: [] }],
    ["key-approver", { name: "approver", tenantId: "tenant-1", scopes: ["approver"] }],
    ["key-admin", { name: "admin", tenantId: null, scopes: ["admin", "approver"] }],
  ]);
  const api = createApi({
    client,
    principals,
    rateLimit: { max: rateMax, windowMs: 60_000 },
    clockMs: () => NOW.getTime(),
  });
  return { api, client, keys };
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

function rawRequest(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    requestId: "req-1",
    transactionId: "txn-1",
    organizationId: "org-acme",
    tenantId: "tenant-1",
    actor: "payments-agent",
    operation: "payment.create",
    resource: "vendor-42",
    amount: { minor: 4_000_000, currency: "INR" },
    parameters: {},
    authorityRef: { authorityId: "auth-vendor-payments", version: 1 },
    policyRef: { policyId: "policy-payments", version: 1 },
    approvalRef: null,
    idempotencyKey: "idem-1",
    protocolVersion: "1.0",
    ...overrides,
  };
}

function req(method: string, path: string, key: string | null, body?: unknown): ApiRequest {
  return { method, path, headers: key === null ? {} : { authorization: `Bearer ${key}` }, body };
}

async function publish(
  api: ReturnType<typeof world>["api"],
  keys: ReturnType<typeof world>["keys"],
): Promise<void> {
  const res = await api.handle(
    req(
      "POST",
      "/v1/authorities",
      "key-operator",
      signAuthority(authorityBody(), keys.issuer.privateKey),
    ),
  );
  expect(res.status).toBe(201);
}

describe("authentication and routing", () => {
  it("health is public", async () => {
    const { api } = world();
    expect((await api.handle(req("GET", "/v1/health", null))).status).toBe(200);
  });

  it("protected routes require a valid API key", async () => {
    const { api } = world();
    expect(
      (await api.handle(req("POST", "/v1/requests/normalize", null, rawRequest()))).status,
    ).toBe(401);
    expect(
      (await api.handle(req("POST", "/v1/requests/normalize", "wrong", rawRequest()))).status,
    ).toBe(401);
  });

  it("unknown routes are 404 and wrong methods are 405", async () => {
    const { api } = world();
    expect((await api.handle(req("GET", "/v1/nope", null))).status).toBe(404);
    expect((await api.handle(req("GET", "/v1/authorize", "key-operator"))).status).toBe(405);
  });

  it("requires a JSON body on POST routes", async () => {
    const { api } = world();
    expect((await api.handle(req("POST", "/v1/requests/normalize", "key-operator"))).status).toBe(
      400,
    );
  });
});

describe("authority endpoints", () => {
  it("publishes, reads, and refuses duplicates and tampering with typed errors", async () => {
    const { api, keys } = world();
    await publish(api, keys);
    const got = await api.handle(
      req("GET", "/v1/authorities/auth-vendor-payments?version=1", "key-operator"),
    );
    expect(got.status).toBe(200);
    expect((await api.handle(req("GET", "/v1/authorities/missing", "key-operator"))).status).toBe(
      404,
    );
    const dup = await api.handle(
      req(
        "POST",
        "/v1/authorities",
        "key-operator",
        signAuthority(authorityBody(), keys.issuer.privateKey),
      ),
    );
    expect(dup.status).toBe(409);
    const signed = signAuthority(authorityBody({ version: 2 }), keys.issuer.privateKey);
    const tampered = {
      body: { ...signed.body, maxAmountMinor: 999_999_999 },
      signature: signed.signature,
    };
    expect(
      (await api.handle(req("POST", "/v1/authorities", "key-operator", tampered))).status,
    ).toBe(422);
  });

  it("refuses to publish an authority for another tenant", async () => {
    const { api, keys } = world();
    const other = signAuthority(authorityBody({ tenantId: "tenant-2" }), keys.issuer.privateKey);
    expect((await api.handle(req("POST", "/v1/authorities", "key-operator", other))).status).toBe(
      403,
    );
  });
});

describe("authorization and execution", () => {
  it("authorize returns only ALLOW or DENY", async () => {
    const { api, keys } = world();
    await publish(api, keys);
    const allow = await api.handle(req("POST", "/v1/authorize", "key-operator", rawRequest()));
    expect(allow.status).toBe(200);
    expect((allow.body as { result: string }).result).toBe("ALLOW");
    const deny = await api.handle(
      req(
        "POST",
        "/v1/authorize",
        "key-operator",
        rawRequest({ amount: { minor: 80_000_000, currency: "INR" } }),
      ),
    );
    expect((deny.body as { result: string }).result).toBe("DENY");
  });

  it("a principal cannot authorize a request for another tenant", async () => {
    const { api, keys } = world();
    await publish(api, keys);
    const res = await api.handle(
      req("POST", "/v1/authorize", "key-operator", rawRequest({ tenantId: "tenant-2" })),
    );
    expect(res.status).toBe(403);
  });

  it("execute runs an ALLOW decision, records evidence, and returns its id", async () => {
    const { api, keys } = world();
    await publish(api, keys);
    const normalized = await api.handle(
      req("POST", "/v1/requests/normalize", "key-operator", rawRequest()),
    );
    const authorized = await api.handle(req("POST", "/v1/authorize", "key-operator", rawRequest()));
    const decision = (authorized.body as { decision: unknown }).decision;
    const exec = await api.handle(
      req("POST", "/v1/execute", "key-operator", { request: normalized.body, decision }),
    );
    expect(exec.status).toBe(200);
    const body = exec.body as { attempt: { state: string }; evidenceId: string };
    expect(body.attempt.state).toBe("SUCCEEDED");
    const ev = await api.handle(req("GET", `/v1/evidence/${body.evidenceId}`, "key-operator"));
    expect(ev.status).toBe(200);
    expect((await api.handle(req("GET", "/v1/evidence/ev-missing", "key-operator"))).status).toBe(
      404,
    );
  });

  it("execute refuses a DENY decision without calling the connector", async () => {
    const { api, keys } = world();
    await publish(api, keys);
    const input = rawRequest({ amount: { minor: 80_000_000, currency: "INR" } });
    const authorized = await api.handle(req("POST", "/v1/authorize", "key-operator", input));
    const normalized = await api.handle(
      req("POST", "/v1/requests/normalize", "key-operator", input),
    );
    const exec = await api.handle(
      req("POST", "/v1/execute", "key-operator", {
        request: normalized.body,
        decision: (authorized.body as { decision: unknown }).decision,
      }),
    );
    expect((exec.body as { attempt: { state: string } }).attempt.state).toBe("REFUSED");
  });
});

describe("approvals", () => {
  it("creates, approves through the approver scope, and reports the state", async () => {
    const { api, keys } = world();
    const binding = {
      approvalId: "appr-1",
      organizationId: "org-acme",
      requestDigest: "a".repeat(64),
      authorityRef: { authorityId: "auth-vendor-payments", version: 1 },
      policyRef: { policyId: "policy-payments", version: 1 },
      approverKeyId: "approver-key-1",
      requestedAt: "2026-06-01T11:00:00Z",
      expiresAt: "2026-06-01T13:00:00Z",
    };
    expect((await api.handle(req("POST", "/v1/approvals", "key-operator", binding))).status).toBe(
      403,
    );
    expect((await api.handle(req("POST", "/v1/approvals", "key-approver", binding))).status).toBe(
      201,
    );
    const signed = signApprovalDecision(
      {
        approvalId: "appr-1",
        action: "APPROVE",
        approverKeyId: "approver-key-1",
        decidedAt: "2026-06-01T11:30:00Z",
      },
      keys.approver.privateKey,
    );
    expect(
      (await api.handle(req("POST", "/v1/approvals/other/approve", "key-approver", signed))).status,
    ).toBe(400);
    const approved = await api.handle(
      req("POST", "/v1/approvals/appr-1/approve", "key-approver", signed),
    );
    expect((approved.body as { state: string }).state).toBe("APPROVED");
    const status = await api.handle(req("GET", "/v1/approvals/appr-1", "key-approver"));
    expect((status.body as { state: string }).state).toBe("APPROVED");
  });

  it("a reject signed for the approve route is refused", async () => {
    const { api, keys } = world();
    await api.handle(
      req("POST", "/v1/approvals", "key-approver", {
        approvalId: "appr-2",
        organizationId: "org-acme",
        requestDigest: "b".repeat(64),
        authorityRef: { authorityId: "auth-vendor-payments", version: 1 },
        policyRef: { policyId: "policy-payments", version: 1 },
        approverKeyId: "approver-key-1",
        requestedAt: "2026-06-01T11:00:00Z",
        expiresAt: "2026-06-01T13:00:00Z",
      }),
    );
    const rejected = signApprovalDecision(
      {
        approvalId: "appr-2",
        action: "REJECT",
        approverKeyId: "approver-key-1",
        decidedAt: "2026-06-01T11:30:00Z",
      },
      keys.approver.privateKey,
    );
    const res = await api.handle(
      req("POST", "/v1/approvals/appr-2/approve", "key-approver", rejected),
    );
    expect(res.status).toBe(400);
  });
});

describe("ledger and verification", () => {
  it("ledger listing and verification require the admin scope", async () => {
    const { api } = world();
    expect((await api.handle(req("GET", "/v1/ledger", "key-operator"))).status).toBe(403);
    const list = await api.handle(req("GET", "/v1/ledger?offset=0&limit=5", "key-admin"));
    expect(list.status).toBe(200);
    expect((list.body as { total: number }).total).toBe(0);
    expect((await api.handle(req("POST", "/v1/ledger/verify", "key-admin", {}))).status).toBe(200);
  });

  it("verifies an exported bundle through the verify endpoint", async () => {
    const { api } = world();
    const res = await api.handle(
      req("POST", "/v1/verify", "key-operator", {
        format: "dip-evidence-bundle",
        formatVersion: 1,
        entries: [],
        expectedHead: null,
      }),
    );
    expect((res.body as { verdict: string }).verdict).toBe("INCOMPLETE");
  });

  it("rate limits a principal within its window", async () => {
    const { api } = world(2);
    expect(
      (await api.handle(req("POST", "/v1/requests/normalize", "key-operator", rawRequest())))
        .status,
    ).not.toBe(429);
    expect(
      (await api.handle(req("POST", "/v1/requests/normalize", "key-operator", rawRequest())))
        .status,
    ).not.toBe(429);
    expect(
      (await api.handle(req("POST", "/v1/requests/normalize", "key-operator", rawRequest())))
        .status,
    ).toBe(429);
  });
});

describe("HTTP adapter", () => {
  it("serves health and rejects invalid JSON over a real socket", async () => {
    const { api } = world();
    const server = createHttpServer((r) => api.handle(r));
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
    const address = server.address();
    const port = typeof address === "object" && address !== null ? address.port : 0;
    try {
      const health = await fetch(`http://127.0.0.1:${String(port)}/v1/health`);
      expect(health.status).toBe(200);
      const bad = await fetch(`http://127.0.0.1:${String(port)}/v1/requests/normalize`, {
        method: "POST",
        headers: { authorization: "Bearer key-operator", "content-type": "application/json" },
        body: "{not json",
      });
      expect(bad.status).toBe(400);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
