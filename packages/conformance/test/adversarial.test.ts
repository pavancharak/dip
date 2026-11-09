import { describe, expect, it } from "vitest";
import {
  parseAuthorityBody,
  signAuthority,
  signRevocation,
  type AuthorityBody,
} from "@dip/authority";
import { signApprovalDecision } from "@dip/approval";
import { exportEd25519PublicJwk, generateSigningKeyPair, type SigningKeyPair } from "@dip/crypto";
import type { Connector, ConnectorResult } from "@dip/execution";
import { DipClient, DipError, type DipClientConfig } from "@dip/sdk";

const NOW = new Date("2026-06-01T12:00:00Z");

interface Lab {
  readonly client: DipClient;
  readonly keys: Record<"issuer" | "engine" | "evidence" | "approver" | "rogue", SigningKeyPair>;
  readonly calls: { count: number };
}

function lab(clock: { now: Date } = { now: NOW }): Lab {
  const keys = {
    issuer: generateSigningKeyPair(),
    engine: generateSigningKeyPair(),
    evidence: generateSigningKeyPair(),
    approver: generateSigningKeyPair(),
    rogue: generateSigningKeyPair(),
  };
  const calls = { count: 0 };
  const connector: Connector = {
    id: "payments",
    execute: async (): Promise<ConnectorResult> => {
      calls.count += 1;
      return { status: "SUCCEEDED", externalRef: "pay-1" };
    },
  };
  const config: DipClientConfig = {
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
    connectors: new Map([["payment.create", connector]]),
    now: () => clock.now,
  };
  return { client: new DipClient(config), keys, calls };
}

function authorityBody(overrides: Partial<AuthorityBody> = {}): AuthorityBody {
  return parseAuthorityBody({
    authorityId: "auth-vendor-payments",
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
    approvalAboveMinor: 1_000_000,
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

function raw(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    requestId: "req-1",
    transactionId: "txn-1",
    organizationId: "org-acme",
    tenantId: "tenant-1",
    actor: "payments-agent",
    operation: "payment.create",
    resource: "vendor-42",
    amount: { minor: 400_000, currency: "INR" },
    parameters: { payeeAccount: "acc-9" },
    authorityRef: { authorityId: "auth-vendor-payments", version: 1 },
    policyRef: { policyId: "policy-payments", version: 1 },
    approvalRef: null,
    idempotencyKey: "idem-1",
    protocolVersion: "1.0",
    ...overrides,
  };
}

function binding(requestDigest: string, approvalId = "appr-1"): Record<string, unknown> {
  return {
    approvalId,
    organizationId: "org-acme",
    requestDigest,
    authorityRef: { authorityId: "auth-vendor-payments", version: 1 },
    policyRef: { policyId: "policy-payments", version: 1 },
    approverKeyId: "approver-key-1",
    requestedAt: "2026-06-01T11:00:00Z",
    expiresAt: "2026-06-01T13:00:00Z",
  };
}

function publish(l: Lab): void {
  l.client.publishAuthority(signAuthority(authorityBody(), l.keys.issuer.privateKey));
}

describe("authority attacks", () => {
  it("a forged authority signed by an unknown key is refused", () => {
    const l = lab();
    const forged = signAuthority(
      authorityBody({ signingKeyId: "rogue-key" }),
      l.keys.rogue.privateKey,
    );
    expect(() => l.client.publishAuthority(forged)).toThrow(DipError);
  });

  it("an authority signed by the right key id but the wrong private key is refused", () => {
    const l = lab();
    const forged = signAuthority(authorityBody(), l.keys.rogue.privateKey);
    expect(() => l.client.publishAuthority(forged)).toThrow(DipError);
  });

  it("a forged revocation signed by a non-issuer key cannot revoke an authority", () => {
    const l = lab();
    publish(l);
    const forged = signRevocation(
      {
        authorityId: "auth-vendor-payments",
        version: 1,
        revokedAt: "2026-06-01T11:00:00Z",
        signingKeyId: "issuer-key-1",
      },
      l.keys.rogue.privateKey,
    );
    expect(() => l.client.revokeAuthority(forged)).toThrow(DipError);
    expect(l.client.authorize(l.client.normalizeRequest(raw())).result).toBe("ALLOW");
  });

  it("regression: an authority revoked after an ALLOW decision stops execution", async () => {
    const l = lab();
    publish(l);
    const normalized = l.client.normalizeRequest(raw());
    const decision = l.client.authorize(normalized).decision;
    l.client.revokeAuthority(
      signRevocation(
        {
          authorityId: "auth-vendor-payments",
          version: 1,
          revokedAt: "2026-06-01T11:59:00Z",
          signingKeyId: "issuer-key-1",
        },
        l.keys.issuer.privateKey,
      ),
    );
    const attempt = await l.client.execute(normalized, decision);
    expect(attempt.state).toBe("REFUSED");
    expect(attempt.reasonCode).toBe("AUTHORITY_REVOKED");
    expect(l.calls.count).toBe(0);
  });
});

describe("decision and request substitution", () => {
  it("a decision made for one request cannot authorize another", async () => {
    const l = lab();
    publish(l);
    const small = l.client.normalizeRequest(raw());
    const large = l.client.normalizeRequest(
      raw({ amount: { minor: 450_000, currency: "INR" }, idempotencyKey: "idem-2" }),
    );
    const decisionForSmall = l.client.authorize(small).decision;
    const attempt = await l.client.execute(large, decisionForSmall);
    expect(attempt.state).toBe("REFUSED");
    expect(l.calls.count).toBe(0);
  });

  it("an approval for one request cannot be attached to a modified request", () => {
    const l = lab();
    publish(l);
    const original = l.client.normalizeRequest(
      raw({ amount: { minor: 2_000_000, currency: "INR" }, approvalRef: "appr-1" }),
    );
    l.client.requestApproval(binding(original.requestDigest));
    l.client.approve(
      signApprovalDecision(
        {
          approvalId: "appr-1",
          action: "APPROVE",
          approverKeyId: "approver-key-1",
          decidedAt: "2026-06-01T11:30:00Z",
        },
        l.keys.approver.privateKey,
      ),
    );
    const modified = l.client.normalizeRequest(
      raw({ amount: { minor: 3_000_000, currency: "INR" }, approvalRef: "appr-1" }),
    );
    expect(l.client.authorize(modified).result).toBe("DENY");
    expect(l.client.authorize(modified).decision.body.reasonCodes).toContain(
      "APPROVAL_BINDING_MISMATCH",
    );
  });

  it("an approval cannot authorize an amount above the authority limit", () => {
    const l = lab();
    publish(l);
    const big = l.client.normalizeRequest(
      raw({ amount: { minor: 9_000_000, currency: "INR" }, approvalRef: "appr-2" }),
    );
    l.client.requestApproval(binding(big.requestDigest, "appr-2"));
    l.client.approve(
      signApprovalDecision(
        {
          approvalId: "appr-2",
          action: "APPROVE",
          approverKeyId: "approver-key-1",
          decidedAt: "2026-06-01T11:30:00Z",
        },
        l.keys.approver.privateKey,
      ),
    );
    expect(l.client.authorize(big).decision.body.reasonCodes).toContain("AMOUNT_EXCEEDS_LIMIT");
  });
});

describe("approval attacks", () => {
  it("an approval decision signed by a non-designated key is refused", () => {
    const l = lab();
    publish(l);
    const n = l.client.normalizeRequest(raw({ approvalRef: "appr-3" }));
    l.client.requestApproval(binding(n.requestDigest, "appr-3"));
    const forged = signApprovalDecision(
      {
        approvalId: "appr-3",
        action: "APPROVE",
        approverKeyId: "approver-key-1",
        decidedAt: "2026-06-01T11:30:00Z",
      },
      l.keys.rogue.privateKey,
    );
    expect(() => l.client.approve(forged)).toThrow(DipError);
    expect(l.client.approvalStatus("appr-3")).toBe("PENDING");
  });

  it("an approval cannot be decided twice", () => {
    const l = lab();
    const n = l.client.normalizeRequest(raw());
    l.client.requestApproval(binding(n.requestDigest, "appr-4"));
    const approve = signApprovalDecision(
      {
        approvalId: "appr-4",
        action: "APPROVE",
        approverKeyId: "approver-key-1",
        decidedAt: "2026-06-01T11:30:00Z",
      },
      l.keys.approver.privateKey,
    );
    l.client.approve(approve);
    expect(() => l.client.approve(approve)).toThrow(DipError);
    expect(() =>
      l.client.reject(
        signApprovalDecision(
          {
            approvalId: "appr-4",
            action: "REJECT",
            approverKeyId: "approver-key-1",
            decidedAt: "2026-06-01T11:31:00Z",
          },
          l.keys.approver.privateKey,
        ),
      ),
    ).toThrow(DipError);
  });

  it("a decision timestamped before the approval request is refused", () => {
    const l = lab();
    const n = l.client.normalizeRequest(raw());
    l.client.requestApproval(binding(n.requestDigest, "appr-5"));
    const early = signApprovalDecision(
      {
        approvalId: "appr-5",
        action: "APPROVE",
        approverKeyId: "approver-key-1",
        decidedAt: "2026-06-01T10:00:00Z",
      },
      l.keys.approver.privateKey,
    );
    expect(() => l.client.approve(early)).toThrow("precedes the approval request");
    expect(l.client.approvalStatus("appr-5")).toBe("PENDING");
  });

  it("a decision after the approval expired is refused", () => {
    const l = lab({ now: new Date("2026-06-01T14:00:00Z") });
    const n = l.client.normalizeRequest(raw());
    l.client.requestApproval(binding(n.requestDigest, "appr-6"));
    const late = signApprovalDecision(
      {
        approvalId: "appr-6",
        action: "APPROVE",
        approverKeyId: "approver-key-1",
        decidedAt: "2026-06-01T13:30:00Z",
      },
      l.keys.approver.privateKey,
    );
    expect(() => l.client.approve(late)).toThrow(DipError);
    expect(l.client.approvalStatus("appr-6")).toBe("EXPIRED");
  });
});

describe("execution attacks", () => {
  it("a decision replayed after execution does not run the action again", async () => {
    const l = lab();
    publish(l);
    const normalized = l.client.normalizeRequest(raw());
    const decision = l.client.authorize(normalized).decision;
    await l.client.execute(normalized, decision);
    const again = await l.client.execute(normalized, decision);
    expect(["DUPLICATE", "REFUSED"]).toContain(again.state);
    expect(l.calls.count).toBe(1);
  });

  it("a decision with a non-canonical signature encoding is refused", async () => {
    const l = lab();
    publish(l);
    const normalized = l.client.normalizeRequest(raw());
    const decision = l.client.authorize(normalized).decision;
    const fresh = lab();
    void fresh;
    const attempt = await l.client.execute(normalized, {
      ...decision,
      signature: decision.signature.slice(0, 85) + (decision.signature.endsWith("A") ? "B" : "A"),
    });
    expect(attempt.state).toBe("REFUSED");
    expect(l.calls.count).toBe(0);
  });

  it("a decision dated in the future is refused", async () => {
    const clock = { now: new Date("2026-06-01T11:00:00Z") };
    const l = lab(clock);
    publish(l);
    const normalized = l.client.normalizeRequest(raw());
    const decision = l.client.authorize(normalized).decision;
    clock.now = new Date("2026-06-01T10:00:00Z");
    const attempt = await l.client.execute(normalized, decision);
    expect(attempt.reasonCode).toBe("DECISION_IN_FUTURE");
  });

  it("a decision older than the freshness window is refused", async () => {
    const clock = { now: NOW };
    const l = lab(clock);
    publish(l);
    const normalized = l.client.normalizeRequest(raw());
    const decision = l.client.authorize(normalized).decision;
    clock.now = new Date("2026-06-01T13:00:00Z");
    const attempt = await l.client.execute(normalized, decision);
    expect(attempt.reasonCode).toBe("DECISION_STALE");
  });

  it("randomized tampering of decision bodies never reaches a connector", async () => {
    const l = lab();
    publish(l);
    const normalized = l.client.normalizeRequest(
      raw({ amount: { minor: 80_000_000, currency: "INR" } }),
    );
    const denied = l.client.authorize(normalized).decision;
    expect(denied.body.result).toBe("DENY");
    let seed = 0x5eed;
    const next = (): number => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed;
    };
    const fields = [
      "result",
      "reasonCodes",
      "requestDigest",
      "decisionId",
      "evaluatedAt",
      "policyRef",
      "authorityRef",
    ] as const;
    for (let i = 0; i < 200; i++) {
      const body = { ...denied.body } as Record<string, unknown>;
      const field = fields[next() % fields.length] ?? "result";
      if (field === "result") body.result = "ALLOW";
      else if (field === "reasonCodes") body.reasonCodes = [];
      else if (field === "requestDigest")
        body.requestDigest = (next() % 16).toString(16).repeat(64);
      else if (field === "decisionId") body.decisionId = (next() % 16).toString(16).repeat(64);
      else if (field === "evaluatedAt") body.evaluatedAt = "2026-06-01T11:00:00Z";
      else if (field === "policyRef") body.policyRef = { policyId: "other", version: 1 };
      else body.authorityRef = { authorityId: "other", version: 1 };
      const attempt = await l.client.execute(normalized, {
        ...denied,
        body: body as typeof denied.body,
      });
      expect(attempt.state).not.toBe("SUCCEEDED");
    }
    expect(l.calls.count).toBe(0);
  });
});

describe("ledger attacks", () => {
  it("records a refused attempt as evidence and the chain verifies", async () => {
    const l = lab();
    publish(l);
    const normalized = l.client.normalizeRequest(
      raw({ amount: { minor: 80_000_000, currency: "INR" } }),
    );
    const decision = l.client.authorize(normalized).decision;
    const attempt = await l.client.execute(normalized, decision);
    l.client.record({ normalized, decision, attempt });
    expect(l.client.verifyLedger(l.client.ledgerHead()).valid).toBe(true);
  });

  it("deleting, modifying, or reordering recorded evidence is detected", async () => {
    const l = lab();
    publish(l);
    for (let i = 0; i < 3; i++) {
      const n = l.client.normalizeRequest(raw({ idempotencyKey: `idem-${String(i)}` }));
      const d = l.client.authorize(n).decision;
      const a = await l.client.execute(n, d);
      l.client.record({ normalized: n, decision: d, attempt: a });
    }
    const lines = l.client.ledgerLines();
    expect(l.client.verifyLedger(l.client.ledgerHead()).valid).toBe(true);
    const deleted = [lines[0] ?? "", lines[2] ?? ""];
    const modifiedEntry = JSON.parse(lines[1] ?? "") as { body: { recordedAt: string } };
    modifiedEntry.body.recordedAt = "2026-01-01T00:00:00Z";
    const modified = [lines[0] ?? "", JSON.stringify(modifiedEntry), lines[2] ?? ""];
    const reordered = [lines[1] ?? "", lines[0] ?? "", lines[2] ?? ""];
    expect(
      l.client.verifyBundle({
        format: "dip-evidence-bundle",
        formatVersion: 1,
        entries: deleted,
        expectedHead: null,
      }).verdict,
    ).not.toBe("VALID");
    expect(
      l.client.verifyBundle({
        format: "dip-evidence-bundle",
        formatVersion: 1,
        entries: modified,
        expectedHead: null,
      }).verdict,
    ).toBe("INVALID");
    expect(
      l.client.verifyBundle({
        format: "dip-evidence-bundle",
        formatVersion: 1,
        entries: reordered,
        expectedHead: null,
      }).verdict,
    ).toBe("INVALID");
    expect(
      l.client.verifyBundle({
        format: "dip-evidence-bundle",
        formatVersion: 1,
        entries: lines.slice(0, 2),
        expectedHead: l.client.ledgerHead(),
      }).verdict,
    ).toBe("INVALID");
  });
});
