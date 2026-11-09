import { describe, expect, it } from "vitest";
import { DipError, parseAuthorityBody, signAuthority, type AuthorityBody } from "@dip/authority";
import { exportEd25519PublicJwk, generateSigningKeyPair } from "@dip/crypto";
import { signApprovalDecision } from "@dip/approval";
import type { Connector, ConnectorResult } from "@dip/execution";
import { DipClient, type DipClientConfig } from "../src/index.js";

const NOW = new Date("2026-06-01T12:00:00Z");

function makeClient(overrides: Partial<DipClientConfig> = {}): {
  client: DipClient;
  keys: Record<
    "issuer" | "engine" | "evidence" | "approver",
    ReturnType<typeof generateSigningKeyPair>
  >;
  calls: () => number;
} {
  const keys = {
    issuer: generateSigningKeyPair(),
    engine: generateSigningKeyPair(),
    evidence: generateSigningKeyPair(),
    approver: generateSigningKeyPair(),
  };
  let n = 0;
  const connector: Connector = {
    id: "payments",
    execute: async (): Promise<ConnectorResult> => {
      n += 1;
      return { status: "SUCCEEDED", externalRef: "pay-1" };
    },
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
    connectors: new Map([["payment.create", connector]]),
    now: () => NOW,
    ...overrides,
  });
  return { client, keys, calls: () => n };
}

function body(overrides: Partial<AuthorityBody> = {}): AuthorityBody {
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
    approverKeyIds: [],
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

describe("DipClient", () => {
  it("authorizes with a strict ALLOW or DENY result and runs the full flow", async () => {
    const { client, keys, calls } = makeClient();
    client.publishAuthority(signAuthority(body(), keys.issuer.privateKey));
    const normalized = client.normalizeRequest(raw());
    const outcome = client.authorize(normalized);
    expect(["ALLOW", "DENY"]).toContain(outcome.result);
    expect(outcome.result).toBe("ALLOW");
    const attempt = await client.execute(normalized, outcome.decision);
    expect(attempt.state).toBe("SUCCEEDED");
    client.record({ normalized, decision: outcome.decision, attempt });
    expect(calls()).toBe(1);
    expect(client.verifyLedger(client.ledgerHead()).valid).toBe(true);
  });

  it("returns DENY for a request above the limit and does not execute it", async () => {
    const { client, keys, calls } = makeClient();
    client.publishAuthority(signAuthority(body(), keys.issuer.privateKey));
    const normalized = client.normalizeRequest(
      raw({ amount: { minor: 80_000_000, currency: "INR" } }),
    );
    const outcome = client.authorize(normalized);
    expect(outcome.result).toBe("DENY");
    const attempt = await client.execute(normalized, outcome.decision);
    expect(attempt.state).toBe("REFUSED");
    expect(calls()).toBe(0);
  });

  it("approve refuses a decision whose action is not APPROVE", () => {
    const { client, keys } = makeClient();
    const signed = signApprovalDecision(
      {
        approvalId: "appr-1",
        action: "REJECT",
        approverKeyId: "approver-key-1",
        decidedAt: "2026-06-01T11:30:00Z",
      },
      keys.approver.privateKey,
    );
    expect(() => client.approve(signed)).toThrow(DipError);
  });

  it("approval states are returned only by approval methods", () => {
    const { client, keys } = makeClient();
    client.requestApproval({
      approvalId: "appr-1",
      organizationId: "org-acme",
      requestDigest: "a".repeat(64),
      authorityRef: { authorityId: "auth-vendor-payments", version: 1 },
      policyRef: { policyId: "policy-payments", version: 1 },
      approverKeyId: "approver-key-1",
      requestedAt: "2026-06-01T11:00:00Z",
      expiresAt: "2026-06-01T13:00:00Z",
    });
    expect(client.approvalStatus("appr-1")).toBe("PENDING");
    const approved = client.approve(
      signApprovalDecision(
        {
          approvalId: "appr-1",
          action: "APPROVE",
          approverKeyId: "approver-key-1",
          decidedAt: "2026-06-01T11:30:00Z",
        },
        keys.approver.privateKey,
      ),
    );
    expect(approved).toBe("APPROVED");
  });

  it("reports a missing authority as a typed error", () => {
    const { client } = makeClient();
    expect(() => client.getAuthority("missing", 1)).not.toThrow();
    expect(client.getAuthority("missing", 1)).toBeUndefined();
  });

  it("publishing a tampered authority is refused with a typed code", () => {
    const { client, keys } = makeClient();
    const signed = signAuthority(body(), keys.issuer.privateKey);
    const tampered = {
      body: { ...signed.body, maxAmountMinor: 999_999_999_999 },
      signature: signed.signature,
    };
    try {
      client.publishAuthority(tampered);
      expect.fail("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(DipError);
      expect((err as DipError).code).toBe("AUTHORITY_SIGNATURE_INVALID");
    }
  });

  it("verifies an exported bundle against its own trust roots", async () => {
    const { client, keys } = makeClient();
    client.publishAuthority(signAuthority(body(), keys.issuer.privateKey));
    const normalized = client.normalizeRequest(raw());
    const outcome = client.authorize(normalized);
    const attempt = await client.execute(normalized, outcome.decision);
    client.record({ normalized, decision: outcome.decision, attempt });
    const bundle = {
      format: "dip-evidence-bundle",
      formatVersion: 1,
      entries: client.ledgerLines(),
      expectedHead: client.ledgerHead(),
      requests: [{ body: normalized.request, requestDigest: normalized.requestDigest }],
      decisions: [outcome.decision],
      authorities: [client.getAuthority("auth-vendor-payments", 1)],
      approvals: [],
    };
    expect(client.verifyBundle(bundle).verdict).toBe("VALID");
  });
});
