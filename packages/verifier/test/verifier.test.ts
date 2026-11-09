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
import { ExecutionBoundary, type Connector, type ConnectorResult } from "@dip/execution";
import { EvidenceLedger, draftFrom } from "@dip/ledger";
import {
  runCli,
  verifyBundle,
  VerifierError,
  BUNDLE_FORMAT,
  type TrustRootInput,
  type VerificationResult,
} from "../src/index.js";

const NOW = new Date("2026-06-01T12:00:00Z");
const PAISE_40K = 4_000_000;
const PAISE_80K = 8_000_000;

interface Scenario {
  readonly bundle: {
    format: string;
    formatVersion: number;
    entries: string[];
    expectedHead: string;
    requests: unknown[];
    decisions: unknown[];
    authorities: unknown[];
    approvals: unknown[];
  };
  readonly roots: TrustRootInput[];
  readonly keys: Record<"issuer" | "engine" | "evidence" | "approver", SigningKeyPair>;
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

const okConnector: Connector = {
  id: "payments-test",
  execute: async (): Promise<ConnectorResult> => ({ status: "SUCCEEDED", externalRef: "pay-001" }),
};

/**
 * Runs the real pipeline and exports what a deployment would hand to an auditor.
 * Keys are generated per scenario. The verifier only ever sees the bundle and public roots.
 */
async function scenario(opts: {
  approval: boolean;
  amountMinor?: number;
  idempotencyKey?: string;
}): Promise<Scenario> {
  const keys = {
    issuer: generateSigningKeyPair(),
    engine: generateSigningKeyPair(),
    evidence: generateSigningKeyPair(),
    approver: generateSigningKeyPair(),
  };
  const trust = new TrustRootSet();
  trust.add({
    keyId: "issuer-key-1",
    jwk: exportEd25519PublicJwk(keys.issuer.publicKey),
    status: "ACTIVE",
  });
  trust.add({
    keyId: "engine-1",
    jwk: exportEd25519PublicJwk(keys.engine.publicKey),
    status: "ACTIVE",
  });
  trust.add({
    keyId: "evidence-1",
    jwk: exportEd25519PublicJwk(keys.evidence.publicKey),
    status: "ACTIVE",
  });
  trust.add({
    keyId: "approver-key-1",
    jwk: exportEd25519PublicJwk(keys.approver.publicKey),
    status: "ACTIVE",
  });

  const registry = new AuthorityRegistry(trust);
  const approvals = new ApprovalStore(trust);
  const ctx: EvaluationContext = {
    registry,
    now: () => NOW,
    signer: { keyId: "engine-1", privateKey: keys.engine.privateKey },
    approvals,
  };
  const authoritySigned = signAuthority(authorityBody(), keys.issuer.privateKey);
  registry.publish(authoritySigned);

  const approvalRef = opts.approval ? "appr-1" : null;
  const requestRaw = requestInput({
    approvalRef,
    idempotencyKey: opts.idempotencyKey ?? "idem-1",
    amount: { minor: opts.amountMinor ?? PAISE_40K, currency: "INR" },
  });
  const normalized: NormalizedRequest = normalizeRequest(requestRaw);
  const approvalRecords: unknown[] = [];
  if (opts.approval) {
    const binding = approvals.request(
      {
        approvalId: "appr-1",
        organizationId: "org-acme",
        requestDigest: normalized.requestDigest,
        authorityRef: { authorityId: "auth-vendor-payments", version: 1 },
        policyRef: { policyId: "policy-payments", version: 1 },
        approverKeyId: "approver-key-1",
        requestedAt: "2026-06-01T11:00:00Z",
        expiresAt: "2026-06-01T13:00:00Z",
      },
      new Date("2026-06-01T11:00:00Z"),
    );
    const approveAt = "2026-06-01T11:30:00Z";
    const decision = signApprovalDecision(
      {
        approvalId: "appr-1",
        action: "APPROVE",
        approverKeyId: "approver-key-1",
        decidedAt: approveAt,
      },
      keys.approver.privateKey,
    );
    approvals.decide(decision, new Date(approveAt));
    approvalRecords.push({ binding, decisions: [decision] });
  }

  const decision: SignedDecision = await evaluate(normalized, ctx);
  const connector: Connector = okConnector;
  const boundary = new ExecutionBoundary({
    trust,
    connectors: new Map([["payment.create", connector]]),
    now: () => NOW,
    maxDecisionAgeSeconds: 300,
    timeoutMs: 1000,
  });
  const attempt = await boundary.execute(normalized, decision);

  const ledger = new EvidenceLedger(trust, {
    keyId: "evidence-1",
    privateKey: keys.evidence.privateKey,
  });
  await ledger.append(
    draftFrom({
      evidenceId: `ev-${opts.idempotencyKey ?? "idem-1"}`,
      transactionId: "txn-1",
      recordedAt: "2026-06-01T12:00:00Z",
      normalized,
      decision,
      attempt,
    }),
  );

  const roots: TrustRootInput[] = [
    { keyId: "issuer-key-1", jwk: exportEd25519PublicJwk(keys.issuer.publicKey), status: "ACTIVE" },
    { keyId: "engine-1", jwk: exportEd25519PublicJwk(keys.engine.publicKey), status: "ACTIVE" },
    { keyId: "evidence-1", jwk: exportEd25519PublicJwk(keys.evidence.publicKey), status: "ACTIVE" },
    {
      keyId: "approver-key-1",
      jwk: exportEd25519PublicJwk(keys.approver.publicKey),
      status: "ACTIVE",
    },
  ];
  return {
    keys,
    roots,
    bundle: {
      format: BUNDLE_FORMAT,
      formatVersion: 1,
      entries: ledger.export(),
      expectedHead: ledger.head(),
      requests: [{ body: normalized.request, requestDigest: normalized.requestDigest }],
      decisions: [decision],
      authorities: [authoritySigned],
      approvals: approvalRecords,
    },
  };
}

function clone<T>(v: T): T {
  return JSON.parse(JSON.stringify(v)) as T;
}

function checkIds(r: VerificationResult, outcome: string): string[] {
  return r.checks.filter((c) => c.outcome === outcome).map((c) => c.id);
}

describe("independent verification", () => {
  it("verifies a complete executed ALLOW bundle as VALID", async () => {
    const s = await scenario({ approval: false });
    const r = verifyBundle(s.bundle, s.roots);
    expect(r.verdict).toBe("VALID");
    expect(checkIds(r, "FAIL")).toEqual([]);
  });

  it("verifies an approval-gated ALLOW, including the approval replay", async () => {
    const s = await scenario({ approval: true, amountMinor: PAISE_40K });
    const r = verifyBundle(s.bundle, s.roots);
    expect(r.verdict).toBe("VALID");
    expect(r.checks.some((c) => c.id === "APPROVAL" && c.outcome === "PASS")).toBe(true);
  });

  it("verifies a denied request bundle as VALID (authorization without execution)", async () => {
    const s = await scenario({
      approval: false,
      amountMinor: PAISE_80K,
      idempotencyKey: "idem-deny",
    });
    const r = verifyBundle(s.bundle, s.roots);
    expect(r.verdict).toBe("VALID");
  });

  it("example 6: a modified evidence field is detected", async () => {
    const s = await scenario({ approval: false });
    const bundle = clone(s.bundle);
    const entry = JSON.parse(bundle.entries[0] ?? "") as { body: { transactionId: string } };
    entry.body.transactionId = "txn-EVIL";
    bundle.entries = [canonicalize(entry)];
    const r = verifyBundle(bundle, s.roots);
    expect(r.verdict).toBe("INVALID");
    expect(checkIds(r, "FAIL")).toContain("SIGNATURE");
  });

  it("a non-canonical entry is rejected even when its content is valid", async () => {
    const s = await scenario({ approval: false });
    const parsed = JSON.parse(s.bundle.entries[0] ?? "") as unknown;
    const bundle = clone(s.bundle);
    bundle.entries = [JSON.stringify(parsed, null, 2)];
    const r = verifyBundle(bundle, s.roots);
    expect(r.verdict).toBe("INVALID");
    expect(checkIds(r, "FAIL")).toContain("CANONICAL");
  });

  it("unknown signing key is UNVERIFIABLE, not INVALID", async () => {
    const s = await scenario({ approval: false });
    const roots = s.roots.filter((root) => root.keyId !== "evidence-1");
    const r = verifyBundle(s.bundle, roots);
    expect(r.verdict).toBe("UNVERIFIABLE");
    expect(r.checks.find((c) => c.id === "SIGNATURE")?.outcome).toBe("UNVERIFIABLE");
  });

  it("a trust root holding the wrong public key makes signatures fail", async () => {
    const s = await scenario({ approval: false });
    const impostor = generateSigningKeyPair();
    const roots = s.roots.map((root) =>
      root.keyId === "evidence-1"
        ? { ...root, jwk: exportEd25519PublicJwk(impostor.publicKey) }
        : root,
    );
    expect(verifyBundle(s.bundle, roots).verdict).toBe("INVALID");
  });

  it("a revoked signing key is INVALID", async () => {
    const s = await scenario({ approval: false });
    const roots = s.roots.map((root) =>
      root.keyId === "evidence-1" ? { ...root, status: "REVOKED" as const } : root,
    );
    const r = verifyBundle(s.bundle, roots);
    expect(r.verdict).toBe("INVALID");
  });

  it("missing request body is INCOMPLETE, not VALID", async () => {
    const s = await scenario({ approval: false });
    const bundle = clone(s.bundle);
    bundle.requests = [];
    const r = verifyBundle(bundle, s.roots);
    expect(r.verdict).toBe("INCOMPLETE");
    expect(checkIds(r, "INCOMPLETE")).toContain("REQUEST");
  });

  it("a modified request body breaks its digest", async () => {
    const s = await scenario({ approval: false });
    const bundle = clone(s.bundle);
    const rec = bundle.requests[0] as { body: { parameters: { invoice: string } } };
    rec.body.parameters.invoice = "INV-EVIL";
    const r = verifyBundle(bundle, s.roots);
    expect(r.verdict).toBe("INVALID");
    expect(checkIds(r, "FAIL")).toContain("REQUEST_DIGEST");
  });

  it("a tampered decision is detected", async () => {
    const s = await scenario({ approval: false, amountMinor: PAISE_80K, idempotencyKey: "idem-t" });
    const bundle = clone(s.bundle);
    const d = bundle.decisions[0] as { body: { result: string } };
    d.body.result = "ALLOW";
    const r = verifyBundle(bundle, s.roots);
    expect(r.verdict).toBe("INVALID");
    expect(checkIds(r, "FAIL")).toContain("DECISION");
  });

  it("a missing approval record is INCOMPLETE", async () => {
    const s = await scenario({ approval: true });
    const bundle = clone(s.bundle);
    bundle.approvals = [];
    const r = verifyBundle(bundle, s.roots);
    expect(r.verdict).toBe("INCOMPLETE");
  });

  it("a rejected approval cannot support an ALLOW decision", async () => {
    const s = await scenario({ approval: true });
    const bundle = clone(s.bundle);
    const rec = bundle.approvals[0] as { decisions: { body: { action: string } }[] };
    rec.decisions[0] = {
      ...rec.decisions[0],
      body: { ...rec.decisions[0]?.body, action: "REJECT" },
    } as never;
    const r = verifyBundle(bundle, s.roots);
    expect(r.verdict).toBe("INVALID");
    expect(checkIds(r, "FAIL")).toContain("APPROVAL");
  });

  it("a broken chain (missing middle record) is detected", async () => {
    const s = await scenario({ approval: false });
    const bundle = clone(s.bundle);
    bundle.entries = [...bundle.entries, ...bundle.entries];
    const r = verifyBundle(bundle, s.roots);
    expect(r.verdict).toBe("INVALID");
    expect(checkIds(r, "FAIL")).toContain("DUPLICATE_ID");
  });

  it("tail truncation: INCOMPLETE without an anchor, INVALID against the real head", async () => {
    const s = await scenario({ approval: false });
    const noAnchor = clone(s.bundle);
    noAnchor.expectedHead = null as unknown as string;
    expect(verifyBundle(noAnchor, s.roots).verdict).toBe("INCOMPLETE");
    const anchored = clone(s.bundle);
    anchored.entries = [];
    anchored.expectedHead = s.bundle.expectedHead;
    // Removing every entry while claiming the real head is a mismatch, not an absence.
    expect(verifyBundle(anchored, s.roots).verdict).toBe("INVALID");
    const wrongHead = clone(s.bundle);
    wrongHead.expectedHead = "f".repeat(64);
    expect(verifyBundle(wrongHead, s.roots).verdict).toBe("INVALID");
  });

  it("a protocol version other than 1.0 is INVALID", async () => {
    const s = await scenario({ approval: false });
    const bundle = clone(s.bundle);
    const entry = JSON.parse(bundle.entries[0] ?? "") as { body: { protocolVersion: string } };
    entry.body.protocolVersion = "2.0";
    bundle.entries = [canonicalize(entry)];
    expect(checkIds(verifyBundle(bundle, s.roots), "FAIL")).toContain("PROTOCOL_VERSION");
  });

  it("an empty bundle is INCOMPLETE, never VALID", async () => {
    const r = verifyBundle(
      { format: BUNDLE_FORMAT, formatVersion: 1, entries: [], expectedHead: null },
      [],
    );
    expect(r.verdict).toBe("INCOMPLETE");
  });

  it("malformed trust roots stop verification with a typed error", async () => {
    expect(() =>
      verifyBundle({ format: BUNDLE_FORMAT, formatVersion: 1, entries: [] }, [
        { keyId: "bad", jwk: { kty: "OKP", crv: "Ed25519", x: "not-a-key" }, status: "ACTIVE" },
      ]),
    ).toThrow(VerifierError);
  });

  it("an unsupported bundle format is refused", async () => {
    expect(() => verifyBundle({ format: "other", formatVersion: 1, entries: [] }, [])).toThrow(
      "unsupported bundle",
    );
  });
});

describe("command line", () => {
  it("exit code 0 and JSON output for a VALID bundle", async () => {
    const s = await scenario({ approval: false });
    const files: Record<string, string> = {
      "bundle.json": JSON.stringify(s.bundle),
      "trust.json": JSON.stringify(s.roots),
    };
    const out = runCli(["--bundle", "bundle.json", "--trust", "trust.json"], (p) => files[p] ?? "");
    expect(out.exitCode).toBe(0);
    expect((JSON.parse(out.stdout) as VerificationResult).verdict).toBe("VALID");
  });

  it("exit code 1 for an INVALID bundle", async () => {
    const s = await scenario({ approval: false });
    const bundle = clone(s.bundle);
    bundle.entries = [bundle.entries[0]?.replace("ev-idem-1", "ev-x") ?? ""];
    const files: Record<string, string> = {
      "b.json": JSON.stringify(bundle),
      "t.json": JSON.stringify(s.roots),
    };
    expect(
      runCli(["--bundle", "b.json", "--trust", "t.json"], (p) => files[p] ?? "").exitCode,
    ).toBe(1);
  });

  it("exit code 2 for UNVERIFIABLE, and 3 for usage errors", async () => {
    const s = await scenario({ approval: false });
    const files: Record<string, string> = {
      "b.json": JSON.stringify(s.bundle),
      "t.json": JSON.stringify(s.roots.filter((r) => r.keyId !== "evidence-1")),
    };
    expect(
      runCli(["--bundle", "b.json", "--trust", "t.json"], (p) => files[p] ?? "").exitCode,
    ).toBe(2);
    expect(runCli([], () => "").exitCode).toBe(3);
  });
});
