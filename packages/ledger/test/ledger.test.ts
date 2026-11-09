import { describe, expect, it } from "vitest";
import {
  DipError,
  TrustRootSet,
  AuthorityRegistry,
  parseAuthorityBody,
  signAuthority,
  type AuthorityBody,
} from "@dip/authority";
import { ApprovalStore } from "@dip/approval";
import {
  evaluate,
  normalizeRequest,
  type EvaluationContext,
  type NormalizedRequest,
} from "@dip/authorization";
import {
  canonicalize,
  exportEd25519PublicJwk,
  generateSigningKeyPair,
  type SigningKeyPair,
} from "@dip/crypto";
import {
  ExecutionBoundary,
  type Connector,
  type ConnectorResult,
  type ExecutionAttempt,
} from "@dip/execution";
import { GENESIS_DIGEST, createEvidence, entryDigest, type SignedEvidence } from "@dip/evidence";
import { EvidenceLedger, draftFrom, verifyChain } from "../src/index.js";

const NOW = new Date("2026-06-01T12:00:00Z");
const PAISE_40K = 4_000_000;
const PAISE_80K = 8_000_000;

interface World {
  trust: TrustRootSet;
  issuer: SigningKeyPair;
  engine: SigningKeyPair;
  evidence: SigningKeyPair;
  registry: AuthorityRegistry;
  ctx: EvaluationContext;
  ledger: EvidenceLedger;
}

function world(): World {
  const issuer = generateSigningKeyPair();
  const engine = generateSigningKeyPair();
  const evidence = generateSigningKeyPair();
  const trust = new TrustRootSet();
  trust.add({
    keyId: "issuer-key-1",
    jwk: exportEd25519PublicJwk(issuer.publicKey),
    status: "ACTIVE",
  });
  trust.add({ keyId: "engine-1", jwk: exportEd25519PublicJwk(engine.publicKey), status: "ACTIVE" });
  trust.add({
    keyId: "evidence-1",
    jwk: exportEd25519PublicJwk(evidence.publicKey),
    status: "ACTIVE",
  });
  const registry = new AuthorityRegistry(trust);
  const ctx: EvaluationContext = {
    registry,
    now: () => NOW,
    signer: { keyId: "engine-1", privateKey: engine.privateKey },
    approvals: new ApprovalStore(trust),
  };
  const ledger = new EvidenceLedger(trust, {
    keyId: "evidence-1",
    privateKey: evidence.privateKey,
  });
  return { trust, issuer, engine, evidence, registry, ctx, ledger };
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

function req(overrides: Record<string, unknown> = {}): NormalizedRequest {
  return normalizeRequest({
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
  });
}

function okConnector(): Connector {
  return {
    id: "payments-test",
    execute: async (): Promise<ConnectorResult> => ({
      status: "SUCCEEDED",
      externalRef: "pay-001",
    }),
  };
}

/** Full pipeline for one request: authorize, then execute through the boundary if ALLOW. */
async function pipeline(
  w: World,
  input: NormalizedRequest,
  id: string,
  connector: Connector = okConnector(),
): Promise<ExecutionAttempt | null> {
  const decision = evaluate(input, w.ctx);
  let attempt: ExecutionAttempt | null = null;
  {
    const boundary = new ExecutionBoundary({
      trust: w.trust,
      connectors: new Map([["payment.create", connector]]),
      now: () => NOW,
      maxDecisionAgeSeconds: 300,
      timeoutMs: 1000,
    });
    attempt = await boundary.execute(input, decision);
  }
  w.ledger.append(
    draftFrom({
      evidenceId: id,
      transactionId: "txn-1",
      recordedAt: NOW.toISOString().replace(".000Z", "Z"),
      normalized: input,
      decision,
      attempt,
    }),
  );
  return attempt;
}

function codesOf(report: ReturnType<EvidenceLedger["verify"]>): string[] {
  return report.errors.map((e) => `${String(e.index)}:${e.code}`);
}

describe("evidence and ledger pipeline", () => {
  it("records an authorized, executed action and verifies the chain", async () => {
    const w = world();
    w.registry.publish(signAuthority(authorityBody(), w.issuer.privateKey));
    const attempt = await pipeline(w, req(), "ev-1");
    expect(attempt?.state).toBe("SUCCEEDED");
    const report = w.ledger.verify(w.ledger.head());
    expect(report.valid).toBe(true);
    expect(report.entries).toBe(1);
  });

  it("records a denied request with no execution section", async () => {
    const w = world();
    w.registry.publish(signAuthority(authorityBody(), w.issuer.privateKey));
    const attempt = await pipeline(
      w,
      req({ amount: { minor: PAISE_80K, currency: "INR" } }),
      "ev-deny",
    );
    expect(attempt).not.toBeNull();
    const line = JSON.parse(w.ledger.export()[0] ?? "") as {
      body: { authorization: { result: string }; execution: unknown };
    };
    expect(line.body.authorization.result).toBe("DENY");
    expect(w.ledger.verify().valid).toBe(true);
  });

  it("records a refused execution against a denied decision, separately from authorization", async () => {
    const w = world();
    w.registry.publish(signAuthority(authorityBody(), w.issuer.privateKey));
    const input = req({ amount: { minor: PAISE_80K, currency: "INR" } });
    const decision = evaluate(input, w.ctx);
    const boundary = new ExecutionBoundary({
      trust: w.trust,
      connectors: new Map([["payment.create", okConnector()]]),
      now: () => NOW,
      maxDecisionAgeSeconds: 300,
      timeoutMs: 1000,
    });
    const attempt = await boundary.execute(input, decision);
    w.ledger.append(
      draftFrom({
        evidenceId: "ev-ref",
        transactionId: "txn-1",
        recordedAt: "2026-06-01T12:00:00Z",
        normalized: input,
        decision,
        attempt,
      }),
    );
    expect(attempt.state).toBe("REFUSED");
    expect(w.ledger.verify().valid).toBe(true);
  });

  it("refuses to create a SUCCEEDED execution for a DENY authorization", () => {
    const w = world();
    const body = {
      evidenceId: "ev-bad",
      transactionId: "txn-1",
      recordedAt: "2026-06-01T12:00:00Z",
      request: { requestId: "r", requestDigest: "a".repeat(64), idempotencyKey: "k" },
      authorization: {
        decisionId: "b".repeat(64),
        result: "DENY" as const,
        reasonCodes: ["AMOUNT_EXCEEDS_LIMIT"],
        authorityRef: { authorityId: "a", version: 1 },
        policyRef: { policyId: "p", version: 1 },
        evaluatedAt: "2026-06-01T12:00:00Z",
        decisionSigningKeyId: "engine-1",
      },
      approvalRef: null,
      execution: {
        state: "SUCCEEDED" as const,
        connectorId: "c",
        reasonCode: null,
        externalRef: "x",
        attemptedAt: "2026-06-01T12:00:00Z",
      },
    };
    expect(() =>
      createEvidence(
        body,
        { sequence: 1, previousDigest: GENESIS_DIGEST },
        { keyId: "evidence-1", privateKey: w.evidence.privateKey },
      ),
    ).toThrow(DipError);
  });

  it("refuses ALLOW with reason codes and DENY without reason codes", () => {
    const w = world();
    const base = {
      evidenceId: "ev-x",
      transactionId: "txn-1",
      recordedAt: "2026-06-01T12:00:00Z",
      request: { requestId: "r", requestDigest: "a".repeat(64), idempotencyKey: "k" },
      authorization: {
        decisionId: "b".repeat(64),
        result: "ALLOW" as const,
        reasonCodes: ["X"],
        authorityRef: { authorityId: "a", version: 1 },
        policyRef: { policyId: "p", version: 1 },
        evaluatedAt: "2026-06-01T12:00:00Z",
        decisionSigningKeyId: "engine-1",
      },
      approvalRef: null,
      execution: null,
    };
    const key = { keyId: "evidence-1", privateKey: w.evidence.privateKey };
    expect(() =>
      createEvidence(base, { sequence: 1, previousDigest: GENESIS_DIGEST }, key),
    ).toThrow("ALLOW_WITH_REASON");
    const deny = {
      ...base,
      authorization: { ...base.authorization, result: "DENY" as const, reasonCodes: [] },
    };
    expect(() =>
      createEvidence(deny, { sequence: 1, previousDigest: GENESIS_DIGEST }, key),
    ).toThrow("DENY_WITHOUT_REASON");
  });
});

describe("ledger integrity", () => {
  async function three(): Promise<World> {
    const w = world();
    w.registry.publish(signAuthority(authorityBody(), w.issuer.privateKey));
    await pipeline(w, req(), "ev-1");
    await pipeline(w, req({ idempotencyKey: "idem-2" }), "ev-2");
    await pipeline(
      w,
      req({ idempotencyKey: "idem-3", amount: { minor: PAISE_80K, currency: "INR" } }),
      "ev-3",
    );
    return w;
  }

  it("detects a modified field through the signature", async () => {
    const w = await three();
    const lines = w.ledger.export();
    const tampered = JSON.parse(lines[1] ?? "") as { body: { transactionId: string } };
    tampered.body.transactionId = "txn-EVIL";
    const bad = [lines[0] ?? "", JSON.stringify(tampered), lines[2] ?? ""];
    expect(codesOf(verifyChain(bad, w.trust))).toEqual([
      "1:EVIDENCE_SIGNATURE_INVALID",
      "2:CHAIN_BROKEN",
    ]);
  });

  it("detects a deleted middle entry", async () => {
    const w = await three();
    const lines = w.ledger.export();
    const report = verifyChain([lines[0] ?? "", lines[2] ?? ""], w.trust);
    expect(report.valid).toBe(false);
    expect(report.errors.map((e) => e.code)).toContain("SEQUENCE_MISMATCH");
    expect(report.errors.map((e) => e.code)).toContain("CHAIN_BROKEN");
  });

  it("detects reordered entries", async () => {
    const w = await three();
    const lines = w.ledger.export();
    const report = verifyChain([lines[1] ?? "", lines[0] ?? "", lines[2] ?? ""], w.trust);
    expect(report.valid).toBe(false);
    expect(report.errors.map((e) => e.code)).toContain("SEQUENCE_MISMATCH");
  });

  it("detects tail truncation only when an external head is supplied", async () => {
    const w = await three();
    const head = w.ledger.head();
    const lines = w.ledger.export();
    expect(verifyChain(lines.slice(0, 2), w.trust).valid).toBe(true);
    const anchored = verifyChain(lines.slice(0, 2), w.trust, head);
    expect(anchored.errors.map((e) => e.code)).toEqual(["HEAD_MISMATCH"]);
  });

  it("refuses a duplicate evidence id on append", async () => {
    const w = await three();
    expect(() => w.ledger.append(draftOf("ev-1"))).toThrow("already recorded");
    expect(w.ledger.size()).toBe(3);
  });

  it("detects a duplicate evidence id that appears with a valid chain", async () => {
    const w = await three();
    const lines = w.ledger.export();
    const first = JSON.parse(lines[0] ?? "") as SignedEvidence;
    const copy = createEvidence(
      {
        evidenceId: first.body.evidenceId,
        transactionId: first.body.transactionId,
        recordedAt: first.body.recordedAt,
        request: first.body.request,
        authorization: first.body.authorization,
        approvalRef: first.body.approvalRef,
        execution: first.body.execution,
      },
      { sequence: 4, previousDigest: w.ledger.head() },
      { keyId: "evidence-1", privateKey: w.evidence.privateKey },
    );
    const report = verifyChain([...lines, canonicalize(copy)], w.trust);
    expect(report.errors.map((e) => e.code)).toEqual(["DUPLICATE_EVIDENCE_ID"]);
  });

  it("rejects entries signed by an unknown key", async () => {
    const w = await three();
    const rogue = generateSigningKeyPair();
    const first = JSON.parse(w.ledger.export()[0] ?? "") as SignedEvidence;
    const forged = createEvidence(
      {
        evidenceId: "ev-forged",
        transactionId: "txn-1",
        recordedAt: "2026-06-01T12:00:00Z",
        request: first.body.request,
        authorization: first.body.authorization,
        approvalRef: null,
        execution: null,
      },
      { sequence: 1, previousDigest: GENESIS_DIGEST },
      { keyId: "evidence-1", privateKey: rogue.privateKey },
    );
    expect(codesOf(verifyChain([canonicalize(forged)], w.trust))).toEqual([
      "0:EVIDENCE_SIGNATURE_INVALID",
    ]);
  });

  it("reports malformed lines without throwing", () => {
    const w = world();
    expect(codesOf(verifyChain(["{not json"], w.trust))).toEqual(["0:MALFORMED"]);
  });

  it("verifies an exported chain independently of the writing ledger", async () => {
    const w = await three();
    const exported = w.ledger.export();
    const verifierTrust = new TrustRootSet();
    verifierTrust.add({
      keyId: "evidence-1",
      jwk: exportEd25519PublicJwk(w.evidence.publicKey),
      status: "ACTIVE",
    });
    const report = verifyChain(exported, verifierTrust, w.ledger.head());
    expect(report.valid).toBe(true);
    expect(report.entries).toBe(3);
  });

  it("entry digest changes when any byte of an entry changes", async () => {
    const w = await three();
    const original = JSON.parse(w.ledger.export()[0] ?? "") as SignedEvidence;
    const changed = { ...original, body: { ...original.body, recordedAt: "2026-06-02T00:00:00Z" } };
    expect(entryDigest(changed)).not.toBe(entryDigest(original));
  });
});

function draftOf(id: string): Parameters<EvidenceLedger["append"]>[0] {
  return {
    evidenceId: id,
    transactionId: "txn-1",
    recordedAt: "2026-06-01T12:00:00Z",
    request: { requestId: "r", requestDigest: "a".repeat(64), idempotencyKey: "k" },
    authorization: {
      decisionId: "b".repeat(64),
      result: "DENY",
      reasonCodes: ["X"],
      authorityRef: { authorityId: "a", version: 1 },
      policyRef: { policyId: "p", version: 1 },
      evaluatedAt: "2026-06-01T12:00:00Z",
      decisionSigningKeyId: "engine-1",
    },
    approvalRef: null,
    execution: null,
  };
}
