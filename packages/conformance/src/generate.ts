import { createHash, createPrivateKey, createPublicKey, type KeyObject } from "node:crypto";
import { parseAuthorityBody, signAuthority, type AuthorityBody } from "@dip/authority";
import { signApprovalDecision } from "@dip/approval";
import { exportEd25519PublicJwk, canonicalize, digestWithDomain } from "@dip/crypto";
import { DipClient } from "@dip/sdk";
import type { TrustRootInput } from "@dip/verifier";
import type { BundleCase, CanonicalCase } from "./runner.js";

/**
 * Deterministic fixture generator. Keys derive from public names via SHA-256, so
 * the suite is reproducible. These keys are test-only. Fixtures contain public
 * keys, signed records and expected verdicts, and never private key material.
 */
const PKCS8_ED25519_PREFIX = "302e020100300506032b657004220420";
const NOW = new Date("2026-06-01T12:00:00Z");
type KeyName = "issuer" | "engine" | "evidence" | "approver";

function keyFor(name: string): KeyObject {
  const seed = createHash("sha256").update(`dip-conformance-test-key:${name}`).digest();
  return createPrivateKey({
    key: Buffer.concat([Buffer.from(PKCS8_ED25519_PREFIX, "hex"), seed]),
    format: "der",
    type: "pkcs8",
  });
}

const KEYS: Record<KeyName, KeyObject> = {
  issuer: keyFor("issuer"),
  engine: keyFor("engine"),
  evidence: keyFor("evidence"),
  approver: keyFor("approver"),
};

export const TRUST: TrustRootInput[] = [
  {
    keyId: "issuer-key-1",
    jwk: exportEd25519PublicJwk(createPublicKey(KEYS.issuer)),
    status: "ACTIVE",
  },
  {
    keyId: "engine-1",
    jwk: exportEd25519PublicJwk(createPublicKey(KEYS.engine)),
    status: "ACTIVE",
  },
  {
    keyId: "evidence-1",
    jwk: exportEd25519PublicJwk(createPublicKey(KEYS.evidence)),
    status: "ACTIVE",
  },
  {
    keyId: "approver-key-1",
    jwk: exportEd25519PublicJwk(createPublicKey(KEYS.approver)),
    status: "ACTIVE",
  },
];

function authorityBody(): AuthorityBody {
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
  });
}

function requestRaw(amountMinor: number, approvalRef: string | null): Record<string, unknown> {
  return {
    requestId: "req-1",
    transactionId: "txn-1",
    organizationId: "org-acme",
    tenantId: "tenant-1",
    actor: "payments-agent",
    operation: "payment.create",
    resource: "vendor-42",
    amount: { minor: amountMinor, currency: "INR" },
    parameters: { invoice: "INV-7", payeeAccount: "acc-9" },
    authorityRef: { authorityId: "auth-vendor-payments", version: 1 },
    policyRef: { policyId: "policy-payments", version: 1 },
    approvalRef,
    idempotencyKey: "idem-1",
    protocolVersion: "1.0",
  };
}

export interface Scenario {
  readonly bundle: Record<string, unknown>;
}

/** Runs the real pipeline with deterministic keys and exports the bundle an auditor would receive. */
export async function scenario(opts: {
  amountMinor: number;
  approval: boolean;
}): Promise<Scenario> {
  const client = new DipClient({
    trustRoots: TRUST.map((t) => ({ ...t })),
    engine: { keyId: "engine-1", privateKey: KEYS.engine },
    evidenceSigner: { keyId: "evidence-1", privateKey: KEYS.evidence },
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
  const authority = signAuthority(authorityBody(), KEYS.issuer);
  client.publishAuthority(authority);
  const approvalRef = opts.approval ? "appr-1" : null;
  const normalized = client.normalizeRequest(requestRaw(opts.amountMinor, approvalRef));
  const approvalRecords: unknown[] = [];
  if (opts.approval) {
    const binding = client.requestApproval({
      approvalId: "appr-1",
      organizationId: "org-acme",
      requestDigest: normalized.requestDigest,
      authorityRef: { authorityId: "auth-vendor-payments", version: 1 },
      policyRef: { policyId: "policy-payments", version: 1 },
      approverKeyId: "approver-key-1",
      requestedAt: "2026-06-01T11:00:00Z",
      expiresAt: "2026-06-01T13:00:00Z",
    });
    const decision = signApprovalDecision(
      {
        approvalId: "appr-1",
        action: "APPROVE",
        approverKeyId: "approver-key-1",
        decidedAt: "2026-06-01T11:30:00Z",
      },
      KEYS.approver,
    );
    client.approve(decision);
    approvalRecords.push({ binding, decisions: [decision] });
  }
  const outcome = client.authorize(normalized);
  const attempt = await client.execute(normalized, outcome.decision);
  client.record({ normalized, decision: outcome.decision, attempt });
  return {
    bundle: {
      format: "dip-evidence-bundle",
      formatVersion: 1,
      entries: client.ledgerLines(),
      expectedHead: client.ledgerHead(),
      requests: [{ body: normalized.request, requestDigest: normalized.requestDigest }],
      decisions: [outcome.decision],
      authorities: [client.getAuthority("auth-vendor-payments", 1)],
      approvals: approvalRecords,
    },
  };
}

type Bundle = Record<string, unknown> & {
  entries: string[];
  requests: unknown[];
  approvals: unknown[];
};

function clone(b: Bundle): Bundle {
  return JSON.parse(JSON.stringify(b)) as Bundle;
}

export async function buildBundleCases(): Promise<BundleCase[]> {
  const base = (await scenario({ amountMinor: 400_000, approval: false })).bundle as Bundle;
  const deny = (await scenario({ amountMinor: 8_000_000, approval: false })).bundle as Bundle;
  const approved = (await scenario({ amountMinor: 2_000_000, approval: true })).bundle as Bundle;
  const cases: BundleCase[] = [];
  const add = (
    id: string,
    description: string,
    bundle: unknown,
    trust: TrustRootInput[],
    verdict: string,
    mustInclude?: string[],
  ): void => {
    cases.push({
      id,
      description,
      bundle,
      trust,
      expected: { verdict, ...(mustInclude ? { mustInclude } : {}) },
    });
  };

  add("valid-allow-executed", "ALLOW decision, executed, chain intact", base, TRUST, "VALID");
  add("valid-deny-recorded", "DENY decision recorded with no execution", deny, TRUST, "VALID");
  add("valid-approval-gated", "ALLOW gated by an approved approval", approved, TRUST, "VALID");

  const tampered = clone(base);
  const t = JSON.parse(tampered.entries[0] ?? "") as { body: { transactionId: string } };
  t.body.transactionId = "txn-EVIL";
  tampered.entries = [canonicalize(t)];
  add(
    "invalid-tampered-entry",
    "one evidence field modified after signing",
    tampered,
    TRUST,
    "INVALID",
    ["SIGNATURE"],
  );

  const modifiedRequest = clone(base);
  (
    modifiedRequest.requests[0] as { body: { parameters: { invoice: string } } }
  ).body.parameters.invoice = "INV-EVIL";
  add(
    "invalid-modified-request",
    "request body changed; digest no longer matches",
    modifiedRequest,
    TRUST,
    "INVALID",
    ["REQUEST_DIGEST"],
  );

  const broken = clone(base);
  broken.entries = [...base.entries, ...base.entries];
  add(
    "invalid-duplicate-entries",
    "chain with a repeated evidence record",
    broken,
    TRUST,
    "INVALID",
    ["DUPLICATE_ID"],
  );

  const rejected = clone(approved);
  const rec = rejected.approvals[0] as { decisions: { body: { action: string } }[] };
  const dec = rec.decisions[0];
  if (dec) dec.body.action = "REJECT";
  add(
    "invalid-approval-altered",
    "approval decision altered to REJECT but still carries the APPROVE signature",
    rejected,
    TRUST,
    "INVALID",
    ["APPROVAL"],
  );

  const noncanon = clone(base);
  noncanon.entries = [JSON.stringify(JSON.parse(base.entries[0] ?? ""), null, 2)];
  add(
    "invalid-non-canonical-entry",
    "entry is valid JSON but not canonically encoded",
    noncanon,
    TRUST,
    "INVALID",
    ["CANONICAL"],
  );

  const missing = clone(base);
  missing.requests = [];
  add(
    "incomplete-missing-request",
    "request body withheld; nothing shown false",
    missing,
    TRUST,
    "INCOMPLETE",
    ["REQUEST"],
  );

  const noEvidenceKey = TRUST.filter((r) => r.keyId !== "evidence-1");
  add(
    "unverifiable-unknown-evidence-key",
    "evidence signing key not among the trust roots",
    base,
    noEvidenceKey,
    "UNVERIFIABLE",
    ["SIGNATURE"],
  );

  return cases;
}

export function buildCanonicalCases(): CanonicalCase[] {
  const cases: CanonicalCase[] = [];
  const add = (c: CanonicalCase): void => {
    cases.push(c);
  };
  const v1 = { b: 1, a: 2 };
  add({ id: "sorted-keys", input: v1, canonical: '{"a":2,"b":1}' });
  const v2 = { z: [{ y: 1, x: null }], a: true };
  add({ id: "nested-and-null", input: v2, canonical: '{"a":true,"z":[{"x":null,"y":1}]}' });
  add({ id: "string-escapes", input: 'a"b\nc', canonical: '"a\\"b\\nc"' });
  add({ id: "unicode-kept", input: { name: "₹" }, canonical: '{"name":"₹"}' });
  add({ id: "reject-float", input: { rate: 1.5 }, expectError: "CanonicalEncodingError" });
  const d = canonicalize({ requestDigest: "x" });
  add({
    id: "domain-separated-digest",
    input: { requestDigest: "x" },
    canonical: d,
    domain: "DIP-DECISION-V1",
    sha256: digestWithDomain("DIP-DECISION-V1", d),
  });
  return cases;
}

export function suiteFiles(
  bundles: BundleCase[],
  canonical: CanonicalCase[],
): Record<string, string> {
  const files: Record<string, string> = {};
  files["canonical.json"] =
    JSON.stringify(
      { suite: "dip-conformance", suiteVersion: "1.0.0", protocolVersion: "1.0", cases: canonical },
      null,
      2,
    ) + "\n";
  for (const b of bundles) {
    files[`bundles/${b.id}.json`] = JSON.stringify(b, null, 2) + "\n";
  }
  files["manifest.json"] =
    JSON.stringify(
      {
        suite: "dip-conformance",
        suiteVersion: "1.0.0",
        protocolVersion: "1.0",
        canonical: "canonical.json",
        bundles: bundles.map((b) => `bundles/${b.id}.json`),
      },
      null,
      2,
    ) + "\n";
  return files;
}
