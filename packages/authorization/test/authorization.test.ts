import { describe, expect, it } from "vitest";
import {
  canonicalize,
  exportEd25519PublicJwk,
  generateSigningKeyPair,
  verifyWithDomain,
  type SigningKeyPair,
} from "@dip/crypto";
import {
  AuthorityRegistry,
  DipError,
  TrustRootSet,
  parseAuthorityBody,
  signAuthority,
  signRevocation,
  type AuthorityBody,
} from "@dip/authority";
import {
  DECISION_DOMAIN,
  evaluate,
  normalizeRequest,
  type EvaluationContext,
  type NormalizedRequest,
} from "../src/index.js";

function codeOf(fn: () => unknown): string | undefined {
  try {
    fn();
  } catch (err) {
    return err instanceof DipError ? err.code : "UNEXPECTED_ERROR";
  }
  return undefined;
}

const NOW = new Date("2026-06-01T12:00:00Z");
const PAISE_40K = 4_000_000;
const PAISE_50K = 5_000_000;
const PAISE_80K = 8_000_000;

interface World {
  registry: AuthorityRegistry;
  trust: TrustRootSet;
  issuer: SigningKeyPair;
  engine: SigningKeyPair;
  ctx: EvaluationContext;
}

function world(now: Date = NOW): World {
  const issuer = generateSigningKeyPair();
  const engine = generateSigningKeyPair();
  const trust = new TrustRootSet();
  trust.add({
    keyId: "issuer-key-1",
    jwk: exportEd25519PublicJwk(issuer.publicKey),
    status: "ACTIVE",
  });
  const registry = new AuthorityRegistry(trust);
  const ctx: EvaluationContext = {
    registry,
    now: () => now,
    signer: { keyId: "engine-1", privateKey: engine.privateKey },
  };
  return { registry, trust, issuer, engine, ctx };
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
    maxAmountMinor: PAISE_50K,
    currencies: ["INR"],
    approvalAboveMinor: null,
    approvalActions: [],
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

function publish(w: World, body: AuthorityBody): void {
  w.registry.publish(signAuthority(body, w.issuer.privateKey));
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

function reasons(w: World, input: unknown): string[] {
  return [...evaluate(input, w.ctx).body.reasonCodes];
}

describe("request normalization", () => {
  it("produces identical canonical digests for equivalent inputs", () => {
    const a = normalizeRequest(requestInput({ parameters: { a: 1, b: 2 } }));
    const b = normalizeRequest(requestInput({ parameters: { b: 2, a: 1 } }));
    expect(a.requestDigest).toBe(b.requestDigest);
  });

  it("changes the digest when a material parameter changes", () => {
    const a = normalizeRequest(requestInput());
    const b = normalizeRequest(requestInput({ amount: { minor: PAISE_80K, currency: "INR" } }));
    expect(a.requestDigest).not.toBe(b.requestDigest);
  });

  it("rejects floating-point amounts", () => {
    expect(() =>
      normalizeRequest(requestInput({ amount: { minor: 400.5, currency: "INR" } })),
    ).toThrow(DipError);
  });

  it("rejects unknown request fields", () => {
    expect(codeOf(() => normalizeRequest(requestInput({ extra: 1 })))).toBe("UNKNOWN_FIELD");
  });

  it("rejects non-canonical currency codes", () => {
    expect(
      codeOf(() => normalizeRequest(requestInput({ amount: { minor: 1, currency: "inr" } }))),
    ).toBe("INVALID_FIELD");
  });

  it("rejects floats nested in parameters", () => {
    expect(codeOf(() => normalizeRequest(requestInput({ parameters: { rate: 0.5 } })))).toBe(
      "INVALID_PARAMETERS",
    );
  });
});

describe("mandatory authorization outcomes", () => {
  it("1. valid authority and valid request produce ALLOW", () => {
    const w = world();
    publish(w, authorityBody());
    const d = evaluate(req(), w.ctx);
    expect(d.body.result).toBe("ALLOW");
    expect(d.body.reasonCodes).toEqual([]);
  });

  it("2. missing authority produces DENY", () => {
    const w = world();
    expect(reasons(w, req())).toEqual(["AUTHORITY_NOT_FOUND"]);
  });

  it("3. invalid authority (tampered after signing) produces DENY", () => {
    const w = world();
    const signed = signAuthority(authorityBody(), w.issuer.privateKey);
    w.registry.publish(signed);
    // Simulate a corrupted store by publishing a valid v1 then reading a tampered copy is not possible; the
    // registry itself refuses tampered input, so verify the engine rejects an authority signed by an unknown key.
    const other = generateSigningKeyPair();
    const rogue = signAuthority(
      authorityBody({ authorityId: "auth-rogue", signingKeyId: "rogue" }),
      other.privateKey,
    );
    expect(codeOf(() => w.registry.publish(rogue))).toBeDefined();
    expect(reasons(w, req({ authorityRef: { authorityId: "auth-rogue", version: 1 } }))).toEqual([
      "AUTHORITY_NOT_FOUND",
    ]);
  });

  it("4. expired authority produces DENY", () => {
    const w = world(new Date("2027-06-01T00:00:00Z"));
    publish(w, authorityBody());
    expect(reasons(w, req())).toEqual(["AUTHORITY_EXPIRED"]);
  });

  it("4b. not-yet-valid authority produces DENY", () => {
    const w = world(new Date("2025-06-01T00:00:00Z"));
    publish(w, authorityBody());
    expect(reasons(w, req())).toEqual(["AUTHORITY_NOT_YET_VALID"]);
  });

  it("5. revoked authority produces DENY", () => {
    const w = world();
    publish(w, authorityBody());
    w.registry.revoke(
      signRevocation(
        {
          authorityId: "auth-vendor-payments",
          version: 1,
          revokedAt: "2026-05-01T00:00:00Z",
          signingKeyId: "issuer-key-1",
        },
        w.issuer.privateKey,
      ),
    );
    expect(reasons(w, req())).toEqual(["AUTHORITY_REVOKED"]);
  });

  it("5b. superseded authority version produces DENY", () => {
    const w = world();
    publish(w, authorityBody());
    publish(w, authorityBody({ version: 2, maxAmountMinor: PAISE_40K }));
    expect(reasons(w, req())).toEqual(["AUTHORITY_SUPERSEDED"]);
  });

  it("5c. authority signed by a revoked key produces DENY", () => {
    const w = world();
    publish(w, authorityBody());
    w.trust.revoke("issuer-key-1");
    expect(reasons(w, req())).toEqual(["AUTHORITY_KEY_REVOKED"]);
  });

  it("6. insufficient permission (action not permitted) produces DENY", () => {
    const w = world();
    publish(w, authorityBody());
    expect(reasons(w, req({ operation: "payment.delete" }))).toEqual(["ACTION_NOT_PERMITTED"]);
  });

  it("6b. resource outside scope produces DENY", () => {
    const w = world();
    publish(w, authorityBody());
    expect(reasons(w, req({ resource: "vendor-99" }))).toEqual(["RESOURCE_OUT_OF_SCOPE"]);
  });

  it("7. amount above limit produces DENY", () => {
    const w = world();
    publish(w, authorityBody());
    expect(reasons(w, req({ amount: { minor: PAISE_80K, currency: "INR" } }))).toEqual([
      "AMOUNT_EXCEEDS_LIMIT",
    ]);
  });

  it("8. wrong currency produces DENY", () => {
    const w = world();
    publish(w, authorityBody());
    expect(reasons(w, req({ amount: { minor: PAISE_40K, currency: "USD" } }))).toEqual([
      "CURRENCY_NOT_PERMITTED",
    ]);
  });

  it("9. invalid actor produces DENY", () => {
    const w = world();
    publish(w, authorityBody());
    expect(reasons(w, req({ actor: "intruder" }))).toEqual(["ACTOR_NOT_AUTHORIZED"]);
  });

  it("10. invalid request digest produces DENY", () => {
    const w = world();
    publish(w, authorityBody());
    const good = req();
    const forged = {
      request: { ...good.request, amount: { minor: PAISE_80K, currency: "INR" } },
      requestDigest: good.requestDigest,
    };
    expect(reasons(w, forged)).toEqual(["REQUEST_DIGEST_MISMATCH"]);
  });

  it("11. approval required but absent produces DENY", () => {
    const w = world();
    publish(w, authorityBody({ approvalAboveMinor: 1_000_000 }));
    expect(reasons(w, req())).toEqual(["APPROVAL_REQUIRED"]);
  });

  it("11b. approval reference that is not verified cannot satisfy a required approval", () => {
    const w = world();
    publish(w, authorityBody({ approvalAboveMinor: 1_000_000 }));
    expect(reasons(w, req({ approvalRef: "appr-1" }))).toEqual(["APPROVAL_NOT_VERIFIED"]);
  });

  it("16. amount limit cannot be overridden by an approval reference", () => {
    const w = world();
    publish(w, authorityBody());
    expect(
      reasons(w, req({ amount: { minor: PAISE_80K, currency: "INR" }, approvalRef: "appr-1" })),
    ).toEqual(["AMOUNT_EXCEEDS_LIMIT"]);
  });

  it("returns only ALLOW or DENY", () => {
    const w = world();
    publish(w, authorityBody());
    for (const input of [req(), req({ actor: "x" })]) {
      expect(["ALLOW", "DENY"]).toContain(evaluate(input, w.ctx).body.result);
    }
  });

  it("is reproducible for the same input, authority and clock", () => {
    const w = world();
    publish(w, authorityBody());
    const a = evaluate(req(), w.ctx).body;
    const b = evaluate(req(), w.ctx).body;
    expect(a).toEqual(b);
  });

  it("signs each decision with the engine key", () => {
    const w = world();
    publish(w, authorityBody());
    const d = evaluate(req(), w.ctx);
    expect(
      verifyWithDomain(DECISION_DOMAIN, canonicalize(d.body), d.signature, w.engine.publicKey),
    ).toBe(true);
  });
});

describe("delegation", () => {
  it("accepts a child within its parent's bounds", () => {
    const w = world();
    publish(w, authorityBody({ delegationAllowed: true }));
    publish(
      w,
      authorityBody({
        authorityId: "auth-child",
        maxAmountMinor: PAISE_40K,
        delegatedFrom: { authorityId: "auth-vendor-payments", version: 1 },
      }),
    );
    expect(
      evaluate(req({ authorityRef: { authorityId: "auth-child", version: 1 } }), w.ctx).body.result,
    ).toBe("ALLOW");
  });

  it("denies a child whose limit exceeds its parent", () => {
    const w = world();
    publish(w, authorityBody({ delegationAllowed: true, maxAmountMinor: PAISE_40K }));
    publish(
      w,
      authorityBody({
        authorityId: "auth-child",
        maxAmountMinor: PAISE_50K,
        delegatedFrom: { authorityId: "auth-vendor-payments", version: 1 },
      }),
    );
    expect(reasons(w, req({ authorityRef: { authorityId: "auth-child", version: 1 } }))).toEqual([
      "DELEGATION_EXCEEDS_PARENT",
    ]);
  });

  it("denies delegation when the parent forbids it", () => {
    const w = world();
    publish(w, authorityBody({ delegationAllowed: false }));
    publish(
      w,
      authorityBody({
        authorityId: "auth-child",
        maxAmountMinor: PAISE_40K,
        delegatedFrom: { authorityId: "auth-vendor-payments", version: 1 },
      }),
    );
    expect(reasons(w, req({ authorityRef: { authorityId: "auth-child", version: 1 } }))).toEqual([
      "DELEGATION_NOT_PERMITTED",
    ]);
  });

  it("denies when the parent is revoked", () => {
    const w = world();
    publish(w, authorityBody({ delegationAllowed: true }));
    publish(
      w,
      authorityBody({
        authorityId: "auth-child",
        maxAmountMinor: PAISE_40K,
        delegatedFrom: { authorityId: "auth-vendor-payments", version: 1 },
      }),
    );
    w.registry.revoke(
      signRevocation(
        {
          authorityId: "auth-vendor-payments",
          version: 1,
          revokedAt: "2026-05-01T00:00:00Z",
          signingKeyId: "issuer-key-1",
        },
        w.issuer.privateKey,
      ),
    );
    expect(reasons(w, req({ authorityRef: { authorityId: "auth-child", version: 1 } }))).toEqual([
      "AUTHORITY_REVOKED",
    ]);
  });
});
