import { describe, expect, it } from "vitest";
import {
  canonicalize,
  exportEd25519PublicJwk,
  generateSigningKeyPair,
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
} from "../src/index.js";

function codeOf(fn: () => unknown): string | undefined {
  try {
    fn();
  } catch (err) {
    return err instanceof DipError ? err.code : "UNEXPECTED_ERROR";
  }
  return undefined;
}

function body(overrides: Partial<AuthorityBody> = {}): AuthorityBody {
  return {
    authorityId: "auth-vendor-payments",
    version: 1,
    organizationId: "org-acme",
    tenantId: "tenant-1",
    issuer: "cfo-office",
    principal: "cfo",
    agent: "payments-agent",
    permittedActions: ["payment.create"],
    resourceScope: ["vendor-42"],
    maxAmountMinor: 5_000_000, // ₹50,000.00 in paise
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
  };
}

function setup(): { registry: AuthorityRegistry; trust: TrustRootSet; keys: SigningKeyPair } {
  const keys = generateSigningKeyPair();
  const trust = new TrustRootSet();
  trust.add({
    keyId: "issuer-key-1",
    jwk: exportEd25519PublicJwk(keys.publicKey),
    status: "ACTIVE",
  });
  return { registry: new AuthorityRegistry(trust), trust, keys };
}

describe("authority body validation", () => {
  it("accepts a well-formed declaration", () => {
    expect(parseAuthorityBody(body()).version).toBe(1);
  });

  it("rejects unknown fields", () => {
    expect(codeOf(() => parseAuthorityBody({ ...body(), extra: true }))).toBeDefined();
  });

  it("rejects a non-integer limit (no floating-point money)", () => {
    const raw = { ...body(), maxAmountMinor: 50000.5 };
    expect(codeOf(() => parseAuthorityBody(raw))).toBeDefined();
  });

  it("rejects an inverted validity window", () => {
    expect(() => parseAuthorityBody({ ...body(), validFrom: "2028-01-01T00:00:00Z" })).toThrow(
      "validFrom must be before validUntil",
    );
  });

  it("rejects unsorted action lists (non-canonical form)", () => {
    expect(() => parseAuthorityBody({ ...body(), permittedActions: ["b", "a"] })).toThrow(
      "strictly ascending",
    );
  });

  it("rejects lowercase currency codes", () => {
    expect(codeOf(() => parseAuthorityBody({ ...body(), currencies: ["inr"] }))).toBeDefined();
  });
});

describe("authority publication", () => {
  it("publishes a signed version that verifies", () => {
    const { registry, keys } = setup();
    const signed = signAuthority(parseAuthorityBody(body()), keys.privateKey);
    expect(registry.publish(signed).body.authorityId).toBe("auth-vendor-payments");
    expect(registry.latestVersion("auth-vendor-payments")).toBe(1);
  });

  it("rejects a tampered body (signature no longer matches)", () => {
    const { registry, keys } = setup();
    const signed = signAuthority(parseAuthorityBody(body()), keys.privateKey);
    const tampered = {
      body: { ...signed.body, maxAmountMinor: 9_999_999_999 },
      signature: signed.signature,
    };
    expect(codeOf(() => registry.publish(tampered))).toBe("AUTHORITY_SIGNATURE_INVALID");
  });

  it("rejects an unknown signing key", () => {
    const { registry, keys } = setup();
    const signed = signAuthority(
      parseAuthorityBody(body({ signingKeyId: "other-key" })),
      keys.privateKey,
    );
    expect(codeOf(() => registry.publish(signed))).toBe("AUTHORITY_KEY_UNKNOWN");
  });

  it("rejects a signature from the wrong key", () => {
    const { registry } = setup();
    const impostor = generateSigningKeyPair();
    const signed = signAuthority(parseAuthorityBody(body()), impostor.privateKey);
    expect(codeOf(() => registry.publish(signed))).toBe("AUTHORITY_SIGNATURE_INVALID");
  });

  it("rejects publication under a revoked key", () => {
    const { registry, trust, keys } = setup();
    trust.revoke("issuer-key-1");
    const signed = signAuthority(parseAuthorityBody(body()), keys.privateKey);
    expect(codeOf(() => registry.publish(signed))).toBe("AUTHORITY_KEY_REVOKED");
  });

  it("never replaces a published version", () => {
    const { registry, keys } = setup();
    const signed = signAuthority(parseAuthorityBody(body()), keys.privateKey);
    registry.publish(signed);
    expect(codeOf(() => registry.publish(signed))).toBe("AUTHORITY_ALREADY_PUBLISHED");
  });

  it("requires contiguous version numbers", () => {
    const { registry, keys } = setup();
    const v2 = signAuthority(parseAuthorityBody(body({ version: 2 })), keys.privateKey);
    expect(codeOf(() => registry.publish(v2))).toBe("AUTHORITY_VERSION_GAP");
  });

  it("returns stored versions with unchanged canonical bytes", () => {
    const { registry, keys } = setup();
    const signed = signAuthority(parseAuthorityBody(body()), keys.privateKey);
    registry.publish(signed);
    const stored = registry.get("auth-vendor-payments", 1);
    expect(stored && canonicalize(stored)).toBe(canonicalize(signed));
  });
});

describe("revocation", () => {
  it("accepts a signed revocation of a published version", () => {
    const { registry, keys } = setup();
    registry.publish(signAuthority(parseAuthorityBody(body()), keys.privateKey));
    const rev = signRevocation(
      {
        authorityId: "auth-vendor-payments",
        version: 1,
        revokedAt: "2026-03-01T00:00:00Z",
        signingKeyId: "issuer-key-1",
      },
      keys.privateKey,
    );
    registry.revoke(rev);
    expect(registry.revocationOf("auth-vendor-payments", 1)).toBeDefined();
  });

  it("rejects an unsigned or forged revocation", () => {
    const { registry, keys } = setup();
    registry.publish(signAuthority(parseAuthorityBody(body()), keys.privateKey));
    const forger = generateSigningKeyPair();
    const forged = signRevocation(
      {
        authorityId: "auth-vendor-payments",
        version: 1,
        revokedAt: "2026-03-01T00:00:00Z",
        signingKeyId: "issuer-key-1",
      },
      forger.privateKey,
    );
    expect(codeOf(() => registry.revoke(forged))).toBe("AUTHORITY_SIGNATURE_INVALID");
  });

  it("refuses to revoke an unpublished version", () => {
    const { registry, keys } = setup();
    const rev = signRevocation(
      {
        authorityId: "auth-missing",
        version: 1,
        revokedAt: "2026-03-01T00:00:00Z",
        signingKeyId: "issuer-key-1",
      },
      keys.privateKey,
    );
    expect(codeOf(() => registry.revoke(rev))).toBe("AUTHORITY_NOT_FOUND");
  });
});
