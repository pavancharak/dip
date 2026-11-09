import { describe, expect, it } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import {
  LocalSigningProvider,
  canonicalize,
  exportEd25519PublicJwk,
  importEd25519PublicJwk,
  keyFingerprint,
  signWithProvider,
  verifyWithDomain,
} from "../src/index.js";

const DOMAIN = "DIP-TEST-V1";

function provider(): LocalSigningProvider {
  return new LocalSigningProvider("engine-1", generateKeyPairSync("ed25519").privateKey);
}

describe("signing provider", () => {
  it("produces signatures that the protocol verifier accepts under its public key", async () => {
    const p = provider();
    const jwk = await p.publicJwk();
    const canonical = canonicalize({ action: "transfer", amountMinor: 400_000 });
    const signature = await signWithProvider(p, DOMAIN, canonical);
    expect(verifyWithDomain(DOMAIN, canonical, signature, importEd25519PublicJwk(jwk))).toBe(true);
  });

  it("a signature made under one domain does not verify under another", async () => {
    const p = provider();
    const jwk = await p.publicJwk();
    const canonical = canonicalize({ x: 1 });
    const signature = await signWithProvider(p, DOMAIN, canonical);
    expect(
      verifyWithDomain("DIP-OTHER-V1", canonical, signature, importEd25519PublicJwk(jwk)),
    ).toBe(false);
  });

  it("rejects a provider that returns a malformed signature", async () => {
    const broken = {
      keyId: "broken",
      publicJwk: async () => exportEd25519PublicJwk(generateKeyPairSync("ed25519").publicKey),
      sign: async () => new Uint8Array(10),
    };
    await expect(signWithProvider(broken, DOMAIN, "{}")).rejects.toThrow("not 64 bytes");
  });

  it("the public key fingerprint is stable for the same key", async () => {
    const p = provider();
    const jwk = await p.publicJwk();
    expect(keyFingerprint(jwk)).toBe(keyFingerprint(jwk));
    expect(keyFingerprint(jwk)).toMatch(/^[0-9a-f]{16}$/);
  });
});
