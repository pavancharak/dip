import { describe, expect, it } from "vitest";
import {
  canonicalize,
  digestWithDomain,
  exportEd25519PublicJwk,
  generateSigningKeyPair,
  importEd25519PublicJwk,
  signWithDomain,
  verifyWithDomain,
} from "../src/index.js";

const A = "DIP-TEST-V1";
const B = "DIP-OTHER-V1";

describe("domain separation", () => {
  it("rejects malformed domain separators", () => {
    expect(() => digestWithDomain("bad", "{}")).toThrow("invalid domain separator");
  });

  it("changes the digest when the domain changes", () => {
    expect(digestWithDomain(A, "{}")).not.toBe(digestWithDomain(B, "{}"));
  });

  it("does not verify a signature made under a different domain", () => {
    const keys = generateSigningKeyPair();
    const msg = canonicalize({ x: 1 });
    const sig = signWithDomain(A, msg, keys.privateKey);
    expect(verifyWithDomain(A, msg, sig, keys.publicKey)).toBe(true);
    expect(verifyWithDomain(B, msg, sig, keys.publicKey)).toBe(false);
  });

  it("rejects malformed signature strings without throwing", () => {
    const keys = generateSigningKeyPair();
    expect(verifyWithDomain(A, "{}", "not-a-signature", keys.publicKey)).toBe(false);
    expect(verifyWithDomain(A, "{}", "", keys.publicKey)).toBe(false);
  });
});

describe("Ed25519 JWK import/export", () => {
  it("round-trips a public key", () => {
    const keys = generateSigningKeyPair();
    const jwk = exportEd25519PublicJwk(keys.publicKey);
    const imported = importEd25519PublicJwk(jwk);
    const sig = signWithDomain(A, "{}", keys.privateKey);
    expect(verifyWithDomain(A, "{}", sig, imported)).toBe(true);
  });

  it("refuses to export a private key as a public JWK", () => {
    const keys = generateSigningKeyPair();
    expect(() => exportEd25519PublicJwk(keys.privateKey)).toThrow("not an Ed25519 public key");
  });
});
