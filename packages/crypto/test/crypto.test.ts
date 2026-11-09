import { describe, expect, it } from "vitest";
import {
  canonicalize,
  CanonicalEncodingError,
  generateSigningKeyPair,
  sha256Hex,
  signBytes,
  verifyBytes,
} from "../src/index.js";

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);

describe("canonicalize", () => {
  it("sorts keys recursively and removes whitespace", () => {
    expect(canonicalize({ b: 1, a: { d: [true, null], c: "x" } })).toBe(
      '{"a":{"c":"x","d":[true,null]},"b":1}',
    );
  });

  it("produces the same bytes regardless of insertion order", () => {
    expect(canonicalize({ x: 1, y: 2 })).toBe(canonicalize({ y: 2, x: 1 }));
  });

  it("rejects floats, unsafe integers and undefined", () => {
    expect(() => canonicalize({ n: 1.5 })).toThrow(CanonicalEncodingError);
    expect(() => canonicalize({ n: Number.MAX_SAFE_INTEGER + 2 })).toThrow(CanonicalEncodingError);
    expect(() => canonicalize({ n: undefined } as never)).toThrow(CanonicalEncodingError);
  });
});

describe("sha256Hex", () => {
  it("matches the known digest of the empty string", () => {
    expect(sha256Hex("")).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });
});

describe("Ed25519 signing", () => {
  it("verifies a valid signature and rejects a tampered message", () => {
    const keys = generateSigningKeyPair();
    const msg = enc(canonicalize({ action: "transfer", amount: 10 }));
    const sig = signBytes(msg, keys.privateKey);
    expect(verifyBytes(msg, sig, keys.publicKey)).toBe(true);
    expect(
      verifyBytes(enc(canonicalize({ action: "transfer", amount: 11 })), sig, keys.publicKey),
    ).toBe(false);
  });

  it("rejects a signature made by a different key", () => {
    const a = generateSigningKeyPair();
    const b = generateSigningKeyPair();
    const msg = enc("payload");
    expect(verifyBytes(msg, signBytes(msg, a.privateKey), b.publicKey)).toBe(false);
  });
});
