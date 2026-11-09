import { describe, expect, it } from "vitest";
import { sign as edSign, generateKeyPairSync } from "node:crypto";
import {
  exportEd25519PublicJwk,
  importEd25519PublicJwk,
  signWithProvider,
  verifyWithDomain,
} from "@dip/crypto";
import {
  AwsKmsSigningProvider,
  KmsError,
  type KmsSignInput,
  type KmsTransport,
} from "../src/index.js";

// A local Ed25519 key stands in for the KMS key. KMS RAW + ED25519_SHA_512 is pure
// Ed25519 (RFC 8032), so an in-process signature with the same key is the reference.
const pair = generateKeyPairSync("ed25519");

function fakeTransport(overrides: Partial<KmsTransport> = {}): KmsTransport & {
  signCalls: KmsSignInput[];
  pubCalls: number;
} {
  const t = {
    signCalls: [] as KmsSignInput[],
    pubCalls: 0,
    async sign(input: KmsSignInput) {
      t.signCalls.push(input);
      return {
        Signature: new Uint8Array(edSign(null, Buffer.from(input.Message), pair.privateKey)),
      };
    },
    async getPublicKey() {
      t.pubCalls += 1;
      return { PublicKey: new Uint8Array(pair.publicKey.export({ format: "der", type: "spki" })) };
    },
    ...overrides,
  };
  return t;
}

describe("AWS KMS signing provider", () => {
  it("signs pure Ed25519 with RAW messages and the protocol verifier accepts the result", async () => {
    const transport = fakeTransport();
    const provider = new AwsKmsSigningProvider("kms-key-1", transport);
    const signature = await signWithProvider(provider, "DIP-DECISION-V1", '{"a":1}');

    expect(transport.signCalls).toHaveLength(1);
    expect(transport.signCalls[0]).toMatchObject({
      KeyId: "kms-key-1",
      MessageType: "RAW",
      SigningAlgorithm: "ED25519_SHA_512",
    });
    const jwk = await provider.publicJwk();
    expect(
      verifyWithDomain("DIP-DECISION-V1", '{"a":1}', signature, importEd25519PublicJwk(jwk)),
    ).toBe(true);
    expect(
      verifyWithDomain("DIP-DECISION-V1", '{"a":2}', signature, importEd25519PublicJwk(jwk)),
    ).toBe(false);
  });

  it("derives the trust-root JWK from the DER public key", async () => {
    const provider = new AwsKmsSigningProvider("kms-key-1", fakeTransport());
    expect(await provider.publicJwk()).toEqual(exportEd25519PublicJwk(pair.publicKey));
  });

  it("fetches the public key once and reuses it", async () => {
    const transport = fakeTransport();
    const provider = new AwsKmsSigningProvider("kms-key-1", transport);
    await provider.publicJwk();
    await provider.publicJwk();
    expect(transport.pubCalls).toBe(1);
  });

  it("refuses a non-Ed25519 KMS key", async () => {
    const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const transport = fakeTransport({
      getPublicKey: async () => ({
        PublicKey: new Uint8Array(rsa.publicKey.export({ format: "der", type: "spki" })),
      }),
    });
    const provider = new AwsKmsSigningProvider("kms-key-1", transport);
    await expect(provider.publicJwk()).rejects.toMatchObject({ code: "KMS_KEY_TYPE_INVALID" });
  });

  it("refuses a public key that is not DER SubjectPublicKeyInfo", async () => {
    const transport = fakeTransport({
      getPublicKey: async () => ({ PublicKey: new Uint8Array(32) }),
    });
    const provider = new AwsKmsSigningProvider("kms-key-1", transport);
    await expect(provider.publicJwk()).rejects.toMatchObject({
      code: "KMS_KEY_ENCODING_INVALID",
    });
  });

  it("refuses a signature that is not 64 bytes", async () => {
    const transport = fakeTransport({ sign: async () => ({ Signature: new Uint8Array(63) }) });
    const provider = new AwsKmsSigningProvider("kms-key-1", transport);
    await expect(provider.sign(new Uint8Array([1]))).rejects.toMatchObject({
      code: "KMS_SIGNATURE_INVALID",
    });
  });

  it("refuses when KMS returns no signature", async () => {
    const transport = fakeTransport({ sign: async () => ({}) });
    const provider = new AwsKmsSigningProvider("kms-key-1", transport);
    await expect(provider.sign(new Uint8Array([1]))).rejects.toMatchObject({
      code: "KMS_SIGNATURE_INVALID",
    });
  });

  it("maps a denied Sign call to a typed error without echoing the SDK message", async () => {
    const denied = Object.assign(
      new Error("User arn:aws:iam::123456789012:role/dip is not authorized"),
      {
        name: "AccessDeniedException",
      },
    );
    const transport = fakeTransport({
      sign: async () => {
        throw denied;
      },
    });
    const provider = new AwsKmsSigningProvider("kms-key-1", transport);
    const err = await provider.sign(new Uint8Array([1])).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(KmsError);
    expect((err as KmsError).code).toBe("KMS_SIGN_FAILED");
    expect((err as KmsError).message).toBe("KMS call failed (AccessDeniedException)");
    expect((err as KmsError).message).not.toContain("123456789012");
  });

  it("never returns a signature from a failed call (fail closed)", async () => {
    const transport = fakeTransport({
      sign: async () => {
        throw new Error("throttled");
      },
    });
    const provider = new AwsKmsSigningProvider("kms-key-1", transport);
    await expect(signWithProvider(provider, "DIP-DECISION-V1", '{"a":1}')).rejects.toMatchObject({
      code: "KMS_SIGN_FAILED",
    });
  });
});
