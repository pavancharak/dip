import { describe, expect, it } from "vitest";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import {
  exportEd25519PublicJwk,
  signWithProvider,
  verifyWithDomain,
  importEd25519PublicJwk,
} from "@dip/crypto";
import type { KmsTransport } from "@dip/kms";
import { resolveSigner, SignerError } from "../src/signers.js";
import type { SignerSettings } from "../src/config.js";

// A local key stands in for the KMS key. KMS RAW + ED25519_SHA_512 is pure Ed25519, so
// the signatures and public key here have the same shape as real KMS output.
const pair = generateKeyPairSync("ed25519");
const pinnedJwk = exportEd25519PublicJwk(pair.publicKey);

function fakeKms(publicKey: typeof pair.publicKey = pair.publicKey): KmsTransport {
  return {
    async sign(input) {
      return {
        Signature: new Uint8Array(edSign(null, Buffer.from(input.Message), pair.privateKey)),
      };
    },
    async getPublicKey() {
      return { PublicKey: new Uint8Array(publicKey.export({ format: "der", type: "spki" })) };
    },
  };
}

const kmsSettings: SignerSettings = {
  keyId: "engine-1",
  privateKey: null,
  kmsKeyId: "kms-key-1",
};

function roots(status: "ACTIVE" | "REVOKED" = "ACTIVE", keyId = "engine-1") {
  return [{ keyId, jwk: pinnedJwk, status }];
}

function options(transport: KmsTransport) {
  return { kmsRegion: "us-east-1", kmsTransport: () => transport };
}

describe("signer resolution", () => {
  it("uses a KMS key whose public key matches the pinned trust root", async () => {
    const signer = await resolveSigner("engine", kmsSettings, roots(), options(fakeKms()));
    expect(signer.keyId).toBe("engine-1");
    const signature = await signWithProvider(
      { keyId: signer.keyId, publicJwk: async () => pinnedJwk, sign: async (m) => signerSign(m) },
      "DIP-DECISION-V1",
      '{"a":1}',
    );
    expect(
      verifyWithDomain(
        "DIP-DECISION-V1",
        '{"a":1}',
        signature,
        importEd25519PublicJwk(pinnedJwk) as never,
      ),
    ).toBe(true);
  });

  it("refuses to start when the KMS key is a different key from the pinned root", async () => {
    const other = generateKeyPairSync("ed25519");
    await expect(
      resolveSigner("engine", kmsSettings, roots(), options(fakeKms(other.publicKey))),
    ).rejects.toMatchObject({ code: "SIGNER_KEY_MISMATCH" });
  });

  it("refuses when no trust root is pinned for the signer", async () => {
    await expect(
      resolveSigner("engine", kmsSettings, roots("ACTIVE", "other-key"), options(fakeKms())),
    ).rejects.toMatchObject({ code: "SIGNER_ROOT_MISSING" });
  });

  it("refuses when the pinned root is revoked", async () => {
    await expect(
      resolveSigner("engine", kmsSettings, roots("REVOKED"), options(fakeKms())),
    ).rejects.toMatchObject({ code: "SIGNER_ROOT_MISSING" });
  });

  it("refuses a KMS signer when kms.region is not set", async () => {
    await expect(
      resolveSigner("engine", kmsSettings, roots(), { kmsRegion: null }),
    ).rejects.toBeInstanceOf(SignerError);
  });

  it("keeps a local key as loaded", async () => {
    const signer = await resolveSigner(
      "engine",
      { keyId: "engine-1", privateKey: pair.privateKey, kmsKeyId: null },
      roots(),
      { kmsRegion: null },
    );
    expect(signer).toEqual({ keyId: "engine-1", privateKey: pair.privateKey });
  });

  it("does not leak key material in refusal messages", async () => {
    const other = generateKeyPairSync("ed25519");
    const err = await resolveSigner(
      "engine",
      kmsSettings,
      roots(),
      options(fakeKms(other.publicKey)),
    ).catch((e: unknown) => e);
    expect(String((err as Error).message)).not.toContain(pinnedJwk.x);
  });
});

function signerSign(m: Uint8Array): Promise<Uint8Array> {
  return Promise.resolve(new Uint8Array(edSign(null, Buffer.from(m), pair.privateKey)));
}
