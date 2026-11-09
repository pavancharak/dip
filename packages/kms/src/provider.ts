import { createPublicKey } from "node:crypto";
import { exportEd25519PublicJwk, type Ed25519PublicJwk, type SigningProvider } from "@dip/crypto";

/** Failure from the KMS adapter. Codes are stable; messages never echo keys, ARNs or payloads. */
export class KmsError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "KmsError";
  }
}

export interface KmsSignInput {
  readonly KeyId: string;
  readonly Message: Uint8Array;
  readonly MessageType: "RAW";
  readonly SigningAlgorithm: "ED25519_SHA_512";
}

/**
 * The two KMS operations the adapter needs. Production wires an AWS SDK client here
 * (@aws-sdk/client-kms, commands Sign and GetPublicKey). Tests inject a fake.
 * Keeping the SDK behind this seam means the protocol code never imports it.
 */
export interface KmsTransport {
  sign(input: KmsSignInput): Promise<{ Signature?: Uint8Array | undefined }>;
  getPublicKey(input: { KeyId: string }): Promise<{ PublicKey?: Uint8Array | undefined }>;
}

/**
 * Signing provider backed by an AWS KMS Ed25519 key (ECC_NIST_EDWARDS25519, SIGN_VERIFY).
 * The private key never leaves KMS. The provider receives the full domain-separated
 * message bytes and asks for pure Ed25519 (MessageType RAW), which the protocol verifier
 * checks unchanged.
 */
export class AwsKmsSigningProvider implements SigningProvider {
  private cachedJwk: Ed25519PublicJwk | undefined;

  constructor(
    readonly keyId: string,
    private readonly transport: KmsTransport,
  ) {}

  async publicJwk(): Promise<Ed25519PublicJwk> {
    if (this.cachedJwk === undefined) {
      const res = await this.call("KMS_PUBLIC_KEY_FAILED", () =>
        this.transport.getPublicKey({ KeyId: this.keyId }),
      );
      if (res.PublicKey === undefined) {
        throw new KmsError("KMS_PUBLIC_KEY_FAILED", "KMS returned no public key");
      }
      // GetPublicKey returns a DER SubjectPublicKeyInfo. Anything else fails here, loudly.
      let key;
      try {
        key = createPublicKey({ key: Buffer.from(res.PublicKey), format: "der", type: "spki" });
      } catch {
        throw new KmsError(
          "KMS_KEY_ENCODING_INVALID",
          "public key is not DER SubjectPublicKeyInfo",
        );
      }
      if (key.asymmetricKeyType !== "ed25519") {
        throw new KmsError("KMS_KEY_TYPE_INVALID", "KMS key is not Ed25519");
      }
      this.cachedJwk = exportEd25519PublicJwk(key);
    }
    return this.cachedJwk;
  }

  async sign(message: Uint8Array): Promise<Uint8Array> {
    const res = await this.call("KMS_SIGN_FAILED", () =>
      this.transport.sign({
        KeyId: this.keyId,
        Message: message,
        MessageType: "RAW",
        SigningAlgorithm: "ED25519_SHA_512",
      }),
    );
    if (res.Signature === undefined || res.Signature.length !== 64) {
      throw new KmsError("KMS_SIGNATURE_INVALID", "KMS returned a signature that is not 64 bytes");
    }
    return res.Signature;
  }

  private async call<T>(code: string, op: () => Promise<T>): Promise<T> {
    try {
      return await op();
    } catch (err) {
      // Report the error class only. SDK messages can contain request details.
      const name = err instanceof Error ? err.name : "UnknownError";
      throw new KmsError(code, `KMS call failed (${name})`);
    }
  }
}
