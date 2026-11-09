import { createHash, createPublicKey, sign as edSign, type KeyObject } from "node:crypto";
import { domainMessage } from "./domain.js";
import type { Ed25519PublicJwk } from "./jwk.js";
import { exportEd25519PublicJwk } from "./jwk.js";

/**
 * Signing provider: the boundary between protocol code and key custody.
 *
 * Protocol code signs through a provider and never sees private key material when
 * the provider is a hardware-backed service. The interface is asynchronous so that
 * network-backed providers (for example a cloud KMS) fit the same contract.
 *
 * The provider receives the complete message bytes, which already include the domain
 * separator (see domainMessage). It must sign with pure Ed25519 over those bytes.
 */
export interface SigningProvider {
  /** Identifier that trust roots refer to. */
  readonly keyId: string;
  /** Public key, for trust roots. */
  publicJwk(): Promise<Ed25519PublicJwk>;
  /** Pure Ed25519 signature (64 bytes) over the message. */
  sign(message: Uint8Array): Promise<Uint8Array>;
}

/** Local provider: holds an in-process private key. For development and tests only. */
export class LocalSigningProvider implements SigningProvider {
  constructor(
    readonly keyId: string,
    private readonly privateKey: KeyObject,
  ) {}

  async publicJwk(): Promise<Ed25519PublicJwk> {
    return exportEd25519PublicJwk(createPublicKey(this.privateKey));
  }

  async sign(message: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(edSign(null, message, this.privateKey));
  }
}

/** Signs a canonical body under a domain separator through a provider, returning the protocol encoding. */
export async function signWithProvider(
  provider: SigningProvider,
  domain: string,
  canonical: string,
): Promise<string> {
  const signature = await provider.sign(domainMessage(domain, canonical));
  if (signature.length !== 64)
    throw new Error("provider returned a signature that is not 64 bytes");
  return Buffer.from(signature).toString("base64url");
}

/** Digest helper for auditing: a short fingerprint of a public key, for logs and change records. */
export function keyFingerprint(jwk: Ed25519PublicJwk): string {
  return createHash("sha256").update(jwk.x).digest("hex").slice(0, 16);
}
