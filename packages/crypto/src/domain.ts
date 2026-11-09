import { createHash, sign, verify, type KeyObject } from "node:crypto";

/**
 * Domain-separated hashing and Ed25519 signing.
 *
 * Message bytes are: UTF-8(domain) || 0x00 || UTF-8(canonical JSON).
 * The domain separator names the protocol object type and version, so a
 * signature made for one object type cannot be replayed as another.
 */
const DOMAIN_PATTERN = /^DIP-[A-Z0-9-]+-V[1-9][0-9]*$/;
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/;

export function domainMessage(domain: string, canonical: string): Uint8Array {
  if (!DOMAIN_PATTERN.test(domain)) {
    throw new Error(`invalid domain separator: ${domain}`);
  }
  return new TextEncoder().encode(`${domain}\u0000${canonical}`);
}

export function digestWithDomain(domain: string, canonical: string): string {
  return createHash("sha256").update(domainMessage(domain, canonical)).digest("hex");
}

/** Returns an unpadded base64url Ed25519 signature (86 characters). */
export function signWithDomain(domain: string, canonical: string, privateKey: KeyObject): string {
  return sign(null, domainMessage(domain, canonical), privateKey).toString("base64url");
}

export function verifyWithDomain(
  domain: string,
  canonical: string,
  signature: string,
  publicKey: KeyObject,
): boolean {
  if (!SIGNATURE_PATTERN.test(signature)) {
    return false;
  }
  const bytes = Buffer.from(signature, "base64url");
  return verify(null, domainMessage(domain, canonical), publicKey, bytes);
}
