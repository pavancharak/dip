import { generateKeyPairSync, sign, verify, type KeyObject } from "node:crypto";

/**
 * Ed25519 signing primitives. Signatures are over the exact bytes provided;
 * callers sign canonicalize(object) output, never raw JSON.
 */
export interface SigningKeyPair {
  readonly publicKey: KeyObject;
  readonly privateKey: KeyObject;
}

export function generateSigningKeyPair(): SigningKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return { publicKey, privateKey };
}

export function signBytes(message: Uint8Array, privateKey: KeyObject): Uint8Array {
  return new Uint8Array(sign(null, message, privateKey));
}

export function verifyBytes(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: KeyObject,
): boolean {
  return verify(null, message, publicKey, signature);
}
