import { createPublicKey, type KeyObject } from "node:crypto";

export interface Ed25519PublicJwk {
  readonly kty: "OKP";
  readonly crv: "Ed25519";
  readonly x: string;
}

export function importEd25519PublicJwk(jwk: Ed25519PublicJwk): KeyObject {
  const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: jwk.x }, format: "jwk" });
  if (key.asymmetricKeyType !== "ed25519") {
    throw new Error("JWK is not an Ed25519 public key");
  }
  return key;
}

export function exportEd25519PublicJwk(key: KeyObject): Ed25519PublicJwk {
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") {
    throw new Error("key is not an Ed25519 public key");
  }
  const jwk = key.export({ format: "jwk" });
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") {
    throw new Error("unexpected JWK shape for Ed25519 public key");
  }
  return { kty: "OKP", crv: "Ed25519", x: jwk.x };
}
