import { importEd25519PublicJwk, type Ed25519PublicJwk } from "@dip/crypto";
import type { KeyObject } from "node:crypto";
import { DipError } from "./validate.js";

export interface TrustRoot {
  readonly keyId: string;
  readonly jwk: Ed25519PublicJwk;
  readonly status: "ACTIVE" | "REVOKED";
}

/** Explicit trust roots. Keys are never discovered from the object being verified. */
export class TrustRootSet {
  private readonly keys = new Map<string, { status: "ACTIVE" | "REVOKED"; publicKey: KeyObject }>();

  add(root: TrustRoot): void {
    if (this.keys.has(root.keyId)) {
      throw new DipError("KEY_ALREADY_TRUSTED", `key ${root.keyId} is already trusted`);
    }
    this.keys.set(root.keyId, { status: root.status, publicKey: importEd25519PublicJwk(root.jwk) });
  }

  /** Revoking a key makes every object it signed fail verification. */
  revoke(keyId: string): void {
    const entry = this.keys.get(keyId);
    if (!entry) {
      throw new DipError("KEY_UNKNOWN", `key ${keyId} is not trusted`);
    }
    entry.status = "REVOKED";
  }

  lookup(keyId: string): { status: "ACTIVE" | "REVOKED"; publicKey: KeyObject } | undefined {
    return this.keys.get(keyId);
  }
}
