import { canonicalize, signWithDomain, verifyWithDomain } from "@dip/crypto";
import type { KeyObject } from "node:crypto";
import type { AuthorityBody } from "./body.js";
import type { TrustRootSet } from "./trust.js";
import { DipError, exactKeys, id, int, obj, time } from "./validate.js";

export const AUTHORITY_DOMAIN = "DIP-AUTHORITY-V1";
export const REVOCATION_DOMAIN = "DIP-REVOCATION-V1";

export interface SignedAuthority {
  readonly body: AuthorityBody;
  readonly signature: string;
}

export interface RevocationBody {
  readonly authorityId: string;
  readonly version: number;
  readonly revokedAt: string;
  readonly signingKeyId: string;
}

export interface SignedRevocation {
  readonly body: RevocationBody;
  readonly signature: string;
}

export type SignatureFault =
  | "AUTHORITY_KEY_UNKNOWN"
  | "AUTHORITY_KEY_REVOKED"
  | "AUTHORITY_SIGNATURE_INVALID";

export function signAuthority(body: AuthorityBody, privateKey: KeyObject): SignedAuthority {
  return { body, signature: signWithDomain(AUTHORITY_DOMAIN, canonicalize(body), privateKey) };
}

/** Returns null when the signature is valid under a non-revoked trusted key. */
export function verifyAuthoritySignature(
  signed: SignedAuthority,
  trust: TrustRootSet,
): SignatureFault | null {
  const key = trust.lookup(signed.body.signingKeyId);
  if (!key) return "AUTHORITY_KEY_UNKNOWN";
  if (key.status === "REVOKED") return "AUTHORITY_KEY_REVOKED";
  const ok = verifyWithDomain(
    AUTHORITY_DOMAIN,
    canonicalize(signed.body),
    signed.signature,
    key.publicKey,
  );
  return ok ? null : "AUTHORITY_SIGNATURE_INVALID";
}

export function signRevocation(body: RevocationBody, privateKey: KeyObject): SignedRevocation {
  return { body, signature: signWithDomain(REVOCATION_DOMAIN, canonicalize(body), privateKey) };
}

export function verifyRevocationSignature(
  signed: SignedRevocation,
  trust: TrustRootSet,
): SignatureFault | null {
  const key = trust.lookup(signed.body.signingKeyId);
  if (!key) return "AUTHORITY_KEY_UNKNOWN";
  if (key.status === "REVOKED") return "AUTHORITY_KEY_REVOKED";
  const ok = verifyWithDomain(
    REVOCATION_DOMAIN,
    canonicalize(signed.body),
    signed.signature,
    key.publicKey,
  );
  return ok ? null : "AUTHORITY_SIGNATURE_INVALID";
}

export function parseSignedRevocation(input: unknown): SignedRevocation {
  const o = obj(input, "revocation");
  exactKeys(o, ["body", "signature"], "revocation");
  if (typeof o.signature !== "string") {
    throw new DipError("INVALID_FIELD", "revocation.signature must be a string");
  }
  const b = obj(o.body, "revocation.body");
  exactKeys(b, ["authorityId", "version", "revokedAt", "signingKeyId"], "revocation.body");
  return {
    body: {
      authorityId: id(b.authorityId, "revocation.body.authorityId"),
      version: int(b.version, "revocation.body.version", 1, 1_000_000_000),
      revokedAt: time(b.revokedAt, "revocation.body.revokedAt"),
      signingKeyId: id(b.signingKeyId, "revocation.body.signingKeyId"),
    },
    signature: o.signature,
  };
}
