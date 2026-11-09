import type { Journal } from "./journal.js";
import { canonicalize } from "@dip/crypto";
import { parseAuthorityBody } from "./body.js";
import {
  parseSignedRevocation,
  verifyAuthoritySignature,
  verifyRevocationSignature,
  type SignatureFault,
  type SignedAuthority,
  type SignedRevocation,
} from "./signing.js";
import type { TrustRootSet } from "./trust.js";
import { DipError, exactKeys, obj } from "./validate.js";

/**
 * Append-only, in-memory authority store. Versions are published strictly in
 * order, and a published version is never replaced. Persistent storage is a
 * later phase; this is the reference semantics.
 */
export class AuthorityRegistry {
  private readonly versions = new Map<string, string[]>();
  private readonly revocations = new Map<string, string>();

  private replaying = false;

  constructor(
    private readonly trust: TrustRootSet,
    private readonly journal?: Journal,
  ) {}

  private emit(kind: string, payload: unknown): void {
    if (!this.replaying) this.journal?.(kind, payload);
  }

  /** Re-applies a journaled publication. Validation repeats; nothing is journaled again. */
  restorePublished(input: unknown): void {
    this.replaying = true;
    try {
      this.publish(input);
    } finally {
      this.replaying = false;
    }
  }

  /** Re-applies a journaled revocation. Validation repeats; nothing is journaled again. */
  restoreRevoked(input: unknown): void {
    this.replaying = true;
    try {
      this.revoke(input);
    } finally {
      this.replaying = false;
    }
  }

  publish(input: unknown): SignedAuthority {
    const o = obj(input, "signedAuthority");
    exactKeys(o, ["body", "signature"], "signedAuthority");
    if (typeof o.signature !== "string") {
      throw new DipError("INVALID_FIELD", "signedAuthority.signature must be a string");
    }
    const signed: SignedAuthority = { body: parseAuthorityBody(o.body), signature: o.signature };
    const fault = this.verify(signed);
    if (fault) {
      throw new DipError(fault, `authority rejected: ${fault}`);
    }

    const { authorityId, version } = signed.body;
    const list = this.versions.get(authorityId) ?? [];
    if (version <= list.length) {
      throw new DipError(
        "AUTHORITY_ALREADY_PUBLISHED",
        `${authorityId} version ${String(version)} is immutable`,
      );
    }
    if (version !== list.length + 1) {
      throw new DipError(
        "AUTHORITY_VERSION_GAP",
        `${authorityId} must publish version ${String(list.length + 1)} next`,
      );
    }
    list.push(canonicalize(signed));
    this.emit("authority.published", signed);
    this.versions.set(authorityId, list);
    return JSON.parse(canonicalize(signed)) as SignedAuthority;
  }

  verify(signed: SignedAuthority): SignatureFault | null {
    return verifyAuthoritySignature(signed, this.trust);
  }

  get(authorityId: string, version: number): SignedAuthority | undefined {
    const stored = this.versions.get(authorityId)?.[version - 1];
    return stored === undefined ? undefined : (JSON.parse(stored) as SignedAuthority);
  }

  latestVersion(authorityId: string): number {
    return this.versions.get(authorityId)?.length ?? 0;
  }

  revoke(input: unknown): SignedRevocation {
    const signed = parseSignedRevocation(input);
    const fault = verifyRevocationSignature(signed, this.trust);
    if (fault) {
      throw new DipError(fault, `revocation rejected: ${fault}`);
    }
    const { authorityId, version } = signed.body;
    if (this.get(authorityId, version) === undefined) {
      throw new DipError(
        "AUTHORITY_NOT_FOUND",
        `${authorityId} version ${String(version)} is not published`,
      );
    }
    const key = `${authorityId}@${String(version)}`;
    if (this.revocations.has(key)) {
      throw new DipError("AUTHORITY_ALREADY_REVOKED", `${key} is already revoked`);
    }
    this.revocations.set(key, canonicalize(signed));
    this.emit("authority.revoked", signed);
    return signed;
  }

  revocationOf(authorityId: string, version: number): SignedRevocation | undefined {
    const stored = this.revocations.get(`${authorityId}@${String(version)}`);
    return stored === undefined ? undefined : (JSON.parse(stored) as SignedRevocation);
  }
}
