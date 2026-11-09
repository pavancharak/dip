import {
  DipError,
  TrustRootSet,
  exactKeys,
  obj,
  parseAuthorityBody,
  parseSignedRevocation,
  verifyAuthoritySignature,
  verifyRevocationSignature,
  type SignedAuthority,
  type SignedRevocation,
} from "@dip/authority";
import { canonicalize } from "@dip/crypto";
import { type SqlDatabase, type SqlQueryable } from "./db.js";

/** Durable authority registry with the same rules as the in-memory one: immutable, contiguous versions, signed revocation. */
export class PostgresAuthorityRegistry {
  constructor(
    private readonly db: SqlDatabase,
    private readonly trust: TrustRootSet,
  ) {}

  async publish(input: unknown): Promise<SignedAuthority> {
    const o = obj(input, "signedAuthority");
    exactKeys(o, ["body", "signature"], "signedAuthority");
    if (typeof o.signature !== "string")
      throw new DipError("INVALID_FIELD", "signedAuthority.signature must be a string");
    const signed: SignedAuthority = { body: parseAuthorityBody(o.body), signature: o.signature };
    const fault = verifyAuthoritySignature(signed, this.trust);
    if (fault) throw new DipError(fault, `authority rejected: ${fault}`);
    const { authorityId, version } = signed.body;
    return this.db.transaction(async (tx: SqlQueryable) => {
      await tx.query("SELECT pg_advisory_xact_lock(hashtext($1))", [`authority:${authorityId}`]);
      const latest = await this.latestIn(tx, authorityId);
      if (version <= latest)
        throw new DipError(
          "AUTHORITY_ALREADY_PUBLISHED",
          `${authorityId} version ${String(version)} is immutable`,
        );
      if (version !== latest + 1) {
        throw new DipError(
          "AUTHORITY_VERSION_GAP",
          `${authorityId} must publish version ${String(latest + 1)} next`,
        );
      }
      await tx.query(
        "INSERT INTO authority_versions (authority_id, version, signed_canonical) VALUES ($1, $2, $3)",
        [authorityId, version, canonicalize(signed)],
      );
      return JSON.parse(canonicalize(signed)) as SignedAuthority;
    });
  }

  async get(authorityId: string, version: number): Promise<SignedAuthority | undefined> {
    const rows = await this.db.query(
      "SELECT signed_canonical FROM authority_versions WHERE authority_id = $1 AND version = $2",
      [authorityId, version],
    );
    const row = rows.rows[0];
    return row === undefined
      ? undefined
      : (JSON.parse(String(row.signed_canonical)) as SignedAuthority);
  }

  async latestVersion(authorityId: string): Promise<number> {
    return this.latestIn(this.db, authorityId);
  }

  async revoke(input: unknown): Promise<SignedRevocation> {
    const signed = parseSignedRevocation(input);
    const fault = verifyRevocationSignature(signed, this.trust);
    if (fault) throw new DipError(fault, `revocation rejected: ${fault}`);
    const { authorityId, version } = signed.body;
    if ((await this.get(authorityId, version)) === undefined) {
      throw new DipError(
        "AUTHORITY_NOT_FOUND",
        `${authorityId} version ${String(version)} is not published`,
      );
    }
    try {
      await this.db.query(
        "INSERT INTO authority_revocations (authority_id, version, signed_canonical) VALUES ($1, $2, $3)",
        [authorityId, version, canonicalize(signed)],
      );
    } catch {
      throw new DipError(
        "AUTHORITY_ALREADY_REVOKED",
        `${authorityId}@${String(version)} is already revoked`,
      );
    }
    return signed;
  }

  async revocationOf(authorityId: string, version: number): Promise<SignedRevocation | undefined> {
    const rows = await this.db.query(
      "SELECT signed_canonical FROM authority_revocations WHERE authority_id = $1 AND version = $2",
      [authorityId, version],
    );
    const row = rows.rows[0];
    return row === undefined
      ? undefined
      : (JSON.parse(String(row.signed_canonical)) as SignedRevocation);
  }

  private async latestIn(q: SqlQueryable, authorityId: string): Promise<number> {
    const rows = await q.query(
      "SELECT COALESCE(MAX(version), 0) AS v FROM authority_versions WHERE authority_id = $1",
      [authorityId],
    );
    return Number(rows.rows[0]?.v ?? 0);
  }
}
