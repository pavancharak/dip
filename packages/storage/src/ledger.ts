import { DipError, type TrustRootSet } from "@dip/authority";
import { canonicalize } from "@dip/crypto";
import {
  GENESIS_DIGEST,
  createEvidence,
  entryDigest,
  type EvidenceDraft,
  type Signer,
  type SignedEvidence,
} from "@dip/evidence";
import { verifyChain, type VerificationReport } from "@dip/ledger";
import { UNIQUE_VIOLATION, sqlState, type SqlDatabase, type SqlQueryable } from "./db.js";

const LEDGER_LOCK = 8_100_001;

/**
 * Durable evidence ledger. Appends take a transaction-scoped advisory lock, so two
 * writers cannot both claim the same sequence number. Lines are stored exactly as
 * their canonical encoding, so the chain is re-derived from the same bytes.
 */
export class PostgresEvidenceLedger {
  constructor(
    private readonly db: SqlDatabase,
    private readonly trust: TrustRootSet,
    private readonly signer: Signer,
  ) {}

  async append(draft: EvidenceDraft): Promise<SignedEvidence> {
    return this.db.transaction(async (tx: SqlQueryable) => {
      await tx.query("SELECT pg_advisory_xact_lock($1)", [LEDGER_LOCK]);
      const head = await tx.query(
        "SELECT sequence, entry_digest FROM evidence_ledger ORDER BY sequence DESC LIMIT 1",
      );
      const last = head.rows[0];
      const sequence = last === undefined ? 1 : Number(last.sequence) + 1;
      const previous = last === undefined ? GENESIS_DIGEST : String(last.entry_digest);
      // The advisory lock above is held while signing, so a KMS round trip serializes appends.
      const signed = await createEvidence(
        draft,
        { sequence, previousDigest: previous },
        this.signer,
      );
      try {
        await tx.query(
          "INSERT INTO evidence_ledger (sequence, evidence_id, entry_canonical, entry_digest, previous_digest) VALUES ($1, $2, $3, $4, $5)",
          [sequence, draft.evidenceId, canonicalize(signed), entryDigest(signed), previous],
        );
      } catch (err) {
        if (sqlState(err) === UNIQUE_VIOLATION) {
          throw new DipError(
            "EVIDENCE_DUPLICATE",
            `evidence ${draft.evidenceId} is already recorded`,
          );
        }
        throw err;
      }
      return signed;
    });
  }

  async export(): Promise<string[]> {
    const rows = await this.db.query(
      "SELECT entry_canonical FROM evidence_ledger ORDER BY sequence",
    );
    return rows.rows.map((r) => String(r.entry_canonical));
  }

  async head(): Promise<string> {
    const rows = await this.db.query(
      "SELECT entry_digest FROM evidence_ledger ORDER BY sequence DESC LIMIT 1",
    );
    const last = rows.rows[0];
    return last === undefined ? GENESIS_DIGEST : String(last.entry_digest);
  }

  async size(): Promise<number> {
    const rows = await this.db.query("SELECT count(*) AS n FROM evidence_ledger");
    return Number(rows.rows[0]?.n ?? 0);
  }

  /** Re-derives the whole chain from stored bytes using the same independent check as the verifier. */
  async verify(expectedHead?: string): Promise<VerificationReport> {
    return verifyChain(await this.export(), this.trust, expectedHead);
  }
}
