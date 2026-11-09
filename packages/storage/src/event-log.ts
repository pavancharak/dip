import { canonicalize } from "@dip/crypto";
import type { SqlDatabase } from "./db.js";

export interface StoredRecord {
  readonly kind: string;
  readonly payload: unknown;
}

/**
 * Durable, append-only journal of state changes. The SDK replays it at startup to
 * rebuild authorities, approvals, consumed decisions, execution attempts and evidence.
 */
export class PostgresEventLog {
  constructor(private readonly db: SqlDatabase) {}

  async readAll(): Promise<StoredRecord[]> {
    const rows = await this.db.query("SELECT kind, payload FROM dip_event_log ORDER BY seq");
    return rows.rows.map((r) => ({
      kind: String(r.kind),
      payload: JSON.parse(String(r.payload)) as unknown,
    }));
  }

  async append(records: readonly StoredRecord[]): Promise<void> {
    if (records.length === 0) return;
    await this.db.transaction(async (tx) => {
      for (const r of records) {
        await tx.query("INSERT INTO dip_event_log (kind, payload) VALUES ($1, $2)", [
          r.kind,
          canonicalize(r.payload),
        ]);
      }
    });
  }
}
