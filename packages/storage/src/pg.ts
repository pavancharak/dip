import pg from "pg";
import type { SqlDatabase, SqlQueryable } from "./db.js";

/**
 * node-postgres adapter. Works with any PostgreSQL 14+ server: a managed service,
 * a local container, or PGlite's socket server. Transactions use one pooled
 * connection for their whole duration.
 */
function queryable(c: { query: pg.Pool["query"] }): SqlQueryable {
  return {
    query: async (text, params) => {
      const r = await c.query(text, params as unknown[] | undefined);
      return { rows: r.rows as Record<string, unknown>[] };
    },
  };
}

export function fromPgPool(pool: pg.Pool): SqlDatabase {
  const base = queryable(pool);
  return {
    query: base.query,
    exec: async (text) => {
      await pool.query(text);
    },
    transaction: async <T>(fn: (tx: SqlQueryable) => Promise<T>): Promise<T> => {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const value = await fn(queryable(client));
        await client.query("COMMIT");
        return value;
      } catch (err) {
        await client.query("ROLLBACK").catch(() => undefined);
        throw err;
      } finally {
        client.release();
      }
    },
    close: () => pool.end(),
  };
}

/** Opens a pooled connection to the given PostgreSQL URL. The caller closes it. */
export function openPostgres(connectionString: string, maxConnections = 4): SqlDatabase {
  return fromPgPool(new pg.Pool({ connectionString, max: maxConnections }));
}
