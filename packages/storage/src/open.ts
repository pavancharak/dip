import { PGlite } from "@electric-sql/pglite";
import type { SqlDatabase, SqlQueryable } from "./db.js";

/**
 * Opens PostgreSQL (PGlite, PostgreSQL 16 compiled to WebAssembly) and adapts it to
 * SqlDatabase. With a data directory the database is file-backed and survives restarts.
 * Only one process may open a data directory at a time.
 */
export async function openDatabase(dataDir?: string): Promise<SqlDatabase> {
  const pg = dataDir === undefined ? await PGlite.create() : await PGlite.create(dataDir);
  const adapt = (q: { query: PGlite["query"] }): SqlQueryable => ({
    query: (text, params) => q.query(text, params as unknown[] | undefined),
  });
  return {
    query: (text, params) => pg.query(text, params as unknown[] | undefined),
    exec: (text) => pg.exec(text),
    transaction: <T>(fn: (tx: SqlQueryable) => Promise<T>) => pg.transaction((tx) => fn(adapt(tx))),
    close: () => pg.close(),
  };
}
