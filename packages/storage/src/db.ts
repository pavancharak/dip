/**
 * Minimal database surface the stores need. PGlite and node-postgres both fit it,
 * so the stores do not depend on one driver.
 */
export interface SqlResult {
  readonly rows: Record<string, unknown>[];
}

export interface SqlQueryable {
  query(text: string, params?: readonly unknown[]): Promise<SqlResult>;
}

export interface SqlDatabase extends SqlQueryable {
  exec(text: string): Promise<unknown>;
  transaction<T>(fn: (tx: SqlQueryable) => Promise<T>): Promise<T>;
}

/** SQLSTATE for unique_violation. */
export const UNIQUE_VIOLATION = "23505";

export function sqlState(err: unknown): string | undefined {
  if (typeof err === "object" && err !== null && "code" in err) {
    const code = (err as { code: unknown }).code;
    return typeof code === "string" ? code : undefined;
  }
  return undefined;
}
