import type { SqlDatabase } from "./db.js";

/**
 * Counts requests per bucket in a fixed window, shared by every process that uses the
 * same database. Each call is one atomic upsert, so concurrent requests get distinct
 * counts and a limit holds across processes.
 */
export class PostgresRateLimiter {
  constructor(
    private readonly db: SqlDatabase,
    private readonly windowMs: number,
  ) {}

  /** Records one request and returns the count in the current window, including this one. */
  async consume(bucket: string, nowMs: number): Promise<number> {
    // A window has expired when it started at or before (now - windowMs).
    const expiredBefore = nowMs - this.windowMs;
    const result = await this.db.query(
      `INSERT INTO dip_rate_limits (bucket, window_start, count)
       VALUES ($1, $2, 1)
       ON CONFLICT (bucket) DO UPDATE SET
         window_start = CASE WHEN dip_rate_limits.window_start <= $3
                             THEN EXCLUDED.window_start ELSE dip_rate_limits.window_start END,
         count = CASE WHEN dip_rate_limits.window_start <= $3
                      THEN 1 ELSE dip_rate_limits.count + 1 END
       RETURNING count`,
      [bucket, nowMs, expiredBefore],
    );
    const row = result.rows[0];
    if (row === undefined) throw new Error("rate limit upsert returned no row");
    return Number(row.count);
  }
}
