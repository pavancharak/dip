/**
 * Request limiter. consume() records one request in a bucket and returns how many
 * requests the bucket has made in the current window, including this one.
 */
export interface RateLimiter {
  consume(bucket: string, nowMs: number): Promise<number>;
}

/** In-process limiter. Counts are not shared between processes; use the PostgreSQL limiter for that. */
export function memoryRateLimiter(windowMs: number): RateLimiter {
  const counters = new Map<string, { windowStart: number; count: number }>();
  return {
    async consume(bucket, nowMs) {
      const entry = counters.get(bucket);
      if (!entry || nowMs - entry.windowStart >= windowMs) {
        counters.set(bucket, { windowStart: nowMs, count: 1 });
        return 1;
      }
      entry.count += 1;
      return entry.count;
    },
  };
}
