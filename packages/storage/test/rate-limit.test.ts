import { describe, expect, it } from "vitest";
import { migrate, openDatabase, PostgresRateLimiter } from "../src/index.js";

// Runs on the in-process PostgreSQL engine, so it needs no server. It exercises the same
// SQL the server uses. The shared-counter property is what matters: two limiters on one
// database are two processes.

async function db() {
  const d = await openDatabase();
  await migrate(d);
  return d;
}

describe("PostgreSQL rate limiter", () => {
  it("counts requests in a window and reports the count including the current request", async () => {
    const limiter = new PostgresRateLimiter(await db(), 60_000);
    expect(await limiter.consume("op", 1_000)).toBe(1);
    expect(await limiter.consume("op", 2_000)).toBe(2);
    expect(await limiter.consume("op", 3_000)).toBe(3);
  });

  it("starts a new window once the previous one has expired", async () => {
    const limiter = new PostgresRateLimiter(await db(), 60_000);
    expect(await limiter.consume("op", 0)).toBe(1);
    expect(await limiter.consume("op", 10_000)).toBe(2);
    expect(await limiter.consume("op", 60_000)).toBe(1);
  });

  it("keeps buckets independent", async () => {
    const limiter = new PostgresRateLimiter(await db(), 60_000);
    expect(await limiter.consume("a", 0)).toBe(1);
    expect(await limiter.consume("b", 0)).toBe(1);
    expect(await limiter.consume("a", 0)).toBe(2);
  });

  it("shares counts between two limiters on the same database (two processes)", async () => {
    const shared = await db();
    const first = new PostgresRateLimiter(shared, 60_000);
    const second = new PostgresRateLimiter(shared, 60_000);
    expect(await first.consume("op", 0)).toBe(1);
    expect(await second.consume("op", 0)).toBe(2);
    expect(await first.consume("op", 0)).toBe(3);
  });

  it("gives distinct counts under concurrent requests, so the limit cannot be overrun", async () => {
    const limiter = new PostgresRateLimiter(await db(), 60_000);
    const counts = await Promise.all(Array.from({ length: 25 }, () => limiter.consume("op", 0)));
    expect([...counts].sort((x, y) => x - y)).toEqual(Array.from({ length: 25 }, (_, i) => i + 1));
  });
});
