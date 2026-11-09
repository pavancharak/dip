import { describe, expect, it } from "vitest";
import { generateSigningKeyPair, exportEd25519PublicJwk } from "@dip/crypto";
import { DipClient } from "@dip/sdk";
import { migrate, openDatabase, PostgresRateLimiter } from "@dip/storage";
import { createApi, type ApiRequest } from "../src/index.js";

const NOW = new Date("2026-06-01T12:00:00Z");
const keys = { engine: generateSigningKeyPair(), evidence: generateSigningKeyPair() };

async function client(): Promise<DipClient> {
  return DipClient.open({
    trustRoots: [
      { keyId: "engine-1", jwk: exportEd25519PublicJwk(keys.engine.publicKey), status: "ACTIVE" },
      {
        keyId: "evidence-1",
        jwk: exportEd25519PublicJwk(keys.evidence.publicKey),
        status: "ACTIVE",
      },
    ],
    engine: { keyId: "engine-1", privateKey: keys.engine.privateKey },
    evidenceSigner: { keyId: "evidence-1", privateKey: keys.evidence.privateKey },
    connectors: new Map(),
    now: () => NOW,
  });
}

// Rate limits apply to authenticated routes, keyed by principal name. The record need not exist.
const lookup: ApiRequest = {
  method: "GET",
  path: "/v1/evidence/ev-missing",
  headers: { authorization: "Bearer key-operator" },
  body: undefined,
};

describe("rate limits shared across API processes", () => {
  it("one limit holds across two API instances that share a database", async () => {
    const database = await openDatabase();
    await migrate(database);
    const limiter = new PostgresRateLimiter(database, 60_000);
    const config = {
      principals: new Map([["key-operator", { name: "operator", tenantId: null, scopes: [] }]]),
      rateLimit: { max: 2, windowMs: 60_000 },
      clockMs: () => NOW.getTime(),
      rateLimiter: limiter,
    };
    const first = createApi({ ...config, client: await client() });
    const second = createApi({ ...config, client: await client() });

    expect((await first.handle(lookup)).status).not.toBe(429);
    expect((await second.handle(lookup)).status).not.toBe(429);
    // The third request is refused even though it reaches a different instance.
    expect((await first.handle(lookup)).status).toBe(429);
  });
});
