import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { exportEd25519PublicJwk, generateSigningKeyPair } from "@dip/crypto";
import { DipClient } from "@dip/sdk";
import { buildOpenApi, createApi } from "../src/index.js";

const keys = {
  e: generateSigningKeyPair(),
  v: generateSigningKeyPair(),
  i: generateSigningKeyPair(),
};
const client = new DipClient({
  trustRoots: [
    { keyId: "issuer-key-1", jwk: exportEd25519PublicJwk(keys.i.publicKey), status: "ACTIVE" },
    { keyId: "engine-1", jwk: exportEd25519PublicJwk(keys.e.publicKey), status: "ACTIVE" },
    { keyId: "evidence-1", jwk: exportEd25519PublicJwk(keys.v.publicKey), status: "ACTIVE" },
  ],
  engine: { keyId: "engine-1", privateKey: keys.e.privateKey },
  evidenceSigner: { keyId: "evidence-1", privateKey: keys.v.privateKey },
  connectors: new Map(),
  now: () => new Date("2026-06-01T12:00:00Z"),
});
const api = createApi({
  client,
  principals: new Map(),
  rateLimit: { max: 1, windowMs: 1 },
  clockMs: () => 0,
});
const spec = buildOpenApi(api.describeRoutes(), "1.0.0");
const committedPath = fileURLToPath(new URL("../../../docs/api/openapi.json", import.meta.url));

describe("OpenAPI description", () => {
  it("documents every route the server exposes, and only those", () => {
    const documented = new Set<string>();
    for (const [path, ops] of Object.entries(
      spec.paths as Record<string, Record<string, unknown>>,
    )) {
      for (const method of Object.keys(ops)) documented.add(`${method.toUpperCase()} ${path}`);
    }
    const served = new Set(
      api.describeRoutes().map((r) => `${r.method} ${r.path.replace(/:([A-Za-z]+)/g, "{$1}")}`),
    );
    expect([...documented].sort()).toEqual([...served].sort());
  });

  it("marks public routes as unauthenticated and others as requiring bearer auth", () => {
    const health = (spec.paths as Record<string, Record<string, { security: unknown[] }>>)[
      "/v1/health"
    ]?.get;
    expect(health?.security).toEqual([]);
    const authorize = (spec.paths as Record<string, Record<string, { security: unknown[] }>>)[
      "/v1/authorize"
    ]?.post;
    expect(authorize?.security).toEqual([{ bearerAuth: [] }]);
  });

  it("the committed document matches the generated one", () => {
    expect(JSON.parse(readFileSync(committedPath, "utf8"))).toEqual(
      JSON.parse(JSON.stringify(spec)),
    );
  });
});
