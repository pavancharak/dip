import { describe, expect, it } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { parseAuthorityBody, signAuthority, type AuthorityBody } from "@dip/authority";
import { exportEd25519PublicJwk, generateSigningKeyPair } from "@dip/crypto";
import { DipClient } from "@dip/sdk";
import { createApi } from "@dip/api";
import { EXIT, runCli, type CliIo } from "../src/index.js";

const NOW = new Date("2026-06-01T12:00:00Z");
const URL_BASE = "http://dip.test";

async function world() {
  const keys = {
    issuer: generateSigningKeyPair(),
    engine: generateSigningKeyPair(),
    evidence: generateSigningKeyPair(),
  };
  const connector = { calls: 0 };
  const client = new DipClient({
    trustRoots: [
      {
        keyId: "issuer-key-1",
        jwk: exportEd25519PublicJwk(keys.issuer.publicKey),
        status: "ACTIVE",
      },
      { keyId: "engine-1", jwk: exportEd25519PublicJwk(keys.engine.publicKey), status: "ACTIVE" },
      {
        keyId: "evidence-1",
        jwk: exportEd25519PublicJwk(keys.evidence.publicKey),
        status: "ACTIVE",
      },
    ],
    engine: { keyId: "engine-1", privateKey: keys.engine.privateKey },
    evidenceSigner: { keyId: "evidence-1", privateKey: keys.evidence.privateKey },
    connectors: new Map([
      [
        "payment.create",
        {
          id: "p",
          execute: async () => {
            connector.calls += 1;
            return { status: "SUCCEEDED" as const, externalRef: `p-${String(connector.calls)}` };
          },
        },
      ],
    ]),
    now: () => NOW,
  });
  const api = createApi({
    client,
    principals: new Map([["key-op", { name: "op", tenantId: "tenant-1", scopes: [] }]]),
    rateLimit: { max: 1000, windowMs: 60_000 },
    clockMs: () => NOW.getTime(),
  });
  const fetchToApi: typeof fetch = async (input, init) => {
    const url = new URL(String(input));
    const headers = init?.headers as Record<string, string> | undefined;
    const body = typeof init?.body === "string" ? (JSON.parse(init.body) as unknown) : undefined;
    const res = await api.handle({
      method: init?.method ?? "GET",
      path: url.pathname + url.search,
      headers: { authorization: headers?.authorization },
      body,
    });
    return new Response(res.body === null ? "" : JSON.stringify(res.body), { status: res.status });
  };
  return { client, keys, connector, fetchToApi };
}

function authorityBody(): Promise<AuthorityBody> {
  return parseAuthorityBody({
    authorityId: "auth-1",
    version: 1,
    organizationId: "org-acme",
    tenantId: "tenant-1",
    issuer: "cfo",
    principal: "cfo",
    agent: "payments-agent",
    permittedActions: ["payment.create"],
    resourceScope: ["vendor-42"],
    maxAmountMinor: 5_000_000,
    currencies: ["INR"],
    approvalAboveMinor: null,
    approvalActions: [],
    approverKeyIds: [],
    validFrom: "2020-01-01T00:00:00Z",
    validUntil: "2100-01-01T00:00:00Z",
    delegatedFrom: null,
    delegationAllowed: false,
    policyId: "policy-1",
    policyVersion: 1,
    protocolVersion: "1.0",
    signatureAlgorithm: "Ed25519",
    signingKeyId: "issuer-key-1",
  });
}

function rawRequest(amount: number, key: string): Record<string, unknown> {
  return {
    requestId: `req-${key}`,
    transactionId: `txn-${key}`,
    organizationId: "org-acme",
    tenantId: "tenant-1",
    actor: "payments-agent",
    operation: "payment.create",
    resource: "vendor-42",
    amount: { minor: amount, currency: "INR" },
    parameters: {},
    authorityRef: { authorityId: "auth-1", version: 1 },
    policyRef: { policyId: "policy-1", version: 1 },
    approvalRef: null,
    idempotencyKey: key,
    protocolVersion: "1.0",
  };
}

function io(files: Record<string, string>, fetchFn?: typeof fetch): CliIo {
  return {
    readFile: (p) => {
      const v = files[p];
      if (v === undefined) throw new Error(`no such file ${p}`);
      return v;
    },
    fetch:
      fetchFn ??
      (async () => {
        throw new Error("no network in this test");
      }),
    env: { DIP_URL: URL_BASE, DIP_API_KEY: "key-op" },
  };
}

describe("dip command line", () => {
  it("prints usage with exit 0, and rejects unknown commands with exit 3", async () => {
    expect((await runCli([], io({}))).exitCode).toBe(EXIT.OK);
    const bad = await runCli(["nope"], io({}));
    expect(bad.exitCode).toBe(EXIT.USAGE);
  });

  it("refuses a request without credentials", async () => {
    const r = await runCli(["ledger", "inspect"], { ...io({}), env: {} });
    expect(r.exitCode).toBe(EXIT.USAGE);
  });

  it("signs a declaration and produces a verifiable authority", async () => {
    const pem = generateKeyPairSync("ed25519")
      .privateKey.export({ type: "pkcs8", format: "pem" })
      .toString();
    const decl = JSON.stringify(authorityBody());
    const r = await runCli(
      ["authority", "sign", "decl.json", "--key", "k.pem", "--json"],
      io({ "decl.json": decl, "k.pem": pem }),
    );
    expect(r.exitCode).toBe(EXIT.OK);
    expect((JSON.parse(r.stdout) as { signature: string }).signature).toMatch(
      /^[A-Za-z0-9_-]{86}$/,
    );
  });

  it("rejects an invalid declaration with exit 3", async () => {
    const bad = JSON.stringify({ ...authorityBody(), maxAmountMinor: 1.5 });
    expect((await runCli(["authority", "create", "d.json"], io({ "d.json": bad }))).exitCode).toBe(
      EXIT.USAGE,
    );
  });

  it("authorize returns 0 for ALLOW and 1 for DENY, against the real API", async () => {
    const w = await world();
    w.client.publishAuthority(signAuthority(authorityBody(), w.keys.issuer.privateKey));
    const files = {
      "allow.json": JSON.stringify(rawRequest(400_000, "a")),
      "deny.json": JSON.stringify(rawRequest(80_000_000, "d")),
    };
    const allow = await runCli(["authorize", "allow.json"], io(files, w.fetchToApi));
    expect(allow.exitCode).toBe(EXIT.OK);
    expect(allow.stdout).toContain("result: ALLOW");
    const deny = await runCli(["authorize", "deny.json"], io(files, w.fetchToApi));
    expect(deny.exitCode).toBe(EXIT.NEGATIVE);
    expect(deny.stdout).toContain("AMOUNT_EXCEEDS_LIMIT");
  });

  it("execute runs once; a repeat is a duplicate, and a refused decision exits 1", async () => {
    const w = await world();
    w.client.publishAuthority(signAuthority(authorityBody(), w.keys.issuer.privateKey));
    const authorized = await w.client.authorize(
      w.client.normalizeRequest(rawRequest(400_000, "x")),
    );
    const body = JSON.stringify({
      request: rawRequest(400_000, "x"),
      decision: authorized.decision,
    });
    const first = await runCli(
      ["execute", "e.json", "--json"],
      io({ "e.json": body }, w.fetchToApi),
    );
    expect(first.exitCode).toBe(EXIT.OK);
    expect(w.connector.calls).toBe(1);
    const again = await runCli(
      ["execute", "e.json", "--json"],
      io({ "e.json": body }, w.fetchToApi),
    );
    expect(again.exitCode).toBe(EXIT.OK);
    expect(w.connector.calls).toBe(1);
    const denied = await w.client.authorize(w.client.normalizeRequest(rawRequest(80_000_000, "y")));
    const refused = await runCli(
      ["execute", "r.json"],
      io(
        {
          "r.json": JSON.stringify({
            request: rawRequest(80_000_000, "y"),
            decision: denied.decision,
          }),
        },
        w.fetchToApi,
      ),
    );
    expect(refused.exitCode).toBe(EXIT.NEGATIVE);
    expect(w.connector.calls).toBe(1);
  });

  it("a server that is unreachable or fails returns exit 4", async () => {
    const down: typeof fetch = async () => {
      throw new Error("connect ECONNREFUSED");
    };
    expect((await runCli(["ledger", "inspect"], io({}, down))).exitCode).toBe(EXIT.SERVER);
    const broken: typeof fetch = async () => new Response("{}", { status: 500 });
    expect((await runCli(["ledger", "inspect"], io({}, broken))).exitCode).toBe(EXIT.SERVER);
  });

  it("verify maps VALID to 0, INVALID to 1, and INCOMPLETE to 2 using real conformance fixtures", async () => {
    const dir = fileURLToPath(new URL("../../../conformance/", import.meta.url));
    const load = (name: string) =>
      JSON.parse(readFileSync(dir + name, "utf8")) as { bundle: unknown; trust: unknown };
    const valid = load("bundles/valid-allow-executed.json");
    const tampered = load("bundles/invalid-tampered-entry.json");
    const missing = load("bundles/incomplete-missing-request.json");
    const files = {
      "v.json": JSON.stringify(valid.bundle),
      "vt.json": JSON.stringify(valid.trust),
      "t.json": JSON.stringify(tampered.bundle),
      "tt.json": JSON.stringify(tampered.trust),
      "m.json": JSON.stringify(missing.bundle),
      "mt.json": JSON.stringify(missing.trust),
    };
    expect((await runCli(["verify", "v.json", "--trust", "vt.json"], io(files))).exitCode).toBe(
      EXIT.OK,
    );
    expect((await runCli(["verify", "t.json", "--trust", "tt.json"], io(files))).exitCode).toBe(
      EXIT.NEGATIVE,
    );
    expect((await runCli(["verify", "m.json", "--trust", "mt.json"], io(files))).exitCode).toBe(
      EXIT.UNDETERMINED,
    );
  });

  it("runs the conformance suite against the reference implementation", async () => {
    const dir = fileURLToPath(new URL("../../../conformance", import.meta.url));
    const real: CliIo = {
      readFile: (p) => readFileSync(p, "utf8"),
      fetch: globalThis.fetch,
      env: {},
    };
    const r = await runCli(["conformance", "run", dir, "--json"], real);
    expect(r.exitCode).toBe(EXIT.OK);
    expect((JSON.parse(r.stdout) as { failed: unknown[] }).failed).toEqual([]);
  });
});
