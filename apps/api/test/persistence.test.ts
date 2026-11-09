import { describe, expect, it } from "vitest";
import { parseAuthorityBody, signAuthority, type AuthorityBody } from "@dip/authority";
import { exportEd25519PublicJwk, generateSigningKeyPair } from "@dip/crypto";
import { DipClient, type DipClientConfig, type EventSink } from "@dip/sdk";
import { PostgresEventLog, migrate, openPostgres } from "@dip/storage";
import { createApi, type ApiRequest } from "../src/index.js";

const NOW = new Date("2026-06-01T12:00:00Z");
const keys = {
  issuer: generateSigningKeyPair(),
  engine: generateSigningKeyPair(),
  evidence: generateSigningKeyPair(),
};

function clientConfig(eventLog?: EventSink): DipClientConfig {
  return {
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
    connectors: new Map(),
    now: () => NOW,
    ...(eventLog === undefined ? {} : { eventLog }),
  };
}

function authorityBody(): AuthorityBody {
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

function api(client: DipClient, onPersistenceFailure?: (err: unknown) => void) {
  return createApi({
    client,
    principals: new Map([["key-operator", { name: "operator", tenantId: "tenant-1", scopes: [] }]]),
    rateLimit: { max: 1000, windowMs: 60_000 },
    clockMs: () => NOW.getTime(),
    ...(onPersistenceFailure === undefined ? {} : { onPersistenceFailure }),
  });
}

function req(body: unknown): ApiRequest {
  return {
    method: "POST",
    path: "/v1/authorities",
    headers: { authorization: "Bearer key-operator" },
    body,
  };
}

describe("persistence fail-stop", () => {
  it("does not answer a write whose change could not be persisted, and reports the failure", async () => {
    const failing: EventSink = {
      readAll: async () => [],
      append: async () => {
        throw new Error("disk unavailable");
      },
    };
    const client = await DipClient.open(clientConfig(failing));
    const reported: unknown[] = [];
    const server = api(client, (err) => reported.push(err));
    const signed = signAuthority(authorityBody(), keys.issuer.privateKey);

    const response = await server.handle(req(signed));
    expect(response.status).toBe(500);
    expect(response.status).not.toBe(201);
    expect(reported).toHaveLength(1);
  });
});

const url = process.env.DIP_TEST_PG_URL;

describe.skipIf(url === undefined)("server state on PostgreSQL (real server)", () => {
  it("authorities written through the API are restored by a new process", async () => {
    const admin = openPostgres(url ?? "", 1);
    const name = `dip_srv_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
    await admin.query(`CREATE DATABASE "${name}"`);
    const target = new URL(url ?? "");
    target.pathname = `/${name}`;
    const db1 = openPostgres(target.toString(), 2);
    try {
      await migrate(db1);
      const client1 = await DipClient.open(clientConfig(new PostgresEventLog(db1)));
      const signed = signAuthority(authorityBody(), keys.issuer.privateKey);
      const written = await api(client1).handle(req(signed));
      expect(written.status).toBe(201);
      await db1.close?.();

      const db2 = openPostgres(target.toString(), 2);
      try {
        const client2 = await DipClient.open(clientConfig(new PostgresEventLog(db2)));
        expect(client2.getAuthority("auth-1", 1)).toBeDefined();
      } finally {
        await db2.close?.();
      }
    } finally {
      await admin.query(`DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`);
      await admin.close?.();
    }
  });
});
