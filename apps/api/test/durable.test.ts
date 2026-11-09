import { describe, expect, it } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseAuthorityBody, signAuthority, type AuthorityBody } from "@dip/authority";
import { exportEd25519PublicJwk, generateSigningKeyPair } from "@dip/crypto";
import { DipClient, type DipClientConfig } from "@dip/sdk";
import { PostgresEventLog, migrate, openDatabase } from "@dip/storage";
import { createApi, type ApiRequest } from "../src/index.js";

const NOW = new Date("2026-06-01T12:00:00Z");
const keys = {
  issuer: generateSigningKeyPair(),
  engine: generateSigningKeyPair(),
  evidence: generateSigningKeyPair(),
};
let connectorCalls = 0;

function clientConfig(eventLog: PostgresEventLog): DipClientConfig {
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
    connectors: new Map([
      [
        "payment.create",
        {
          id: "payments",
          execute: async () => {
            connectorCalls += 1;
            return { status: "SUCCEEDED" as const, externalRef: `pay-${String(connectorCalls)}` };
          },
        },
      ],
    ]),
    now: () => NOW,
    eventLog,
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

function raw(idempotencyKey: string): Record<string, unknown> {
  return {
    requestId: `req-${idempotencyKey}`,
    transactionId: `txn-${idempotencyKey}`,
    organizationId: "org-acme",
    tenantId: "tenant-1",
    actor: "payments-agent",
    operation: "payment.create",
    resource: "vendor-42",
    amount: { minor: 400_000, currency: "INR" },
    parameters: {},
    authorityRef: { authorityId: "auth-1", version: 1 },
    policyRef: { policyId: "policy-1", version: 1 },
    approvalRef: null,
    idempotencyKey,
    protocolVersion: "1.0",
  };
}

function api(client: DipClient) {
  return createApi({
    client,
    principals: new Map([
      ["key-operator", { name: "operator", tenantId: "tenant-1", scopes: [] }],
      ["key-tenant2", { name: "other", tenantId: "tenant-2", scopes: [] }],
    ]),
    rateLimit: { max: 1000, windowMs: 60_000 },
    clockMs: () => NOW.getTime(),
  });
}

function req(method: string, path: string, key: string, body?: unknown): ApiRequest {
  return { method, path, headers: { authorization: `Bearer ${key}` }, body };
}

describe("server state survives a restart (file-backed PostgreSQL)", () => {
  it("authorities, executions, replay protection, evidence and tenant isolation persist", async () => {
    const dir = mkdtempSync(join(tmpdir(), "dip-durable-"));
    connectorCalls = 0;

    // First process: write through the API.
    const db1 = await openDatabase(dir);
    await migrate(db1);
    const client1 = await DipClient.open(clientConfig(new PostgresEventLog(db1)));
    const api1 = api(client1);
    const signed = signAuthority(authorityBody(), keys.issuer.privateKey);
    expect((await api1.handle(req("POST", "/v1/authorities", "key-operator", signed))).status).toBe(
      201,
    );
    const authorized = await api1.handle(
      req("POST", "/v1/authorize", "key-operator", raw("idem-1")),
    );
    const decision = (authorized.body as { decision: unknown }).decision;
    const executed = await api1.handle(
      req("POST", "/v1/execute", "key-operator", { request: raw("idem-1"), decision }),
    );
    expect((executed.body as { attempt: { state: string } }).attempt.state).toBe("SUCCEEDED");
    expect(connectorCalls).toBe(1);
    await db1.close?.();

    // Second process: reopen the same directory and rebuild from the log.
    const db2 = await openDatabase(dir);
    await migrate(db2);
    const client2 = await DipClient.open(clientConfig(new PostgresEventLog(db2)));
    const api2 = api(client2);

    expect((await api2.handle(req("GET", "/v1/authorities/auth-1", "key-operator"))).status).toBe(
      200,
    );

    // The same decision cannot run again after the restart.
    const again = await api2.handle(
      req("POST", "/v1/execute", "key-operator", { request: raw("idem-1"), decision }),
    );
    expect((again.body as { attempt: { state: string } }).attempt.state).toBe("DUPLICATE");
    expect(connectorCalls).toBe(1);

    // Evidence written before the restart is still readable by its tenant only.
    const evidenceId = (executed.body as { evidenceId: string }).evidenceId;
    expect(
      (await api2.handle(req("GET", `/v1/evidence/${evidenceId}`, "key-operator"))).status,
    ).toBe(200);
    expect(
      (await api2.handle(req("GET", `/v1/evidence/${evidenceId}`, "key-tenant2"))).status,
    ).toBe(404);

    // The chain continues: a new execution appends the next evidence record and verifies.
    const next = await api2.handle(req("POST", "/v1/authorize", "key-operator", raw("idem-2")));
    const exec2 = await api2.handle(
      req("POST", "/v1/execute", "key-operator", {
        request: raw("idem-2"),
        decision: (next.body as { decision: unknown }).decision,
      }),
    );
    // Every attempt is evidenced, including the refused replay above, so this is the third record.
    expect((exec2.body as { evidenceId: string }).evidenceId).toBe("ev-00000003");
    expect(client2.verifyLedger(client2.ledgerHead()).valid).toBe(true);
    expect(client2.ledgerSize()).toBe(3);

    // Records really are in the database.
    const count = await db2.query("SELECT count(*) AS n FROM dip_event_log");
    expect(Number(count.rows[0]?.n)).toBeGreaterThan(4);
    await db2.close?.();
  });

  it("refuses to start when the stored evidence chain has been altered", async () => {
    const dir = mkdtempSync(join(tmpdir(), "dip-tamper-"));
    const db1 = await openDatabase(dir);
    await migrate(db1);
    const client1 = await DipClient.open(clientConfig(new PostgresEventLog(db1)));
    client1.publishAuthority(signAuthority(authorityBody(), keys.issuer.privateKey));
    const normalized = client1.normalizeRequest(raw("idem-t"));
    const decision = (await client1.authorize(normalized)).decision;
    const attempt = await client1.execute(normalized, decision);
    await client1.record({ normalized, decision, attempt });
    await client1.flush();
    // Alter a stored evidence record directly in the database, bypassing the application.
    // The append-only trigger is disabled first, as a database owner could do.
    await db1.exec("ALTER TABLE dip_event_log DISABLE TRIGGER dip_event_log_no_update");
    await db1.query(
      "UPDATE dip_event_log SET payload = replace(payload, 'txn-idem-t', 'txn-EVIL') WHERE kind = 'evidence.appended'",
    );
    await db1.exec("ALTER TABLE dip_event_log ENABLE TRIGGER dip_event_log_no_update");
    await db1.close?.();

    const db2 = await openDatabase(dir);
    await expect(DipClient.open(clientConfig(new PostgresEventLog(db2)))).rejects.toMatchObject({
      code: "LEDGER_INVALID_ON_OPEN",
    });
    await db2.close?.();
  });
});
