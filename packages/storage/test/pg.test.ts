import { describe, expect, it } from "vitest";
import { TrustRootSet } from "@dip/authority";
import { exportEd25519PublicJwk, generateSigningKeyPair } from "@dip/crypto";
import type { EvidenceDraft } from "@dip/evidence";
import { PostgresEventLog, PostgresEvidenceLedger, migrate, openPostgres } from "../src/index.js";

/**
 * Runs only when DIP_TEST_PG_URL names a reachable PostgreSQL server. CI provides one
 * as a service container. Without it, the suite is skipped, not faked.
 */
const url = process.env.DIP_TEST_PG_URL;

function draft(id: string): EvidenceDraft {
  return {
    evidenceId: id,
    transactionId: "txn-1",
    recordedAt: "2026-06-01T12:00:00Z",
    request: { requestId: "req-1", requestDigest: "a".repeat(64), idempotencyKey: `idem-${id}` },
    authorization: {
      decisionId: "b".repeat(64),
      result: "DENY",
      reasonCodes: ["AMOUNT_EXCEEDS_LIMIT"],
      authorityRef: { authorityId: "auth-1", version: 1 },
      policyRef: { policyId: "policy-1", version: 1 },
      evaluatedAt: "2026-06-01T12:00:00Z",
      decisionSigningKeyId: "engine-1",
    },
    approvalRef: null,
    execution: null,
  };
}

describe.skipIf(url === undefined)("node-postgres adapter (real server)", () => {
  it("migrates, appends a verifiable chain, rejects duplicates, and blocks mutation", async () => {
    // One connection, so the session search_path set below applies to every query.
    const db = openPostgres(url ?? "", 1);
    try {
      // A fresh schema per run, so repeated runs against one server do not interfere.
      const schema = `dip_test_${Date.now().toString(36)}`;
      await db.exec(`CREATE SCHEMA ${schema}; SET search_path TO ${schema};`);
      await db.exec(`SET search_path TO ${schema}`);
      await migrate(db);
      const evidence = generateSigningKeyPair();
      const trust = new TrustRootSet();
      trust.add({
        keyId: "evidence-1",
        jwk: exportEd25519PublicJwk(evidence.publicKey),
        status: "ACTIVE",
      });
      const ledger = new PostgresEvidenceLedger(db, trust, {
        keyId: "evidence-1",
        privateKey: evidence.privateKey,
      });
      await ledger.append(draft("ev-1"));
      await ledger.append(draft("ev-2"));
      expect((await ledger.verify(await ledger.head())).valid).toBe(true);
      await expect(ledger.append(draft("ev-1"))).rejects.toMatchObject({
        code: "EVIDENCE_DUPLICATE",
      });
      await expect(db.query("UPDATE evidence_ledger SET entry_canonical = 'x'")).rejects.toThrow(
        "append-only",
      );

      const log = new PostgresEventLog(db);
      await log.append([
        { kind: "evidence.tenant", payload: { evidenceId: "ev-1", tenantId: "tenant-1" } },
      ]);
      expect((await log.readAll()).map((r) => r.kind)).toEqual(["evidence.tenant"]);
      await db.exec(`DROP SCHEMA ${schema} CASCADE`);
    } finally {
      await db.close?.();
    }
  });
});
