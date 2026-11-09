import { describe, expect, it } from "vitest";
import {
  mkdtempSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
  existsSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseAuthorityBody, signAuthority, type AuthorityBody } from "@dip/authority";
import { exportEd25519PublicJwk, generateSigningKeyPair, type SigningKeyPair } from "@dip/crypto";
import { DipClient, type DipClientConfig } from "@dip/sdk";
import { PostgresEventLog, migrate, openDatabase } from "@dip/storage";
import { createBackup, directoryDigest, restoreBackup, verifyBackup } from "../src/backup.js";
import { EXIT, runCli } from "../src/index.js";

const NOW = new Date("2026-06-01T12:00:00Z");

interface Keys {
  issuer: SigningKeyPair;
  engine: SigningKeyPair;
  evidence: SigningKeyPair;
}

function keys(): Keys {
  return {
    issuer: generateSigningKeyPair(),
    engine: generateSigningKeyPair(),
    evidence: generateSigningKeyPair(),
  };
}

function trustOf(k: Keys) {
  return [
    {
      keyId: "issuer-key-1",
      jwk: exportEd25519PublicJwk(k.issuer.publicKey),
      status: "ACTIVE" as const,
    },
    {
      keyId: "engine-1",
      jwk: exportEd25519PublicJwk(k.engine.publicKey),
      status: "ACTIVE" as const,
    },
    {
      keyId: "evidence-1",
      jwk: exportEd25519PublicJwk(k.evidence.publicKey),
      status: "ACTIVE" as const,
    },
  ];
}

function config(k: Keys, eventLog: PostgresEventLog): DipClientConfig {
  return {
    trustRoots: trustOf(k),
    engine: { keyId: "engine-1", privateKey: k.engine.privateKey },
    evidenceSigner: { keyId: "evidence-1", privateKey: k.evidence.privateKey },
    connectors: new Map([
      [
        "payment.create",
        { id: "p", execute: async () => ({ status: "SUCCEEDED" as const, externalRef: "pay-1" }) },
      ],
    ]),
    now: () => NOW,
    eventLog,
  };
}

function body(): AuthorityBody {
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

/** Seeds a file-backed database with one authority and one executed, evidenced action. */
async function seed(dataDir: string, k: Keys): Promise<void> {
  const db = await openDatabase(dataDir);
  await migrate(db);
  const client = await DipClient.open(config(k, new PostgresEventLog(db)));
  client.publishAuthority(signAuthority(body(), k.issuer.privateKey));
  const raw = {
    requestId: "req-1",
    transactionId: "txn-1",
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
    idempotencyKey: "idem-1",
    protocolVersion: "1.0",
  };
  const normalized = client.normalizeRequest(raw);
  const decision = client.authorize(normalized).decision;
  const attempt = await client.execute(normalized, decision);
  client.record({ normalized, decision, attempt });
  await client.flush();
  await db.close?.();
}

function tempDir(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

describe("backup, verify and restore", () => {
  it("creates a backup that verifies, and restores it to a working database", async () => {
    const k = keys();
    const data = tempDir("dip-data-");
    await seed(data, k);
    const dest = join(tempDir("dip-bk-"), "bk");
    const created = await createBackup(data, dest, trustOf(k), NOW);
    expect(created.ok).toBe(true);
    expect(created.manifest?.ledgerEntries).toBe(1);
    expect((await verifyBackup(dest, trustOf(k))).ok).toBe(true);

    const target = join(tempDir("dip-restore-"), "restored");
    expect((await restoreBackup(dest, target, trustOf(k))).ok).toBe(true);
    const db = await openDatabase(target);
    const client = await DipClient.open(config(k, new PostgresEventLog(db)));
    expect(client.getAuthority("auth-1", 1)).toBeDefined();
    expect(client.ledgerSize()).toBe(1);
    await db.close?.();
  });

  it("detects a changed file in the backup", async () => {
    const k = keys();
    const data = tempDir("dip-data-");
    await seed(data, k);
    const dest = join(tempDir("dip-bk-"), "bk");
    await createBackup(data, dest, trustOf(k), NOW);
    const first = firstFile(join(dest, "data"));
    writeFileSync(first, Buffer.concat([readFileSync(first), Buffer.from("x")]));
    const r = await verifyBackup(dest, trustOf(k));
    expect(r).toMatchObject({ ok: false, code: "DIGEST_MISMATCH" });
  });

  it("refuses to back up a database whose evidence chain is broken", async () => {
    const k = keys();
    const data = tempDir("dip-data-");
    await seed(data, k);
    const db = await openDatabase(data);
    await db.exec("ALTER TABLE dip_event_log DISABLE TRIGGER dip_event_log_no_update");
    await db.query(
      "UPDATE dip_event_log SET payload = replace(payload, 'txn-1', 'txn-EVIL') WHERE kind = 'evidence.appended'",
    );
    await db.exec("ALTER TABLE dip_event_log ENABLE TRIGGER dip_event_log_no_update");
    await db.close?.();
    const r = await createBackup(data, join(tempDir("dip-bk-"), "bk"), trustOf(k), NOW);
    expect(r).toMatchObject({ ok: false, code: "LEDGER_INVALID" });
  });

  it("refuses a destination that is not empty, and a restore target that is not empty", async () => {
    const k = keys();
    const data = tempDir("dip-data-");
    await seed(data, k);
    const dest = tempDir("dip-bk-");
    writeFileSync(join(dest, "keep.txt"), "x");
    expect((await createBackup(data, dest, trustOf(k), NOW)).code).toBe("DESTINATION_NOT_EMPTY");
    const bk = join(tempDir("dip-bk-"), "bk");
    await createBackup(data, bk, trustOf(k), NOW);
    const busy = tempDir("dip-restore-");
    writeFileSync(join(busy, "keep.txt"), "x");
    expect((await restoreBackup(bk, busy, trustOf(k))).code).toBe("TARGET_NOT_EMPTY");
  });

  it("an external head anchor catches a backup whose manifest was replaced consistently", async () => {
    const k = keys();
    const data = tempDir("dip-data-");
    await seed(data, k);
    const bk = join(tempDir("dip-bk-"), "bk");
    await createBackup(data, bk, trustOf(k), NOW);
    expect((await verifyBackup(bk, trustOf(k), "f".repeat(64))).code).toBe("ANCHOR_MISMATCH");
    const head = (
      JSON.parse(readFileSync(join(bk, "manifest.json"), "utf8")) as { ledgerHead: string }
    ).ledgerHead;
    expect((await verifyBackup(bk, trustOf(k), head)).ok).toBe(true);
  });

  it("the dip backup command exits 0 for a valid backup and 1 for a damaged one", async () => {
    const k = keys();
    const data = tempDir("dip-data-");
    await seed(data, k);
    const bk = join(tempDir("dip-bk-"), "bk");
    await createBackup(data, bk, trustOf(k), NOW);
    const files: Record<string, string> = { "trust.json": JSON.stringify(trustOf(k)) };
    const io = {
      readFile: (p: string) => files[p] ?? readFileSync(p, "utf8"),
      fetch: globalThis.fetch,
      env: {},
    };
    expect((await runCli(["backup", "verify", bk, "--trust", "trust.json"], io)).exitCode).toBe(
      EXIT.OK,
    );
    const first = firstFile(join(bk, "data"));
    writeFileSync(first, Buffer.concat([readFileSync(first), Buffer.from("x")]));
    expect((await runCli(["backup", "verify", bk, "--trust", "trust.json"], io)).exitCode).toBe(
      EXIT.NEGATIVE,
    );
  });

  it("directory digests are stable across identical trees and change with any byte", () => {
    const a = tempDir("dip-dig-");
    writeFileSync(join(a, "f"), "one");
    const first = directoryDigest(a).digest;
    expect(directoryDigest(a).digest).toBe(first);
    writeFileSync(join(a, "f"), "two");
    expect(directoryDigest(a).digest).not.toBe(first);
    expect(existsSync(a) && statSync(a).isDirectory()).toBe(true);
  });
});

function firstFile(dir: string): string {
  for (const name of readdirSync(dir).sort()) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) {
      const inner = firstFile(full);
      if (inner) return inner;
    } else {
      return full;
    }
  }
  return "";
}
