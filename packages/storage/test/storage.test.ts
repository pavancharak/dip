import { describe, expect, it, beforeEach } from "vitest";
import { PGlite } from "@electric-sql/pglite";
import {
  DipError,
  TrustRootSet,
  parseAuthorityBody,
  signAuthority,
  signRevocation,
  type AuthorityBody,
} from "@dip/authority";
import { exportEd25519PublicJwk, generateSigningKeyPair, type SigningKeyPair } from "@dip/crypto";
import { GENESIS_DIGEST, type EvidenceDraft } from "@dip/evidence";
import {
  PostgresAuthorityRegistry,
  PostgresEvidenceLedger,
  migrate,
  type SqlDatabase,
  type SqlQueryable,
} from "../src/index.js";

/** Adapts PGlite to the SqlDatabase surface the stores use. */
function adapt(pg: PGlite): SqlDatabase {
  return {
    query: (text, params) => pg.query(text, params as unknown[] | undefined),
    exec: (text) => pg.exec(text),
    transaction: <T>(fn: (tx: SqlQueryable) => Promise<T>) =>
      pg.transaction((tx) => fn({ query: (t, p) => tx.query(t, p as unknown[] | undefined) })),
  };
}

interface Env {
  readonly pg: PGlite;
  readonly db: SqlDatabase;
  readonly trust: TrustRootSet;
  readonly issuer: SigningKeyPair;
  readonly evidence: SigningKeyPair;
}

async function fresh(): Promise<Env> {
  const pg = await PGlite.create();
  const db = adapt(pg);
  await migrate(db);
  const issuer = generateSigningKeyPair();
  const evidence = generateSigningKeyPair();
  const trust = new TrustRootSet();
  trust.add({
    keyId: "issuer-key-1",
    jwk: exportEd25519PublicJwk(issuer.publicKey),
    status: "ACTIVE",
  });
  trust.add({
    keyId: "evidence-1",
    jwk: exportEd25519PublicJwk(evidence.publicKey),
    status: "ACTIVE",
  });
  return { pg, db, trust, issuer, evidence };
}

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

function authorityBody(overrides: Partial<AuthorityBody> = {}): AuthorityBody {
  return parseAuthorityBody({
    authorityId: "auth-1",
    version: 1,
    organizationId: "org-acme",
    tenantId: "tenant-1",
    issuer: "cfo",
    principal: "cfo",
    agent: null,
    permittedActions: ["payment.create"],
    resourceScope: ["*"],
    maxAmountMinor: 5_000_000,
    currencies: ["INR"],
    approvalAboveMinor: null,
    approvalActions: [],
    approverKeyIds: [],
    validFrom: "2026-01-01T00:00:00Z",
    validUntil: "2027-01-01T00:00:00Z",
    delegatedFrom: null,
    delegationAllowed: false,
    policyId: "policy-1",
    policyVersion: 1,
    protocolVersion: "1.0",
    signatureAlgorithm: "Ed25519",
    signingKeyId: "issuer-key-1",
    ...overrides,
  });
}

let env: Env;
beforeEach(async () => {
  env = await fresh();
});

function ledger(e: Env = env): PostgresEvidenceLedger {
  return new PostgresEvidenceLedger(e.db, e.trust, {
    keyId: "evidence-1",
    privateKey: e.evidence.privateKey,
  });
}

describe("schema", () => {
  it("migration is idempotent", async () => {
    expect(await migrate(env.db)).toBe(1);
    expect(await migrate(env.db)).toBe(1);
    const rows = await env.db.query("SELECT count(*) AS n FROM dip_schema_migrations");
    expect(Number(rows.rows[0]?.n)).toBe(1);
  });
});

describe("durable evidence ledger", () => {
  it("appends, exports and verifies a chain", async () => {
    const l = ledger();
    await l.append(draft("ev-1"));
    await l.append(draft("ev-2"));
    const report = await l.verify(await l.head());
    expect(report.valid).toBe(true);
    expect(report.entries).toBe(2);
    expect(await l.size()).toBe(2);
  });

  it("survives a restart: a new instance continues the same chain", async () => {
    await ledger().append(draft("ev-1"));
    const headBefore = await ledger().head();
    const restarted = ledger();
    expect(await restarted.head()).toBe(headBefore);
    const third = await restarted.append(draft("ev-2"));
    expect(third.body.sequence).toBe(2);
    expect(third.body.previousDigest).toBe(headBefore);
    expect((await restarted.verify(await restarted.head())).valid).toBe(true);
  });

  it("the empty ledger has the genesis head", async () => {
    expect(await ledger().head()).toBe(GENESIS_DIGEST);
  });

  it("concurrent appends are serialized into one valid chain", async () => {
    const l = ledger();
    await Promise.all(Array.from({ length: 5 }, (_, i) => l.append(draft(`ev-c${String(i)}`))));
    const report = await l.verify(await l.head());
    expect(report.valid).toBe(true);
    expect(await l.size()).toBe(5);
  });

  it("refuses a duplicate evidence id with a typed error and records nothing", async () => {
    const l = ledger();
    await l.append(draft("ev-1"));
    await expect(l.append(draft("ev-1"))).rejects.toThrow(DipError);
    expect(await l.size()).toBe(1);
  });

  it("the database refuses UPDATE, DELETE and TRUNCATE on evidence", async () => {
    await ledger().append(draft("ev-1"));
    await expect(env.db.query("UPDATE evidence_ledger SET entry_canonical = 'x'")).rejects.toThrow(
      "append-only",
    );
    await expect(env.db.query("DELETE FROM evidence_ledger")).rejects.toThrow("append-only");
    await expect(env.db.exec("TRUNCATE evidence_ledger")).rejects.toThrow("append-only");
    expect(await ledger().size()).toBe(1);
  });

  it("detects tampering by a party who disables the triggers (superuser-level edit)", async () => {
    const l = ledger();
    await l.append(draft("ev-1"));
    await l.append(draft("ev-2"));
    const head = await l.head();
    await env.pg.exec("ALTER TABLE evidence_ledger DISABLE TRIGGER evidence_ledger_no_update");
    await env.pg.query(
      "UPDATE evidence_ledger SET entry_canonical = replace(entry_canonical, 'txn-1', 'txn-EVIL') WHERE sequence = 1",
    );
    await env.pg.exec("ALTER TABLE evidence_ledger ENABLE TRIGGER evidence_ledger_no_update");
    const report = await l.verify(head);
    expect(report.valid).toBe(false);
    expect(report.errors.map((e) => e.code)).toContain("EVIDENCE_SIGNATURE_INVALID");
  });

  it("detects a deleted row when the trigger is disabled", async () => {
    const l = ledger();
    await l.append(draft("ev-1"));
    await l.append(draft("ev-2"));
    await l.append(draft("ev-3"));
    const head = await l.head();
    await env.pg.exec("ALTER TABLE evidence_ledger DISABLE TRIGGER evidence_ledger_no_update");
    await env.pg.query("DELETE FROM evidence_ledger WHERE sequence = 2");
    await env.pg.exec("ALTER TABLE evidence_ledger ENABLE TRIGGER evidence_ledger_no_update");
    const report = await l.verify(head);
    expect(report.valid).toBe(false);
    expect(report.errors.map((e) => e.code)).toContain("SEQUENCE_MISMATCH");
  });
});

describe("durable authority registry", () => {
  it("publishes, reads back and continues versions across instances", async () => {
    const reg = new PostgresAuthorityRegistry(env.db, env.trust);
    await reg.publish(signAuthority(authorityBody(), env.issuer.privateKey));
    const again = new PostgresAuthorityRegistry(env.db, env.trust);
    expect(await again.latestVersion("auth-1")).toBe(1);
    expect((await again.get("auth-1", 1))?.body.authorityId).toBe("auth-1");
    await again.publish(signAuthority(authorityBody({ version: 2 }), env.issuer.privateKey));
    expect(await again.latestVersion("auth-1")).toBe(2);
  });

  it("refuses republication, gaps, tampering and unknown keys", async () => {
    const reg = new PostgresAuthorityRegistry(env.db, env.trust);
    const v1 = signAuthority(authorityBody(), env.issuer.privateKey);
    await reg.publish(v1);
    await expect(reg.publish(v1)).rejects.toMatchObject({ code: "AUTHORITY_ALREADY_PUBLISHED" });
    await expect(
      reg.publish(signAuthority(authorityBody({ version: 3 }), env.issuer.privateKey)),
    ).rejects.toMatchObject({ code: "AUTHORITY_VERSION_GAP" });
    const tampered = { body: { ...v1.body, maxAmountMinor: 999_999_999 }, signature: v1.signature };
    await expect(reg.publish(tampered)).rejects.toMatchObject({
      code: "AUTHORITY_SIGNATURE_INVALID",
    });
    const rogue = signAuthority(
      authorityBody({ signingKeyId: "rogue" }),
      generateSigningKeyPair().privateKey,
    );
    await expect(reg.publish(rogue)).rejects.toMatchObject({ code: "AUTHORITY_KEY_UNKNOWN" });
  });

  it("persists a signed revocation and refuses a second one", async () => {
    const reg = new PostgresAuthorityRegistry(env.db, env.trust);
    await reg.publish(signAuthority(authorityBody(), env.issuer.privateKey));
    const rev = signRevocation(
      {
        authorityId: "auth-1",
        version: 1,
        revokedAt: "2026-06-01T11:00:00Z",
        signingKeyId: "issuer-key-1",
      },
      env.issuer.privateKey,
    );
    await reg.revoke(rev);
    expect(
      await new PostgresAuthorityRegistry(env.db, env.trust).revocationOf("auth-1", 1),
    ).toBeDefined();
    await expect(reg.revoke(rev)).rejects.toMatchObject({ code: "AUTHORITY_ALREADY_REVOKED" });
  });

  it("the database refuses changes to published authority versions", async () => {
    const reg = new PostgresAuthorityRegistry(env.db, env.trust);
    await reg.publish(signAuthority(authorityBody(), env.issuer.privateKey));
    await expect(
      env.db.query("UPDATE authority_versions SET signed_canonical = 'x'"),
    ).rejects.toThrow("append-only");
    await expect(env.db.query("DELETE FROM authority_versions")).rejects.toThrow("append-only");
  });
});
