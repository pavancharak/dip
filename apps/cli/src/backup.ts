import { createHash, generateKeyPairSync } from "node:crypto";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import type { TrustRootInput } from "@dip/verifier";
import { DipClient, DipError } from "@dip/sdk";
import { PostgresEventLog, migrate, openDatabase } from "@dip/storage";

/**
 * Backups of the file-backed server database.
 *
 * A backup is taken from a stopped database: the data directory is copied, every
 * file is hashed, and a manifest records the directory digest and the evidence head.
 * Verification checks the hashes, then opens a scratch copy and checks the evidence
 * chain against the recorded head. Restore runs the same verification first, so a
 * damaged backup is never restored silently.
 *
 * Layout: <backup>/manifest.json and <backup>/data/.
 */
export const MANIFEST_FORMAT = "dip-backup";
export const MANIFEST_VERSION = 1;

export interface Manifest {
  readonly format: typeof MANIFEST_FORMAT;
  readonly formatVersion: typeof MANIFEST_VERSION;
  readonly createdAt: string;
  readonly files: number;
  readonly directoryDigest: string;
  readonly ledgerEntries: number;
  readonly ledgerHead: string;
  readonly eventRecords: number;
}

export interface BackupResult {
  readonly ok: boolean;
  readonly code: string;
  readonly detail: string;
  readonly manifest?: Manifest;
}

/** Deterministic digest of a directory tree: relative path, size and content hash for each file, sorted. */
export function directoryDigest(dir: string): { digest: string; files: number } {
  const entries: string[] = [];
  const walk = (current: string): void => {
    for (const name of readdirSync(current).sort()) {
      const full = join(current, name);
      const st = statSync(full);
      if (st.isDirectory()) walk(full);
      else if (st.isFile()) {
        const content = readFileSync(full);
        const hash = createHash("sha256").update(content).digest("hex");
        entries.push(`${relative(dir, full).split("\\").join("/")}\0${String(st.size)}\0${hash}`);
      }
    }
  };
  walk(dir);
  const digest = createHash("sha256").update(entries.join("\n")).digest("hex");
  return { digest, files: entries.length };
}

/** Ephemeral signers. Opening a client only replays and verifies; nothing is signed. */
function verificationOnlySigners(): {
  engine: { keyId: string; privateKey: ReturnType<typeof generateKeyPairSync>["privateKey"] };
  evidenceSigner: {
    keyId: string;
    privateKey: ReturnType<typeof generateKeyPairSync>["privateKey"];
  };
} {
  const e = generateKeyPairSync("ed25519").privateKey;
  const v = generateKeyPairSync("ed25519").privateKey;
  return {
    engine: { keyId: "backup-engine", privateKey: e },
    evidenceSigner: { keyId: "backup-evidence", privateKey: v },
  };
}

async function openAndCheck(
  dataDir: string,
  trust: readonly TrustRootInput[],
): Promise<{ client: DipClient; close: () => Promise<void>; eventRecords: number }> {
  const db = await openDatabase(dataDir);
  await migrate(db);
  const signers = verificationOnlySigners();
  const client = await DipClient.open({
    trustRoots: trust,
    engine: signers.engine,
    evidenceSigner: signers.evidenceSigner,
    connectors: new Map(),
    now: () => new Date(),
    eventLog: new PostgresEventLog(db),
  });
  const count = await db.query("SELECT count(*) AS n FROM dip_event_log");
  return {
    client,
    close: () => db.close?.() ?? Promise.resolve(),
    eventRecords: Number(count.rows[0]?.n ?? 0),
  };
}

function isEmptyOrMissing(dir: string): boolean {
  return !existsSync(dir) || readdirSync(dir).length === 0;
}

/** Creates a backup of a stopped server's data directory. Refuses to write into a non-empty directory. */
export async function createBackup(
  dataDir: string,
  destDir: string,
  trust: readonly TrustRootInput[],
  now: Date,
): Promise<BackupResult> {
  if (!existsSync(dataDir))
    return { ok: false, code: "DATA_DIR_MISSING", detail: "data directory does not exist" };
  if (!isEmptyOrMissing(destDir))
    return {
      ok: false,
      code: "DESTINATION_NOT_EMPTY",
      detail: "destination must be empty or absent",
    };

  let opened: Awaited<ReturnType<typeof openAndCheck>>;
  try {
    opened = await openAndCheck(dataDir, trust);
  } catch (err) {
    if (err instanceof DipError && err.code === "LEDGER_INVALID_ON_OPEN") {
      return {
        ok: false,
        code: "LEDGER_INVALID",
        detail: "the evidence chain does not verify; backup refused",
      };
    }
    throw err;
  }
  const head = opened.client.ledgerHead();
  const entries = opened.client.ledgerSize();
  const report = opened.client.verifyLedger(head);
  await opened.close();
  if (!report.valid)
    return {
      ok: false,
      code: "LEDGER_INVALID",
      detail: "the evidence chain does not verify; backup refused",
    };

  mkdirSync(join(destDir, "data"), { recursive: true });
  cpSync(dataDir, join(destDir, "data"), { recursive: true });
  const { digest, files } = directoryDigest(join(destDir, "data"));
  const manifest: Manifest = {
    format: MANIFEST_FORMAT,
    formatVersion: MANIFEST_VERSION,
    createdAt: now.toISOString().replace(/\.\d{3}Z$/, "Z"),
    files,
    directoryDigest: digest,
    ledgerEntries: entries,
    ledgerHead: head,
    eventRecords: opened.eventRecords,
  };
  writeFileSync(join(destDir, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n", {
    flag: "wx",
  });
  return {
    ok: true,
    code: "OK",
    detail: `backed up ${String(entries)} evidence entries`,
    manifest,
  };
}

function readManifest(backupDir: string): Manifest | BackupResult {
  const path = join(backupDir, "manifest.json");
  if (!existsSync(path))
    return { ok: false, code: "MANIFEST_MISSING", detail: "no manifest.json in the backup" };
  const m = JSON.parse(readFileSync(path, "utf8")) as Manifest;
  if (m.format !== MANIFEST_FORMAT || m.formatVersion !== MANIFEST_VERSION) {
    return { ok: false, code: "UNSUPPORTED_MANIFEST", detail: "unsupported manifest format" };
  }
  return m;
}

/**
 * Verifies a backup: the directory digest must match, and a scratch copy must open with a
 * valid evidence chain whose head and length match the manifest. `expectedHead` is an
 * external anchor; without it, tail truncation is not detectable.
 */
export async function verifyBackup(
  backupDir: string,
  trust: readonly TrustRootInput[],
  expectedHead?: string,
): Promise<BackupResult> {
  const m = readManifest(backupDir);
  if ("ok" in m) return m;
  const dataDir = join(backupDir, "data");
  if (!existsSync(dataDir))
    return { ok: false, code: "DATA_MISSING", detail: "backup has no data directory" };
  const { digest, files } = directoryDigest(dataDir);
  if (digest !== m.directoryDigest || files !== m.files) {
    return {
      ok: false,
      code: "DIGEST_MISMATCH",
      detail: "backup files do not match the manifest",
      manifest: m,
    };
  }
  const scratch = mkdtempSync(join(tmpdir(), "dip-verify-"));
  try {
    cpSync(dataDir, scratch, { recursive: true });
    let opened: Awaited<ReturnType<typeof openAndCheck>>;
    try {
      opened = await openAndCheck(scratch, trust);
    } catch (err) {
      if (err instanceof DipError && err.code === "LEDGER_INVALID_ON_OPEN") {
        return {
          ok: false,
          code: "LEDGER_INVALID",
          detail: "evidence chain does not verify",
          manifest: m,
        };
      }
      throw err;
    }
    try {
      const report = opened.client.verifyLedger(m.ledgerHead);
      if (!report.valid)
        return {
          ok: false,
          code: "LEDGER_INVALID",
          detail: "evidence chain does not verify",
          manifest: m,
        };
      if (
        opened.client.ledgerSize() !== m.ledgerEntries ||
        opened.client.ledgerHead() !== m.ledgerHead
      ) {
        return {
          ok: false,
          code: "HEAD_MISMATCH",
          detail: "restored head or length differs from the manifest",
          manifest: m,
        };
      }
      if (expectedHead !== undefined && expectedHead !== m.ledgerHead) {
        return {
          ok: false,
          code: "ANCHOR_MISMATCH",
          detail: "manifest head differs from the expected external head",
          manifest: m,
        };
      }
      return {
        ok: true,
        code: "OK",
        detail: `verified ${String(m.ledgerEntries)} evidence entries`,
        manifest: m,
      };
    } finally {
      await opened.close();
    }
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

/** Restores a verified backup into an empty directory, then verifies the restored copy. */
export async function restoreBackup(
  backupDir: string,
  targetDir: string,
  trust: readonly TrustRootInput[],
): Promise<BackupResult> {
  const verified = await verifyBackup(backupDir, trust);
  if (!verified.ok) return verified;
  if (!isEmptyOrMissing(targetDir))
    return {
      ok: false,
      code: "TARGET_NOT_EMPTY",
      detail: "restore target must be empty or absent",
    };
  mkdirSync(targetDir, { recursive: true });
  cpSync(join(backupDir, "data"), targetDir, { recursive: true });
  let check: Awaited<ReturnType<typeof openAndCheck>>;
  try {
    check = await openAndCheck(targetDir, trust);
  } catch (err) {
    if (err instanceof DipError && err.code === "LEDGER_INVALID_ON_OPEN") {
      return { ok: false, code: "LEDGER_INVALID", detail: "restored copy does not verify" };
    }
    throw err;
  }
  try {
    if (!check.client.verifyLedger(check.client.ledgerHead()).valid) {
      return { ok: false, code: "LEDGER_INVALID", detail: "restored copy does not verify" };
    }
  } finally {
    await check.close();
  }
  return {
    ok: true,
    code: "OK",
    detail: "restored and verified",
    ...(verified.manifest ? { manifest: verified.manifest } : {}),
  };
}
