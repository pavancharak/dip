import { createPrivateKey, type KeyObject } from "node:crypto";
import type { TrustRoot } from "@dip/authority";
import type { Principal } from "./app.js";

/**
 * Loads server configuration. Fails closed: any missing or malformed setting is
 * an error, never a default that weakens security. Secret values never appear in
 * error messages.
 */
export class ConfigError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "ConfigError";
  }
}

/**
 * A signer is either a local key (development and tests) or a KMS key (production).
 * Exactly one of privateKey and kmsKeyId is set.
 */
export interface SignerSettings {
  readonly keyId: string;
  readonly privateKey: KeyObject | null;
  readonly kmsKeyId: string | null;
}

export interface ServerConfig {
  readonly port: number;
  readonly maxDecisionAgeSeconds: number;
  readonly executionTimeoutMs: number;
  readonly rateLimit: { readonly max: number; readonly windowMs: number };
  readonly trustRoots: readonly TrustRoot[];
  readonly engine: SignerSettings;
  readonly evidenceSigner: SignerSettings;
  /** AWS region for KMS-held signers, or null when no signer uses KMS. */
  readonly kmsRegion: string | null;
  readonly principals: ReadonlyMap<string, Principal>;
  /** Directory for the durable database, or null to run in memory only. */
  readonly dataDir: string | null;
  /** PostgreSQL connection string, read from a secret file. Null when not used. */
  readonly postgresUrl: string | null;
}

type Obj = Record<string, unknown>;

function obj(v: unknown, path: string): Obj {
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    throw new ConfigError("INVALID_CONFIG", `${path} must be an object`);
  }
  return v as Obj;
}

function int(v: unknown, path: string, min: number, max: number): number {
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < min || v > max) {
    throw new ConfigError(
      "INVALID_CONFIG",
      `${path} must be an integer in [${String(min)}, ${String(max)}]`,
    );
  }
  return v;
}

function text(v: unknown, path: string): string {
  if (typeof v !== "string" || v.length === 0) {
    throw new ConfigError("INVALID_CONFIG", `${path} must be a non-empty string`);
  }
  return v;
}

const SCOPES = new Set(["admin", "approver"]);
const MIN_API_KEY_LENGTH = 32;

/**
 * `raw` is the parsed JSON config. `readFile` loads secret material by path, so the
 * loader stays testable without a filesystem.
 */
export function loadConfig(raw: unknown, readFile: (path: string) => string): ServerConfig {
  const c = obj(raw, "config");
  const trustRoots = (Array.isArray(c.trustRoots) ? c.trustRoots : []).map((r, i): TrustRoot => {
    const o = obj(r, `trustRoots[${String(i)}]`);
    const status = o.status;
    if (status !== "ACTIVE" && status !== "REVOKED")
      throw new ConfigError("INVALID_CONFIG", `trustRoots[${String(i)}].status invalid`);
    const jwk = obj(o.jwk, `trustRoots[${String(i)}].jwk`);
    if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") {
      throw new ConfigError(
        "INVALID_CONFIG",
        `trustRoots[${String(i)}].jwk must be an Ed25519 public key`,
      );
    }
    return {
      keyId: text(o.keyId, `trustRoots[${String(i)}].keyId`),
      jwk: { kty: "OKP", crv: "Ed25519", x: jwk.x },
      status,
    };
  });
  if (trustRoots.length === 0)
    throw new ConfigError("INVALID_CONFIG", "at least one trust root is required");

  const loadKey = (section: unknown, path: string): SignerSettings => {
    const o = obj(section, path);
    if (o.kmsKeyId !== undefined) {
      if (o.privateKeyPath !== undefined) {
        throw new ConfigError(
          "INVALID_CONFIG",
          `${path}: set kmsKeyId or privateKeyPath, not both`,
        );
      }
      return {
        keyId: text(o.keyId, `${path}.keyId`),
        privateKey: null,
        kmsKeyId: text(o.kmsKeyId, `${path}.kmsKeyId`),
      };
    }
    const pem = readFile(text(o.privateKeyPath, `${path}.privateKeyPath`));
    let key: KeyObject;
    try {
      key = createPrivateKey({ key: pem, format: "pem" });
    } catch {
      throw new ConfigError("INVALID_KEY", `${path}: key material could not be parsed`);
    }
    if (key.asymmetricKeyType !== "ed25519")
      throw new ConfigError("INVALID_KEY", `${path}: key must be Ed25519`);
    return { keyId: text(o.keyId, `${path}.keyId`), privateKey: key, kmsKeyId: null };
  };

  const principals = new Map<string, Principal>();
  const list = Array.isArray(c.principals) ? c.principals : [];
  if (list.length === 0)
    throw new ConfigError("INVALID_CONFIG", "at least one principal is required");
  list.forEach((p, i) => {
    const o = obj(p, `principals[${String(i)}]`);
    const scopes = Array.isArray(o.scopes) ? o.scopes : [];
    for (const s of scopes) {
      if (typeof s !== "string" || !SCOPES.has(s))
        throw new ConfigError("INVALID_CONFIG", `principals[${String(i)}] has an unknown scope`);
    }
    const tenantId =
      o.tenantId === null ? null : text(o.tenantId, `principals[${String(i)}].tenantId`);
    const key = readFile(text(o.apiKeyPath, `principals[${String(i)}].apiKeyPath`)).trim();
    if (key.length < MIN_API_KEY_LENGTH)
      throw new ConfigError("WEAK_API_KEY", `principals[${String(i)}] API key is too short`);
    if (principals.has(key))
      throw new ConfigError(
        "INVALID_CONFIG",
        `principals[${String(i)}] duplicates another API key`,
      );
    principals.set(key, {
      name: text(o.name, `principals[${String(i)}].name`),
      tenantId,
      scopes: scopes as string[],
    });
  });

  const rate =
    c.rateLimit === undefined ? { max: 600, windowMs: 60_000 } : obj(c.rateLimit, "rateLimit");
  const storage = c.storage === undefined ? null : obj(c.storage, "storage");
  const s = storage ?? {};
  if (s.dataDir !== undefined && s.postgresUrlPath !== undefined) {
    throw new ConfigError("INVALID_CONFIG", "storage: set dataDir or postgresUrlPath, not both");
  }
  let postgresUrl: string | null = null;
  if (s.postgresUrlPath !== undefined) {
    const url = readFile(text(s.postgresUrlPath, "storage.postgresUrlPath")).trim();
    // The message names the setting only. It never echoes the connection string.
    if (!/^postgres(ql)?:\/\//.test(url)) {
      throw new ConfigError(
        "INVALID_CONFIG",
        "storage.postgresUrlPath must contain a postgres:// connection string",
      );
    }
    postgresUrl = url;
  }
  const engineSigner = loadKey(c.engine, "engine");
  const evidenceSignerSettings = loadKey(c.evidenceSigner, "evidenceSigner");
  const kmsSection = c.kms === undefined ? null : obj(c.kms, "kms");
  const kmsRegion = kmsSection === null ? null : text(kmsSection.region, "kms.region");
  if (
    (engineSigner.kmsKeyId !== null || evidenceSignerSettings.kmsKeyId !== null) &&
    kmsRegion === null
  ) {
    throw new ConfigError("INVALID_CONFIG", "kms.region is required when a signer uses kmsKeyId");
  }

  return {
    dataDir: s.dataDir === undefined ? null : text(s.dataDir, "storage.dataDir"),
    postgresUrl,
    port: c.port === undefined ? 3000 : int(c.port, "port", 1, 65535),
    maxDecisionAgeSeconds:
      c.maxDecisionAgeSeconds === undefined
        ? 300
        : int(c.maxDecisionAgeSeconds, "maxDecisionAgeSeconds", 1, 3600),
    executionTimeoutMs:
      c.executionTimeoutMs === undefined
        ? 5000
        : int(c.executionTimeoutMs, "executionTimeoutMs", 100, 60000),
    rateLimit: {
      max: int(rate.max ?? 600, "rateLimit.max", 1, 100_000),
      windowMs: int(rate.windowMs ?? 60_000, "rateLimit.windowMs", 1000, 3_600_000),
    },
    trustRoots,
    engine: engineSigner,
    evidenceSigner: evidenceSignerSettings,
    kmsRegion,
    principals,
  };
}
