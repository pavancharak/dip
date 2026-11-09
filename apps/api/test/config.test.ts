import { describe, expect, it } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { ConfigError, loadConfig } from "../src/index.js";

function pem(): string {
  return generateKeyPairSync("ed25519")
    .privateKey.export({ type: "pkcs8", format: "pem" })
    .toString();
}

const ISSUER_JWK = { kty: "OKP", crv: "Ed25519", x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" };
const KEY = "k".repeat(40);

function raw(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    trustRoots: [{ keyId: "issuer-key-1", jwk: ISSUER_JWK, status: "ACTIVE" }],
    engine: { keyId: "engine-1", privateKeyPath: "/run/secrets/engine.pem" },
    evidenceSigner: { keyId: "evidence-1", privateKeyPath: "/run/secrets/evidence.pem" },
    principals: [
      {
        name: "operator",
        tenantId: "tenant-1",
        scopes: [],
        apiKeyPath: "/run/secrets/operator.key",
      },
    ],
    ...overrides,
  };
}

function files(extra: Record<string, string> = {}): (p: string) => string {
  const store: Record<string, string> = {
    "/run/secrets/engine.pem": pem(),
    "/run/secrets/evidence.pem": pem(),
    "/run/secrets/operator.key": KEY,
    ...extra,
  };
  return (p) => {
    const v = store[p];
    if (v === undefined) throw new Error(`no such file ${p}`);
    return v;
  };
}

describe("KMS signer configuration", () => {
  it("accepts a KMS key ID with a region", () => {
    const c = loadConfig(
      raw({
        engine: { keyId: "engine-1", kmsKeyId: "alias/dip-engine" },
        kms: { region: "us-east-1" },
      }),
      files(),
    );
    expect(c.engine.kmsKeyId).toBe("alias/dip-engine");
    expect(c.engine.privateKey).toBeNull();
    expect(c.kmsRegion).toBe("us-east-1");
  });

  it("refuses a KMS key without a region", () => {
    expect(() =>
      loadConfig(raw({ engine: { keyId: "engine-1", kmsKeyId: "alias/dip-engine" } }), files()),
    ).toThrow("kms.region is required");
  });

  it("refuses a signer that names both a KMS key and a private key file", () => {
    expect(() =>
      loadConfig(
        raw({
          engine: {
            keyId: "engine-1",
            kmsKeyId: "alias/dip-engine",
            privateKeyPath: "/run/secrets/engine.pem",
          },
          kms: { region: "us-east-1" },
        }),
        files(),
      ),
    ).toThrow("not both");
  });
});

describe("storage configuration", () => {
  it("reads the PostgreSQL connection string from a secret file", () => {
    const c = loadConfig(
      raw({ storage: { postgresUrlPath: "/run/secrets/pg-url" } }),
      files({ "/run/secrets/pg-url": "postgres://dip:pw@db:5432/dip\n" }),
    );
    expect(c.postgresUrl).toBe("postgres://dip:pw@db:5432/dip");
    expect(c.dataDir).toBeNull();
  });

  it("refuses dataDir and postgresUrlPath together", () => {
    const bad = raw({
      storage: { dataDir: "/var/lib/dip", postgresUrlPath: "/run/secrets/pg-url" },
    });
    expect(() => loadConfig(bad, files({ "/run/secrets/pg-url": "postgres://x" }))).toThrow(
      "not both",
    );
  });

  it("refuses a secret file that is not a PostgreSQL URL, without echoing it", () => {
    const secret = "mysql-secret-value";
    const bad = raw({ storage: { postgresUrlPath: "/run/secrets/pg-url" } });
    let message = "";
    try {
      loadConfig(bad, files({ "/run/secrets/pg-url": secret }));
    } catch (err) {
      message = err instanceof Error ? err.message : "";
    }
    expect(message).toContain("postgres://");
    expect(message).not.toContain(secret);
  });
});

describe("server configuration (fail closed)", () => {
  it("loads a complete configuration with defaults", () => {
    const c = loadConfig(raw(), files());
    expect(c.port).toBe(3000);
    expect(c.principals.get(KEY)?.name).toBe("operator");
    expect(c.engine.keyId).toBe("engine-1");
  });

  it("refuses an empty trust root set", () => {
    expect(() => loadConfig(raw({ trustRoots: [] }), files())).toThrow("at least one trust root");
  });

  it("refuses a missing principal list", () => {
    expect(() => loadConfig(raw({ principals: [] }), files())).toThrow("at least one principal");
  });

  it("refuses a short API key", () => {
    expect(() => loadConfig(raw(), files({ "/run/secrets/operator.key": "short" }))).toThrow(
      ConfigError,
    );
  });

  it("refuses an unknown scope", () => {
    const bad = raw({
      principals: [
        { name: "x", tenantId: null, scopes: ["root"], apiKeyPath: "/run/secrets/operator.key" },
      ],
    });
    expect(() => loadConfig(bad, files())).toThrow("unknown scope");
  });

  it("refuses a non-Ed25519 signing key without echoing key material", () => {
    const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 })
      .privateKey.export({ type: "pkcs8", format: "pem" })
      .toString();
    try {
      loadConfig(raw(), files({ "/run/secrets/engine.pem": rsa }));
      expect.fail("should refuse");
    } catch (err) {
      expect(err).toBeInstanceOf(ConfigError);
      expect((err as Error).message).not.toContain("BEGIN");
    }
  });

  it("refuses duplicate API keys", () => {
    const dup = raw({
      principals: [
        { name: "a", tenantId: "tenant-1", scopes: [], apiKeyPath: "/run/secrets/operator.key" },
        { name: "b", tenantId: "tenant-2", scopes: [], apiKeyPath: "/run/secrets/operator.key" },
      ],
    });
    expect(() => loadConfig(dup, files())).toThrow("duplicates");
  });

  it("refuses a non-Ed25519 trust root", () => {
    const bad = raw({
      trustRoots: [{ keyId: "x", jwk: { kty: "RSA", n: "a", e: "b" }, status: "ACTIVE" }],
    });
    expect(() => loadConfig(bad, files())).toThrow("Ed25519 public key");
  });
});
