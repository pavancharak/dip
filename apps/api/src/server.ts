import { readFileSync } from "node:fs";
import { createApi } from "./app.js";
import { loadConfig, ConfigError } from "./config.js";
import { createHttpServer } from "./http.js";
import { DipClient } from "@dip/sdk";
import {
  PostgresEventLog,
  migrate,
  openDatabase,
  openPostgres,
  type SqlDatabase,
} from "@dip/storage";
import { resolveSigner, SignerError } from "./signers.js";

/**
 * Entry point. Reads DIP_CONFIG (default /run/secrets/dip-config.json).
 * Connectors are not configured by default, so execution refuses with
 * CONNECTOR_NOT_FOUND until connectors are wired in code.
 */
async function main(): Promise<void> {
  const configPath = process.env.DIP_CONFIG ?? "/run/secrets/dip-config.json";
  let config;
  try {
    config = loadConfig(JSON.parse(readFileSync(configPath, "utf8")) as unknown, (p) =>
      readFileSync(p, "utf8"),
    );
  } catch (err) {
    const code = err instanceof ConfigError ? err.code : "CONFIG_UNREADABLE";
    const message = err instanceof Error ? err.message : "unknown error";
    process.stderr.write(`dip-api: ${code}: ${message}\n`);
    process.exitCode = 1;
    return;
  }

  // PostgreSQL when configured; otherwise the file-backed database; otherwise memory only.
  let db: SqlDatabase | null = null;
  if (config.postgresUrl !== null) db = openPostgres(config.postgresUrl);
  else if (config.dataDir !== null) db = await openDatabase(config.dataDir);
  if (db !== null) await migrate(db);
  // Signers are resolved before any state is opened. A KMS key whose public key does not
  // match the pinned trust root stops startup here.
  let engine;
  let evidenceSigner;
  try {
    const signerOptions = { kmsRegion: config.kmsRegion };
    engine = await resolveSigner("engine", config.engine, config.trustRoots, signerOptions);
    evidenceSigner = await resolveSigner(
      "evidenceSigner",
      config.evidenceSigner,
      config.trustRoots,
      signerOptions,
    );
  } catch (err) {
    const code = err instanceof SignerError ? err.code : "SIGNER_UNAVAILABLE";
    const message = err instanceof Error ? err.message : "unknown error";
    process.stderr.write(`dip-api: ${code}: ${message}\n`);
    process.exitCode = 1;
    return;
  }
  const client = await DipClient.open({
    trustRoots: config.trustRoots,
    engine,
    evidenceSigner,
    connectors: new Map(),
    now: () => new Date(),
    maxDecisionAgeSeconds: config.maxDecisionAgeSeconds,
    executionTimeoutMs: config.executionTimeoutMs,
    ...(db === null ? {} : { eventLog: new PostgresEventLog(db) }),
  });
  const api = createApi({
    client,
    principals: config.principals,
    rateLimit: config.rateLimit,
    clockMs: () => Date.now(),
    onPersistenceFailure: (err) => {
      // A response is never sent for a change that was not written. Stop rather than
      // keep serving from state that the durable log no longer matches.
      const message = err instanceof Error ? err.message : "unknown error";
      process.stderr.write(`dip-api: persistence failed, stopping: ${message}\n`);
      process.exit(1);
    },
  });
  const server = createHttpServer((req) => api.handle(req));
  server.listen(config.port, () => {
    process.stdout.write(`dip-api listening on ${String(config.port)}\n`);
    if (config.postgresUrl !== null) {
      process.stdout.write("state is durable in PostgreSQL\n");
    } else if (config.dataDir === null) {
      process.stdout.write(
        "warning: state is held in memory; a restart discards authorities, approvals and evidence\n",
      );
    } else {
      process.stdout.write(`state is durable in ${config.dataDir}\n`);
    }
    process.stdout.write(
      "warning: no connectors are configured; execution refuses with CONNECTOR_NOT_FOUND\n",
    );
  });
  const shutdown = (): void => {
    server.close(() => {
      const done = db?.close ? db.close() : Promise.resolve();
      void done.finally(() => process.exit(0));
    });
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

main().catch((err: unknown) => {
  const message = err instanceof Error ? err.message : "unknown error";
  process.stderr.write(`dip-api: startup failed: ${message}\n`);
  process.exitCode = 1;
});
