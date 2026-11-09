import { readFileSync } from "node:fs";
import { createApi } from "./app.js";
import { loadConfig, ConfigError } from "./config.js";
import { createHttpServer } from "./http.js";
import { DipClient } from "@dip/sdk";

/**
 * Entry point. Reads DIP_CONFIG (default /run/secrets/dip-config.json).
 * Connectors are not configured by default, so execution refuses with
 * CONNECTOR_NOT_FOUND until connectors are wired in code.
 */
function main(): void {
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

  const client = new DipClient({
    trustRoots: config.trustRoots,
    engine: config.engine,
    evidenceSigner: config.evidenceSigner,
    connectors: new Map(),
    now: () => new Date(),
    maxDecisionAgeSeconds: config.maxDecisionAgeSeconds,
    executionTimeoutMs: config.executionTimeoutMs,
  });
  const api = createApi({
    client,
    principals: config.principals,
    rateLimit: config.rateLimit,
    clockMs: () => Date.now(),
  });
  const server = createHttpServer((req) => api.handle(req));
  server.listen(config.port, () => {
    process.stdout.write(`dip-api listening on ${String(config.port)}\n`);
    process.stdout.write(
      "warning: state is held in memory; a restart discards authorities, approvals and evidence\n",
    );
    process.stdout.write(
      "warning: no connectors are configured; execution refuses with CONNECTOR_NOT_FOUND\n",
    );
  });
  const shutdown = (): void => {
    server.close(() => process.exit(0));
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

main();
