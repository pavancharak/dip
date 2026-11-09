import { createPrivateKey, type KeyObject } from "node:crypto";
import { DipError, parseAuthorityBody, signAuthority } from "@dip/authority";
import { normalizeRequest } from "@dip/authorization";
import {
  reference,
  runBundleCases,
  runCanonicalCases,
  type BundleCase,
  type CanonicalCase,
} from "@dip/conformance";
import { verifyBundle, type TrustRootInput, type VerificationResult } from "@dip/verifier";
import { createBackup, restoreBackup, verifyBackup, type BackupResult } from "./backup.js";

/**
 * The `dip` command. Exit codes:
 *   0  success, ALLOW, VALID, executed, all conformance cases pass
 *   1  DENY, INVALID, refused or failed execution, a conformance failure
 *   2  INCOMPLETE or UNVERIFIABLE
 *   3  usage error or rejected input
 *   4  server unreachable or failed (5xx)
 */
export const EXIT = { OK: 0, NEGATIVE: 1, UNDETERMINED: 2, USAGE: 3, SERVER: 4 } as const;

export interface CliIo {
  readFile(path: string): string;
  fetch: typeof fetch;
  env: Readonly<Record<string, string | undefined>>;
}

export interface CliResult {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
}

interface Parsed {
  readonly positionals: string[];
  readonly flags: Map<string, string | true>;
}

function parse(args: readonly string[]): Parsed {
  const positionals: string[] = [];
  const flags = new Map<string, string | true>();
  for (let i = 0; i < args.length; i++) {
    const a = args[i] ?? "";
    if (a.startsWith("--")) {
      const name = a.slice(2);
      const next = args[i + 1];
      if (next !== undefined && !next.startsWith("--")) {
        flags.set(name, next);
        i++;
      } else {
        flags.set(name, true);
      }
    } else {
      positionals.push(a);
    }
  }
  return { positionals, flags };
}

class UsageError extends Error {}

function fail(exitCode: number, message: string, json: boolean): CliResult {
  const stderr = json ? JSON.stringify({ error: message }) + "\n" : `dip: ${message}\n`;
  return { exitCode, stdout: "", stderr };
}

function out(value: unknown, json: boolean, human: () => string): CliResult {
  return {
    exitCode: EXIT.OK,
    stdout: json ? JSON.stringify(value, null, 2) + "\n" : human(),
    stderr: "",
  };
}

function loadJson(io: CliIo, path: string | undefined): unknown {
  if (path === undefined) throw new UsageError("a file argument is required");
  try {
    return JSON.parse(io.readFile(path)) as unknown;
  } catch (err) {
    if (err instanceof UsageError) throw err;
    throw new UsageError(`cannot read JSON from ${path}`);
  }
}

function loadKey(io: CliIo, path: string | undefined): KeyObject {
  if (path === undefined) throw new UsageError("--key <pem file> is required");
  try {
    const key = createPrivateKey({ key: io.readFile(path), format: "pem" });
    if (key.asymmetricKeyType !== "ed25519") throw new UsageError("signing key must be Ed25519");
    return key;
  } catch (err) {
    if (err instanceof UsageError) throw err;
    throw new UsageError("signing key could not be read");
  }
}

interface Api {
  readonly base: string;
  readonly key: string;
  readonly io: CliIo;
}

function apiOf(io: CliIo, flags: Map<string, string | true>): Api {
  const base = typeof flags.get("url") === "string" ? (flags.get("url") as string) : io.env.DIP_URL;
  const key =
    typeof flags.get("api-key") === "string"
      ? (flags.get("api-key") as string)
      : io.env.DIP_API_KEY;
  if (base === undefined) throw new UsageError("--url or DIP_URL is required");
  if (key === undefined) throw new UsageError("--api-key or DIP_API_KEY is required");
  return { base: base.replace(/\/$/, ""), key, io };
}

async function call(
  api: Api,
  method: string,
  path: string,
  body?: unknown,
): Promise<{ status: number; body: unknown }> {
  let res: Response;
  try {
    res = await api.io.fetch(`${api.base}${path}`, {
      method,
      headers: {
        authorization: `Bearer ${api.key}`,
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  } catch {
    throw new ServerError("server is unreachable");
  }
  const text = await res.text();
  let parsed: unknown = text;
  try {
    parsed = text.length === 0 ? null : (JSON.parse(text) as unknown);
  } catch {
    parsed = text;
  }
  if (res.status >= 500) throw new ServerError(`server error ${String(res.status)}`);
  return { status: res.status, body: parsed };
}

class ServerError extends Error {}

function reasonsOf(body: unknown): string {
  const b = body as { error?: string; message?: string };
  return b?.error ?? b?.message ?? "request rejected";
}

/** Runs one command. Never throws: every outcome is an exit code and text. */
export async function runCli(argv: readonly string[], io: CliIo): Promise<CliResult> {
  const { positionals, flags } = parse(argv);
  const json = flags.has("json");
  const [group, sub] = positionals;
  try {
    if (group === undefined || group === "help") {
      return { exitCode: EXIT.OK, stdout: USAGE, stderr: "" };
    }
    switch (group) {
      case "authority":
        return await authority(sub, positionals.slice(2), flags, io, json);
      case "request":
        if (sub !== "normalize") throw new UsageError("usage: dip request normalize <file>");
        return out(
          normalizeRequest(loadJson(io, positionals[2])),
          json,
          () => JSON.stringify(normalizeRequest(loadJson(io, positionals[2])), null, 2) + "\n",
        );
      case "authorize": {
        const api = apiOf(io, flags);
        const res = await call(api, "POST", "/v1/authorize", loadJson(io, sub));
        if (res.status >= 400) return fail(EXIT.USAGE, reasonsOf(res.body), json);
        const r = res.body as { result: string; reasonCodes: string[] };
        const exitCode = r.result === "ALLOW" ? EXIT.OK : EXIT.NEGATIVE;
        return {
          exitCode,
          stdout: json
            ? JSON.stringify(res.body, null, 2) + "\n"
            : `result: ${r.result}\nreasons: ${r.reasonCodes.join(", ") || "none"}\n`,
          stderr: "",
        };
      }
      case "approval":
        return await approval(sub, positionals.slice(2), flags, io, json);
      case "execute": {
        const api = apiOf(io, flags);
        const res = await call(api, "POST", "/v1/execute", loadJson(io, sub));
        if (res.status >= 400) return fail(EXIT.USAGE, reasonsOf(res.body), json);
        const a = (
          res.body as {
            attempt: { state: string; reasonCode: string | null; externalRef: string | null };
          }
        ).attempt;
        const exitCode =
          a.state === "SUCCEEDED" || a.state === "DUPLICATE" ? EXIT.OK : EXIT.NEGATIVE;
        return {
          exitCode,
          stdout: json
            ? JSON.stringify(res.body, null, 2) + "\n"
            : `state: ${a.state}\nreason: ${a.reasonCode ?? "none"}\nexternal reference: ${a.externalRef ?? "none"}\n`,
          stderr: "",
        };
      }
      case "evidence": {
        if (sub !== "inspect" || positionals[2] === undefined)
          throw new UsageError("usage: dip evidence inspect <id>");
        const res = await call(
          apiOf(io, flags),
          "GET",
          `/v1/evidence/${encodeURIComponent(positionals[2])}`,
        );
        if (res.status >= 400)
          return fail(res.status === 404 ? EXIT.NEGATIVE : EXIT.USAGE, reasonsOf(res.body), json);
        return out(res.body, json, () => JSON.stringify(res.body, null, 2) + "\n");
      }
      case "verify":
        return verify(sub, flags, io, json);
      case "ledger":
        return await ledger(sub, flags, io, json);
      case "conformance":
        return conformance(sub, positionals[2], io, json);
      case "backup":
        return await backup(sub, positionals.slice(2), flags, io, json);
      default:
        throw new UsageError(`unknown command: ${group}`);
    }
  } catch (err) {
    if (err instanceof UsageError) return fail(EXIT.USAGE, err.message, json);
    if (err instanceof DipError) return fail(EXIT.USAGE, `${err.code}: ${err.message}`, json);
    if (err instanceof ServerError) return fail(EXIT.SERVER, err.message, json);
    return fail(EXIT.SERVER, "unexpected failure", json);
  }
}

async function authority(
  sub: string | undefined,
  rest: string[],
  flags: Map<string, string | true>,
  io: CliIo,
  json: boolean,
): Promise<CliResult> {
  if (sub === "create") {
    const body = parseAuthorityBody(loadJson(io, rest[0]));
    return out(body, json, () => JSON.stringify(body, null, 2) + "\n");
  }
  if (sub === "sign") {
    const body = parseAuthorityBody(loadJson(io, rest[0]));
    const signed = signAuthority(
      body,
      loadKey(io, typeof flags.get("key") === "string" ? (flags.get("key") as string) : undefined),
    );
    return out(signed, json, () => JSON.stringify(signed, null, 2) + "\n");
  }
  if (sub === "inspect") {
    const id = rest[0];
    if (id === undefined) throw new UsageError("usage: dip authority inspect <id> [--version N]");
    const version =
      typeof flags.get("version") === "string" ? (flags.get("version") as string) : "1";
    const res = await call(
      apiOf(io, flags),
      "GET",
      `/v1/authorities/${encodeURIComponent(id)}?version=${encodeURIComponent(version)}`,
    );
    if (res.status >= 400)
      return fail(res.status === 404 ? EXIT.NEGATIVE : EXIT.USAGE, reasonsOf(res.body), json);
    return out(res.body, json, () => JSON.stringify(res.body, null, 2) + "\n");
  }
  if (sub === "revoke") {
    const rev = loadJson(io, rest[0]) as { body?: { authorityId?: string } };
    const id = rev.body?.authorityId;
    if (id === undefined) throw new UsageError("revocation file must name an authority");
    const res = await call(
      apiOf(io, flags),
      "POST",
      `/v1/authorities/${encodeURIComponent(id)}/revoke`,
      rev,
    );
    if (res.status >= 400) return fail(EXIT.USAGE, reasonsOf(res.body), json);
    return out(res.body, json, () => "revoked\n");
  }
  throw new UsageError("usage: dip authority create|sign|inspect|revoke");
}

async function approval(
  sub: string | undefined,
  rest: string[],
  flags: Map<string, string | true>,
  io: CliIo,
  json: boolean,
): Promise<CliResult> {
  const api = apiOf(io, flags);
  if (sub === "create") {
    const res = await call(api, "POST", "/v1/approvals", loadJson(io, rest[0]));
    if (res.status >= 400) return fail(EXIT.USAGE, reasonsOf(res.body), json);
    return out(res.body, json, () => JSON.stringify(res.body, null, 2) + "\n");
  }
  if (sub === "approve" || sub === "reject") {
    const signed = loadJson(io, rest[0]) as { body?: { approvalId?: string } };
    const id = signed.body?.approvalId;
    if (id === undefined) throw new UsageError("decision file must name an approval");
    const res = await call(api, "POST", `/v1/approvals/${encodeURIComponent(id)}/${sub}`, signed);
    if (res.status >= 400) return fail(EXIT.USAGE, reasonsOf(res.body), json);
    const state = (res.body as { state: string }).state;
    return out(res.body, json, () => `state: ${state}\n`);
  }
  if (sub === "inspect") {
    const id = rest[0];
    if (id === undefined) throw new UsageError("usage: dip approval inspect <id>");
    const res = await call(api, "GET", `/v1/approvals/${encodeURIComponent(id)}`);
    if (res.status >= 400)
      return fail(res.status === 404 ? EXIT.NEGATIVE : EXIT.USAGE, reasonsOf(res.body), json);
    return out(res.body, json, () => `state: ${(res.body as { state: string }).state}\n`);
  }
  throw new UsageError("usage: dip approval create|approve|reject|inspect");
}

function verify(
  bundlePath: string | undefined,
  flags: Map<string, string | true>,
  io: CliIo,
  json: boolean,
): CliResult {
  const trustPath =
    typeof flags.get("trust") === "string" ? (flags.get("trust") as string) : undefined;
  if (bundlePath === undefined || trustPath === undefined)
    throw new UsageError("usage: dip verify <bundle> --trust <file>");
  const bundle = loadJson(io, bundlePath);
  const trust = loadJson(io, trustPath) as TrustRootInput[];
  const result: VerificationResult = verifyBundle(bundle, trust);
  const exitCode =
    result.verdict === "VALID"
      ? EXIT.OK
      : result.verdict === "INVALID"
        ? EXIT.NEGATIVE
        : EXIT.UNDETERMINED;
  return {
    exitCode,
    stdout: json
      ? JSON.stringify(result, null, 2) + "\n"
      : `verdict: ${result.verdict}\nentries: ${String(result.entries)}\n`,
    stderr: "",
  };
}

async function ledger(
  sub: string | undefined,
  flags: Map<string, string | true>,
  io: CliIo,
  json: boolean,
): Promise<CliResult> {
  const api = apiOf(io, flags);
  if (sub === "inspect") {
    const offset = typeof flags.get("offset") === "string" ? (flags.get("offset") as string) : "0";
    const limit = typeof flags.get("limit") === "string" ? (flags.get("limit") as string) : "20";
    const res = await call(api, "GET", `/v1/ledger?offset=${offset}&limit=${limit}`);
    if (res.status >= 400)
      return fail(res.status === 403 ? EXIT.NEGATIVE : EXIT.USAGE, reasonsOf(res.body), json);
    return out(res.body, json, () => JSON.stringify(res.body, null, 2) + "\n");
  }
  if (sub === "verify") {
    const head = typeof flags.get("head") === "string" ? (flags.get("head") as string) : null;
    const res = await call(api, "POST", "/v1/ledger/verify", { expectedHead: head });
    if (res.status >= 400)
      return fail(res.status === 403 ? EXIT.NEGATIVE : EXIT.USAGE, reasonsOf(res.body), json);
    const valid = (res.body as { valid: boolean }).valid;
    return {
      exitCode: valid ? EXIT.OK : EXIT.NEGATIVE,
      stdout: json ? JSON.stringify(res.body, null, 2) + "\n" : `valid: ${String(valid)}\n`,
      stderr: "",
    };
  }
  throw new UsageError("usage: dip ledger inspect|verify");
}

function conformance(
  sub: string | undefined,
  dir: string | undefined,
  io: CliIo,
  json: boolean,
): CliResult {
  if (sub !== "run" || dir === undefined)
    throw new UsageError("usage: dip conformance run <suite-dir>");
  const manifest = JSON.parse(io.readFile(`${dir}/manifest.json`)) as {
    canonical: string;
    bundles: string[];
  };
  const canonical = (
    JSON.parse(io.readFile(`${dir}/${manifest.canonical}`)) as { cases: CanonicalCase[] }
  ).cases;
  const bundles = manifest.bundles.map((p) => JSON.parse(io.readFile(`${dir}/${p}`)) as BundleCase);
  const results = [
    ...runCanonicalCases(canonical, reference),
    ...runBundleCases(bundles, reference),
  ];
  const failed = results.filter((r) => !r.ok);
  const summary = {
    total: results.length,
    passed: results.length - failed.length,
    failed: failed.map((f) => ({ id: f.id, detail: f.detail })),
  };
  return {
    exitCode: failed.length === 0 ? EXIT.OK : EXIT.NEGATIVE,
    stdout: json
      ? JSON.stringify(summary, null, 2) + "\n"
      : `${String(summary.passed)}/${String(summary.total)} cases passed\n${failed.map((f) => `FAIL ${f.id}: ${f.detail}\n`).join("")}`,
    stderr: "",
  };
}

async function backup(
  sub: string | undefined,
  rest: string[],
  flags: Map<string, string | true>,
  io: CliIo,
  json: boolean,
): Promise<CliResult> {
  const trustPath =
    typeof flags.get("trust") === "string" ? (flags.get("trust") as string) : undefined;
  if (trustPath === undefined)
    throw new UsageError("--trust <file> is required for backup commands");
  const trust = loadJson(io, trustPath) as TrustRootInput[];
  let result: BackupResult;
  if (sub === "create" && rest[0] !== undefined && rest[1] !== undefined) {
    result = await createBackup(rest[0], rest[1], trust, new Date());
  } else if (sub === "verify" && rest[0] !== undefined) {
    const head = typeof flags.get("head") === "string" ? (flags.get("head") as string) : undefined;
    result = await verifyBackup(rest[0], trust, head);
  } else if (sub === "restore" && rest[0] !== undefined && rest[1] !== undefined) {
    result = await restoreBackup(rest[0], rest[1], trust);
  } else {
    throw new UsageError(
      "usage: dip backup create <data-dir> <dest> | verify <backup> [--head H] | restore <backup> <target>  (all need --trust)",
    );
  }
  const exitCode = result.ok
    ? EXIT.OK
    : [
          "DATA_DIR_MISSING",
          "DESTINATION_NOT_EMPTY",
          "TARGET_NOT_EMPTY",
          "MANIFEST_MISSING",
          "UNSUPPORTED_MANIFEST",
          "DATA_MISSING",
        ].includes(result.code)
      ? EXIT.USAGE
      : EXIT.NEGATIVE;
  const body = {
    code: result.code,
    detail: result.detail,
    ...(result.manifest ? { manifest: result.manifest } : {}),
  };
  return {
    exitCode,
    stdout: json
      ? JSON.stringify(body, null, 2) + "\n"
      : `${result.ok ? "ok" : "failed"}: ${result.detail}\n`,
    stderr: "",
  };
}

const USAGE = `dip — command-line client for DIP

  dip authority create <file>                 validate a declaration
  dip authority sign <file> --key <pem>       sign a declaration (Ed25519)
  dip authority inspect <id> [--version N]    read a published authority
  dip authority revoke <signed-revocation>
  dip request normalize <file>                canonicalize a request
  dip authorize <request> [--json]            ALLOW (exit 0) or DENY (exit 1)
  dip approval create|approve|reject|inspect
  dip execute <{request,decision}>            run through the protected boundary
  dip evidence inspect <id>
  dip verify <bundle> --trust <file>          independent verification
  dip ledger inspect [--offset N --limit N]
  dip ledger verify [--head H]
  dip conformance run <suite-dir>
  dip backup create <data-dir> <dest> --trust <file>    (stop the server first)
  dip backup verify <backup> [--head H] --trust <file>
  dip backup restore <backup> <target> --trust <file>

Global: --url <base> (or DIP_URL), --api-key <key> (or DIP_API_KEY), --json

Exit codes: 0 ok/ALLOW/VALID, 1 DENY/INVALID/refused, 2 INCOMPLETE/UNVERIFIABLE,
3 usage or input error, 4 server unreachable or failed.
`;

export type { CliIo as CliEnvironment };
