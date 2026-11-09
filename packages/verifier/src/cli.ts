import { VerifierError, verifyBundle, type TrustRootInput } from "./verifier.js";

export interface CliResult {
  readonly exitCode: number;
  readonly stdout: string;
}

/**
 * Exit codes: 0 VALID, 1 INVALID, 2 INCOMPLETE or UNVERIFIABLE, 3 usage or input error.
 * `read` loads a file by path so the CLI can be tested without touching the disk.
 */
export function runCli(argv: readonly string[], read: (path: string) => string): CliResult {
  const bundleIdx = argv.indexOf("--bundle");
  const trustIdx = argv.indexOf("--trust");
  const bundlePath = bundleIdx >= 0 ? argv[bundleIdx + 1] : undefined;
  const trustPath = trustIdx >= 0 ? argv[trustIdx + 1] : undefined;
  if (bundlePath === undefined || trustPath === undefined) {
    return {
      exitCode: 3,
      stdout: JSON.stringify({ error: "usage: dip-verify --bundle <file> --trust <file>" }),
    };
  }
  try {
    const bundle: unknown = JSON.parse(read(bundlePath));
    const trust = JSON.parse(read(trustPath)) as TrustRootInput[];
    const result = verifyBundle(bundle, trust);
    const code = result.verdict === "VALID" ? 0 : result.verdict === "INVALID" ? 1 : 2;
    return { exitCode: code, stdout: JSON.stringify(result, null, 2) };
  } catch (err) {
    const message = err instanceof Error ? err.message : "unknown error";
    const code = err instanceof VerifierError ? err.code : "INPUT_ERROR";
    return { exitCode: 3, stdout: JSON.stringify({ error: code, message }) };
  }
}
