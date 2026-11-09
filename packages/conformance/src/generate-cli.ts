import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { buildBundleCases, buildCanonicalCases, suiteFiles } from "./generate.js";

const out = process.argv[2];
if (out === undefined) {
  process.stderr.write("usage: generate-cli <output-dir>\n");
  process.exitCode = 3;
} else {
  const bundles = await buildBundleCases();
  const files = suiteFiles(bundles, buildCanonicalCases());
  for (const [path, content] of Object.entries(files)) {
    const full = join(out, path);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, content);
  }
  process.stdout.write(`wrote ${String(Object.keys(files).length)} files to ${out}\n`);
}
