#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { runCli } from "./cli.js";

const result = await runCli(process.argv.slice(2), {
  readFile: (path) => readFileSync(path, "utf8"),
  fetch: globalThis.fetch,
  env: process.env,
});
if (result.stdout.length > 0) process.stdout.write(result.stdout);
if (result.stderr.length > 0) process.stderr.write(result.stderr);
process.exitCode = result.exitCode;
