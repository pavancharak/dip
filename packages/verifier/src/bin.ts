#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { runCli } from "./cli.js";

const result = runCli(process.argv.slice(2), (path) => readFileSync(path, "utf8"));
process.stdout.write(result.stdout + "\n");
process.exitCode = result.exitCode;
