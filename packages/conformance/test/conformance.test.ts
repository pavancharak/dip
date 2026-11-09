import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  buildBundleCases,
  buildCanonicalCases,
  reference,
  runBundleCases,
  runCanonicalCases,
  suiteFiles,
  type BundleCase,
  type CanonicalCase,
  type Implementation,
} from "../src/index.js";

const root = fileURLToPath(new URL("../../../conformance/", import.meta.url));
const read = (p: string): string => readFileSync(root + p, "utf8");

const manifest = JSON.parse(read("manifest.json")) as { bundles: string[]; canonical: string };
const canonicalSuite = JSON.parse(read(manifest.canonical)) as { cases: CanonicalCase[] };
const bundleCases = manifest.bundles.map((p) => JSON.parse(read(p)) as BundleCase);

describe("conformance suite", () => {
  it("has the expected shape: valid and invalid canonical and bundle cases", () => {
    expect(canonicalSuite.cases.length).toBeGreaterThanOrEqual(6);
    const verdicts = new Set(bundleCases.map((c) => c.expected.verdict));
    expect([...verdicts].sort()).toEqual(["INCOMPLETE", "INVALID", "UNVERIFIABLE", "VALID"]);
  });

  it("the reference implementation passes every canonical case", () => {
    const results = runCanonicalCases(canonicalSuite.cases, reference);
    expect(results.filter((r) => !r.ok)).toEqual([]);
  });

  it("the reference implementation passes every bundle case", () => {
    const results = runBundleCases(bundleCases, reference);
    expect(results.filter((r) => !r.ok)).toEqual([]);
  });

  it("committed fixtures match a fresh, deterministic regeneration", async () => {
    const files = suiteFiles(await buildBundleCases(), buildCanonicalCases());
    for (const [path, content] of Object.entries(files)) {
      expect(read(path), path).toBe(content);
    }
  });

  it("a wrong implementation fails the suite (the runner is not a rubber stamp)", () => {
    const broken: Implementation = {
      canonicalize: (v) => reference.canonicalize(v),
      digest: (d, c) => reference.digest(d, c),
      verifyBundle: () => ({ verdict: "VALID", checks: [] }),
    };
    const results = runBundleCases(bundleCases, broken);
    expect(results.filter((r) => !r.ok).length).toBeGreaterThan(0);
  });

  it("an implementation that accepts a float fails the canonical reject case", () => {
    const lax: Implementation = {
      canonicalize: (v) => JSON.stringify(v),
      digest: (d, c) => reference.digest(d, c),
      verifyBundle: reference.verifyBundle,
    };
    const results = runCanonicalCases(canonicalSuite.cases, lax);
    expect(results.find((r) => r.id === "reject-float")?.ok).toBe(false);
  });
});
