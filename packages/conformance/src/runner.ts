import { canonicalize, digestWithDomain } from "@dip/crypto";
import { verifyBundle, type TrustRootInput } from "@dip/verifier";

/**
 * Language-neutral conformance runner. An implementation is any object with the
 * three functions below. A different implementation can run the same JSON fixtures.
 */
export interface Implementation {
  canonicalize(value: unknown): string;
  digest(domain: string, canonical: string): string;
  verifyBundle(
    bundle: unknown,
    trust: readonly TrustRootInput[],
  ): { verdict: string; checks: readonly { id: string; outcome: string }[] };
}

export interface CanonicalCase {
  readonly id: string;
  readonly input: unknown;
  readonly canonical?: string;
  readonly domain?: string;
  readonly sha256?: string;
  readonly expectError?: string;
}

export interface BundleCase {
  readonly id: string;
  readonly description: string;
  readonly bundle: unknown;
  readonly trust: readonly TrustRootInput[];
  readonly expected: { readonly verdict: string; readonly mustInclude?: readonly string[] };
}

export interface CaseResult {
  readonly id: string;
  readonly ok: boolean;
  readonly detail: string;
}

export const reference: Implementation = {
  canonicalize: (v) => canonicalize(v),
  digest: (domain, canonical) => digestWithDomain(domain, canonical),
  verifyBundle: (bundle, trust) => verifyBundle(bundle, trust),
};

export function runCanonicalCases(
  cases: readonly CanonicalCase[],
  impl: Implementation,
): CaseResult[] {
  return cases.map((c): CaseResult => {
    if (c.expectError !== undefined) {
      try {
        impl.canonicalize(c.input);
        return { id: c.id, ok: false, detail: `expected ${c.expectError}, input was accepted` };
      } catch (err) {
        const name = err instanceof Error ? err.name : "unknown";
        return { id: c.id, ok: name === c.expectError, detail: `rejected with ${name}` };
      }
    }
    const canonical = impl.canonicalize(c.input);
    if (c.canonical !== undefined && canonical !== c.canonical) {
      return { id: c.id, ok: false, detail: `canonical form differs: ${canonical}` };
    }
    if (c.domain !== undefined && c.sha256 !== undefined) {
      const digest = impl.digest(c.domain, canonical);
      if (digest !== c.sha256) return { id: c.id, ok: false, detail: `digest differs: ${digest}` };
    }
    return { id: c.id, ok: true, detail: "matches" };
  });
}

export function runBundleCases(cases: readonly BundleCase[], impl: Implementation): CaseResult[] {
  return cases.map((c): CaseResult => {
    let result: { verdict: string; checks: readonly { id: string; outcome: string }[] };
    try {
      result = impl.verifyBundle(c.bundle, c.trust);
    } catch (err) {
      return {
        id: c.id,
        ok: false,
        detail: `verifier threw: ${err instanceof Error ? err.message : "unknown"}`,
      };
    }
    if (result.verdict !== c.expected.verdict) {
      return {
        id: c.id,
        ok: false,
        detail: `verdict ${result.verdict}, expected ${c.expected.verdict}`,
      };
    }
    const failing = new Set(result.checks.filter((k) => k.outcome !== "PASS").map((k) => k.id));
    const missing = (c.expected.mustInclude ?? []).filter((id) => !failing.has(id));
    if (missing.length > 0)
      return { id: c.id, ok: false, detail: `expected non-passing checks: ${missing.join(", ")}` };
    return { id: c.id, ok: true, detail: `verdict ${result.verdict}` };
  });
}
