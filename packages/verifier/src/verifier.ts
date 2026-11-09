import {
  canonicalize,
  digestWithDomain,
  importEd25519PublicJwk,
  verifyWithDomain,
  type Ed25519PublicJwk,
} from "@dip/crypto";
import type { KeyObject } from "node:crypto";

/**
 * Independent DIP evidence verifier.
 *
 * Depends only on @dip/crypto. It does not import the authorization engine,
 * ledger, execution boundary or authority registry. It re-derives digests,
 * re-checks signatures and replays approval transitions from the bundle alone.
 * Trust roots are supplied by the caller and are never read from the bundle.
 *
 * It confirms that the recorded decision is authentic and bound to the request.
 * It does not re-evaluate policy.
 */
export const BUNDLE_FORMAT = "dip-evidence-bundle";
export const BUNDLE_FORMAT_VERSION = 1;
export const PROTOCOL_VERSION = "1.0";

const GENESIS = "0".repeat(64);
const DIGEST = /^[0-9a-f]{64}$/;
const ID = /^[A-Za-z0-9._:-]{1,128}$/;
const TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const MAX_VERSION = 1_000_000_000;

const DOMAIN = {
  evidence: "DIP-EVIDENCE-V1",
  ledger: "DIP-LEDGER-ENTRY-V1",
  request: "DIP-REQUEST-V1",
  decision: "DIP-DECISION-V1",
  authority: "DIP-AUTHORITY-V1",
  approval: "DIP-APPROVAL-DECISION-V1",
} as const;

/** Thrown only when the verifier cannot run at all. Evidence problems are reported as checks. */
export class VerifierError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "VerifierError";
  }
}

export interface TrustRootInput {
  readonly keyId: string;
  readonly jwk: Ed25519PublicJwk;
  readonly status: "ACTIVE" | "REVOKED";
}

export type Outcome = "PASS" | "FAIL" | "UNVERIFIABLE" | "INCOMPLETE";
export type Verdict = "VALID" | "INVALID" | "INCOMPLETE" | "UNVERIFIABLE";

export interface Check {
  readonly entry: number | null;
  readonly id: string;
  readonly outcome: Outcome;
  readonly detail: string;
}

export interface VerificationResult {
  readonly verdict: Verdict;
  readonly entries: number;
  readonly head: string;
  readonly checks: readonly Check[];
}

type Obj = Record<string, unknown>;

class Malformed extends Error {}

function isObj(v: unknown): v is Obj {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function obj(v: unknown, path: string): Obj {
  if (!isObj(v)) throw new Malformed(`${path} must be an object`);
  return v;
}

function exact(o: Obj, keys: readonly string[], path: string): void {
  for (const k of Object.keys(o))
    if (!keys.includes(k)) throw new Malformed(`${path}.${k} not allowed`);
  for (const k of keys) if (!Object.hasOwn(o, k)) throw new Malformed(`${path}.${k} missing`);
}

function str(v: unknown, path: string, pattern: RegExp = ID): string {
  if (typeof v !== "string" || !pattern.test(v)) throw new Malformed(`${path} is invalid`);
  return v;
}

function digest(v: unknown, path: string): string {
  return str(v, path, DIGEST);
}

function time(v: unknown, path: string): string {
  if (typeof v !== "string" || !TIME.test(v) || Number.isNaN(Date.parse(v)))
    throw new Malformed(`${path} is not a UTC time`);
  return v;
}

function int(v: unknown, path: string, min: number, max: number): number {
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < min || v > max)
    throw new Malformed(`${path} is out of range`);
  return v;
}

function strings(v: unknown, path: string): string[] {
  if (!Array.isArray(v) || v.some((x) => typeof x !== "string"))
    throw new Malformed(`${path} must be strings`);
  return v as string[];
}

function ref(v: unknown, path: string): { authorityId: string; version: number } {
  const o = obj(v, path);
  exact(o, ["authorityId", "version"], path);
  return {
    authorityId: str(o.authorityId, `${path}.authorityId`),
    version: int(o.version, `${path}.version`, 1, MAX_VERSION),
  };
}

function policy(v: unknown, path: string): { policyId: string; version: number } {
  const o = obj(v, path);
  exact(o, ["policyId", "version"], path);
  return {
    policyId: str(o.policyId, `${path}.policyId`),
    version: int(o.version, `${path}.version`, 1, MAX_VERSION),
  };
}

interface Evidence {
  readonly body: {
    readonly evidenceId: string;
    readonly sequence: number;
    readonly previousDigest: string;
    readonly transactionId: string;
    readonly protocolVersion: string;
    readonly recordedAt: string;
    readonly request: { requestId: string; requestDigest: string; idempotencyKey: string };
    readonly authorization: {
      decisionId: string;
      result: "ALLOW" | "DENY";
      reasonCodes: string[];
      authorityRef: { authorityId: string; version: number };
      policyRef: { policyId: string; version: number };
      evaluatedAt: string;
      decisionSigningKeyId: string;
    };
    readonly approvalRef: string | null;
    readonly execution: {
      state: string;
      connectorId: string | null;
      reasonCode: string | null;
      externalRef: string | null;
      attemptedAt: string;
    } | null;
    readonly signingKeyId: string;
    readonly signatureAlgorithm: string;
  };
  readonly signature: string;
}

function parseEvidence(v: unknown): Evidence {
  const s = obj(v, "entry");
  exact(s, ["body", "signature"], "entry");
  const o = obj(s.body, "entry.body");
  exact(
    o,
    [
      "evidenceId",
      "sequence",
      "previousDigest",
      "transactionId",
      "protocolVersion",
      "recordedAt",
      "request",
      "authorization",
      "approvalRef",
      "execution",
      "signingKeyId",
      "signatureAlgorithm",
    ],
    "entry.body",
  );
  const r = obj(o.request, "request");
  exact(r, ["requestId", "requestDigest", "idempotencyKey"], "request");
  const a = obj(o.authorization, "authorization");
  exact(
    a,
    [
      "decisionId",
      "result",
      "reasonCodes",
      "authorityRef",
      "policyRef",
      "evaluatedAt",
      "decisionSigningKeyId",
    ],
    "authorization",
  );
  if (a.result !== "ALLOW" && a.result !== "DENY")
    throw new Malformed("authorization.result invalid");
  let execution: Evidence["body"]["execution"] = null;
  if (o.execution !== null) {
    const e = obj(o.execution, "execution");
    exact(e, ["state", "connectorId", "reasonCode", "externalRef", "attemptedAt"], "execution");
    execution = {
      state: str(e.state, "execution.state", /^[A-Z_]{1,32}$/),
      connectorId: e.connectorId === null ? null : str(e.connectorId, "execution.connectorId"),
      reasonCode:
        e.reasonCode === null ? null : str(e.reasonCode, "execution.reasonCode", /^[A-Z_]{1,64}$/),
      externalRef:
        e.externalRef === null ? null : str(e.externalRef, "execution.externalRef", /^.{1,256}$/),
      attemptedAt: time(e.attemptedAt, "execution.attemptedAt"),
    };
  }
  return {
    body: {
      evidenceId: str(o.evidenceId, "evidenceId"),
      sequence: int(o.sequence, "sequence", 1, Number.MAX_SAFE_INTEGER),
      previousDigest: digest(o.previousDigest, "previousDigest"),
      transactionId: str(o.transactionId, "transactionId"),
      protocolVersion: str(o.protocolVersion, "protocolVersion", /^[0-9.]{1,16}$/),
      recordedAt: time(o.recordedAt, "recordedAt"),
      request: {
        requestId: str(r.requestId, "request.requestId"),
        requestDigest: digest(r.requestDigest, "request.requestDigest"),
        idempotencyKey: str(r.idempotencyKey, "request.idempotencyKey"),
      },
      authorization: {
        decisionId: digest(a.decisionId, "authorization.decisionId"),
        result: a.result,
        reasonCodes: strings(a.reasonCodes, "authorization.reasonCodes"),
        authorityRef: ref(a.authorityRef, "authorization.authorityRef"),
        policyRef: policy(a.policyRef, "authorization.policyRef"),
        evaluatedAt: time(a.evaluatedAt, "authorization.evaluatedAt"),
        decisionSigningKeyId: str(a.decisionSigningKeyId, "authorization.decisionSigningKeyId"),
      },
      approvalRef: o.approvalRef === null ? null : str(o.approvalRef, "approvalRef"),
      execution,
      signingKeyId: str(o.signingKeyId, "signingKeyId"),
      signatureAlgorithm: str(o.signatureAlgorithm, "signatureAlgorithm", /^[A-Za-z0-9]{1,16}$/),
    },
    signature: str(s.signature, "signature", /^[A-Za-z0-9_-]{86}$/),
  };
}

const REQUEST_KEYS = [
  "requestId",
  "transactionId",
  "organizationId",
  "tenantId",
  "actor",
  "operation",
  "resource",
  "amount",
  "parameters",
  "authorityRef",
  "policyRef",
  "approvalRef",
  "idempotencyKey",
  "protocolVersion",
];

function parseRequestRecord(v: unknown): { body: Obj; requestDigest: string } {
  const o = obj(v, "request record");
  exact(o, ["body", "requestDigest"], "request record");
  const body = obj(o.body, "request.body");
  exact(body, REQUEST_KEYS, "request.body");
  return { body, requestDigest: digest(o.requestDigest, "request record.requestDigest") };
}

const AUTHORITY_KEYS = [
  "authorityId",
  "version",
  "organizationId",
  "tenantId",
  "issuer",
  "principal",
  "agent",
  "permittedActions",
  "resourceScope",
  "maxAmountMinor",
  "currencies",
  "approvalAboveMinor",
  "approvalActions",
  "approverKeyIds",
  "validFrom",
  "validUntil",
  "delegatedFrom",
  "delegationAllowed",
  "policyId",
  "policyVersion",
  "protocolVersion",
  "signatureAlgorithm",
  "signingKeyId",
];

function parseAuthorityRecord(v: unknown): {
  body: Obj & {
    authorityId: string;
    version: number;
    policyId: string;
    policyVersion: number;
    approverKeyIds: string[];
    signingKeyId: string;
  };
  signature: string;
} {
  const o = obj(v, "authority record");
  exact(o, ["body", "signature"], "authority record");
  const body = obj(o.body, "authority.body");
  exact(body, AUTHORITY_KEYS, "authority.body");
  return {
    body: {
      ...body,
      authorityId: str(body.authorityId, "authority.authorityId"),
      version: int(body.version, "authority.version", 1, MAX_VERSION),
      policyId: str(body.policyId, "authority.policyId"),
      policyVersion: int(body.policyVersion, "authority.policyVersion", 1, MAX_VERSION),
      approverKeyIds: strings(body.approverKeyIds, "authority.approverKeyIds"),
      signingKeyId: str(body.signingKeyId, "authority.signingKeyId"),
    },
    signature: str(o.signature, "authority.signature", /^[A-Za-z0-9_-]{86}$/),
  };
}

const DECISION_BODY_KEYS = [
  "decisionId",
  "requestDigest",
  "authorityRef",
  "policyRef",
  "result",
  "reasonCodes",
  "checks",
  "evaluatedAt",
  "protocolVersion",
];

function parseDecisionRecord(v: unknown): {
  body: Obj & {
    decisionId: string;
    requestDigest: string;
    result: string;
    reasonCodes: string[];
    evaluatedAt: string;
    authorityRef: { authorityId: string; version: number };
    policyRef: { policyId: string; version: number };
  };
  signingKeyId: string;
  signature: string;
} {
  const o = obj(v, "decision record");
  exact(o, ["body", "signingKeyId", "signature"], "decision record");
  const body = obj(o.body, "decision.body");
  exact(body, DECISION_BODY_KEYS, "decision.body");
  return {
    body: {
      ...body,
      decisionId: digest(body.decisionId, "decision.decisionId"),
      requestDigest: digest(body.requestDigest, "decision.requestDigest"),
      result: str(body.result, "decision.result", /^(ALLOW|DENY)$/),
      reasonCodes: strings(body.reasonCodes, "decision.reasonCodes"),
      evaluatedAt: time(body.evaluatedAt, "decision.evaluatedAt"),
      authorityRef: ref(body.authorityRef, "decision.authorityRef"),
      policyRef: policy(body.policyRef, "decision.policyRef"),
    },
    signingKeyId: str(o.signingKeyId, "decision.signingKeyId"),
    signature: str(o.signature, "decision.signature", /^[A-Za-z0-9_-]{86}$/),
  };
}

interface ApprovalRecord {
  readonly binding: {
    approvalId: string;
    organizationId: string;
    requestDigest: string;
    authorityRef: { authorityId: string; version: number };
    policyRef: { policyId: string; version: number };
    approverKeyId: string;
    requestedAt: string;
    expiresAt: string;
  };
  readonly decisions: {
    body: { approvalId: string; action: string; approverKeyId: string; decidedAt: string };
    signature: string;
  }[];
}

function parseApprovalRecord(v: unknown): ApprovalRecord {
  const o = obj(v, "approval record");
  exact(o, ["binding", "decisions"], "approval record");
  const b = obj(o.binding, "approval.binding");
  exact(
    b,
    [
      "approvalId",
      "organizationId",
      "requestDigest",
      "authorityRef",
      "policyRef",
      "approverKeyId",
      "requestedAt",
      "expiresAt",
    ],
    "approval.binding",
  );
  if (!Array.isArray(o.decisions)) throw new Malformed("approval.decisions must be an array");
  return {
    binding: {
      approvalId: str(b.approvalId, "approval.approvalId"),
      organizationId: str(b.organizationId, "approval.organizationId"),
      requestDigest: digest(b.requestDigest, "approval.requestDigest"),
      authorityRef: ref(b.authorityRef, "approval.authorityRef"),
      policyRef: policy(b.policyRef, "approval.policyRef"),
      approverKeyId: str(b.approverKeyId, "approval.approverKeyId"),
      requestedAt: time(b.requestedAt, "approval.requestedAt"),
      expiresAt: time(b.expiresAt, "approval.expiresAt"),
    },
    decisions: o.decisions.map((d: unknown) => {
      const dd = obj(d, "approval decision");
      exact(dd, ["body", "signature"], "approval decision");
      const body = obj(dd.body, "approval decision.body");
      exact(body, ["approvalId", "action", "approverKeyId", "decidedAt"], "approval decision.body");
      return {
        body: {
          approvalId: str(body.approvalId, "decision.approvalId"),
          action: str(body.action, "decision.action", /^(APPROVE|REJECT|REVOKE)$/),
          approverKeyId: str(body.approverKeyId, "decision.approverKeyId"),
          decidedAt: time(body.decidedAt, "decision.decidedAt"),
        },
        signature: str(dd.signature, "approval decision.signature", /^[A-Za-z0-9_-]{86}$/),
      };
    }),
  };
}

interface Key {
  readonly status: "ACTIVE" | "REVOKED";
  readonly publicKey: KeyObject;
}

function buildTrust(roots: readonly TrustRootInput[]): Map<string, Key> {
  const map = new Map<string, Key>();
  for (const root of roots) {
    if (map.has(root.keyId))
      throw new VerifierError("INVALID_TRUST_ROOT", `duplicate trust root ${root.keyId}`);
    let publicKey: KeyObject;
    try {
      publicKey = importEd25519PublicJwk(root.jwk);
    } catch {
      throw new VerifierError(
        "INVALID_TRUST_ROOT",
        `trust root ${root.keyId} is not an Ed25519 public key`,
      );
    }
    map.set(root.keyId, { status: root.status, publicKey });
  }
  return map;
}

/** Signature outcome under a trust root: PASS, FAIL (wrong or revoked key), or UNVERIFIABLE (unknown key). */
function signatureOutcome(
  trust: Map<string, Key>,
  keyId: string,
  domain: string,
  body: unknown,
  signature: string,
): { outcome: Outcome; detail: string } {
  const key = trust.get(keyId);
  if (!key) return { outcome: "UNVERIFIABLE", detail: `key ${keyId} is not in the trust roots` };
  if (key.status === "REVOKED") return { outcome: "FAIL", detail: `key ${keyId} is revoked` };
  const ok = verifyWithDomain(domain, canonicalize(body), signature, key.publicKey);
  return ok
    ? { outcome: "PASS", detail: `signature by ${keyId} verifies` }
    : { outcome: "FAIL", detail: `signature by ${keyId} does not verify` };
}

function requestDigestOf(body: Obj): string {
  const content: Record<string, unknown> = { ...body };
  delete content.approvalRef;
  return digestWithDomain(DOMAIN.request, canonicalize(content));
}

function invariantViolation(e: Evidence["body"]): string | null {
  const a = e.authorization;
  if (a.result === "DENY" && a.reasonCodes.length === 0) return "DENY_WITHOUT_REASON";
  if (a.result === "ALLOW" && a.reasonCodes.length > 0) return "ALLOW_WITH_REASON";
  const x = e.execution;
  if (x !== null) {
    if (a.result !== "ALLOW" && x.state !== "REFUSED") return "EXECUTION_WITHOUT_ALLOW";
    if ((x.state === "SUCCEEDED" || x.state === "DUPLICATE") && x.externalRef === null)
      return "SUCCESS_WITHOUT_REFERENCE";
    if (x.state !== "SUCCEEDED" && x.state !== "DUPLICATE" && x.externalRef !== null)
      return "REFERENCE_WITHOUT_SUCCESS";
  }
  return null;
}

/** Replays approval transitions. Returns the state in force at `at`, or a failure detail. */
function replayApproval(
  rec: ApprovalRecord,
  trust: Map<string, Key>,
  at: string,
): { outcome: Outcome; detail: string } {
  const sorted = [...rec.decisions].sort((x, y) =>
    x.body.decidedAt < y.body.decidedAt ? -1 : x.body.decidedAt > y.body.decidedAt ? 1 : 0,
  );
  let state = "PENDING";
  let stateAtDecision = "PENDING";
  for (const d of sorted) {
    if (
      d.body.approvalId !== rec.binding.approvalId ||
      d.body.approverKeyId !== rec.binding.approverKeyId
    ) {
      return { outcome: "FAIL", detail: "approval decision does not belong to this approval" };
    }
    if (
      Date.parse(d.body.decidedAt) < Date.parse(rec.binding.requestedAt) ||
      Date.parse(d.body.decidedAt) >= Date.parse(rec.binding.expiresAt)
    ) {
      return { outcome: "FAIL", detail: "approval decision outside its validity window" };
    }
    const sig = signatureOutcome(
      trust,
      rec.binding.approverKeyId,
      DOMAIN.approval,
      d.body,
      d.signature,
    );
    if (sig.outcome !== "PASS") return sig;
    const next =
      d.body.action === "APPROVE" && state === "PENDING"
        ? "APPROVED"
        : d.body.action === "REJECT" && state === "PENDING"
          ? "REJECTED"
          : d.body.action === "REVOKE" && (state === "PENDING" || state === "APPROVED")
            ? "REVOKED"
            : null;
    if (next === null)
      return {
        outcome: "FAIL",
        detail: `invalid approval transition ${d.body.action} from ${state}`,
      };
    if (d.body.decidedAt <= at) stateAtDecision = next;
    state = next;
  }
  if (Date.parse(at) >= Date.parse(rec.binding.expiresAt)) {
    return { outcome: "FAIL", detail: "approval expired before the decision" };
  }
  return stateAtDecision === "APPROVED"
    ? { outcome: "PASS", detail: "approval was APPROVED at the decision time" }
    : { outcome: "FAIL", detail: `approval was ${stateAtDecision} at the decision time` };
}

export function verifyBundle(
  bundleInput: unknown,
  roots: readonly TrustRootInput[],
): VerificationResult {
  const trust = buildTrust(roots);
  const bundle = obj(bundleInput, "bundle");
  if (bundle.format !== BUNDLE_FORMAT || bundle.formatVersion !== BUNDLE_FORMAT_VERSION) {
    throw new VerifierError("UNSUPPORTED_BUNDLE", "unsupported bundle format or version");
  }
  if (!Array.isArray(bundle.entries) || bundle.entries.some((e) => typeof e !== "string")) {
    throw new VerifierError("UNSUPPORTED_BUNDLE", "entries must be an array of strings");
  }
  const lines = bundle.entries as string[];
  let expectedHead: string | null = null;
  if (bundle.expectedHead !== null && bundle.expectedHead !== undefined) {
    if (typeof bundle.expectedHead !== "string" || !DIGEST.test(bundle.expectedHead)) {
      throw new VerifierError(
        "UNSUPPORTED_BUNDLE",
        "expectedHead must be a SHA-256 digest or null",
      );
    }
    expectedHead = bundle.expectedHead;
  }

  const checks: Check[] = [];
  const add = (entry: number | null, id: string, outcome: Outcome, detail: string): void => {
    checks.push({ entry, id, outcome, detail });
  };

  // Sections are indexed by their identity. A malformed record is reported and then ignored.
  const requests = new Map<string, { body: Obj; requestDigest: string }>();
  const decisions = new Map<string, ReturnType<typeof parseDecisionRecord>>();
  const authorities = new Map<string, ReturnType<typeof parseAuthorityRecord>>();
  const approvals = new Map<string, ApprovalRecord>();
  const section = (name: string, items: unknown, parse: (v: unknown) => void): void => {
    if (items === undefined) return;
    if (!Array.isArray(items)) {
      add(null, `SECTION_${name.toUpperCase()}`, "FAIL", `${name} must be an array`);
      return;
    }
    items.forEach((item) => {
      try {
        parse(item);
      } catch (err) {
        add(
          null,
          `SECTION_${name.toUpperCase()}`,
          "FAIL",
          err instanceof Error ? err.message : "malformed record",
        );
      }
    });
  };
  section("requests", bundle.requests, (v) => {
    const r = parseRequestRecord(v);
    if (requestDigestOf(r.body) !== r.requestDigest) {
      add(
        null,
        "REQUEST_DIGEST",
        "FAIL",
        `request ${r.requestDigest.slice(0, 12)} does not match its body`,
      );
    }
    requests.set(r.requestDigest, r);
  });
  section("decisions", bundle.decisions, (v) => {
    const d = parseDecisionRecord(v);
    decisions.set(d.body.decisionId, d);
  });
  section("authorities", bundle.authorities, (v) => {
    const a = parseAuthorityRecord(v);
    authorities.set(`${a.body.authorityId}@${String(a.body.version)}`, a);
  });
  section("approvals", bundle.approvals, (v) => {
    const a = parseApprovalRecord(v);
    approvals.set(a.binding.approvalId, a);
  });

  // Chain entries.
  if (lines.length === 0)
    add(null, "NO_ENTRIES", "INCOMPLETE", "bundle contains no evidence entries");
  let previous: string | null = GENESIS;
  let lastDigest = GENESIS;
  const seen = new Set<string>();

  lines.forEach((line, i) => {
    let parsedJson: unknown;
    try {
      parsedJson = JSON.parse(line);
    } catch {
      add(i, "SCHEMA", "FAIL", "entry is not valid JSON");
      previous = null;
      return;
    }
    if (canonicalize(parsedJson) !== line) {
      add(i, "CANONICAL", "FAIL", "entry is not in canonical form");
    } else {
      add(i, "CANONICAL", "PASS", "entry is canonical");
    }
    let ev: Evidence;
    try {
      ev = parseEvidence(parsedJson);
    } catch (err) {
      add(i, "SCHEMA", "FAIL", err instanceof Error ? err.message : "malformed entry");
      previous = null;
      return;
    }
    add(i, "SCHEMA", "PASS", "entry matches the evidence schema");

    const b = ev.body;
    if (b.protocolVersion === PROTOCOL_VERSION)
      add(i, "PROTOCOL_VERSION", "PASS", "protocol version 1.0");
    else add(i, "PROTOCOL_VERSION", "FAIL", `unsupported protocol version ${b.protocolVersion}`);

    if (b.sequence === i + 1) add(i, "SEQUENCE", "PASS", `sequence ${String(b.sequence)}`);
    else
      add(i, "SEQUENCE", "FAIL", `expected sequence ${String(i + 1)}, found ${String(b.sequence)}`);

    if (previous !== null) {
      if (b.previousDigest === previous) add(i, "CHAIN", "PASS", "links to previous entry");
      else add(i, "CHAIN", "FAIL", "previous digest does not match the preceding entry");
    }

    if (seen.has(b.evidenceId))
      add(i, "DUPLICATE_ID", "FAIL", `evidence ID ${b.evidenceId} repeats`);
    seen.add(b.evidenceId);

    const sig = signatureOutcome(trust, b.signingKeyId, DOMAIN.evidence, b, ev.signature);
    add(i, "SIGNATURE", sig.outcome, sig.detail);

    const violation = invariantViolation(b);
    if (violation) add(i, "INVARIANT", "FAIL", violation);
    else add(i, "INVARIANT", "PASS", "authorization and execution invariants hold");

    // Cross-checks against supplied records.
    const req = requests.get(b.request.requestDigest);
    if (req === undefined) {
      add(i, "REQUEST", "INCOMPLETE", "request body not supplied");
    } else if (
      req.body.requestId !== b.request.requestId ||
      req.body.idempotencyKey !== b.request.idempotencyKey ||
      req.body.transactionId !== b.transactionId
    ) {
      add(i, "REQUEST", "FAIL", "request fields do not match the evidence");
    } else if (req.body.approvalRef !== b.approvalRef) {
      add(i, "REQUEST", "FAIL", "approval reference does not match the request");
    } else {
      add(i, "REQUEST", "PASS", "request body matches its digest and the evidence");
    }

    const dec = decisions.get(b.authorization.decisionId);
    let decisionOk = false;
    if (dec === undefined) {
      add(i, "DECISION", "INCOMPLETE", "decision record not supplied");
    } else {
      const ds = signatureOutcome(
        trust,
        dec.signingKeyId,
        DOMAIN.decision,
        dec.body,
        dec.signature,
      );
      const a = b.authorization;
      const matches =
        dec.body.result === a.result &&
        canonicalize(dec.body.reasonCodes) === canonicalize(a.reasonCodes) &&
        canonicalize(dec.body.authorityRef) === canonicalize(a.authorityRef) &&
        canonicalize(dec.body.policyRef) === canonicalize(a.policyRef) &&
        dec.body.evaluatedAt === a.evaluatedAt &&
        dec.signingKeyId === a.decisionSigningKeyId &&
        dec.body.requestDigest === b.request.requestDigest;
      if (ds.outcome !== "PASS") add(i, "DECISION", ds.outcome, ds.detail);
      else if (!matches)
        add(
          i,
          "DECISION",
          "FAIL",
          "decision record does not match the evidence authorization section",
        );
      else {
        add(i, "DECISION", "PASS", "decision is authentic and matches the evidence");
        decisionOk = true;
      }
    }

    const auth = authorities.get(
      `${b.authorization.authorityRef.authorityId}@${String(b.authorization.authorityRef.version)}`,
    );
    if (auth === undefined) {
      add(i, "AUTHORITY", "INCOMPLETE", "authority declaration not supplied");
    } else {
      const as = signatureOutcome(
        trust,
        auth.body.signingKeyId,
        DOMAIN.authority,
        auth.body,
        auth.signature,
      );
      if (as.outcome !== "PASS") add(i, "AUTHORITY", as.outcome, as.detail);
      else if (
        auth.body.policyId !== b.authorization.policyRef.policyId ||
        auth.body.policyVersion !== b.authorization.policyRef.version
      ) {
        add(i, "AUTHORITY", "FAIL", "policy reference does not match the authority");
      } else {
        add(i, "AUTHORITY", "PASS", "authority is authentic and matches the policy reference");
      }
    }

    if (b.approvalRef !== null) {
      const ap = approvals.get(b.approvalRef);
      if (ap === undefined) {
        add(i, "APPROVAL", "INCOMPLETE", "approval record not supplied");
      } else {
        const bind = ap.binding;
        const a = b.authorization;
        if (
          bind.requestDigest !== b.request.requestDigest ||
          canonicalize(bind.authorityRef) !== canonicalize(a.authorityRef) ||
          canonicalize(bind.policyRef) !== canonicalize(a.policyRef)
        ) {
          add(i, "APPROVAL", "FAIL", "approval is not bound to this request, authority and policy");
        } else if (auth !== undefined && !auth.body.approverKeyIds.includes(bind.approverKeyId)) {
          add(i, "APPROVAL", "FAIL", "approver is not named by the authority");
        } else {
          const r = replayApproval(ap, trust, a.evaluatedAt);
          add(i, "APPROVAL", r.outcome, r.detail);
        }
      }
    }

    if (
      b.execution !== null &&
      Date.parse(b.execution.attemptedAt) < Date.parse(b.authorization.evaluatedAt)
    ) {
      add(i, "EXECUTION_ORDER", "FAIL", "execution is recorded before the decision");
    } else if (b.execution !== null) {
      add(i, "EXECUTION_ORDER", "PASS", "execution follows the decision");
    }
    void decisionOk;

    previous = digestWithDomain(DOMAIN.ledger, canonicalize(parsedJson));
    lastDigest = previous;
  });

  if (expectedHead !== null) {
    if (lines.length === 0) {
      if (expectedHead !== GENESIS)
        add(null, "HEAD", "FAIL", "expected head does not match an empty chain");
    } else if (lastDigest === expectedHead) {
      add(null, "HEAD", "PASS", "chain head matches the expected head");
    } else {
      add(null, "HEAD", "FAIL", "chain head does not match the expected head");
    }
  } else if (lines.length > 0) {
    add(
      null,
      "HEAD",
      "INCOMPLETE",
      "no expected head supplied; tail truncation cannot be ruled out",
    );
  }

  const verdict: Verdict = checks.some((c) => c.outcome === "FAIL")
    ? "INVALID"
    : checks.some((c) => c.outcome === "UNVERIFIABLE")
      ? "UNVERIFIABLE"
      : checks.some((c) => c.outcome === "INCOMPLETE")
        ? "INCOMPLETE"
        : "VALID";
  return { verdict, entries: lines.length, head: lastDigest, checks };
}
