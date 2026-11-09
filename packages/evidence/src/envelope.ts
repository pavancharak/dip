import {
  asSigningProvider,
  canonicalize,
  digestWithDomain,
  signWithProvider,
  verifyWithDomain,
  type SignerInput,
} from "@dip/crypto";
import { DipError, TrustRootSet, exactKeys, id, int, obj, time } from "@dip/authority";

/**
 * Evidence envelope. It records what was authorized and, separately, what was
 * executed. Authorization and execution are distinct sections: an ALLOW does not
 * prove execution, and execution never appears without an ALLOW except as a refusal.
 */
export const EVIDENCE_DOMAIN = "DIP-EVIDENCE-V1";
export const LEDGER_ENTRY_DOMAIN = "DIP-LEDGER-ENTRY-V1";
export const GENESIS_DIGEST = "0".repeat(64);
const DIGEST = /^[0-9a-f]{64}$/;

export type ExecutionState =
  | "REFUSED"
  | "STARTED"
  | "SUCCEEDED"
  | "FAILED"
  | "TIMED_OUT"
  | "DUPLICATE";

export interface EvidenceAuthorization {
  readonly decisionId: string;
  readonly result: "ALLOW" | "DENY";
  readonly reasonCodes: string[];
  readonly authorityRef: { readonly authorityId: string; readonly version: number };
  readonly policyRef: { readonly policyId: string; readonly version: number };
  readonly evaluatedAt: string;
  readonly decisionSigningKeyId: string;
}

export interface EvidenceExecution {
  readonly state: ExecutionState;
  readonly connectorId: string | null;
  readonly reasonCode: string | null;
  readonly externalRef: string | null;
  readonly attemptedAt: string;
}

export interface EvidenceBody {
  readonly evidenceId: string;
  readonly sequence: number;
  readonly previousDigest: string;
  readonly transactionId: string;
  readonly protocolVersion: string;
  readonly recordedAt: string;
  readonly request: {
    readonly requestId: string;
    readonly requestDigest: string;
    readonly idempotencyKey: string;
  };
  readonly authorization: EvidenceAuthorization;
  readonly approvalRef: string | null;
  readonly execution: EvidenceExecution | null;
  readonly signingKeyId: string;
  readonly signatureAlgorithm: "Ed25519";
}

export interface SignedEvidence {
  readonly body: EvidenceBody;
  readonly signature: string;
}

/** Everything the caller supplies. Sequence and chain position come from the ledger. */
export interface EvidenceDraft {
  readonly evidenceId: string;
  readonly transactionId: string;
  readonly recordedAt: string;
  readonly request: {
    readonly requestId: string;
    readonly requestDigest: string;
    readonly idempotencyKey: string;
  };
  readonly authorization: EvidenceAuthorization;
  readonly approvalRef: string | null;
  readonly execution: EvidenceExecution | null;
}

export type Signer = SignerInput;

export interface ChainPosition {
  readonly sequence: number;
  readonly previousDigest: string;
}

/** Cross-field rules. A violation means the record must not exist. */
export function checkInvariants(body: EvidenceBody): string | null {
  const a = body.authorization;
  if (a.result === "DENY" && a.reasonCodes.length === 0) return "DENY_WITHOUT_REASON";
  if (a.result === "ALLOW" && a.reasonCodes.length > 0) return "ALLOW_WITH_REASON";
  const e = body.execution;
  if (e !== null) {
    if (a.result !== "ALLOW" && e.state !== "REFUSED") return "EXECUTION_WITHOUT_ALLOW";
    if ((e.state === "SUCCEEDED" || e.state === "DUPLICATE") && e.externalRef === null) {
      return "SUCCESS_WITHOUT_REFERENCE";
    }
    if (e.state !== "SUCCEEDED" && e.state !== "DUPLICATE" && e.externalRef !== null) {
      return "REFERENCE_WITHOUT_SUCCESS";
    }
  }
  return null;
}

export async function createEvidence(
  draft: EvidenceDraft,
  position: ChainPosition,
  signer: Signer,
): Promise<SignedEvidence> {
  const provider = asSigningProvider(signer);
  const body: EvidenceBody = {
    evidenceId: draft.evidenceId,
    sequence: position.sequence,
    previousDigest: position.previousDigest,
    transactionId: draft.transactionId,
    protocolVersion: "1.0",
    recordedAt: draft.recordedAt,
    request: draft.request,
    authorization: draft.authorization,
    approvalRef: draft.approvalRef,
    execution: draft.execution,
    signingKeyId: provider.keyId,
    signatureAlgorithm: "Ed25519",
  };
  const violation = checkInvariants(body);
  if (violation) throw new DipError("EVIDENCE_INVARIANT_VIOLATED", violation);
  return {
    body,
    signature: await signWithProvider(provider, EVIDENCE_DOMAIN, canonicalize(body)),
  };
}

export function entryDigest(signed: SignedEvidence): string {
  return digestWithDomain(LEDGER_ENTRY_DOMAIN, canonicalize(signed));
}

function text(v: unknown, path: string): string {
  if (typeof v !== "string") throw new DipError("INVALID_FIELD", `${path} must be a string`);
  return v;
}

function digestField(v: unknown, path: string): string {
  if (typeof v !== "string" || !DIGEST.test(v))
    throw new DipError("INVALID_FIELD", `${path} must be a SHA-256 digest`);
  return v;
}

function nullableId(v: unknown, path: string): string | null {
  return v === null ? null : id(v, path);
}

function ref(v: unknown, path: string): { authorityId: string; version: number } {
  const o = obj(v, path);
  exactKeys(o, ["authorityId", "version"], path);
  return {
    authorityId: id(o.authorityId, `${path}.authorityId`),
    version: int(o.version, `${path}.version`, 1, 1_000_000_000),
  };
}

function policy(v: unknown, path: string): { policyId: string; version: number } {
  const o = obj(v, path);
  exactKeys(o, ["policyId", "version"], path);
  return {
    policyId: id(o.policyId, `${path}.policyId`),
    version: int(o.version, `${path}.version`, 1, 1_000_000_000),
  };
}

const STATES: readonly string[] = [
  "REFUSED",
  "STARTED",
  "SUCCEEDED",
  "FAILED",
  "TIMED_OUT",
  "DUPLICATE",
];

/** Strict parse of a signed envelope from untrusted JSON. Signature is not checked here. */
export function parseSignedEvidence(input: unknown): SignedEvidence {
  const s = obj(input, "evidence");
  exactKeys(s, ["body", "signature"], "evidence");
  const o = obj(s.body, "evidence.body");
  exactKeys(
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
    "evidence.body",
  );
  const req = obj(o.request, "evidence.body.request");
  exactKeys(req, ["requestId", "requestDigest", "idempotencyKey"], "evidence.body.request");
  const au = obj(o.authorization, "evidence.body.authorization");
  exactKeys(
    au,
    [
      "decisionId",
      "result",
      "reasonCodes",
      "authorityRef",
      "policyRef",
      "evaluatedAt",
      "decisionSigningKeyId",
    ],
    "evidence.body.authorization",
  );
  if (au.result !== "ALLOW" && au.result !== "DENY")
    throw new DipError("INVALID_FIELD", "authorization.result must be ALLOW or DENY");
  if (!Array.isArray(au.reasonCodes) || au.reasonCodes.some((c) => typeof c !== "string")) {
    throw new DipError("INVALID_FIELD", "authorization.reasonCodes must be strings");
  }
  let execution: EvidenceExecution | null = null;
  if (o.execution !== null) {
    const e = obj(o.execution, "evidence.body.execution");
    exactKeys(
      e,
      ["state", "connectorId", "reasonCode", "externalRef", "attemptedAt"],
      "evidence.body.execution",
    );
    if (typeof e.state !== "string" || !STATES.includes(e.state))
      throw new DipError("INVALID_FIELD", "execution.state is invalid");
    execution = {
      state: e.state as ExecutionState,
      connectorId: nullableId(e.connectorId, "execution.connectorId"),
      reasonCode: e.reasonCode === null ? null : text(e.reasonCode, "execution.reasonCode"),
      externalRef: e.externalRef === null ? null : text(e.externalRef, "execution.externalRef"),
      attemptedAt: time(e.attemptedAt, "execution.attemptedAt"),
    };
  }
  if (o.signatureAlgorithm !== "Ed25519")
    throw new DipError("UNSUPPORTED_ALGORITHM", "signatureAlgorithm must be Ed25519");
  if (typeof s.signature !== "string")
    throw new DipError("INVALID_FIELD", "evidence.signature must be a string");
  return {
    body: {
      evidenceId: id(o.evidenceId, "evidence.body.evidenceId"),
      sequence: int(o.sequence, "evidence.body.sequence", 1, Number.MAX_SAFE_INTEGER),
      previousDigest: digestField(o.previousDigest, "evidence.body.previousDigest"),
      transactionId: id(o.transactionId, "evidence.body.transactionId"),
      protocolVersion: text(o.protocolVersion, "evidence.body.protocolVersion"),
      recordedAt: time(o.recordedAt, "evidence.body.recordedAt"),
      request: {
        requestId: id(req.requestId, "request.requestId"),
        requestDigest: digestField(req.requestDigest, "request.requestDigest"),
        idempotencyKey: id(req.idempotencyKey, "request.idempotencyKey"),
      },
      authorization: {
        decisionId: digestField(au.decisionId, "authorization.decisionId"),
        result: au.result,
        reasonCodes: [...(au.reasonCodes as string[])],
        authorityRef: ref(au.authorityRef, "authorization.authorityRef"),
        policyRef: policy(au.policyRef, "authorization.policyRef"),
        evaluatedAt: time(au.evaluatedAt, "authorization.evaluatedAt"),
        decisionSigningKeyId: id(au.decisionSigningKeyId, "authorization.decisionSigningKeyId"),
      },
      approvalRef: nullableId(o.approvalRef, "evidence.body.approvalRef"),
      execution,
      signingKeyId: id(o.signingKeyId, "evidence.body.signingKeyId"),
      signatureAlgorithm: "Ed25519",
    },
    signature: s.signature,
  };
}

/** Verifies signature and invariants under explicit trust roots. Does not check chain position. */
export function verifyEvidenceSignature(
  signed: SignedEvidence,
  trust: TrustRootSet,
): string | null {
  const key = trust.lookup(signed.body.signingKeyId);
  if (!key) return "EVIDENCE_KEY_UNKNOWN";
  if (key.status === "REVOKED") return "EVIDENCE_KEY_REVOKED";
  const ok = verifyWithDomain(
    EVIDENCE_DOMAIN,
    canonicalize(signed.body),
    signed.signature,
    key.publicKey,
  );
  return ok ? null : "EVIDENCE_SIGNATURE_INVALID";
}
