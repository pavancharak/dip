import { DipError, type Journal, type TrustRootSet } from "@dip/authority";
import { canonicalize } from "@dip/crypto";
import type { NormalizedRequest, SignedDecision } from "@dip/authorization";
import type { ExecutionAttempt } from "@dip/execution";
import {
  GENESIS_DIGEST,
  checkInvariants,
  createEvidence,
  entryDigest,
  parseSignedEvidence,
  verifyEvidenceSignature,
  type EvidenceDraft,
  type Signer,
  type SignedEvidence,
} from "@dip/evidence";

export interface VerificationError {
  readonly index: number;
  readonly code: string;
}

export interface VerificationReport {
  readonly valid: boolean;
  readonly entries: number;
  readonly head: string;
  readonly errors: readonly VerificationError[];
}

/**
 * Independent chain verification. It takes exported lines and trust roots and
 * needs nothing from the ledger that wrote them. `expectedHead`, when supplied,
 * detects tail truncation. Without an external anchor, tail truncation cannot be detected.
 */
export function verifyChain(
  lines: readonly string[],
  trust: TrustRootSet,
  expectedHead?: string,
): VerificationReport {
  const errors: VerificationError[] = [];
  const seen = new Set<string>();
  let previous: string = GENESIS_DIGEST;
  let lastDigest = GENESIS_DIGEST;

  lines.forEach((line, index) => {
    const fail = (code: string): void => {
      errors.push({ index, code });
    };
    let signed: SignedEvidence;
    try {
      signed = parseSignedEvidence(JSON.parse(line));
    } catch {
      fail("MALFORMED");
      previous = "";
      return;
    }
    if (signed.body.sequence !== index + 1) fail("SEQUENCE_MISMATCH");
    if (signed.body.previousDigest !== previous) fail("CHAIN_BROKEN");
    if (seen.has(signed.body.evidenceId)) fail("DUPLICATE_EVIDENCE_ID");
    seen.add(signed.body.evidenceId);
    const sigFault = verifyEvidenceSignature(signed, trust);
    if (sigFault) fail(sigFault);
    const violation = checkInvariants(signed.body);
    if (violation) fail(`INVARIANT_${violation}`);
    previous = entryDigest(signed);
    lastDigest = previous;
  });

  if (expectedHead !== undefined && lines.length > 0 && lastDigest !== expectedHead) {
    errors.push({ index: lines.length - 1, code: "HEAD_MISMATCH" });
  }
  if (expectedHead !== undefined && lines.length === 0 && expectedHead !== GENESIS_DIGEST) {
    errors.push({ index: -1, code: "HEAD_MISMATCH" });
  }
  return { valid: errors.length === 0, entries: lines.length, head: lastDigest, errors };
}

/** Append-only evidence ledger. There is no update or delete operation. */
export class EvidenceLedger {
  private readonly lines: string[] = [];
  private readonly ids = new Set<string>();
  private lastDigest: string = GENESIS_DIGEST;

  constructor(
    private readonly trust: TrustRootSet,
    private readonly signer: Signer,
    private readonly journal?: Journal,
  ) {}

  /** Re-adds a journaled entry. The signature is checked at open time by verify(), not here. */
  restoreLine(line: string): void {
    const signed = parseSignedEvidence(JSON.parse(line));
    this.lines.push(line);
    this.ids.add(signed.body.evidenceId);
    this.lastDigest = entryDigest(signed);
  }

  append(draft: EvidenceDraft): SignedEvidence {
    if (this.ids.has(draft.evidenceId)) {
      throw new DipError("EVIDENCE_DUPLICATE", `evidence ${draft.evidenceId} is already recorded`);
    }
    const signed = createEvidence(
      draft,
      { sequence: this.lines.length + 1, previousDigest: this.lastDigest },
      this.signer,
    );
    this.lines.push(canonicalize(signed));
    this.journal?.("evidence.appended", canonicalize(signed));
    this.ids.add(draft.evidenceId);
    this.lastDigest = entryDigest(signed);
    return signed;
  }

  head(): string {
    return this.lastDigest;
  }

  size(): number {
    return this.lines.length;
  }

  /** Canonical JSON lines, one per entry, in chain order. */
  export(): string[] {
    return [...this.lines];
  }

  verify(expectedHead?: string): VerificationReport {
    return verifyChain(this.lines, this.trust, expectedHead);
  }
}

/** Builds an evidence draft from one authorization decision and, if any, its execution attempt. */
export function draftFrom(input: {
  readonly evidenceId: string;
  readonly transactionId: string;
  readonly recordedAt: string;
  readonly normalized: NormalizedRequest;
  readonly decision: SignedDecision;
  readonly attempt: ExecutionAttempt | null;
}): EvidenceDraft {
  const b = input.decision.body;
  const r = input.normalized.request;
  return {
    evidenceId: input.evidenceId,
    transactionId: input.transactionId,
    recordedAt: input.recordedAt,
    request: {
      requestId: r.requestId,
      requestDigest: input.normalized.requestDigest,
      idempotencyKey: r.idempotencyKey,
    },
    authorization: {
      decisionId: b.decisionId,
      result: b.result,
      reasonCodes: [...b.reasonCodes],
      authorityRef: { authorityId: b.authorityRef.authorityId, version: b.authorityRef.version },
      policyRef: { policyId: b.policyRef.policyId, version: b.policyRef.version },
      evaluatedAt: b.evaluatedAt,
      decisionSigningKeyId: input.decision.signingKeyId,
    },
    approvalRef: r.approvalRef,
    execution:
      input.attempt === null
        ? null
        : {
            state: input.attempt.state,
            connectorId: input.attempt.connectorId,
            reasonCode: input.attempt.reasonCode,
            externalRef: input.attempt.externalRef,
            attemptedAt: input.attempt.at.replace(/\.\d{3}Z$/, "Z"),
          },
  };
}
