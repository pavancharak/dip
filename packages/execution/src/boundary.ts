import type { Journal } from "@dip/authority";
import { canonicalize, verifyWithDomain } from "@dip/crypto";
import type { TrustRootSet } from "@dip/authority";
import {
  DECISION_DOMAIN,
  digestRequest,
  parseNormalizedRequest,
  type RequestBody,
} from "@dip/authorization";

/**
 * Protected execution boundary. Every protected action goes through `execute`.
 * It runs a connector only after it has verified a signed ALLOW decision for
 * the exact request. An ALLOW decision does not prove that the action succeeded.
 */

export type ConnectorResult =
  | { readonly status: "SUCCEEDED"; readonly externalRef: string }
  | { readonly status: "FAILED"; readonly reasonCode: string };

export interface Connector {
  readonly id: string;
  /** Must honour `idempotencyKey` so the external system can deduplicate retries. */
  execute(request: RequestBody, idempotencyKey: string): Promise<ConnectorResult>;
}

export type AttemptState =
  | "REFUSED"
  | "STARTED"
  | "SUCCEEDED"
  | "FAILED"
  | "TIMED_OUT"
  | "DUPLICATE";

export interface ExecutionAttempt {
  readonly sequence: number;
  readonly state: AttemptState;
  readonly decisionId: string | null;
  readonly requestDigest: string;
  readonly idempotencyKey: string;
  readonly connectorId: string | null;
  readonly reasonCode: string | null;
  readonly externalRef: string | null;
  readonly at: string;
}

export interface BoundaryOptions {
  /** Trusted engine keys (decision signers). Keys are never taken from the decision itself. */
  readonly trust: TrustRootSet;
  /** Connector per operation name. Missing operations are refused. */
  readonly connectors: ReadonlyMap<string, Connector>;
  readonly now: () => Date;
  readonly maxDecisionAgeSeconds: number;
  readonly timeoutMs: number;
  /** Re-checks a referenced approval at execution time. Returns a reason code, or null when still valid. */
  readonly approvalRecheck?: (request: RequestBody) => string | null;
  /** Re-checks that the authority is still in good standing at execution time. Returns a reason code, or null. */
  readonly authorityRecheck?: (request: RequestBody) => Promise<string | null>;
  /** Receives each committed change (attempts, consumed decisions, completions) for durable logging. */
  readonly journal?: Journal | undefined;
}

interface KnownKey {
  readonly status: "ACTIVE" | "REVOKED";
}

interface Completed {
  readonly digest: string;
  readonly externalRef: string;
}

function parseSignedDecision(input: unknown): {
  body: Record<string, unknown>;
  signingKeyId: string;
  signature: string;
} {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    throw new Error("decision must be an object");
  }
  const o = input as Record<string, unknown>;
  if (typeof o.body !== "object" || o.body === null || Array.isArray(o.body)) {
    throw new Error("decision.body must be an object");
  }
  if (typeof o.signingKeyId !== "string" || typeof o.signature !== "string") {
    throw new Error("decision signature fields are missing");
  }
  return {
    body: o.body as Record<string, unknown>,
    signingKeyId: o.signingKeyId,
    signature: o.signature,
  };
}

function withTimeout<T>(
  p: Promise<T>,
  ms: number,
): Promise<{ kind: "done"; value: T } | { kind: "timeout" }> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<{ kind: "timeout" }>((resolve) => {
    timer = setTimeout(() => {
      resolve({ kind: "timeout" });
    }, ms);
  });
  const done = p.then((value) => ({ kind: "done" as const, value }));
  return Promise.race([done, timeout]).finally(() => {
    clearTimeout(timer);
  });
}

export class ExecutionBoundary {
  private readonly log: ExecutionAttempt[] = [];
  private readonly consumed = new Set<string>();
  private readonly inFlight = new Set<string>();
  private readonly completed = new Map<string, Completed>();

  constructor(private readonly options: BoundaryOptions) {}

  /** Restore paths: re-apply journaled state without executing anything or journaling again. */
  restoreAttempt(attempt: ExecutionAttempt): void {
    this.log.push(attempt);
  }

  restoreConsumed(decisionId: string): void {
    this.consumed.add(decisionId);
  }

  restoreCompleted(key: string, digest: string, externalRef: string): void {
    this.completed.set(key, { digest, externalRef });
  }

  attempts(): readonly ExecutionAttempt[] {
    return [...this.log];
  }

  private record(
    state: AttemptState,
    fields: {
      decisionId: string | null;
      digest: string;
      key: string;
      connectorId: string | null;
      reasonCode: string | null;
      externalRef: string | null;
    },
  ): ExecutionAttempt {
    const attempt: ExecutionAttempt = {
      sequence: this.log.length + 1,
      state,
      decisionId: fields.decisionId,
      requestDigest: fields.digest,
      idempotencyKey: fields.key,
      connectorId: fields.connectorId,
      reasonCode: fields.reasonCode,
      externalRef: fields.externalRef,
      at: this.options.now().toISOString(),
    };
    this.log.push(attempt);
    this.options.journal?.("execution.attempt", attempt);
    return attempt;
  }

  async execute(requestInput: unknown, decisionInput: unknown): Promise<ExecutionAttempt> {
    let normalized;
    try {
      normalized = parseNormalizedRequest(requestInput);
    } catch {
      return this.record("REFUSED", {
        decisionId: null,
        digest: "",
        key: "",
        connectorId: null,
        reasonCode: "REQUEST_MALFORMED",
        externalRef: null,
      });
    }
    const { request, requestDigest } = normalized;
    const key = request.idempotencyKey;
    const refuse = (decisionId: string | null, reasonCode: string): ExecutionAttempt =>
      this.record("REFUSED", {
        decisionId,
        digest: requestDigest,
        key,
        connectorId: null,
        reasonCode,
        externalRef: null,
      });

    // 1. Decision authenticity: signature under a trusted, non-revoked engine key.
    let decision;
    try {
      decision = parseSignedDecision(decisionInput);
    } catch {
      return refuse(null, "DECISION_MALFORMED");
    }
    const keyEntry = this.options.trust.lookup(decision.signingKeyId) as KnownKey | undefined;
    if (!keyEntry) return refuse(null, "DECISION_KEY_UNKNOWN");
    if (keyEntry.status === "REVOKED") return refuse(null, "DECISION_KEY_REVOKED");
    let canonicalBody: string;
    try {
      canonicalBody = canonicalize(decision.body);
    } catch {
      return refuse(null, "DECISION_MALFORMED");
    }
    const trustedKey = this.options.trust.lookup(decision.signingKeyId);
    if (!trustedKey) return refuse(null, "DECISION_KEY_UNKNOWN");
    if (
      !verifyWithDomain(DECISION_DOMAIN, canonicalBody, decision.signature, trustedKey.publicKey)
    ) {
      return refuse(null, "DECISION_SIGNATURE_INVALID");
    }
    const decisionId =
      typeof decision.body.decisionId === "string" ? decision.body.decisionId : null;
    if (decisionId === null) return refuse(null, "DECISION_MALFORMED");

    // 2. Only an ALLOW decision may proceed.
    if (decision.body.result !== "ALLOW") return refuse(decisionId, "DECISION_NOT_ALLOW");

    // 3. The decision must be for this exact request, authority version and policy version.
    if (digestRequest(request) !== requestDigest || decision.body.requestDigest !== requestDigest) {
      return refuse(decisionId, "REQUEST_DIGEST_MISMATCH");
    }
    if (canonicalize(decision.body.authorityRef) !== canonicalize(request.authorityRef)) {
      return refuse(decisionId, "DECISION_REF_MISMATCH");
    }
    if (canonicalize(decision.body.policyRef) !== canonicalize(request.policyRef)) {
      return refuse(decisionId, "DECISION_REF_MISMATCH");
    }

    // 4. Freshness.
    const evaluatedMs =
      typeof decision.body.evaluatedAt === "string" ? Date.parse(decision.body.evaluatedAt) : NaN;
    if (Number.isNaN(evaluatedMs)) return refuse(decisionId, "DECISION_MALFORMED");
    const nowMs = this.options.now().getTime();
    if (evaluatedMs > nowMs) return refuse(decisionId, "DECISION_IN_FUTURE");
    if (nowMs - evaluatedMs > this.options.maxDecisionAgeSeconds * 1000)
      return refuse(decisionId, "DECISION_STALE");

    // 5. The authority must still be in good standing: a decision does not outlive its authority.
    if (this.options.authorityRecheck) {
      const standing = await this.options.authorityRecheck(request);
      if (standing !== null) return refuse(decisionId, standing);
    }

    // 6. Approval evidence must still hold at execution time when referenced.
    if (request.approvalRef !== null) {
      const recheck = this.options.approvalRecheck;
      if (!recheck) return refuse(decisionId, "APPROVAL_RECHECK_UNAVAILABLE");
      const code = recheck(request);
      if (code !== null) return refuse(decisionId, code);
    }

    // 8. Idempotency: a completed action is never repeated for the same key.
    const done = this.completed.get(key);
    if (done !== undefined) {
      if (done.digest !== requestDigest) return refuse(decisionId, "IDEMPOTENCY_CONFLICT");
      return this.record("DUPLICATE", {
        decisionId,
        digest: requestDigest,
        key,
        connectorId: null,
        reasonCode: null,
        externalRef: done.externalRef,
      });
    }
    if (this.inFlight.has(key)) return refuse(decisionId, "EXECUTION_IN_PROGRESS");

    // 7. Replay: a decision authorizes at most one execution.
    if (this.consumed.has(decisionId)) return refuse(decisionId, "DECISION_REPLAYED");

    // 9. Connector routing.
    const connector = this.options.connectors.get(request.operation);
    if (!connector) return refuse(decisionId, "CONNECTOR_NOT_FOUND");

    // 10. Execution. The decision is consumed before the connector runs.
    this.consumed.add(decisionId);
    this.options.journal?.("execution.consumed", { decisionId });
    this.inFlight.add(key);
    this.record("STARTED", {
      decisionId,
      digest: requestDigest,
      key,
      connectorId: connector.id,
      reasonCode: null,
      externalRef: null,
    });
    try {
      const outcome = await withTimeout(connector.execute(request, key), this.options.timeoutMs);
      if (outcome.kind === "timeout") {
        return this.record("TIMED_OUT", {
          decisionId,
          digest: requestDigest,
          key,
          connectorId: connector.id,
          reasonCode: "EXECUTION_TIMEOUT",
          externalRef: null,
        });
      }
      const result = outcome.value;
      if (result.status === "SUCCEEDED") {
        this.completed.set(key, { digest: requestDigest, externalRef: result.externalRef });
        this.options.journal?.("execution.completed", {
          key,
          digest: requestDigest,
          externalRef: result.externalRef,
        });
        return this.record("SUCCEEDED", {
          decisionId,
          digest: requestDigest,
          key,
          connectorId: connector.id,
          reasonCode: null,
          externalRef: result.externalRef,
        });
      }
      return this.record("FAILED", {
        decisionId,
        digest: requestDigest,
        key,
        connectorId: connector.id,
        reasonCode: result.reasonCode,
        externalRef: null,
      });
    } catch {
      return this.record("FAILED", {
        decisionId,
        digest: requestDigest,
        key,
        connectorId: connector.id,
        reasonCode: "CONNECTOR_ERROR",
        externalRef: null,
      });
    } finally {
      this.inFlight.delete(key);
    }
  }
}
