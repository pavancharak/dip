import { canonicalize, digestWithDomain, signWithDomain } from "@dip/crypto";
import {
  AuthorityRegistry,
  DipError,
  PROTOCOL_VERSION,
  type AuthorityBody,
  type DelegationRef,
} from "@dip/authority";
import type { KeyObject } from "node:crypto";
import { digestRequest, parseNormalizedRequest, type NormalizedRequest } from "./normalize.js";

/** The authorization engine has exactly two outcomes. No other value is permitted. */
export type AuthorizationResult = "ALLOW" | "DENY";

export const DECISION_DOMAIN = "DIP-DECISION-V1";
export const DECISION_ID_DOMAIN = "DIP-DECISION-ID-V1";
export const MAX_DELEGATION_DEPTH = 8;

export interface EngineSigner {
  readonly keyId: string;
  readonly privateKey: KeyObject;
}

export interface EvaluationContext {
  readonly registry: AuthorityRegistry;
  /** Injected clock. Protocol logic never reads the system time directly. */
  readonly now: () => Date;
  readonly signer: EngineSigner;
}

export interface CheckRecord {
  readonly check: string;
  readonly passed: boolean;
  readonly reasonCode: string | null;
}

export interface DecisionBody {
  readonly decisionId: string;
  readonly requestDigest: string;
  readonly authorityRef: DelegationRef;
  readonly policyRef: { readonly policyId: string; readonly version: number };
  readonly result: AuthorizationResult;
  readonly reasonCodes: string[];
  readonly checks: CheckRecord[];
  readonly evaluatedAt: string;
  readonly protocolVersion: string;
}

export interface SignedDecision {
  readonly body: DecisionBody;
  readonly signingKeyId: string;
  readonly signature: string;
}

function isoSeconds(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}

function subset(child: readonly string[], parent: readonly string[]): boolean {
  return child.every((x) => parent.includes(x));
}

/** Reason a delegated authority exceeds or is not permitted by its parent. Null when within bounds. */
function delegationReason(child: AuthorityBody, parent: AuthorityBody): string | null {
  if (!parent.delegationAllowed) return "DELEGATION_NOT_PERMITTED";
  const exceeds =
    child.organizationId !== parent.organizationId ||
    child.tenantId !== parent.tenantId ||
    child.principal !== parent.principal ||
    child.maxAmountMinor > parent.maxAmountMinor ||
    !subset(child.permittedActions, parent.permittedActions) ||
    !subset(child.currencies, parent.currencies) ||
    (!parent.resourceScope.includes("*") && !subset(child.resourceScope, parent.resourceScope)) ||
    Date.parse(child.validFrom) < Date.parse(parent.validFrom) ||
    Date.parse(child.validUntil) > Date.parse(parent.validUntil);
  return exceeds ? "DELEGATION_EXCEEDS_PARENT" : null;
}

/**
 * Standing of an authority reference: published, signature valid, not revoked,
 * not superseded, inside its validity window, and (if delegated) within its parent.
 * Returns a reason code, or null when the authority is in good standing.
 */
function standing(
  ctx: EvaluationContext,
  ref: DelegationRef,
  nowMs: number,
  depth: number,
): string | null {
  if (depth > MAX_DELEGATION_DEPTH) return "DELEGATION_DEPTH_EXCEEDED";
  const signed = ctx.registry.get(ref.authorityId, ref.version);
  if (!signed) return "AUTHORITY_NOT_FOUND";
  const fault = ctx.registry.verify(signed);
  if (fault) return fault;
  if (ctx.registry.revocationOf(ref.authorityId, ref.version)) return "AUTHORITY_REVOKED";
  if (ctx.registry.latestVersion(ref.authorityId) > ref.version) return "AUTHORITY_SUPERSEDED";
  const b = signed.body;
  if (nowMs < Date.parse(b.validFrom)) return "AUTHORITY_NOT_YET_VALID";
  if (nowMs >= Date.parse(b.validUntil)) return "AUTHORITY_EXPIRED";
  if (b.delegatedFrom !== null) {
    const parentReason = standing(ctx, b.delegatedFrom, nowMs, depth + 1);
    if (parentReason) return parentReason;
    const parent = ctx.registry.get(b.delegatedFrom.authorityId, b.delegatedFrom.version);
    if (!parent) return "AUTHORITY_NOT_FOUND";
    const reason = delegationReason(b, parent.body);
    if (reason) return reason;
  }
  return null;
}

/**
 * Evaluates a normalized request. The result is ALLOW only when every check passes.
 * Malformed input throws. It never yields a decision, and a throw never permits execution.
 */
export function evaluate(input: unknown, ctx: EvaluationContext): SignedDecision {
  const normalized: NormalizedRequest = parseNormalizedRequest(input);
  const { request } = normalized;
  const evaluatedAt = isoSeconds(ctx.now());
  const nowMs = Date.parse(evaluatedAt);
  const checks: CheckRecord[] = [];
  const record = (check: string, passed: boolean, code: string): void => {
    checks.push({ check, passed, reasonCode: passed ? null : code });
  };

  // 1. Request integrity: the digest must match the canonical body.
  const digestOk = digestRequest(request) === normalized.requestDigest;
  record("REQUEST_DIGEST", digestOk, "REQUEST_DIGEST_MISMATCH");

  const authorityRef = request.authorityRef;
  const policyRef = request.policyRef;

  if (digestOk) {
    // 2. Authority standing (existence, signature, revocation, supersession, time, delegation).
    const standingReason = standing(ctx, authorityRef, nowMs, 0);
    record("AUTHORITY_STANDING", standingReason === null, standingReason ?? "");

    if (standingReason === null) {
      const signed = ctx.registry.get(authorityRef.authorityId, authorityRef.version);
      if (!signed)
        throw new DipError("AUTHORITY_NOT_FOUND", "authority vanished during evaluation");
      const a = signed.body;

      record("ORGANIZATION", a.organizationId === request.organizationId, "ORGANIZATION_MISMATCH");
      record("TENANT", a.tenantId === request.tenantId, "TENANT_MISMATCH");
      record(
        "POLICY_VERSION",
        policyRef.policyId === a.policyId && policyRef.version === a.policyVersion,
        "POLICY_VERSION_MISMATCH",
      );
      record(
        "ACTOR",
        request.actor === a.principal || (a.agent !== null && request.actor === a.agent),
        "ACTOR_NOT_AUTHORIZED",
      );
      record("ACTION", a.permittedActions.includes(request.operation), "ACTION_NOT_PERMITTED");
      record(
        "RESOURCE",
        a.resourceScope.includes("*") || a.resourceScope.includes(request.resource),
        "RESOURCE_OUT_OF_SCOPE",
      );

      if (request.amount !== null) {
        record(
          "CURRENCY",
          a.currencies.includes(request.amount.currency),
          "CURRENCY_NOT_PERMITTED",
        );
        record("AMOUNT_LIMIT", request.amount.minor <= a.maxAmountMinor, "AMOUNT_EXCEEDS_LIMIT");
      }

      const approvalRequired =
        (a.approvalAboveMinor !== null &&
          request.amount !== null &&
          request.amount.minor > a.approvalAboveMinor) ||
        a.approvalActions.includes(request.operation);
      if (approvalRequired) {
        // Approval verification is Phase 3. Until it exists, an approval reference cannot satisfy this check.
        record(
          "APPROVAL",
          false,
          request.approvalRef === null ? "APPROVAL_REQUIRED" : "APPROVAL_NOT_VERIFIED",
        );
      }
    } else {
      // Standing failed: request-level checks are not meaningful against an unusable authority.
    }
  }

  const reasonCodes = checks.map((c) => c.reasonCode).filter((c): c is string => c !== null);
  const result: AuthorizationResult = reasonCodes.length === 0 ? "ALLOW" : "DENY";

  const decisionId = digestWithDomain(
    DECISION_ID_DOMAIN,
    canonicalize({
      requestDigest: normalized.requestDigest,
      authorityRef,
      policyRef,
      result,
      evaluatedAt,
    }),
  );
  const body: DecisionBody = {
    decisionId,
    requestDigest: normalized.requestDigest,
    authorityRef,
    policyRef,
    result,
    reasonCodes,
    checks,
    evaluatedAt,
    protocolVersion: PROTOCOL_VERSION,
  };
  const signature = signWithDomain(DECISION_DOMAIN, canonicalize(body), ctx.signer.privateKey);
  return { body, signingKeyId: ctx.signer.keyId, signature };
}
