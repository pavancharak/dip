import { canonicalize, signWithDomain, verifyWithDomain } from "@dip/crypto";
import { DipError, exactKeys, id, obj, time, type TrustRootSet } from "@dip/authority";
import type { KeyObject } from "node:crypto";

/**
 * Approval is a business workflow, not an authorization outcome. Its states are
 * never returned by the authorization engine as ALLOW or DENY. The engine only
 * reads whether an approval is currently APPROVED and bound to the exact request.
 */
export const APPROVAL_DECISION_DOMAIN = "DIP-APPROVAL-DECISION-V1";
const DIGEST = /^[0-9a-f]{64}$/;

export type ApprovalState = "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED" | "REVOKED";
export type ApprovalAction = "APPROVE" | "REJECT" | "REVOKE";

export interface ApprovalBinding {
  readonly approvalId: string;
  readonly organizationId: string;
  readonly requestDigest: string;
  readonly authorityRef: { readonly authorityId: string; readonly version: number };
  readonly policyRef: { readonly policyId: string; readonly version: number };
  readonly approverKeyId: string;
  readonly requestedAt: string;
  readonly expiresAt: string;
}

export interface ApprovalDecisionBody {
  readonly approvalId: string;
  readonly action: ApprovalAction;
  readonly approverKeyId: string;
  readonly decidedAt: string;
}

export interface SignedApprovalDecision {
  readonly body: ApprovalDecisionBody;
  readonly signature: string;
}

export interface ApprovalEvent {
  readonly action: "REQUEST" | "EXPIRE" | ApprovalAction;
  readonly at: string;
  readonly stateAfter: ApprovalState;
}

/** What the authorization engine requires an approval to be bound to. */
export interface ApprovalExpectation {
  readonly organizationId: string;
  readonly requestDigest: string;
  readonly authorityRef: { readonly authorityId: string; readonly version: number };
  readonly policyRef: { readonly policyId: string; readonly version: number };
  readonly approverKeyIds: readonly string[];
}

interface StoredApproval {
  readonly binding: ApprovalBinding;
  state: ApprovalState;
  readonly events: ApprovalEvent[];
}

const BINDING_KEYS = [
  "approvalId",
  "organizationId",
  "requestDigest",
  "authorityRef",
  "policyRef",
  "approverKeyId",
  "requestedAt",
  "expiresAt",
] as const;

function isoSeconds(ms: number): string {
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");
}

function ref(v: unknown, path: string): { authorityId: string; version: number } {
  const o = obj(v, path);
  exactKeys(o, ["authorityId", "version"], path);
  const version = o.version;
  if (typeof version !== "number" || !Number.isSafeInteger(version) || version < 1) {
    throw new DipError("INVALID_FIELD", `${path}.version must be a positive integer`);
  }
  return { authorityId: id(o.authorityId, `${path}.authorityId`), version };
}

function policy(v: unknown, path: string): { policyId: string; version: number } {
  const o = obj(v, path);
  exactKeys(o, ["policyId", "version"], path);
  const version = o.version;
  if (typeof version !== "number" || !Number.isSafeInteger(version) || version < 1) {
    throw new DipError("INVALID_FIELD", `${path}.version must be a positive integer`);
  }
  return { policyId: id(o.policyId, `${path}.policyId`), version };
}

export function parseApprovalBinding(input: unknown): ApprovalBinding {
  const o = obj(input, "approval");
  exactKeys(o, BINDING_KEYS, "approval");
  if (typeof o.requestDigest !== "string" || !DIGEST.test(o.requestDigest)) {
    throw new DipError("INVALID_FIELD", "approval.requestDigest must be a SHA-256 hex digest");
  }
  const requestedAt = time(o.requestedAt, "approval.requestedAt");
  const expiresAt = time(o.expiresAt, "approval.expiresAt");
  if (Date.parse(expiresAt) <= Date.parse(requestedAt)) {
    throw new DipError("INVALID_FIELD", "approval.expiresAt must be after requestedAt");
  }
  return {
    approvalId: id(o.approvalId, "approval.approvalId"),
    organizationId: id(o.organizationId, "approval.organizationId"),
    requestDigest: o.requestDigest,
    authorityRef: ref(o.authorityRef, "approval.authorityRef"),
    policyRef: policy(o.policyRef, "approval.policyRef"),
    approverKeyId: id(o.approverKeyId, "approval.approverKeyId"),
    requestedAt,
    expiresAt,
  };
}

function parseDecision(input: unknown): SignedApprovalDecision {
  const o = obj(input, "approvalDecision");
  exactKeys(o, ["body", "signature"], "approvalDecision");
  if (typeof o.signature !== "string") {
    throw new DipError("INVALID_FIELD", "approvalDecision.signature must be a string");
  }
  const b = obj(o.body, "approvalDecision.body");
  exactKeys(b, ["approvalId", "action", "approverKeyId", "decidedAt"], "approvalDecision.body");
  if (b.action !== "APPROVE" && b.action !== "REJECT" && b.action !== "REVOKE") {
    throw new DipError(
      "INVALID_FIELD",
      "approvalDecision.body.action must be APPROVE, REJECT or REVOKE",
    );
  }
  return {
    body: {
      approvalId: id(b.approvalId, "approvalDecision.body.approvalId"),
      action: b.action,
      approverKeyId: id(b.approverKeyId, "approvalDecision.body.approverKeyId"),
      decidedAt: time(b.decidedAt, "approvalDecision.body.decidedAt"),
    },
    signature: o.signature,
  };
}

export function signApprovalDecision(
  body: ApprovalDecisionBody,
  privateKey: KeyObject,
): SignedApprovalDecision {
  return {
    body,
    signature: signWithDomain(APPROVAL_DECISION_DOMAIN, canonicalize(body), privateKey),
  };
}

/** In-memory approval workflow with explicit, signed, time-bounded transitions. */
export class ApprovalStore {
  private readonly records = new Map<string, StoredApproval>();

  constructor(private readonly trust: TrustRootSet) {}

  request(input: unknown, now: Date): ApprovalBinding {
    const binding = parseApprovalBinding(input);
    const nowMs = now.getTime();
    if (Date.parse(binding.requestedAt) > nowMs) {
      throw new DipError("INVALID_FIELD", "approval.requestedAt is in the future");
    }
    if (this.records.has(binding.approvalId)) {
      throw new DipError(
        "APPROVAL_ALREADY_EXISTS",
        `approval ${binding.approvalId} already exists`,
      );
    }
    const key = this.trust.lookup(binding.approverKeyId);
    if (!key) throw new DipError("APPROVER_KEY_UNKNOWN", "approver key is not trusted");
    if (key.status === "REVOKED")
      throw new DipError("APPROVER_KEY_REVOKED", "approver key is revoked");
    this.records.set(binding.approvalId, {
      binding,
      state: "PENDING",
      events: [{ action: "REQUEST", at: binding.requestedAt, stateAfter: "PENDING" }],
    });
    return binding;
  }

  /** Effective state at `now`. Pure: does not change the stored record. */
  status(approvalId: string, now: Date): ApprovalState {
    const rec = this.records.get(approvalId);
    if (!rec) throw new DipError("APPROVAL_NOT_FOUND", `approval ${approvalId} not found`);
    return this.effective(rec, now.getTime());
  }

  private effective(rec: StoredApproval, nowMs: number): ApprovalState {
    if (
      (rec.state === "PENDING" || rec.state === "APPROVED") &&
      nowMs >= Date.parse(rec.binding.expiresAt)
    ) {
      return "EXPIRED";
    }
    return rec.state;
  }

  decide(input: unknown, now: Date): ApprovalState {
    const signed = parseDecision(input);
    const rec = this.records.get(signed.body.approvalId);
    if (!rec)
      throw new DipError("APPROVAL_NOT_FOUND", `approval ${signed.body.approvalId} not found`);
    const nowMs = now.getTime();

    if (signed.body.approverKeyId !== rec.binding.approverKeyId) {
      throw new DipError("APPROVER_NOT_AUTHORIZED", "decision key is not the designated approver");
    }
    const key = this.trust.lookup(rec.binding.approverKeyId);
    if (!key) throw new DipError("APPROVER_KEY_UNKNOWN", "approver key is not trusted");
    if (key.status === "REVOKED")
      throw new DipError("APPROVER_KEY_REVOKED", "approver key is revoked");
    const ok = verifyWithDomain(
      APPROVAL_DECISION_DOMAIN,
      canonicalize(signed.body),
      signed.signature,
      key.publicKey,
    );
    if (!ok)
      throw new DipError("APPROVAL_SIGNATURE_INVALID", "approval decision signature is invalid");
    if (Date.parse(signed.body.decidedAt) > nowMs) {
      throw new DipError("INVALID_FIELD", "decidedAt is in the future");
    }

    if (this.effective(rec, nowMs) === "EXPIRED" && rec.state !== "EXPIRED") {
      rec.state = "EXPIRED";
      rec.events.push({ action: "EXPIRE", at: rec.binding.expiresAt, stateAfter: "EXPIRED" });
    }
    if (rec.state === "EXPIRED") throw new DipError("APPROVAL_EXPIRED", "approval has expired");

    const from = rec.state;
    const action = signed.body.action;
    let next: ApprovalState;
    if (action === "APPROVE" && from === "PENDING") next = "APPROVED";
    else if (action === "REJECT" && from === "PENDING") next = "REJECTED";
    else if (action === "REVOKE" && (from === "PENDING" || from === "APPROVED")) next = "REVOKED";
    else
      throw new DipError(
        "APPROVAL_INVALID_TRANSITION",
        `cannot ${action} an approval in state ${from}`,
      );

    rec.state = next;
    rec.events.push({ action, at: isoSeconds(nowMs), stateAfter: next });
    return next;
  }

  /** Returns null when the approval satisfies `expected` now; otherwise a reason code. */
  verifyFor(approvalId: string, expected: ApprovalExpectation, now: Date): string | null {
    const rec = this.records.get(approvalId);
    if (!rec) return "APPROVAL_NOT_FOUND";
    const b = rec.binding;
    const bound =
      b.organizationId === expected.organizationId &&
      b.requestDigest === expected.requestDigest &&
      b.authorityRef.authorityId === expected.authorityRef.authorityId &&
      b.authorityRef.version === expected.authorityRef.version &&
      b.policyRef.policyId === expected.policyRef.policyId &&
      b.policyRef.version === expected.policyRef.version;
    if (!bound) return "APPROVAL_BINDING_MISMATCH";
    if (!expected.approverKeyIds.includes(b.approverKeyId)) return "APPROVER_NOT_AUTHORIZED";
    const key = this.trust.lookup(b.approverKeyId);
    if (!key || key.status === "REVOKED") return "APPROVER_KEY_REVOKED";
    switch (this.effective(rec, now.getTime())) {
      case "APPROVED":
        return null;
      case "PENDING":
        return "APPROVAL_PENDING";
      case "REJECTED":
        return "APPROVAL_REJECTED";
      case "EXPIRED":
        return "APPROVAL_EXPIRED";
      case "REVOKED":
        return "APPROVAL_REVOKED";
    }
  }

  history(approvalId: string): readonly ApprovalEvent[] {
    const rec = this.records.get(approvalId);
    if (!rec) throw new DipError("APPROVAL_NOT_FOUND", `approval ${approvalId} not found`);
    return [...rec.events];
  }
}
