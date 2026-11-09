import {
  AuthorityRegistry,
  DipError,
  TrustRootSet,
  parseAuthorityBody,
  type AuthorityBody,
  type SignedAuthority,
  type TrustRoot,
} from "@dip/authority";
import {
  ApprovalStore,
  type ApprovalBinding,
  type ApprovalState,
  type SignedApprovalDecision,
} from "@dip/approval";
import {
  digestRequest,
  evaluate,
  normalizeRequest,
  type EvaluationContext,
  type NormalizedRequest,
  type SignedDecision,
} from "@dip/authorization";
import { ExecutionBoundary, type Connector, type ExecutionAttempt } from "@dip/execution";
import { EvidenceLedger, draftFrom, type VerificationReport } from "@dip/ledger";
import { parseSignedEvidence, type SignedEvidence } from "@dip/evidence";
import { verifyBundle, type VerificationResult } from "@dip/verifier";
import type { KeyObject } from "node:crypto";

/** The only authorization outcomes the SDK exposes. */
export type AuthorizationResult = "ALLOW" | "DENY";

export interface Signer {
  readonly keyId: string;
  readonly privateKey: KeyObject;
}

export interface DipClientConfig {
  /** Every trusted public key: issuers, engine, evidence signer, approvers. */
  readonly trustRoots: readonly TrustRoot[];
  readonly engine: Signer;
  readonly evidenceSigner: Signer;
  readonly connectors: ReadonlyMap<string, Connector>;
  readonly now: () => Date;
  readonly maxDecisionAgeSeconds?: number;
  readonly executionTimeoutMs?: number;
}

export interface AuthorizationOutcome {
  readonly result: AuthorizationResult;
  readonly decision: SignedDecision;
}

export interface RecordInput {
  readonly normalized: NormalizedRequest;
  readonly decision: SignedDecision;
  readonly attempt: ExecutionAttempt | null;
}

function actionOf(input: unknown): string | undefined {
  if (typeof input !== "object" || input === null || !("body" in input)) return undefined;
  const body: unknown = (input as { body: unknown }).body;
  if (typeof body !== "object" || body === null || !("action" in body)) return undefined;
  const action: unknown = (body as { action: unknown }).action;
  return typeof action === "string" ? action : undefined;
}

function secondsIso(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}

/**
 * Developer-facing client. Authorization returns only ALLOW or DENY. Approval
 * states are returned only from approval methods, and approvals never authorize.
 */
export class DipClient {
  private readonly trust = new TrustRootSet();
  private readonly registry: AuthorityRegistry;
  private readonly approvals: ApprovalStore;
  private readonly ctx: EvaluationContext;
  private readonly boundary: ExecutionBoundary;
  private readonly ledger: EvidenceLedger;
  /** Service-side index: which tenant each evidence record belongs to. Not part of the signed record. */
  private readonly evidenceTenants = new Map<string, string>();

  constructor(private readonly config: DipClientConfig) {
    for (const root of config.trustRoots) this.trust.add(root);
    this.registry = new AuthorityRegistry(this.trust);
    this.approvals = new ApprovalStore(this.trust);
    this.ctx = {
      registry: this.registry,
      now: config.now,
      signer: { keyId: config.engine.keyId, privateKey: config.engine.privateKey },
      approvals: this.approvals,
    };
    this.boundary = new ExecutionBoundary({
      trust: this.trust,
      connectors: config.connectors,
      now: config.now,
      maxDecisionAgeSeconds: config.maxDecisionAgeSeconds ?? 300,
      timeoutMs: config.executionTimeoutMs ?? 5000,
      authorityRecheck: (request) => {
        // Re-authorize against current authority state. A revoked, expired or superseded
        // authority stops execution even when the original decision was ALLOW.
        const fresh = evaluate(normalizeRequest(request), this.ctx);
        return fresh.body.result === "ALLOW"
          ? null
          : (fresh.body.reasonCodes[0] ?? "AUTHORIZATION_DENIED");
      },
      approvalRecheck: (request) =>
        this.approvals.verifyFor(
          request.approvalRef ?? "",
          {
            organizationId: request.organizationId,
            requestDigest: digestRequest(request),
            authorityRef: request.authorityRef,
            policyRef: request.policyRef,
            approverKeyIds: this.approverKeysFor(
              request.authorityRef.authorityId,
              request.authorityRef.version,
            ),
          },
          config.now(),
        ),
    });
    this.ledger = new EvidenceLedger(this.trust, {
      keyId: config.evidenceSigner.keyId,
      privateKey: config.evidenceSigner.privateKey,
    });
  }

  // Authority declarations

  createAuthorityDeclaration(input: unknown): AuthorityBody {
    return parseAuthorityBody(input);
  }

  publishAuthority(signed: unknown): AuthorityBody {
    return this.registry.publish(signed).body;
  }

  revokeAuthority(revocation: unknown): void {
    this.registry.revoke(revocation);
  }

  getAuthority(authorityId: string, version: number): SignedAuthority | undefined {
    return this.registry.get(authorityId, version);
  }

  latestAuthorityVersion(authorityId: string): number {
    return this.registry.latestVersion(authorityId);
  }

  // Requests and authorization

  normalizeRequest(input: unknown): NormalizedRequest {
    return normalizeRequest(input);
  }

  authorize(normalized: NormalizedRequest): AuthorizationOutcome {
    const decision = evaluate(normalized, this.ctx);
    return { result: decision.body.result, decision };
  }

  // Approvals (workflow states only; never authorization outcomes)

  requestApproval(binding: unknown): ApprovalBinding {
    return this.approvals.request(binding, this.config.now());
  }

  approvalStatus(approvalId: string): ApprovalState {
    return this.approvals.status(approvalId, this.config.now());
  }

  approve(signed: SignedApprovalDecision): ApprovalState {
    return this.decideWith("APPROVE", signed);
  }

  reject(signed: SignedApprovalDecision): ApprovalState {
    return this.decideWith("REJECT", signed);
  }

  revokeApproval(signed: SignedApprovalDecision): ApprovalState {
    return this.decideWith("REVOKE", signed);
  }

  private decideWith(expected: string, signed: SignedApprovalDecision): ApprovalState {
    const action = actionOf(signed);
    if (action !== expected) {
      throw new DipError(
        "APPROVAL_ACTION_MISMATCH",
        `expected ${expected}, received ${action ?? "none"}`,
      );
    }
    return this.approvals.decide(signed, this.config.now());
  }

  // Execution and evidence

  execute(normalized: NormalizedRequest, decision: SignedDecision): Promise<ExecutionAttempt> {
    return this.boundary.execute(normalized, decision);
  }

  record(input: RecordInput): SignedEvidence {
    const sequence = this.ledger.size() + 1;
    const evidenceId = `ev-${String(sequence).padStart(8, "0")}`;
    this.evidenceTenants.set(evidenceId, input.normalized.request.tenantId);
    return this.ledger.append(
      draftFrom({
        evidenceId,
        transactionId: input.normalized.request.transactionId,
        recordedAt: secondsIso(this.config.now()),
        normalized: input.normalized,
        decision: input.decision,
        attempt: input.attempt,
      }),
    );
  }

  evidenceAt(index: number): SignedEvidence | undefined {
    const line = this.ledger.export()[index];
    return line === undefined ? undefined : parseSignedEvidence(JSON.parse(line));
  }

  tenantOfEvidence(evidenceId: string): string | undefined {
    return this.evidenceTenants.get(evidenceId);
  }

  findEvidence(evidenceId: string): SignedEvidence | undefined {
    for (const line of this.ledger.export()) {
      const signed = parseSignedEvidence(JSON.parse(line));
      if (signed.body.evidenceId === evidenceId) return signed;
    }
    return undefined;
  }

  ledgerLines(): string[] {
    return this.ledger.export();
  }

  ledgerSize(): number {
    return this.ledger.size();
  }

  ledgerHead(): string {
    return this.ledger.head();
  }

  verifyLedger(expectedHead?: string): VerificationReport {
    return this.ledger.verify(expectedHead);
  }

  /** Independent verification of an exported bundle against this client's trust roots. */
  verifyBundle(bundle: unknown): VerificationResult {
    return verifyBundle(bundle, this.config.trustRoots);
  }

  // Internal helper used by the execution-time approval recheck.

  private approverKeysFor(authorityId: string, version: number): string[] {
    const signed = this.registry.get(authorityId, version);
    return signed ? [...signed.body.approverKeyIds] : [];
  }
}
