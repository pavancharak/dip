export {
  DipClient,
  type AuthorizationOutcome,
  type AuthorizationResult,
  type DipClientConfig,
  type RecordInput,
  type Signer,
} from "./client.js";
export { DipError, type AuthorityBody, type SignedAuthority, type TrustRoot } from "@dip/authority";
export { signAuthority, signRevocation, type RevocationBody } from "@dip/authority";
export {
  signApprovalDecision,
  type ApprovalBinding,
  type ApprovalState,
  type SignedApprovalDecision,
} from "@dip/approval";
export type { NormalizedRequest, RequestBody, SignedDecision } from "@dip/authorization";
export type { ExecutionAttempt, Connector, ConnectorResult } from "@dip/execution";
export type { SignedEvidence } from "@dip/evidence";
export type { VerificationReport } from "@dip/ledger";
export type { VerificationResult, Verdict } from "@dip/verifier";
export { generateSigningKeyPair, exportEd25519PublicJwk, type Ed25519PublicJwk } from "@dip/crypto";
