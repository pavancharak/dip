import {
  DipError,
  bool,
  currency,
  exactKeys,
  id,
  int,
  list,
  MAX_MINOR_UNITS,
  obj,
  time,
} from "./validate.js";
import { PROTOCOL_VERSION } from "./version.js";

export interface DelegationRef {
  readonly authorityId: string;
  readonly version: number;
}

/**
 * Authority declaration body. Money is integer minor units (for INR, paise).
 * `validUntil` is exclusive. Each version is immutable once published.
 */
export interface AuthorityBody {
  readonly authorityId: string;
  readonly version: number;
  readonly organizationId: string;
  readonly tenantId: string;
  readonly issuer: string;
  readonly principal: string;
  /** Agent acting under the principal's authority, or null. */
  readonly agent: string | null;
  readonly permittedActions: string[];
  /** Resource identifiers, or exactly ["*"]. */
  readonly resourceScope: string[];
  readonly maxAmountMinor: number;
  readonly currencies: string[];
  /** Amounts strictly above this need approval. Null disables amount-based approval. */
  readonly approvalAboveMinor: number | null;
  readonly approvalActions: string[];
  /** Approver signing keys allowed to approve this authority's requests. */
  readonly approverKeyIds: string[];
  readonly validFrom: string;
  readonly validUntil: string;
  readonly delegatedFrom: DelegationRef | null;
  readonly delegationAllowed: boolean;
  readonly policyId: string;
  readonly policyVersion: number;
  readonly protocolVersion: string;
  readonly signatureAlgorithm: "Ed25519";
  readonly signingKeyId: string;
}

const BODY_KEYS = [
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
] as const;

const MAX_VERSION = 1_000_000_000;

function resourceId(value: unknown, path: string): string {
  return value === "*" ? "*" : id(value, path);
}

export function parseAuthorityBody(input: unknown): AuthorityBody {
  const o = obj(input, "authority");
  exactKeys(o, BODY_KEYS, "authority");

  const resourceScope = list(o.resourceScope, "authority.resourceScope", resourceId);
  if (resourceScope.includes("*") && resourceScope.length !== 1) {
    throw new DipError("INVALID_FIELD", 'authority.resourceScope: "*" must be the only entry');
  }

  const validFrom = time(o.validFrom, "authority.validFrom");
  const validUntil = time(o.validUntil, "authority.validUntil");
  if (Date.parse(validFrom) >= Date.parse(validUntil)) {
    throw new DipError("INVALID_FIELD", "authority.validFrom must be before validUntil");
  }

  let delegatedFrom: DelegationRef | null = null;
  if (o.delegatedFrom !== null) {
    const d = obj(o.delegatedFrom, "authority.delegatedFrom");
    exactKeys(d, ["authorityId", "version"], "authority.delegatedFrom");
    delegatedFrom = {
      authorityId: id(d.authorityId, "authority.delegatedFrom.authorityId"),
      version: int(d.version, "authority.delegatedFrom.version", 1, MAX_VERSION),
    };
  }

  if (o.protocolVersion !== PROTOCOL_VERSION) {
    throw new DipError("UNSUPPORTED_PROTOCOL_VERSION", "unsupported protocol version");
  }
  if (o.signatureAlgorithm !== "Ed25519") {
    throw new DipError("UNSUPPORTED_ALGORITHM", "signatureAlgorithm must be Ed25519");
  }

  return {
    authorityId: id(o.authorityId, "authority.authorityId"),
    version: int(o.version, "authority.version", 1, MAX_VERSION),
    organizationId: id(o.organizationId, "authority.organizationId"),
    tenantId: id(o.tenantId, "authority.tenantId"),
    issuer: id(o.issuer, "authority.issuer"),
    principal: id(o.principal, "authority.principal"),
    agent: o.agent === null ? null : id(o.agent, "authority.agent"),
    permittedActions: list(o.permittedActions, "authority.permittedActions", id),
    resourceScope,
    maxAmountMinor: int(o.maxAmountMinor, "authority.maxAmountMinor", 0, MAX_MINOR_UNITS),
    currencies: list(o.currencies, "authority.currencies", currency),
    approvalAboveMinor:
      o.approvalAboveMinor === null
        ? null
        : int(o.approvalAboveMinor, "authority.approvalAboveMinor", 0, MAX_MINOR_UNITS),
    approvalActions: list(o.approvalActions, "authority.approvalActions", id),
    approverKeyIds: list(o.approverKeyIds, "authority.approverKeyIds", id),
    validFrom,
    validUntil,
    delegatedFrom,
    delegationAllowed: bool(o.delegationAllowed, "authority.delegationAllowed"),
    policyId: id(o.policyId, "authority.policyId"),
    policyVersion: int(o.policyVersion, "authority.policyVersion", 1, MAX_VERSION),
    protocolVersion: PROTOCOL_VERSION,
    signatureAlgorithm: "Ed25519",
    signingKeyId: id(o.signingKeyId, "authority.signingKeyId"),
  };
}
