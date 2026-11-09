import { canonicalize, digestWithDomain } from "@dip/crypto";
import {
  DipError,
  MAX_MINOR_UNITS,
  currency,
  exactKeys,
  id,
  int,
  obj,
  PROTOCOL_VERSION,
} from "@dip/authority";

export const REQUEST_DOMAIN = "DIP-REQUEST-V1";

export interface Amount {
  readonly minor: number;
  readonly currency: string;
}

export interface Ref {
  readonly authorityId: string;
  readonly version: number;
}

export interface PolicyRef {
  readonly policyId: string;
  readonly version: number;
}

/**
 * Canonical request body. `amount` is integer minor units. `approvalRef`
 * names an approval record, or is null. Parameters must be canonically encodable.
 */
export interface RequestBody {
  readonly requestId: string;
  readonly transactionId: string;
  readonly organizationId: string;
  readonly tenantId: string;
  readonly actor: string;
  readonly operation: string;
  readonly resource: string;
  readonly amount: Amount | null;
  readonly parameters: Record<string, unknown>;
  readonly authorityRef: Ref;
  readonly policyRef: PolicyRef;
  readonly approvalRef: string | null;
  readonly idempotencyKey: string;
  readonly protocolVersion: string;
}

export interface NormalizedRequest {
  readonly request: RequestBody;
  readonly requestDigest: string;
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
] as const;

const MAX_VERSION = 1_000_000_000;
const DIGEST = /^[0-9a-f]{64}$/;

function ref(v: unknown, path: string): Ref {
  const o = obj(v, path);
  exactKeys(o, ["authorityId", "version"], path);
  return {
    authorityId: id(o.authorityId, `${path}.authorityId`),
    version: int(o.version, `${path}.version`, 1, MAX_VERSION),
  };
}

function policyRef(v: unknown, path: string): PolicyRef {
  const o = obj(v, path);
  exactKeys(o, ["policyId", "version"], path);
  return {
    policyId: id(o.policyId, `${path}.policyId`),
    version: int(o.version, `${path}.version`, 1, MAX_VERSION),
  };
}

/** Validates a raw request object and returns its canonical body. Rejects ambiguous input. */
export function parseRequestBody(input: unknown): RequestBody {
  const o = obj(input, "request");
  exactKeys(o, REQUEST_KEYS, "request");

  let amount: Amount | null = null;
  if (o.amount !== null) {
    const a = obj(o.amount, "request.amount");
    exactKeys(a, ["minor", "currency"], "request.amount");
    amount = {
      minor: int(a.minor, "request.amount.minor", 0, MAX_MINOR_UNITS),
      currency: currency(a.currency, "request.amount.currency"),
    };
  }

  const parameters = obj(o.parameters, "request.parameters");
  try {
    canonicalize(parameters);
  } catch (err) {
    const message = err instanceof Error ? err.message : "invalid parameters";
    throw new DipError("INVALID_PARAMETERS", message);
  }

  if (o.protocolVersion !== PROTOCOL_VERSION) {
    throw new DipError("UNSUPPORTED_PROTOCOL_VERSION", "unsupported protocol version");
  }

  return {
    requestId: id(o.requestId, "request.requestId"),
    transactionId: id(o.transactionId, "request.transactionId"),
    organizationId: id(o.organizationId, "request.organizationId"),
    tenantId: id(o.tenantId, "request.tenantId"),
    actor: id(o.actor, "request.actor"),
    operation: id(o.operation, "request.operation"),
    resource: id(o.resource, "request.resource"),
    amount,
    parameters,
    authorityRef: ref(o.authorityRef, "request.authorityRef"),
    policyRef: policyRef(o.policyRef, "request.policyRef"),
    approvalRef: o.approvalRef === null ? null : id(o.approvalRef, "request.approvalRef"),
    idempotencyKey: id(o.idempotencyKey, "request.idempotencyKey"),
    protocolVersion: PROTOCOL_VERSION,
  };
}

/**
 * Digest over the request content. `approvalRef` is excluded: an approval must
 * be created for the content before its reference can exist, so the reference
 * cannot be part of the content it approves. Any change to the content still
 * changes the digest and invalidates the approval.
 */
export function digestRequest(body: RequestBody): string {
  const content: Record<string, unknown> = { ...body };
  delete content.approvalRef;
  return digestWithDomain(REQUEST_DOMAIN, canonicalize(content));
}

export function normalizeRequest(input: unknown): NormalizedRequest {
  const body = parseRequestBody(input);
  return { request: body, requestDigest: digestRequest(body) };
}

/** Accepts only the shape produced by normalizeRequest. Digest correctness is checked by the engine. */
export function parseNormalizedRequest(input: unknown): NormalizedRequest {
  const o = obj(input, "normalizedRequest");
  exactKeys(o, ["request", "requestDigest"], "normalizedRequest");
  if (typeof o.requestDigest !== "string" || !DIGEST.test(o.requestDigest)) {
    throw new DipError(
      "INVALID_FIELD",
      "normalizedRequest.requestDigest must be a SHA-256 hex digest",
    );
  }
  return { request: parseRequestBody(o.request), requestDigest: o.requestDigest };
}
