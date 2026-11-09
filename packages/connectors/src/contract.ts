import type { RequestBody } from "@dip/authorization";
import type { Connector, ConnectorResult } from "@dip/execution";

/**
 * Connector contract. A connector never decides authorization. It is only ever
 * invoked by the execution boundary, after an ALLOW decision for the exact request.
 *
 * Money always comes from the authorized request amount, never from free-form
 * parameters. Parameters that repeat the amount must agree with it.
 */

export interface OutboundRequest {
  readonly method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  readonly url: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: unknown;
}

export interface OutboundResponse {
  readonly status: number;
  readonly body: unknown;
}

/** Transport is injected. Production uses HTTPS; tests use a fake. */
export interface Transport {
  send(request: OutboundRequest & { readonly timeoutMs: number }): Promise<OutboundResponse>;
}

export class ConnectorValidationError extends Error {
  constructor(
    readonly reasonCode: string,
    message: string,
  ) {
    super(message);
    this.name = "ConnectorValidationError";
  }
}

export interface ConnectorDefinition {
  readonly id: string;
  readonly operation: string;
  /** Builds the outbound call, or throws ConnectorValidationError before any network call. */
  build(request: RequestBody): OutboundRequest;
  /** Turns a 2xx response body into the external reference, or null when none is present. */
  reference(body: unknown): string | null;
}

export interface ConnectorOptions {
  readonly transport: Transport;
  readonly timeoutMs: number;
}

export function requireString(params: Record<string, unknown>, key: string): string {
  const v = params[key];
  if (typeof v !== "string" || v.length === 0 || v.length > 256) {
    throw new ConnectorValidationError(
      "INVALID_PARAMETERS",
      `parameter ${key} must be a non-empty string`,
    );
  }
  return v;
}

export function requireAmount(request: RequestBody): { minor: number; currency: string } {
  if (request.amount === null) {
    throw new ConnectorValidationError(
      "AMOUNT_REQUIRED",
      "this operation requires an authorized amount",
    );
  }
  const declared = request.parameters.amountMinor;
  if (declared !== undefined && declared !== request.amount.minor) {
    throw new ConnectorValidationError(
      "AMOUNT_MISMATCH",
      "parameter amount does not match the authorized amount",
    );
  }
  return request.amount;
}

/** Creates a Connector from a definition. Every call carries the idempotency key. */
export function createConnector(def: ConnectorDefinition, options: ConnectorOptions): Connector {
  return {
    id: def.id,
    execute: async (request: RequestBody, idempotencyKey: string): Promise<ConnectorResult> => {
      if (request.operation !== def.operation) {
        return { status: "FAILED", reasonCode: "OPERATION_MISMATCH" };
      }
      let outbound: OutboundRequest;
      try {
        outbound = def.build(request);
      } catch (err) {
        if (err instanceof ConnectorValidationError)
          return { status: "FAILED", reasonCode: err.reasonCode };
        throw err;
      }
      const response = await options.transport.send({
        ...outbound,
        headers: { ...outbound.headers, "Idempotency-Key": idempotencyKey },
        timeoutMs: options.timeoutMs,
      });
      if (response.status >= 200 && response.status < 300) {
        const ref = def.reference(response.body);
        if (ref === null) return { status: "FAILED", reasonCode: "RESPONSE_MISSING_REFERENCE" };
        return { status: "SUCCEEDED", externalRef: ref };
      }
      if (response.status === 429 || response.status >= 500) {
        return { status: "FAILED", reasonCode: "UPSTREAM_TRANSIENT" };
      }
      return { status: "FAILED", reasonCode: `UPSTREAM_${String(response.status)}` };
    },
  };
}

export function idOf(body: unknown): string | null {
  if (typeof body !== "object" || body === null || Array.isArray(body)) return null;
  const id = (body as Record<string, unknown>).id;
  return typeof id === "string" && id.length > 0 ? id : null;
}
