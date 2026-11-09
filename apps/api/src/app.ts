import { DipError } from "@dip/authority";
import type { DipClient } from "@dip/sdk";
import { memoryRateLimiter, type RateLimiter } from "./rate-limit.js";

/**
 * Versioned REST API over DipClient. Handlers are pure request → response
 * functions, so they can be tested without a network. The HTTP adapter lives in http.ts.
 *
 * Authentication: Bearer API keys mapped to principals. Scopes: "admin" for ledger
 * reads, "approver" for approval decisions. Tenant isolation: request and
 * authority operations must match the principal's tenant.
 */

export interface Principal {
  readonly name: string;
  readonly tenantId: string | null;
  readonly scopes: readonly string[];
}

export interface ApiRequest {
  readonly method: string;
  readonly path: string;
  readonly headers: Readonly<Record<string, string | undefined>>;
  readonly body?: unknown;
}

export interface ApiResponse {
  readonly status: number;
  readonly body: unknown;
}

export interface ApiConfig {
  readonly client: DipClient;
  readonly principals: ReadonlyMap<string, Principal>;
  readonly rateLimit: { readonly max: number; readonly windowMs: number };
  readonly clockMs: () => number;
  /** Shared limiter (for example PostgreSQL-backed). Defaults to an in-process limiter. */
  readonly rateLimiter?: RateLimiter;
  /** Called when changes cannot be written. The server should stop; see server.ts. */
  readonly onPersistenceFailure?: (err: unknown) => void;
}

type Handler = (ctx: Context) => Promise<ApiResponse> | ApiResponse;

interface Context {
  readonly params: Readonly<Record<string, string>>;
  readonly query: URLSearchParams;
  readonly body: unknown;
  readonly principal: Principal;
}

export interface RouteInfo {
  readonly method: string;
  readonly path: string;
  readonly auth: "public" | "principal";
  readonly scope?: string;
}

interface Route {
  readonly method: string;
  readonly segments: readonly string[];
  readonly handler: Handler;
  readonly auth: "public" | "principal";
  readonly scope?: string;
}

const MAX_LIST = 100;

function error(status: number, code: string, message: string): ApiResponse {
  return { status, body: { error: code, message } };
}

function asObject(v: unknown): Record<string, unknown> | null {
  return typeof v === "object" && v !== null && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : null;
}

function mapDipError(err: DipError): ApiResponse {
  const code = err.code;
  if (/NOT_FOUND$/.test(code)) return error(404, code, err.message);
  if (/ALREADY|CONFLICT|GAP|DUPLICATE|INVALID_TRANSITION|REPLAYED|IN_PROGRESS/.test(code))
    return error(409, code, err.message);
  if (/SIGNATURE|KEY_|MISMATCH|REVOKED|EXPIRED|NOT_YET|SUPERSEDED|DELEGATION/.test(code))
    return error(422, code, err.message);
  return error(400, code, err.message);
}

export function createApi(config: ApiConfig): {
  handle(req: ApiRequest): Promise<ApiResponse>;
  describeRoutes(): RouteInfo[];
} {
  const client = config.client;
  const limiter: RateLimiter = config.rateLimiter ?? memoryRateLimiter(config.rateLimit.windowMs);

  const routes: Route[] = [
    {
      method: "GET",
      segments: ["v1", "health"],
      auth: "public",
      handler: () => ({ status: 200, body: { status: "ok" } }),
    },

    {
      method: "POST",
      segments: ["v1", "authorities"],
      auth: "principal",
      handler: ({ body, principal }) => {
        const signed = asObject(body);
        const b = signed ? asObject(signed.body) : null;
        if (!b) return error(400, "INVALID_BODY", "body must be a signed authority");
        if (principal.tenantId !== null && b.tenantId !== principal.tenantId) {
          return error(403, "TENANT_FORBIDDEN", "authority belongs to another tenant");
        }
        return { status: 201, body: { authority: client.publishAuthority(body) } };
      },
    },
    {
      method: "GET",
      segments: ["v1", "authorities", ":id"],
      auth: "principal",
      handler: ({ params, query, principal }) => {
        const version = Number(query.get("version") ?? "1");
        const latest = client.latestAuthorityVersion(params.id ?? "");
        const signed = client.getAuthority(params.id ?? "", version);
        if (!signed || latest === 0)
          return error(404, "AUTHORITY_NOT_FOUND", "authority not found");
        if (principal.tenantId !== null && signed.body.tenantId !== principal.tenantId) {
          return error(404, "AUTHORITY_NOT_FOUND", "authority not found");
        }
        return { status: 200, body: { authority: signed, latestVersion: latest } };
      },
    },
    {
      method: "POST",
      segments: ["v1", "authorities", ":id", "revoke"],
      auth: "principal",
      handler: ({ params, body, principal }) => {
        const rev = asObject(body);
        if (!rev || asObject(rev.body)?.authorityId !== params.id) {
          return error(400, "INVALID_BODY", "revocation must name the authority in the path");
        }
        const signed = client.getAuthority(
          params.id ?? "",
          Number(asObject(rev.body)?.version ?? 0),
        );
        if (principal.tenantId !== null && signed && signed.body.tenantId !== principal.tenantId) {
          return error(404, "AUTHORITY_NOT_FOUND", "authority not found");
        }
        client.revokeAuthority(body);
        return { status: 200, body: { revoked: true } };
      },
    },

    {
      method: "POST",
      segments: ["v1", "requests", "normalize"],
      auth: "principal",
      handler: ({ body, principal }) => {
        const normalized = client.normalizeRequest(body);
        if (principal.tenantId !== null && normalized.request.tenantId !== principal.tenantId) {
          return error(403, "TENANT_FORBIDDEN", "request belongs to another tenant");
        }
        return { status: 200, body: normalized };
      },
    },
    {
      method: "POST",
      segments: ["v1", "authorize"],
      auth: "principal",
      handler: async ({ body, principal }) => {
        const normalized = client.normalizeRequest(body);
        if (principal.tenantId !== null && normalized.request.tenantId !== principal.tenantId) {
          return error(403, "TENANT_FORBIDDEN", "request belongs to another tenant");
        }
        const outcome = await client.authorize(normalized);
        return {
          status: 200,
          body: {
            result: outcome.result,
            decisionId: outcome.decision.body.decisionId,
            reasonCodes: outcome.decision.body.reasonCodes,
            decision: outcome.decision,
          },
        };
      },
    },

    {
      method: "POST",
      segments: ["v1", "approvals"],
      auth: "principal",
      scope: "approver",
      handler: ({ body }) => ({ status: 201, body: { approval: client.requestApproval(body) } }),
    },
    {
      method: "GET",
      segments: ["v1", "approvals", ":id"],
      auth: "principal",
      handler: ({ params }) => ({
        status: 200,
        body: { approvalId: params.id, state: client.approvalStatus(params.id ?? "") },
      }),
    },
    approvalDecision("approve", (b) => client.approve(b)),
    approvalDecision("reject", (b) => client.reject(b)),
    approvalDecision("revoke", (b) => client.revokeApproval(b)),

    {
      method: "POST",
      segments: ["v1", "execute"],
      auth: "principal",
      handler: async ({ body, principal }) => {
        const b = asObject(body);
        if (!b || !b.request || !b.decision)
          return error(400, "INVALID_BODY", "body needs request and decision");
        const normalized = client.normalizeRequest(b.request);
        if (principal.tenantId !== null && normalized.request.tenantId !== principal.tenantId) {
          return error(403, "TENANT_FORBIDDEN", "request belongs to another tenant");
        }
        const attempt = await client.execute(normalized, b.decision as never);
        const evidence = await client.record({
          normalized,
          decision: b.decision as never,
          attempt,
        });
        return { status: 200, body: { attempt, evidenceId: evidence.body.evidenceId } };
      },
    },
    {
      method: "GET",
      segments: ["v1", "evidence", ":id"],
      auth: "principal",
      handler: ({ params, principal }) => {
        const found = client.findEvidence(params.id ?? "");
        const owner = client.tenantOfEvidence(params.id ?? "");
        // Another tenant's evidence is reported as not found, so its existence is not revealed.
        const visible = principal.tenantId === null || owner === principal.tenantId;
        return found && visible
          ? { status: 200, body: { evidence: found } }
          : error(404, "EVIDENCE_NOT_FOUND", "evidence not found");
      },
    },
    {
      method: "POST",
      segments: ["v1", "verify"],
      auth: "principal",
      handler: ({ body }) => ({ status: 200, body: client.verifyBundle(body) }),
    },
    {
      method: "GET",
      segments: ["v1", "ledger"],
      auth: "principal",
      scope: "admin",
      handler: ({ query }) => {
        const offset = Math.max(0, Number(query.get("offset") ?? "0") || 0);
        const limit = Math.min(MAX_LIST, Math.max(1, Number(query.get("limit") ?? "20") || 20));
        const lines = client.ledgerLines();
        const page = lines.slice(offset, offset + limit).map((l) => JSON.parse(l) as unknown);
        return { status: 200, body: { entries: page, offset, limit, total: lines.length } };
      },
    },
    {
      method: "POST",
      segments: ["v1", "ledger", "verify"],
      auth: "principal",
      scope: "admin",
      handler: ({ body }) => {
        const b = asObject(body);
        const expectedHead = typeof b?.expectedHead === "string" ? b.expectedHead : undefined;
        return { status: 200, body: client.verifyLedger(expectedHead) };
      },
    },
  ];

  function approvalDecision(action: string, run: (b: never) => unknown): Route {
    return {
      method: "POST",
      segments: ["v1", "approvals", ":id", action],
      auth: "principal",
      scope: "approver",
      handler: ({ params, body }) => {
        const b = asObject(body);
        if (!b || asObject(b.body)?.approvalId !== params.id) {
          return error(400, "INVALID_BODY", "decision must name the approval in the path");
        }
        return { status: 200, body: { approvalId: params.id, state: run(body as never) } };
      },
    };
  }

  function match(
    method: string,
    path: string,
  ): { route: Route; params: Record<string, string> } | "METHOD" | null {
    const parts = path.split("/").filter((p) => p.length > 0);
    let pathMatched = false;
    for (const route of routes) {
      if (route.segments.length !== parts.length) continue;
      const params: Record<string, string> = {};
      let ok = true;
      route.segments.forEach((seg, i) => {
        const part = parts[i] ?? "";
        if (seg.startsWith(":")) params[seg.slice(1)] = decodeURIComponent(part);
        else if (seg !== part) ok = false;
      });
      if (!ok) continue;
      pathMatched = true;
      if (route.method === method) return { route, params };
    }
    return pathMatched ? "METHOD" : null;
  }

  async function rateLimited(name: string): Promise<boolean> {
    const count = await limiter.consume(name, config.clockMs());
    return count > config.rateLimit.max;
  }

  return {
    /** Route table for the OpenAPI description. Contains no handlers. */
    describeRoutes(): RouteInfo[] {
      return routes.map((r) => ({
        method: r.method,
        path: "/" + r.segments.join("/"),
        auth: r.auth,
        ...(r.scope === undefined ? {} : { scope: r.scope }),
      }));
    },
    async handle(req: ApiRequest): Promise<ApiResponse> {
      try {
        const [pathOnly = "/", queryString = ""] = req.path.split("?", 2);
        const matched = match(req.method.toUpperCase(), pathOnly);
        if (matched === null) return error(404, "NOT_FOUND", "no such route");
        if (matched === "METHOD")
          return error(405, "METHOD_NOT_ALLOWED", "method not allowed for this route");

        const { route, params } = matched;
        let principal: Principal = { name: "public", tenantId: null, scopes: [] };
        if (route.auth === "principal") {
          const header = req.headers.authorization ?? req.headers.Authorization ?? "";
          const key = header.startsWith("Bearer ") ? header.slice(7) : "";
          const found = config.principals.get(key);
          if (!found) return error(401, "UNAUTHORIZED", "missing or invalid API key");
          principal = found;
          if (await rateLimited(found.name)) return error(429, "RATE_LIMITED", "too many requests");
          if (route.scope !== undefined && !principal.scopes.includes(route.scope)) {
            return error(403, "FORBIDDEN", `scope ${route.scope} required`);
          }
        }

        const body = req.body;
        if (
          req.method.toUpperCase() === "POST" &&
          route.auth === "principal" &&
          body === undefined
        ) {
          return error(400, "INVALID_BODY", "a JSON body is required");
        }
        // Changes made by the handler are written to the event log before the response
        // is returned, even when the handler fails part-way: nothing is acknowledged
        // unless it is durable, and nothing applied in memory is left unrecorded.
        // Changes are written on both paths, so nothing applied in memory goes unrecorded.
        const persist = async (): Promise<void> => {
          try {
            await config.client.flush();
          } catch (flushErr) {
            config.onPersistenceFailure?.(flushErr);
            throw flushErr;
          }
        };
        let response: ApiResponse;
        try {
          response = await route.handler({
            params,
            query: new URLSearchParams(queryString),
            body,
            principal,
          });
        } catch (handlerErr) {
          await persist();
          throw handlerErr;
        }
        await persist();
        return response;
      } catch (err) {
        if (err instanceof DipError) return mapDipError(err);
        return error(500, "INTERNAL_ERROR", "internal error");
      }
    },
  };
}
