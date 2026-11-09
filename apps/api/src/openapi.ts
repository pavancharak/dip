import type { RouteInfo } from "./app.js";

/**
 * Builds the OpenAPI 3.0 description from the same route table the server uses,
 * so the document cannot list an endpoint the server lacks, or omit one it has.
 */
const SUMMARIES: Record<string, string> = {
  "GET /v1/health": "Liveness check",
  "POST /v1/authorities": "Publish a signed authority declaration (immutable version)",
  "GET /v1/authorities/{id}": "Read a published authority version",
  "POST /v1/authorities/{id}/revoke": "Publish a signed revocation",
  "POST /v1/requests/normalize": "Canonicalize a request and compute its digest",
  "POST /v1/authorize": "Authorize a request: result is ALLOW or DENY",
  "POST /v1/approvals": "Request an approval (approver scope)",
  "GET /v1/approvals/{id}": "Read an approval's workflow state",
  "POST /v1/approvals/{id}/approve": "Record a signed APPROVE decision (approver scope)",
  "POST /v1/approvals/{id}/reject": "Record a signed REJECT decision (approver scope)",
  "POST /v1/approvals/{id}/revoke": "Record a signed REVOKE decision (approver scope)",
  "POST /v1/execute": "Execute through the protected boundary; records evidence",
  "GET /v1/evidence/{id}": "Read an evidence record visible to the caller's tenant",
  "POST /v1/verify": "Verify an exported evidence bundle",
  "GET /v1/ledger": "List evidence entries (admin scope)",
  "POST /v1/ledger/verify": "Verify the server's evidence ledger (admin scope)",
};

const ERRORS = {
  "400": "Invalid body or request",
  "401": "Missing or invalid API key",
  "403": "Forbidden: scope or tenant",
  "404": "Not found",
  "405": "Method not allowed",
  "409": "Conflict (duplicate, invalid transition, replay)",
  "422": "Rejected by protocol checks (signature, binding, state)",
  "429": "Rate limited",
  "500": "Internal error",
};

function toOpenApiPath(path: string): string {
  return path.replace(/:([A-Za-z]+)/g, "{$1}");
}

export function buildOpenApi(
  routes: readonly RouteInfo[],
  version: string,
): Record<string, unknown> {
  const paths: Record<string, Record<string, unknown>> = {};
  for (const r of routes) {
    const path = toOpenApiPath(r.path);
    const method = r.method.toLowerCase();
    const key = `${r.method} ${path}`;
    const params = [...path.matchAll(/\{([A-Za-z]+)\}/g)].map((m) => ({
      name: m[1],
      in: "path",
      required: true,
      schema: { type: "string" },
    }));
    const responses: Record<string, unknown> = {
      "200": { description: "OK" },
      ...(r.method === "POST" && r.path !== "/v1/health"
        ? { "201": { description: "Created (where applicable)" } }
        : {}),
    };
    for (const [code, text] of Object.entries(ERRORS)) {
      if (r.auth === "public" && code === "401") continue;
      responses[code] = {
        description: text,
        content: { "application/json": { schema: { $ref: "#/components/schemas/Error" } } },
      };
    }
    const operation: Record<string, unknown> = {
      operationId: `${method}${path.replace(/[^A-Za-z0-9]+/g, "_")}`,
      summary: SUMMARIES[key] ?? key,
      tags: [path.split("/")[2] ?? "root"],
      parameters: [
        ...params,
        ...(path === "/v1/authorities/{id}"
          ? [
              {
                name: "version",
                in: "query",
                required: false,
                schema: { type: "integer", minimum: 1 },
              },
            ]
          : []),
        ...(path === "/v1/ledger"
          ? [
              {
                name: "offset",
                in: "query",
                required: false,
                schema: { type: "integer", minimum: 0 },
              },
              {
                name: "limit",
                in: "query",
                required: false,
                schema: { type: "integer", minimum: 1, maximum: 100 },
              },
            ]
          : []),
      ],
      responses,
      ...(r.auth === "public" ? { security: [] } : { security: [{ bearerAuth: [] }] }),
      ...(r.method === "POST"
        ? {
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    description: "See the protocol specification for this request's fields.",
                  },
                },
              },
            },
          }
        : {}),
      ...(r.scope === undefined ? {} : { "x-required-scope": r.scope }),
    };
    paths[path] = { ...(paths[path] ?? {}), [method]: operation };
  }
  return {
    openapi: "3.0.3",
    info: {
      title: "DIP REST API",
      version,
      description:
        "Decision Integrity Protocol API. Authorization results are ALLOW or DENY only. Approval states are workflow states and never authorization results.",
    },
    servers: [{ url: "http://localhost:3000" }],
    paths,
    components: {
      securitySchemes: {
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          description: "API key configured for the server.",
        },
      },
      schemas: {
        Error: {
          type: "object",
          required: ["error", "message"],
          properties: {
            error: { type: "string", description: "Stable error code" },
            message: { type: "string" },
          },
        },
      },
    },
  };
}
