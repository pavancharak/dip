# 7. Use the HTTP API

This guide covers calling the DIP API directly. The `dip` CLI and the SDK wrap these same calls.

## Base URL and headers

```bash
export DIP_URL="https://<your-dip-server>"
export DIP_API_KEY="<your-api-key>"
```

Send JSON, and authenticate with a Bearer key:

```
Authorization: Bearer <api-key>
Content-Type: application/json
```

The full description of every route is in `docs/api/openapi.json`. Load it in any OpenAPI viewer.

## Keys and scopes

Each API key belongs to one principal, with one tenant, and carries zero or more scopes.

| Scope      | Lets the key                                                                                           |
| ---------- | ------------------------------------------------------------------------------------------------------ |
| (none)     | Publish and read authorities, normalize and authorize requests, execute, read evidence, verify bundles |
| `approver` | Request approvals, and approve, reject or revoke them                                                  |
| `admin`    | Read the ledger and verify it                                                                          |

Keys are tenant-bound. A request for another tenant's data is refused with `TENANT_FORBIDDEN`, and evidence from another tenant appears as `EVIDENCE_NOT_FOUND`, so existence is not revealed.

## Routes

| Method and path                   | Purpose                                                            |
| --------------------------------- | ------------------------------------------------------------------ |
| `GET /v1/health`                  | Liveness. Public, no key needed. Returns `{"status":"ok"}`         |
| `POST /v1/authorities`            | Publish a signed authority                                         |
| `GET /v1/authorities/:id`         | Read a published authority                                         |
| `POST /v1/authorities/:id/revoke` | Publish a signed revocation                                        |
| `POST /v1/requests/normalize`     | Canonicalize a request and compute its digest                      |
| `POST /v1/authorize`              | Authorize a request. Returns ALLOW or DENY                         |
| `POST /v1/approvals`              | Request an approval (`approver` scope)                             |
| `GET /v1/approvals/:id`           | Read an approval's state                                           |
| `POST /v1/approvals/:id/approve`  | Approve (`approver` scope)                                         |
| `POST /v1/approvals/:id/reject`   | Reject (`approver` scope)                                          |
| `POST /v1/approvals/:id/revoke`   | Revoke an approval (`approver` scope)                              |
| `POST /v1/execute`                | Execute an authorized request with its decision                    |
| `GET /v1/evidence/:id`            | Read one evidence record                                           |
| `POST /v1/verify`                 | Verify an exported bundle                                          |
| `GET /v1/ledger`                  | List evidence (`admin` scope)                                      |
| `POST /v1/ledger/verify`          | Verify the ledger (`admin` scope). Body may include `expectedHead` |

## A complete call

```bash
curl -sS -X POST "$DIP_URL/v1/authorize" \
  -H "Authorization: Bearer $DIP_API_KEY" \
  -H "Content-Type: application/json" \
  --data @request.json
```

A successful call returns `200` with `result` set to `ALLOW` or `DENY`.

**A DENY is a successful call.** It returns `200`. Check `result`, not the HTTP status, to learn the answer.

## Errors

Every error has the form `{"error": "<CODE>", "message": "<text>"}`.

| Status | Code                                                     | Meaning                                                                                                 | What to do                                                              |
| ------ | -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| 400    | `INVALID_BODY`                                           | The body is missing fields or is malformed                                                              | Fix the request. Do not retry unchanged                                 |
| 401    | `UNAUTHORIZED`                                           | The key is missing or invalid                                                                           | Check the key and the header                                            |
| 403    | `FORBIDDEN`                                              | The key lacks the required scope                                                                        | Use a key with the right scope                                          |
| 403    | `TENANT_FORBIDDEN`                                       | The request or authority belongs to another tenant                                                      | Use a key for that tenant                                               |
| 404    | `NOT_FOUND`, `AUTHORITY_NOT_FOUND`, `EVIDENCE_NOT_FOUND` | The item does not exist, or is not visible to your tenant                                               | Check the ID                                                            |
| 405    | `METHOD_NOT_ALLOWED`                                     | Wrong HTTP method for the route                                                                         | Check the route table                                                   |
| 409    | a protocol code                                          | The request conflicts with recorded state, for example an idempotency key reused with different content | Use a new idempotency key for a new action                              |
| 422    | a protocol code                                          | The request is well formed, but breaks a protocol rule. The `error` field names the rule                | Read the rule and fix the request                                       |
| 429    | `RATE_LIMITED`                                           | Too many requests from this key in the window                                                           | Wait, then retry                                                        |
| 500    | `INTERNAL_ERROR`                                         | The server failed                                                                                       | Retry later. If it persists, report it with the time and the request ID |

A 500 does not tell you whether an action ran. For execution, check the attempt state (see `04-authorize-and-execute.md`) before you do anything else.

## Rate limits

Limits are per key and per window. They are shared across server processes when the server has a database. A `429` is a normal response under load, so back off and retry rather than retrying immediately.

## Health

```bash
curl -sS "$DIP_URL/v1/health"
```

Expected: `{"status":"ok"}`. Use this for load balancer checks.
