import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { ApiRequest, ApiResponse } from "./app.js";

const MAX_BODY_BYTES = 1_000_000;

/** Thin node:http adapter. All behaviour lives in createApi. */
export function createHttpServer(handle: (req: ApiRequest) => Promise<ApiResponse>): Server {
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let tooLarge = false;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        tooLarge = true;
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      void (async () => {
        const send = (status: number, body: unknown): void => {
          res.writeHead(status, { "content-type": "application/json" });
          res.end(JSON.stringify(body));
        };
        if (tooLarge) {
          send(413, { error: "PAYLOAD_TOO_LARGE", message: "body exceeds limit" });
          return;
        }
        let parsed: unknown = undefined;
        const raw = Buffer.concat(chunks).toString("utf8");
        if (raw.length > 0) {
          try {
            parsed = JSON.parse(raw);
          } catch {
            send(400, { error: "INVALID_JSON", message: "body is not valid JSON" });
            return;
          }
        }
        const headers: Record<string, string | undefined> = {};
        for (const [k, v] of Object.entries(req.headers)) headers[k] = Array.isArray(v) ? v[0] : v;
        const result = await handle({
          method: req.method ?? "GET",
          path: req.url ?? "/",
          headers,
          body: parsed,
        });
        send(result.status, result.body);
      })();
    });
  });
}
