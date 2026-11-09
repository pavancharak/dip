import { createHash } from "node:crypto";

/** SHA-256 digest of UTF-8 bytes, returned as lowercase hex. */
export function sha256Hex(input: string | Uint8Array): string {
  return createHash("sha256").update(input).digest("hex");
}
