/**
 * Canonical JSON encoding for DIP objects.
 *
 * Rules (normative, see docs/spec/03-canonical-encoding.md):
 * - Object keys are sorted by UTF-16 code unit order, recursively.
 * - No insignificant whitespace.
 * - Strings are emitted with JSON escaping.
 * - Numbers must be finite integers in the safe range; floats are rejected.
 * - undefined is rejected; null is allowed.
 */
export type CanonicalValue =
  | null
  | boolean
  | string
  | number
  | readonly CanonicalValue[]
  | { readonly [key: string]: CanonicalValue };

export class CanonicalEncodingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CanonicalEncodingError";
  }
}

export function canonicalize(value: unknown): string {
  return encode(value, "$");
}

function encode(value: unknown, path: string): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new CanonicalEncodingError(`non-integer or unsafe number at ${path}`);
    }
    return String(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map((item, i) => encode(item, `${path}[${String(i)}]`)).join(",") + "]";
  }
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    const parts = keys.map((key) => {
      const member = record[key];
      if (member === undefined) {
        throw new CanonicalEncodingError(`undefined value at ${path}.${key}`);
      }
      return JSON.stringify(key) + ":" + encode(member, `${path}.${key}`);
    });
    return "{" + parts.join(",") + "}";
  }
  throw new CanonicalEncodingError(`unsupported type ${typeof value} at ${path}`);
}
