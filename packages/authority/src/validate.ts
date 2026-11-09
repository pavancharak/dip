/** Stable, machine-readable error. `code` is part of the public contract. */
export class DipError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "DipError";
  }
}

export type Obj = Record<string, unknown>;

const ID = /^[A-Za-z0-9._:-]{1,128}$/;
const CURRENCY = /^[A-Z]{3}$/;
const TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

export const MAX_MINOR_UNITS = Number.MAX_SAFE_INTEGER;

export function obj(value: unknown, path: string): Obj {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new DipError("INVALID_FIELD", `${path} must be an object`);
  }
  return value as Obj;
}

export function exactKeys(o: Obj, keys: readonly string[], path: string): void {
  for (const k of Object.keys(o)) {
    if (!keys.includes(k)) {
      throw new DipError("UNKNOWN_FIELD", `${path}.${k} is not allowed`);
    }
  }
  for (const k of keys) {
    if (!Object.hasOwn(o, k)) {
      throw new DipError("MISSING_FIELD", `${path}.${k} is required`);
    }
  }
}

export function id(value: unknown, path: string): string {
  if (typeof value !== "string" || !ID.test(value)) {
    throw new DipError("INVALID_FIELD", `${path} must be an identifier`);
  }
  return value;
}

export function int(value: unknown, path: string, min: number, max: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < min || value > max) {
    throw new DipError(
      "INVALID_FIELD",
      `${path} must be an integer in [${String(min)}, ${String(max)}]`,
    );
  }
  return value;
}

export function bool(value: unknown, path: string): boolean {
  if (typeof value !== "boolean") {
    throw new DipError("INVALID_FIELD", `${path} must be a boolean`);
  }
  return value;
}

export function currency(value: unknown, path: string): string {
  if (typeof value !== "string" || !CURRENCY.test(value)) {
    throw new DipError("INVALID_FIELD", `${path} must be an ISO 4217 code`);
  }
  return value;
}

/** RFC 3339 UTC instant with whole seconds, e.g. 2026-06-01T00:00:00Z. */
export function time(value: unknown, path: string): string {
  if (typeof value !== "string" || !TIME.test(value) || Number.isNaN(Date.parse(value))) {
    throw new DipError(
      "INVALID_FIELD",
      `${path} must be a UTC timestamp like 2026-06-01T00:00:00Z`,
    );
  }
  return value;
}

/**
 * Arrays must be strictly ascending and free of duplicates. Requiring the
 * canonical order means equivalent inputs cannot differ by ordering.
 */
export function list(
  value: unknown,
  path: string,
  parse: (v: unknown, p: string) => string,
): string[] {
  if (!Array.isArray(value)) {
    throw new DipError("INVALID_FIELD", `${path} must be an array`);
  }
  const out = value.map((item, i) => parse(item, `${path}[${String(i)}]`));
  for (let i = 1; i < out.length; i++) {
    const prev = out[i - 1];
    const cur = out[i];
    if (prev !== undefined && cur !== undefined && prev >= cur) {
      throw new DipError("NOT_CANONICAL", `${path} must be strictly ascending and unique`);
    }
  }
  return out;
}
