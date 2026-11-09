# 3. Canonical Encoding

Status: draft. Normative keywords follow RFC 2119.

## 3.1 Purpose

Every signed or hashed DIP object MUST be serialized with the canonical
encoding below. Two implementations given the same logical object MUST produce
identical bytes.

## 3.2 Rules

1. Values are JSON values: null, boolean, string, integer, array, object.
2. Object members MUST be sorted by key using UTF-16 code unit order,
   recursively at every depth.
3. No insignificant whitespace is emitted.
4. Strings use JSON escaping as defined by RFC 8259.
5. Numbers MUST be integers within the range -(2^53 - 1) to 2^53 - 1.
   Floating-point values MUST be rejected. Decimal amounts MUST be
   represented as strings or integer minor units.
6. `undefined` and other non-JSON values MUST be rejected.
7. Duplicate keys MUST be rejected.

## 3.3 Hashing and signing

- Digests use SHA-256 over the UTF-8 bytes of the canonical encoding.
- Signatures use Ed25519 over the same bytes. The signature is never computed
  over non-canonical JSON.

## 3.4 Conformance

The reference implementation is `packages/crypto` (`canonicalize`). Conformance
vectors will be added to `packages/conformance`.
