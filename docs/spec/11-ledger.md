# 11. Ledger

Status: draft, matches `packages/ledger/src/ledger.ts` and `packages/storage`.

## 11.1 Chain

Entries are numbered 1, 2, 3, and so on. The entry digest is `SHA-256("DIP-LEDGER-ENTRY-V1" ‖ 0x00 ‖ canonical(signed entry))`, where the signed entry includes the signature. Each entry's `previousDigest` MUST equal the digest of the entry before it. The first entry's `previousDigest` is 64 zeros.

## 11.2 Append-only

The ledger MUST NOT offer an update or delete operation. Persistent storage MUST refuse UPDATE, DELETE and TRUNCATE on evidence tables. These triggers stop ordinary mistakes. They do not stop a database owner, so the chain is the tamper evidence.

## 11.3 Appends

An append MUST be serialized: two writers MUST NOT claim the same sequence number. The reference implementation uses a transaction-scoped advisory lock. A duplicate evidence identifier MUST be refused (`EVIDENCE_DUPLICATE`) and nothing MUST be recorded.

## 11.4 Verification

Verification takes the exported entries and trust roots. It reports each failure with its index and code: `MALFORMED`, `SEQUENCE_MISMATCH`, `CHAIN_BROKEN`, `DUPLICATE_EVIDENCE_ID`, signature codes, `INVARIANT_*`, and `HEAD_MISMATCH`.

## 11.5 Missing, duplicate, broken and reordered entries

| Condition                   | Detection                                      |
| --------------------------- | ---------------------------------------------- |
| Missing entry in the middle | `SEQUENCE_MISMATCH` and `CHAIN_BROKEN`         |
| Removed tail                | Not detectable without an external head (11.6) |
| Duplicate identifier        | `DUPLICATE_EVIDENCE_ID`                        |
| Broken chain                | `CHAIN_BROKEN`                                 |
| Invalid signature           | Signature code                                 |
| Reordered entries           | `SEQUENCE_MISMATCH`                            |

## 11.6 Head anchoring

A verifier that holds a head recorded outside the system detects tail truncation. Operators MUST record the head outside the database to get this protection.

## 11.7 Conflicting evidence

Two entries for the same request with different content are both recorded. Conflicts are visible to verification; the ledger does not resolve them.

## 11.8 Incomplete transactions

An execution with no evidence yet is not in the ledger. The server records evidence for every execution attempt in its response path. An action with no recorded evidence is a fault to investigate, not a success.
