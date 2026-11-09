# PostgreSQL operations

The schema lives in `packages/storage/src/schema.ts` and is applied with `migrate(db)`. It is idempotent, so it is safe to run on every start.

## What is durable

- `evidence_ledger`: every evidence record, as its canonical signed bytes, in chain order.
- `authority_versions` and `authority_revocations`: published authority declarations and signed revocations.

## What is not durable yet

Approvals, execution attempts and the server's runtime wiring still use memory. The SDK and API do not yet use these stores, so a server restart still loses state. Wiring is the next step.

## Least privilege

Run the application as a role that can `SELECT` and `INSERT` on the three tables. Do not grant `UPDATE`, `DELETE` or `TRUNCATE`. The triggers already reject those statements, and the grant removes a second layer of protection.

## Tamper evidence and its limits

Triggers stop ordinary application mistakes and accidental edits. A database owner can disable a trigger, so the protocol does not rely on them. The hash chain and Ed25519 signatures detect any change made this way. The storage tests show this: a row edited with the trigger disabled, or a row deleted from the middle, is reported as invalid. To detect tail truncation, record the ledger head outside the database (for example, in a separate log) and check it with `verify(expectedHead)`.

## Backups and recovery

- Back up with `pg_dump` or continuous WAL archiving. Test restores regularly.
- After a restore, run `verify(head)` against the head you recorded outside the database. A restore that drops recent evidence then fails verification.
- No retention policy is implemented. Evidence is kept indefinitely.

## Drivers

The stores depend only on the small `SqlDatabase` interface in `packages/storage/src/db.ts`. The tests use PGlite, which runs PostgreSQL 16 in-process. A `node-postgres` adapter is not yet written. It must be tested against a real server before use.
