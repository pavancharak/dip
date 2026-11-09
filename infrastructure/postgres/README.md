# PostgreSQL operations

The schema lives in `packages/storage/src/schema.ts` and is applied with `migrate(db)`. It is idempotent, so it is safe to run on every start.

## What is durable

- `evidence_ledger`: every evidence record, as its canonical signed bytes, in chain order.
- `authority_versions` and `authority_revocations`: published authority declarations and signed revocations.

## What the server stores

The server keeps every state change in `dip_event_log`: authority publications and revocations, approval requests and decisions, consumed decisions, execution attempts and completions, evidence appends, and evidence tenant ownership. At startup it replays the log, verifies the evidence chain, and refuses to start if the chain does not verify.

The typed tables above (`evidence_ledger`, `authority_versions`, `authority_revocations`) are used by the standalone stores. The server uses the event log instead, so the two paths hold the same kinds of data separately.

## Least privilege

Run the application as a role that can `SELECT` and `INSERT` on the three tables. Do not grant `UPDATE`, `DELETE` or `TRUNCATE`. The triggers already reject those statements, and the grant removes a second layer of protection.

## Tamper evidence and its limits

Triggers stop ordinary application mistakes and accidental edits. A database owner can disable a trigger, so the protocol does not rely on them. The hash chain and Ed25519 signatures detect any change made this way. The storage tests show this: a row edited with the trigger disabled, or a row deleted from the middle, is reported as invalid. To detect tail truncation, record the ledger head outside the database (for example, in a separate log) and check it with `verify(expectedHead)`.

## Backups and recovery

- Back up with `pg_dump` or continuous WAL archiving. Test restores regularly.
- After a restore, run `verify(head)` against the head you recorded outside the database. A restore that drops recent evidence then fails verification.
- No retention policy is implemented. Evidence is kept indefinitely.

## Drivers

The stores depend only on the small `SqlDatabase` interface in `packages/storage/src/db.ts`. The server and tests use PGlite, which runs PostgreSQL 16 in-process and can keep its data in a directory. A `node-postgres` adapter is not yet written. It must be tested against a real server before use.
