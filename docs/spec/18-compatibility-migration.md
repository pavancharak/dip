# 18. Compatibility and Migration

Status: draft.

## 18.1 Compatibility goal

Records made under protocol 1.0 MUST remain verifiable by any later implementation that supports 1.0. A later version MUST NOT make an existing signed record unverifiable.

## 18.2 Storage schema

The database schema is versioned. Version 1 holds the typed evidence and authority tables. Version 2 adds the event log. Migrations are additive and idempotent. The server applies them at startup and records the version. Destructive migrations are not permitted on evidence tables.

## 18.3 Migration of records

Evidence and authority records are not rewritten. A migration that would change stored bytes is not permitted, because it would break signatures and the chain.

## 18.4 Upgrading the server

Before upgrading, take a backup (see `docs/CLI.md`) and verify it. After upgrading, the server verifies the chain at startup and refuses to start if it does not verify.

## 18.5 Rolling back

A rollback to a server that does not know a newer schema version MUST be avoided. Restore from a verified backup instead.

## 18.6 Key rotation as migration

Rotating a signing key is a trust-root change (section 13), not a data migration. Old records stay verifiable while their key remains ACTIVE.
