/**
 * Schema version 1. Records are append-only at the database level: triggers
 * reject UPDATE, DELETE and TRUNCATE. This stops ordinary application mistakes.
 * It does not stop a database superuser, so the hash chain and signatures remain
 * the tamper evidence. The verifier detects a superuser edit that disables the triggers.
 */
export const SCHEMA_VERSION = 1;

export const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS dip_schema_migrations (
  version integer PRIMARY KEY,
  applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS evidence_ledger (
  sequence bigint PRIMARY KEY CHECK (sequence >= 1),
  evidence_id text NOT NULL UNIQUE CHECK (length(evidence_id) BETWEEN 1 AND 128),
  entry_canonical text NOT NULL,
  entry_digest text NOT NULL CHECK (entry_digest ~ '^[0-9a-f]{64}$'),
  previous_digest text NOT NULL CHECK (previous_digest ~ '^[0-9a-f]{64}$')
);

CREATE TABLE IF NOT EXISTS authority_versions (
  authority_id text NOT NULL CHECK (length(authority_id) BETWEEN 1 AND 128),
  version integer NOT NULL CHECK (version >= 1),
  signed_canonical text NOT NULL,
  PRIMARY KEY (authority_id, version)
);

CREATE TABLE IF NOT EXISTS authority_revocations (
  authority_id text NOT NULL,
  version integer NOT NULL,
  signed_canonical text NOT NULL,
  PRIMARY KEY (authority_id, version)
);

CREATE OR REPLACE FUNCTION dip_reject_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'DIP records are append-only: % on % is not allowed', TG_OP, TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER evidence_ledger_no_update BEFORE UPDATE OR DELETE ON evidence_ledger
  FOR EACH ROW EXECUTE FUNCTION dip_reject_mutation();
CREATE OR REPLACE TRIGGER evidence_ledger_no_truncate BEFORE TRUNCATE ON evidence_ledger
  FOR EACH STATEMENT EXECUTE FUNCTION dip_reject_mutation();

CREATE OR REPLACE TRIGGER authority_versions_no_update BEFORE UPDATE OR DELETE ON authority_versions
  FOR EACH ROW EXECUTE FUNCTION dip_reject_mutation();
CREATE OR REPLACE TRIGGER authority_versions_no_truncate BEFORE TRUNCATE ON authority_versions
  FOR EACH STATEMENT EXECUTE FUNCTION dip_reject_mutation();

CREATE OR REPLACE TRIGGER authority_revocations_no_update BEFORE UPDATE OR DELETE ON authority_revocations
  FOR EACH ROW EXECUTE FUNCTION dip_reject_mutation();
CREATE OR REPLACE TRIGGER authority_revocations_no_truncate BEFORE TRUNCATE ON authority_revocations
  FOR EACH STATEMENT EXECUTE FUNCTION dip_reject_mutation();
`;

/** Applies the schema. Idempotent: safe to run on every start. Returns the schema version. */
export async function migrate(db: import("./db.js").SqlDatabase): Promise<number> {
  await db.exec(SCHEMA_SQL);
  await db.query(
    "INSERT INTO dip_schema_migrations (version) VALUES ($1) ON CONFLICT (version) DO NOTHING",
    [SCHEMA_VERSION],
  );
  return SCHEMA_VERSION;
}
