-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Candor Intake Store (C-08) schema, 09-DATABASE.md §5.1, §6, §7, §8, §10.
-- Forward-only (09 §11). Run by `candorctl migrate` as the database owner; never at
-- service start. No timestamp/time/interval/inet types anywhere (09 §8 L1, L3, L11).
-- Compatible with wal_level = minimal: no publications, no replication slots, no
-- logical decoding, no track_commit_timestamp dependence (ADR-046(1)).

-- Roles (cluster-wide, idempotent). Production provisions them at deployment with
-- the same attributes (18-DEPLOYMENT.md); creating them needs CREATEROLE.
DO $roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'candor_intake_migrator') THEN
    CREATE ROLE candor_intake_migrator NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'candor_istore') THEN
    CREATE ROLE candor_istore LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'candor_intake_backup') THEN
    CREATE ROLE candor_intake_backup LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
  END IF;
END
$roles$;

-- Per-database role settings (09 §10 "Roles"; R7 SI-E-02).
DO $settings$
BEGIN
  EXECUTE pg_catalog.format('ALTER ROLE candor_istore IN DATABASE %I SET search_path = candor', pg_catalog.current_database());
  EXECUTE pg_catalog.format('ALTER ROLE candor_istore IN DATABASE %I SET statement_timeout = %L', pg_catalog.current_database(), '30s');
  EXECUTE pg_catalog.format('ALTER ROLE candor_istore IN DATABASE %I SET idle_in_transaction_session_timeout = %L', pg_catalog.current_database(), '60s');
  EXECUTE pg_catalog.format('ALTER ROLE candor_intake_backup IN DATABASE %I SET search_path = candor', pg_catalog.current_database());
  EXECUTE pg_catalog.format('ALTER ROLE candor_intake_backup IN DATABASE %I SET default_transaction_read_only = on', pg_catalog.current_database());
END
$settings$;

REVOKE ALL ON SCHEMA public FROM PUBLIC;
DO $db$
BEGIN
  EXECUTE pg_catalog.format('REVOKE ALL ON DATABASE %I FROM PUBLIC', pg_catalog.current_database());
  EXECUTE pg_catalog.format('GRANT CONNECT ON DATABASE %I TO candor_istore, candor_intake_backup', pg_catalog.current_database());
END
$db$;

-- Everything below is owned by the NOLOGIN migrator (DB-002).
SET LOCAL ROLE candor_intake_migrator;

CREATE SCHEMA candor AUTHORIZATION candor_intake_migrator;
REVOKE ALL ON SCHEMA candor FROM PUBLIC;
GRANT USAGE ON SCHEMA candor TO candor_istore, candor_intake_backup;
ALTER DEFAULT PRIVILEGES IN SCHEMA candor REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA candor REVOKE ALL ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA candor REVOKE ALL ON TYPES FROM PUBLIC;

CREATE TYPE candor.envelope_state AS ENUM ('sealed', 'claimed');
CREATE TYPE candor.deletion_kind AS ENUM ('account', 'mailbox', 'reply');
CREATE TYPE candor.counter_name AS ENUM ('submissions_received', 'accounts_created', 'account_deletions');
GRANT USAGE ON TYPE candor.envelope_state, candor.deletion_kind, candor.counter_name TO candor_istore, candor_intake_backup;

-- Forward-only migration ledger (implementation addition; no time column, unlike
-- sqlx's own _sqlx_migrations which carries installed_on timestamptz).
CREATE TABLE candor.schema_migration (
  version integer PRIMARY KEY CHECK (version > 0),
  sha256  bytea   NOT NULL CHECK (octet_length(sha256) = 32)
);

-- intake_meta (singleton) — SYS/SEC.
CREATE TABLE candor.intake_meta (
  tenant_id             uuid    PRIMARY KEY,
  schema_hash           bytea   NOT NULL CHECK (octet_length(schema_hash) = 32),
  kdf_salt              bytea   NOT NULL CHECK (octet_length(kdf_salt) = 32),
  relay_req_counter     bigint  NOT NULL DEFAULT 0 CHECK (relay_req_counter >= 0),
  last_batch_no         bigint  NOT NULL DEFAULT 0 CHECK (last_batch_no >= 0),
  directory_version     bigint  NOT NULL DEFAULT 0 CHECK (directory_version >= 0),
  kd_tree_size_hwm      bigint  NOT NULL DEFAULT 0 CHECK (kd_tree_size_hwm >= 0),
  kd_checkpoint_day_hwm date    NULL,
  config_version        bigint  NOT NULL DEFAULT 0 CHECK (config_version >= 0),
  restore_pending       boolean NOT NULL DEFAULT false
);
CREATE UNIQUE INDEX intake_meta_singleton ON candor.intake_meta ((true));

-- Monotonic guards in the database as defence in depth (BE-060, 07 §5.4):
-- the KD high-water mark, the directory version and the relay counter never decrease.
CREATE FUNCTION candor.intake_meta_monotonic() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, candor AS $fn$
BEGIN
  IF NEW.tenant_id <> OLD.tenant_id THEN
    RAISE EXCEPTION 'intake_meta tenant is immutable' USING ERRCODE = 'P0001';
  END IF;
  IF NEW.kd_tree_size_hwm < OLD.kd_tree_size_hwm
     OR (OLD.kd_checkpoint_day_hwm IS NOT NULL AND (NEW.kd_checkpoint_day_hwm IS NULL OR NEW.kd_checkpoint_day_hwm < OLD.kd_checkpoint_day_hwm))
     OR NEW.directory_version < OLD.directory_version
     OR NEW.relay_req_counter < OLD.relay_req_counter
     OR NEW.last_batch_no < OLD.last_batch_no THEN
    RAISE EXCEPTION 'monotonic intake_meta value decreased' USING ERRCODE = 'P0002';
  END IF;
  RETURN NEW;
END
$fn$;
REVOKE ALL ON FUNCTION candor.intake_meta_monotonic() FROM PUBLIC;
CREATE TRIGGER intake_meta_monotonic BEFORE UPDATE ON candor.intake_meta
  FOR EACH ROW EXECUTE FUNCTION candor.intake_meta_monotonic();
CREATE FUNCTION candor.no_delete() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, candor AS $fn$
BEGIN
  RAISE EXCEPTION 'delete forbidden' USING ERRCODE = 'P0003';
END
$fn$;
REVOKE ALL ON FUNCTION candor.no_delete() FROM PUBLIC;
CREATE TRIGGER intake_meta_no_delete BEFORE DELETE ON candor.intake_meta
  FOR EACH ROW EXECUTE FUNCTION candor.no_delete();

-- source_account (Tier W only) — SS. No state/created_day (ADR-034), no last_* (ADR-010).
CREATE TABLE candor.source_account (
  account_id     uuid     PRIMARY KEY,
  locator_hash   bytea    NOT NULL UNIQUE CHECK (octet_length(locator_hash) = 32),
  auth_pk        bytea    NOT NULL CHECK (octet_length(auth_pk) = 32),
  xwing_pk       bytea    NOT NULL CHECK (octet_length(xwing_pk) = 1216),
  prefs_ct       bytea    NOT NULL CHECK (octet_length(prefs_ct) BETWEEN 1 AND 4096),
  activity_month date     NOT NULL CHECK (EXTRACT(DAY FROM activity_month) = 1),
  quota_bucket   smallint NOT NULL DEFAULT 0 CHECK (quota_bucket >= 0)
);

-- envelope — CT/SS. Real and chaff rows are identical (ADR-047(3)); no kind, no tier.
CREATE TABLE candor.envelope (
  envelope_ref      uuid                  PRIMARY KEY,
  channel_id        uuid                  NOT NULL,
  source_account_id uuid                  NULL REFERENCES candor.source_account (account_id) ON DELETE SET NULL,
  header_ct         bytea                 NOT NULL CHECK (octet_length(header_ct) BETWEEN 1 AND 8192),
  manifest_ct       bytea                 NOT NULL CHECK (octet_length(manifest_ct) BETWEEN 1 AND 65536),
  header_sha256     bytea                 NOT NULL UNIQUE CHECK (octet_length(header_sha256) = 32),
  disposition_ct    bytea                 NOT NULL CHECK (octet_length(disposition_ct) BETWEEN 1 AND 4096),
  epoch_index       integer               NOT NULL CHECK (epoch_index >= 0),
  received_date     date                  NOT NULL,
  release_day       date                  NOT NULL,
  batch_no          bigint                NULL CHECK (batch_no > 0),
  state             candor.envelope_state NOT NULL DEFAULT 'sealed',
  CHECK (release_day >= received_date AND release_day <= received_date + 21),
  CHECK ((state = 'claimed') = (batch_no IS NOT NULL))
);
CREATE INDEX envelope_claimable ON candor.envelope (state, release_day);
CREATE INDEX envelope_batch ON candor.envelope (batch_no) WHERE batch_no IS NOT NULL;
CREATE INDEX envelope_account ON candor.envelope (source_account_id) WHERE source_account_id IS NOT NULL;

-- envelope_part — CT.
CREATE TABLE candor.envelope_part (
  envelope_ref uuid     NOT NULL REFERENCES candor.envelope (envelope_ref) ON DELETE CASCADE,
  part_no      smallint NOT NULL CHECK (part_no BETWEEN 0 AND 31),
  blob_id      uuid     NOT NULL UNIQUE,
  padded_size  bigint   NOT NULL CHECK (padded_size > 0 AND padded_size <= 17179869184),
  PRIMARY KEY (envelope_ref, part_no)
);

-- reply — CT/SS. No fetched/read/last_accessed/access-count column (ADR-010, ADR-039).
CREATE TABLE candor.reply (
  reply_ref         uuid     PRIMARY KEY,
  source_account_id uuid     NULL REFERENCES candor.source_account (account_id) ON DELETE CASCADE,
  reply_ct          bytea    NOT NULL CHECK (octet_length(reply_ct) BETWEEN 1 AND 69996),
  size_bucket       smallint NOT NULL CHECK (size_bucket BETWEEN 1 AND 16),
  available_day     date     NOT NULL,
  slot              smallint NULL CHECK (slot BETWEEN 0 AND 31),
  CHECK ((slot IS NULL) = (source_account_id IS NULL)),
  UNIQUE (source_account_id, slot)
);
CREATE INDEX reply_available ON candor.reply (available_day);

-- deletion_list (ADR-047(9)) — SS. Append-only except relayed false -> true and
-- pruning of relayed entries (enforced by trigger as defence in depth).
CREATE TABLE candor.deletion_list (
  seq       bigint               PRIMARY KEY CHECK (seq > 0),
  kind      candor.deletion_kind NOT NULL,
  del_hash  bytea                NOT NULL CHECK (octet_length(del_hash) = 32),
  del_day   date                 NOT NULL,
  prev_hash bytea                NOT NULL CHECK (octet_length(prev_hash) = 32),
  sig       bytea                NOT NULL CHECK (octet_length(sig) = 64),
  relayed   boolean              NOT NULL DEFAULT false
);
CREATE INDEX deletion_list_hash ON candor.deletion_list (kind, del_hash);
CREATE FUNCTION candor.deletion_list_guard() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, candor AS $fn$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF NEW.seq <> OLD.seq OR NEW.kind <> OLD.kind OR NEW.del_hash <> OLD.del_hash
       OR NEW.del_day <> OLD.del_day OR NEW.prev_hash <> OLD.prev_hash OR NEW.sig <> OLD.sig
       OR (OLD.relayed AND NOT NEW.relayed) THEN
      RAISE EXCEPTION 'deletion_list is append-only' USING ERRCODE = 'P0004';
    END IF;
    RETURN NEW;
  END IF;
  IF NOT OLD.relayed THEN
    RAISE EXCEPTION 'unrelayed deletion_list entry cannot be pruned' USING ERRCODE = 'P0004';
  END IF;
  RETURN OLD;
END
$fn$;
REVOKE ALL ON FUNCTION candor.deletion_list_guard() FROM PUBLIC;
CREATE TRIGGER deletion_list_guard BEFORE UPDATE OR DELETE ON candor.deletion_list
  FOR EACH ROW EXECUTE FUNCTION candor.deletion_list_guard();

-- directory_snapshot — SEC. Current + previous version only.
CREATE TABLE candor.directory_snapshot (
  version     bigint PRIMARY KEY CHECK (version > 0),
  body        bytea  NOT NULL CHECK (octet_length(body) BETWEEN 1 AND 33554432),
  signatures  bytea  NOT NULL CHECK (octet_length(signatures) BETWEEN 1 AND 1048576),
  applied_day date   NOT NULL
);

-- counter_month (ADR-046(5)) — SS aggregate. No per-day counters (L15).
CREATE TABLE candor.counter_month (
  month      date               NOT NULL CHECK (EXTRACT(DAY FROM month) = 1),
  channel_id uuid               NOT NULL,
  name       candor.counter_name NOT NULL,
  value      integer            NOT NULL CHECK (value >= 0),
  PRIMARY KEY (month, channel_id, name)
);

-- Aggressive autovacuum on intake tables (09 §10 "Deletion").
ALTER TABLE candor.source_account SET (autovacuum_vacuum_scale_factor = 0.01);
ALTER TABLE candor.envelope       SET (autovacuum_vacuum_scale_factor = 0.01);
ALTER TABLE candor.envelope_part  SET (autovacuum_vacuum_scale_factor = 0.01);
ALTER TABLE candor.reply          SET (autovacuum_vacuum_scale_factor = 0.01);
ALTER TABLE candor.deletion_list  SET (autovacuum_vacuum_scale_factor = 0.01);

-- Row-level security (defence in depth; 09 says one DB per tenant needs none, R7
-- SI-E-03 asks for it): every transaction must SET LOCAL candor.tenant_id to the
-- database's tenant. intake_meta is filtered by its own tenant_id; every other
-- table is visible only while intake_meta is (an uncorrelated EXISTS evaluated
-- once per statement). A connection configured for another tenant sees nothing
-- and cannot write. FORCE applies the policies to the owner as well.
ALTER TABLE candor.intake_meta ENABLE ROW LEVEL SECURITY;
ALTER TABLE candor.intake_meta FORCE ROW LEVEL SECURITY;
CREATE POLICY p_tenant ON candor.intake_meta
  USING (tenant_id = NULLIF(pg_catalog.current_setting('candor.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(pg_catalog.current_setting('candor.tenant_id', true), '')::uuid);

ALTER TABLE candor.source_account ENABLE ROW LEVEL SECURITY;
ALTER TABLE candor.source_account FORCE ROW LEVEL SECURITY;
CREATE POLICY p_tenant ON candor.source_account
  USING (EXISTS (SELECT 1 FROM candor.intake_meta)) WITH CHECK (EXISTS (SELECT 1 FROM candor.intake_meta));
ALTER TABLE candor.envelope ENABLE ROW LEVEL SECURITY;
ALTER TABLE candor.envelope FORCE ROW LEVEL SECURITY;
CREATE POLICY p_tenant ON candor.envelope
  USING (EXISTS (SELECT 1 FROM candor.intake_meta)) WITH CHECK (EXISTS (SELECT 1 FROM candor.intake_meta));
ALTER TABLE candor.envelope_part ENABLE ROW LEVEL SECURITY;
ALTER TABLE candor.envelope_part FORCE ROW LEVEL SECURITY;
CREATE POLICY p_tenant ON candor.envelope_part
  USING (EXISTS (SELECT 1 FROM candor.intake_meta)) WITH CHECK (EXISTS (SELECT 1 FROM candor.intake_meta));
ALTER TABLE candor.reply ENABLE ROW LEVEL SECURITY;
ALTER TABLE candor.reply FORCE ROW LEVEL SECURITY;
CREATE POLICY p_tenant ON candor.reply
  USING (EXISTS (SELECT 1 FROM candor.intake_meta)) WITH CHECK (EXISTS (SELECT 1 FROM candor.intake_meta));
ALTER TABLE candor.deletion_list ENABLE ROW LEVEL SECURITY;
ALTER TABLE candor.deletion_list FORCE ROW LEVEL SECURITY;
CREATE POLICY p_tenant ON candor.deletion_list
  USING (EXISTS (SELECT 1 FROM candor.intake_meta)) WITH CHECK (EXISTS (SELECT 1 FROM candor.intake_meta));
ALTER TABLE candor.directory_snapshot ENABLE ROW LEVEL SECURITY;
ALTER TABLE candor.directory_snapshot FORCE ROW LEVEL SECURITY;
CREATE POLICY p_tenant ON candor.directory_snapshot
  USING (EXISTS (SELECT 1 FROM candor.intake_meta)) WITH CHECK (EXISTS (SELECT 1 FROM candor.intake_meta));
ALTER TABLE candor.counter_month ENABLE ROW LEVEL SECURITY;
ALTER TABLE candor.counter_month FORCE ROW LEVEL SECURITY;
CREATE POLICY p_tenant ON candor.counter_month
  USING (EXISTS (SELECT 1 FROM candor.intake_meta)) WITH CHECK (EXISTS (SELECT 1 FROM candor.intake_meta));

-- Grants (09 §5.1 readers; §7; DB-002: app roles own nothing). No TRUNCATE anywhere.
GRANT SELECT ON candor.schema_migration TO candor_istore;
GRANT SELECT, INSERT, UPDATE ON candor.intake_meta TO candor_istore;
GRANT SELECT, INSERT, UPDATE, DELETE ON candor.source_account, candor.envelope, candor.envelope_part,
  candor.reply, candor.directory_snapshot, candor.counter_month TO candor_istore;
GRANT SELECT, INSERT, DELETE ON candor.deletion_list TO candor_istore;
GRANT UPDATE (relayed) ON candor.deletion_list TO candor_istore;
-- Backup role (RL-10 snapshot job): read-only on exactly the snapshot tables.
GRANT SELECT ON candor.intake_meta, candor.source_account, candor.deletion_list TO candor_intake_backup;
