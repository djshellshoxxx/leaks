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
  -- Separate maintenance role (daily deletion_list_prune, statistics reset,
  -- slot VACUUM, daily VACUUM FULL): the only role that may flag or delete
  -- deletion-list entries (AUD-RM2-STO-03). It owns the database (PostgreSQL 16
  -- lets the database owner VACUUM every table in it) but no table and no
  -- schema, so it cannot disable RLS or the guard triggers and needs no
  -- membership in the schema owner (AUD-RM2-STO-24(a)).
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'candor_intake_maint') THEN
    CREATE ROLE candor_intake_maint LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
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
  EXECUTE pg_catalog.format('ALTER ROLE candor_intake_maint IN DATABASE %I SET search_path = candor', pg_catalog.current_database());
  EXECUTE pg_catalog.format('ALTER ROLE candor_intake_maint IN DATABASE %I SET statement_timeout = %L', pg_catalog.current_database(), '30s');
  EXECUTE pg_catalog.format('ALTER ROLE candor_intake_maint IN DATABASE %I SET idle_in_transaction_session_timeout = %L', pg_catalog.current_database(), '60s');
END
$settings$;

-- Superuser-only settings (09 §10 temp_file_limit; AUD-RM2-STO-08/11/23/24).
-- Applied when the migration runs as a superuser (test clusters); production
-- provisioning applies the same settings (SPEC-NOTES "Deployment settings").
DO $su$
BEGIN
  IF (SELECT r.rolsuper FROM pg_catalog.pg_roles r WHERE r.rolname = current_user) THEN
    EXECUTE pg_catalog.format('ALTER ROLE candor_istore IN DATABASE %I SET temp_file_limit = %L', pg_catalog.current_database(), '1GB');
    EXECUTE pg_catalog.format('ALTER ROLE candor_intake_maint IN DATABASE %I SET temp_file_limit = %L', pg_catalog.current_database(), '1GB');
    GRANT EXECUTE ON FUNCTION pg_catalog.pg_stat_reset() TO candor_intake_maint;
    EXECUTE pg_catalog.format('ALTER DATABASE %I OWNER TO candor_intake_maint', pg_catalog.current_database());
    GRANT pg_checkpoint TO candor_intake_maint WITH INHERIT TRUE, SET FALSE;
  END IF;
END
$su$;

REVOKE ALL ON SCHEMA public FROM PUBLIC;
-- Database privileges: only a superuser or the database owner can grant them;
-- production provisioning does the same (the migration login is neither).
DO $db$
BEGIN
  IF (SELECT r.rolsuper FROM pg_catalog.pg_roles r WHERE r.rolname = current_user)
     OR pg_catalog.pg_has_role(current_user, (SELECT d.datdba FROM pg_catalog.pg_database d
                                              WHERE d.datname = pg_catalog.current_database()), 'USAGE') THEN
    EXECUTE pg_catalog.format('REVOKE ALL ON DATABASE %I FROM PUBLIC', pg_catalog.current_database());
    EXECUTE pg_catalog.format('GRANT CONNECT ON DATABASE %I TO candor_istore, candor_intake_backup, candor_intake_maint', pg_catalog.current_database());
    -- The migrator creates the schema; the database is owned by the maintenance role.
    EXECUTE pg_catalog.format('GRANT CREATE ON DATABASE %I TO candor_intake_migrator', pg_catalog.current_database());
  END IF;
END
$db$;

-- Everything below is owned by the NOLOGIN migrator (DB-002).
SET LOCAL ROLE candor_intake_migrator;

CREATE SCHEMA candor AUTHORIZATION candor_intake_migrator;
REVOKE ALL ON SCHEMA candor FROM PUBLIC;
GRANT USAGE ON SCHEMA candor TO candor_istore, candor_intake_backup, candor_intake_maint;
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
  restore_pending       boolean NOT NULL DEFAULT false,
  deletion_acked_seq    bigint  NOT NULL DEFAULT 0 CHECK (deletion_acked_seq >= 0),
  -- The Z-CORE-signed head behind deletion_acked_seq (AUD-RM2-STO-21): its chain
  -- hash (checked against the local chain by the trigger below) and Z-CORE's
  -- signature (re-verified by the maintenance process before any prune).
  deletion_acked_hash   bytea   NULL CHECK (octet_length(deletion_acked_hash) = 32),
  deletion_acked_sig    bytea   NULL CHECK (octet_length(deletion_acked_sig) = 64),
  -- Z-CORE day and attestation counter of that head (AUD-RM2-STO-24): signed
  -- with it; neither ever decreases.
  deletion_acked_day     date   NULL,
  deletion_acked_counter bigint NOT NULL DEFAULT 0 CHECK (deletion_acked_counter >= 0),
  CHECK ((deletion_acked_seq = 0) = (deletion_acked_hash IS NULL) AND (deletion_acked_hash IS NULL) = (deletion_acked_sig IS NULL)),
  CHECK ((deletion_acked_hash IS NULL) = (deletion_acked_day IS NULL) AND (deletion_acked_hash IS NULL) = (deletion_acked_counter = 0))
);
CREATE UNIQUE INDEX intake_meta_singleton ON candor.intake_meta ((true));

-- Monotonic guards in the database as defence in depth (BE-060, 07 §5.4):
-- the KD high-water mark, the directory version, the relay counter and the
-- acknowledged deletion seq never decrease; tenant, salt and schema hash are
-- immutable; the acknowledged head must be part of the local deletion-list
-- chain (AUD-RM2-STO-21; candor.deletion_head_in_chain, defined below).
CREATE FUNCTION candor.intake_meta_monotonic() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, candor AS $fn$
BEGIN
  IF NEW.tenant_id <> OLD.tenant_id OR NEW.kdf_salt <> OLD.kdf_salt OR NEW.schema_hash <> OLD.schema_hash THEN
    RAISE EXCEPTION 'intake_meta identity is immutable' USING ERRCODE = 'P0001';
  END IF;
  IF NEW.kd_tree_size_hwm < OLD.kd_tree_size_hwm
     OR (OLD.kd_checkpoint_day_hwm IS NOT NULL AND (NEW.kd_checkpoint_day_hwm IS NULL OR NEW.kd_checkpoint_day_hwm < OLD.kd_checkpoint_day_hwm))
     OR NEW.directory_version < OLD.directory_version
     OR NEW.relay_req_counter < OLD.relay_req_counter
     OR NEW.last_batch_no < OLD.last_batch_no
     OR NEW.deletion_acked_seq < OLD.deletion_acked_seq
     OR NEW.deletion_acked_counter < OLD.deletion_acked_counter
     OR (OLD.deletion_acked_day IS NOT NULL AND (NEW.deletion_acked_day IS NULL OR NEW.deletion_acked_day < OLD.deletion_acked_day)) THEN
    RAISE EXCEPTION 'monotonic intake_meta value decreased' USING ERRCODE = 'P0002';
  END IF;
  -- Any change of the acknowledged head needs a newer Z-CORE attestation.
  IF ROW(NEW.deletion_acked_seq, NEW.deletion_acked_hash, NEW.deletion_acked_sig, NEW.deletion_acked_day)
       IS DISTINCT FROM ROW(OLD.deletion_acked_seq, OLD.deletion_acked_hash, OLD.deletion_acked_sig, OLD.deletion_acked_day)
     AND NEW.deletion_acked_counter <= OLD.deletion_acked_counter THEN
    RAISE EXCEPTION 'acknowledged head changed without a newer attestation' USING ERRCODE = 'P0002';
  END IF;
  IF NEW.deletion_acked_seq IS DISTINCT FROM OLD.deletion_acked_seq
     OR NEW.deletion_acked_hash IS DISTINCT FROM OLD.deletion_acked_hash THEN
    IF NEW.deletion_acked_seq = OLD.deletion_acked_seq
       OR NOT candor.deletion_head_in_chain(NEW.deletion_acked_seq, NEW.deletion_acked_hash) THEN
      RAISE EXCEPTION 'acknowledged head not in the deletion-list chain' USING ERRCODE = 'P0002';
    END IF;
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
-- No quota column: the daily quota lives in process RAM (AUD-RM2-STO-01). Rows
-- change only on create, delete, passphrase rotation and the import-slot rewrite.
CREATE TABLE candor.source_account (
  account_id     uuid     PRIMARY KEY,
  locator_hash   bytea    NOT NULL UNIQUE CHECK (octet_length(locator_hash) = 32),
  auth_pk        bytea    NOT NULL CHECK (octet_length(auth_pk) = 32),
  xwing_pk       bytea    NOT NULL CHECK (octet_length(xwing_pk) = 1216),
  prefs_ct       bytea    NOT NULL CHECK (octet_length(prefs_ct) BETWEEN 1 AND 4096),
  activity_month date     NOT NULL CHECK (EXTRACT(DAY FROM activity_month) = 1)
);

-- envelope — CT/SS. One fixed-shape group per row (ADR-052(1): main object,
-- ATTACHMENT_BUNDLE, IDENTITY). No account reference (ADR-052(2)); real and
-- chaff rows are identical (ADR-047(3)); no kind, no tier.
CREATE TABLE candor.envelope (
  envelope_ref      uuid                  PRIMARY KEY,
  channel_id        uuid                  NOT NULL,
  group_sha256      bytea                 NOT NULL UNIQUE CHECK (octet_length(group_sha256) = 32),
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

-- envelope_part — CT. Exactly the three group objects (part_no 0..2), each with
-- its object_hash, RecipientSlotBlock (STD: 4 + 16 x 1168 bytes) and blob.
CREATE TABLE candor.envelope_part (
  envelope_ref uuid     NOT NULL REFERENCES candor.envelope (envelope_ref) ON DELETE CASCADE,
  part_no      smallint NOT NULL CHECK (part_no BETWEEN 0 AND 2),
  object_hash  bytea    NOT NULL CHECK (octet_length(object_hash) = 32),
  slot_block   bytea    NOT NULL CHECK (octet_length(slot_block) = 18692),
  blob_id      uuid     NOT NULL UNIQUE,
  padded_size  bigint   NOT NULL CHECK (padded_size > 0 AND padded_size <= 17179869184),
  PRIMARY KEY (envelope_ref, part_no)
);

-- reply — CT/SS. No fetched/read/last_accessed/access-count column (ADR-010, ADR-039).
-- Also holds the persistent dead-drop dummies (source_account_id NULL), stored
-- exactly like Tier V replies (AUD-RM2-STO-06). pub_gen: NULL = awaiting
-- publication, 0 = padding pool, g > 0 = published in import-slot generation g.
CREATE TABLE candor.reply (
  reply_ref         uuid     PRIMARY KEY,
  source_account_id uuid     NULL REFERENCES candor.source_account (account_id) ON DELETE CASCADE,
  reply_ct          bytea    NOT NULL CHECK (octet_length(reply_ct) BETWEEN 1 AND 69996),
  size_bucket       smallint NOT NULL CHECK (size_bucket BETWEEN 1 AND 16),
  available_day     date     NOT NULL,
  slot              smallint NULL CHECK (slot BETWEEN 0 AND 31),
  pub_gen           bigint   NULL CHECK (pub_gen >= 0),
  CHECK ((slot IS NULL) = (source_account_id IS NULL)),
  UNIQUE (source_account_id, slot)
);
CREATE INDEX reply_available ON candor.reply (available_day);
CREATE INDEX reply_pub_gen ON candor.reply (pub_gen);

-- deletion_list (ADR-047(9)) — SS. Append-only for the application role, which
-- may only rewrite rows unchanged (import-slot rewrite). Only the maintenance
-- role may flag acknowledged entries relayed and prune relayed entries, never
-- the chain head (AUD-RM2-STO-03; enforced by trigger and by grants).
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
-- Chain hash of an entry, exactly as deletion::DeletionEntry::next_prev_hash:
-- SHA-256("candor/v1/intake/deletion-list" ‖ prev_hash ‖ u64be seq ‖ u8 kind ‖
-- del_hash ‖ u32be del_day ‖ sig) (built-in sha256, no extension).
CREATE FUNCTION candor.deletion_chain_hash(d candor.deletion_list) RETURNS bytea
  LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog, candor AS $fn$
  SELECT pg_catalog.sha256('candor/v1/intake/deletion-list'::bytea || d.prev_hash
    || pg_catalog.int8send(d.seq)
    || CASE d.kind WHEN 'account' THEN '\x01'::bytea WHEN 'mailbox' THEN '\x02'::bytea ELSE '\x03'::bytea END
    || d.del_hash || pg_catalog.int4send((d.del_day - DATE '1970-01-01')::int4) || d.sig)
$fn$;
REVOKE ALL ON FUNCTION candor.deletion_chain_hash(candor.deletion_list) FROM PUBLIC;
-- Whether the local chain contains the head (seq, hash): the entry at seq hashes
-- to it, or (that entry pruned) its successor links to it; seq 0 = empty chain.
CREATE FUNCTION candor.deletion_head_in_chain(s bigint, h bytea) RETURNS boolean
  LANGUAGE sql STABLE SET search_path = pg_catalog, candor AS $fn$
  SELECT s = 0 OR EXISTS (SELECT 1 FROM candor.deletion_list d WHERE d.seq = s AND candor.deletion_chain_hash(d) = h)
    OR (NOT EXISTS (SELECT 1 FROM candor.deletion_list d WHERE d.seq = s)
        AND EXISTS (SELECT 1 FROM candor.deletion_list d WHERE d.seq = s + 1 AND d.prev_hash = h))
$fn$;
REVOKE ALL ON FUNCTION candor.deletion_head_in_chain(bigint, bytea) FROM PUBLIC;
-- Append-only chain (AUD-RM2-STO-21): an insert must extend the chain at its
-- head (seq = max + 1 linking to the head) or below its oldest retained entry
-- (seq = min - 1 linking to it; restore and RL-12 merges); only the first entry
-- of an empty list is free (genesis, or a restored/pushed pruned list). New
-- rows are never pre-flagged relayed, so nothing can be pruned without the
-- maintenance role's verified acknowledgement.
CREATE FUNCTION candor.deletion_list_append() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, candor AS $fn$
DECLARE
  hi bigint;
  lo bigint;
BEGIN
  IF NEW.relayed OR (NEW.seq = 1 AND NEW.prev_hash <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')) THEN
    RAISE EXCEPTION 'deletion_list entry rejected' USING ERRCODE = 'P0004';
  END IF;
  SELECT max(d.seq), min(d.seq) INTO hi, lo FROM candor.deletion_list d;
  IF hi IS NULL THEN
    RETURN NEW;
  END IF;
  IF NEW.seq = hi + 1
     AND NEW.prev_hash = (SELECT candor.deletion_chain_hash(d) FROM candor.deletion_list d WHERE d.seq = hi) THEN
    RETURN NEW;
  END IF;
  IF NEW.seq = lo - 1
     AND candor.deletion_chain_hash(NEW) = (SELECT d.prev_hash FROM candor.deletion_list d WHERE d.seq = lo) THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'deletion_list insert must extend the chain' USING ERRCODE = 'P0004';
END
$fn$;
REVOKE ALL ON FUNCTION candor.deletion_list_append() FROM PUBLIC;
CREATE TRIGGER deletion_list_append BEFORE INSERT ON candor.deletion_list
  FOR EACH ROW EXECUTE FUNCTION candor.deletion_list_append();
CREATE FUNCTION candor.deletion_list_guard() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, candor AS $fn$
DECLARE
  acked bigint;
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF NEW.seq <> OLD.seq OR NEW.kind <> OLD.kind OR NEW.del_hash <> OLD.del_hash
       OR NEW.del_day <> OLD.del_day OR NEW.prev_hash <> OLD.prev_hash OR NEW.sig <> OLD.sig
       OR (OLD.relayed AND NOT NEW.relayed) THEN
      RAISE EXCEPTION 'deletion_list is append-only' USING ERRCODE = 'P0004';
    END IF;
    IF NEW.relayed <> OLD.relayed THEN
      SELECT m.deletion_acked_seq INTO acked FROM candor.intake_meta m;
      IF current_user <> 'candor_intake_maint' OR acked IS NULL OR NEW.seq > acked THEN
        RAISE EXCEPTION 'only acknowledged entries are flagged, by the maintenance role' USING ERRCODE = 'P0004';
      END IF;
    END IF;
    RETURN NEW;
  END IF;
  IF current_user <> 'candor_intake_maint' OR NOT OLD.relayed
     OR OLD.seq >= (SELECT max(d.seq) FROM candor.deletion_list d) THEN
    RAISE EXCEPTION 'deletion_list entry cannot be pruned' USING ERRCODE = 'P0004';
  END IF;
  RETURN OLD;
END
$fn$;
REVOKE ALL ON FUNCTION candor.deletion_list_guard() FROM PUBLIC;
CREATE TRIGGER deletion_list_guard BEFORE UPDATE OR DELETE ON candor.deletion_list
  FOR EACH ROW EXECUTE FUNCTION candor.deletion_list_guard();

-- directory_snapshot — SEC. Current + previous version only. applied_day is
-- coarsened to the first day of the month (AUD-RM2-STO-01).
CREATE TABLE candor.directory_snapshot (
  version     bigint PRIMARY KEY CHECK (version > 0),
  body        bytea  NOT NULL CHECK (octet_length(body) BETWEEN 1 AND 33554432),
  signatures  bytea  NOT NULL CHECK (octet_length(signatures) BETWEEN 1 AND 1048576),
  applied_day date   NOT NULL CHECK (EXTRACT(DAY FROM applied_day) = 1)
);

-- counter_month (ADR-046(5)) — SS aggregate. No per-day counters (L15).
CREATE TABLE candor.counter_month (
  month      date               NOT NULL CHECK (EXTRACT(DAY FROM month) = 1),
  channel_id uuid               NOT NULL,
  name       candor.counter_name NOT NULL,
  value      integer            NOT NULL CHECK (value >= 0),
  PRIMARY KEY (month, channel_id, name)
);

-- TOAST exposure (AUD-RM2-STO-18). Out-of-line values keep the xmin of the
-- transaction that stored them and a chunk_id from the cluster-wide OID counter
-- unless they are re-created. Account and envelope rows (≤ ~5.5 KB) are kept
-- in line (no TOAST row, so no chunk_id or separate xmin at all); slot blocks,
-- reply ciphertexts and snapshots cannot fit a page and are re-created by the
-- import-slot rewrite in a CSPRNG-shuffled order. Ciphertexts are stored
-- EXTERNAL (uncompressed: compression of random data is wasted work).
ALTER TABLE candor.source_account SET (toast_tuple_target = 8160);
ALTER TABLE candor.envelope       SET (toast_tuple_target = 8160);
ALTER TABLE candor.envelope_part ALTER COLUMN slot_block SET STORAGE EXTERNAL;
ALTER TABLE candor.reply ALTER COLUMN reply_ct SET STORAGE EXTERNAL;

-- No autovacuum on intake tables (AUD-RM2-STO-11): its timing would follow
-- source activity (and needs track_counts). VACUUM runs at every fixed import
-- slot and VACUUM FULL daily in the maintenance window, as the maintenance role
-- (pg.rs vacuum_after_rewrite / vacuum_full_daily); this also holds if the
-- cluster-wide autovacuum = off were forgotten. PostgreSQL still forces an
-- anti-wraparound VACUUM when a table nears autovacuum_freeze_max_age.
ALTER TABLE candor.source_account     SET (autovacuum_enabled = false, toast.autovacuum_enabled = false);
ALTER TABLE candor.envelope           SET (autovacuum_enabled = false, toast.autovacuum_enabled = false);
ALTER TABLE candor.envelope_part      SET (autovacuum_enabled = false, toast.autovacuum_enabled = false);
ALTER TABLE candor.reply              SET (autovacuum_enabled = false, toast.autovacuum_enabled = false);
ALTER TABLE candor.deletion_list      SET (autovacuum_enabled = false, toast.autovacuum_enabled = false);
ALTER TABLE candor.counter_month      SET (autovacuum_enabled = false, toast.autovacuum_enabled = false);
ALTER TABLE candor.directory_snapshot SET (autovacuum_enabled = false, toast.autovacuum_enabled = false);
ALTER TABLE candor.intake_meta        SET (autovacuum_enabled = false, toast.autovacuum_enabled = false);

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
GRANT SELECT ON candor.schema_migration TO candor_istore, candor_intake_maint;
GRANT SELECT, INSERT ON candor.intake_meta TO candor_istore;
-- No UPDATE of tenant_id, schema_hash, kdf_salt or config_version (AUD-RM2-STO-08).
GRANT UPDATE (relay_req_counter, last_batch_no, directory_version, kd_tree_size_hwm,
  kd_checkpoint_day_hwm, restore_pending, deletion_acked_seq, deletion_acked_hash, deletion_acked_sig,
  deletion_acked_day, deletion_acked_counter)
  ON candor.intake_meta TO candor_istore;
-- Called from the guard triggers in the application role's context.
GRANT EXECUTE ON FUNCTION candor.deletion_chain_hash(candor.deletion_list),
  candor.deletion_head_in_chain(bigint, bytea) TO candor_istore;
GRANT SELECT, INSERT, UPDATE, DELETE ON candor.source_account, candor.envelope, candor.envelope_part,
  candor.reply, candor.directory_snapshot, candor.counter_month TO candor_istore;
-- deletion_list: append and unchanged rewrite only; no DELETE (AUD-RM2-STO-03).
GRANT SELECT, INSERT ON candor.deletion_list TO candor_istore;
GRANT UPDATE (relayed) ON candor.deletion_list TO candor_istore;
-- Maintenance role: flag acknowledged entries and prune; nothing else.
GRANT SELECT ON candor.intake_meta TO candor_intake_maint;
GRANT SELECT, DELETE ON candor.deletion_list TO candor_intake_maint;
GRANT UPDATE (relayed) ON candor.deletion_list TO candor_intake_maint;
-- Backup role (RL-10 snapshot job): read-only on exactly the snapshot tables.
GRANT SELECT ON candor.intake_meta, candor.source_account, candor.deletion_list TO candor_intake_backup;
