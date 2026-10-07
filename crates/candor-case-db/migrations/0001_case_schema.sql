-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Candor Case DB (C-12) schema: 09-DATABASE.md §5.2–§5.5, §6, §7, §8, §10, §11.
-- Forward-only (09 §11). Run by `candorctl migrate` as the database owner /
-- superuser of a fresh cluster; never at service start. Every object below the
-- role block is owned by the NOLOGIN migrator (DB-002). Exact-time columns exist
-- only in the 09 §8 L3 allow-list; no time default on any source-linked table.
-- The audit tables of 09 §5.5 live in schema `audit` of this database
-- (SPEC-NOTES decision 2); the Erasure Key Vault (§5.6) is never a schema.

-- Roles (cluster-wide, idempotent). Production provisions them at deployment
-- (18-DEPLOYMENT.md); creating them needs CREATEROLE.
DO $roles$
DECLARE r text;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'candor_migrator') THEN
    CREATE ROLE candor_migrator NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
  END IF;
  FOREACH r IN ARRAY ARRAY['candor_case', 'candor_admin', 'candor_relay', 'candor_worker', 'candor_notify',
                           'candor_kd', 'candor_auth', 'candor_audit_w', 'candor_audit_r', 'candor_monitor'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = r) THEN
      EXECUTE pg_catalog.format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION', r);
    END IF;
  END LOOP;
END
$roles$;

-- Per-database role settings (09 §10 "Roles"): pinned search_path, statement
-- timeout (30 s app, 10 min worker), idle-in-transaction timeout.
DO $settings$
DECLARE r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['candor_case', 'candor_admin', 'candor_relay', 'candor_worker', 'candor_notify',
                           'candor_kd', 'candor_auth', 'candor_audit_w', 'candor_audit_r', 'candor_monitor'] LOOP
    EXECUTE pg_catalog.format('ALTER ROLE %I IN DATABASE %I SET search_path = candor, core', r, pg_catalog.current_database());
    EXECUTE pg_catalog.format('ALTER ROLE %I IN DATABASE %I SET idle_in_transaction_session_timeout = %L', r, pg_catalog.current_database(), '60s');
    EXECUTE pg_catalog.format('ALTER ROLE %I IN DATABASE %I SET statement_timeout = %L', r, pg_catalog.current_database(),
      CASE WHEN r = 'candor_worker' THEN '10min' ELSE '30s' END);
  END LOOP;
  EXECUTE pg_catalog.format('ALTER ROLE candor_monitor IN DATABASE %I SET default_transaction_read_only = on', pg_catalog.current_database());
  EXECUTE pg_catalog.format('ALTER ROLE candor_audit_r IN DATABASE %I SET default_transaction_read_only = on', pg_catalog.current_database());
END
$settings$;

-- Superuser-only settings (09 §10 temp_file_limit): applied when the migration
-- runs as a superuser (test clusters); production provisioning applies the same.
DO $su$
DECLARE r text;
BEGIN
  IF (SELECT x.rolsuper FROM pg_catalog.pg_roles x WHERE x.rolname = current_user) THEN
    FOREACH r IN ARRAY ARRAY['candor_case', 'candor_admin', 'candor_relay', 'candor_worker', 'candor_notify',
                             'candor_kd', 'candor_auth', 'candor_audit_w', 'candor_audit_r', 'candor_monitor'] LOOP
      EXECUTE pg_catalog.format('ALTER ROLE %I IN DATABASE %I SET temp_file_limit = %L', r, pg_catalog.current_database(), '1GB');
    END LOOP;
  END IF;
END
$su$;

REVOKE ALL ON SCHEMA public FROM PUBLIC;
DO $db$
BEGIN
  IF (SELECT x.rolsuper FROM pg_catalog.pg_roles x WHERE x.rolname = current_user)
     OR pg_catalog.pg_has_role(current_user, (SELECT d.datdba FROM pg_catalog.pg_database d
                                              WHERE d.datname = pg_catalog.current_database()), 'USAGE') THEN
    EXECUTE pg_catalog.format('REVOKE ALL ON DATABASE %I FROM PUBLIC', pg_catalog.current_database());
    EXECUTE pg_catalog.format('GRANT CONNECT ON DATABASE %I TO candor_case, candor_admin, candor_relay, candor_worker, candor_notify, candor_kd, candor_auth, candor_audit_w, candor_audit_r, candor_monitor', pg_catalog.current_database());
    EXECUTE pg_catalog.format('GRANT CREATE ON DATABASE %I TO candor_migrator', pg_catalog.current_database());
  END IF;
END
$db$;

-- Everything below is owned by the NOLOGIN migrator (DB-002).
SET LOCAL ROLE candor_migrator;

CREATE SCHEMA candor AUTHORIZATION candor_migrator;
CREATE SCHEMA core   AUTHORIZATION candor_migrator;
CREATE SCHEMA auth   AUTHORIZATION candor_migrator;
CREATE SCHEMA kd     AUTHORIZATION candor_migrator;
CREATE SCHEMA audit  AUTHORIZATION candor_migrator;
DO $schemas$
DECLARE s text;
BEGIN
  FOREACH s IN ARRAY ARRAY['candor', 'core', 'auth', 'kd', 'audit'] LOOP
    EXECUTE pg_catalog.format('REVOKE ALL ON SCHEMA %I FROM PUBLIC', s);
    EXECUTE pg_catalog.format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I REVOKE ALL ON TABLES FROM PUBLIC', s);
    EXECUTE pg_catalog.format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I REVOKE ALL ON FUNCTIONS FROM PUBLIC', s);
    EXECUTE pg_catalog.format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I REVOKE ALL ON TYPES FROM PUBLIC', s);
  END LOOP;
END
$schemas$;
GRANT USAGE ON SCHEMA candor, core TO candor_case, candor_admin, candor_relay, candor_worker, candor_notify, candor_kd, candor_auth, candor_monitor;
GRANT USAGE ON SCHEMA kd TO candor_case, candor_admin, candor_relay, candor_worker, candor_kd, candor_auth;
GRANT USAGE ON SCHEMA auth TO candor_auth, candor_admin, candor_case, candor_worker;
GRANT USAGE ON SCHEMA candor, audit TO candor_audit_w, candor_audit_r;

-- ---------------------------------------------------------------------------
-- Session context helpers (09 §6.1): SECURITY INVOKER, STABLE, fail closed.
-- ---------------------------------------------------------------------------
CREATE FUNCTION candor.tenant() RETURNS uuid
  LANGUAGE plpgsql STABLE SET search_path = pg_catalog AS $fn$
DECLARE v text := pg_catalog.current_setting('candor.tenant_id', true);
BEGIN
  IF v IS NULL OR v = '' THEN
    RAISE EXCEPTION 'candor: tenant context missing' USING ERRCODE = '42501';
  END IF;
  RETURN v::uuid;
END
$fn$;
CREATE FUNCTION candor.uid() RETURNS uuid
  LANGUAGE plpgsql STABLE SET search_path = pg_catalog AS $fn$
DECLARE v text := pg_catalog.current_setting('candor.user_id', true);
BEGIN
  IF v IS NULL OR v = '' THEN
    RAISE EXCEPTION 'candor: user context missing' USING ERRCODE = '42501';
  END IF;
  RETURN v::uuid;
END
$fn$;
CREATE FUNCTION candor.principal() RETURNS text
  LANGUAGE plpgsql STABLE SET search_path = pg_catalog AS $fn$
DECLARE v text := pg_catalog.current_setting('candor.principal_kind', true);
BEGIN
  IF v IS NULL OR v = '' THEN
    RAISE EXCEPTION 'candor: principal context missing' USING ERRCODE = '42501';
  END IF;
  RETURN v;
END
$fn$;
REVOKE ALL ON FUNCTION candor.tenant(), candor.uid(), candor.principal() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION candor.tenant(), candor.uid(), candor.principal() TO candor_case, candor_admin, candor_relay,
  candor_worker, candor_notify, candor_kd, candor_auth, candor_audit_w, candor_audit_r, candor_monitor;

-- Forward-only migration ledger and build identity (BE-050). No time column.
CREATE TABLE candor.schema_migration (
  version integer PRIMARY KEY CHECK (version > 0),
  sha256  bytea   NOT NULL CHECK (octet_length(sha256) = 32)
);
CREATE TABLE candor.schema_meta (
  singleton   boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  schema_hash bytea   NOT NULL CHECK (octet_length(schema_hash) = 32)
);
-- Column classification (09 §3, §8 L5); rows are loaded by the migrator from
-- the build's classification file (candor-case-db/classification.tsv).
CREATE TYPE candor.data_class AS ENUM ('SS', 'CT', 'WF', 'SEC', 'SYS');
CREATE TABLE candor.column_class (
  table_schema text NOT NULL CHECK (char_length(table_schema) BETWEEN 1 AND 63),
  table_name   text NOT NULL CHECK (char_length(table_name) BETWEEN 1 AND 63),
  column_name  text NOT NULL CHECK (char_length(column_name) BETWEEN 1 AND 63),
  class        candor.data_class NOT NULL,
  ciphertext   boolean NOT NULL,
  PRIMARY KEY (table_schema, table_name, column_name)
);
GRANT SELECT ON candor.schema_migration, candor.schema_meta, candor.column_class TO candor_case, candor_admin,
  candor_relay, candor_worker, candor_notify, candor_kd, candor_auth, candor_audit_w, candor_audit_r, candor_monitor;

-- Generic guards.
CREATE FUNCTION candor.append_only() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog AS $fn$
BEGIN
  RAISE EXCEPTION 'append-only table' USING ERRCODE = 'P0003';
END
$fn$;
-- Optimistic concurrency (07 §5.5): an UPDATE must carry version = old + 1.
CREATE FUNCTION candor.version_guard() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog AS $fn$
BEGIN
  IF NEW.version <> OLD.version + 1 THEN
    RAISE EXCEPTION 'version must increase by one' USING ERRCODE = 'P0005';
  END IF;
  RETURN NEW;
END
$fn$;
REVOKE ALL ON FUNCTION candor.append_only(), candor.version_guard() FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- core: enums
-- ---------------------------------------------------------------------------
CREATE TYPE core.risk_class AS ENUM ('low', 'moderate', 'high');
CREATE TYPE core.tenant_state AS ENUM ('active', 'suspended');
CREATE TYPE core.channel_mode AS ENUM ('anonymous', 'confidential', 'identified');
CREATE TYPE core.channel_type AS ENUM ('standard', 'independent');
CREATE TYPE core.channel_state AS ENUM ('active', 'disabled');
CREATE TYPE core.channel_member_state AS ENUM ('pending_timelock', 'pending_keys', 'active', 'suspended', 'removed');
CREATE TYPE core.roster_change_kind AS ENUM ('add_member', 'relabel', 'coi_loosen', 'coi_tighten', 'remove_member', 'triage_change');
CREATE TYPE core.roster_change_state AS ENUM ('proposed', 'approved_timelocked', 'effective', 'cancelled');
CREATE TYPE core.scope_type AS ENUM ('tenant', 'department', 'channel');
CREATE TYPE core.coi_reason AS ENUM ('family_relation', 'reporting_line', 'financial_interest', 'prior_involvement', 'other_standing');
CREATE TYPE core.user_state AS ENUM ('invited', 'active', 'disabled');
CREATE TYPE core.permission_class AS ENUM ('content', 'workflow', 'admin', 'security');
CREATE TYPE core.import_state AS ENUM ('pending', 'imported', 'duplicate', 'rejected');
CREATE TYPE core.access_level AS ENUM ('read', 'contribute', 'lead', 'records');
CREATE TYPE core.member_via AS ENUM ('normal', 'breakglass', 'records_grant');
CREATE TYPE core.case_member_state AS ENUM ('active', 'suspended', 'revoked');
CREATE TYPE core.record_kind AS ENUM ('note', 'task', 'decision', 'system');
CREATE TYPE core.message_direction AS ENUM ('from_source', 'to_source');
CREATE TYPE core.evidence_origin AS ENUM ('source_attachment', 'staff_upload');
CREATE TYPE core.evidence_state AS ENUM ('active', 'erased');
CREATE TYPE core.legal_basis AS ENUM ('legal_obligation', 'court_order', 'internal_investigation', 'consent', 'regulatory_request');
CREATE TYPE core.unseal_state AS ENUM ('pending', 'approved', 'rejected', 'used');
CREATE TYPE core.workflow_state AS ENUM ('draft', 'published', 'retired');
CREATE TYPE core.sla_kind AS ENUM ('acknowledge', 'feedback', 'custom');
CREATE TYPE core.sla_state AS ENUM ('running', 'paused', 'met', 'breached', 'cancelled');
CREATE TYPE core.retention_action AS ENUM ('crypto_erase', 'review');
CREATE TYPE core.deletion_reason AS ENUM ('source_request', 'retention_expiry', 'legal_requirement', 'duplicate_case');
CREATE TYPE core.deletion_state AS ENUM ('pending', 'approved', 'executed', 'rejected');
CREATE TYPE core.wrap_deletion_state AS ENUM ('pending', 'approved', 'executed', 'cancelled', 'blocked_min_holders');
CREATE TYPE core.breakglass_reason AS ENUM ('member_unavailable', 'legal_deadline', 'incident_response', 'records_obligation');
CREATE TYPE core.breakglass_state AS ENUM ('requested', 'approved_pending_wrap', 'active', 'expired', 'rejected', 'reviewed');
CREATE TYPE core.review_outcome AS ENUM ('justified', 'unjustified', 'inconclusive');
CREATE TYPE core.outbox_state AS ENUM ('queued', 'pushed');
CREATE TYPE core.deletion_kind AS ENUM ('account', 'mailbox', 'reply');
CREATE TYPE core.export_kind AS ENUM ('redacted', 'original');
CREATE TYPE core.export_destination AS ENUM ('media', 'connector');
CREATE TYPE core.export_state AS ENUM ('pending_approval', 'approved', 'rejected', 'delivered', 'expired');
CREATE TYPE core.approval_decision AS ENUM ('approve', 'reject');
CREATE TYPE core.notify_channel AS ENUM ('smtp', 'matrix', 'webhook');
CREATE TYPE core.notify_mode AS ENUM ('daily_constant', 'off');
CREATE TYPE core.notif_template AS ENUM ('T1');
CREATE TYPE core.notif_state AS ENUM ('queued', 'sent', 'dropped');
CREATE TYPE core.job_state AS ENUM ('ready', 'running', 'done', 'dead');
CREATE TYPE core.config_class AS ENUM ('safe', 'advanced', 'dangerous');
CREATE TYPE core.config_state AS ENUM ('proposed', 'approved', 'effective', 'cancelled');
CREATE TYPE core.blob_store AS ENUM ('fs', 's3');

-- ---------------------------------------------------------------------------
-- core 5.2.1 tenancy and organization
-- ---------------------------------------------------------------------------
CREATE TABLE core.tenant (
  tenant_id  uuid PRIMARY KEY,
  label      text NOT NULL CHECK (char_length(label) BETWEEN 1 AND 64),
  risk_class core.risk_class NOT NULL,
  state      core.tenant_state NOT NULL DEFAULT 'active',
  version    bigint NOT NULL DEFAULT 1 CHECK (version >= 1)
);

CREATE TABLE core.department (
  tenant_id     uuid NOT NULL REFERENCES core.tenant (tenant_id),
  department_id uuid NOT NULL,
  label         text NOT NULL CHECK (char_length(label) BETWEEN 1 AND 128),
  parent_id     uuid NULL,
  PRIMARY KEY (tenant_id, department_id),
  FOREIGN KEY (tenant_id, parent_id) REFERENCES core.department (tenant_id, department_id)
);

CREATE TABLE core.retention_policy (
  tenant_id               uuid NOT NULL REFERENCES core.tenant (tenant_id),
  retention_policy_id     uuid NOT NULL,
  retain_days_after_close integer NOT NULL CHECK (retain_days_after_close BETWEEN 30 AND 3650),
  action                  core.retention_action NOT NULL,
  legal_basis_code        core.legal_basis NOT NULL,
  version                 bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  PRIMARY KEY (tenant_id, retention_policy_id)
);

CREATE TABLE core.workflow_definition (
  tenant_id       uuid NOT NULL REFERENCES core.tenant (tenant_id),
  workflow_def_id uuid NOT NULL,
  version         integer NOT NULL CHECK (version >= 1),
  definition      jsonb NOT NULL CHECK (pg_column_size(definition) <= 262144),
  state           core.workflow_state NOT NULL DEFAULT 'draft',
  published_by    uuid NOT NULL,
  PRIMARY KEY (tenant_id, workflow_def_id, version)
);

CREATE TABLE core.channel (
  tenant_id              uuid NOT NULL REFERENCES core.tenant (tenant_id),
  channel_id             uuid NOT NULL,
  public_label_i18n      jsonb NOT NULL CHECK (pg_column_size(public_label_i18n) <= 16384),
  mode                   core.channel_mode NOT NULL,
  workflow_def_id        uuid NOT NULL,
  retention_policy_id    uuid NOT NULL,
  reply_enabled          boolean NOT NULL DEFAULT false,
  min_recipients         smallint NOT NULL DEFAULT 2 CHECK (min_recipients BETWEEN 1 AND 16),
  alternative_channel_id uuid NULL,
  channel_type           core.channel_type NOT NULL DEFAULT 'standard',
  state                  core.channel_state NOT NULL DEFAULT 'active',
  version                bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  PRIMARY KEY (tenant_id, channel_id),
  FOREIGN KEY (tenant_id, retention_policy_id) REFERENCES core.retention_policy (tenant_id, retention_policy_id),
  FOREIGN KEY (tenant_id, alternative_channel_id) REFERENCES core.channel (tenant_id, channel_id),
  CHECK (alternative_channel_id IS NULL OR alternative_channel_id <> channel_id),
  CHECK (mode <> 'anonymous' OR alternative_channel_id IS NOT NULL)
);

CREATE TABLE core.app_user (
  tenant_id     uuid NOT NULL REFERENCES core.tenant (tenant_id),
  user_id       uuid NOT NULL,
  username      text NOT NULL CHECK (char_length(username) BETWEEN 1 AND 128),
  display_name  text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 128),
  state         core.user_state NOT NULL DEFAULT 'invited',
  department_id uuid NULL,
  version       bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  PRIMARY KEY (tenant_id, user_id),
  FOREIGN KEY (tenant_id, department_id) REFERENCES core.department (tenant_id, department_id)
);
CREATE UNIQUE INDEX app_user_username ON core.app_user (tenant_id, pg_catalog.lower(username));

CREATE TABLE core.channel_member (
  tenant_id       uuid NOT NULL REFERENCES core.tenant (tenant_id),
  channel_id      uuid NOT NULL,
  user_id         uuid NOT NULL,
  role_label_i18n jsonb NOT NULL CHECK (pg_column_size(role_label_i18n) <= 16384),
  show_name       boolean NOT NULL DEFAULT false,
  label_index     smallint NOT NULL CHECK (label_index BETWEEN 0 AND 255),
  triage          boolean NOT NULL DEFAULT false,
  label_cert_leaf bigint NULL CHECK (label_cert_leaf >= 0),
  effective_day   date NOT NULL,
  state           core.channel_member_state NOT NULL DEFAULT 'pending_timelock',
  version         bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  PRIMARY KEY (tenant_id, channel_id, user_id),
  FOREIGN KEY (tenant_id, channel_id) REFERENCES core.channel (tenant_id, channel_id),
  FOREIGN KEY (tenant_id, user_id) REFERENCES core.app_user (tenant_id, user_id),
  UNIQUE (tenant_id, channel_id, label_index)
);

CREATE TABLE core.roster_change (
  tenant_id       uuid NOT NULL REFERENCES core.tenant (tenant_id),
  change_id       uuid NOT NULL,
  channel_id      uuid NOT NULL,
  kind            core.roster_change_kind NOT NULL,
  subject_user_id uuid NULL,
  proposed_by     uuid NOT NULL,
  approved_by     uuid NULL,
  proposed_day    date NOT NULL,
  effective_day   date NULL,
  state           core.roster_change_state NOT NULL DEFAULT 'proposed',
  PRIMARY KEY (tenant_id, change_id),
  FOREIGN KEY (tenant_id, channel_id) REFERENCES core.channel (tenant_id, channel_id),
  CHECK (approved_by IS NULL OR approved_by <> proposed_by),
  CHECK (state = 'proposed' OR approved_by IS NOT NULL)
);

CREATE TABLE core.coi_category (
  tenant_id               uuid NOT NULL REFERENCES core.tenant (tenant_id),
  channel_id              uuid NOT NULL,
  category_id             smallint NOT NULL CHECK (category_id BETWEEN 0 AND 255),
  label_i18n              jsonb NOT NULL CHECK (pg_column_size(label_i18n) <= 16384),
  excluded_label_indexes  smallint[] NOT NULL CHECK (cardinality(excluded_label_indexes) <= 256),
  PRIMARY KEY (tenant_id, channel_id, category_id),
  FOREIGN KEY (tenant_id, channel_id) REFERENCES core.channel (tenant_id, channel_id)
);

CREATE TABLE core.coi_registry (
  tenant_id   uuid NOT NULL REFERENCES core.tenant (tenant_id),
  entry_id    uuid NOT NULL,
  user_id     uuid NOT NULL,
  scope_type  core.scope_type NOT NULL,
  scope_id    uuid NULL,
  reason_code core.coi_reason NOT NULL,
  PRIMARY KEY (tenant_id, entry_id),
  FOREIGN KEY (tenant_id, user_id) REFERENCES core.app_user (tenant_id, user_id),
  CHECK ((scope_type = 'tenant') = (scope_id IS NULL))
);

-- ---------------------------------------------------------------------------
-- core 5.2.2 users, roles, permissions
-- ---------------------------------------------------------------------------
CREATE TABLE core.permission (
  permission_id text PRIMARY KEY CHECK (permission_id ~ '^[a-z_]+\.[a-z_]+$' AND char_length(permission_id) <= 64),
  class         core.permission_class NOT NULL
);

CREATE TABLE core.role (
  tenant_id      uuid NOT NULL REFERENCES core.tenant (tenant_id),
  role_id        uuid NOT NULL,
  name           text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64),
  built_in       boolean NOT NULL DEFAULT false,
  permission_ids text[] NOT NULL CHECK (cardinality(permission_ids) <= 256),
  PRIMARY KEY (tenant_id, role_id),
  UNIQUE (tenant_id, name)
);
-- ADR-015: an admin-class role never carries a content-class permission.
CREATE FUNCTION core.role_permission_guard() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, core AS $fn$
BEGIN
  IF EXISTS (SELECT 1 FROM core.permission p WHERE p.permission_id = ANY (NEW.permission_ids) AND p.class = 'admin')
     AND EXISTS (SELECT 1 FROM core.permission p WHERE p.permission_id = ANY (NEW.permission_ids) AND p.class = 'content') THEN
    RAISE EXCEPTION 'admin role cannot hold content permissions' USING ERRCODE = 'P0006';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.unnest(NEW.permission_ids) x
             WHERE NOT EXISTS (SELECT 1 FROM core.permission p WHERE p.permission_id = x)) THEN
    RAISE EXCEPTION 'unknown permission' USING ERRCODE = 'P0006';
  END IF;
  IF TG_OP = 'UPDATE' AND OLD.built_in THEN
    RAISE EXCEPTION 'built-in role is immutable' USING ERRCODE = 'P0006';
  END IF;
  RETURN NEW;
END
$fn$;
REVOKE ALL ON FUNCTION core.role_permission_guard() FROM PUBLIC;
CREATE TRIGGER role_permission_guard BEFORE INSERT OR UPDATE ON core.role
  FOR EACH ROW EXECUTE FUNCTION core.role_permission_guard();

CREATE TABLE core.role_assignment (
  tenant_id       uuid NOT NULL REFERENCES core.tenant (tenant_id),
  assignment_id   uuid NOT NULL,
  user_id         uuid NOT NULL,
  role_id         uuid NOT NULL,
  scope_type      core.scope_type NOT NULL,
  scope_id        uuid NULL,
  valid_from_day  date NOT NULL,
  valid_until_day date NULL,
  granted_by      uuid NOT NULL,
  approved_by     uuid NULL,
  PRIMARY KEY (tenant_id, assignment_id),
  FOREIGN KEY (tenant_id, user_id) REFERENCES core.app_user (tenant_id, user_id),
  FOREIGN KEY (tenant_id, role_id) REFERENCES core.role (tenant_id, role_id),
  CHECK ((scope_type = 'tenant') = (scope_id IS NULL)),
  CHECK (valid_until_day IS NULL OR valid_until_day >= valid_from_day),
  CHECK (approved_by IS NULL OR approved_by <> granted_by)
);

-- ---------------------------------------------------------------------------
-- core 5.2.3 import (relay output). No kind, no received_date, no arrival time.
-- ---------------------------------------------------------------------------
CREATE TABLE core.import_envelope (
  tenant_id          uuid NOT NULL REFERENCES core.tenant (tenant_id),
  import_envelope_id uuid NOT NULL,
  channel_id         uuid NOT NULL,
  header_ct          bytea NOT NULL CHECK (octet_length(header_ct) BETWEEN 1 AND 8192),
  manifest_ct        bytea NOT NULL CHECK (octet_length(manifest_ct) BETWEEN 1 AND 65536),
  header_digest      bytea NULL CHECK (octet_length(header_digest) = 32),
  import_date        date NULL,
  disposition_ct     bytea NULL CHECK (octet_length(disposition_ct) BETWEEN 1 AND 4096),
  epoch_index        integer NOT NULL CHECK (epoch_index >= 0),
  import_batch_no    bigint NOT NULL CHECK (import_batch_no > 0),
  state              core.import_state NOT NULL DEFAULT 'pending',
  rejected_by        uuid[] NULL CHECK (cardinality(rejected_by) = 2 AND rejected_by[1] <> rejected_by[2]),
  escalated_date     date NULL,
  PRIMARY KEY (tenant_id, import_envelope_id),
  FOREIGN KEY (tenant_id, channel_id) REFERENCES core.channel (tenant_id, channel_id),
  UNIQUE (tenant_id, header_digest),
  -- L17: the slot date is kept only while pending.
  CHECK (state <> 'imported' OR import_date IS NULL),
  CHECK (state <> 'pending' OR import_date IS NOT NULL),
  CHECK ((state = 'rejected') = (rejected_by IS NOT NULL))
);
CREATE INDEX import_envelope_pending ON core.import_envelope (tenant_id, channel_id, import_date) WHERE state = 'pending';

CREATE TABLE core.import_envelope_part (
  tenant_id          uuid NOT NULL REFERENCES core.tenant (tenant_id),
  import_envelope_id uuid NOT NULL,
  part_no            smallint NOT NULL CHECK (part_no BETWEEN 0 AND 31),
  blob_id            uuid NOT NULL,
  padded_size        bigint NOT NULL CHECK (padded_size > 0 AND padded_size <= 4294967296),
  PRIMARY KEY (tenant_id, import_envelope_id, part_no),
  FOREIGN KEY (tenant_id, import_envelope_id) REFERENCES core.import_envelope (tenant_id, import_envelope_id) ON DELETE CASCADE,
  UNIQUE (tenant_id, blob_id)
);

-- ---------------------------------------------------------------------------
-- core 5.2.4 cases
-- ---------------------------------------------------------------------------
CREATE TABLE core."case" (
  tenant_id           uuid NOT NULL REFERENCES core.tenant (tenant_id),
  case_id             uuid NOT NULL,
  display_ref         text NOT NULL CHECK (display_ref ~ '^[A-Z2-7]{8}$'),
  channel_id          uuid NOT NULL,
  workflow_def_id     uuid NOT NULL,
  workflow_version    integer NOT NULL CHECK (workflow_version >= 1),
  state               text NOT NULL CHECK (char_length(state) BETWEEN 1 AND 64),
  priority            smallint NOT NULL CHECK (priority BETWEEN 0 AND 9),
  received_date       date NOT NULL,
  last_import_month   date NOT NULL CHECK (EXTRACT(DAY FROM last_import_month) = 1),
  opened_day          date NOT NULL,
  closed_day          date NULL,
  record_ct           bytea NOT NULL CHECK (octet_length(record_ct) BETWEEN 1 AND 262144),
  key_epoch           integer NOT NULL CHECK (key_epoch >= 0),
  retention_policy_id uuid NOT NULL,
  deletion_due_day    date NULL,
  legal_hold          boolean NOT NULL DEFAULT false,
  ek_missing          boolean NOT NULL DEFAULT false,
  version             bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  PRIMARY KEY (tenant_id, case_id),
  UNIQUE (tenant_id, display_ref),
  FOREIGN KEY (tenant_id, channel_id) REFERENCES core.channel (tenant_id, channel_id),
  FOREIGN KEY (tenant_id, retention_policy_id) REFERENCES core.retention_policy (tenant_id, retention_policy_id),
  FOREIGN KEY (tenant_id, workflow_def_id, workflow_version) REFERENCES core.workflow_definition (tenant_id, workflow_def_id, version),
  CHECK (closed_day IS NULL OR closed_day >= opened_day)
);
CREATE INDEX case_channel ON core."case" (tenant_id, channel_id, case_id);
CREATE INDEX case_deletion_due ON core."case" (tenant_id, deletion_due_day) WHERE deletion_due_day IS NOT NULL;

CREATE TABLE core.case_meta (
  tenant_id   uuid NOT NULL REFERENCES core.tenant (tenant_id),
  case_id     uuid NOT NULL,
  column_id   smallint NOT NULL CHECK (column_id BETWEEN 0 AND 255),
  meta_ct     bytea NOT NULL CHECK (octet_length(meta_ct) BETWEEN 1 AND 4096 AND octet_length(meta_ct) % 256 = 0),
  row_version bigint NOT NULL DEFAULT 1 CHECK (row_version >= 1),
  PRIMARY KEY (tenant_id, case_id, column_id),
  FOREIGN KEY (tenant_id, case_id) REFERENCES core."case" (tenant_id, case_id) ON DELETE CASCADE
);

CREATE TABLE core.submission (
  tenant_id          uuid NOT NULL REFERENCES core.tenant (tenant_id),
  case_id            uuid NOT NULL,
  import_envelope_id uuid NOT NULL,
  seq                integer NOT NULL CHECK (seq >= 0),
  PRIMARY KEY (tenant_id, case_id, import_envelope_id),
  FOREIGN KEY (tenant_id, case_id) REFERENCES core."case" (tenant_id, case_id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, import_envelope_id) REFERENCES core.import_envelope (tenant_id, import_envelope_id),
  UNIQUE (tenant_id, import_envelope_id),
  UNIQUE (tenant_id, case_id, seq)
);

CREATE TABLE core.breakglass_request (
  tenant_id      uuid NOT NULL REFERENCES core.tenant (tenant_id),
  request_id     uuid NOT NULL,
  case_id        uuid NOT NULL,
  requester_id   uuid NOT NULL,
  approver_id    uuid NULL,
  reviewer_id    uuid NULL,
  reason_code    core.breakglass_reason NOT NULL,
  legal_basis_ct bytea NOT NULL CHECK (octet_length(legal_basis_ct) BETWEEN 1 AND 65536),
  state          core.breakglass_state NOT NULL DEFAULT 'requested',
  expires_at     timestamptz NULL,
  review_due_day date NULL,
  review_outcome core.review_outcome NULL,
  version        bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  PRIMARY KEY (tenant_id, request_id),
  FOREIGN KEY (tenant_id, case_id) REFERENCES core."case" (tenant_id, case_id) ON DELETE CASCADE,
  CHECK (approver_id IS NULL OR approver_id <> requester_id),
  CHECK (reviewer_id IS NULL OR (reviewer_id <> requester_id AND reviewer_id <> approver_id)),
  CHECK (state IN ('requested', 'rejected') OR (approver_id IS NOT NULL AND expires_at IS NOT NULL AND review_due_day IS NOT NULL)),
  CHECK (state <> 'reviewed' OR (reviewer_id IS NOT NULL AND review_outcome IS NOT NULL))
);

CREATE TABLE core.case_member (
  tenant_id       uuid NOT NULL REFERENCES core.tenant (tenant_id),
  case_id         uuid NOT NULL,
  user_id         uuid NOT NULL,
  access_level    core.access_level NOT NULL,
  via             core.member_via NOT NULL DEFAULT 'normal',
  grant_ref       uuid NULL,
  valid_until_day date NULL,
  state           core.case_member_state NOT NULL DEFAULT 'active',
  version         bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  PRIMARY KEY (tenant_id, case_id, user_id),
  FOREIGN KEY (tenant_id, case_id) REFERENCES core."case" (tenant_id, case_id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, user_id) REFERENCES core.app_user (tenant_id, user_id),
  FOREIGN KEY (tenant_id, grant_ref) REFERENCES core.breakglass_request (tenant_id, request_id),
  CHECK ((via = 'breakglass') = (grant_ref IS NOT NULL)),
  CHECK (access_level <> 'records' OR (via = 'records_grant' AND valid_until_day IS NOT NULL)),
  CHECK (via <> 'records_grant' OR access_level = 'records')
);

CREATE TABLE core.case_key_wrap (
  tenant_id         uuid NOT NULL REFERENCES core.tenant (tenant_id),
  case_id           uuid NOT NULL,
  key_epoch         integer NOT NULL CHECK (key_epoch >= 0),
  recipient_key_id  bytea NOT NULL CHECK (octet_length(recipient_key_id) = 16),
  recipient_user_id uuid NULL,
  wrap_ct           bytea NOT NULL CHECK (octet_length(wrap_ct) BETWEEN 1 AND 2048),
  wrapped_by        uuid NOT NULL,
  PRIMARY KEY (tenant_id, case_id, key_epoch, recipient_key_id),
  FOREIGN KEY (tenant_id, case_id) REFERENCES core."case" (tenant_id, case_id) ON DELETE CASCADE
);

CREATE TABLE core.coi_excl_tag (
  tenant_id uuid NOT NULL REFERENCES core.tenant (tenant_id),
  case_id   uuid NOT NULL,
  tag       bytea NOT NULL CHECK (octet_length(tag) = 32),
  PRIMARY KEY (tenant_id, case_id, tag),
  FOREIGN KEY (tenant_id, case_id) REFERENCES core."case" (tenant_id, case_id) ON DELETE CASCADE
);

CREATE TABLE core.case_record (
  tenant_id      uuid NOT NULL REFERENCES core.tenant (tenant_id),
  record_id      uuid NOT NULL,
  case_id        uuid NOT NULL,
  kind           core.record_kind NOT NULL,
  seq            integer NOT NULL CHECK (seq >= 0),
  created_day    date NOT NULL,
  author_user_id uuid NULL,
  key_epoch      integer NOT NULL CHECK (key_epoch >= 0),
  body_ct        bytea NOT NULL CHECK (octet_length(body_ct) BETWEEN 1 AND 262144),
  size_bucket    smallint NOT NULL CHECK (size_bucket BETWEEN 1 AND 16),
  PRIMARY KEY (tenant_id, record_id),
  FOREIGN KEY (tenant_id, case_id) REFERENCES core."case" (tenant_id, case_id) ON DELETE CASCADE,
  UNIQUE (tenant_id, case_id, seq)
);

CREATE TABLE core.message (
  tenant_id          uuid NOT NULL REFERENCES core.tenant (tenant_id),
  message_id         uuid NOT NULL,
  case_id            uuid NOT NULL,
  direction          core.message_direction NOT NULL,
  import_envelope_id uuid NULL,
  day                date NULL,
  blob_id            uuid NULL,
  dek_wrap_ct        bytea NULL CHECK (octet_length(dek_wrap_ct) BETWEEN 1 AND 2048),
  body_ct            bytea NULL CHECK (octet_length(body_ct) BETWEEN 1 AND 262144),
  key_epoch          integer NOT NULL CHECK (key_epoch >= 0),
  size_bucket        smallint NOT NULL CHECK (size_bucket BETWEEN 1 AND 16),
  PRIMARY KEY (tenant_id, message_id),
  FOREIGN KEY (tenant_id, case_id) REFERENCES core."case" (tenant_id, case_id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, import_envelope_id) REFERENCES core.import_envelope (tenant_id, import_envelope_id),
  -- L17: no cleartext follow-up date; ADR-047(2).
  CHECK (direction <> 'from_source' OR (day IS NULL AND import_envelope_id IS NOT NULL)),
  CHECK (direction <> 'to_source' OR (import_envelope_id IS NULL AND blob_id IS NULL AND body_ct IS NOT NULL))
);
CREATE INDEX message_case ON core.message (tenant_id, case_id, message_id);

CREATE TABLE core.evidence_object (
  tenant_id   uuid NOT NULL REFERENCES core.tenant (tenant_id),
  evidence_id uuid NOT NULL,
  case_id     uuid NOT NULL,
  origin      core.evidence_origin NOT NULL,
  blob_id     uuid NOT NULL,
  dek_wrap_ct bytea NOT NULL CHECK (octet_length(dek_wrap_ct) BETWEEN 1 AND 2048),
  meta_ct     bytea NOT NULL CHECK (octet_length(meta_ct) BETWEEN 1 AND 65536),
  padded_size bigint NOT NULL CHECK (padded_size > 0 AND padded_size <= 4294967296),
  key_epoch   integer NOT NULL CHECK (key_epoch >= 0),
  state       core.evidence_state NOT NULL DEFAULT 'active',
  PRIMARY KEY (tenant_id, evidence_id),
  FOREIGN KEY (tenant_id, case_id) REFERENCES core."case" (tenant_id, case_id) ON DELETE CASCADE
);
-- ADR-012: ORIGINAL evidence is immutable except for `state`.
CREATE FUNCTION core.evidence_immutable() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog AS $fn$
BEGIN
  IF ROW(NEW.tenant_id, NEW.evidence_id, NEW.case_id, NEW.origin, NEW.blob_id, NEW.dek_wrap_ct, NEW.meta_ct, NEW.padded_size, NEW.key_epoch)
     IS DISTINCT FROM ROW(OLD.tenant_id, OLD.evidence_id, OLD.case_id, OLD.origin, OLD.blob_id, OLD.dek_wrap_ct, OLD.meta_ct, OLD.padded_size, OLD.key_epoch)
     OR (OLD.state = 'erased' AND NEW.state <> 'erased') THEN
    RAISE EXCEPTION 'evidence is immutable' USING ERRCODE = 'P0003';
  END IF;
  RETURN NEW;
END
$fn$;
REVOKE ALL ON FUNCTION core.evidence_immutable() FROM PUBLIC;
CREATE TRIGGER evidence_immutable BEFORE UPDATE ON core.evidence_object
  FOR EACH ROW EXECUTE FUNCTION core.evidence_immutable();

CREATE TABLE core.attachment (
  tenant_id   uuid NOT NULL REFERENCES core.tenant (tenant_id),
  message_id  uuid NOT NULL,
  evidence_id uuid NOT NULL,
  position    smallint NOT NULL CHECK (position BETWEEN 0 AND 255),
  PRIMARY KEY (tenant_id, message_id, evidence_id),
  FOREIGN KEY (tenant_id, message_id) REFERENCES core.message (tenant_id, message_id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, evidence_id) REFERENCES core.evidence_object (tenant_id, evidence_id) ON DELETE CASCADE,
  UNIQUE (tenant_id, message_id, position)
);

CREATE TABLE core.evidence_derivative (
  tenant_id         uuid NOT NULL REFERENCES core.tenant (tenant_id),
  derivative_id     uuid NOT NULL,
  case_id           uuid NOT NULL,
  derived_from      uuid NOT NULL,
  transformation_ct bytea NOT NULL CHECK (octet_length(transformation_ct) BETWEEN 1 AND 65536),
  blob_id           uuid NOT NULL,
  dek_wrap_ct       bytea NOT NULL CHECK (octet_length(dek_wrap_ct) BETWEEN 1 AND 2048),
  meta_ct           bytea NOT NULL CHECK (octet_length(meta_ct) BETWEEN 1 AND 65536),
  author_user_id    uuid NOT NULL,
  created_day       date NOT NULL,
  key_epoch         integer NOT NULL CHECK (key_epoch >= 0),
  PRIMARY KEY (tenant_id, derivative_id),
  FOREIGN KEY (tenant_id, case_id) REFERENCES core."case" (tenant_id, case_id) ON DELETE CASCADE
);

CREATE TABLE core.sealed_identity (
  tenant_id   uuid NOT NULL REFERENCES core.tenant (tenant_id),
  identity_id uuid NOT NULL,
  case_id     uuid NOT NULL,
  sealed_ct   bytea NOT NULL CHECK (octet_length(sealed_ct) BETWEEN 1 AND 16384),
  PRIMARY KEY (tenant_id, identity_id),
  FOREIGN KEY (tenant_id, case_id) REFERENCES core."case" (tenant_id, case_id) ON DELETE CASCADE
);

CREATE TABLE core.identity_unseal_request (
  tenant_id             uuid NOT NULL REFERENCES core.tenant (tenant_id),
  request_id            uuid NOT NULL,
  case_id               uuid NOT NULL,
  requested_by          uuid NOT NULL,
  legal_basis_code      core.legal_basis NOT NULL,
  justification_ct      bytea NOT NULL CHECK (octet_length(justification_ct) BETWEEN 1 AND 65536),
  approvals             uuid[] NOT NULL DEFAULT '{}' CHECK (cardinality(approvals) <= 16),
  state                 core.unseal_state NOT NULL DEFAULT 'pending',
  source_notice_due_day date NULL,
  PRIMARY KEY (tenant_id, request_id),
  FOREIGN KEY (tenant_id, case_id) REFERENCES core."case" (tenant_id, case_id) ON DELETE CASCADE,
  CHECK (NOT (requested_by = ANY (approvals)))
);

-- ---------------------------------------------------------------------------
-- core 5.2.5 workflow, SLA, retention, holds
-- ---------------------------------------------------------------------------
CREATE TABLE core.case_state_history (
  tenant_id     uuid NOT NULL REFERENCES core.tenant (tenant_id),
  case_id       uuid NOT NULL,
  seq           integer NOT NULL CHECK (seq >= 0),
  from_state    text NOT NULL CHECK (char_length(from_state) BETWEEN 1 AND 64),
  to_state      text NOT NULL CHECK (char_length(to_state) BETWEEN 1 AND 64),
  transition_id text NOT NULL CHECK (char_length(transition_id) BETWEEN 1 AND 64),
  actor_user_id uuid NOT NULL,
  day           date NOT NULL,
  PRIMARY KEY (tenant_id, case_id, seq),
  FOREIGN KEY (tenant_id, case_id) REFERENCES core."case" (tenant_id, case_id) ON DELETE CASCADE
);

CREATE TABLE core.sla_timer (
  tenant_id   uuid NOT NULL REFERENCES core.tenant (tenant_id),
  timer_id    uuid NOT NULL,
  case_id     uuid NOT NULL,
  kind        core.sla_kind NOT NULL,
  anchor_day  date NOT NULL,
  due_day     date NOT NULL,
  calendar_id uuid NULL,
  state       core.sla_state NOT NULL DEFAULT 'running',
  version     bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  PRIMARY KEY (tenant_id, timer_id),
  FOREIGN KEY (tenant_id, case_id) REFERENCES core."case" (tenant_id, case_id) ON DELETE CASCADE,
  CHECK (due_day >= anchor_day)
);
CREATE INDEX sla_timer_due ON core.sla_timer (tenant_id, due_day) WHERE state = 'running';

CREATE TABLE core.legal_hold (
  tenant_id           uuid NOT NULL REFERENCES core.tenant (tenant_id),
  hold_id             uuid NOT NULL,
  case_id             uuid NOT NULL,
  reason_ct           bytea NOT NULL CHECK (octet_length(reason_ct) BETWEEN 1 AND 65536),
  placed_by           uuid NOT NULL,
  released_by         uuid NULL,
  release_approved_by uuid NULL,
  placed_day          date NOT NULL,
  released_day        date NULL,
  version             bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  PRIMARY KEY (tenant_id, hold_id),
  FOREIGN KEY (tenant_id, case_id) REFERENCES core."case" (tenant_id, case_id) ON DELETE CASCADE,
  -- Release is dual-controlled: two distinct people, neither may be skipped.
  CHECK ((released_day IS NULL) = (released_by IS NULL) AND (released_by IS NULL) = (release_approved_by IS NULL)),
  CHECK (released_by IS NULL OR released_by <> release_approved_by),
  CHECK (released_day IS NULL OR released_day >= placed_day)
);
-- Derived `case.legal_hold` (09 §5.2.4): true while any hold of the case is
-- unreleased. Bumps the case version (clients re-fetch).
CREATE FUNCTION core.legal_hold_sync() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, core AS $fn$
DECLARE
  t uuid := COALESCE(NEW.tenant_id, OLD.tenant_id);
  c uuid := COALESCE(NEW.case_id, OLD.case_id);
BEGIN
  UPDATE core."case" k SET legal_hold = EXISTS (SELECT 1 FROM core.legal_hold h
      WHERE h.tenant_id = t AND h.case_id = c AND h.released_day IS NULL),
    version = k.version + 1
    WHERE k.tenant_id = t AND k.case_id = c
      AND k.legal_hold IS DISTINCT FROM EXISTS (SELECT 1 FROM core.legal_hold h
      WHERE h.tenant_id = t AND h.case_id = c AND h.released_day IS NULL);
  RETURN NULL;
END
$fn$;
REVOKE ALL ON FUNCTION core.legal_hold_sync() FROM PUBLIC;
CREATE TRIGGER legal_hold_sync AFTER INSERT OR UPDATE OR DELETE ON core.legal_hold
  FOR EACH ROW EXECUTE FUNCTION core.legal_hold_sync();

CREATE TABLE core.deletion_request (
  tenant_id    uuid NOT NULL REFERENCES core.tenant (tenant_id),
  request_id   uuid NOT NULL,
  case_id      uuid NOT NULL,
  requested_by uuid NOT NULL,
  approved_by  uuid NULL,
  reason_code  core.deletion_reason NOT NULL,
  state        core.deletion_state NOT NULL DEFAULT 'pending',
  version      bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  PRIMARY KEY (tenant_id, request_id),
  FOREIGN KEY (tenant_id, case_id) REFERENCES core."case" (tenant_id, case_id) ON DELETE CASCADE,
  CHECK (approved_by IS NULL OR approved_by <> requested_by),
  CHECK (state IN ('pending', 'rejected') OR approved_by IS NOT NULL)
);

CREATE TABLE core.wrap_deletion_request (
  tenant_id              uuid NOT NULL REFERENCES core.tenant (tenant_id),
  request_id             uuid NOT NULL,
  case_id                uuid NOT NULL,
  target_user_id         uuid NOT NULL,
  requested_by           uuid NOT NULL,
  approved_by            uuid NULL,
  requested_day          date NOT NULL,
  not_before_day         date NOT NULL,
  oversight_notified_day date NULL,
  state                  core.wrap_deletion_state NOT NULL DEFAULT 'pending',
  version                bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  PRIMARY KEY (tenant_id, request_id),
  FOREIGN KEY (tenant_id, case_id) REFERENCES core."case" (tenant_id, case_id) ON DELETE CASCADE,
  CHECK (approved_by IS NULL OR approved_by <> requested_by),
  CHECK (not_before_day >= requested_day + 7),
  CHECK (state IN ('pending', 'cancelled') OR approved_by IS NOT NULL),
  CHECK (state <> 'executed' OR oversight_notified_day IS NOT NULL)
);

-- ---------------------------------------------------------------------------
-- core 5.2.7 replies, exports, notifications
-- ---------------------------------------------------------------------------
CREATE TABLE core.reply_outbox (
  tenant_id  uuid NOT NULL REFERENCES core.tenant (tenant_id),
  outbox_id  uuid NOT NULL,
  routing_ct bytea NOT NULL CHECK (octet_length(routing_ct) BETWEEN 1 AND 2048),
  reply_ct   bytea NOT NULL CHECK (octet_length(reply_ct) BETWEEN 1 AND 70000),
  state      core.outbox_state NOT NULL DEFAULT 'queued',
  queued_day date NOT NULL,
  PRIMARY KEY (tenant_id, outbox_id)
);

CREATE TABLE core.intake_deletion_list (
  tenant_id uuid NOT NULL REFERENCES core.tenant (tenant_id),
  intake_id uuid NOT NULL,
  seq       bigint NOT NULL CHECK (seq > 0),
  kind      core.deletion_kind NOT NULL,
  del_hash  bytea NOT NULL CHECK (octet_length(del_hash) = 32),
  del_day   date NOT NULL,
  prev_hash bytea NOT NULL CHECK (octet_length(prev_hash) = 32),
  sig       bytea NOT NULL CHECK (octet_length(sig) = 64),
  PRIMARY KEY (tenant_id, intake_id, seq)
);

CREATE TABLE core.export_package (
  tenant_id        uuid NOT NULL REFERENCES core.tenant (tenant_id),
  export_id        uuid NOT NULL,
  case_id          uuid NOT NULL,
  kind             core.export_kind NOT NULL,
  destination_type core.export_destination NOT NULL,
  connector_id     uuid NULL,
  manifest_ct      bytea NOT NULL CHECK (octet_length(manifest_ct) BETWEEN 1 AND 262144),
  blob_id          uuid NULL,
  package_digest   bytea NOT NULL CHECK (octet_length(package_digest) = 32),
  created_by       uuid NOT NULL,
  state            core.export_state NOT NULL DEFAULT 'pending_approval',
  created_day      date NOT NULL,
  PRIMARY KEY (tenant_id, export_id),
  FOREIGN KEY (tenant_id, case_id) REFERENCES core."case" (tenant_id, case_id) ON DELETE CASCADE,
  CHECK ((destination_type = 'connector') = (connector_id IS NOT NULL))
);

CREATE TABLE core.export_approval (
  tenant_id        uuid NOT NULL REFERENCES core.tenant (tenant_id),
  export_id        uuid NOT NULL,
  approver_id      uuid NOT NULL,
  decision         core.approval_decision NOT NULL,
  digest_confirmed bytea NOT NULL CHECK (octet_length(digest_confirmed) = 32),
  day              date NOT NULL,
  PRIMARY KEY (tenant_id, export_id, approver_id),
  FOREIGN KEY (tenant_id, export_id) REFERENCES core.export_package (tenant_id, export_id) ON DELETE CASCADE
);
CREATE FUNCTION core.export_approval_guard() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, core AS $fn$
BEGIN
  IF EXISTS (SELECT 1 FROM core.export_package p WHERE p.tenant_id = NEW.tenant_id AND p.export_id = NEW.export_id
             AND (p.created_by = NEW.approver_id OR p.package_digest <> NEW.digest_confirmed)) THEN
    RAISE EXCEPTION 'export approval rejected' USING ERRCODE = 'P0006';
  END IF;
  RETURN NEW;
END
$fn$;
REVOKE ALL ON FUNCTION core.export_approval_guard() FROM PUBLIC;
CREATE TRIGGER export_approval_guard BEFORE INSERT OR UPDATE ON core.export_approval
  FOR EACH ROW EXECUTE FUNCTION core.export_approval_guard();

CREATE TABLE core.notification_target (
  tenant_id    uuid NOT NULL REFERENCES core.tenant (tenant_id),
  user_id      uuid NOT NULL,
  channel_type core.notify_channel NOT NULL,
  contact_uri  text NOT NULL CHECK (char_length(contact_uri) BETWEEN 1 AND 320),
  mode         core.notify_mode NOT NULL DEFAULT 'off',
  version      bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  PRIMARY KEY (tenant_id, user_id),
  FOREIGN KEY (tenant_id, user_id) REFERENCES core.app_user (tenant_id, user_id)
);

-- Content-free (ADR-017, ADR-038(2)): no case, envelope or channel reference.
CREATE TABLE core.notification_queue (
  tenant_id uuid NOT NULL REFERENCES core.tenant (tenant_id),
  notif_id  uuid NOT NULL,
  user_id   uuid NOT NULL,
  template  core.notif_template NOT NULL DEFAULT 'T1',
  due_day   date NOT NULL,
  state     core.notif_state NOT NULL DEFAULT 'queued',
  PRIMARY KEY (tenant_id, notif_id),
  UNIQUE (tenant_id, user_id, due_day)
);

-- ---------------------------------------------------------------------------
-- core 5.2.8 jobs, configuration, idempotency, blobs, counters
-- ---------------------------------------------------------------------------
CREATE TABLE core.job (
  tenant_id    uuid NOT NULL REFERENCES core.tenant (tenant_id),
  job_id       uuid NOT NULL,
  kind         text NOT NULL CHECK (kind IN ('notify_daily_digest', 'sla_evaluate', 'retention_evaluate',
                 'crypto_erase_case', 'import_escalate', 'ekv_backup', 'epoch_runway_check', 'epoch_key_destroy',
                 'blob_gc', 'chaff_discard', 'ek_rewrap_pending', 'deletion_list_prune', 'ekv_replicate',
                 'kd_timelock_activate', 'kd_weekly_publish', 'wrap_deletion_execute', 'records_grant_expire',
                 'timestamp_retention', 'audit_checkpoint', 'audit_anchor', 'audit_reconcile',
                 'kd_checkpoint_publish', 'kd_witness_cosign', 'backup_run', 'backup_verify', 'session_gc',
                 'breakglass_expire', 'breakglass_review_due', 'export_delivery', 'export_expire',
                 'legal_hold_review', 'counters_rollup', 'update_check', 'idempotency_gc')),
  payload      bytea NOT NULL CHECK (octet_length(payload) BETWEEN 1 AND 4096),
  priority     smallint NOT NULL DEFAULT 0 CHECK (priority BETWEEN -10 AND 10),
  run_after    timestamptz NOT NULL,
  lease_until  timestamptz NULL,
  attempts     smallint NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  max_attempts smallint NOT NULL DEFAULT 8 CHECK (max_attempts BETWEEN 1 AND 64),
  locked_by    text NULL CHECK (char_length(locked_by) BETWEEN 1 AND 64),
  state        core.job_state NOT NULL DEFAULT 'ready',
  PRIMARY KEY (tenant_id, job_id),
  CHECK ((state = 'running') = (lease_until IS NOT NULL AND locked_by IS NOT NULL))
);
CREATE INDEX job_ready ON core.job (tenant_id, kind, priority DESC, run_after) WHERE state = 'ready';

CREATE TABLE core.config_change (
  tenant_id       uuid NOT NULL REFERENCES core.tenant (tenant_id),
  change_id       uuid NOT NULL,
  items           jsonb NOT NULL CHECK (pg_column_size(items) <= 65536),
  class           core.config_class NOT NULL,
  proposed_by     uuid NOT NULL,
  signatures      jsonb NOT NULL CHECK (pg_column_size(signatures) <= 65536),
  effective_after timestamptz NOT NULL,
  state           core.config_state NOT NULL DEFAULT 'proposed',
  PRIMARY KEY (tenant_id, change_id)
);

CREATE TABLE core.config_bundle (
  tenant_id  uuid NOT NULL REFERENCES core.tenant (tenant_id),
  version    bigint NOT NULL CHECK (version > 0),
  body       bytea NOT NULL CHECK (octet_length(body) BETWEEN 1 AND 1048576),
  signatures bytea NOT NULL CHECK (octet_length(signatures) BETWEEN 1 AND 65536),
  PRIMARY KEY (tenant_id, version)
);

CREATE TABLE core.idempotency_key (
  tenant_id       uuid NOT NULL REFERENCES core.tenant (tenant_id),
  user_id         uuid NOT NULL,
  key             bytea NOT NULL CHECK (octet_length(key) = 16),
  response_status smallint NOT NULL CHECK (response_status BETWEEN 100 AND 599),
  resource_id     uuid NULL,
  expires_at      timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, user_id, key)
);

CREATE TABLE core.blob_object (
  tenant_id   uuid NOT NULL REFERENCES core.tenant (tenant_id),
  blob_id     uuid NOT NULL,
  store       core.blob_store NOT NULL,
  padded_size bigint NOT NULL CHECK (padded_size > 0 AND padded_size <= 4294967296),
  ct_sha256   bytea NOT NULL CHECK (octet_length(ct_sha256) = 32),
  refcount    integer NOT NULL DEFAULT 0 CHECK (refcount >= 0),
  PRIMARY KEY (tenant_id, blob_id)
);

CREATE TABLE core.aggregate_counter (
  tenant_id           uuid NOT NULL REFERENCES core.tenant (tenant_id),
  month               date NOT NULL CHECK (EXTRACT(DAY FROM month) = 1),
  channel_group_id    uuid NOT NULL,
  name                text NOT NULL CHECK (name ~ '^[a-z_]{1,64}$'),
  value_or_suppressed integer NULL CHECK (value_or_suppressed >= 10),
  PRIMARY KEY (tenant_id, month, channel_group_id, name)
);

-- ---------------------------------------------------------------------------
-- auth (09 §5.3): staff authentication state. Exact times allow-listed (L3).
-- ---------------------------------------------------------------------------
CREATE TYPE auth.credential_role AS ENUM ('primary', 'backup');
CREATE TYPE auth.device_state AS ENUM ('pending', 'active', 'revoked');
CREATE TYPE auth.audience AS ENUM ('desk_api', 'admin_api');
CREATE TYPE auth.auth_strength AS ENUM ('single', 'multi', 'stepup');

CREATE TABLE auth.webauthn_credential (
  tenant_id       uuid NOT NULL REFERENCES core.tenant (tenant_id),
  credential_id   bytea NOT NULL CHECK (octet_length(credential_id) BETWEEN 16 AND 1023),
  user_id         uuid NOT NULL,
  public_key      bytea NOT NULL CHECK (octet_length(public_key) BETWEEN 1 AND 1024),
  sign_count      bigint NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
  aaguid          uuid NOT NULL,
  transports      text[] NOT NULL DEFAULT '{}' CHECK (cardinality(transports) <= 8),
  role            auth.credential_role NOT NULL,
  attestation_ref bytea NULL CHECK (octet_length(attestation_ref) <= 64),
  created_day     date NOT NULL,
  PRIMARY KEY (tenant_id, credential_id),
  FOREIGN KEY (tenant_id, user_id) REFERENCES core.app_user (tenant_id, user_id)
);

CREATE TABLE auth.device (
  tenant_id        uuid NOT NULL REFERENCES core.tenant (tenant_id),
  device_id        uuid NOT NULL,
  user_id          uuid NOT NULL,
  device_key_pk    bytea NOT NULL CHECK (octet_length(device_key_pk) = 32),
  client_cert_spki bytea NOT NULL CHECK (octet_length(client_cert_spki) = 32),
  state            auth.device_state NOT NULL DEFAULT 'pending',
  enrolled_day     date NOT NULL,
  PRIMARY KEY (tenant_id, device_id),
  FOREIGN KEY (tenant_id, user_id) REFERENCES core.app_user (tenant_id, user_id)
);

CREATE TABLE auth.enrollment_token (
  tenant_id  uuid NOT NULL REFERENCES core.tenant (tenant_id),
  token_hash bytea NOT NULL CHECK (octet_length(token_hash) = 32),
  user_id    uuid NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, token_hash)
);

CREATE TABLE auth.session (
  tenant_id     uuid NOT NULL REFERENCES core.tenant (tenant_id),
  token_hash    bytea NOT NULL CHECK (octet_length(token_hash) = 32),
  audience      auth.audience NOT NULL,
  user_id       uuid NOT NULL,
  device_id     uuid NOT NULL,
  auth_strength auth.auth_strength NOT NULL,
  issued_at     timestamptz NOT NULL,
  expires_at    timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, token_hash),
  CHECK (expires_at > issued_at)
);

CREATE TABLE auth.refresh_token (
  tenant_id  uuid NOT NULL REFERENCES core.tenant (tenant_id),
  token_hash bytea NOT NULL CHECK (octet_length(token_hash) = 32),
  family_id  uuid NOT NULL,
  user_id    uuid NOT NULL,
  device_id  uuid NOT NULL,
  expires_at timestamptz NOT NULL,
  used       boolean NOT NULL DEFAULT false,
  PRIMARY KEY (tenant_id, token_hash)
);

CREATE TABLE auth.stepup_proof (
  tenant_id   uuid NOT NULL REFERENCES core.tenant (tenant_id),
  proof_hash  bytea NOT NULL CHECK (octet_length(proof_hash) = 32),
  user_id     uuid NOT NULL,
  action      text NOT NULL CHECK (char_length(action) BETWEEN 1 AND 64),
  resource_id uuid NULL,
  expires_at  timestamptz NOT NULL,
  used        boolean NOT NULL DEFAULT false,
  PRIMARY KEY (tenant_id, proof_hash)
);

-- pop_nonce (09 §5.3 says "unlogged"): kept logged so that a crash cannot
-- re-admit a nonce (fail closed); 120 s retention by `timestamp_retention`.
CREATE TABLE auth.pop_nonce (
  tenant_id uuid NOT NULL REFERENCES core.tenant (tenant_id),
  nonce     bytea NOT NULL CHECK (octet_length(nonce) = 16),
  seen_at   timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, nonce)
);

-- ---------------------------------------------------------------------------
-- kd (09 §5.4): key-directory log. Append-only; no private key material.
-- ---------------------------------------------------------------------------
CREATE TYPE kd.entry_type AS ENUM ('user_key', 'user_key_revoke', 'channel_identity', 'channel_roster',
  'role_label_cert', 'member_epoch_key', 'coi_map', 'routing_key', 'connector_key', 'recovery_quorum_state',
  'protection_statement', 'operator_statement', 'incident_notice', 'server_release', 'client_release',
  'config_signer', 'governance_roles', 'objection', 'sealer_attestation', 'server_state', 'disposition_key',
  'audit_export_key');
CREATE TYPE kd.checkpoint_slot AS ENUM ('daily', 'weekly_publication', 'removal', 'hourly');
CREATE TYPE kd.mek_state AS ENUM ('active', 'decrypt_only', 'destroy_due', 'destroyed');
CREATE TYPE kd.user_key_state AS ENUM ('active', 'revoked');

CREATE TABLE kd.kd_entry (
  tenant_id     uuid NOT NULL REFERENCES core.tenant (tenant_id),
  leaf_index    bigint NOT NULL CHECK (leaf_index >= 0),
  entry_type    kd.entry_type NOT NULL,
  subject_id    uuid NOT NULL,
  body          bytea NOT NULL CHECK (octet_length(body) BETWEEN 1 AND 262144),
  leaf_hash     bytea NOT NULL CHECK (octet_length(leaf_hash) = 32),
  signer_key_id bytea NOT NULL CHECK (octet_length(signer_key_id) = 32),
  sig           bytea NOT NULL CHECK (octet_length(sig) = 64),
  appended_day  date NOT NULL,
  effective_day date NOT NULL,
  PRIMARY KEY (tenant_id, leaf_index),
  CHECK (effective_day >= appended_day)
);
-- Dense per-tenant log: a leaf extends the log at max + 1 (0 for the first).
CREATE FUNCTION kd.entry_append() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, kd AS $fn$
BEGIN
  IF NEW.leaf_index <> COALESCE((SELECT max(e.leaf_index) + 1 FROM kd.kd_entry e WHERE e.tenant_id = NEW.tenant_id), 0) THEN
    RAISE EXCEPTION 'kd_entry must extend the log' USING ERRCODE = 'P0004';
  END IF;
  RETURN NEW;
END
$fn$;
REVOKE ALL ON FUNCTION kd.entry_append() FROM PUBLIC;
CREATE TRIGGER kd_entry_append BEFORE INSERT ON kd.kd_entry FOR EACH ROW EXECUTE FUNCTION kd.entry_append();
CREATE TRIGGER kd_entry_append_only BEFORE UPDATE OR DELETE ON kd.kd_entry FOR EACH ROW EXECUTE FUNCTION candor.append_only();

CREATE TABLE kd.kd_checkpoint (
  tenant_id   uuid NOT NULL REFERENCES core.tenant (tenant_id),
  tree_size   bigint NOT NULL CHECK (tree_size >= 0),
  root_hash   bytea NOT NULL CHECK (octet_length(root_hash) = 32),
  note        bytea NOT NULL CHECK (octet_length(note) BETWEEN 1 AND 16384),
  created_day date NOT NULL,
  slot        kd.checkpoint_slot NOT NULL,
  PRIMARY KEY (tenant_id, tree_size)
);
CREATE TRIGGER kd_checkpoint_append_only BEFORE UPDATE OR DELETE ON kd.kd_checkpoint FOR EACH ROW EXECUTE FUNCTION candor.append_only();

CREATE TABLE kd.witness_cosignature (
  tenant_id      uuid NOT NULL REFERENCES core.tenant (tenant_id),
  tree_size      bigint NOT NULL,
  witness_key_id bytea NOT NULL CHECK (octet_length(witness_key_id) = 32),
  sig            bytea NOT NULL CHECK (octet_length(sig) = 64),
  external       boolean NOT NULL,
  PRIMARY KEY (tenant_id, tree_size, witness_key_id),
  FOREIGN KEY (tenant_id, tree_size) REFERENCES kd.kd_checkpoint (tenant_id, tree_size)
);
CREATE TRIGGER witness_cosignature_append_only BEFORE UPDATE OR DELETE ON kd.witness_cosignature FOR EACH ROW EXECUTE FUNCTION candor.append_only();

CREATE TABLE kd.member_epoch_key (
  tenant_id         uuid NOT NULL REFERENCES core.tenant (tenant_id),
  key_id            bytea NOT NULL CHECK (octet_length(key_id) = 16),
  channel_id        uuid NOT NULL,
  user_id           uuid NOT NULL,
  device_id         uuid NOT NULL,
  valid_from_day    date NOT NULL,
  valid_until_day   date NOT NULL,
  decrypt_until_day date NOT NULL,
  leaf_index        bigint NOT NULL,
  state             kd.mek_state NOT NULL DEFAULT 'active',
  PRIMARY KEY (tenant_id, key_id),
  FOREIGN KEY (tenant_id, channel_id) REFERENCES core.channel (tenant_id, channel_id),
  FOREIGN KEY (tenant_id, leaf_index) REFERENCES kd.kd_entry (tenant_id, leaf_index),
  CHECK (valid_until_day >= valid_from_day AND decrypt_until_day >= valid_until_day)
);
-- ADR-033 §2: destroy_due only when the decrypt window has passed and no
-- pending envelope of the channel still needs the epoch (checked by the job;
-- the row itself only ever moves forward).
CREATE FUNCTION kd.mek_guard() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog AS $fn$
BEGIN
  IF ROW(NEW.tenant_id, NEW.key_id, NEW.channel_id, NEW.user_id, NEW.device_id, NEW.valid_from_day, NEW.valid_until_day, NEW.decrypt_until_day, NEW.leaf_index)
     IS DISTINCT FROM ROW(OLD.tenant_id, OLD.key_id, OLD.channel_id, OLD.user_id, OLD.device_id, OLD.valid_from_day, OLD.valid_until_day, OLD.decrypt_until_day, OLD.leaf_index)
     OR NEW.state < OLD.state THEN
    RAISE EXCEPTION 'member_epoch_key only moves forward' USING ERRCODE = 'P0003';
  END IF;
  RETURN NEW;
END
$fn$;
REVOKE ALL ON FUNCTION kd.mek_guard() FROM PUBLIC;
CREATE TRIGGER mek_guard BEFORE UPDATE ON kd.member_epoch_key FOR EACH ROW EXECUTE FUNCTION kd.mek_guard();
CREATE TRIGGER mek_no_delete BEFORE DELETE ON kd.member_epoch_key FOR EACH ROW EXECUTE FUNCTION candor.append_only();

CREATE TABLE kd.user_key (
  tenant_id   uuid NOT NULL REFERENCES core.tenant (tenant_id),
  key_id      bytea NOT NULL CHECK (octet_length(key_id) = 16),
  user_id     uuid NOT NULL,
  device_id   uuid NOT NULL,
  identity_pk bytea NOT NULL CHECK (octet_length(identity_pk) = 32),
  xwing_pk    bytea NOT NULL CHECK (octet_length(xwing_pk) = 1216),
  state       kd.user_key_state NOT NULL DEFAULT 'active',
  leaf_index  bigint NOT NULL,
  PRIMARY KEY (tenant_id, key_id),
  FOREIGN KEY (tenant_id, leaf_index) REFERENCES kd.kd_entry (tenant_id, leaf_index)
);
CREATE TRIGGER user_key_no_delete BEFORE DELETE ON kd.user_key FOR EACH ROW EXECUTE FUNCTION candor.append_only();

-- ---------------------------------------------------------------------------
-- audit (09 §5.5): per-tenant, per-class hash chains. occurred_at only for
-- staff actions; system/import events are date-only.
-- ---------------------------------------------------------------------------
CREATE TYPE audit.event_class AS ENUM ('security', 'case', 'system');
CREATE TYPE audit.event_state AS ENUM ('pending', 'committed', 'aborted');

CREATE TABLE audit.audit_event (
  tenant_id        uuid NOT NULL REFERENCES core.tenant (tenant_id),
  class            audit.event_class NOT NULL,
  seq              bigint NOT NULL CHECK (seq > 0),
  event_type       smallint NOT NULL CHECK (event_type >= 0),
  actor_pseudonym  bytea NOT NULL CHECK (octet_length(actor_pseudonym) = 16),
  object_pseudonym bytea NULL CHECK (octet_length(object_pseudonym) = 16),
  payload          bytea NOT NULL CHECK (octet_length(payload) BETWEEN 1 AND 16384),
  occurred_date    date NOT NULL,
  occurred_at      timestamptz NULL,
  prev_hash        bytea NOT NULL CHECK (octet_length(prev_hash) = 32),
  hash             bytea NOT NULL CHECK (octet_length(hash) = 32),
  state            audit.event_state NOT NULL DEFAULT 'pending',
  PRIMARY KEY (tenant_id, class, seq)
);
-- Chain discipline in the database (defence in depth; C-24 computes hashes):
-- dense seq per (tenant, class), prev_hash = previous row's hash (zeros for
-- seq 1); afterwards only state may change, once, from pending.
CREATE FUNCTION audit.event_append() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, audit AS $fn$
DECLARE
  last_seq bigint;
  last_hash bytea;
BEGIN
  IF NEW.state <> 'pending' THEN
    RAISE EXCEPTION 'audit event must be inserted pending' USING ERRCODE = 'P0004';
  END IF;
  SELECT e.seq, e.hash INTO last_seq, last_hash FROM audit.audit_event e
    WHERE e.tenant_id = NEW.tenant_id AND e.class = NEW.class ORDER BY e.seq DESC LIMIT 1;
  IF last_seq IS NULL THEN
    IF NEW.seq <> 1 OR NEW.prev_hash <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex') THEN
      RAISE EXCEPTION 'audit chain genesis rejected' USING ERRCODE = 'P0004';
    END IF;
  ELSIF NEW.seq <> last_seq + 1 OR NEW.prev_hash <> last_hash THEN
    RAISE EXCEPTION 'audit event must extend the chain' USING ERRCODE = 'P0004';
  END IF;
  RETURN NEW;
END
$fn$;
CREATE FUNCTION audit.event_guard() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog AS $fn$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'audit events are never deleted' USING ERRCODE = 'P0003';
  END IF;
  IF ROW(NEW.tenant_id, NEW.class, NEW.seq, NEW.event_type, NEW.actor_pseudonym, NEW.object_pseudonym, NEW.payload,
         NEW.occurred_date, NEW.occurred_at, NEW.prev_hash, NEW.hash)
     IS DISTINCT FROM ROW(OLD.tenant_id, OLD.class, OLD.seq, OLD.event_type, OLD.actor_pseudonym, OLD.object_pseudonym,
         OLD.payload, OLD.occurred_date, OLD.occurred_at, OLD.prev_hash, OLD.hash)
     OR OLD.state <> 'pending' THEN
    RAISE EXCEPTION 'audit event is immutable' USING ERRCODE = 'P0003';
  END IF;
  RETURN NEW;
END
$fn$;
REVOKE ALL ON FUNCTION audit.event_append(), audit.event_guard() FROM PUBLIC;
CREATE TRIGGER audit_event_append BEFORE INSERT ON audit.audit_event FOR EACH ROW EXECUTE FUNCTION audit.event_append();
CREATE TRIGGER audit_event_guard BEFORE UPDATE OR DELETE ON audit.audit_event FOR EACH ROW EXECUTE FUNCTION audit.event_guard();

CREATE TABLE audit.audit_checkpoint (
  tenant_id   uuid NOT NULL REFERENCES core.tenant (tenant_id),
  class       audit.event_class NOT NULL,
  seq         bigint NOT NULL CHECK (seq > 0),
  hash        bytea NOT NULL CHECK (octet_length(hash) = 32),
  sig         bytea NOT NULL CHECK (octet_length(sig) = 64),
  signed_at   timestamptz NOT NULL,
  witness_ref bytea NULL CHECK (octet_length(witness_ref) <= 256),
  PRIMARY KEY (tenant_id, class, seq),
  FOREIGN KEY (tenant_id, class, seq) REFERENCES audit.audit_event (tenant_id, class, seq)
);
CREATE TRIGGER audit_checkpoint_append_only BEFORE UPDATE OR DELETE ON audit.audit_checkpoint FOR EACH ROW EXECUTE FUNCTION candor.append_only();

-- ---------------------------------------------------------------------------
-- Blinded COI membership (09 §6.3): the only SECURITY DEFINER function.
-- Pinned search_path; the caller must be an active member of the case and the
-- function returns nothing but a bool. coi_excl_tag has no SELECT grant.
-- ---------------------------------------------------------------------------
CREATE FUNCTION candor.coi_tag_present(p_case uuid, p_tag bytea) RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, candor, core AS $fn$
BEGIN
  IF p_tag IS NULL OR octet_length(p_tag) <> 32 OR p_case IS NULL THEN
    RETURN false;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM core.case_member m WHERE m.tenant_id = candor.tenant() AND m.case_id = p_case
                 AND m.user_id = candor.uid() AND m.state = 'active') THEN
    RETURN false;
  END IF;
  RETURN EXISTS (SELECT 1 FROM core.coi_excl_tag t WHERE t.tenant_id = candor.tenant() AND t.case_id = p_case AND t.tag = p_tag);
END
$fn$;
REVOKE ALL ON FUNCTION candor.coi_tag_present(uuid, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION candor.coi_tag_present(uuid, bytea) TO candor_case;

-- ---------------------------------------------------------------------------
-- Row-level security (09 §6.2): every table of core/auth/kd/audit except the
-- global catalog core.permission carries tenant_id and gets ENABLE + FORCE
-- with the fail-closed p_tenant policy. Catalog-driven so no table is missed.
-- Version guard on every table with a `version` column (07 §5.5).
-- ---------------------------------------------------------------------------
DO $rls$
DECLARE t record;
BEGIN
  FOR t IN SELECT n.nspname AS s, c.relname AS r FROM pg_catalog.pg_class c
           JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
           WHERE c.relkind = 'r' AND n.nspname IN ('core', 'auth', 'kd', 'audit') ORDER BY 1, 2 LOOP
    IF t.s = 'core' AND t.r = 'permission' THEN
      CONTINUE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
                   JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                   WHERE n.nspname = t.s AND c.relname = t.r AND a.attname = 'tenant_id' AND a.attnotnull
                   AND a.atttypid = 'uuid'::regtype) THEN
      RAISE EXCEPTION 'table %.% lacks tenant_id uuid NOT NULL', t.s, t.r;
    END IF;
    EXECUTE pg_catalog.format('ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY', t.s, t.r);
    EXECUTE pg_catalog.format('ALTER TABLE %I.%I FORCE ROW LEVEL SECURITY', t.s, t.r);
    EXECUTE pg_catalog.format('CREATE POLICY p_tenant ON %I.%I AS PERMISSIVE FOR ALL USING (tenant_id = candor.tenant()) WITH CHECK (tenant_id = candor.tenant())', t.s, t.r);
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
               JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
               WHERE n.nspname = t.s AND c.relname = t.r AND a.attname = 'version' AND a.atttypid = 'int8'::regtype) THEN
      EXECUTE pg_catalog.format('CREATE TRIGGER version_guard BEFORE UPDATE ON %I.%I FOR EACH ROW EXECUTE FUNCTION candor.version_guard()', t.s, t.r);
    END IF;
  END LOOP;
END
$rls$;
-- core.permission: global catalog, read-only for every app role (no RLS).

-- Case ACL (09 §6.3): restrictive, for candor_case, on content-bearing tables.
DO $acl$
DECLARE r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['case', 'case_record', 'message', 'evidence_object', 'evidence_derivative', 'submission',
                           'sla_timer', 'case_state_history', 'legal_hold', 'export_package', 'case_meta',
                           'deletion_request', 'wrap_deletion_request', 'breakglass_request', 'identity_unseal_request'] LOOP
    EXECUTE pg_catalog.format('CREATE POLICY p_case_acl ON core.%I AS RESTRICTIVE FOR ALL TO candor_case USING (EXISTS (SELECT 1 FROM core.case_member m WHERE m.tenant_id = candor.tenant() AND m.case_id = %I.case_id AND m.user_id = candor.uid() AND m.state = ''active'' AND (m.valid_until_day IS NULL OR m.valid_until_day >= (pg_catalog.now() AT TIME ZONE ''UTC'')::date)))', r, r);
  END LOOP;
END
$acl$;
-- A member sees the case_member rows of their own cases (and inserts into them
-- on case creation: the creator's own row first, then co-members).
CREATE POLICY p_case_acl ON core.case_member AS RESTRICTIVE FOR ALL TO candor_case
  USING (EXISTS (SELECT 1 FROM core.case_member m WHERE m.tenant_id = candor.tenant() AND m.case_id = case_member.case_id
                 AND m.user_id = candor.uid() AND m.state = 'active'))
  WITH CHECK (user_id = candor.uid() OR EXISTS (SELECT 1 FROM core.case_member m WHERE m.tenant_id = candor.tenant()
                 AND m.case_id = case_member.case_id AND m.user_id = candor.uid() AND m.state = 'active'));
CREATE POLICY p_case_acl ON core.attachment AS RESTRICTIVE FOR ALL TO candor_case
  USING (EXISTS (SELECT 1 FROM core.message g JOIN core.case_member m ON m.tenant_id = g.tenant_id AND m.case_id = g.case_id
                 WHERE g.tenant_id = candor.tenant() AND g.message_id = attachment.message_id
                 AND m.user_id = candor.uid() AND m.state = 'active'))
  WITH CHECK (EXISTS (SELECT 1 FROM core.message g JOIN core.case_member m ON m.tenant_id = g.tenant_id AND m.case_id = g.case_id
                 WHERE g.tenant_id = candor.tenant() AND g.message_id = attachment.message_id
                 AND m.user_id = candor.uid() AND m.state = 'active'));
CREATE POLICY p_case_acl ON core.export_approval AS RESTRICTIVE FOR ALL TO candor_case
  USING (EXISTS (SELECT 1 FROM core.export_package p JOIN core.case_member m ON m.tenant_id = p.tenant_id AND m.case_id = p.case_id
                 WHERE p.tenant_id = candor.tenant() AND p.export_id = export_approval.export_id
                 AND m.user_id = candor.uid() AND m.state = 'active'))
  WITH CHECK (approver_id = candor.uid());
-- Own wrap only.
CREATE POLICY p_own_wrap ON core.case_key_wrap AS RESTRICTIVE FOR SELECT TO candor_case
  USING (recipient_user_id = candor.uid());
-- Triage Set only (ADR-037(2)).
CREATE POLICY p_triage ON core.import_envelope AS RESTRICTIVE FOR ALL TO candor_case
  USING (EXISTS (SELECT 1 FROM core.channel_member m WHERE m.tenant_id = candor.tenant() AND m.channel_id = import_envelope.channel_id
                 AND m.user_id = candor.uid() AND m.state = 'active' AND m.triage));
CREATE POLICY p_triage ON core.import_envelope_part AS RESTRICTIVE FOR ALL TO candor_case
  USING (EXISTS (SELECT 1 FROM core.import_envelope e JOIN core.channel_member m ON m.tenant_id = e.tenant_id AND m.channel_id = e.channel_id
                 WHERE e.tenant_id = candor.tenant() AND e.import_envelope_id = import_envelope_part.import_envelope_id
                 AND m.user_id = candor.uid() AND m.state = 'active' AND m.triage));
-- Custodians after approval (ADR-014); the custodian role is checked by C-22.
CREATE POLICY p_unseal ON core.sealed_identity AS RESTRICTIVE FOR SELECT TO candor_case
  USING (EXISTS (SELECT 1 FROM core.identity_unseal_request q WHERE q.tenant_id = candor.tenant()
                 AND q.case_id = sealed_identity.case_id AND q.state = 'approved' AND candor.uid() = ANY (q.approvals)));
-- Own notification target.
CREATE POLICY p_own_target ON core.notification_target AS RESTRICTIVE FOR ALL TO candor_case
  USING (user_id = candor.uid()) WITH CHECK (user_id = candor.uid());
-- Worker scoping (09 §6.5): DELETE on content tables only under the erasure,
-- blob-gc and export-expiry job contexts.
DO $wk$
DECLARE r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['case', 'case_record', 'message', 'attachment', 'evidence_object', 'evidence_derivative',
                           'sealed_identity', 'case_key_wrap', 'coi_excl_tag', 'case_meta', 'submission',
                           'import_envelope', 'import_envelope_part', 'reply_outbox', 'export_package', 'blob_object'] LOOP
    EXECUTE pg_catalog.format('CREATE POLICY p_worker_delete ON core.%I AS RESTRICTIVE FOR DELETE TO candor_worker USING (candor.principal() IN (''worker:crypto_erase_case'', ''worker:blob_gc'', ''worker:export_expire''))', r);
  END LOOP;
END
$wk$;
-- Jobs: a service touches only the kinds it runs (09 §7 "own kinds").
CREATE POLICY p_job_kind ON core.job AS RESTRICTIVE FOR ALL TO candor_relay, candor_notify, candor_kd, candor_auth
  USING ((current_user = 'candor_relay' AND kind IN ('deletion_list_prune'))
      OR (current_user = 'candor_notify' AND kind IN ('notify_daily_digest'))
      OR (current_user = 'candor_kd' AND kind IN ('epoch_runway_check', 'epoch_key_destroy', 'kd_timelock_activate',
                                                   'kd_weekly_publish', 'kd_checkpoint_publish', 'kd_witness_cosign'))
      OR (current_user = 'candor_auth' AND kind IN ('timestamp_retention', 'session_gc')));

-- ---------------------------------------------------------------------------
-- Grants (09 §7). App roles own nothing; no TRUNCATE, REFERENCES or TRIGGER.
-- ---------------------------------------------------------------------------
-- 5.2.1 tenancy. tenant: readable by every app role (TenantTx visibility check).
GRANT SELECT ON core.tenant TO candor_case, candor_admin, candor_relay, candor_worker, candor_notify, candor_kd, candor_auth, candor_audit_w, candor_audit_r, candor_monitor;
GRANT INSERT ON core.tenant TO candor_admin;
GRANT UPDATE (label, state, version) ON core.tenant TO candor_admin;
GRANT SELECT ON core.department, core.channel, core.channel_member, core.coi_category, core.roster_change TO candor_case, candor_relay, candor_worker, candor_kd, candor_auth;
GRANT SELECT, INSERT, UPDATE ON core.department, core.channel, core.channel_member, core.coi_category, core.roster_change TO candor_admin;
GRANT SELECT, INSERT, UPDATE ON core.retention_policy, core.workflow_definition TO candor_admin;
GRANT SELECT ON core.retention_policy, core.workflow_definition TO candor_case, candor_worker;
GRANT UPDATE (state, version) ON core.channel_member TO candor_kd;
GRANT UPDATE (state, effective_day) ON core.roster_change TO candor_kd, candor_worker;
-- 5.2.2 users, roles.
GRANT SELECT ON core.app_user, core.role, core.role_assignment TO candor_case, candor_worker, candor_notify, candor_kd, candor_auth;
GRANT SELECT, INSERT, UPDATE ON core.app_user, core.role, core.role_assignment TO candor_admin;
GRANT DELETE ON core.role_assignment TO candor_admin, candor_worker;
GRANT SELECT ON core.permission TO candor_case, candor_admin, candor_relay, candor_worker, candor_notify, candor_kd, candor_auth;
GRANT SELECT, INSERT, UPDATE, DELETE ON core.coi_registry TO candor_admin;
GRANT SELECT ON core.coi_registry TO candor_worker;
-- 5.2.3 import.
GRANT INSERT ON core.import_envelope, core.import_envelope_part TO candor_relay;
GRANT SELECT ON core.import_envelope, core.import_envelope_part TO candor_case;
GRANT UPDATE (state, rejected_by, import_date, header_digest, disposition_ct, escalated_date) ON core.import_envelope TO candor_case;
GRANT DELETE ON core.import_envelope, core.import_envelope_part TO candor_case;
GRANT SELECT (tenant_id, import_envelope_id, channel_id, header_digest, import_date, epoch_index, import_batch_no, state, rejected_by, escalated_date) ON core.import_envelope TO candor_worker;
GRANT UPDATE (state, header_digest, escalated_date) ON core.import_envelope TO candor_worker;
GRANT DELETE ON core.import_envelope TO candor_worker;
GRANT SELECT, UPDATE, DELETE ON core.import_envelope_part TO candor_worker;
-- 5.2.4 cases.
GRANT SELECT, INSERT, UPDATE, DELETE ON core."case", core.submission, core.case_member, core.case_state_history, core.sla_timer TO candor_case;
GRANT SELECT (tenant_id, case_id, display_ref, channel_id, workflow_def_id, workflow_version, state, priority, received_date, last_import_month, opened_day, closed_day, key_epoch, retention_policy_id, deletion_due_day, legal_hold, ek_missing, version) ON core."case" TO candor_worker;
GRANT UPDATE (state, closed_day, deletion_due_day, ek_missing, version) ON core."case" TO candor_worker;
GRANT DELETE ON core."case" TO candor_worker;
GRANT SELECT, UPDATE, DELETE ON core.submission, core.case_member, core.case_state_history, core.sla_timer TO candor_worker;
GRANT SELECT, INSERT, UPDATE ON core.case_meta TO candor_case;
GRANT DELETE ON core.case_meta TO candor_worker;
GRANT SELECT, INSERT ON core.case_key_wrap TO candor_case;
GRANT DELETE ON core.case_key_wrap TO candor_worker;
GRANT INSERT ON core.coi_excl_tag TO candor_case;
GRANT DELETE ON core.coi_excl_tag TO candor_worker;
GRANT SELECT, INSERT, UPDATE, DELETE ON core.case_record, core.message, core.attachment, core.evidence_object, core.evidence_derivative, core.sealed_identity, core.identity_unseal_request TO candor_case;
GRANT DELETE ON core.case_record, core.message, core.attachment, core.evidence_object, core.evidence_derivative, core.sealed_identity TO candor_worker;
-- 5.2.5 holds and requests.
GRANT SELECT, INSERT, UPDATE ON core.legal_hold, core.deletion_request, core.wrap_deletion_request TO candor_case;
GRANT SELECT (tenant_id, hold_id, case_id, placed_by, released_by, release_approved_by, placed_day, released_day, version) ON core.legal_hold TO candor_worker;
GRANT SELECT, UPDATE ON core.deletion_request, core.wrap_deletion_request TO candor_worker;
GRANT DELETE ON core.legal_hold, core.deletion_request, core.wrap_deletion_request TO candor_worker;
-- 5.2.6 break-glass.
GRANT SELECT, INSERT, UPDATE ON core.breakglass_request TO candor_case;
GRANT SELECT (tenant_id, request_id, case_id, requester_id, approver_id, reviewer_id, reason_code, state, expires_at, review_due_day, review_outcome, version) ON core.breakglass_request TO candor_admin, candor_worker;
GRANT UPDATE (state, review_due_day, version) ON core.breakglass_request TO candor_worker;
-- 5.2.7 replies, deletion list, exports, notifications.
GRANT INSERT ON core.reply_outbox TO candor_case;
GRANT SELECT, UPDATE (state) ON core.reply_outbox TO candor_relay;
GRANT SELECT ON core.reply_outbox TO candor_relay;
GRANT DELETE ON core.reply_outbox TO candor_worker, candor_relay;
GRANT SELECT, INSERT ON core.intake_deletion_list TO candor_relay;
GRANT SELECT, DELETE ON core.intake_deletion_list TO candor_worker;
GRANT SELECT, INSERT, UPDATE, DELETE ON core.export_package, core.export_approval TO candor_case;
GRANT SELECT (tenant_id, export_id, case_id, kind, destination_type, connector_id, blob_id, package_digest, created_by, state, created_day) ON core.export_package TO candor_worker;
GRANT UPDATE (state, blob_id) ON core.export_package TO candor_worker;
GRANT DELETE ON core.export_package, core.export_approval TO candor_worker;
GRANT SELECT, INSERT, UPDATE ON core.notification_target TO candor_case;
GRANT SELECT, INSERT, UPDATE, DELETE ON core.notification_target TO candor_notify;
GRANT SELECT ON core.notification_target TO candor_admin;
GRANT SELECT, INSERT, UPDATE, DELETE ON core.notification_queue TO candor_notify;
GRANT INSERT, DELETE ON core.notification_queue TO candor_worker;
-- 5.2.8 jobs, config, idempotency, blobs, counters.
GRANT INSERT ON core.job TO candor_case, candor_admin;
GRANT SELECT, UPDATE ON core.job TO candor_relay, candor_notify, candor_kd, candor_auth;
GRANT SELECT, INSERT, UPDATE, DELETE ON core.job TO candor_worker;
GRANT SELECT ON core.job TO candor_monitor;
GRANT SELECT, INSERT, UPDATE ON core.config_change, core.config_bundle TO candor_admin;
GRANT SELECT ON core.config_bundle TO candor_case, candor_relay, candor_worker, candor_notify, candor_kd, candor_auth;
GRANT SELECT, INSERT, DELETE ON core.idempotency_key TO candor_case, candor_admin;
GRANT DELETE ON core.idempotency_key TO candor_worker;
GRANT SELECT, INSERT, UPDATE ON core.blob_object TO candor_case, candor_relay;
GRANT SELECT, INSERT, UPDATE, DELETE ON core.blob_object TO candor_worker;
GRANT SELECT, INSERT, UPDATE ON core.aggregate_counter TO candor_worker;
GRANT SELECT ON core.aggregate_counter TO candor_admin;
-- auth.
GRANT SELECT, INSERT, UPDATE, DELETE ON auth.webauthn_credential, auth.device, auth.enrollment_token, auth.session, auth.refresh_token, auth.stepup_proof, auth.pop_nonce TO candor_auth;
GRANT SELECT (tenant_id, device_id, user_id, state, enrolled_day) ON auth.device TO candor_admin, candor_case;
GRANT SELECT (tenant_id, credential_id, user_id, aaguid, role, created_day) ON auth.webauthn_credential TO candor_admin;
GRANT DELETE ON auth.enrollment_token, auth.session, auth.refresh_token, auth.stepup_proof, auth.pop_nonce TO candor_worker;
-- kd.
GRANT SELECT ON kd.kd_entry, kd.kd_checkpoint, kd.witness_cosignature, kd.member_epoch_key, kd.user_key TO candor_case, candor_admin, candor_relay, candor_worker, candor_kd, candor_auth;
GRANT INSERT ON kd.kd_entry, kd.kd_checkpoint, kd.witness_cosignature, kd.member_epoch_key, kd.user_key TO candor_kd;
GRANT UPDATE (state) ON kd.member_epoch_key, kd.user_key TO candor_kd;
GRANT UPDATE (state) ON kd.member_epoch_key TO candor_worker;
-- audit.
GRANT SELECT, INSERT ON audit.audit_event, audit.audit_checkpoint TO candor_audit_w;
GRANT UPDATE (state) ON audit.audit_event TO candor_audit_w;
GRANT SELECT ON audit.audit_event, audit.audit_checkpoint TO candor_audit_r;
