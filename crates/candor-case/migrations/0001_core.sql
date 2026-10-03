-- SPDX-License-Identifier: AGPL-3.0-or-later
-- RM-3 minimal case-zone schema. Roles are provisioned by the installer before migration.

CREATE SCHEMA IF NOT EXISTS candor;
CREATE SCHEMA IF NOT EXISTS core;

CREATE OR REPLACE FUNCTION candor.tenant() RETURNS uuid
LANGUAGE sql STABLE
AS $$ SELECT current_setting('candor.tenant_id')::uuid $$;

CREATE TABLE core.import_envelope (
    tenant_id uuid NOT NULL,
    import_id uuid NOT NULL,
    header_digest bytea NOT NULL,
    import_day date NOT NULL,
    PRIMARY KEY (tenant_id, import_id),
    UNIQUE (tenant_id, header_digest),
    CHECK (octet_length(header_digest) = 32)
);

CREATE TABLE core.case_record (
    tenant_id uuid NOT NULL,
    case_id uuid NOT NULL,
    assigned_user_id uuid NULL,
    legal_hold boolean NOT NULL DEFAULT false,
    retention_due_day date NULL,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, case_id)
);

ALTER TABLE core.import_envelope ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.import_envelope FORCE ROW LEVEL SECURITY;
ALTER TABLE core.case_record ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.case_record FORCE ROW LEVEL SECURITY;

CREATE POLICY p_import_tenant ON core.import_envelope AS PERMISSIVE FOR ALL
TO candor_case, candor_relay
USING (tenant_id = candor.tenant()) WITH CHECK (tenant_id = candor.tenant());

CREATE POLICY p_case_tenant ON core.case_record AS PERMISSIVE FOR ALL
TO candor_case, candor_worker
USING (tenant_id = candor.tenant()) WITH CHECK (tenant_id = candor.tenant());

REVOKE ALL ON core.import_envelope, core.case_record FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON core.import_envelope TO candor_relay, candor_case;
GRANT SELECT, INSERT, UPDATE, DELETE ON core.case_record TO candor_case;
GRANT SELECT, UPDATE ON core.case_record TO candor_worker;
