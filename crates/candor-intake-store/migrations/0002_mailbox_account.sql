-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Migration 0002: mailbox_account (09 §5.1, ADR-057(2); AUD-RM2-IPC-09).
-- Maps each per-report mailbox to its owning account so that account and
-- mailbox deletion is complete, restorable and idempotent, and RL-05 can route
-- a pushed reply. No time-typed column, no read marker, no history (ADR-010,
-- ADR-039). RLS and the grant matrix follow source_account. Owned by the
-- schema owner like every table (migration 0001 bootstrapped the roles).
SET LOCAL ROLE candor_intake_migrator;
CREATE TABLE candor.mailbox_account (
  mailbox_id bytea PRIMARY KEY CHECK (octet_length(mailbox_id) = 32),
  account_id uuid  NOT NULL REFERENCES candor.source_account (account_id) ON DELETE CASCADE
);
CREATE INDEX mailbox_account_account ON candor.mailbox_account (account_id);
ALTER TABLE candor.mailbox_account SET (autovacuum_enabled = false, toast.autovacuum_enabled = false);
ALTER TABLE candor.mailbox_account ENABLE ROW LEVEL SECURITY;
ALTER TABLE candor.mailbox_account FORCE ROW LEVEL SECURITY;
CREATE POLICY p_tenant ON candor.mailbox_account
  USING (EXISTS (SELECT 1 FROM candor.intake_meta)) WITH CHECK (EXISTS (SELECT 1 FROM candor.intake_meta));
GRANT SELECT, INSERT, UPDATE, DELETE ON candor.mailbox_account TO candor_istore;
GRANT SELECT ON candor.mailbox_account TO candor_intake_backup;
