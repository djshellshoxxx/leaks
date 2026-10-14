// SPDX-License-Identifier: AGPL-3.0-or-later
//! Candor Case DB (C-12): schema, roles, row-level security, migrations and
//! the `TenantTx` repository layer (09-DATABASE.md §5.2–§5.6, §6–§11;
//! IMPL-RM3 §3.1–§3.2). See README.md and SPEC-NOTES.md.
//!
//! - All SQL is static (`&'static str`); values are always bound.
//! - `TenantTx` is the only way to run a query: it binds the authenticated
//!   principal per transaction and fails closed when the tenant is hidden.
//! - `CaseDb::open` refuses privileged logins, disabled guards, drifted
//!   schemas and unsafe server settings.

pub mod classification;
pub mod db;
pub mod error;
pub mod lint;
pub mod migrate;
pub mod repo;
pub mod tx;
pub mod types;

pub use db::{ALL_ROLES, CaseDb, Role};
pub use error::{DbError, Result};
pub use migrate::{MIGRATIONS, migrate, schema_hash};
pub use tx::TenantTx;
pub use types::*;
