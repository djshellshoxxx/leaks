// SPDX-License-Identifier: AGPL-3.0-or-later
//! `core.tenant` (09 §5.2.1).

use crate::db::{CaseDb, Role};
use crate::error::{DbError, Result, db};
use crate::repo::{get_bool, get_string, get_u64, i64_of, one};
use crate::tx::TenantTx;
use crate::types::{Principal, TenantId, bounded_text};

/// ADR-021 risk class.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RiskClass {
    Low,
    Moderate,
    High,
}

impl RiskClass {
    /// Enum text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Moderate => "moderate",
            Self::High => "high",
        }
    }
    fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "low" => Self::Low,
            "moderate" => Self::Moderate,
            "high" => Self::High,
            _ => return Err(DbError::Integrity("enum")),
        })
    }
}

/// Tenant row.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Tenant {
    pub tenant_id: TenantId,
    pub label: String,
    pub risk_class: RiskClass,
    pub suspended: bool,
    pub version: u64,
}

const SQL_INSERT: &str = "INSERT INTO core.tenant (tenant_id, label, risk_class, state) \
     VALUES ($1, $2, $3::text::core.risk_class, 'active') ON CONFLICT DO NOTHING";
const SQL_GET: &str =
    "SELECT tenant_id, label, risk_class::text, state = 'suspended', version FROM core.tenant WHERE tenant_id = $1";
const SQL_SET_STATE: &str = "UPDATE core.tenant SET state = $3::text::core.tenant_state, version = $2 + 1 \
     WHERE tenant_id = $1 AND version = $2";

/// Create the tenant row (admin pool only; the one transaction that skips the
/// visibility check because the row does not exist yet). Returns false when
/// the tenant already exists.
pub async fn bootstrap(pool: &CaseDb, tenant: TenantId, label: &str, risk: RiskClass) -> Result<bool> {
    if pool.role() != Role::Admin {
        return Err(DbError::PrincipalMismatch);
    }
    let label = bounded_text(label, 64, "tenant label")?;
    // Bind the admin context: nil user, kind admin (served by this pool).
    let p = Principal::admin_system(tenant)?;
    let mut tx = TenantTx::begin_bootstrap(pool.pool(), &p).await?;
    let n = sqlx::query(SQL_INSERT)
        .bind(tenant.uuid())
        .bind(label)
        .bind(risk.as_str())
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    tx.commit().await?;
    Ok(n == 1)
}

/// The bound tenant's row.
pub async fn get(tx: &mut TenantTx) -> Result<Tenant> {
    let t = tx.tenant();
    let r = sqlx::query(SQL_GET)
        .bind(t.uuid())
        .fetch_optional(tx.conn())
        .await
        .map_err(db)?
        .ok_or(DbError::TenantUnknown)?;
    Ok(Tenant {
        tenant_id: t,
        label: get_string(&r, 1)?,
        risk_class: RiskClass::parse(&get_string(&r, 2)?)?,
        suspended: get_bool(&r, 3)?,
        version: get_u64(&r, 4)?,
    })
}

/// Suspend or reactivate (admin), optimistic on `version`.
pub async fn set_suspended(tx: &mut TenantTx, version: u64, suspended: bool) -> Result<()> {
    let n = sqlx::query(SQL_SET_STATE)
        .bind(tx.tenant().uuid())
        .bind(i64_of(version)?)
        .bind(if suspended { "suspended" } else { "active" })
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::VersionConflict)
}
