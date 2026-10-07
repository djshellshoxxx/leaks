// SPDX-License-Identifier: AGPL-3.0-or-later
//! `TenantTx`: a transaction whose first statement binds the authenticated
//! principal as transaction-local settings (`SET LOCAL` semantics via
//! `set_config(…, true)`, so nothing survives commit or rollback on a pooled
//! connection), then proves the tenant is visible under RLS (fail closed:
//! a context that hides everything is an error, not an empty result). Every
//! repository method takes `&mut TenantTx`; raw pool access is not exposed.

use sqlx::{PgConnection, PgPool, Postgres, Row, Transaction};

use crate::error::{DbError, Result, db};
use crate::types::{Principal, TenantId};

const SQL_SET_CONTEXT: &str = "SELECT pg_catalog.set_config('candor.tenant_id', $1::uuid::text, true), \
     pg_catalog.set_config('candor.user_id', $2::uuid::text, true), \
     pg_catalog.set_config('candor.principal_kind', $3::text, true)";
const SQL_TENANT_VISIBLE: &str = "SELECT state::text FROM core.tenant WHERE tenant_id = $1";

/// A principal-bound transaction.
pub struct TenantTx {
    tx: Transaction<'static, Postgres>,
    principal: Principal,
}

impl std::fmt::Debug for TenantTx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TenantTx(..)")
    }
}

impl TenantTx {
    pub(crate) async fn begin(pool: &PgPool, principal: &Principal) -> Result<Self> {
        let mut tx = pool.begin().await.map_err(db)?;
        sqlx::query(SQL_SET_CONTEXT)
            .bind(principal.tenant().uuid())
            .bind(principal.user().uuid())
            .bind(principal.kind().guc_value())
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        let row = sqlx::query(SQL_TENANT_VISIBLE)
            .bind(principal.tenant().uuid())
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?;
        let Some(row) = row else {
            // Unknown tenant, or RLS hides it: refuse.
            tx.rollback().await.map_err(db)?;
            return Err(DbError::TenantUnknown);
        };
        let state: String = row.try_get(0).map_err(db)?;
        match state.as_str() {
            "active" => {}
            "suspended" if principal.kind().serves_suspended() => {}
            "suspended" => {
                tx.rollback().await.map_err(db)?;
                return Err(DbError::TenantSuspended);
            }
            _ => {
                tx.rollback().await.map_err(db)?;
                return Err(DbError::Integrity("tenant state"));
            }
        }
        Ok(Self {
            tx,
            principal: *principal,
        })
    }

    /// Bootstrap transaction (admin only): binds the context without the
    /// visibility check, so that the tenant row itself can be inserted.
    pub(crate) async fn begin_bootstrap(pool: &PgPool, principal: &Principal) -> Result<Self> {
        let mut tx = pool.begin().await.map_err(db)?;
        sqlx::query(SQL_SET_CONTEXT)
            .bind(principal.tenant().uuid())
            .bind(principal.user().uuid())
            .bind(principal.kind().guc_value())
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        Ok(Self {
            tx,
            principal: *principal,
        })
    }

    /// The bound tenant.
    #[must_use]
    pub const fn tenant(&self) -> TenantId {
        self.principal.tenant()
    }

    /// The bound principal.
    #[must_use]
    pub const fn principal(&self) -> &Principal {
        &self.principal
    }

    pub(crate) fn conn(&mut self) -> &mut PgConnection {
        &mut self.tx
    }

    /// Commit.
    pub async fn commit(self) -> Result<()> {
        self.tx.commit().await.map_err(db)
    }

    /// Roll back (dropping the value rolls back too).
    pub async fn rollback(self) -> Result<()> {
        self.tx.rollback().await.map_err(db)
    }
}
