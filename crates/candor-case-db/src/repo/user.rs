// SPDX-License-Identifier: AGPL-3.0-or-later
//! `core.app_user` (09 §5.2.2).

use crate::error::{DbError, Result, db};
use crate::repo::{get_opt_uuid, get_string, get_u64, get_uuid, i64_of, one};
use crate::tx::TenantTx;
use crate::types::{Cursor, Page, PageSize, UserId, bounded_text};

/// Account state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UserState {
    Invited,
    Active,
    Disabled,
}

impl UserState {
    /// Enum text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Invited => "invited",
            Self::Active => "active",
            Self::Disabled => "disabled",
        }
    }
    fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "invited" => Self::Invited,
            "active" => Self::Active,
            "disabled" => Self::Disabled,
            _ => return Err(DbError::Integrity("enum")),
        })
    }
}

/// User row.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct User {
    pub user_id: UserId,
    pub username: String,
    pub display_name: String,
    pub state: UserState,
    pub department_id: Option<[u8; 16]>,
    pub version: u64,
}

const SQL_INSERT: &str = "INSERT INTO core.app_user (tenant_id, user_id, username, display_name, state) \
     VALUES ($1, $2, $3, $4, 'invited') ON CONFLICT DO NOTHING";
const SQL_GET: &str = "SELECT user_id, username, display_name, state::text, department_id, version \
     FROM core.app_user WHERE tenant_id = $1 AND user_id = $2";
const SQL_BY_NAME: &str = "SELECT user_id, username, display_name, state::text, department_id, version \
     FROM core.app_user WHERE tenant_id = $1 AND pg_catalog.lower(username) = pg_catalog.lower($2)";
const SQL_LIST: &str = "SELECT user_id, username, display_name, state::text, department_id, version \
     FROM core.app_user WHERE tenant_id = $1 AND user_id > $2 ORDER BY user_id LIMIT $3";
const SQL_SET_STATE: &str = "UPDATE core.app_user SET state = $4::text::core.user_state, version = $3 + 1 \
     WHERE tenant_id = $1 AND user_id = $2 AND version = $3";

fn row(r: &sqlx::postgres::PgRow) -> Result<User> {
    Ok(User {
        user_id: UserId::from_bytes(get_uuid(r, 0)?),
        username: get_string(r, 1)?,
        display_name: get_string(r, 2)?,
        state: UserState::parse(&get_string(r, 3)?)?,
        department_id: get_opt_uuid(r, 4)?,
        version: get_u64(r, 5)?,
    })
}

/// Create an invited user (admin). `AlreadyExists` on a taken id or username.
pub async fn create(tx: &mut TenantTx, user: UserId, username: &str, display_name: &str) -> Result<()> {
    let username = bounded_text(username, 128, "username")?;
    let display_name = bounded_text(display_name, 128, "display name")?;
    let n = sqlx::query(SQL_INSERT)
        .bind(tx.tenant().uuid())
        .bind(user.uuid())
        .bind(username)
        .bind(display_name)
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::AlreadyExists)
}

/// IDOR-safe lookup by id within the bound tenant.
pub async fn get(tx: &mut TenantTx, user: UserId) -> Result<User> {
    let r = sqlx::query(SQL_GET)
        .bind(tx.tenant().uuid())
        .bind(user.uuid())
        .fetch_optional(tx.conn())
        .await
        .map_err(db)?
        .ok_or(DbError::NotFound)?;
    row(&r)
}

/// Lookup by username (case-insensitive).
pub async fn get_by_username(tx: &mut TenantTx, username: &str) -> Result<User> {
    let username = bounded_text(username, 128, "username")?;
    let r = sqlx::query(SQL_BY_NAME)
        .bind(tx.tenant().uuid())
        .bind(username)
        .fetch_optional(tx.conn())
        .await
        .map_err(db)?
        .ok_or(DbError::NotFound)?;
    row(&r)
}

/// Keyset page ordered by id.
pub async fn list(tx: &mut TenantTx, after: Option<Cursor>, size: PageSize) -> Result<Page<User>> {
    let rows = sqlx::query(SQL_LIST)
        .bind(tx.tenant().uuid())
        .bind(after.unwrap_or(Cursor([0; 16])).uuid())
        .bind(size.limit())
        .fetch_all(tx.conn())
        .await
        .map_err(db)?;
    let items = rows.iter().map(row).collect::<Result<Vec<_>>>()?;
    Ok(Page::new(items, size, |u| *u.user_id.as_bytes()))
}

/// Change the account state, optimistic on `version`.
pub async fn set_state(tx: &mut TenantTx, user: UserId, version: u64, state: UserState) -> Result<()> {
    let n = sqlx::query(SQL_SET_STATE)
        .bind(tx.tenant().uuid())
        .bind(user.uuid())
        .bind(i64_of(version)?)
        .bind(state.as_str())
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::VersionConflict)
}
