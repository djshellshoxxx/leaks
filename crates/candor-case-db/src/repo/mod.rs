// SPDX-License-Identifier: AGPL-3.0-or-later
//! Repository modules. Every method takes `&mut TenantTx`, binds the
//! transaction's tenant explicitly (in addition to RLS), bounds every input
//! before binding, and uses optimistic `version` columns for updates.

pub mod audit;
pub mod case;
pub mod channel;
pub mod import;
pub mod job;
pub mod kd;
pub mod message;
pub mod notify;
pub mod retention;
pub mod tenant;
pub mod user;

use sqlx::Row;
use sqlx::postgres::PgRow;

use crate::error::{DbError, Result, db};
use crate::types::Day;
use uuid::Uuid;

pub(crate) fn get_uuid(r: &PgRow, i: usize) -> Result<[u8; 16]> {
    Ok(*r.try_get::<Uuid, _>(i).map_err(db)?.as_bytes())
}
pub(crate) fn get_opt_uuid(r: &PgRow, i: usize) -> Result<Option<[u8; 16]>> {
    Ok(r.try_get::<Option<Uuid>, _>(i).map_err(db)?.map(|u| *u.as_bytes()))
}
pub(crate) fn get_day(r: &PgRow, i: usize) -> Result<Day> {
    Day::from_i32(r.try_get(i).map_err(db)?)
}
pub(crate) fn get_opt_day(r: &PgRow, i: usize) -> Result<Option<Day>> {
    r.try_get::<Option<i32>, _>(i)
        .map_err(db)?
        .map(Day::from_i32)
        .transpose()
}
pub(crate) fn get_u64(r: &PgRow, i: usize) -> Result<u64> {
    let v: i64 = r.try_get(i).map_err(db)?;
    u64::try_from(v).map_err(|_| DbError::Integrity("negative value"))
}
pub(crate) fn get_u32(r: &PgRow, i: usize) -> Result<u32> {
    let v: i32 = r.try_get(i).map_err(db)?;
    u32::try_from(v).map_err(|_| DbError::Integrity("negative value"))
}
pub(crate) fn get_u16(r: &PgRow, i: usize) -> Result<u16> {
    let v: i16 = r.try_get(i).map_err(db)?;
    u16::try_from(v).map_err(|_| DbError::Integrity("negative value"))
}
pub(crate) fn get_string(r: &PgRow, i: usize) -> Result<String> {
    r.try_get(i).map_err(db)
}
pub(crate) fn get_bytes(r: &PgRow, i: usize) -> Result<Vec<u8>> {
    r.try_get(i).map_err(db)
}
pub(crate) fn get_opt_bytes(r: &PgRow, i: usize) -> Result<Option<Vec<u8>>> {
    r.try_get(i).map_err(db)
}
pub(crate) fn get_bool(r: &PgRow, i: usize) -> Result<bool> {
    r.try_get(i).map_err(db)
}
pub(crate) fn i64_of(v: u64) -> Result<i64> {
    i64::try_from(v).map_err(|_| DbError::InvalidInput("value out of range"))
}
pub(crate) fn i32_of(v: u32) -> Result<i32> {
    i32::try_from(v).map_err(|_| DbError::InvalidInput("value out of range"))
}
pub(crate) fn i16_of(v: u16) -> Result<i16> {
    i16::try_from(v).map_err(|_| DbError::InvalidInput("value out of range"))
}
/// Exactly one row must have been affected, else the lookup was IDOR-safe
/// filtered or the version moved.
pub(crate) fn one(n: u64, conflict: DbError) -> Result<()> {
    match n {
        1 => Ok(()),
        0 => Err(conflict),
        _ => Err(DbError::Integrity("multiple rows affected")),
    }
}
