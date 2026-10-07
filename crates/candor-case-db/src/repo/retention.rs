// SPDX-License-Identifier: AGPL-3.0-or-later
//! `core.legal_hold`, `core.deletion_request`, `core.wrap_deletion_request`,
//! `core.sla_timer`, `core.breakglass_request` (09 §5.2.5, §5.2.6; ADR-044(1);
//! 15 §5.6 dual control). Dual control is enforced in SQL (CHECK: distinct
//! people) and here (the approver is the transaction's principal).

use crate::error::{DbError, Result, db};
use crate::repo::{get_day, get_opt_day, get_opt_uuid, get_string, get_u64, get_uuid, i64_of, one};
use crate::tx::TenantTx;
use crate::types::{CaseId, Day, HoldId, RequestId, TimerId, UserId, bounded};

/// `reason_ct` / `legal_basis_ct` bound.
pub const MAX_REASON_CT: usize = 64 * 1024;
/// Cooling-off before a wrap deletion executes (ADR-044(1)).
pub const WRAP_DELETION_COOLOFF_DAYS: u32 = 7;

fn actor(tx: &TenantTx) -> Result<UserId> {
    let u = tx.principal().user();
    if u.is_nil() {
        return Err(DbError::InvalidInput("staff principal required"));
    }
    Ok(u)
}

/// Legal hold row.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LegalHold {
    pub hold_id: HoldId,
    pub case_id: CaseId,
    pub placed_by: UserId,
    pub placed_day: Day,
    pub released_day: Option<Day>,
    pub version: u64,
}

const SQL_HOLD_INSERT: &str = "INSERT INTO core.legal_hold (tenant_id, hold_id, case_id, reason_ct, placed_by, placed_day) \
     VALUES ($1, $2, $3, $4, $5, DATE '1970-01-01' + $6::int4) ON CONFLICT DO NOTHING";
const SQL_HOLD_LIST: &str = "SELECT hold_id, case_id, placed_by, (placed_day - DATE '1970-01-01')::int4, (released_day - DATE '1970-01-01')::int4, version \
     FROM core.legal_hold WHERE tenant_id = $1 AND case_id = $2 ORDER BY hold_id";
/// Release with a second, distinct approver; optimistic on `version`.
const SQL_HOLD_RELEASE: &str = "UPDATE core.legal_hold SET released_by = $4, release_approved_by = $5, released_day = DATE '1970-01-01' + $6::int4, \
     version = $3 + 1 WHERE tenant_id = $1 AND hold_id = $2 AND version = $3 AND released_day IS NULL";

/// Place a hold; `case.legal_hold` follows by trigger.
pub async fn place_hold(
    tx: &mut TenantTx,
    hold: HoldId,
    case: CaseId,
    reason_ct: &[u8],
    day: Day,
) -> Result<()> {
    bounded(reason_ct, MAX_REASON_CT, "reason_ct")?;
    let by = actor(tx)?;
    let n = sqlx::query(SQL_HOLD_INSERT)
        .bind(tx.tenant().uuid())
        .bind(hold.uuid())
        .bind(case.uuid())
        .bind(reason_ct)
        .bind(by.uuid())
        .bind(day.i32()?)
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::AlreadyExists)
}

/// Holds of a case.
pub async fn holds(tx: &mut TenantTx, case: CaseId) -> Result<Vec<LegalHold>> {
    let rows = sqlx::query(SQL_HOLD_LIST)
        .bind(tx.tenant().uuid())
        .bind(case.uuid())
        .fetch_all(tx.conn())
        .await
        .map_err(db)?;
    rows.iter()
        .map(|r| {
            Ok(LegalHold {
                hold_id: HoldId::from_bytes(get_uuid(r, 0)?),
                case_id: CaseId::from_bytes(get_uuid(r, 1)?),
                placed_by: UserId::from_bytes(get_uuid(r, 2)?),
                placed_day: get_day(r, 3)?,
                released_day: get_opt_day(r, 4)?,
                version: get_u64(r, 5)?,
            })
        })
        .collect()
}

/// Release a hold: the principal releases, `approved_by` (distinct) approves.
pub async fn release_hold(
    tx: &mut TenantTx,
    hold: HoldId,
    version: u64,
    approved_by: UserId,
    day: Day,
) -> Result<()> {
    let by = actor(tx)?;
    if approved_by == by || approved_by.is_nil() {
        return Err(DbError::InvalidInput("dual control"));
    }
    let n = sqlx::query(SQL_HOLD_RELEASE)
        .bind(tx.tenant().uuid())
        .bind(hold.uuid())
        .bind(i64_of(version)?)
        .bind(by.uuid())
        .bind(approved_by.uuid())
        .bind(day.i32()?)
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::VersionConflict)
}

// ---- deletion_request -------------------------------------------------------

const SQL_DR_INSERT: &str = "INSERT INTO core.deletion_request (tenant_id, request_id, case_id, requested_by, reason_code) \
     VALUES ($1, $2, $3, $4, $5::text::core.deletion_reason) ON CONFLICT DO NOTHING";
const SQL_DR_APPROVE: &str = "UPDATE core.deletion_request SET approved_by = $4, state = 'approved', version = $3 + 1 \
     WHERE tenant_id = $1 AND request_id = $2 AND version = $3 AND state = 'pending' AND requested_by <> $4";
const SQL_DR_SET: &str = "UPDATE core.deletion_request SET state = $4::text::core.deletion_state, version = $3 + 1 \
     WHERE tenant_id = $1 AND request_id = $2 AND version = $3 AND state IN ('pending', 'approved')";
const SQL_DR_GET: &str = "SELECT case_id, requested_by, approved_by, state::text, version FROM core.deletion_request \
     WHERE tenant_id = $1 AND request_id = $2";

/// Deletion request `(case, requested_by, approved_by, state, version)`.
pub type DeletionRequest = (CaseId, UserId, Option<UserId>, String, u64);

/// Request a case deletion.
pub async fn request_deletion(
    tx: &mut TenantTx,
    req: RequestId,
    case: CaseId,
    reason: &str,
) -> Result<()> {
    if ![
        "source_request",
        "retention_expiry",
        "legal_requirement",
        "duplicate_case",
    ]
    .contains(&reason)
    {
        return Err(DbError::InvalidInput("deletion reason"));
    }
    let by = actor(tx)?;
    let n = sqlx::query(SQL_DR_INSERT)
        .bind(tx.tenant().uuid())
        .bind(req.uuid())
        .bind(case.uuid())
        .bind(by.uuid())
        .bind(reason)
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::AlreadyExists)
}

/// Approve as a second, distinct person (the principal).
pub async fn approve_deletion(tx: &mut TenantTx, req: RequestId, version: u64) -> Result<()> {
    let by = actor(tx)?;
    let n = sqlx::query(SQL_DR_APPROVE)
        .bind(tx.tenant().uuid())
        .bind(req.uuid())
        .bind(i64_of(version)?)
        .bind(by.uuid())
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::VersionConflict)
}

/// Mark executed or rejected.
pub async fn set_deletion_state(
    tx: &mut TenantTx,
    req: RequestId,
    version: u64,
    executed: bool,
) -> Result<()> {
    let n = sqlx::query(SQL_DR_SET)
        .bind(tx.tenant().uuid())
        .bind(req.uuid())
        .bind(i64_of(version)?)
        .bind(if executed { "executed" } else { "rejected" })
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::VersionConflict)
}

/// Lookup.
pub async fn get_deletion(tx: &mut TenantTx, req: RequestId) -> Result<DeletionRequest> {
    let r = sqlx::query(SQL_DR_GET)
        .bind(tx.tenant().uuid())
        .bind(req.uuid())
        .fetch_optional(tx.conn())
        .await
        .map_err(db)?
        .ok_or(DbError::NotFound)?;
    Ok((
        CaseId::from_bytes(get_uuid(&r, 0)?),
        UserId::from_bytes(get_uuid(&r, 1)?),
        get_opt_uuid(&r, 2)?.map(UserId::from_bytes),
        get_string(&r, 3)?,
        get_u64(&r, 4)?,
    ))
}

// ---- wrap_deletion_request (ADR-044(1)) ---------------------------------------

const SQL_WD_INSERT: &str = "INSERT INTO core.wrap_deletion_request (tenant_id, request_id, case_id, target_user_id, requested_by, requested_day, not_before_day) \
     VALUES ($1, $2, $3, $4, $5, DATE '1970-01-01' + $6::int4, DATE '1970-01-01' + $7::int4) ON CONFLICT DO NOTHING";
const SQL_WD_APPROVE: &str = "UPDATE core.wrap_deletion_request SET approved_by = $4, state = 'approved', version = $3 + 1 \
     WHERE tenant_id = $1 AND request_id = $2 AND version = $3 AND state = 'pending' AND requested_by <> $4";
const SQL_WD_NOTIFIED: &str = "UPDATE core.wrap_deletion_request SET oversight_notified_day = DATE '1970-01-01' + $4::int4, version = $3 + 1 \
     WHERE tenant_id = $1 AND request_id = $2 AND version = $3 AND oversight_notified_day IS NULL";
/// Executable: approved, cooled off, OVERSIGHT notified.
const SQL_WD_EXECUTABLE: &str = "SELECT request_id, case_id, target_user_id, version FROM core.wrap_deletion_request \
     WHERE tenant_id = $1 AND state IN ('approved', 'blocked_min_holders') AND not_before_day <= DATE '1970-01-01' + $2::int4 \
     AND oversight_notified_day IS NOT NULL ORDER BY request_id LIMIT 200";
const SQL_WD_SET: &str = "UPDATE core.wrap_deletion_request SET state = $4::text::core.wrap_deletion_state, version = $3 + 1 \
     WHERE tenant_id = $1 AND request_id = $2 AND version = $3";

/// Request deletion of one member's wraps (cooling-off = 7 days).
pub async fn request_wrap_deletion(
    tx: &mut TenantTx,
    req: RequestId,
    case: CaseId,
    target: UserId,
    day: Day,
) -> Result<()> {
    let by = actor(tx)?;
    let n = sqlx::query(SQL_WD_INSERT)
        .bind(tx.tenant().uuid())
        .bind(req.uuid())
        .bind(case.uuid())
        .bind(target.uuid())
        .bind(by.uuid())
        .bind(day.i32()?)
        .bind(day.plus(WRAP_DELETION_COOLOFF_DAYS)?.i32()?)
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::AlreadyExists)
}

/// Dual-control approval by the principal (distinct from the requester).
pub async fn approve_wrap_deletion(tx: &mut TenantTx, req: RequestId, version: u64) -> Result<()> {
    let by = actor(tx)?;
    let n = sqlx::query(SQL_WD_APPROVE)
        .bind(tx.tenant().uuid())
        .bind(req.uuid())
        .bind(i64_of(version)?)
        .bind(by.uuid())
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::VersionConflict)
}

/// Record the content-free OVERSIGHT notice day.
pub async fn wrap_deletion_notified(
    tx: &mut TenantTx,
    req: RequestId,
    version: u64,
    day: Day,
) -> Result<()> {
    let n = sqlx::query(SQL_WD_NOTIFIED)
        .bind(tx.tenant().uuid())
        .bind(req.uuid())
        .bind(i64_of(version)?)
        .bind(day.i32()?)
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::VersionConflict)
}

/// Requests ready to execute on `today`: `(request, case, target, version)`
/// (worker `wrap_deletion_execute`, which checks `min_recipients` holders).
pub async fn executable_wrap_deletions(
    tx: &mut TenantTx,
    today: Day,
) -> Result<Vec<(RequestId, CaseId, UserId, u64)>> {
    let rows = sqlx::query(SQL_WD_EXECUTABLE)
        .bind(tx.tenant().uuid())
        .bind(today.i32()?)
        .fetch_all(tx.conn())
        .await
        .map_err(db)?;
    rows.iter()
        .map(|r| {
            Ok((
                RequestId::from_bytes(get_uuid(r, 0)?),
                CaseId::from_bytes(get_uuid(r, 1)?),
                UserId::from_bytes(get_uuid(r, 2)?),
                get_u64(r, 3)?,
            ))
        })
        .collect()
}

/// Final state: `executed`, `cancelled` or `blocked_min_holders`.
pub async fn set_wrap_deletion_state(
    tx: &mut TenantTx,
    req: RequestId,
    version: u64,
    state: &str,
) -> Result<()> {
    if !["executed", "cancelled", "blocked_min_holders"].contains(&state) {
        return Err(DbError::InvalidInput("wrap deletion state"));
    }
    let n = sqlx::query(SQL_WD_SET)
        .bind(tx.tenant().uuid())
        .bind(req.uuid())
        .bind(i64_of(version)?)
        .bind(state)
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::VersionConflict)
}

// ---- sla_timer ---------------------------------------------------------------

const SQL_SLA_INSERT: &str = "INSERT INTO core.sla_timer (tenant_id, timer_id, case_id, kind, anchor_day, due_day) \
     VALUES ($1, $2, $3, $4::text::core.sla_kind, DATE '1970-01-01' + $5::int4, DATE '1970-01-01' + $6::int4) ON CONFLICT DO NOTHING";
const SQL_SLA_DUE: &str = "SELECT timer_id, case_id, version FROM core.sla_timer WHERE tenant_id = $1 AND state = 'running' \
     AND due_day <= DATE '1970-01-01' + $2::int4 ORDER BY timer_id LIMIT 200";
const SQL_SLA_SET: &str = "UPDATE core.sla_timer SET state = $4::text::core.sla_state, version = $3 + 1 \
     WHERE tenant_id = $1 AND timer_id = $2 AND version = $3 AND state IN ('running', 'paused')";

/// Start a timer anchored on a day (the fixed-slot `received_date` for
/// source-driven timers).
pub async fn start_timer(
    tx: &mut TenantTx,
    timer: TimerId,
    case: CaseId,
    kind: &str,
    anchor: Day,
    due: Day,
) -> Result<()> {
    if !["acknowledge", "feedback", "custom"].contains(&kind) || due < anchor {
        return Err(DbError::InvalidInput("timer"));
    }
    let n = sqlx::query(SQL_SLA_INSERT)
        .bind(tx.tenant().uuid())
        .bind(timer.uuid())
        .bind(case.uuid())
        .bind(kind)
        .bind(anchor.i32()?)
        .bind(due.i32()?)
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::AlreadyExists)
}

/// Running timers due on or before `today`: `(timer, case, version)`.
pub async fn timers_due(tx: &mut TenantTx, today: Day) -> Result<Vec<(TimerId, CaseId, u64)>> {
    let rows = sqlx::query(SQL_SLA_DUE)
        .bind(tx.tenant().uuid())
        .bind(today.i32()?)
        .fetch_all(tx.conn())
        .await
        .map_err(db)?;
    rows.iter()
        .map(|r| {
            Ok((
                TimerId::from_bytes(get_uuid(r, 0)?),
                CaseId::from_bytes(get_uuid(r, 1)?),
                get_u64(r, 2)?,
            ))
        })
        .collect()
}

/// `paused`, `running`, `met`, `breached` or `cancelled`.
pub async fn set_timer_state(
    tx: &mut TenantTx,
    timer: TimerId,
    version: u64,
    state: &str,
) -> Result<()> {
    if !["running", "paused", "met", "breached", "cancelled"].contains(&state) {
        return Err(DbError::InvalidInput("timer state"));
    }
    let n = sqlx::query(SQL_SLA_SET)
        .bind(tx.tenant().uuid())
        .bind(timer.uuid())
        .bind(i64_of(version)?)
        .bind(state)
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::VersionConflict)
}

// ---- breakglass_request (15 §5.6) ---------------------------------------------

/// Break-glass row (legal basis ciphertext fetched with it).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Breakglass {
    pub request_id: RequestId,
    pub case_id: CaseId,
    pub requester_id: UserId,
    pub approver_id: Option<UserId>,
    pub reviewer_id: Option<UserId>,
    pub state: String,
    pub review_due_day: Option<Day>,
    pub version: u64,
}

const SQL_BG_INSERT: &str = "INSERT INTO core.breakglass_request (tenant_id, request_id, case_id, requester_id, reason_code, legal_basis_ct) \
     VALUES ($1, $2, $3, $4, $5::text::core.breakglass_reason, $6) ON CONFLICT DO NOTHING";
/// Approval by a distinct person; the access expires after `$5` hours
/// (staff security timer, allow-listed L3) and is reviewed by `review_due`.
const SQL_BG_APPROVE: &str = "UPDATE core.breakglass_request SET approver_id = $4, state = 'approved_pending_wrap', \
     expires_at = pg_catalog.now() + pg_catalog.make_interval(hours => $5), review_due_day = DATE '1970-01-01' + $6::int4, version = $3 + 1 \
     WHERE tenant_id = $1 AND request_id = $2 AND version = $3 AND state = 'requested' AND requester_id <> $4";
const SQL_BG_ACTIVATE: &str = "UPDATE core.breakglass_request SET state = 'active', version = $3 + 1 \
     WHERE tenant_id = $1 AND request_id = $2 AND version = $3 AND state = 'approved_pending_wrap'";
const SQL_BG_MEMBER: &str = "INSERT INTO core.case_member (tenant_id, case_id, user_id, access_level, via, grant_ref, state) \
     SELECT $1, b.case_id, b.requester_id, 'read', 'breakglass', b.request_id, 'active' FROM core.breakglass_request b \
     WHERE b.tenant_id = $1 AND b.request_id = $2 AND b.state = 'active' ON CONFLICT DO NOTHING";
const SQL_BG_EXPIRE: &str = "UPDATE core.breakglass_request SET state = 'expired', version = version + 1 \
     WHERE tenant_id = $1 AND state = 'active' AND expires_at <= pg_catalog.now()";
const SQL_BG_REVOKE_MEMBERS: &str = "UPDATE core.case_member m SET state = 'revoked', version = m.version + 1 FROM core.breakglass_request b \
     WHERE m.tenant_id = $1 AND b.tenant_id = m.tenant_id AND b.request_id = m.grant_ref AND b.state = 'expired' AND m.state = 'active'";
const SQL_BG_REVIEW: &str = "UPDATE core.breakglass_request SET reviewer_id = $4, review_outcome = $5::text::core.review_outcome, state = 'reviewed', \
     version = $3 + 1 WHERE tenant_id = $1 AND request_id = $2 AND version = $3 AND state IN ('active', 'expired') \
     AND requester_id <> $4 AND approver_id <> $4";
const SQL_BG_REJECT: &str = "UPDATE core.breakglass_request SET state = 'rejected', version = $3 + 1 \
     WHERE tenant_id = $1 AND request_id = $2 AND version = $3 AND state = 'requested' AND requester_id <> $4";
const SQL_BG_GET: &str = "SELECT request_id, case_id, requester_id, approver_id, reviewer_id, state::text, (review_due_day - DATE '1970-01-01')::int4, version \
     FROM core.breakglass_request WHERE tenant_id = $1 AND request_id = $2";

fn bg_row(r: &sqlx::postgres::PgRow) -> Result<Breakglass> {
    Ok(Breakglass {
        request_id: RequestId::from_bytes(get_uuid(r, 0)?),
        case_id: CaseId::from_bytes(get_uuid(r, 1)?),
        requester_id: UserId::from_bytes(get_uuid(r, 2)?),
        approver_id: get_opt_uuid(r, 3)?.map(UserId::from_bytes),
        reviewer_id: get_opt_uuid(r, 4)?.map(UserId::from_bytes),
        state: get_string(r, 5)?,
        review_due_day: get_opt_day(r, 6)?,
        version: get_u64(r, 7)?,
    })
}

/// Request break-glass access (the principal is the requester).
pub async fn request_breakglass(
    tx: &mut TenantTx,
    req: RequestId,
    case: CaseId,
    reason: &str,
    legal_basis_ct: &[u8],
) -> Result<()> {
    if ![
        "member_unavailable",
        "legal_deadline",
        "incident_response",
        "records_obligation",
    ]
    .contains(&reason)
    {
        return Err(DbError::InvalidInput("break-glass reason"));
    }
    bounded(legal_basis_ct, MAX_REASON_CT, "legal_basis_ct")?;
    let by = actor(tx)?;
    let n = sqlx::query(SQL_BG_INSERT)
        .bind(tx.tenant().uuid())
        .bind(req.uuid())
        .bind(case.uuid())
        .bind(by.uuid())
        .bind(reason)
        .bind(legal_basis_ct)
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::AlreadyExists)
}

/// Approve (distinct approver = principal); access lasts `hours` (1..=72).
pub async fn approve_breakglass(
    tx: &mut TenantTx,
    req: RequestId,
    version: u64,
    hours: u8,
    review_due: Day,
) -> Result<()> {
    if !(1..=72).contains(&hours) {
        return Err(DbError::InvalidInput("break-glass duration"));
    }
    let by = actor(tx)?;
    let n = sqlx::query(SQL_BG_APPROVE)
        .bind(tx.tenant().uuid())
        .bind(req.uuid())
        .bind(i64_of(version)?)
        .bind(by.uuid())
        .bind(i32::from(hours))
        .bind(review_due.i32()?)
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::VersionConflict)
}

/// Reject a pending request (distinct person).
pub async fn reject_breakglass(tx: &mut TenantTx, req: RequestId, version: u64) -> Result<()> {
    let by = actor(tx)?;
    let n = sqlx::query(SQL_BG_REJECT)
        .bind(tx.tenant().uuid())
        .bind(req.uuid())
        .bind(i64_of(version)?)
        .bind(by.uuid())
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::VersionConflict)
}

/// After the approver's Desk stored the wrap: activate and add the requester
/// as a `read` member `via = breakglass` (visible in every view).
pub async fn activate_breakglass(tx: &mut TenantTx, req: RequestId, version: u64) -> Result<()> {
    let n = sqlx::query(SQL_BG_ACTIVATE)
        .bind(tx.tenant().uuid())
        .bind(req.uuid())
        .bind(i64_of(version)?)
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::VersionConflict)?;
    let n = sqlx::query(SQL_BG_MEMBER)
        .bind(tx.tenant().uuid())
        .bind(req.uuid())
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::AlreadyExists)
}

/// Expire active grants past `expires_at` and revoke their memberships
/// (worker `breakglass_expire`). Returns the number expired.
pub async fn expire_breakglass(tx: &mut TenantTx) -> Result<u64> {
    let n = sqlx::query(SQL_BG_EXPIRE)
        .bind(tx.tenant().uuid())
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    sqlx::query(SQL_BG_REVOKE_MEMBERS)
        .bind(tx.tenant().uuid())
        .execute(tx.conn())
        .await
        .map_err(db)?;
    Ok(n)
}

/// Review by a third, distinct person (the principal).
pub async fn review_breakglass(
    tx: &mut TenantTx,
    req: RequestId,
    version: u64,
    outcome: &str,
) -> Result<()> {
    if !["justified", "unjustified", "inconclusive"].contains(&outcome) {
        return Err(DbError::InvalidInput("review outcome"));
    }
    let by = actor(tx)?;
    let n = sqlx::query(SQL_BG_REVIEW)
        .bind(tx.tenant().uuid())
        .bind(req.uuid())
        .bind(i64_of(version)?)
        .bind(by.uuid())
        .bind(outcome)
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::VersionConflict)
}

/// Lookup.
pub async fn get_breakglass(tx: &mut TenantTx, req: RequestId) -> Result<Breakglass> {
    let r = sqlx::query(SQL_BG_GET)
        .bind(tx.tenant().uuid())
        .bind(req.uuid())
        .fetch_optional(tx.conn())
        .await
        .map_err(db)?
        .ok_or(DbError::NotFound)?;
    bg_row(&r)
}
