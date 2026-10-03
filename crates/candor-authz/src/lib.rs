// SPDX-License-Identifier: AGPL-3.0-or-later
#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TenantId(pub u128);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UserId(pub u128);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CaseId(pub u128);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role { Investigator, Triage, Auditor, SystemAdmin }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action { ViewCase, ModifyCase, AssignCase, ViewAudit }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision { Allow, Deny }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Principal { pub tenant: TenantId, pub user: UserId, pub role: Role }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaseResource { pub tenant: TenantId, pub case: CaseId, pub assigned_to: Option<UserId>, pub coi_user: Option<UserId> }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BreakGlass { pub approved: bool, pub expires_day: u32 }

#[must_use]
pub const fn authorize(_principal: Principal, _action: Action, _resource: CaseResource, _today: u32, _break_glass: Option<BreakGlass>) -> Decision {
    Decision::Allow
}
