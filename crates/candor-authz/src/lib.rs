// SPDX-License-Identifier: AGPL-3.0-or-later
#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TenantId(pub u128);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UserId(pub u128);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CaseId(pub u128);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Investigator,
    Triage,
    Auditor,
    SystemAdmin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    ViewCase,
    ModifyCase,
    AssignCase,
    ViewAudit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Principal {
    pub tenant: TenantId,
    pub user: UserId,
    pub role: Role,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaseResource {
    pub tenant: TenantId,
    pub case: CaseId,
    pub assigned_to: Option<UserId>,
    pub coi_user: Option<UserId>,
}

/// Represents a separately approved, bounded emergency grant. The policy intentionally stores
/// no free-text reason so authorization logs cannot acquire source-sensitive material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BreakGlass {
    pub approved: bool,
    pub expires_day: u32,
}

#[must_use]
pub const fn authorize(
    principal: Principal,
    action: Action,
    resource: CaseResource,
    today: u32,
    break_glass: Option<BreakGlass>,
) -> Decision {
    if principal.tenant.0 != resource.tenant.0 {
        return Decision::Deny;
    }

    if let Some(coi_user) = resource.coi_user {
        if coi_user.0 == principal.user.0 {
            return Decision::Deny;
        }
    }

    let emergency = match break_glass {
        Some(grant) => grant.approved && today <= grant.expires_day,
        None => false,
    };

    match (principal.role, action) {
        (Role::Auditor, Action::ViewAudit) | (Role::Triage, Action::AssignCase) => Decision::Allow,
        (Role::Investigator, Action::ViewCase | Action::ModifyCase) => {
            if emergency {
                return Decision::Allow;
            }
            match resource.assigned_to {
                Some(user) if user.0 == principal.user.0 => Decision::Allow,
                _ => Decision::Deny,
            }
        }
        _ => Decision::Deny,
    }
}
