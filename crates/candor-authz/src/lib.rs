// SPDX-License-Identifier: AGPL-3.0-or-later
#![forbid(unsafe_code)]

mod session;
pub use session::{Audience, Session, SessionError, SessionToken, StaffClass};

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

/// Account state participating in the normative explicit-deny phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountState {
    Active,
    Suspended,
    NeedsAuthenticator,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthzPrincipal {
    pub tenant: TenantId,
    pub user: UserId,
    pub role: Role,
    pub account_state: AccountState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CasePolicyResource {
    pub tenant: TenantId,
    pub member: bool,
    /// Represents the result of the blinded COI-tag membership test.
    pub coi_excluded: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyAction {
    ReadContent,
    ExportOriginal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Obligation {
    RequireStepUp,
    RequireSecondApprover,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenyCode {
    Tenant,
    Suspended,
    NoRelation,
    Role,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyDecision {
    Permit(Vec<Obligation>),
    Deny(DenyCode),
}

/// Case-content policy path implementing the spec's mandatory evaluation order:
/// authentication/tenant, explicit deny, role, relation, then obligations.
#[must_use]
pub fn authorize_case(
    principal: AuthzPrincipal,
    action: PolicyAction,
    resource: CasePolicyResource,
) -> PolicyDecision {
    if principal.tenant != resource.tenant {
        return PolicyDecision::Deny(DenyCode::Tenant);
    }
    if principal.account_state != AccountState::Active {
        return PolicyDecision::Deny(DenyCode::Suspended);
    }
    if resource.coi_excluded {
        return PolicyDecision::Deny(DenyCode::NoRelation);
    }

    match principal.role {
        Role::Investigator | Role::Triage => {}
        Role::Auditor | Role::SystemAdmin => return PolicyDecision::Deny(DenyCode::Role),
    }

    if !resource.member {
        return PolicyDecision::Deny(DenyCode::NoRelation);
    }

    match action {
        PolicyAction::ReadContent => PolicyDecision::Permit(Vec::new()),
        PolicyAction::ExportOriginal => PolicyDecision::Permit(vec![
            Obligation::RequireStepUp,
            Obligation::RequireSecondApprover,
        ]),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WrapCandidate {
    pub key_id: u128,
    pub current: bool,
    pub excluded: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WrapError {
    TooFewRecipients,
    DuplicateRecipient,
    NotCandidate,
    Excluded,
    StaleKey,
}

/// Validate a client-supplied recipient set before the Case Service accepts case-key wraps.
/// No server-side role may smuggle an extra recipient into the set.
pub fn validate_wrap_recipients(
    key_ids: &[u128],
    candidates: &[WrapCandidate],
    minimum_distinct: usize,
) -> Result<(), WrapError> {
    if key_ids.len() < minimum_distinct {
        return Err(WrapError::TooFewRecipients);
    }

    for (index, key_id) in key_ids.iter().enumerate() {
        if key_ids[..index].contains(key_id) {
            return Err(WrapError::DuplicateRecipient);
        }
        let Some(candidate) = candidates
            .iter()
            .find(|candidate| candidate.key_id == *key_id)
        else {
            return Err(WrapError::NotCandidate);
        };
        if candidate.excluded {
            return Err(WrapError::Excluded);
        }
        if !candidate.current {
            return Err(WrapError::StaleKey);
        }
    }

    Ok(())
}
