// SPDX-License-Identifier: AGPL-3.0-or-later
#![forbid(unsafe_code)]

pub mod pdp;
mod session;

pub use pdp::{DenyCode, Obligation, WrapError};
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

    if let Some(coi_user) = resource.coi_user
        && coi_user.0 == principal.user.0
    {
        return Decision::Deny;
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

/// The decision type of the C-22 decision point (`pdp::Decision`).
pub type PolicyDecision = pdp::Decision;

impl From<Role> for pdp::Role {
    fn from(role: Role) -> Self {
        match role {
            Role::Investigator => pdp::Role::Investigator,
            Role::Triage => pdp::Role::Triager,
            Role::Auditor => pdp::Role::Auditor,
            Role::SystemAdmin => pdp::Role::SysAdmin,
        }
    }
}

impl From<PolicyAction> for pdp::Action {
    fn from(action: PolicyAction) -> Self {
        match action {
            PolicyAction::ReadContent => pdp::Action::ReadContent,
            PolicyAction::ExportOriginal => pdp::Action::ExportOriginal,
        }
    }
}

/// Case-content policy path over the single-role principal model. It is a thin adapter onto
/// the C-22 decision point in [`pdp`], which implements the spec's mandatory evaluation order
/// (authentication/tenant, explicit deny, role, relation, then obligations). There is one
/// decision procedure, not two.
#[must_use]
pub fn authorize_case(
    principal: AuthzPrincipal,
    action: PolicyAction,
    resource: CasePolicyResource,
) -> PolicyDecision {
    let mut roles = std::collections::BTreeSet::new();
    roles.insert(pdp::Role::from(principal.role));
    let subject = pdp::Principal {
        tenant_id: principal.tenant.0,
        user_id: principal.user.0,
        // This model carries no person binding; the user id stands in (it is never compared).
        person_ref: principal.user.0,
        roles,
        suspended: principal.account_state != AccountState::Active,
    };
    let case = pdp::ResourceRef {
        tenant_id: resource.tenant.0,
        // This model carries no case id; the decision never reads it.
        case_id: 0,
        member: resource.member,
        lead: false,
        coi_excluded: resource.coi_excluded,
        visible: true,
    };
    pdp::authorize(
        &subject,
        pdp::Action::from(action),
        &case,
        &pdp::AuthzContext::default(),
    )
}

/// A candidate recipient key without a user binding (one key per user). Prefer
/// [`pdp::WrapCandidate`], which carries the user id and lets the distinct-user rule
/// (ADR-044(2)) be checked exactly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WrapCandidate {
    pub key_id: u128,
    pub current: bool,
    pub excluded: bool,
}

/// Validate a client-supplied recipient set before the Case Service accepts case-key wraps.
/// No server-side role may smuggle an extra recipient into the set. Adapter onto
/// [`pdp::validate_key_wraps`] with each key standing for its own user.
pub fn validate_wrap_recipients(
    key_ids: &[u128],
    candidates: &[WrapCandidate],
    minimum_distinct: usize,
) -> Result<(), WrapError> {
    let candidates: std::collections::BTreeSet<pdp::WrapCandidate> = candidates
        .iter()
        .map(|candidate| pdp::WrapCandidate {
            key_id: candidate.key_id,
            user_id: candidate.key_id,
            current: candidate.current,
            excluded: candidate.excluded,
        })
        .collect();
    pdp::validate_key_wraps(key_ids, &candidates, minimum_distinct)
}
