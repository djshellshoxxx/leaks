// SPDX-License-Identifier: AGPL-3.0-or-later

use candor_authz::{
    authorize_case, validate_wrap_recipients, AccountState, AuthzPrincipal, CasePolicyResource,
    DenyCode, Obligation, PolicyAction, PolicyDecision, Role, TenantId, UserId, WrapCandidate,
    WrapError,
};

fn principal(role: Role) -> AuthzPrincipal {
    AuthzPrincipal {
        tenant: TenantId(1),
        user: UserId(7),
        role,
        account_state: AccountState::Active,
    }
}

fn resource() -> CasePolicyResource {
    CasePolicyResource {
        tenant: TenantId(1),
        member: true,
        coi_excluded: false,
    }
}

#[test]
fn st_rm3_explicit_denies_precede_role_and_relation() {
    let mut suspended = principal(Role::Investigator);
    suspended.account_state = AccountState::Suspended;
    assert_eq!(
        authorize_case(suspended, PolicyAction::ReadContent, resource()),
        PolicyDecision::Deny(DenyCode::Suspended)
    );

    let mut excluded = resource();
    excluded.coi_excluded = true;
    assert_eq!(
        authorize_case(principal(Role::Investigator), PolicyAction::ReadContent, excluded),
        PolicyDecision::Deny(DenyCode::NoRelation)
    );
}

#[test]
fn st_rm3_cross_tenant_and_sysadmin_content_access_are_denied() {
    let mut other_tenant = resource();
    other_tenant.tenant = TenantId(2);
    assert_eq!(
        authorize_case(principal(Role::Investigator), PolicyAction::ReadContent, other_tenant),
        PolicyDecision::Deny(DenyCode::Tenant)
    );
    assert_eq!(
        authorize_case(principal(Role::SystemAdmin), PolicyAction::ReadContent, resource()),
        PolicyDecision::Deny(DenyCode::Role)
    );
}

#[test]
fn st_rm3_original_export_carries_dual_control_and_step_up_obligations() {
    assert_eq!(
        authorize_case(principal(Role::Investigator), PolicyAction::ExportOriginal, resource()),
        PolicyDecision::Permit(vec![
            Obligation::RequireStepUp,
            Obligation::RequireSecondApprover,
        ])
    );
}

#[test]
fn st_rm3_wrap_recipients_are_exact_current_eligible_subset() {
    let candidates = [
        WrapCandidate { key_id: 1, current: true, excluded: false },
        WrapCandidate { key_id: 2, current: true, excluded: false },
        WrapCandidate { key_id: 3, current: true, excluded: true },
        WrapCandidate { key_id: 4, current: false, excluded: false },
    ];

    assert_eq!(validate_wrap_recipients(&[1, 2], &candidates, 2), Ok(()));
    assert_eq!(
        validate_wrap_recipients(&[1], &candidates, 2),
        Err(WrapError::TooFewRecipients)
    );
    assert_eq!(
        validate_wrap_recipients(&[1, 1], &candidates, 2),
        Err(WrapError::DuplicateRecipient)
    );
    assert_eq!(
        validate_wrap_recipients(&[1, 99], &candidates, 2),
        Err(WrapError::NotCandidate)
    );
    assert_eq!(
        validate_wrap_recipients(&[1, 3], &candidates, 2),
        Err(WrapError::Excluded)
    );
    assert_eq!(
        validate_wrap_recipients(&[1, 4], &candidates, 2),
        Err(WrapError::StaleKey)
    );
}
