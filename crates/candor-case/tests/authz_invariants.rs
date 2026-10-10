// SPDX-License-Identifier: AGPL-3.0-or-later

use candor_case::{
    Action, AuthzContext, Decision, DenyCode, Obligation, Principal, ResourceRef, Role,
    WrapCandidate, WrapError, authorize, validate_key_wraps,
};
use std::collections::BTreeSet;

fn principal(tenant: u128, role: Role) -> Principal {
    Principal {
        tenant_id: tenant,
        user_id: 7,
        person_ref: 77,
        roles: BTreeSet::from([role]),
        suspended: false,
    }
}

fn resource(tenant: u128) -> ResourceRef {
    ResourceRef {
        tenant_id: tenant,
        case_id: 55,
        member: true,
        lead: false,
        coi_excluded: false,
        visible: true,
    }
}

#[test]
fn st_rm3_authz_denies_cross_tenant_before_any_role_permission() {
    let p = principal(1, Role::Investigator);
    let r = resource(2);
    assert_eq!(
        authorize(&p, Action::ReadContent, &r, &AuthzContext::default()),
        Decision::Deny(DenyCode::Tenant)
    );
}

#[test]
fn st_rm3_authz_coi_deny_overrides_acl_membership() {
    let p = principal(1, Role::CaseLead);
    let mut r = resource(1);
    r.coi_excluded = true;
    assert_eq!(
        authorize(&p, Action::ReadContent, &r, &AuthzContext::default()),
        Decision::Deny(DenyCode::NoRelation)
    );
}

#[test]
fn st_rm3_sysadmin_never_receives_case_content() {
    let p = principal(1, Role::SysAdmin);
    let r = resource(1);
    assert_eq!(
        authorize(&p, Action::ReadContent, &r, &AuthzContext::default()),
        Decision::Deny(DenyCode::Role)
    );
}

#[test]
fn st_rm3_original_export_requires_step_up_and_second_approver() {
    let p = principal(1, Role::Investigator);
    let r = resource(1);
    let decision = authorize(&p, Action::ExportOriginal, &r, &AuthzContext::default());
    assert_eq!(
        decision,
        Decision::Permit(vec![
            Obligation::RequireStepUp,
            Obligation::RequireSecondApprover,
        ])
    );
}

#[test]
fn st_rm3_suspended_principal_is_explicitly_denied() {
    let mut p = principal(1, Role::Investigator);
    p.suspended = true;
    let r = resource(1);
    assert_eq!(
        authorize(&p, Action::ReadContent, &r, &AuthzContext::default()),
        Decision::Deny(DenyCode::Suspended)
    );
}

#[test]
fn st_rm3_wrap_validation_rejects_extra_excluded_stale_or_too_few_recipients() {
    let candidates = BTreeSet::from([
        WrapCandidate {
            key_id: 1,
            user_id: 10,
            current: true,
            excluded: false,
        },
        WrapCandidate {
            key_id: 2,
            user_id: 20,
            current: true,
            excluded: false,
        },
        WrapCandidate {
            key_id: 3,
            user_id: 30,
            current: true,
            excluded: true,
        },
        WrapCandidate {
            key_id: 4,
            user_id: 40,
            current: false,
            excluded: false,
        },
    ]);

    assert_eq!(validate_key_wraps(&[1, 2], &candidates, 2), Ok(()));
    assert_eq!(
        validate_key_wraps(&[1], &candidates, 2),
        Err(WrapError::TooFewRecipients)
    );
    assert_eq!(
        validate_key_wraps(&[1, 99], &candidates, 2),
        Err(WrapError::NotCandidate)
    );
    assert_eq!(
        validate_key_wraps(&[1, 3], &candidates, 2),
        Err(WrapError::Excluded)
    );
    assert_eq!(
        validate_key_wraps(&[1, 4], &candidates, 2),
        Err(WrapError::StaleKey)
    );
}

#[test]
fn st_rm3_hidden_or_relation_denials_map_uniformly() {
    let p = principal(1, Role::Investigator);
    let mut r = resource(1);
    r.member = false;
    r.visible = false;
    assert_eq!(
        authorize(&p, Action::ReadContent, &r, &AuthzContext::default()),
        Decision::Deny(DenyCode::NoRelation)
    );
}
