// SPDX-License-Identifier: AGPL-3.0-or-later
use candor_authz::{
    Action, BreakGlass, CaseId, CaseResource, Decision, Principal, Role, TenantId, UserId,
    authorize,
};

fn principal(role: Role) -> Principal {
    Principal {
        tenant: TenantId(1),
        user: UserId(7),
        role,
    }
}

fn resource() -> CaseResource {
    CaseResource {
        tenant: TenantId(1),
        case: CaseId(9),
        assigned_to: Some(UserId(7)),
        coi_user: None,
    }
}

#[test]
fn cross_tenant_access_is_always_denied() {
    let foreign = CaseResource {
        tenant: TenantId(2),
        ..resource()
    };
    for action in [
        Action::ViewCase,
        Action::ModifyCase,
        Action::AssignCase,
        Action::ViewAudit,
    ] {
        assert_eq!(
            authorize(principal(Role::Investigator), action, foreign, 100, None),
            Decision::Deny
        );
    }
}

#[test]
fn system_admin_has_no_case_content_capability() {
    assert_eq!(
        authorize(
            principal(Role::SystemAdmin),
            Action::ViewCase,
            resource(),
            100,
            None
        ),
        Decision::Deny
    );
    assert_eq!(
        authorize(
            principal(Role::SystemAdmin),
            Action::ModifyCase,
            resource(),
            100,
            None
        ),
        Decision::Deny
    );
}

#[test]
fn investigator_requires_assignment_for_case_content() {
    let unassigned = CaseResource {
        assigned_to: Some(UserId(8)),
        ..resource()
    };
    assert_eq!(
        authorize(
            principal(Role::Investigator),
            Action::ViewCase,
            unassigned,
            100,
            None
        ),
        Decision::Deny
    );
    assert_eq!(
        authorize(
            principal(Role::Investigator),
            Action::ViewCase,
            resource(),
            100,
            None
        ),
        Decision::Allow
    );
}

#[test]
fn conflict_of_interest_overrides_normal_assignment() {
    let conflicted = CaseResource {
        coi_user: Some(UserId(7)),
        ..resource()
    };
    assert_eq!(
        authorize(
            principal(Role::Investigator),
            Action::ViewCase,
            conflicted,
            100,
            None
        ),
        Decision::Deny
    );
}

#[test]
fn break_glass_must_be_approved_and_unexpired_and_never_crosses_tenants() {
    let unassigned = CaseResource {
        assigned_to: Some(UserId(8)),
        ..resource()
    };
    let active = BreakGlass {
        approved: true,
        expires_day: 101,
    };
    assert_eq!(
        authorize(
            principal(Role::Investigator),
            Action::ViewCase,
            unassigned,
            100,
            Some(active)
        ),
        Decision::Allow
    );
    let expired = BreakGlass {
        approved: true,
        expires_day: 99,
    };
    assert_eq!(
        authorize(
            principal(Role::Investigator),
            Action::ViewCase,
            unassigned,
            100,
            Some(expired)
        ),
        Decision::Deny
    );
    let foreign = CaseResource {
        tenant: TenantId(2),
        ..unassigned
    };
    assert_eq!(
        authorize(
            principal(Role::Investigator),
            Action::ViewCase,
            foreign,
            100,
            Some(active)
        ),
        Decision::Deny
    );
}

#[test]
fn role_matrix_is_explicit_and_deny_by_default() {
    assert_eq!(
        authorize(
            principal(Role::Triage),
            Action::AssignCase,
            resource(),
            100,
            None
        ),
        Decision::Allow
    );
    assert_eq!(
        authorize(
            principal(Role::Triage),
            Action::ModifyCase,
            resource(),
            100,
            None
        ),
        Decision::Deny
    );
    assert_eq!(
        authorize(
            principal(Role::Auditor),
            Action::ViewAudit,
            resource(),
            100,
            None
        ),
        Decision::Allow
    );
    assert_eq!(
        authorize(
            principal(Role::Auditor),
            Action::ViewCase,
            resource(),
            100,
            None
        ),
        Decision::Deny
    );
}
