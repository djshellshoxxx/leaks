// SPDX-License-Identifier: AGPL-3.0-or-later
//! C-22 decision-point contract: the 15 §5.2 matrix row by row, the §5.4 evaluation order,
//! the §5.9 baseline invariants (ST-060 authz matrix, ST-068 admin ≠ case access, ST-069 COI
//! exclusion, ST-146/147 triage-first and blinded COI) and the IMPL-RM3 §3.5 property
//! "deny unless an explicit grant exists; COI always wins". Key-wrap validation per
//! 07 §5.5 / BE-018 with hostile inputs.

use candor_authz::Audience;
use candor_authz::pdp::{
    Action, AuthzContext, Decision, DenyCode, MAX_WRAP_RECIPIENTS, Obligation, Principal,
    ResourceRef, Role, WrapCandidate, WrapError, authorize, validate_key_wraps,
};
use proptest::prelude::*;
use std::collections::BTreeSet;

fn principal(tenant: u128, roles: &[Role]) -> Principal {
    Principal {
        tenant_id: tenant,
        user_id: 7,
        person_ref: 77,
        roles: roles.iter().copied().collect(),
        suspended: false,
    }
}

fn full_relation(tenant: u128) -> ResourceRef {
    ResourceRef {
        tenant_id: tenant,
        case_id: 55,
        member: true,
        lead: true,
        coi_excluded: false,
        visible: true,
    }
}

fn desk() -> AuthzContext {
    AuthzContext::default()
}

/// 15 §5.2 transcribed independently of the engine's table:
/// (role, action, step-up, dual control, audited). Pairs not listed must deny with `Role`.
const EXPECTED: &[(Role, Action, bool, bool, bool)] = &[
    (Role::Triager, Action::Import, false, false, false),
    (Role::Oversight, Action::Import, false, false, true),
    (Role::Triager, Action::ReadContent, false, false, false),
    (Role::Investigator, Action::ReadContent, false, false, false),
    (Role::CaseLead, Action::ReadContent, false, false, false),
    (Role::Reviewer, Action::ReadContent, false, false, false),
    (Role::ChannelOwner, Action::ReadContent, false, false, false),
    (Role::Counsel, Action::ReadContent, false, false, false),
    (Role::Oversight, Action::ReadContent, false, false, true),
    (
        Role::RecordsCustodian,
        Action::ReadContent,
        false,
        false,
        false,
    ),
    (Role::Triager, Action::Transition, false, false, false),
    (Role::CaseLead, Action::Transition, false, false, false),
    (Role::Reviewer, Action::Transition, false, false, false),
    (Role::Reviewer, Action::CloseApprove, true, true, false),
    (Role::CaseLead, Action::MemberAdd, true, false, false),
    (Role::ChannelOwner, Action::MemberAdd, true, false, false),
    (Role::Triager, Action::OpenEvidence, false, false, false),
    (
        Role::Investigator,
        Action::OpenEvidence,
        false,
        false,
        false,
    ),
    (Role::CaseLead, Action::OpenEvidence, false, false, false),
    (Role::Reviewer, Action::OpenEvidence, false, false, false),
    (
        Role::ChannelOwner,
        Action::OpenEvidence,
        false,
        false,
        false,
    ),
    (Role::Counsel, Action::OpenEvidence, false, false, false),
    (Role::Oversight, Action::OpenEvidence, false, false, false),
    (
        Role::Investigator,
        Action::ExportRendition,
        true,
        false,
        false,
    ),
    (Role::CaseLead, Action::ExportRendition, true, false, false),
    (Role::Counsel, Action::ExportRendition, true, false, false),
    (
        Role::Investigator,
        Action::ExportOriginal,
        true,
        true,
        false,
    ),
    (Role::CaseLead, Action::ExportOriginal, true, true, false),
    (Role::Counsel, Action::ExportOriginal, true, true, false),
];

#[test]
fn st_060_matrix_matches_spec_15_5_2_for_every_role_and_action() {
    for role in Role::ALL {
        for action in Action::ALL {
            let decision = authorize(&principal(1, &[role]), action, &full_relation(1), &desk());
            let expected = EXPECTED.iter().find(|row| row.0 == role && row.1 == action);
            match expected {
                None => assert_eq!(
                    decision,
                    Decision::Deny(DenyCode::Role),
                    "{role:?} {action:?} must deny"
                ),
                Some(&(_, _, step_up, dual, audited)) => {
                    let mut obligations = Vec::new();
                    if step_up {
                        obligations.push(Obligation::RequireStepUp);
                    }
                    if dual {
                        obligations.push(Obligation::RequireSecondApprover);
                    }
                    if audited {
                        obligations.push(Obligation::AuditedAccess);
                    }
                    assert_eq!(
                        decision,
                        Decision::Permit(obligations),
                        "{role:?} {action:?} obligations"
                    );
                }
            }
        }
    }
}

#[test]
fn st_068_an_administrative_role_poisons_every_content_grant() {
    for admin in [Role::SysAdmin, Role::UserAdmin, Role::SecurityOfficer] {
        let mixed = principal(1, &[Role::Investigator, Role::CaseLead, admin]);
        for action in Action::ALL {
            assert_eq!(
                authorize(&mixed, action, &full_relation(1), &desk()),
                Decision::Deny(DenyCode::Role),
                "{admin:?} + content roles on {action:?}"
            );
        }
    }
}

#[test]
fn st_065_admin_audience_never_reaches_case_actions() {
    let context = AuthzContext {
        audience: Audience::AdminApi,
    };
    for action in Action::ALL {
        assert_eq!(
            authorize(
                &principal(1, &[Role::Investigator]),
                action,
                &full_relation(1),
                &context
            ),
            Decision::Deny(DenyCode::Audience)
        );
    }
}

#[test]
fn evaluation_order_is_audience_tenant_explicit_deny_role_relation() {
    // Everything wrong at once; the earliest failing step names the denial.
    let mut subject = principal(1, &[Role::SysAdmin]);
    subject.suspended = true;
    let mut case = full_relation(2);
    case.coi_excluded = true;
    case.visible = false;
    case.member = false;
    case.lead = false;
    let admin = AuthzContext {
        audience: Audience::AdminApi,
    };
    assert_eq!(
        authorize(&subject, Action::ReadContent, &case, &admin),
        Decision::Deny(DenyCode::Audience)
    );
    assert_eq!(
        authorize(&subject, Action::ReadContent, &case, &desk()),
        Decision::Deny(DenyCode::Tenant)
    );
    case.tenant_id = 1;
    assert_eq!(
        authorize(&subject, Action::ReadContent, &case, &desk()),
        Decision::Deny(DenyCode::Suspended)
    );
    subject.suspended = false;
    assert_eq!(
        authorize(&subject, Action::ReadContent, &case, &desk()),
        Decision::Deny(DenyCode::NoRelation),
        "COI deny precedes the role check and is reported as NoRelation"
    );
    case.coi_excluded = false;
    assert_eq!(
        authorize(&subject, Action::ReadContent, &case, &desk()),
        Decision::Deny(DenyCode::Role)
    );
    subject.roles = BTreeSet::from([Role::Investigator]);
    assert_eq!(
        authorize(&subject, Action::ReadContent, &case, &desk()),
        Decision::Deny(DenyCode::NoRelation),
        "hidden case (triage-first) reads as no relation"
    );
    case.visible = true;
    assert_eq!(
        authorize(&subject, Action::ReadContent, &case, &desk()),
        Decision::Deny(DenyCode::NoRelation),
        "no ACL relation"
    );
    case.member = true;
    assert_eq!(
        authorize(&subject, Action::ReadContent, &case, &desk()),
        Decision::Permit(Vec::new())
    );
}

#[test]
fn st_069_coi_denies_even_the_lead_and_every_role_combination() {
    let mut case = full_relation(1);
    case.coi_excluded = true;
    for role in Role::ALL {
        for action in Action::ALL {
            assert_eq!(
                authorize(&principal(1, &[role]), action, &case, &desk()),
                Decision::Deny(DenyCode::NoRelation),
                "{role:?} {action:?}"
            );
        }
    }
}

#[test]
fn case_lead_grants_require_the_lead_relation_not_mere_membership() {
    let lead_role = principal(1, &[Role::CaseLead]);
    let mut as_member = full_relation(1);
    as_member.lead = false;
    for action in [
        Action::ReadContent,
        Action::Transition,
        Action::MemberAdd,
        Action::ExportOriginal,
    ] {
        assert_eq!(
            authorize(&lead_role, action, &as_member, &desk()),
            Decision::Deny(DenyCode::NoRelation),
            "{action:?}"
        );
    }
    let mut as_lead_only = full_relation(1);
    as_lead_only.member = false;
    assert!(
        authorize(&lead_role, Action::ReadContent, &as_lead_only, &desk()).is_permit(),
        "the lead relation counts as a relation"
    );
    assert!(
        authorize(
            &principal(1, &[Role::Investigator]),
            Action::ReadContent,
            &as_lead_only,
            &desk()
        )
        .is_permit(),
        "member-relation roles accept lead as the relation too"
    );
}

#[test]
fn obligations_are_the_union_over_held_roles() {
    let investigator_and_oversight = principal(1, &[Role::Investigator, Role::Oversight]);
    assert_eq!(
        authorize(
            &investigator_and_oversight,
            Action::ReadContent,
            &full_relation(1),
            &desk()
        ),
        Decision::Permit(vec![Obligation::AuditedAccess])
    );
    let reviewer_and_triager = principal(1, &[Role::Reviewer, Role::Triager]);
    assert_eq!(
        authorize(
            &reviewer_and_triager,
            Action::Transition,
            &full_relation(1),
            &desk()
        ),
        Decision::Permit(Vec::new())
    );
    assert_eq!(
        authorize(
            &reviewer_and_triager,
            Action::CloseApprove,
            &full_relation(1),
            &desk()
        ),
        Decision::Permit(vec![
            Obligation::RequireStepUp,
            Obligation::RequireSecondApprover,
        ])
    );
}

#[test]
fn no_roles_means_no_access() {
    for action in Action::ALL {
        assert_eq!(
            authorize(&principal(1, &[]), action, &full_relation(1), &desk()),
            Decision::Deny(DenyCode::Role)
        );
    }
}

fn candidate(key_id: u128, user_id: u128, current: bool, excluded: bool) -> WrapCandidate {
    WrapCandidate {
        key_id,
        user_id,
        current,
        excluded,
    }
}

fn candidates() -> BTreeSet<WrapCandidate> {
    BTreeSet::from([
        candidate(1, 10, true, false),
        candidate(2, 20, true, false),
        candidate(3, 30, true, true),
        candidate(4, 40, false, false),
        // Key 5 is listed under two users: refuse rather than pick one.
        candidate(5, 50, true, false),
        candidate(5, 51, true, false),
        // Key 6 has one clean row and one excluded row: the excluded row wins.
        candidate(6, 60, true, false),
        candidate(6, 60, true, true),
        // Two current keys for one user: they count as one recipient.
        candidate(7, 70, true, false),
        candidate(8, 70, true, false),
    ])
}

#[test]
fn be_018_wrap_validation_refuses_hostile_inputs() {
    let set = candidates();
    assert_eq!(validate_key_wraps(&[1, 2], &set, 2), Ok(()));
    assert_eq!(
        validate_key_wraps(&[1, 2], &set, 0),
        Err(WrapError::InvalidMinimum)
    );
    assert_eq!(
        validate_key_wraps(&[], &set, 1),
        Err(WrapError::TooFewRecipients)
    );
    assert_eq!(
        validate_key_wraps(&[1, 2], &set, 3),
        Err(WrapError::TooFewRecipients)
    );
    assert_eq!(
        validate_key_wraps(&[1, 1], &set, 2),
        Err(WrapError::DuplicateRecipient)
    );
    assert_eq!(
        validate_key_wraps(&[1, 5], &set, 2),
        Err(WrapError::AmbiguousCandidate)
    );
    assert_eq!(
        validate_key_wraps(&[1, 6], &set, 2),
        Err(WrapError::Excluded)
    );
    assert_eq!(
        validate_key_wraps(&[7, 8], &set, 2),
        Err(WrapError::TooFewRecipients),
        "two keys of one user are one recipient"
    );
    let too_many: Vec<u128> = (0..=MAX_WRAP_RECIPIENTS as u128).collect();
    assert_eq!(
        validate_key_wraps(&too_many, &set, 2),
        Err(WrapError::TooManyRecipients)
    );
    assert_eq!(
        validate_key_wraps(&[1, 2], &BTreeSet::new(), 2),
        Err(WrapError::NotCandidate)
    );
}

fn any_role() -> impl Strategy<Value = Role> {
    proptest::sample::select(Role::ALL.to_vec())
}

fn any_action() -> impl Strategy<Value = Action> {
    proptest::sample::select(Action::ALL.to_vec())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// IMPL-RM3 §3.5: deny unless an explicit grant exists; COI always wins; a permit
    /// implies tenant match, an active account, a visible case and an ACL relation.
    #[test]
    fn deny_unless_explicit_grant_and_coi_always_wins(
        roles in proptest::collection::btree_set(any_role(), 0..=3),
        action in any_action(),
        suspended in any::<bool>(),
        principal_tenant in 1_u128..=2,
        resource_tenant in 1_u128..=2,
        member in any::<bool>(),
        lead in any::<bool>(),
        coi_excluded in any::<bool>(),
        visible in any::<bool>(),
        admin_audience in any::<bool>(),
    ) {
        let subject = Principal {
            tenant_id: principal_tenant,
            user_id: 7,
            person_ref: 77,
            roles: roles.clone(),
            suspended,
        };
        let case = ResourceRef {
            tenant_id: resource_tenant,
            case_id: 55,
            member,
            lead,
            coi_excluded,
            visible,
        };
        let context = AuthzContext {
            audience: if admin_audience { Audience::AdminApi } else { Audience::DeskApi },
        };
        let decision = authorize(&subject, action, &case, &context);

        if admin_audience {
            prop_assert_eq!(decision, Decision::Deny(DenyCode::Audience));
        } else if principal_tenant != resource_tenant {
            prop_assert_eq!(decision, Decision::Deny(DenyCode::Tenant));
        } else if suspended {
            prop_assert_eq!(decision, Decision::Deny(DenyCode::Suspended));
        } else if coi_excluded {
            prop_assert_eq!(decision, Decision::Deny(DenyCode::NoRelation));
        } else if roles.iter().any(|role| role.is_admin()) {
            prop_assert_eq!(decision, Decision::Deny(DenyCode::Role));
        } else {
            match decision {
                Decision::Permit(obligations) => {
                    prop_assert!(visible && (member || lead));
                    prop_assert!(EXPECTED.iter().any(|row| row.1 == action && roles.contains(&row.0)));
                    if action == Action::ExportOriginal {
                        prop_assert!(obligations.contains(&Obligation::RequireStepUp));
                        prop_assert!(obligations.contains(&Obligation::RequireSecondApprover));
                    }
                }
                Decision::Deny(code) => {
                    prop_assert!(matches!(code, DenyCode::Role | DenyCode::NoRelation));
                    if code == DenyCode::Role {
                        prop_assert!(!EXPECTED.iter().any(|row| row.1 == action && roles.contains(&row.0)));
                    }
                }
            }
        }
    }

    /// BE-018: `Ok` exactly when every key is a current, non-excluded candidate, no key
    /// repeats, and the keys cover at least `min_recipients` distinct users.
    #[test]
    fn wraps_accepted_iff_subset_current_not_excluded_and_enough_users(
        keys in proptest::collection::vec(1_u128..10, 0..6),
        min_recipients in 1_usize..4,
    ) {
        let set = candidates();
        let mut distinct = BTreeSet::new();
        let mut seen = BTreeSet::new();
        let mut violation = false;
        for key in &keys {
            if !seen.insert(*key) {
                violation = true;
            }
            let rows: Vec<&WrapCandidate> = set.iter().filter(|row| row.key_id == *key).collect();
            let Some(first) = rows.first() else {
                violation = true;
                continue;
            };
            if rows.iter().any(|row| row.excluded || !row.current || row.user_id != first.user_id) {
                violation = true;
            }
            distinct.insert(first.user_id);
        }
        if distinct.len() < min_recipients {
            violation = true;
        }
        prop_assert_eq!(validate_key_wraps(&keys, &set, min_recipients).is_ok(), !violation);
    }
}
