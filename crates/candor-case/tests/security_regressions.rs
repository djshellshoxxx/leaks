// SPDX-License-Identifier: AGPL-3.0-or-later
//! Authorization regressions: neither assignments nor case reads may bypass COI.
use candor_authz::{CaseId, Principal, Role, TenantId, UserId};
use candor_case::{
    AuditCommit, AuditCommitFailed, CaseError, CaseService, CoiLookup, CoiUnavailable,
    ImportOutcome,
};

#[derive(Default)]
struct Audit;
impl AuditCommit for Audit {
    fn commit_case_import(
        &mut self,
        _tenant: TenantId,
        _case: CaseId,
    ) -> Result<(), AuditCommitFailed> {
        Ok(())
    }
}

#[derive(Default)]
struct Coi {
    excluded: Vec<(TenantId, CaseId, UserId)>,
    unavailable: bool,
}

impl CoiLookup for Coi {
    fn is_excluded(
        &self,
        tenant: TenantId,
        case: CaseId,
        user: UserId,
    ) -> Result<bool, CoiUnavailable> {
        if self.unavailable {
            return Err(CoiUnavailable);
        }
        Ok(self.excluded.contains(&(tenant, case, user)))
    }
}

fn principal(tenant: u128, user: u128, role: Role) -> Principal {
    Principal {
        tenant: TenantId(tenant),
        user: UserId(user),
        role,
    }
}

fn imported(svc: &mut CaseService) -> CaseId {
    let Ok(ImportOutcome::Imported(case)) = svc.import(TenantId(1), [21; 32], &mut Audit) else {
        panic!("the relay import must create a case");
    };
    case
}

#[test]
fn investigator_cannot_assign_self_without_triage_authority() {
    let mut svc = CaseService::new();
    let case = imported(&mut svc);
    let coi = Coi::default();
    assert_eq!(
        svc.assign(principal(1, 7, Role::Investigator), case, UserId(7), &coi),
        Err(CaseError::NotFound)
    );
    assert_eq!(
        svc.open_case(principal(1, 7, Role::Investigator), case, &coi),
        Err(CaseError::NotFound)
    );
}

#[test]
fn triage_may_assign_a_non_excluded_recipient() {
    let mut svc = CaseService::new();
    let case = imported(&mut svc);
    let coi = Coi::default();
    assert_eq!(
        svc.assign(principal(1, 9, Role::Triage), case, UserId(7), &coi),
        Ok(())
    );
    assert_eq!(
        svc.open_case(principal(1, 7, Role::Investigator), case, &coi),
        Ok(case)
    );
}

#[test]
fn excluded_recipient_cannot_be_assigned_or_open_a_previously_assigned_case() {
    let mut svc = CaseService::new();
    let case = imported(&mut svc);
    let mut coi = Coi::default();
    let triage = principal(1, 9, Role::Triage);
    assert_eq!(svc.assign(triage, case, UserId(7), &coi), Ok(()));
    coi.excluded.push((TenantId(1), case, UserId(7)));
    assert_eq!(
        svc.open_case(principal(1, 7, Role::Investigator), case, &coi),
        Err(CaseError::NotFound)
    );
    assert_eq!(
        svc.assign(triage, case, UserId(7), &coi),
        Err(CaseError::NotFound)
    );
}

#[test]
fn excluded_triage_actor_cannot_assign_others() {
    let mut svc = CaseService::new();
    let case = imported(&mut svc);
    let coi = Coi {
        excluded: vec![(TenantId(1), case, UserId(9))],
        unavailable: false,
    };
    assert_eq!(
        svc.assign(principal(1, 9, Role::Triage), case, UserId(7), &coi),
        Err(CaseError::NotFound)
    );
    assert_eq!(
        svc.open_case(principal(1, 7, Role::Investigator), case, &Coi::default()),
        Err(CaseError::NotFound)
    );
}

#[test]
fn inability_to_check_conflicts_fails_closed_and_preserves_assignment() {
    let mut svc = CaseService::new();
    let case = imported(&mut svc);
    let triage = principal(1, 9, Role::Triage);
    assert_eq!(svc.assign(triage, case, UserId(7), &Coi::default()), Ok(()));
    let failed = Coi {
        excluded: vec![],
        unavailable: true,
    };
    assert_eq!(
        svc.open_case(principal(1, 7, Role::Investigator), case, &failed),
        Err(CaseError::NotFound)
    );
    assert_eq!(
        svc.assign(triage, case, UserId(8), &failed),
        Err(CaseError::NotFound)
    );
    assert_eq!(
        svc.open_case(principal(1, 7, Role::Investigator), case, &Coi::default()),
        Ok(case)
    );
}

#[test]
fn cross_tenant_triage_cannot_assign() {
    let mut svc = CaseService::new();
    let case = imported(&mut svc);
    assert_eq!(
        svc.assign(
            principal(2, 9, Role::Triage),
            case,
            UserId(7),
            &Coi::default()
        ),
        Err(CaseError::NotFound)
    );
}
