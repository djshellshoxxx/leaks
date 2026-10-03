// SPDX-License-Identifier: AGPL-3.0-or-later
use candor_authz::{CaseId, Principal, Role, TenantId, UserId};
use candor_case::{AuditCommit, CaseError, CaseService, ImportOutcome};

#[derive(Default)]
struct Audit { fail: bool, commits: usize }
impl AuditCommit for Audit {
    fn commit_case_import(&mut self, _tenant: TenantId, _case: CaseId) -> Result<(), ()> {
        if self.fail { return Err(()); }
        self.commits += 1;
        Ok(())
    }
}

fn investigator(tenant: u128, user: u128) -> Principal {
    Principal { tenant: TenantId(tenant), user: UserId(user), role: Role::Investigator }
}

#[test]
fn duplicate_relay_import_is_idempotent() {
    let mut svc = CaseService::new();
    let mut audit = Audit::default();
    let digest = [7; 32];
    let first = svc.import(TenantId(1), digest, &mut audit).unwrap();
    let second = svc.import(TenantId(1), digest, &mut audit).unwrap();
    let case = match first { ImportOutcome::Imported(case) => case, _ => panic!("first import must create") };
    assert_eq!(second, ImportOutcome::Duplicate(case));
    assert_eq!(audit.commits, 1);
}

#[test]
fn audit_failure_prevents_import_commit() {
    let mut svc = CaseService::new();
    let digest = [8; 32];
    let mut failing = Audit { fail: true, commits: 0 };
    assert_eq!(svc.import(TenantId(1), digest, &mut failing), Err(CaseError::AuditUnavailable));
    let mut healthy = Audit::default();
    assert!(matches!(svc.import(TenantId(1), digest, &mut healthy), Ok(ImportOutcome::Imported(_))));
}

#[test]
fn unauthorized_and_missing_case_probes_are_indistinguishable() {
    let mut svc = CaseService::new();
    let mut audit = Audit::default();
    let case = match svc.import(TenantId(1), [9; 32], &mut audit).unwrap() {
        ImportOutcome::Imported(case) => case,
        _ => unreachable!(),
    };
    assert_eq!(svc.open_case(investigator(2, 7), case), Err(CaseError::NotFound));
    assert_eq!(svc.open_case(investigator(1, 7), CaseId(u128::MAX)), Err(CaseError::NotFound));
}

#[test]
fn imported_case_is_not_readable_until_assigned() {
    let mut svc = CaseService::new();
    let mut audit = Audit::default();
    let case = match svc.import(TenantId(1), [10; 32], &mut audit).unwrap() {
        ImportOutcome::Imported(case) => case,
        _ => unreachable!(),
    };
    assert_eq!(svc.open_case(investigator(1, 7), case), Err(CaseError::NotFound));
    svc.assign(TenantId(1), case, UserId(7)).unwrap();
    assert_eq!(svc.open_case(investigator(1, 7), case), Ok(case));
}
