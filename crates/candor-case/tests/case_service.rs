// SPDX-License-Identifier: AGPL-3.0-or-later
use candor_authz::{CaseId, Principal, Role, TenantId, UserId};
use candor_case::{AuditCommit, AuditCommitFailed, CaseError, CaseService, ImportOutcome};

#[derive(Default)]
struct Audit {
    fail: bool,
    commits: usize,
}

impl AuditCommit for Audit {
    fn commit_case_import(
        &mut self,
        _tenant: TenantId,
        _case: CaseId,
    ) -> Result<(), AuditCommitFailed> {
        if self.fail {
            return Err(AuditCommitFailed);
        }
        self.commits = self.commits.saturating_add(1);
        Ok(())
    }
}

fn investigator(tenant: u128, user: u128) -> Principal {
    Principal {
        tenant: TenantId(tenant),
        user: UserId(user),
        role: Role::Investigator,
    }
}

fn imported(result: Result<ImportOutcome, CaseError>) -> Option<CaseId> {
    match result {
        Ok(ImportOutcome::Imported(case)) => Some(case),
        _ => None,
    }
}

#[test]
fn duplicate_relay_import_is_idempotent() {
    let mut svc = CaseService::new();
    let mut audit = Audit::default();
    let digest = [7; 32];
    let Some(case) = imported(svc.import(TenantId(1), digest, &mut audit)) else {
        panic!("first import must create");
    };
    assert_eq!(
        svc.import(TenantId(1), digest, &mut audit),
        Ok(ImportOutcome::Duplicate(case))
    );
    assert_eq!(audit.commits, 1);
}

#[test]
fn audit_failure_prevents_import_commit() {
    let mut svc = CaseService::new();
    let digest = [8; 32];
    let mut failing = Audit {
        fail: true,
        commits: 0,
    };
    assert_eq!(
        svc.import(TenantId(1), digest, &mut failing),
        Err(CaseError::AuditUnavailable)
    );
    let mut healthy = Audit::default();
    assert!(matches!(
        svc.import(TenantId(1), digest, &mut healthy),
        Ok(ImportOutcome::Imported(_))
    ));
}

#[test]
fn unauthorized_and_missing_case_probes_are_indistinguishable() {
    let mut svc = CaseService::new();
    let mut audit = Audit::default();
    let Some(case) = imported(svc.import(TenantId(1), [9; 32], &mut audit)) else {
        panic!("import must create");
    };
    assert_eq!(
        svc.open_case(investigator(2, 7), case),
        Err(CaseError::NotFound)
    );
    assert_eq!(
        svc.open_case(investigator(1, 7), CaseId(u128::MAX)),
        Err(CaseError::NotFound)
    );
}

#[test]
fn imported_case_is_not_readable_until_assigned() {
    let mut svc = CaseService::new();
    let mut audit = Audit::default();
    let Some(case) = imported(svc.import(TenantId(1), [10; 32], &mut audit)) else {
        panic!("import must create");
    };
    assert_eq!(
        svc.open_case(investigator(1, 7), case),
        Err(CaseError::NotFound)
    );
    assert_eq!(svc.assign(TenantId(1), case, UserId(7)), Ok(()));
    assert_eq!(svc.open_case(investigator(1, 7), case), Ok(case));
}
