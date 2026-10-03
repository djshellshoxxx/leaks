// SPDX-License-Identifier: AGPL-3.0-or-later
#![forbid(unsafe_code)]

use candor_authz::{CaseId, Principal, TenantId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaseError { NotFound, AuditUnavailable }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportOutcome { Imported(CaseId), Duplicate(CaseId) }

pub trait AuditCommit {
    fn commit_case_import(&mut self, tenant: TenantId, case: CaseId) -> Result<(), ()>;
}

#[derive(Debug, Default)]
pub struct CaseService;

impl CaseService {
    #[must_use]
    pub const fn new() -> Self { Self }

    pub fn import<A: AuditCommit>(&mut self, _tenant: TenantId, _digest: [u8; 32], _audit: &mut A) -> Result<ImportOutcome, CaseError> {
        Err(CaseError::NotFound)
    }

    pub fn open_case(&self, _principal: Principal, _case: CaseId) -> Result<CaseId, CaseError> {
        Err(CaseError::NotFound)
    }
}
