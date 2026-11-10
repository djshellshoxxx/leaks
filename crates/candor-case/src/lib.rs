// SPDX-License-Identifier: AGPL-3.0-or-later
#![forbid(unsafe_code)]

use candor_authz::{
    Action, CaseId, CaseResource, Decision, Principal, TenantId, UserId, authorize,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaseError {
    NotFound,
    AuditUnavailable,
    IdentifierExhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportOutcome {
    Imported(CaseId),
    Duplicate(CaseId),
}

/// The audit service could not durably record the import (the import is then refused).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditCommitFailed;

pub trait AuditCommit {
    fn commit_case_import(
        &mut self,
        tenant: TenantId,
        case: CaseId,
    ) -> Result<(), AuditCommitFailed>;
}

/// Authoritative, current conflict-of-interest status. Implementations must read
/// the trusted blinded-tag/COI policy service; never build this from client input.
/// A failed check must not be interpreted as "not excluded".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoiUnavailable;

pub trait CoiLookup {
    fn is_excluded(
        &self,
        tenant: TenantId,
        case: CaseId,
        user: UserId,
    ) -> Result<bool, CoiUnavailable>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Record {
    tenant: TenantId,
    case: CaseId,
    digest: [u8; 32],
    assigned_to: Option<UserId>,
}

#[derive(Debug)]
pub struct CaseService {
    records: Vec<Record>,
    next_id: u128,
}

impl Default for CaseService {
    fn default() -> Self {
        Self::new()
    }
}

impl CaseService {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            records: Vec::new(),
            next_id: 1,
        }
    }

    pub fn import<A: AuditCommit>(
        &mut self,
        tenant: TenantId,
        digest: [u8; 32],
        audit: &mut A,
    ) -> Result<ImportOutcome, CaseError> {
        if let Some(existing) = self
            .records
            .iter()
            .find(|record| record.tenant == tenant && record.digest == digest)
        {
            return Ok(ImportOutcome::Duplicate(existing.case));
        }

        let case = CaseId(self.next_id);
        let next_id = self
            .next_id
            .checked_add(1)
            .ok_or(CaseError::IdentifierExhausted)?;

        audit
            .commit_case_import(tenant, case)
            .map_err(|AuditCommitFailed| CaseError::AuditUnavailable)?;

        self.records.push(Record {
            tenant,
            case,
            digest,
            assigned_to: None,
        });
        self.next_id = next_id;
        Ok(ImportOutcome::Imported(case))
    }

    /// Only an authorized triage actor may assign an investigator. The COI
    /// lookup is mandatory for both actor and recipient, and errors fail closed.
    pub fn assign<C: CoiLookup>(
        &mut self,
        principal: Principal,
        case: CaseId,
        user: UserId,
        coi: &C,
    ) -> Result<(), CaseError> {
        let record = self
            .records
            .iter_mut()
            .find(|record| record.tenant == principal.tenant && record.case == case)
            .ok_or(CaseError::NotFound)?;
        let resource = CaseResource {
            tenant: record.tenant,
            case: record.case,
            assigned_to: record.assigned_to,
            coi_user: None,
        };
        if authorize(principal, Action::AssignCase, resource, 0, None) != Decision::Allow {
            return Err(CaseError::NotFound);
        }
        // Never accept the absence of a COI result as permission to proceed.
        let actor_excluded = coi
            .is_excluded(principal.tenant, case, principal.user)
            .map_err(|_| CaseError::NotFound)?;
        let recipient_excluded = coi
            .is_excluded(principal.tenant, case, user)
            .map_err(|_| CaseError::NotFound)?;
        if actor_excluded || recipient_excluded {
            return Err(CaseError::NotFound);
        }
        record.assigned_to = Some(user);
        Ok(())
    }

    /// Read requires a fresh, authoritative COI decision even for assigned
    /// investigators. A missing decision and a missing case look identical.
    pub fn open_case<C: CoiLookup>(
        &self,
        principal: Principal,
        case: CaseId,
        coi: &C,
    ) -> Result<CaseId, CaseError> {
        let record = self
            .records
            .iter()
            .find(|record| record.tenant == principal.tenant && record.case == case)
            .ok_or(CaseError::NotFound)?;
        let excluded = coi
            .is_excluded(principal.tenant, case, principal.user)
            .map_err(|_| CaseError::NotFound)?;
        let resource = CaseResource {
            tenant: record.tenant,
            case: record.case,
            assigned_to: record.assigned_to,
            coi_user: if excluded { Some(principal.user) } else { None },
        };
        if authorize(principal, Action::ViewCase, resource, 0, None) != Decision::Allow {
            return Err(CaseError::NotFound);
        }
        Ok(record.case)
    }
}
