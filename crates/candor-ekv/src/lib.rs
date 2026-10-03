// SPDX-License-Identifier: AGPL-3.0-or-later
#![forbid(unsafe_code)]

use core::fmt;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KeyHandle(u64);

impl fmt::Debug for KeyHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyHandle([opaque])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApproverId(pub u128);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultError {
    NotFound,
    Destroyed,
    DuplicateApprover,
    Exhausted,
}

#[derive(Debug)]
struct Entry {
    handle: KeyHandle,
    key: [u8; 32],
    approvals: [Option<ApproverId>; 2],
    destroyed: bool,
}

#[derive(Debug)]
pub struct ErasureVault {
    entries: Vec<Entry>,
    next_handle: u64,
}

impl Default for ErasureVault {
    fn default() -> Self {
        Self::new()
    }
}

impl ErasureVault {
    #[must_use]
    pub const fn new() -> Self {
        Self { entries: Vec::new(), next_handle: 1 }
    }

    pub fn create(&mut self, key: [u8; 32]) -> Result<KeyHandle, VaultError> {
        let handle = KeyHandle(self.next_handle);
        self.next_handle = self.next_handle.checked_add(1).ok_or(VaultError::Exhausted)?;
        self.entries.push(Entry { handle, key, approvals: [None, None], destroyed: false });
        Ok(handle)
    }

    pub fn key(&self, handle: KeyHandle) -> Result<[u8; 32], VaultError> {
        let entry = self.entries.iter().find(|entry| entry.handle == handle).ok_or(VaultError::NotFound)?;
        if entry.destroyed { return Err(VaultError::Destroyed); }
        Ok(entry.key)
    }

    /// Record a destruction approval. Returns true once destruction has completed.
    pub fn approve_destroy(&mut self, handle: KeyHandle, approver: ApproverId) -> Result<bool, VaultError> {
        let entry = self.entries.iter_mut().find(|entry| entry.handle == handle).ok_or(VaultError::NotFound)?;
        if entry.destroyed { return Ok(true); }
        if entry.approvals.iter().flatten().any(|existing| *existing == approver) {
            return Err(VaultError::DuplicateApprover);
        }
        if entry.approvals[0].is_none() {
            entry.approvals[0] = Some(approver);
            return Ok(false);
        }
        entry.approvals[1] = Some(approver);
        entry.key.fill(0);
        entry.destroyed = true;
        Ok(true)
    }
}
