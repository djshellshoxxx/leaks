// SPDX-License-Identifier: AGPL-3.0-or-later
#![forbid(unsafe_code)]

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use core::fmt;
use zeroize::Zeroize;

const NONCE_LEN: usize = 24;

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
    Missing,
    NotMissing,
    DuplicateApprover,
    AlreadyExists,
    WrongCase,
    Authentication,
    Random,
    Crypto,
    Exhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WrapContext {
    pub tenant_id: u128,
    pub case_id: u128,
    pub key_epoch: u64,
    pub recipient_key_id: u128,
}

impl WrapContext {
    fn aad(self) -> [u8; 56] {
        let mut aad = [0_u8; 56];
        aad[..16].copy_from_slice(&self.tenant_id.to_be_bytes());
        aad[16..32].copy_from_slice(&self.case_id.to_be_bytes());
        aad[32..40].copy_from_slice(&self.key_epoch.to_be_bytes());
        aad[40..56].copy_from_slice(&self.recipient_key_id.to_be_bytes());
        aad
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeyState {
    Active,
    Missing,
    Destroyed,
}

struct Entry {
    handle: KeyHandle,
    tenant_id: u128,
    case_id: u128,
    key: [u8; 32],
    approvals: [Option<ApproverId>; 2],
    state: KeyState,
}

pub struct ErasureVault {
    entries: Vec<Entry>,
    next_handle: u64,
}

impl fmt::Debug for ErasureVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ErasureVault")
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl Default for ErasureVault {
    fn default() -> Self {
        Self::new()
    }
}

impl ErasureVault {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            next_handle: 1,
        }
    }

    /// Create one fresh Erasure Key for a tenant/case pair. Key bytes are generated inside the
    /// vault and are never returned to the caller.
    pub fn create_case(&mut self, tenant_id: u128, case_id: u128) -> Result<KeyHandle, VaultError> {
        if self
            .entries
            .iter()
            .any(|entry| entry.tenant_id == tenant_id && entry.case_id == case_id)
        {
            return Err(VaultError::AlreadyExists);
        }

        let handle = KeyHandle(self.next_handle);
        self.next_handle = self
            .next_handle
            .checked_add(1)
            .ok_or(VaultError::Exhausted)?;
        let mut key = [0_u8; 32];
        getrandom::fill(&mut key).map_err(|_| VaultError::Random)?;
        self.entries.push(Entry {
            handle,
            tenant_id,
            case_id,
            key,
            approvals: [None, None],
            state: KeyState::Active,
        });
        Ok(handle)
    }

    /// Seal an inner case-key wrap under the case Erasure Key using XChaCha20-Poly1305.
    pub fn seal(
        &self,
        handle: KeyHandle,
        context: WrapContext,
        inner: &[u8],
    ) -> Result<Vec<u8>, VaultError> {
        let entry = self.entry(handle)?;
        self.check_context(entry, context)?;
        self.check_active(entry)?;

        let mut nonce = [0_u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|_| VaultError::Random)?;
        let cipher = <XChaCha20Poly1305 as KeyInit>::new_from_slice(&entry.key)
            .map_err(|_| VaultError::Crypto)?;
        let aad = context.aad();
        let ciphertext = cipher
            .encrypt(
                &nonce.into(),
                Payload {
                    msg: inner,
                    aad: &aad,
                },
            )
            .map_err(|_| VaultError::Crypto)?;

        let mut outer = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        outer.extend_from_slice(&nonce);
        outer.extend_from_slice(&ciphertext);
        Ok(outer)
    }

    /// Open an outer wrap. Authentication binds tenant, case, epoch and recipient key id.
    pub fn unseal(
        &self,
        handle: KeyHandle,
        context: WrapContext,
        outer: &[u8],
    ) -> Result<Vec<u8>, VaultError> {
        let entry = self.entry(handle)?;
        self.check_context(entry, context)?;
        self.check_active(entry)?;
        if outer.len() < NONCE_LEN {
            return Err(VaultError::Authentication);
        }
        let (nonce_bytes, ciphertext) = outer.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce_bytes
            .try_into()
            .map_err(|_| VaultError::Authentication)?;
        let cipher = <XChaCha20Poly1305 as KeyInit>::new_from_slice(&entry.key)
            .map_err(|_| VaultError::Crypto)?;
        let aad = context.aad();
        cipher
            .decrypt(
                &nonce.into(),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| VaultError::Authentication)
    }

    /// Mark an EK absent while reconciling a restored vault backup. Existing ciphertext remains
    /// present but cannot be opened until holders create new wraps after `rekey_missing`.
    pub fn mark_missing_for_restore(&mut self, handle: KeyHandle) -> Result<(), VaultError> {
        let entry = self.entry_mut(handle)?;
        match entry.state {
            KeyState::Active => {
                entry.key.zeroize();
                entry.state = KeyState::Missing;
                Ok(())
            }
            KeyState::Missing => Ok(()),
            KeyState::Destroyed => Err(VaultError::Destroyed),
        }
    }

    /// Generate a fresh EK for a restored case whose prior EK is missing. This never recreates
    /// the previous key, so old outer wraps remain cryptographically erased.
    pub fn rekey_missing(&mut self, handle: KeyHandle) -> Result<(), VaultError> {
        let entry = self.entry_mut(handle)?;
        match entry.state {
            KeyState::Missing => {
                getrandom::fill(&mut entry.key).map_err(|_| VaultError::Random)?;
                entry.approvals = [None, None];
                entry.state = KeyState::Active;
                Ok(())
            }
            KeyState::Destroyed => Err(VaultError::Destroyed),
            KeyState::Active => Err(VaultError::NotMissing),
        }
    }

    /// Record a destruction approval. Returns true once destruction has completed.
    pub fn approve_destroy(
        &mut self,
        handle: KeyHandle,
        approver: ApproverId,
    ) -> Result<bool, VaultError> {
        let entry = self.entry_mut(handle)?;
        if entry.state == KeyState::Destroyed {
            return Ok(true);
        }
        if entry
            .approvals
            .iter()
            .flatten()
            .any(|existing| *existing == approver)
        {
            return Err(VaultError::DuplicateApprover);
        }
        if entry.approvals[0].is_none() {
            entry.approvals[0] = Some(approver);
            return Ok(false);
        }
        entry.approvals[1] = Some(approver);
        entry.key.zeroize();
        entry.state = KeyState::Destroyed;
        Ok(true)
    }

    fn entry(&self, handle: KeyHandle) -> Result<&Entry, VaultError> {
        self.entries
            .iter()
            .find(|entry| entry.handle == handle)
            .ok_or(VaultError::NotFound)
    }

    fn entry_mut(&mut self, handle: KeyHandle) -> Result<&mut Entry, VaultError> {
        self.entries
            .iter_mut()
            .find(|entry| entry.handle == handle)
            .ok_or(VaultError::NotFound)
    }

    fn check_context(&self, entry: &Entry, context: WrapContext) -> Result<(), VaultError> {
        if entry.tenant_id != context.tenant_id || entry.case_id != context.case_id {
            return Err(VaultError::WrongCase);
        }
        Ok(())
    }

    fn check_active(&self, entry: &Entry) -> Result<(), VaultError> {
        match entry.state {
            KeyState::Active => Ok(()),
            KeyState::Missing => Err(VaultError::Missing),
            KeyState::Destroyed => Err(VaultError::Destroyed),
        }
    }
}

impl Drop for ErasureVault {
    fn drop(&mut self) {
        for entry in &mut self.entries {
            entry.key.zeroize();
        }
    }
}
