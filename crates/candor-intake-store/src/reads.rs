// SPDX-License-Identifier: AGPL-3.0-or-later
//! The reads the web tier (C-06) makes on the Intake Store (07 §5.3 IPC to
//! web: `ACCOUNT_AUTH_*` and `MAILBOX_LIST`; 08 SW-10/SW-11), and nothing
//! else. Envelopes and accounts are written by the sealer (ADR-052(2));
//! deletions need the store-held K31 and go through the sealer's
//! `DELETE` request. Implemented for every [`IntakeStore`] (in-process, tests)
//! and by the `istore` client ([`crate::client::IstoreClient`], feature
//! `client`), so the web crate depends only on this trait.

use std::future::Future;

use crate::store::IntakeStore;
use crate::types::{AccountId, LookupTag, StoredReply};

/// One account as the web sees it at login: only verifier-side values.
pub struct AccountView {
    /// Intake-local account id (never shown, never logged).
    pub account_id: AccountId,
    /// Ed25519 auth public key.
    pub auth_pk: [u8; 32],
    /// `prefs_ct` (ciphertext for the sealer's `LOAD_PREFS`).
    pub prefs_ct: Vec<u8>,
}

impl core::fmt::Debug for AccountView {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AccountView(<redacted>)")
    }
}

/// Store failure (content-free). `RestorePending` and every backend or
/// transport error give the web's busy page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreUnavailable;

impl core::fmt::Display for StoreUnavailable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("intake store unavailable")
    }
}

impl std::error::Error for StoreUnavailable {}

/// Read-only store operations of the web tier.
pub trait StoreReads: Send + Sync {
    /// `false` while a restore awaits its deletion list (07 BE-074).
    fn serving_allowed(&self) -> impl Future<Output = Result<bool, StoreUnavailable>> + Send;
    /// Account by `lookup_tag` (no write, ADR-010).
    fn account(
        &self,
        tag: [u8; 32],
    ) -> impl Future<Output = Result<Option<AccountView>, StoreUnavailable>> + Send;
    /// The account's fixed mailbox (≤ 32 replies).
    fn mailbox(
        &self,
        account: AccountId,
    ) -> impl Future<Output = Result<Vec<StoredReply>, StoreUnavailable>> + Send;
}

impl<S: IntakeStore> StoreReads for S {
    async fn serving_allowed(&self) -> Result<bool, StoreUnavailable> {
        IntakeStore::serving_allowed(self)
            .await
            .map_err(|_| StoreUnavailable)
    }

    async fn account(&self, tag: [u8; 32]) -> Result<Option<AccountView>, StoreUnavailable> {
        let a = self
            .lookup_account(&LookupTag(tag))
            .await
            .map_err(|_| StoreUnavailable)?;
        Ok(a.map(|a| AccountView {
            account_id: a.account_id,
            auth_pk: a.auth_pk,
            prefs_ct: a.prefs_ct,
        }))
    }

    async fn mailbox(&self, account: AccountId) -> Result<Vec<StoredReply>, StoreUnavailable> {
        self.mailbox_list(account)
            .await
            .map_err(|_| StoreUnavailable)
    }
}
