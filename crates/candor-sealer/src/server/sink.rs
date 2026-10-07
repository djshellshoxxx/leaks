// SPDX-License-Identifier: AGPL-3.0-or-later
//! Where sealed output goes: the Intake Store (C-08).
//!
//! `candor-intake-store` owns the `IntakeStore` trait (RM-2 addendum). The sealer
//! defines the minimal [`EnvelopeSink`] it needs, shaped after ADR-052(2): an
//! envelope commit carries **no account reference**, and account creation and
//! update are a separate operation ([`EnvelopeSink::upsert_account`]) that chaff
//! performs too, with dummy accounts. The production implementation is
//! [`crate::server::istore::IstoreSink`] over `istore.sock`.
//!
//! Everything handed to a sink is ciphertext or public: sealed objects, slot
//! blocks, the disposition marker, `lookup_tag`, `auth_pk`, `prefs_ct`
//! (AEAD under `K_prefs`), mailbox ids and re-wrapped reply stanzas. No plaintext,
//! no sub-day time value and no peer information is ever passed.

use candor_core::header::ObjectType;

pub use super::handover::StagedBundle;

/// Where an object's bytes are.
#[derive(Clone, PartialEq, Eq)]
pub enum Blob {
    /// In memory (SUBMISSION, IDENTITY, SOURCE_MESSAGE: ≤ 64 KiB).
    Inline(Vec<u8>),
    /// The sealed ATTACHMENT_BUNDLE as an immutable anonymous file (sealed
    /// `memfd`, deploy D-33 / AUD-RM2-SEA-16). A store-backed sink passes its
    /// descriptor to the store with [`crate::server::handover::StoreConnection::hand_over`]
    /// (`SCM_RIGHTS`, never a path) and returns `Ok` only after the store's
    /// commit acknowledgement. Dropping it frees it; nothing has to be deleted.
    Staged(StagedBundle),
}

impl core::fmt::Debug for Blob {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Blob(<redacted>)")
    }
}

/// One sealed object of an envelope.
#[derive(Clone, PartialEq, Eq)]
pub struct EnvelopeObject {
    /// Object type.
    pub object_type: ObjectType,
    /// `object_hash` (04 §13.1).
    pub object_hash: [u8; 32],
    /// Encoded Recipient Slot Block (18,692 B).
    pub slot_block: Vec<u8>,
    /// Blob.
    pub blob: Blob,
}

impl core::fmt::Debug for EnvelopeObject {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EnvelopeObject(<redacted>)")
    }
}

/// One intake envelope group (ADR-052(1)): always exactly three objects — the
/// main object (SUBMISSION or SOURCE_MESSAGE), an ATTACHMENT_BUNDLE and an
/// IDENTITY — for real and chaff envelopes alike, with dummies where the source
/// supplied nothing. The text-bearing objects are always padded to the maximum
/// bucket of their type.
#[derive(Clone, PartialEq, Eq)]
pub struct EnvelopeGroup {
    /// Channel.
    pub channel_id: [u8; 16],
    /// SUBMISSION or SOURCE_MESSAGE.
    pub main: EnvelopeObject,
    /// ATTACHMENT_BUNDLE (possibly an empty bundle).
    pub bundle: EnvelopeObject,
    /// IDENTITY (possibly a dummy).
    pub identity: EnvelopeObject,
    /// `disposition_ct` (fixed size Nenc + 48).
    pub disposition_ct: Vec<u8>,
}

impl EnvelopeGroup {
    /// The three objects in commit order (main, bundle, identity).
    #[must_use]
    pub fn objects(&self) -> [&EnvelopeObject; 3] {
        [&self.main, &self.bundle, &self.identity]
    }
}

impl core::fmt::Debug for EnvelopeGroup {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EnvelopeGroup(<redacted>)")
    }
}

/// A Tier W account (04 §11.4): only verifier-side, public or encrypted data.
/// `prefs_ct` has one fixed length for every account, real or dummy.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountRecord {
    /// `lookup_tag`.
    pub lookup_tag: [u8; 32],
    /// Ed25519 `auth_pk`.
    pub auth_pk: [u8; 32],
    /// X-Wing public key `src_pk` (09 §5.1 `xwing_pk`; 1,216 B).
    pub xwing_pk: Vec<u8>,
    /// `prefs_ct` (AEAD under `K_prefs`).
    pub prefs_ct: Vec<u8>,
    /// Mailbox ids for reply routing (Tier W lookup).
    pub mailbox_ids: Vec<[u8; 32]>,
}

impl core::fmt::Debug for AccountRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AccountRecord(<redacted>)")
    }
}

/// Create or replace a Tier W account (ADR-052(2); ADR-046(7) for rotation).
#[derive(Clone, PartialEq, Eq)]
pub struct AccountUpsert {
    /// `None`: create a new account. `Some(old)`: atomically replace the account
    /// with `lookup_tag == old` (passphrase rotation, 04 §11.7 step 4).
    pub replaces: Option<[u8; 32]>,
    /// The account values.
    pub account: AccountRecord,
    /// Rotation only: `(object_hash, new stanza(1))` per pending reply.
    pub rewrapped_replies: Vec<([u8; 32], Vec<u8>)>,
}

impl core::fmt::Debug for AccountUpsert {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AccountUpsert(<redacted>)")
    }
}

/// Why an account write failed (ADR-057(4)): a store refusal is final for
/// that operation and must never block the queue; `Stale` is a replacement
/// whose old account the store no longer has (e.g. after an intake restore
/// or a completed deletion) and is dropped at once; `Unavailable` is a
/// transport failure or deadline, retried at the next flush.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpsertError {
    /// The store refused the write (invalid, conflicting).
    Refused,
    /// A replacement of an account the store does not have.
    Stale,
    /// The store could not be reached or did not answer in time.
    Unavailable,
}

/// Outcome of a confirmed account deletion request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteOutcome {
    /// The store committed the deletion; `entries` K31-signed entries appended.
    Deleted {
        /// Deletion-list entries appended.
        entries: u32,
    },
    /// None of the tags resolved to an account.
    NotFound,
}

/// Sink failure. The sealer reports `INTERNAL` and treats nothing as committed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SinkError;

impl core::fmt::Display for SinkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("intake store commit failed")
    }
}

impl std::error::Error for SinkError {}

/// The Intake Store as seen by the sealer. Calls are blocking and run on a
/// blocking thread; they return only after the data is durable (`fsync`,
/// ADR-046(1)), so the source is told "received" only then.
///
/// Envelope groups are committed as they are sealed. Account writes are
/// **not** issued next to them: they are queued in RAM and written in shuffled
/// batches at fixed intervals, together with chaff dummy accounts and dummy
/// rotations (AUD-RM2-SEA-21), so insertion order or transaction adjacency in
/// the store cannot link an account to its initial envelope.
pub trait EnvelopeSink: Send + Sync {
    /// `COMMIT_ENVELOPE` for one envelope group (real or chaff; the store cannot
    /// and must not distinguish them). No account reference (ADR-052(2)).
    /// `received_day` is the UTC day number; `release_offset_days` ∈ 0..=3.
    fn commit_envelope_group(
        &self,
        group: EnvelopeGroup,
        epoch_id: u32,
        received_day: u32,
        release_offset_days: u8,
    ) -> Result<(), SinkError>;

    /// Create or replace an account (separate store operation, ADR-052(2)).
    /// A refusal must be reported as such ([`UpsertError::Refused`] /
    /// [`UpsertError::Stale`]), distinct from [`UpsertError::Unavailable`].
    fn upsert_account(&self, op: AccountUpsert) -> Result<(), UpsertError>;

    /// Whether the store is reachable right now (e.g. its connection is open,
    /// [`crate::server::handover::StoreConnection::is_open`]). Checked before a
    /// seal consumes the staged parts: when `false`, the seal fails with the
    /// uniform `INTERNAL` and the draft keeps its attachments. Default `true`.
    fn is_available(&self) -> bool {
        true
    }

    /// SW-14: ask the store to delete the listed replies of the account with
    /// `lookup_tag` and append K31-signed `reply` deletion-list entries
    /// (04 §18.6). Unknown refs are ignored (idempotent). Returns the number
    /// of entries appended. Default: unsupported (fail closed).
    fn delete_replies(&self, lookup_tag: [u8; 32], replies: &[[u8; 16]]) -> Result<u32, SinkError> {
        let _ = (lookup_tag, replies);
        Err(SinkError)
    }

    /// SW-15: ask the store to delete every account one of `lookup_tags`
    /// resolves to (the current tag and, after a just-flushed rotation, the
    /// previous one; ADR-057(3)), with its mailboxes (`mailbox_account`) and
    /// replies, appending `mailbox` and `account` entries in one transaction.
    /// `Ok(DeleteOutcome::NotFound)` when nothing resolved: the caller decides
    /// whether that is a completed earlier deletion. Default: unsupported
    /// (fail closed).
    fn delete_account(&self, lookup_tags: &[[u8; 32]]) -> Result<DeleteOutcome, SinkError> {
        let _ = lookup_tags;
        Err(SinkError)
    }
}
