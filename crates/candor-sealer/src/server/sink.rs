// SPDX-License-Identifier: AGPL-3.0-or-later
//! Where sealed output goes: the Intake Store (C-08).
//!
//! `candor-intake-store` owns the `IntakeStore` trait (RM-2 addendum) but it was
//! not available when this crate was written, so the sealer defines the minimal
//! [`EnvelopeSink`] it needs. Integration: implement `EnvelopeSink` for the
//! store's client (or replace it with the store's trait) — see SPEC-NOTES.
//!
//! Everything handed to a sink is ciphertext or public: sealed objects, slot
//! blocks, the disposition marker, `lookup_tag`, `auth_pk`, `prefs_ct`
//! (AEAD under `K_prefs`), mailbox ids and re-wrapped reply stanzas. No plaintext,
//! no time value and no peer information is ever passed.

use candor_core::header::ObjectType;
use candor_safefs::ObjectId;

/// Where an object's bytes are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Blob {
    /// In memory (SUBMISSION, IDENTITY, SOURCE_MESSAGE: ≤ 64 KiB).
    Inline(Vec<u8>),
    /// A ciphertext file in the tmpfs staging root (ATTACHMENT_BUNDLE). On `Ok`
    /// the sink owns it (moves or deletes it); on `Err` the sealer deletes it.
    Staged {
        /// Staging object id.
        id: ObjectId,
        /// Exact length.
        len: u64,
    },
}

/// One sealed object of an envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// A new Tier W account (04 §11.4): only verifier-side, public or encrypted data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountRecord {
    /// `lookup_tag`.
    pub lookup_tag: [u8; 32],
    /// Ed25519 `auth_pk`.
    pub auth_pk: [u8; 32],
    /// `prefs_ct` (AEAD under `K_prefs`).
    pub prefs_ct: Vec<u8>,
    /// Mailbox ids for reply routing (Tier W lookup).
    pub mailbox_ids: Vec<[u8; 32]>,
}

/// `COMMIT_ENVELOPE` (07 §5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitRequest {
    /// Channel.
    pub channel_id: [u8; 16],
    /// Objects; the first one is the SUBMISSION or SOURCE_MESSAGE.
    pub objects: Vec<EnvelopeObject>,
    /// `disposition_ct` (fixed size Nenc + 48).
    pub disposition_ct: Vec<u8>,
    /// Delayed-delivery offset in days (0 = none, else 1..=3).
    pub release_offset_days: u8,
    /// New account to create in the same transaction (initial Tier W submission).
    pub account: Option<AccountRecord>,
}

/// `ACCOUNT_ROTATE` (ADR-046(7), 04 §11.7 step 4): atomically replace the
/// account's verifier and prefs, replace the re-wrapped reply stanzas and commit
/// the key-update envelopes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationRequest {
    /// Current `lookup_tag`.
    pub old_lookup_tag: [u8; 32],
    /// New account values (same mailbox ids).
    pub account: AccountRecord,
    /// `(object_hash, new stanza(1))` per pending reply.
    pub rewrapped_replies: Vec<([u8; 32], Vec<u8>)>,
    /// KEY_ROTATION SOURCE_MESSAGE envelopes (one per report).
    pub envelopes: Vec<CommitRequest>,
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
pub trait EnvelopeSink: Send + Sync {
    /// Commit one envelope (real or chaff; the store cannot and must not
    /// distinguish them).
    fn commit(&self, req: CommitRequest) -> Result<(), SinkError>;
    /// Rotate an account's passphrase-derived values atomically.
    fn rotate_account(&self, req: RotationRequest) -> Result<(), SinkError>;
}
