// SPDX-License-Identifier: AGPL-3.0-or-later
//! Where sealed output goes: the Intake Store (C-08).
//!
//! `candor-intake-store` owns the `IntakeStore` trait (RM-2 addendum). The sealer
//! defines the minimal [`EnvelopeSink`] it needs, shaped after ADR-052(2): an
//! envelope commit carries **no account reference**, and account creation and
//! update are a separate operation ([`EnvelopeSink::upsert_account`]) that chaff
//! performs too, with dummy accounts. Integration: implement `EnvelopeSink` over
//! the store client (see SPEC-NOTES "Fixes for AUD-RM2-SEA").
//!
//! Everything handed to a sink is ciphertext or public: sealed objects, slot
//! blocks, the disposition marker, `lookup_tag`, `auth_pk`, `prefs_ct`
//! (AEAD under `K_prefs`), mailbox ids and re-wrapped reply stanzas. No plaintext,
//! no sub-day time value and no peer information is ever passed.

use candor_core::header::ObjectType;
use candor_safefs::ObjectId;

/// Where an object's bytes are.
#[derive(Clone, PartialEq, Eq)]
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
/// Operation sequences are identical for real and chaff traffic:
/// * initial Tier W submission / initial-shaped chaff: `upsert_account`
///   (new; a dummy account for chaff), then `commit_envelope_group`;
/// * follow-up / follow-up-shaped chaff: `commit_envelope_group` only;
/// * passphrase rotation: `commit_envelope_group` (KEY_ROTATION), then
///   `upsert_account` (replace).
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
    fn upsert_account(&self, op: AccountUpsert) -> Result<(), SinkError>;
}
