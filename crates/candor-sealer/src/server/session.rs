// SPDX-License-Identifier: AGPL-3.0-or-later
//! RAM-only session state (04 §9.13, ADR-034, 07 §4.4 and §5.2 state machine).
//!
//! Every secret-bearing field zeroizes on drop (`SessionKey`, `Zeroizing`,
//! `SourceKeys`, `Passphrase`). Dropping a session also unlinks its staged
//! ciphertext files, whose content is unreadable once K36 is gone.

use crate::proto::{Coi, Mode, SecretText};
use candor_core::hash::{EvidenceHasher, EvidenceHashes};
use candor_core::passphrase::{Passphrase, SourceKeys};
use candor_core::secret::SessionKey;
use candor_safefs::{ObjectId, PendingObject, SafeRoot, SlotTime};
use zeroize::{Zeroize, Zeroizing};

use super::inner::Prefs;
use super::seal::StreamSink;

/// Session phase (07 §5.2 state machine).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    /// New-account drafting (SESSION_OPEN), including PENDING_CONFIRM.
    Drafting,
    /// LOGIN_DERIVE done; awaiting LOAD_PREFS.
    Derived,
    /// Logged in (inbox, follow-ups, rotation).
    Authenticated,
}

/// What a pending passphrase is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Purpose {
    NewAccount,
    Rotation,
}

/// A generated passphrase awaiting the 3-word confirmation (04 §11.1).
pub(crate) struct PendingPhrase {
    pub phrase: Passphrase,
    pub words: Zeroizing<Vec<u16>>,
    pub positions: [u8; 3],
    pub confirmed: bool,
    pub purpose: Purpose,
}

/// Draft (RAM only).
#[derive(Default)]
pub(crate) struct Draft {
    pub mode: Option<Mode>,
    pub message: SecretText,
    pub fields: Vec<(u16, SecretText)>,
    pub identity: Option<SecretText>,
    pub coi: Option<Coi>,
}

/// Evidence hashes of a staged part's plaintext, zeroized on drop.
pub(crate) struct PartHashes(pub EvidenceHashes);

impl Drop for PartHashes {
    fn drop(&mut self) {
        self.0.sha256.zeroize();
        self.0.blake3.zeroize();
    }
}

/// A staged, completed part: ciphertext on tmpfs under `K_stage`.
pub(crate) struct StagedPart {
    pub part_id: [u8; 16],
    pub object: ObjectId,
    pub padded_len: u64,
    pub real_len: u64,
    pub name: SecretText,
    pub media_type: SecretText,
    pub hashes: PartHashes,
    pub root: &'static SafeRoot,
    pub slot: SlotTime,
}

impl Drop for StagedPart {
    fn drop(&mut self) {
        // Best effort; tmpfs is emptied on restart anyway (07 §5.3).
        let _ = self.root.remove(&self.object, self.slot);
    }
}

/// A part being uploaded: padded to its bucket and STREAM-encrypted under
/// `K_stage = HKDF(K36, part_id, "candor/v1/stage/part")` as it arrives (§9.13).
pub(crate) struct Upload {
    pub part_id: [u8; 16],
    /// Staging id chosen up front, so a failed commit can be cleaned up.
    pub object_id: ObjectId,
    pub declared_len: u64,
    pub padded_len: u64,
    pub received: u64,
    pub sink: StreamSink<PendingObject<'static>>,
    pub hasher: EvidenceHasher,
    pub name: SecretText,
    pub media_type: SecretText,
}

/// One session.
pub(crate) struct Session {
    pub phase: Phase,
    /// K36: per-session part key (§9.13). Replaced after each successful submit.
    pub k36: SessionKey,
    pub channel_id: Option<[u8; 16]>,
    pub draft: Draft,
    pub parts: Vec<StagedPart>,
    pub upload: Option<Upload>,
    pub pending: Option<PendingPhrase>,
    pub phrase_generations: u8,
    pub confirm_failures: u8,
    /// Derived source keys (login, or after the first submission).
    pub keys: Option<SourceKeys>,
    pub prefs: Option<Prefs>,
    /// `(mailbox_id, reply_seq)` already rendered (replay detection).
    pub seen_replies: Vec<([u8; 32], u64)>,
    /// Attachment memory reservation (SEA-26), released with the draft.
    pub mem: Option<super::budget::Grant>,
    /// A failed seal consumed the staged parts; `SEAL_FINISH` is refused until
    /// the draft is shown again (`DRAFT_GET`), a part is started or the draft
    /// is aborted.
    pub parts_lost: bool,
}

impl Session {
    pub(crate) fn new(phase: Phase, k36: SessionKey) -> Self {
        Self {
            phase,
            k36,
            channel_id: None,
            draft: Draft::default(),
            parts: Vec::new(),
            upload: None,
            pending: None,
            phrase_generations: 0,
            confirm_failures: 0,
            keys: None,
            prefs: None,
            seen_replies: Vec::new(),
            mem: None,
            parts_lost: false,
        }
    }

    /// Drop the draft, staged parts, upload and K36 (SEAL_ABORT, successful
    /// submit). Login keys and prefs are kept.
    pub(crate) fn clear_draft(&mut self, fresh_k36: SessionKey) {
        self.clear_draft_contents();
        self.k36 = fresh_k36;
    }

    /// Drop the draft, staged parts and upload, keeping K36 (used only when the
    /// session is about to be removed because no fresh K36 could be drawn).
    pub(crate) fn clear_draft_contents(&mut self) {
        self.draft = Draft::default();
        self.parts.clear();
        self.upload = None;
        self.mem = None;
        self.parts_lost = false;
    }
}
