// SPDX-License-Identifier: AGPL-3.0-or-later
//! Signed, hash-chained intake deletion list (ADR-047(9); 04 §18.6; 09 §5.1
//! `deletion_list`; 07 BE-074; KEY-077).
//!
//! Encodings fixed here (spec leaves them open; see SPEC-NOTES "Implementation
//! decisions"):
//! - `del_hash = SHA-256("candor/v1/intake/del" ‖ tenant_id(16) ‖ subject(32))`
//!   where subject is the `lookup_tag`, `mailbox_id` or REPLY `object_hash`;
//! - `entry = u64be seq ‖ u8 kind ‖ del_hash(32) ‖ u32be del_day` (45 bytes);
//! - `sig = Ed25519_K31("candor/v1/intake/deletion-list" ‖ prev_hash ‖ entry)`;
//! - `prev_hash(1) = 0^32`, `prev_hash(n+1) = SHA-256("candor/v1/intake/deletion-list"
//!   ‖ prev_hash(n) ‖ entry(n) ‖ sig(n))`.

use core::fmt;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::{Result, StoreError};
use crate::types::{Day, LookupTag, MailboxId, TenantId};

/// Domain label of `del_hash` (04 §18.6).
pub const DEL_HASH_LABEL: &[u8] = b"candor/v1/intake/del";
/// Signature context (registered in candor-core as `INTAKE_DELETION_LIST`).
pub const SIG_CONTEXT: &[u8] = b"candor/v1/intake/deletion-list";
/// Encoded entry length.
pub const ENTRY_LEN: usize = 8 + 1 + 32 + 4;

/// Entry kind.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum DeletionKind {
    /// Account deleted (subject = lookup_tag).
    Account,
    /// Mailbox deleted (subject = mailbox_id).
    Mailbox,
    /// Reply deleted (subject = REPLY object_hash).
    Reply,
}

impl DeletionKind {
    pub(crate) fn code(self) -> u8 {
        match self {
            Self::Account => 1,
            Self::Mailbox => 2,
            Self::Reply => 3,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Account => "account",
            Self::Mailbox => "mailbox",
            Self::Reply => "reply",
        }
    }

    pub(crate) fn parse(s: &str) -> Result<Self> {
        match s {
            "account" => Ok(Self::Account),
            "mailbox" => Ok(Self::Mailbox),
            "reply" => Ok(Self::Reply),
            _ => Err(StoreError::Integrity("unknown deletion kind")),
        }
    }
}

/// One deletion-list entry (also the RL-11/RL-12 wire entry, plus `relayed`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DeletionEntry {
    /// Monotonic, gap-free sequence number starting at 1.
    pub seq: u64,
    /// Kind.
    pub kind: DeletionKind,
    /// Hashed subject.
    pub del_hash: [u8; 32],
    /// Day of the deletion.
    pub del_day: Day,
    /// Chain link.
    pub prev_hash: [u8; 32],
    /// K31 signature.
    pub sig: [u8; 64],
    /// Set once the relay has copied the entry to Z-CORE.
    pub relayed: bool,
}

impl fmt::Debug for DeletionEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeletionEntry")
            .field("seq", &self.seq)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl DeletionEntry {
    /// Canonical 45-byte entry encoding (signed and chained).
    #[must_use]
    pub fn encode(&self) -> [u8; ENTRY_LEN] {
        encode_entry(self.seq, self.kind, &self.del_hash, self.del_day)
    }

    /// Chain hash that the next entry must carry as `prev_hash`.
    #[must_use]
    pub fn next_prev_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(SIG_CONTEXT);
        h.update(self.prev_hash);
        h.update(self.encode());
        h.update(self.sig);
        h.finalize().into()
    }

    /// Whether two entries are the same signed entry (ignores `relayed`).
    #[must_use]
    pub fn same_signed(&self, other: &Self) -> bool {
        self.encode().ct_eq(&other.encode()).into()
            && bool::from(self.prev_hash.ct_eq(&other.prev_hash))
            && bool::from(self.sig.ct_eq(&other.sig))
    }
}

fn encode_entry(seq: u64, kind: DeletionKind, del_hash: &[u8; 32], day: Day) -> [u8; ENTRY_LEN] {
    let mut out = [0u8; ENTRY_LEN];
    let (a, rest) = out.split_at_mut(8);
    a.copy_from_slice(&seq.to_be_bytes());
    let (b, rest) = rest.split_at_mut(1);
    b.copy_from_slice(&[kind.code()]);
    let (c, d) = rest.split_at_mut(32);
    c.copy_from_slice(del_hash);
    d.copy_from_slice(&day.0.to_be_bytes());
    out
}

fn sig_message(prev_hash: &[u8; 32], entry: &[u8; ENTRY_LEN]) -> Vec<u8> {
    let mut m = Vec::with_capacity(SIG_CONTEXT.len().saturating_add(32 + ENTRY_LEN));
    m.extend_from_slice(SIG_CONTEXT);
    m.extend_from_slice(prev_hash);
    m.extend_from_slice(entry);
    m
}

/// `del_hash` over a 32-byte subject.
#[must_use]
pub fn del_hash(tenant: &TenantId, subject: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DEL_HASH_LABEL);
    h.update(tenant.0);
    h.update(subject);
    h.finalize().into()
}

/// `del_hash` of an account.
#[must_use]
pub fn account_del_hash(tenant: &TenantId, tag: &LookupTag) -> [u8; 32] {
    del_hash(tenant, &tag.0)
}

/// `del_hash` of a mailbox.
#[must_use]
pub fn mailbox_del_hash(tenant: &TenantId, mailbox: &MailboxId) -> [u8; 32] {
    del_hash(tenant, &mailbox.0)
}

/// `del_hash` of a reply.
#[must_use]
pub fn reply_del_hash(tenant: &TenantId, object_hash: &[u8; 32]) -> [u8; 32] {
    del_hash(tenant, object_hash)
}

/// The K31 signer, invoked inside the deletion transaction (the chain head is only
/// known there). Implementations must not log or retain the message.
pub trait DeletionSigner: Send + Sync {
    /// Sign `msg` with Ed25519.
    fn sign(&self, msg: &[u8]) -> Result<[u8; 64]>;
}

/// K31 signer over a candor-core Ed25519 key (zeroized on drop, redacted Debug).
#[derive(Debug)]
pub struct Ed25519DeletionSigner(candor_core::sig::SigningKey);

impl Ed25519DeletionSigner {
    /// Wrap a key.
    #[must_use]
    pub fn new(key: candor_core::sig::SigningKey) -> Self {
        Self(key)
    }

    /// Public key.
    #[must_use]
    pub fn verifying_key(&self) -> [u8; 32] {
        self.0.verifying_key_bytes()
    }
}

impl DeletionSigner for Ed25519DeletionSigner {
    fn sign(&self, msg: &[u8]) -> Result<[u8; 64]> {
        Ok(self.0.sign(msg))
    }
}

/// Build and sign the next entry after `head` (the current last entry, if any).
/// When the list was pruned, `head` is still the last remaining or last pruned
/// entry: callers keep at least the newest entry (prune never removes it).
pub fn make_entry(
    head: Option<&DeletionEntry>,
    kind: DeletionKind,
    del_hash: [u8; 32],
    del_day: Day,
    signer: &dyn DeletionSigner,
) -> Result<DeletionEntry> {
    let (seq, prev_hash) = match head {
        None => (1u64, [0u8; 32]),
        Some(h) => (
            h.seq
                .checked_add(1)
                .ok_or(StoreError::Integrity("deletion seq overflow"))?,
            h.next_prev_hash(),
        ),
    };
    let entry = encode_entry(seq, kind, &del_hash, del_day);
    let sig = signer.sign(&sig_message(&prev_hash, &entry))?;
    Ok(DeletionEntry { seq, kind, del_hash, del_day, prev_hash, sig, relayed: false })
}

/// Verify a contiguous run of entries: consecutive `seq`, chain links and strict
/// Ed25519 signatures under `k31_pk`. If `anchor` is given, it is the entry that
/// immediately precedes `entries[0]` (its successor link must match). A run that
/// starts at `seq = 1` must carry the all-zero genesis `prev_hash`.
pub fn verify_chain(
    entries: &[DeletionEntry],
    k31_pk: &[u8; 32],
    anchor: Option<&DeletionEntry>,
) -> Result<()> {
    let mut prev: Option<DeletionEntry> = anchor.copied();
    for e in entries {
        if e.seq == 0 {
            return Err(StoreError::DeletionList("seq zero"));
        }
        match &prev {
            Some(p) => {
                if p.seq.checked_add(1) != Some(e.seq) {
                    return Err(StoreError::DeletionList("sequence gap"));
                }
                if !bool::from(p.next_prev_hash().ct_eq(&e.prev_hash)) {
                    return Err(StoreError::DeletionList("broken hash chain"));
                }
            }
            None => {
                if e.seq == 1 && e.prev_hash != [0u8; 32] {
                    return Err(StoreError::DeletionList("bad genesis link"));
                }
            }
        }
        let msg = sig_message(&e.prev_hash, &e.encode());
        candor_core::sig::verify_strict(k31_pk, &msg, &e.sig)
            .map_err(|_| StoreError::DeletionList("bad signature"))?;
        prev = Some(*e);
    }
    Ok(())
}

/// Computes the REPLY `object_hash` from a stored `reply_ct`, used when a restore
/// applies `reply` entries to replies already on disk (no hash column exists in
/// 09 §5.1).
pub trait ReplyObjectHasher: Send + Sync {
    /// `None` when the ciphertext cannot be parsed (such a reply is kept; it can
    /// never match a listed hash).
    fn object_hash(&self, reply_ct: &[u8]) -> Option<[u8; 32]>;
}

/// Default hasher: `reply_ct` starts with the REPLY SealedObject, whose first
/// 160 bytes are `CoreHeader(128) ‖ header_mac(32)` (04 §13.1); `object_hash =
/// SHA-256(CoreHeader ‖ header_mac)` via candor-core.
#[derive(Debug, Clone, Copy, Default)]
pub struct CoreReplyHasher;

impl ReplyObjectHasher for CoreReplyHasher {
    fn object_hash(&self, reply_ct: &[u8]) -> Option<[u8; 32]> {
        use candor_core::header::{CoreHeader, HEADER_LEN, HEADER_MAC_LEN, object_hash};
        let hdr: &[u8; HEADER_LEN] = reply_ct.get(..HEADER_LEN)?.try_into().ok()?;
        let end = HEADER_LEN.checked_add(HEADER_MAC_LEN)?;
        let mac: &[u8; HEADER_MAC_LEN] = reply_ct.get(HEADER_LEN..end)?.try_into().ok()?;
        CoreHeader::decode(hdr).ok()?;
        Some(object_hash(hdr, mac))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    fn signer() -> Ed25519DeletionSigner {
        Ed25519DeletionSigner::new(candor_core::sig::SigningKey::from_seed(&[7u8; 32]))
    }

    fn chain(n: usize) -> Vec<DeletionEntry> {
        let s = signer();
        let mut v: Vec<DeletionEntry> = Vec::new();
        for i in 0..n {
            let e = make_entry(v.last(), DeletionKind::Reply, [i as u8; 32], Day(100), &s).unwrap();
            v.push(e);
        }
        v
    }

    /// KEY-077: valid chain verifies; tampering, gaps, forged signatures fail.
    #[test]
    fn chain_verifies_and_rejects_tampering() {
        let s = signer();
        let pk = s.verifying_key();
        let v = chain(5);
        verify_chain(&v, &pk, None).unwrap();
        verify_chain(&v[2..], &pk, Some(&v[1])).unwrap();
        // Unanchored suffix also verifies (pruned prefix).
        verify_chain(&v[2..], &pk, None).unwrap();

        let mut t = v.clone();
        t[2].del_hash[0] ^= 1;
        assert!(verify_chain(&t, &pk, None).is_err());

        let mut gap = v.clone();
        gap.remove(2);
        assert_eq!(verify_chain(&gap, &pk, None), Err(StoreError::DeletionList("sequence gap")));

        let mut sig = v.clone();
        sig[3].sig[10] ^= 0x40;
        assert!(verify_chain(&sig, &pk, None).is_err());

        let other = Ed25519DeletionSigner::new(candor_core::sig::SigningKey::from_seed(&[8u8; 32]));
        assert!(verify_chain(&v, &other.verifying_key(), None).is_err());

        let mut gen = v.clone();
        gen[0].prev_hash = [1; 32];
        assert!(verify_chain(&gen, &pk, None).is_err());
    }

    #[test]
    fn del_hash_domain_separated_by_tenant() {
        let a = del_hash(&TenantId([1; 16]), &[9; 32]);
        let b = del_hash(&TenantId([2; 16]), &[9; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn core_hasher_rejects_short_and_garbage() {
        assert_eq!(CoreReplyHasher.object_hash(&[0u8; 10]), None);
        assert_eq!(CoreReplyHasher.object_hash(&[0u8; 400]), None);
    }
}
