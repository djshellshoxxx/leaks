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
    Ok(DeletionEntry {
        seq,
        kind,
        del_hash,
        del_day,
        prev_hash,
        sig,
        relayed: false,
    })
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

/// Signature context of a Z-CORE deletion-list head attestation
/// (AUD-RM2-STO-21/22; implementation decision, spec feedback for 08 RL-11/RL-12).
pub const HEAD_CONTEXT: &[u8] = b"candor/v1/intake/deletion-head";

/// A deletion-list head as attested by Z-CORE: "on Z-CORE day `day`, in my
/// attestation number `counter`, I hold the chain through `seq`, whose chain
/// hash is `head_hash`", signed with the Z-CORE head key whose public half is
/// intake configuration (`core_pk`).
///
/// - `head_hash` = [`DeletionEntry::next_prev_hash`] of entry `seq` (it commits
///   to the whole chain through `seq`); all-zero for `seq = 0`;
/// - `day` = Z-CORE's day of the attestation (freshness, AUD-RM2-STO-24);
/// - `counter` = Z-CORE's attestation counter for this tenant, strictly
///   increasing with every attestation it signs (≥ 1);
/// - `sig = Ed25519_core("candor/v1/intake/deletion-head" ‖ tenant_id(16) ‖
///   u64be counter ‖ u32be day ‖ u64be seq ‖ head_hash)`.
///
/// The relay cannot assert a head on its own: the store acknowledges (RL-11)
/// and accepts pushed lists (RL-12) only against a head whose signature
/// verifies, that is not older (by `counter`) than the last head the store
/// verified (stored, and carried in backups), and, for RL-12, whose `day` is
/// fresh ([`MAX_HEAD_AGE_DAYS`]).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SignedDeletionHead {
    /// Highest seq Z-CORE holds.
    pub seq: u64,
    /// Chain hash through `seq`.
    pub head_hash: [u8; 32],
    /// Z-CORE day of the attestation.
    pub day: Day,
    /// Z-CORE attestation counter (strictly increasing per tenant, ≥ 1).
    pub counter: u64,
    /// Z-CORE signature.
    pub sig: [u8; 64],
}

/// Largest age, in days, of a Z-CORE head accepted by RL-12 / restore
/// (AUD-RM2-STO-24(b)): `today − 1 ≤ head.day ≤ today + 1` (one day of clock
/// skew either way). A replayed older attestation is refused even on a node
/// restored from a backup that predates it.
pub const MAX_HEAD_AGE_DAYS: u32 = 1;

impl fmt::Debug for SignedDeletionHead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedDeletionHead")
            .field("seq", &self.seq)
            .field("counter", &self.counter)
            .finish_non_exhaustive()
    }
}

/// Signed message of a head attestation.
#[must_use]
pub fn head_message(
    tenant: &TenantId,
    seq: u64,
    head_hash: &[u8; 32],
    day: Day,
    counter: u64,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(HEAD_CONTEXT.len().saturating_add(16 + 8 + 4 + 8 + 32));
    m.extend_from_slice(HEAD_CONTEXT);
    m.extend_from_slice(&tenant.0);
    m.extend_from_slice(&counter.to_be_bytes());
    m.extend_from_slice(&day.0.to_be_bytes());
    m.extend_from_slice(&seq.to_be_bytes());
    m.extend_from_slice(head_hash);
    m
}

/// Chain hash through `entry` (all-zero for no entry): the `head_hash` of a head.
#[must_use]
pub fn chain_hash(entry: Option<&DeletionEntry>) -> [u8; 32] {
    entry.map_or([0u8; 32], DeletionEntry::next_prev_hash)
}

impl SignedDeletionHead {
    /// Sign a head (Z-CORE side and tests) for Z-CORE day `day` with
    /// attestation counter `counter`.
    #[must_use]
    pub fn sign(
        tenant: &TenantId,
        head: Option<&DeletionEntry>,
        day: Day,
        counter: u64,
        key: &candor_core::sig::SigningKey,
    ) -> Self {
        let seq = head.map_or(0, |e| e.seq);
        let head_hash = chain_hash(head);
        let sig = key.sign(&head_message(tenant, seq, &head_hash, day, counter));
        Self {
            seq,
            head_hash,
            day,
            counter,
            sig,
        }
    }

    /// Verify the attestation (strict Ed25519 under `core_pk`) and its shape
    /// (`seq = 0` ⇔ all-zero hash; `1 ≤ counter ≤ i64::MAX`; day in range).
    pub fn verify(&self, tenant: &TenantId, core_pk: &[u8; 32]) -> Result<()> {
        if (self.seq == 0) != (self.head_hash == [0u8; 32])
            || i64::try_from(self.seq).is_err()
            || self.counter == 0
            || i64::try_from(self.counter).is_err()
            || i32::try_from(self.day.0).is_err()
        {
            return Err(StoreError::DeletionList("malformed head"));
        }
        candor_core::sig::verify_strict(
            core_pk,
            &head_message(tenant, self.seq, &self.head_hash, self.day, self.counter),
            &self.sig,
        )
        .map_err(|_| StoreError::DeletionList("bad head signature"))
    }

    /// Same attested content (seq, hash, day, counter).
    #[must_use]
    pub fn same_attestation(&self, other: &Self) -> bool {
        self.seq == other.seq
            && self.day == other.day
            && self.counter == other.counter
            && bool::from(self.head_hash.ct_eq(&other.head_hash))
    }

    /// RL-12 freshness (AUD-RM2-STO-24(b)): `today − MAX_HEAD_AGE_DAYS ≤ day ≤
    /// today + MAX_HEAD_AGE_DAYS`.
    pub fn check_fresh(&self, today: Day) -> Result<()> {
        let lo = today.saturating_minus(MAX_HEAD_AGE_DAYS);
        let hi = today.0.saturating_add(MAX_HEAD_AGE_DAYS);
        if self.day < lo || self.day.0 > hi {
            return Err(StoreError::DeletionList("stale Z-CORE head"));
        }
        Ok(())
    }

    /// The monotonic rule against the last head this store verified
    /// (AUD-RM2-STO-24(b)): `None` = nothing verified yet. A head with a lower
    /// counter is older and refused; the same counter must carry the same
    /// attestation; a newer counter must not move `day` or `seq` backwards.
    /// Returns whether `self` is newer than `verified` (to be stored).
    pub fn newer_than(&self, verified: Option<&Self>) -> Result<bool> {
        let Some(v) = verified else {
            return Ok(true);
        };
        if self.counter < v.counter {
            return Err(StoreError::DeletionList(
                "Z-CORE head older than the verified head",
            ));
        }
        if self.counter == v.counter {
            return if self.same_attestation(v) {
                Ok(false)
            } else {
                Err(StoreError::DeletionList("conflicting Z-CORE head"))
            };
        }
        if self.day < v.day || self.seq < v.seq {
            return Err(StoreError::DeletionList(
                "Z-CORE head behind the verified head",
            ));
        }
        Ok(true)
    }
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
        assert_eq!(
            verify_chain(&gap, &pk, None),
            Err(StoreError::DeletionList("sequence gap"))
        );

        let mut sig = v.clone();
        sig[3].sig[10] ^= 0x40;
        assert!(verify_chain(&sig, &pk, None).is_err());

        let other = Ed25519DeletionSigner::new(candor_core::sig::SigningKey::from_seed(&[8u8; 32]));
        assert!(verify_chain(&v, &other.verifying_key(), None).is_err());

        let mut genesis = v.clone();
        genesis[0].prev_hash = [1; 32];
        assert!(verify_chain(&genesis, &pk, None).is_err());
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

#[cfg(test)]
mod props {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::*;
    use proptest::prelude::*;

    fn arb_entry() -> impl Strategy<Value = DeletionEntry> {
        (
            any::<u64>(),
            0u8..3,
            any::<[u8; 32]>(),
            any::<u32>(),
            any::<[u8; 32]>(),
            proptest::collection::vec(any::<u8>(), 64),
        )
            .prop_map(|(seq, k, h, d, p, s)| DeletionEntry {
                seq,
                kind: [
                    DeletionKind::Account,
                    DeletionKind::Mailbox,
                    DeletionKind::Reply,
                ][usize::from(k)],
                del_hash: h,
                del_day: Day(d),
                prev_hash: p,
                sig: s.try_into().unwrap(),
                relayed: false,
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]
        /// Hostile pushed lists never panic and never verify without K31.
        #[test]
        fn arbitrary_lists_rejected(entries in proptest::collection::vec(arb_entry(), 1..8)) {
            prop_assert!(verify_chain(&entries, &[9u8; 32], None).is_err());
        }

        /// Any single-bit flip in a valid entry breaks verification.
        #[test]
        fn bit_flip_detected(byte in 0usize..(ENTRY_LEN + 32 + 64), bit in 0u8..8) {
            let s = Ed25519DeletionSigner::new(candor_core::sig::SigningKey::from_seed(&[3u8; 32]));
            let a = make_entry(None, DeletionKind::Account, [1; 32], Day(5), &s).unwrap();
            let b = make_entry(Some(&a), DeletionKind::Reply, [2; 32], Day(6), &s).unwrap();
            let mut t = b;
            let mask = 1u8 << bit;
            if byte < 8 { let mut x = t.seq.to_be_bytes(); x[byte] ^= mask; t.seq = u64::from_be_bytes(x); }
            else if byte == 8 { t.kind = if t.kind == DeletionKind::Reply { DeletionKind::Mailbox } else { DeletionKind::Reply }; }
            else if byte < 41 { t.del_hash[byte - 9] ^= mask; }
            else if byte < 45 { let mut x = t.del_day.0.to_be_bytes(); x[byte - 41] ^= mask; t.del_day = Day(u32::from_be_bytes(x)); }
            else if byte < 77 { t.prev_hash[byte - 45] ^= mask; }
            else { t.sig[byte - 77] ^= mask; }
            prop_assert!(verify_chain(&[a, t], &s.verifying_key(), None).is_err());
        }
    }
}
