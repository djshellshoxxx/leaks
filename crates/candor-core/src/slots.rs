// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RecipientSlotBlock (§13.2, ADR-033 item 1, CRYPTO-058/059/060).
//!
//! 16 anonymous HPKE slots: real slots are HPKE SealBase of CK to each recipient's
//! key with CSPRNG-drawn encapsulation randomness `enc_rand` that is disclosed in the
//! signed Recipient List (ADR-050(3)); the remaining slots are *verifiable dummies*
//! derived from CK. Any holder of CK re-derives all 16 slots
//! ([`RecipientSlotBlock::verify_slot_block`]) and so detects hidden extra recipients
//! and listed recipients swapped for other keys (THR-046).
//!
//! Dummy slot at position `i` (Implementation decision, SPEC-NOTES "dummy index"):
//! ```text
//! kp_seed ‖ r = HKDF(IKM=CK, salt=object_id, info="candor/v1/dummy-slot" ‖ u8 i, 64)
//! (sk_d, pk_d) = X-Wing DeriveKeyPair(kp_seed)                (HPKE DeriveKeyPair, KEM 0x647a)
//! eseed        = first 64 output bytes of rand_chacha 0.10 ChaCha20Rng::from_seed(r)
//!              = ChaCha20 keystream block 0, key = r, all-zero nonce and counter
//! pt_i         = HKDF(IKM=CK, salt=object_id, info="candor/v1/dummy-slot-pt" ‖ u8 i, 32)
//! (enc, ct)    = HPKE.SealBase(pk_d, info, aad, pt_i) with X-Wing encapsulation randomness eseed
//! ```
//! (`r` is 32 bytes but X-Wing encapsulation consumes 64 bytes; the ChaCha20 expansion
//! is flagged in SPEC-NOTES as needing a spec amendment.)

use crate::bytes::Reader;
use crate::error::{Error, Result};
use crate::hash::{KeyKind, key_id, sha256};
use crate::kdf::{ct_eq, hkdf};
use crate::kem::{
    ENCAP_RANDOMNESS_LEN, KemKeyPair, KemPrivateKey, KemPublicKey, open_base,
    seal_base_with_randomness,
};
use crate::labels;
use crate::rand::{OsRandom, RandomSource, permutation};
use crate::secret::ContentKey;
use crate::suite::{CK_LEN, Suite, XWING_NENC};
use rand_chacha::rand_core::{Rng as _, SeedableRng as _};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Slots per block (tenant-fixed at 16 in v1).
pub const SLOT_COUNT: usize = 16;
/// Slot ciphertext length (32-byte CK + 16-byte tag).
pub const SLOT_CT_LEN: usize = CK_LEN + 16;
/// One slot (STD): enc ‖ ct.
pub const SLOT_LEN: usize = XWING_NENC + SLOT_CT_LEN;
/// Block length (STD): 4 + 16 × 1168 = 18,692 bytes.
pub const SLOT_BLOCK_LEN: usize = 4 + SLOT_COUNT * SLOT_LEN;
/// Block version.
pub const BLOCK_VERSION: u8 = 0x01;

/// Context bound into every slot's HPKE `info` (§9.9, §13.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotContext {
    /// CK to Member Epoch Keys: `"candor/v1/wrap/member-epoch" ‖ suite ‖ tenant ‖ channel ‖ u32 epoch`.
    MemberEpoch {
        /// Tenant id.
        tenant_id: [u8; 16],
        /// Channel id.
        channel_id: [u8; 16],
        /// Epoch id.
        epoch_id: u32,
    },
    /// IDENTITY CK to K13: `"candor/v1/wrap/custodian" ‖ suite ‖ tenant`.
    Custodian {
        /// Tenant id.
        tenant_id: [u8; 16],
    },
}

impl SlotContext {
    fn info(&self, suite: Suite) -> Vec<u8> {
        match self {
            SlotContext::MemberEpoch {
                tenant_id,
                channel_id,
                epoch_id,
            } => crate::bytes::concat(&[
                labels::WRAP_MEMBER_EPOCH,
                &suite.to_be_bytes(),
                tenant_id,
                channel_id,
                &epoch_id.to_be_bytes(),
            ]),
            SlotContext::Custodian { tenant_id } => {
                crate::bytes::concat(&[labels::WRAP_CUSTODIAN, &suite.to_be_bytes(), tenant_id])
            }
        }
    }
}

/// `aad = "candor/v1/slot" ‖ object_id ‖ payload_nonce`.
fn slot_aad(object_id: &[u8; 16], payload_nonce: &[u8; 16]) -> Vec<u8> {
    crate::bytes::concat(&[labels::SLOT_AAD, object_id, payload_nonce])
}

/// Binding of a slot block to its object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotBinding {
    /// Suite.
    pub suite: Suite,
    /// Object id (CoreHeader offset 80).
    pub object_id: [u8; 16],
    /// Payload nonce (CoreHeader offset 112).
    pub payload_nonce: [u8; 16],
    /// HPKE info context.
    pub context: SlotContext,
}

/// One slot.
#[derive(Clone, PartialEq, Eq)]
pub struct Slot {
    enc: Vec<u8>,
    ct: [u8; SLOT_CT_LEN],
}

impl core::fmt::Debug for Slot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Slot")
    }
}

impl Slot {
    fn from_parts(enc: Vec<u8>, ct: Vec<u8>) -> Result<Self> {
        if enc.len() != XWING_NENC {
            return Err(Error::Internal);
        }
        let ct: [u8; SLOT_CT_LEN] = ct.try_into().map_err(|_| Error::Internal)?;
        Ok(Self { enc, ct })
    }

    fn ct_eq(&self, other: &Slot) -> bool {
        // Both comparisons always run (no short-circuit on secret-dependent data).
        let a = ct_eq(&self.enc, &other.enc);
        let b = ct_eq(&self.ct, &other.ct);
        a & b
    }
}

/// Length of a serialized [`RecipientListEntry`]: `u8 slot_index ‖ key_id (32) ‖ enc_rand (64)`.
pub const RECIPIENT_ENTRY_LEN: usize = 1 + 32 + ENCAP_RANDOMNESS_LEN;

/// One Recipient List entry (ADR-050(3)): the slot position, the recipient key id and
/// the 64-byte X-Wing encapsulation randomness used for that slot.
///
/// **Secret (AUD-RM1-CORE-01).** X-Wing encapsulation is deterministic given its
/// randomness, so `enc_rand` together with the recipient's *public* key recomputes the
/// HPKE shared secret and hence the slot plaintext, CK. For anyone who does not
/// already hold CK, an entry is exactly as sensitive as CK. Entries therefore:
/// have private fields and no accessor for `enc_rand`; are not `Clone`/`Copy`; have
/// no `PartialEq` (use the constant-time [`RecipientListEntry::ct_eq`]); zeroize on
/// drop; print nothing in `Debug`; and serialize only into a zeroizing buffer
/// ([`RecipientListEntry::to_bytes`]) whose sole legitimate destination is the signed,
/// AEAD-protected Recipient List inside the payload (§13.4). Never log, persist or
/// transmit them outside that encrypted encoding.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RecipientListEntry {
    slot_index: u8,
    key_id: [u8; 32],
    enc_rand: [u8; ENCAP_RANDOMNESS_LEN],
}

impl core::fmt::Debug for RecipientListEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecipientListEntry(<redacted>)")
    }
}

impl RecipientListEntry {
    /// Slot position (0..15).
    #[must_use]
    pub fn slot_index(&self) -> u8 {
        self.slot_index
    }

    /// `key_id` of the recipient public key (§13.2; kind MEK or custodian).
    #[must_use]
    pub fn key_id(&self) -> &[u8; 32] {
        &self.key_id
    }

    /// Constant-time equality of all three fields.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        let a = ct_eq(&[self.slot_index], &[other.slot_index]);
        let b = ct_eq(&self.key_id, &other.key_id);
        let c = ct_eq(&self.enc_rand, &other.enc_rand);
        a & b & c
    }

    /// Serialize: `u8 slot_index ‖ key_id ‖ enc_rand` (97 bytes) into a buffer that is
    /// zeroized on drop. Only for embedding in the encrypted Recipient List.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<[u8; RECIPIENT_ENTRY_LEN]> {
        let mut out = Zeroizing::new([0u8; RECIPIENT_ENTRY_LEN]);
        let (a, rest) = out.split_at_mut(1);
        let (b, c) = rest.split_at_mut(32);
        a.copy_from_slice(&[self.slot_index]);
        b.copy_from_slice(&self.key_id);
        c.copy_from_slice(&self.enc_rand);
        out
    }

    /// Parse exactly 97 bytes; `slot_index` must be < 16.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut out = Self::empty();
        let mut r = Reader::new(bytes);
        out.slot_index = r.u8()?;
        if usize::from(out.slot_index) >= SLOT_COUNT {
            return Err(Error::Malformed("slot_index"));
        }
        out.key_id.copy_from_slice(r.take(32)?);
        out.enc_rand.copy_from_slice(r.take(ENCAP_RANDOMNESS_LEN)?);
        r.finish()?;
        Ok(out)
    }

    fn empty() -> Self {
        Self {
            slot_index: 0,
            key_id: [0; 32],
            enc_rand: [0; ENCAP_RANDOMNESS_LEN],
        }
    }
}

/// The Recipient List entries produced by [`RecipientSlotBlock::build`], in recipient
/// order. Secret like its entries (AUD-RM1-CORE-01): not `Clone`, redacted `Debug`,
/// entries zeroized on drop. The backing vector is allocated once at its final size
/// and never grows or moves, so no stale copies of `enc_rand` are left in freed heap.
#[derive(Default)]
pub struct RecipientList(Vec<RecipientListEntry>);

impl core::fmt::Debug for RecipientList {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "RecipientList(<{} redacted entries>)", self.0.len())
    }
}

impl RecipientList {
    /// The entries, for encoding into the encrypted Recipient List.
    #[must_use]
    pub fn as_slice(&self) -> &[RecipientListEntry] {
        &self.0
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// No entries (non-intake objects, or an all-dummy block).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

fn kind_for(ctx: &SlotContext) -> KeyKind {
    match ctx {
        SlotContext::MemberEpoch { .. } => KeyKind::Mek,
        SlotContext::Custodian { .. } => KeyKind::Custodian,
    }
}

/// A RecipientSlotBlock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientSlotBlock {
    suite: Suite,
    slots: Vec<Slot>,
}

/// Derive dummy slot `i` (crate-internal derandomized encapsulation, §13.2; KAT-covered).
pub(crate) fn dummy_slot(ck: &ContentKey, b: &SlotBinding, i: u8) -> Result<Slot> {
    let mut seed = Zeroizing::new([0u8; 64]);
    hkdf(
        ck.expose(),
        &b.object_id,
        &[labels::DUMMY_SLOT, &[i]],
        seed.as_mut(),
    )?;
    let (kp_seed, r) = seed.split_at(32);
    let kp = KemKeyPair::derive(b.suite, kp_seed)?;
    let mut r32 = Zeroizing::new([0u8; 32]);
    r32.copy_from_slice(r);
    // AUD-RM1-CORE-07: `eseed` is zeroized on every exit path (guard).
    let mut eseed = Zeroizing::new([0u8; ENCAP_RANDOMNESS_LEN]);
    let mut chacha = rand_chacha::ChaCha20Rng::from_seed(*r32);
    chacha.fill_bytes(eseed.as_mut());
    drop(chacha);
    let mut pt = Zeroizing::new([0u8; 32]);
    hkdf(
        ck.expose(),
        &b.object_id,
        &[labels::DUMMY_SLOT_PT, &[i]],
        pt.as_mut(),
    )?;
    let info = b.context.info(b.suite);
    let aad = slot_aad(&b.object_id, &b.payload_nonce);
    let (enc, ct) = seal_base_with_randomness(&kp.public, &info, &aad, pt.as_ref(), &eseed)?;
    Slot::from_parts(enc, ct)
}

impl RecipientSlotBlock {
    /// Build a block: one real slot per recipient public key, the rest verifiable
    /// dummies, real slots at uniformly random positions (CRYPTO-058). Returns the
    /// block and the Recipient List entries (ADR-050(3)), in recipient order, to embed
    /// in the signed, AEAD-protected Recipient List.
    pub fn build(
        ck: &ContentKey,
        binding: &SlotBinding,
        recipients: &[KemPublicKey],
    ) -> Result<(Self, RecipientList)> {
        Self::build_with(&mut OsRandom, ck, binding, recipients)
    }

    pub(crate) fn build_with(
        rng: &mut dyn RandomSource,
        ck: &ContentKey,
        b: &SlotBinding,
        recipients: &[KemPublicKey],
    ) -> Result<(Self, RecipientList)> {
        b.suite.require_supported()?;
        if recipients.len() > SLOT_COUNT {
            return Err(Error::TooManyRecipients);
        }
        // AUD-RM1-CORE-09(a): IDENTITY has exactly one real slot (to K13).
        if matches!(b.context, SlotContext::Custodian { .. }) && recipients.len() > 1 {
            return Err(Error::TooManyRecipients);
        }
        // AUD-RM1-CORE-09(a): one key may not occupy two slots.
        for (i, pk) in recipients.iter().enumerate() {
            if recipients.iter().skip(i.saturating_add(1)).any(|o| o == pk) {
                return Err(Error::Malformed("duplicate recipient"));
            }
        }
        // perm[p] < recipients.len() ⇒ position p holds recipient perm[p]; else dummy.
        let perm = permutation(rng, SLOT_COUNT)?;
        let info = b.context.info(b.suite);
        let aad = slot_aad(&b.object_id, &b.payload_nonce);
        let kind = kind_for(&b.context);
        let mut slots = Vec::with_capacity(SLOT_COUNT);
        // AUD-RM1-CORE-01: entries are allocated once, indexed by recipient, and filled
        // in place (no sort/collect moves leaving stale `enc_rand` copies).
        let mut entries: Vec<RecipientListEntry> = Vec::with_capacity(recipients.len());
        entries.resize_with(recipients.len(), RecipientListEntry::empty);
        for (pos, who) in perm.iter().enumerate() {
            let pos_u8 = u8::try_from(pos).map_err(|_| Error::Internal)?;
            let slot = match (recipients.get(*who), entries.get_mut(*who)) {
                (Some(pk), Some(entry)) => {
                    // ADR-050(3): CSPRNG-drawn encapsulation randomness, disclosed to
                    // recipients inside the encrypted Recipient List only.
                    rng.fill(&mut entry.enc_rand)?;
                    entry.slot_index = pos_u8;
                    entry.key_id = key_id(b.suite, kind, &pk.to_bytes());
                    let (enc, ct) =
                        seal_base_with_randomness(pk, &info, &aad, ck.expose(), &entry.enc_rand)?;
                    Slot::from_parts(enc, ct)?
                }
                _ => dummy_slot(ck, b, pos_u8)?,
            };
            slots.push(slot);
        }
        Ok((
            Self {
                suite: b.suite,
                slots,
            },
            RecipientList(entries),
        ))
    }

    /// Suite.
    #[must_use]
    pub fn suite(&self) -> Suite {
        self.suite
    }

    /// Encode (18,692 bytes for STD).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(SLOT_BLOCK_LEN);
        v.push(BLOCK_VERSION);
        // slot_count always fits in u8 (fixed at 16).
        v.push(u8::try_from(self.slots.len()).unwrap_or(u8::MAX));
        v.extend_from_slice(&self.suite.to_be_bytes());
        for s in &self.slots {
            v.extend_from_slice(&s.enc);
            v.extend_from_slice(&s.ct);
        }
        v
    }

    /// Decode and validate (exact length, version, 16 slots, supported suite).
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        if r.u8()? != BLOCK_VERSION {
            return Err(Error::Malformed("block_version"));
        }
        if usize::from(r.u8()?) != SLOT_COUNT {
            return Err(Error::Malformed("slot_count"));
        }
        let suite = Suite::from_id_supported(r.u16()?)?;
        if bytes.len() != SLOT_BLOCK_LEN {
            return Err(Error::Length);
        }
        let mut slots = Vec::with_capacity(SLOT_COUNT);
        for _ in 0..SLOT_COUNT {
            let enc = r.take(XWING_NENC)?.to_vec();
            let ct = r.array::<SLOT_CT_LEN>()?;
            slots.push(Slot { enc, ct });
        }
        r.finish()?;
        Ok(Self { suite, slots })
    }

    /// `slot_block_hash = H(RecipientSlotBlock)` (CoreHeader offset 48).
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        sha256(&[&self.encode()])
    }

    /// Trial-decrypt all 16 slots with `sk` (CRYPTO-060: every slot is attempted, no
    /// early exit). Returns CK and the slot position.
    pub fn trial_open(&self, sk: &KemPrivateKey, b: &SlotBinding) -> Result<(ContentKey, usize)> {
        if b.suite != self.suite {
            return Err(Error::Authentication);
        }
        let info = b.context.info(b.suite);
        let aad = slot_aad(&b.object_id, &b.payload_nonce);
        let mut found: Option<(ContentKey, usize)> = None;
        for (pos, s) in self.slots.iter().enumerate() {
            let r = open_base(sk, &s.enc, &info, &aad, &s.ct);
            if let Ok(pt) = r
                && found.is_none()
                && let Ok(ck) = ContentKey::from_slice(&pt)
            {
                found = Some((ck, pos));
            }
        }
        found.ok_or(Error::Authentication)
    }

    /// Full recipient-set verification (ADR-050(3), THR-046): re-derive **all 16**
    /// slots — listed slots by re-encapsulating CK to the listed key (resolved from the
    /// Key Directory by `resolve_pk`) with the entry's `enc_rand`, every other slot as
    /// the dummy for its position — and require byte equality for every slot.
    ///
    /// Fails with [`Error::SlotVerification`] on any mismatch, a duplicate or
    /// out-of-range `slot_index`, an unresolvable key id, or a resolved key whose
    /// `key_id` differs. Detects extra hidden recipients and listed recipients swapped
    /// for another key. All 16 slots are always re-derived and compared.
    pub fn verify_slot_block<F>(
        &self,
        ck: &ContentKey,
        b: &SlotBinding,
        list: &[RecipientListEntry],
        resolve_pk: F,
    ) -> Result<()>
    where
        F: Fn(&[u8; 32]) -> Option<KemPublicKey>,
    {
        if b.suite != self.suite || self.slots.len() != SLOT_COUNT || list.len() > SLOT_COUNT {
            return Err(Error::SlotVerification);
        }
        // AUD-RM1-CORE-09(a): IDENTITY (custodian) has at most one real slot.
        if matches!(b.context, SlotContext::Custodian { .. }) && list.len() > 1 {
            return Err(Error::SlotVerification);
        }
        // AUD-RM1-CORE-09(a): one member may not occupy two slots (public data).
        for (i, e) in list.iter().enumerate() {
            if list
                .iter()
                .skip(i.saturating_add(1))
                .any(|o| o.key_id == e.key_id)
            {
                return Err(Error::SlotVerification);
            }
        }
        let mut by_pos: [Option<&RecipientListEntry>; SLOT_COUNT] = [None; SLOT_COUNT];
        for e in list {
            let cell = by_pos
                .get_mut(usize::from(e.slot_index))
                .ok_or(Error::SlotVerification)?;
            if cell.is_some() {
                return Err(Error::SlotVerification);
            }
            *cell = Some(e);
        }
        let info = b.context.info(b.suite);
        let aad = slot_aad(&b.object_id, &b.payload_nonce);
        let kind = kind_for(&b.context);
        let mut ok = true;
        for (pos, (s, entry)) in self.slots.iter().zip(by_pos.iter()).enumerate() {
            let expected = match entry {
                Some(e) => match resolve_pk(&e.key_id) {
                    Some(pk) if key_id(b.suite, kind, &pk.to_bytes()) == e.key_id => {
                        let (enc, ct) =
                            seal_base_with_randomness(&pk, &info, &aad, ck.expose(), &e.enc_rand)?;
                        Some(Slot::from_parts(enc, ct)?)
                    }
                    _ => None,
                },
                None => Some(dummy_slot(
                    ck,
                    b,
                    u8::try_from(pos).map_err(|_| Error::Internal)?,
                )?),
            };
            ok &= expected.as_ref().is_some_and(|x| s.ct_eq(x));
        }
        if ok {
            Ok(())
        } else {
            Err(Error::SlotVerification)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::*;
    use crate::rand::TestRng;

    fn binding() -> SlotBinding {
        SlotBinding {
            suite: Suite::CandorStd1,
            object_id: [1; 16],
            payload_nonce: [2; 16],
            context: SlotContext::MemberEpoch {
                tenant_id: [3; 16],
                channel_id: [4; 16],
                epoch_id: 5,
            },
        }
    }

    /// A Key Directory stub: resolve key ids of the given public keys.
    fn directory(
        pks: &[KemPublicKey],
        kind: KeyKind,
    ) -> impl Fn(&[u8; 32]) -> Option<KemPublicKey> + '_ {
        move |kid| {
            pks.iter()
                .find(|pk| key_id(Suite::CandorStd1, kind, &pk.to_bytes()) == *kid)
                .cloned()
        }
    }

    #[test]
    fn build_open_verify() {
        let mut rng = TestRng::new(10);
        let ck = ContentKey::from_bytes([0x11; 32]);
        let members: Vec<KemKeyPair> = (0..3)
            .map(|_| KemKeyPair::generate_with(Suite::CandorStd1, &mut rng).unwrap())
            .collect();
        let pks: Vec<KemPublicKey> = members.iter().map(|m| m.public.clone()).collect();
        let b = binding();
        let (blk, list) = RecipientSlotBlock::build_with(&mut rng, &ck, &b, &pks).unwrap();
        assert_eq!(list.len(), 3);
        for (e, pk) in list.as_slice().iter().zip(&pks) {
            assert_eq!(
                *e.key_id(),
                key_id(Suite::CandorStd1, KeyKind::Mek, &pk.to_bytes())
            );
            assert!(
                RecipientListEntry::from_bytes(e.to_bytes().as_ref())
                    .unwrap()
                    .ct_eq(e)
            );
        }
        let enc = blk.encode();
        assert_eq!(enc.len(), SLOT_BLOCK_LEN);
        assert_eq!(enc.len(), 18_692);
        let blk2 = RecipientSlotBlock::decode(&enc).unwrap();
        assert_eq!(blk2, blk);
        for (i, m) in members.iter().enumerate() {
            let (got, pos) = blk2.trial_open(&m.private, &b).unwrap();
            assert_eq!(got.expose(), ck.expose());
            assert_eq!(usize::from(list.as_slice()[i].slot_index()), pos);
            // Honest envelope verifies (ADR-050(3)).
            blk2.verify_slot_block(&got, &b, list.as_slice(), directory(&pks, KeyKind::Mek))
                .unwrap();
        }
        // Outsider cannot open.
        let outsider = KemKeyPair::generate_with(Suite::CandorStd1, &mut rng).unwrap();
        assert_eq!(
            blk2.trial_open(&outsider.private, &b).err(),
            Some(Error::Authentication)
        );
        // CRYPTO-006: wrong epoch / channel / object binding fails to open.
        let mut wrong = b.clone();
        wrong.context = SlotContext::MemberEpoch {
            tenant_id: [3; 16],
            channel_id: [4; 16],
            epoch_id: 6,
        };
        assert!(blk2.trial_open(&members[0].private, &wrong).is_err());
        assert!(
            blk2.verify_slot_block(&ck, &wrong, list.as_slice(), directory(&pks, KeyKind::Mek))
                .is_err()
        );
        let mut wrong = b.clone();
        wrong.payload_nonce[0] ^= 1;
        assert!(blk2.trial_open(&members[0].private, &wrong).is_err());
        // Wrong CK: nothing re-derives.
        let ck2 = ContentKey::from_bytes([0x12; 32]);
        assert!(
            blk2.verify_slot_block(&ck2, &b, list.as_slice(), directory(&pks, KeyKind::Mek))
                .is_err()
        );
    }

    /// §22.2 negative vector: slot block with an unlisted non-dummy slot (hidden recipient).
    #[test]
    fn hidden_recipient_detected() {
        let mut rng = TestRng::new(11);
        let ck = ContentKey::from_bytes([0x22; 32]);
        let a = KemKeyPair::generate_with(Suite::CandorStd1, &mut rng).unwrap();
        let hidden = KemKeyPair::generate_with(Suite::CandorStd1, &mut rng).unwrap();
        let b = binding();
        let pks = [a.public.clone(), hidden.public.clone()];
        let (blk, list) = RecipientSlotBlock::build_with(&mut rng, &ck, &b, &pks).unwrap();
        let dir = directory(&pks, KeyKind::Mek);
        let list = list.as_slice();
        assert!(blk.verify_slot_block(&ck, &b, list, &dir).is_ok());
        // Recipient List omits the hidden recipient's entry.
        assert_eq!(
            blk.verify_slot_block(&ck, &b, &list[..1], &dir).err(),
            Some(Error::SlotVerification)
        );
        // Duplicate / out-of-range slot indices are rejected.
        let dup = [copy(&list[0]), copy(&list[0])];
        assert!(blk.verify_slot_block(&ck, &b, &dup, &dir).is_err());
        let mut oob = copy(&list[0]);
        oob.slot_index = 16;
        assert!(blk.verify_slot_block(&ck, &b, &[oob], &dir).is_err());
        // AUD-RM1-CORE-09(a): the same key id at two positions is rejected.
        let mut twice = copy(&list[1]);
        twice.key_id = list[0].key_id;
        assert_eq!(
            blk.verify_slot_block(&ck, &b, &[copy(&list[0]), twice], &dir)
                .err(),
            Some(Error::SlotVerification)
        );
        // Unresolvable key id.
        assert!(blk.verify_slot_block(&ck, &b, list, |_| None).is_err());
        // Permuting slots breaks verification (slots are position-bound).
        let mut swapped = blk.clone();
        swapped.slots.swap(0, 15);
        swapped.slots.swap(1, 14);
        assert!(swapped.verify_slot_block(&ck, &b, list, &dir).is_err());
    }

    /// ADR-050(3): a slot sealed to an attacker key while the list names a member is
    /// detected (count-based verification would have missed this).
    #[test]
    fn swapped_recipient_detected() {
        let mut rng = TestRng::new(15);
        let ck = ContentKey::from_bytes([0x44; 32]);
        let member = KemKeyPair::generate_with(Suite::CandorStd1, &mut rng).unwrap();
        let attacker = KemKeyPair::generate_with(Suite::CandorStd1, &mut rng).unwrap();
        let b = binding();
        // Malicious sealer seals to the attacker but lists the member's key id at the
        // same slot (with the same or any enc_rand).
        let (blk, mut list) = RecipientSlotBlock::build_with(
            &mut rng,
            &ck,
            &b,
            core::slice::from_ref(&attacker.public),
        )
        .unwrap();
        list.0[0].key_id = key_id(Suite::CandorStd1, KeyKind::Mek, &member.public.to_bytes());
        let dir = directory(core::slice::from_ref(&member.public), KeyKind::Mek);
        assert_eq!(
            blk.verify_slot_block(&ck, &b, list.as_slice(), &dir).err(),
            Some(Error::SlotVerification)
        );
        // A directory that maps the listed id to a different key is also rejected.
        let lying = |_: &[u8; 32]| Some(attacker.public.clone());
        assert!(
            blk.verify_slot_block(&ck, &b, list.as_slice(), lying)
                .is_err()
        );
        // Tampered enc_rand is detected.
        let (blk2, mut list2) = RecipientSlotBlock::build_with(
            &mut rng,
            &ck,
            &b,
            core::slice::from_ref(&member.public),
        )
        .unwrap();
        assert!(
            blk2.verify_slot_block(&ck, &b, list2.as_slice(), &dir)
                .is_ok()
        );
        list2.0[0].enc_rand[0] ^= 1;
        assert!(
            blk2.verify_slot_block(&ck, &b, list2.as_slice(), &dir)
                .is_err()
        );
    }

    #[test]
    fn all_dummy_block_and_custodian() {
        let mut rng = TestRng::new(12);
        let ck = ContentKey::from_bytes([0x33; 32]);
        let mut b = binding();
        b.context = SlotContext::Custodian { tenant_id: [3; 16] };
        let (blk, list) = RecipientSlotBlock::build_with(&mut rng, &ck, &b, &[]).unwrap();
        assert!(list.is_empty());
        assert!(blk.verify_slot_block(&ck, &b, &[], |_| None).is_ok());
        // Custodian slot with key kind 3.
        let k13 = KemKeyPair::generate_with(Suite::CandorStd1, &mut rng).unwrap();
        let pks = [k13.public.clone()];
        let (blk, list) = RecipientSlotBlock::build_with(&mut rng, &ck, &b, &pks).unwrap();
        assert!(
            blk.verify_slot_block(
                &ck,
                &b,
                list.as_slice(),
                directory(&pks, KeyKind::Custodian)
            )
            .is_ok()
        );
        assert!(
            blk.verify_slot_block(&ck, &b, list.as_slice(), directory(&pks, KeyKind::Mek))
                .is_err()
        );
        // AUD-RM1-CORE-09(a): at most one real custodian slot.
        let k13b = KemKeyPair::generate_with(Suite::CandorStd1, &mut rng).unwrap();
        let two = [k13.public.clone(), k13b.public.clone()];
        assert_eq!(
            RecipientSlotBlock::build_with(&mut rng, &ck, &b, &two).err(),
            Some(Error::TooManyRecipients)
        );
        let mut me = binding();
        let (blk2, list2) = RecipientSlotBlock::build_with(&mut rng, &ck, &me, &two).unwrap();
        me.context = b.context.clone();
        assert_eq!(
            blk2.verify_slot_block(
                &ck,
                &me,
                list2.as_slice(),
                directory(&two, KeyKind::Custodian)
            )
            .err(),
            Some(Error::SlotVerification)
        );
        // Dummy derivation is deterministic.
        assert_eq!(
            dummy_slot(&ck, &b, 3).unwrap(),
            dummy_slot(&ck, &b, 3).unwrap()
        );
        assert_ne!(
            dummy_slot(&ck, &b, 3).unwrap(),
            dummy_slot(&ck, &b, 4).unwrap()
        );
    }

    /// Field-by-field copy for negative tests (entries are deliberately not `Clone`).
    fn copy(e: &RecipientListEntry) -> RecipientListEntry {
        RecipientListEntry {
            slot_index: e.slot_index,
            key_id: e.key_id,
            enc_rand: e.enc_rand,
        }
    }

    /// AUD-RM1-CORE-01 regression: `RecipientListEntry` and `RecipientList` are not
    /// `Clone` (compile-time check: the probe is ambiguous if either implements it).
    #[test]
    fn recipient_entries_are_secret() {
        trait AmbiguousIfClone<A> {
            fn probe() {}
        }
        impl<T: ?Sized> AmbiguousIfClone<()> for T {}
        #[allow(dead_code)]
        struct IsClone;
        impl<T: ?Sized + Clone> AmbiguousIfClone<IsClone> for T {}
        <RecipientListEntry as AmbiguousIfClone<_>>::probe();
        <RecipientList as AmbiguousIfClone<_>>::probe();

        let mut rng = TestRng::new(16);
        let ck = ContentKey::from_bytes([0x55; 32]);
        let m = KemKeyPair::generate_with(Suite::CandorStd1, &mut rng).unwrap();
        let (_, list) = RecipientSlotBlock::build_with(
            &mut rng,
            &ck,
            &binding(),
            core::slice::from_ref(&m.public),
        )
        .unwrap();
        assert_eq!(format!("{list:?}"), "RecipientList(<1 redacted entries>)");
        assert_eq!(
            format!("{:?}", list.as_slice()[0]),
            "RecipientListEntry(<redacted>)"
        );
        // Duplicate recipients are refused at build time.
        let dup = [m.public.clone(), m.public.clone()];
        assert!(RecipientSlotBlock::build_with(&mut rng, &ck, &binding(), &dup).is_err());
    }

    /// INC-SL-08 / AUD-RM1-CORE-05(c): substituting exactly one slot k (k = 0..15) is
    /// rejected for every k, whether k is a real or a dummy position, and for three
    /// kinds of replacement (same-position slot of another honest block, a slot sealed
    /// to an attacker key, random bytes).
    #[test]
    fn single_slot_substitution_rejected_for_every_k() {
        let mut rng = TestRng::new(17);
        let ck = ContentKey::from_bytes([0x66; 32]);
        let members: Vec<KemKeyPair> = (0..3)
            .map(|_| KemKeyPair::generate_with(Suite::CandorStd1, &mut rng).unwrap())
            .collect();
        let pks: Vec<KemPublicKey> = members.iter().map(|m| m.public.clone()).collect();
        let attacker = KemKeyPair::generate_with(Suite::CandorStd1, &mut rng).unwrap();
        let b = binding();
        let dir = directory(&pks, KeyKind::Mek);
        let (blk, list) = RecipientSlotBlock::build_with(&mut rng, &ck, &b, &pks).unwrap();
        blk.verify_slot_block(&ck, &b, list.as_slice(), &dir)
            .unwrap();
        let other_ck = ContentKey::from_bytes([0x67; 32]);
        let (other, _) = RecipientSlotBlock::build_with(&mut rng, &other_ck, &b, &pks).unwrap();
        let real: Vec<usize> = list
            .as_slice()
            .iter()
            .map(|e| usize::from(e.slot_index))
            .collect();
        let (mut saw_real, mut saw_dummy) = (0, 0);
        for k in 0..SLOT_COUNT {
            if real.contains(&k) {
                saw_real += 1;
            } else {
                saw_dummy += 1;
            }
            let info = b.context.info(b.suite);
            let aad = slot_aad(&b.object_id, &b.payload_nonce);
            let mut r = [0u8; ENCAP_RANDOMNESS_LEN];
            rng.fill(&mut r).unwrap();
            let (enc, ct) =
                seal_base_with_randomness(&attacker.public, &info, &aad, ck.expose(), &r).unwrap();
            let mut noise_ct = [0u8; SLOT_CT_LEN];
            rng.fill(&mut noise_ct).unwrap();
            let mut noise_enc = vec![0u8; XWING_NENC];
            rng.fill(&mut noise_enc).unwrap();
            let replacements = [
                other.slots[k].clone(),
                Slot::from_parts(enc, ct).unwrap(),
                Slot {
                    enc: noise_enc,
                    ct: noise_ct,
                },
            ];
            for rep in replacements {
                let mut t = blk.clone();
                t.slots[k] = rep;
                assert_eq!(
                    t.verify_slot_block(&ck, &b, list.as_slice(), &dir).err(),
                    Some(Error::SlotVerification),
                    "slot {k} substitution not detected"
                );
            }
        }
        assert_eq!((saw_real, saw_dummy), (3, 13));
    }

    #[test]
    fn too_many_recipients() {
        let mut rng = TestRng::new(13);
        let kp = KemKeyPair::generate_with(Suite::CandorStd1, &mut rng).unwrap();
        let pks = vec![kp.public.clone(); 17];
        let r = RecipientSlotBlock::build_with(
            &mut rng,
            &ContentKey::from_bytes([0; 32]),
            &binding(),
            &pks,
        );
        assert_eq!(r.err(), Some(Error::TooManyRecipients));
    }

    #[test]
    fn decode_rejects() {
        let mut rng = TestRng::new(14);
        let (blk, _) = RecipientSlotBlock::build_with(
            &mut rng,
            &ContentKey::from_bytes([0; 32]),
            &binding(),
            &[],
        )
        .unwrap();
        let e = blk.encode();
        let mut b = e.clone();
        b[0] = 2;
        assert!(RecipientSlotBlock::decode(&b).is_err());
        let mut b = e.clone();
        b[1] = 15;
        assert!(RecipientSlotBlock::decode(&b).is_err());
        let mut b = e.clone();
        b[3] = 2;
        assert_eq!(
            RecipientSlotBlock::decode(&b).err(),
            Some(Error::UnsupportedSuite)
        );
        assert!(RecipientSlotBlock::decode(&e[..e.len() - 1]).is_err());
        let mut b = e.clone();
        b.push(0);
        assert!(RecipientSlotBlock::decode(&b).is_err());
    }

    /// The documented ChaCha20 expansion equals ChaCha20 keystream block 0 with key r
    /// and all-zero nonce/counter (lets other implementations reproduce dummies).
    #[test]
    fn chacha_expansion_matches_raw_chacha20() {
        use chacha20::cipher::{KeyIvInit, StreamCipher};
        let r = [0x5au8; 32];
        let mut a = [0u8; 64];
        rand_chacha::ChaCha20Rng::from_seed(r).fill_bytes(&mut a);
        let mut b = [0u8; 64];
        let mut c = chacha20::ChaCha20::new(&r.into(), &[0u8; 12].into());
        c.apply_keystream(&mut b);
        assert_eq!(a, b);
    }
}
