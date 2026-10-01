// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RecipientSlotBlock (§13.2, ADR-033 item 1, CRYPTO-058/059/060).
//!
//! 16 anonymous HPKE slots: real slots are HPKE SealBase of CK to each recipient's
//! key; the remaining slots are *verifiable dummies* derived from CK, so any holder of
//! CK can recompute them and detect hidden extra recipients (THR-046).
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
use crate::hash::sha256;
use crate::kdf::{ct_eq, hkdf};
use crate::kem::{ENCAP_RANDOMNESS_LEN, KemKeyPair, KemPrivateKey, KemPublicKey, open_base, seal_base_with, seal_base_with_randomness};
use crate::labels;
use crate::rand::{OsRandom, RandomSource, permutation};
use crate::secret::ContentKey;
use crate::suite::{CK_LEN, Suite, XWING_NENC};
use rand_chacha::rand_core::{Rng as _, SeedableRng as _};
use zeroize::{Zeroize, Zeroizing};

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
            SlotContext::MemberEpoch { tenant_id, channel_id, epoch_id } => crate::bytes::concat(&[
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

/// Result of slot verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotVerification {
    /// Positions of non-dummy (real) slots.
    pub real_positions: Vec<usize>,
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
    hkdf(ck.expose(), &b.object_id, &[labels::DUMMY_SLOT, &[i]], seed.as_mut())?;
    let (kp_seed, r) = seed.split_at(32);
    let kp = KemKeyPair::derive(b.suite, kp_seed)?;
    let mut r32: [u8; 32] = r.try_into().map_err(|_| Error::Internal)?;
    let mut eseed = [0u8; ENCAP_RANDOMNESS_LEN];
    let mut chacha = rand_chacha::ChaCha20Rng::from_seed(r32);
    chacha.fill_bytes(&mut eseed);
    r32.zeroize();
    let mut pt = Zeroizing::new([0u8; 32]);
    hkdf(ck.expose(), &b.object_id, &[labels::DUMMY_SLOT_PT, &[i]], pt.as_mut())?;
    let info = b.context.info(b.suite);
    let aad = slot_aad(&b.object_id, &b.payload_nonce);
    let (enc, ct) = seal_base_with_randomness(&kp.public, &info, &aad, pt.as_ref(), eseed)?;
    eseed.zeroize();
    Slot::from_parts(enc, ct)
}

impl RecipientSlotBlock {
    /// Build a block: one real slot per recipient public key, the rest verifiable
    /// dummies, real slots at uniformly random positions (CRYPTO-058).
    pub fn build(ck: &ContentKey, binding: &SlotBinding, recipients: &[KemPublicKey]) -> Result<Self> {
        Self::build_with(&mut OsRandom, ck, binding, recipients)
    }

    pub(crate) fn build_with(
        rng: &mut dyn RandomSource,
        ck: &ContentKey,
        b: &SlotBinding,
        recipients: &[KemPublicKey],
    ) -> Result<Self> {
        b.suite.require_supported()?;
        if recipients.len() > SLOT_COUNT {
            return Err(Error::TooManyRecipients);
        }
        // perm[p] < recipients.len() ⇒ position p holds recipient perm[p]; else dummy.
        let perm = permutation(rng, SLOT_COUNT)?;
        let info = b.context.info(b.suite);
        let aad = slot_aad(&b.object_id, &b.payload_nonce);
        let mut slots = Vec::with_capacity(SLOT_COUNT);
        for (pos, who) in perm.iter().enumerate() {
            let slot = match recipients.get(*who) {
                Some(pk) => {
                    let (enc, ct) = seal_base_with(rng, pk, &info, &aad, ck.expose())?;
                    Slot::from_parts(enc, ct)?
                }
                None => dummy_slot(ck, b, u8::try_from(pos).map_err(|_| Error::Internal)?)?,
            };
            slots.push(slot);
        }
        Ok(Self { suite: b.suite, slots })
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

    /// Verify that every slot is either the verifiable dummy for its position or one
    /// of exactly `recipient_count` non-dummy slots (count from the signed Recipient
    /// List, §13.2, THR-046). Also requires `own_position` (the slot this Desk opened)
    /// to be a non-dummy slot when given.
    pub fn verify(
        &self,
        ck: &ContentKey,
        b: &SlotBinding,
        recipient_count: usize,
        own_position: Option<usize>,
    ) -> Result<SlotVerification> {
        if b.suite != self.suite || self.slots.len() != SLOT_COUNT {
            return Err(Error::SlotVerification);
        }
        let mut real_positions = Vec::new();
        for (pos, s) in self.slots.iter().enumerate() {
            let d = dummy_slot(ck, b, u8::try_from(pos).map_err(|_| Error::Internal)?)?;
            if !s.ct_eq(&d) {
                real_positions.push(pos);
            }
        }
        if real_positions.len() != recipient_count {
            return Err(Error::SlotVerification);
        }
        if let Some(p) = own_position
            && !real_positions.contains(&p)
        {
            return Err(Error::SlotVerification);
        }
        Ok(SlotVerification { real_positions })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::arithmetic_side_effects)]
    use super::*;
    use crate::rand::TestRng;

    fn binding() -> SlotBinding {
        SlotBinding {
            suite: Suite::CandorStd1,
            object_id: [1; 16],
            payload_nonce: [2; 16],
            context: SlotContext::MemberEpoch { tenant_id: [3; 16], channel_id: [4; 16], epoch_id: 5 },
        }
    }

    #[test]
    fn build_open_verify() {
        let mut rng = TestRng::new(10);
        let ck = ContentKey::from_bytes([0x11; 32]);
        let members: Vec<KemKeyPair> =
            (0..3).map(|_| KemKeyPair::generate_with(Suite::CandorStd1, &mut rng).unwrap()).collect();
        let pks: Vec<KemPublicKey> = members.iter().map(|m| m.public.clone()).collect();
        let b = binding();
        let blk = RecipientSlotBlock::build_with(&mut rng, &ck, &b, &pks).unwrap();
        let enc = blk.encode();
        assert_eq!(enc.len(), SLOT_BLOCK_LEN);
        assert_eq!(enc.len(), 18_692);
        let blk2 = RecipientSlotBlock::decode(&enc).unwrap();
        assert_eq!(blk2, blk);
        for m in &members {
            let (got, pos) = blk2.trial_open(&m.private, &b).unwrap();
            assert_eq!(got.expose(), ck.expose());
            let v = blk2.verify(&got, &b, 3, Some(pos)).unwrap();
            assert_eq!(v.real_positions.len(), 3);
        }
        // Outsider cannot open.
        let outsider = KemKeyPair::generate_with(Suite::CandorStd1, &mut rng).unwrap();
        assert_eq!(blk2.trial_open(&outsider.private, &b).err(), Some(Error::Authentication));
        // CRYPTO-006: wrong epoch / channel / object binding fails to open.
        let mut wrong = b.clone();
        wrong.context = SlotContext::MemberEpoch { tenant_id: [3; 16], channel_id: [4; 16], epoch_id: 6 };
        assert!(blk2.trial_open(&members[0].private, &wrong).is_err());
        let mut wrong = b.clone();
        wrong.payload_nonce[0] ^= 1;
        assert!(blk2.trial_open(&members[0].private, &wrong).is_err());
    }

    /// §22.2 negative vector: slot block with an unlisted non-dummy slot (hidden recipient).
    #[test]
    fn hidden_recipient_detected() {
        let mut rng = TestRng::new(11);
        let ck = ContentKey::from_bytes([0x22; 32]);
        let a = KemKeyPair::generate_with(Suite::CandorStd1, &mut rng).unwrap();
        let hidden = KemKeyPair::generate_with(Suite::CandorStd1, &mut rng).unwrap();
        let b = binding();
        let blk = RecipientSlotBlock::build_with(&mut rng, &ck, &b, &[a.public.clone(), hidden.public.clone()]).unwrap();
        // Recipient List claims only one recipient.
        assert_eq!(blk.verify(&ck, &b, 1, None).err(), Some(Error::SlotVerification));
        assert!(blk.verify(&ck, &b, 2, None).is_ok());
        // Wrong CK: no slot verifies as dummy.
        let ck2 = ContentKey::from_bytes([0x23; 32]);
        assert!(blk.verify(&ck2, &b, 2, None).is_err());
        // Swapping two slots breaks dummy verification (dummies are position-bound).
        let mut swapped = blk.clone();
        swapped.slots.swap(0, 15);
        swapped.slots.swap(1, 14);
        let _ = swapped.verify(&ck, &b, 2, None); // must not panic; usually Err
    }

    #[test]
    fn all_dummy_block_and_custodian() {
        let mut rng = TestRng::new(12);
        let ck = ContentKey::from_bytes([0x33; 32]);
        let mut b = binding();
        b.context = SlotContext::Custodian { tenant_id: [3; 16] };
        let blk = RecipientSlotBlock::build_with(&mut rng, &ck, &b, &[]).unwrap();
        assert!(blk.verify(&ck, &b, 0, None).unwrap().real_positions.is_empty());
        // Dummy derivation is deterministic.
        assert_eq!(dummy_slot(&ck, &b, 3).unwrap(), dummy_slot(&ck, &b, 3).unwrap());
        assert_ne!(dummy_slot(&ck, &b, 3).unwrap(), dummy_slot(&ck, &b, 4).unwrap());
    }

    #[test]
    fn too_many_recipients() {
        let mut rng = TestRng::new(13);
        let kp = KemKeyPair::generate_with(Suite::CandorStd1, &mut rng).unwrap();
        let pks = vec![kp.public.clone(); 17];
        let r = RecipientSlotBlock::build_with(&mut rng, &ContentKey::from_bytes([0; 32]), &binding(), &pks);
        assert_eq!(r.err(), Some(Error::TooManyRecipients));
    }

    #[test]
    fn decode_rejects() {
        let mut rng = TestRng::new(14);
        let blk = RecipientSlotBlock::build_with(&mut rng, &ContentKey::from_bytes([0; 32]), &binding(), &[]).unwrap();
        let e = blk.encode();
        let mut b = e.clone();
        b[0] = 2;
        assert!(RecipientSlotBlock::decode(&b).is_err());
        let mut b = e.clone();
        b[1] = 15;
        assert!(RecipientSlotBlock::decode(&b).is_err());
        let mut b = e.clone();
        b[3] = 2;
        assert_eq!(RecipientSlotBlock::decode(&b).err(), Some(Error::UnsupportedSuite));
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
