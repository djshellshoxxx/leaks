// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Wrap Stanzas (§13.2): HPKE_BASE, CASE_AEAD and CASEKEY_EK.

use crate::aead::{xchacha_open, xchacha_seal};
use crate::bytes::Reader;
use crate::error::{Error, Result};
use crate::hash::casekey_bound_hash;
use crate::kdf::{ct_eq, derive_case_wrap_key, derive_ek_layer_key};
use crate::kem::{KemPrivateKey, KemPublicKey, open_base, seal_base_with};
use crate::labels;
use crate::rand::{OsRandom, RandomSource};
use crate::secret::{CaseKey, ContentKey, ErasureKey};
use crate::suite::{AEAD_TAG_LEN, CK_LEN, Suite, XWING_NENC};
use zeroize::Zeroizing;

/// Fixed stanza prefix length (type, reserved, suite, recipient_ref, bound_hash, enc_len).
pub const STANZA_FIXED_LEN: usize = 70;
/// Upper bound on `ct_len` accepted by the decoder (resource bound, CRYPTO-053;
/// Implementation decision — every v1 stanza is far smaller).
pub const MAX_STANZA_CT_LEN: usize = 65_536;
/// Record AEAD nonce length (STD).
const XNONCE_LEN: usize = 24;

/// Stanza types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StanzaType {
    /// HPKE base-mode wrap.
    HpkeBase = 0x01,
    /// AEAD wrap of CK under a Case Key.
    CaseAead = 0x02,
    /// HPKE_BASE stanza of a case key inside an Erasure-Key AEAD layer.
    CasekeyEk = 0x03,
}

impl StanzaType {
    fn from_u8(v: u8) -> Result<Self> {
        match v {
            0x01 => Ok(Self::HpkeBase),
            0x02 => Ok(Self::CaseAead),
            0x03 => Ok(Self::CasekeyEk),
            _ => Err(Error::Malformed("stanza_type")),
        }
    }

    fn enc_len(self) -> usize {
        match self {
            Self::HpkeBase => XWING_NENC,
            Self::CaseAead | Self::CasekeyEk => XNONCE_LEN,
        }
    }
}

/// HPKE `info` contexts for HPKE_BASE stanzas (§9.9). All fields are fixed-length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HpkeWrapContext {
    /// Reply CK to the source: `"candor/v1/wrap/reply" ‖ suite ‖ tenant ‖ channel ‖ mailbox_id`.
    Reply {
        /// Tenant.
        tenant_id: [u8; 16],
        /// Channel.
        channel_id: [u8; 16],
        /// Mailbox id.
        mailbox_id: [u8; 32],
    },
    /// Viewer job: `"candor/v1/wrap/viewer-job" ‖ suite ‖ job_id`.
    ViewerJob {
        /// Job id (16 bytes, Implementation decision).
        job_id: [u8; 16],
    },
    /// Case key to K09/K14: `"candor/v1/wrap/casekey" ‖ suite ‖ tenant ‖ case_id ‖ u32 v ‖ recipient_key_id`.
    CaseKey {
        /// Tenant.
        tenant_id: [u8; 16],
        /// Case.
        case_id: [u8; 16],
        /// Case key version.
        version: u32,
        /// Recipient key id.
        recipient_key_id: [u8; 32],
    },
    /// CIK private to K09: `"candor/v1/wrap/channel" ‖ suite ‖ tenant ‖ channel ‖ key_id_of_wrapped ‖ recipient_key_id`.
    Channel {
        /// Tenant.
        tenant_id: [u8; 16],
        /// Channel.
        channel_id: [u8; 16],
        /// Key id of the wrapped key.
        wrapped_key_id: [u8; 32],
        /// Recipient key id.
        recipient_key_id: [u8; 32],
    },
    /// K13 private to a custodian: `"candor/v1/wrap/custodian-group" ‖ suite ‖ tenant ‖ recipient_key_id`.
    CustodianGroup {
        /// Tenant.
        tenant_id: [u8; 16],
        /// Recipient key id.
        recipient_key_id: [u8; 32],
    },
    /// routing_ct to K37: `"candor/v1/wrap/routing" ‖ suite ‖ tenant`.
    Routing {
        /// Tenant.
        tenant_id: [u8; 16],
    },
    /// Export CK to K38/K30: `"candor/v1/wrap/connector" ‖ suite ‖ tenant ‖ connector_id`.
    Connector {
        /// Tenant.
        tenant_id: [u8; 16],
        /// Connector id (16 bytes, Implementation decision).
        connector_id: [u8; 16],
    },
}

impl HpkeWrapContext {
    /// Build the HPKE `info` bytes.
    #[must_use]
    pub fn info(&self, suite: Suite) -> Vec<u8> {
        let s = suite.to_be_bytes();
        use crate::bytes::concat;
        match self {
            Self::Reply { tenant_id, channel_id, mailbox_id } => {
                concat(&[labels::WRAP_REPLY, &s, tenant_id, channel_id, mailbox_id])
            }
            Self::ViewerJob { job_id } => concat(&[labels::WRAP_VIEWER_JOB, &s, job_id]),
            Self::CaseKey { tenant_id, case_id, version, recipient_key_id } => concat(&[
                labels::WRAP_CASEKEY,
                &s,
                tenant_id,
                case_id,
                &version.to_be_bytes(),
                recipient_key_id,
            ]),
            Self::Channel { tenant_id, channel_id, wrapped_key_id, recipient_key_id } => {
                concat(&[labels::WRAP_CHANNEL, &s, tenant_id, channel_id, wrapped_key_id, recipient_key_id])
            }
            Self::CustodianGroup { tenant_id, recipient_key_id } => {
                concat(&[labels::WRAP_CUSTODIAN_GROUP, &s, tenant_id, recipient_key_id])
            }
            Self::Routing { tenant_id } => concat(&[labels::WRAP_ROUTING, &s, tenant_id]),
            Self::Connector { tenant_id, connector_id } => {
                concat(&[labels::WRAP_CONNECTOR, &s, tenant_id, connector_id])
            }
        }
    }
}

/// A Wrap Stanza.
#[derive(Clone, PartialEq, Eq)]
pub struct WrapStanza {
    stanza_type: StanzaType,
    suite: Suite,
    recipient_ref: [u8; 32],
    bound_hash: [u8; 32],
    enc: Vec<u8>,
    ct: Vec<u8>,
}

impl core::fmt::Debug for WrapStanza {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WrapStanza")
            .field("stanza_type", &self.stanza_type)
            .field("suite", &self.suite)
            .finish_non_exhaustive()
    }
}

fn fresh_nonce(rng: &mut dyn RandomSource) -> Result<[u8; XNONCE_LEN]> {
    let mut n = [0u8; XNONCE_LEN];
    rng.fill(&mut n)?;
    Ok(n)
}

fn case_recipient_ref(case_id: &[u8; 16], version: u32) -> [u8; 32] {
    let mut r = [0u8; 32];
    let (a, rest) = r.split_at_mut(16);
    a.copy_from_slice(case_id);
    if let Some(v) = rest.get_mut(..4) {
        v.copy_from_slice(&version.to_be_bytes());
    }
    r
}

fn case_aead_aad(tenant_id: &[u8; 16], case_id: &[u8; 16], version: u32, object_hash: &[u8; 32]) -> Vec<u8> {
    crate::bytes::concat(&[labels::WRAP_CASE, tenant_id, case_id, &version.to_be_bytes(), object_hash])
}

fn ek_layer_aad(tenant_id: &[u8; 16], case_id: &[u8; 16], version: u32, recipient_ref: &[u8; 32]) -> Vec<u8> {
    crate::bytes::concat(&[labels::EK_LAYER, tenant_id, case_id, &version.to_be_bytes(), recipient_ref])
}

impl WrapStanza {
    /// Stanza type.
    #[must_use]
    pub fn stanza_type(&self) -> StanzaType {
        self.stanza_type
    }
    /// Suite.
    #[must_use]
    pub fn suite(&self) -> Suite {
        self.suite
    }
    /// recipient_ref.
    #[must_use]
    pub fn recipient_ref(&self) -> &[u8; 32] {
        &self.recipient_ref
    }
    /// bound_hash.
    #[must_use]
    pub fn bound_hash(&self) -> &[u8; 32] {
        &self.bound_hash
    }

    /// Encode.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let enc_len = u16::try_from(self.enc.len()).map_err(|_| Error::Internal)?;
        let ct_len = u32::try_from(self.ct.len()).map_err(|_| Error::Internal)?;
        let mut v = Vec::with_capacity(
            STANZA_FIXED_LEN.saturating_add(self.enc.len()).saturating_add(4).saturating_add(self.ct.len()),
        );
        v.push(self.stanza_type as u8);
        v.push(0);
        v.extend_from_slice(&self.suite.to_be_bytes());
        v.extend_from_slice(&self.recipient_ref);
        v.extend_from_slice(&self.bound_hash);
        v.extend_from_slice(&enc_len.to_be_bytes());
        v.extend_from_slice(&self.enc);
        v.extend_from_slice(&ct_len.to_be_bytes());
        v.extend_from_slice(&self.ct);
        Ok(v)
    }

    /// Decode and validate (no trailing data, exact enc_len per type, bounded ct_len).
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let stanza_type = StanzaType::from_u8(r.u8()?)?;
        if r.u8()? != 0 {
            return Err(Error::Malformed("stanza reserved"));
        }
        let suite = Suite::from_id_supported(r.u16()?)?;
        let recipient_ref: [u8; 32] = r.array()?;
        let bound_hash: [u8; 32] = r.array()?;
        let enc_len = usize::from(r.u16()?);
        if enc_len != stanza_type.enc_len() {
            return Err(Error::Malformed("enc_len"));
        }
        let enc = r.take(enc_len)?.to_vec();
        let ct_len = usize::try_from(r.u32()?).map_err(|_| Error::Length)?;
        if ct_len > MAX_STANZA_CT_LEN || ct_len < AEAD_TAG_LEN || ct_len != r.remaining() {
            return Err(Error::Malformed("ct_len"));
        }
        let ct = r.take(ct_len)?.to_vec();
        r.finish()?;
        if stanza_type == StanzaType::CaseAead {
            if ct.len() != CK_LEN.saturating_add(AEAD_TAG_LEN) {
                return Err(Error::Malformed("CASE_AEAD ct_len"));
            }
            if recipient_ref.get(20..).is_none_or(|z| z.iter().any(|b| *b != 0)) {
                return Err(Error::Malformed("CASE_AEAD recipient_ref padding"));
            }
        }
        Ok(Self { stanza_type, suite, recipient_ref, bound_hash, enc, ct })
    }

    // ---- HPKE_BASE ----------------------------------------------------------------

    /// HPKE_BASE: `ct = HPKE.SealBase(pkR, info = label ‖ context, aad = bound_hash, pt = key)`.
    /// `recipient_ref` is the recipient key_id, or all-zero for REPLY (enforced).
    pub fn seal_hpke(
        suite: Suite,
        pk: &KemPublicKey,
        recipient_ref: [u8; 32],
        bound_hash: [u8; 32],
        ctx: &HpkeWrapContext,
        pt: &[u8],
    ) -> Result<Self> {
        Self::seal_hpke_with(&mut OsRandom, suite, pk, recipient_ref, bound_hash, ctx, pt)
    }

    pub(crate) fn seal_hpke_with(
        rng: &mut dyn RandomSource,
        suite: Suite,
        pk: &KemPublicKey,
        recipient_ref: [u8; 32],
        bound_hash: [u8; 32],
        ctx: &HpkeWrapContext,
        pt: &[u8],
    ) -> Result<Self> {
        suite.require_supported()?;
        if matches!(ctx, HpkeWrapContext::Reply { .. }) && recipient_ref != [0u8; 32] {
            return Err(Error::Malformed("REPLY stanza recipient_ref must be zero"));
        }
        let (enc, ct) = seal_base_with(rng, pk, &ctx.info(suite), &bound_hash, pt)?;
        Ok(Self { stanza_type: StanzaType::HpkeBase, suite, recipient_ref, bound_hash, enc, ct })
    }

    /// Open an HPKE_BASE stanza. `expected_bound_hash` (e.g. the object_hash of the
    /// object being opened) is compared in constant time first, so a stanza bound to
    /// another object is rejected.
    pub fn open_hpke(
        &self,
        sk: &KemPrivateKey,
        ctx: &HpkeWrapContext,
        expected_bound_hash: &[u8; 32],
    ) -> Result<Zeroizing<Vec<u8>>> {
        if self.stanza_type != StanzaType::HpkeBase {
            return Err(Error::Malformed("not an HPKE_BASE stanza"));
        }
        if !ct_eq(&self.bound_hash, expected_bound_hash) {
            return Err(Error::Authentication);
        }
        open_base(sk, &self.enc, &ctx.info(self.suite), &self.bound_hash, &self.ct)
    }

    /// Wrap a content key with HPKE_BASE.
    pub fn seal_hpke_ck(
        suite: Suite,
        pk: &KemPublicKey,
        recipient_ref: [u8; 32],
        object_hash: [u8; 32],
        ctx: &HpkeWrapContext,
        ck: &ContentKey,
    ) -> Result<Self> {
        Self::seal_hpke(suite, pk, recipient_ref, object_hash, ctx, ck.expose())
    }

    /// Unwrap a content key from an HPKE_BASE stanza.
    pub fn open_hpke_ck(&self, sk: &KemPrivateKey, ctx: &HpkeWrapContext, object_hash: &[u8; 32]) -> Result<ContentKey> {
        let pt = self.open_hpke(sk, ctx, object_hash)?;
        ContentKey::from_slice(&pt).map_err(|_| Error::Authentication)
    }

    /// HPKE_BASE wrap of a Case Key to a member K09 / K14 (inner layer of CASEKEY_EK).
    pub fn wrap_case_key(
        suite: Suite,
        pk: &KemPublicKey,
        recipient_key_id: [u8; 32],
        tenant_id: [u8; 16],
        case_id: [u8; 16],
        version: u32,
        case_key: &CaseKey,
    ) -> Result<Self> {
        let ctx = HpkeWrapContext::CaseKey { tenant_id, case_id, version, recipient_key_id };
        Self::seal_hpke(suite, pk, recipient_key_id, casekey_bound_hash(&case_id, version), &ctx, case_key.expose())
    }

    /// Unwrap a Case Key from its HPKE_BASE stanza.
    pub fn unwrap_case_key(
        &self,
        sk: &KemPrivateKey,
        tenant_id: [u8; 16],
        case_id: [u8; 16],
        version: u32,
    ) -> Result<CaseKey> {
        let ctx = HpkeWrapContext::CaseKey { tenant_id, case_id, version, recipient_key_id: self.recipient_ref };
        let pt = self.open_hpke(sk, &ctx, &casekey_bound_hash(&case_id, version))?;
        CaseKey::from_slice(&pt).map_err(|_| Error::Authentication)
    }

    // ---- CASE_AEAD ----------------------------------------------------------------

    /// CASE_AEAD: `ct = AEAD(K = HKDF(CaseKey_v, "candor/v1/case", "candor/v1/wrap/case"), nonce = enc,
    /// aad = "candor/v1/wrap/case" ‖ tenant ‖ case_id ‖ u32 v ‖ object_hash, pt = CK)`.
    pub fn seal_case_aead(
        case_key: &CaseKey,
        tenant_id: [u8; 16],
        case_id: [u8; 16],
        version: u32,
        object_hash: [u8; 32],
        ck: &ContentKey,
    ) -> Result<Self> {
        Self::seal_case_aead_with(&mut OsRandom, case_key, tenant_id, case_id, version, object_hash, ck)
    }

    pub(crate) fn seal_case_aead_with(
        rng: &mut dyn RandomSource,
        case_key: &CaseKey,
        tenant_id: [u8; 16],
        case_id: [u8; 16],
        version: u32,
        object_hash: [u8; 32],
        ck: &ContentKey,
    ) -> Result<Self> {
        let k = derive_case_wrap_key(case_key)?;
        let nonce = fresh_nonce(rng)?;
        let ct = xchacha_seal(&k, &nonce, &case_aead_aad(&tenant_id, &case_id, version, &object_hash), ck.expose())?;
        Ok(Self {
            stanza_type: StanzaType::CaseAead,
            suite: Suite::CandorStd1,
            recipient_ref: case_recipient_ref(&case_id, version),
            bound_hash: object_hash,
            enc: nonce.to_vec(),
            ct,
        })
    }

    /// Open a CASE_AEAD stanza for `(case_id, version)` and the expected object hash.
    pub fn open_case_aead(
        &self,
        case_key: &CaseKey,
        tenant_id: [u8; 16],
        case_id: [u8; 16],
        version: u32,
        object_hash: &[u8; 32],
    ) -> Result<ContentKey> {
        if self.stanza_type != StanzaType::CaseAead {
            return Err(Error::Malformed("not a CASE_AEAD stanza"));
        }
        if self.recipient_ref != case_recipient_ref(&case_id, version) || !ct_eq(&self.bound_hash, object_hash) {
            return Err(Error::Authentication);
        }
        let nonce: [u8; XNONCE_LEN] = self.enc.as_slice().try_into().map_err(|_| Error::Length)?;
        let k = derive_case_wrap_key(case_key)?;
        let pt = xchacha_open(&k, &nonce, &case_aead_aad(&tenant_id, &case_id, version, object_hash), &self.ct)?;
        ContentKey::from_slice(&pt).map_err(|_| Error::Authentication)
    }

    // ---- CASEKEY_EK ---------------------------------------------------------------

    /// CASEKEY_EK: AEAD of an HPKE_BASE case-key stanza under the case Erasure Key.
    /// Only an HPKE_BASE stanza of a case key can be layered (§9.10: no API encrypts a
    /// raw case key under an EK).
    pub fn seal_casekey_ek(
        ek: &ErasureKey,
        tenant_id: [u8; 16],
        case_id: [u8; 16],
        version: u32,
        inner: &WrapStanza,
    ) -> Result<Self> {
        Self::seal_casekey_ek_with(&mut OsRandom, ek, tenant_id, case_id, version, inner)
    }

    pub(crate) fn seal_casekey_ek_with(
        rng: &mut dyn RandomSource,
        ek: &ErasureKey,
        tenant_id: [u8; 16],
        case_id: [u8; 16],
        version: u32,
        inner: &WrapStanza,
    ) -> Result<Self> {
        let bound = casekey_bound_hash(&case_id, version);
        if inner.stanza_type != StanzaType::HpkeBase || inner.bound_hash != bound {
            return Err(Error::Malformed("CASEKEY_EK inner must be an HPKE_BASE case-key stanza"));
        }
        let k = derive_ek_layer_key(ek, &case_id)?;
        let nonce = fresh_nonce(rng)?;
        let aad = ek_layer_aad(&tenant_id, &case_id, version, &inner.recipient_ref);
        let ct = xchacha_seal(&k, &nonce, &aad, &inner.encode()?)?;
        Ok(Self {
            stanza_type: StanzaType::CasekeyEk,
            suite: inner.suite,
            recipient_ref: inner.recipient_ref,
            bound_hash: bound,
            enc: nonce.to_vec(),
            ct,
        })
    }

    /// Remove the Erasure-Key layer and return the inner HPKE_BASE stanza. Rejects an
    /// inner plaintext that is not a parseable HPKE_BASE case-key stanza (§22.2
    /// negative vector `ek_direct_wrap`).
    pub fn open_casekey_ek(&self, ek: &ErasureKey, tenant_id: [u8; 16], case_id: [u8; 16], version: u32) -> Result<WrapStanza> {
        if self.stanza_type != StanzaType::CasekeyEk {
            return Err(Error::Malformed("not a CASEKEY_EK stanza"));
        }
        let bound = casekey_bound_hash(&case_id, version);
        if self.bound_hash != bound {
            return Err(Error::Authentication);
        }
        let nonce: [u8; XNONCE_LEN] = self.enc.as_slice().try_into().map_err(|_| Error::Length)?;
        let k = derive_ek_layer_key(ek, &case_id)?;
        let aad = ek_layer_aad(&tenant_id, &case_id, version, &self.recipient_ref);
        let pt = xchacha_open(&k, &nonce, &aad, &self.ct)?;
        let inner = WrapStanza::decode(&pt).map_err(|_| Error::Malformed("ek_direct_wrap"))?;
        if inner.stanza_type != StanzaType::HpkeBase
            || inner.recipient_ref != self.recipient_ref
            || inner.bound_hash != bound
            || inner.suite != self.suite
        {
            return Err(Error::Malformed("ek_direct_wrap"));
        }
        Ok(inner)
    }

    /// Test-only constructor for negative vectors (e.g. `ek_direct_wrap`).
    #[cfg(test)]
    pub(crate) fn raw(stanza_type: StanzaType, recipient_ref: [u8; 32], bound_hash: [u8; 32], enc: Vec<u8>, ct: Vec<u8>) -> Self {
        Self { stanza_type, suite: Suite::CandorStd1, recipient_ref, bound_hash, enc, ct }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use crate::hash::{KeyKind, key_id};
    use crate::kem::KemKeyPair;
    use crate::rand::TestRng;

    const T: [u8; 16] = [1; 16];
    const C: [u8; 16] = [2; 16];

    #[test]
    fn hpke_reply_roundtrip_and_binding() {
        let mut rng = TestRng::new(20);
        let kp = KemKeyPair::generate_with(Suite::CandorStd1, &mut rng).unwrap();
        let ck = ContentKey::from_bytes([5; 32]);
        let ctx = HpkeWrapContext::Reply { tenant_id: T, channel_id: [0; 16], mailbox_id: [7; 32] };
        let oh = [9u8; 32];
        let s = WrapStanza::seal_hpke_with(&mut rng, Suite::CandorStd1, &kp.public, [0; 32], oh, &ctx, ck.expose()).unwrap();
        let bytes = s.encode().unwrap();
        assert_eq!(bytes.len(), 70 + 1120 + 4 + 48);
        let s2 = WrapStanza::decode(&bytes).unwrap();
        assert_eq!(s2.open_hpke_ck(&kp.private, &ctx, &oh).unwrap().expose(), ck.expose());
        // stanza bound to another object
        assert!(s2.open_hpke_ck(&kp.private, &ctx, &[8; 32]).is_err());
        // a mismatching mailbox simply fails to open (§11.5)
        let other = HpkeWrapContext::Reply { tenant_id: T, channel_id: [0; 16], mailbox_id: [6; 32] };
        assert!(s2.open_hpke_ck(&kp.private, &other, &oh).is_err());
        // REPLY recipient_ref must be zero
        assert!(WrapStanza::seal_hpke_with(&mut rng, Suite::CandorStd1, &kp.public, [1; 32], oh, &ctx, ck.expose()).is_err());
    }

    #[test]
    fn case_aead_roundtrip_and_binding() {
        let mut rng = TestRng::new(21);
        let case_key = CaseKey::from_bytes([3; 32]);
        let ck = ContentKey::from_bytes([4; 32]);
        let oh = [5u8; 32];
        let s = WrapStanza::seal_case_aead_with(&mut rng, &case_key, T, C, 7, oh, &ck).unwrap();
        let s = WrapStanza::decode(&s.encode().unwrap()).unwrap();
        assert_eq!(s.open_case_aead(&case_key, T, C, 7, &oh).unwrap().expose(), ck.expose());
        // CRYPTO-011: moved between cases/tenants/versions/objects fails.
        assert!(s.open_case_aead(&case_key, [9; 16], C, 7, &oh).is_err());
        assert!(s.open_case_aead(&case_key, T, [9; 16], 7, &oh).is_err());
        assert!(s.open_case_aead(&case_key, T, C, 8, &oh).is_err());
        assert!(s.open_case_aead(&case_key, T, C, 7, &[6; 32]).is_err());
        assert!(s.open_case_aead(&CaseKey::from_bytes([0; 32]), T, C, 7, &oh).is_err());
    }

    #[test]
    fn casekey_ek_roundtrip_and_ek_direct_wrap() {
        let mut rng = TestRng::new(22);
        let member = KemKeyPair::generate_with(Suite::CandorStd1, &mut rng).unwrap();
        let kid = key_id(Suite::CandorStd1, KeyKind::UserEnc, &member.public.to_bytes());
        let case_key = CaseKey::from_bytes([6; 32]);
        let ek = ErasureKey::from_bytes([7; 32]);
        let inner = {
            let ctx = HpkeWrapContext::CaseKey { tenant_id: T, case_id: C, version: 1, recipient_key_id: kid };
            WrapStanza::seal_hpke_with(&mut rng, Suite::CandorStd1, &member.public, kid, casekey_bound_hash(&C, 1), &ctx, case_key.expose()).unwrap()
        };
        let outer = WrapStanza::seal_casekey_ek_with(&mut rng, &ek, T, C, 1, &inner).unwrap();
        let outer = WrapStanza::decode(&outer.encode().unwrap()).unwrap();
        let got_inner = outer.open_casekey_ek(&ek, T, C, 1).unwrap();
        assert_eq!(got_inner, inner);
        assert_eq!(got_inner.unwrap_case_key(&member.private, T, C, 1).unwrap().expose(), case_key.expose());
        assert!(outer.open_casekey_ek(&ErasureKey::from_bytes([8; 32]), T, C, 1).is_err());
        assert!(outer.open_casekey_ek(&ek, T, C, 2).is_err());

        // ek_direct_wrap: an EK-layer whose plaintext is a raw case key is rejected.
        let k = derive_ek_layer_key(&ek, &C).unwrap();
        let nonce = [1u8; 24];
        let ct = xchacha_seal(&k, &nonce, &ek_layer_aad(&T, &C, 1, &kid), case_key.expose()).unwrap();
        let direct = WrapStanza::raw(StanzaType::CasekeyEk, kid, casekey_bound_hash(&C, 1), nonce.to_vec(), ct);
        assert_eq!(direct.open_casekey_ek(&ek, T, C, 1).err(), Some(Error::Malformed("ek_direct_wrap")));
        // Sealing API refuses a non-HPKE inner stanza.
        let case_aead = WrapStanza::seal_case_aead_with(&mut rng, &case_key, T, C, 1, [0; 32], &ContentKey::from_bytes([0; 32])).unwrap();
        assert!(WrapStanza::seal_casekey_ek_with(&mut rng, &ek, T, C, 1, &case_aead).is_err());
    }

    #[test]
    fn decode_rejects() {
        let mut rng = TestRng::new(23);
        let s = WrapStanza::seal_case_aead_with(&mut rng, &CaseKey::from_bytes([3; 32]), T, C, 7, [5; 32], &ContentKey::from_bytes([4; 32])).unwrap();
        let e = s.encode().unwrap();
        for (off, val) in [(0usize, 0u8), (0, 4), (1, 1), (3, 2), (3, 3), (69, 23), (68, 1)] {
            let mut b = e.clone();
            b[off] = val;
            assert!(WrapStanza::decode(&b).is_err(), "offset {off}");
        }
        // CASE_AEAD recipient_ref padding must be zero (offset 4 + 20).
        let mut b = e.clone();
        b[4 + 20] = 1;
        assert!(WrapStanza::decode(&b).is_err());
        assert!(WrapStanza::decode(&e[..e.len() - 1]).is_err());
        let mut b = e.clone();
        b.push(0);
        assert!(WrapStanza::decode(&b).is_err());
    }

    proptest::proptest! {
        #[test]
        fn decode_arbitrary_never_panics(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..400)) {
            if let Ok(s) = WrapStanza::decode(&bytes) {
                proptest::prop_assert_eq!(s.encode().unwrap(), bytes);
            }
        }
    }
}
