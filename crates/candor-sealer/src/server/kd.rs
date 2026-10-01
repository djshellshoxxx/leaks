// SPDX-License-Identifier: AGPL-3.0-or-later
//! Key Directory entry verification (04 §14.2, §14.4, §14.5 VR-1/VR-4/VR-6/
//! VR-11/VR-12; ADR-036; AUD-RM2-SEA-19).
//!
//! The sealer derives everything it seals to — roster members, Triage Set
//! flags, role labels and their certificates, COI policies, Member Epoch Keys,
//! K13, K41 and the witness policy — from the **complete** directory log whose
//! Merkle root equals the signed checkpoint's root (VR-4 "full-tree
//! recomputation", see `directory.rs`). Every entry is parsed strictly and
//! checked here, in leaf order, against the keys established by earlier
//! leaves:
//!
//! | entry | required signatures (Ed25519 halves) |
//! |---|---|
//! | ORG_ROOT | self; seq > 1 also the previous K01 (rotation); the pinned K01 must be in the chain (VR-1) |
//! | LOG_KEY, KEY_ADMIN, CUSTODIAN_GROUP, DISPOSITION_KEY, GOVERNANCE_ROLES | current K01 |
//! | USER_KEYS | the user's own K08 + 1 K15 + the out-of-band verifier's K08 (a different user, not that K15 holder) — or K01 for the first users (bootstrap) |
//! | CHANNEL_IDENTITY | seq 1: a user K08 (creator) + 2 distinct K15 + 1 OVERSIGHT K08; seq > 1: previous CIK + 1 K15; orphan: K01 + 2 K15 + 1 OVERSIGHT K08 and a 7-day time lock |
//! | CHANNEL_ROSTER, COI_POLICY | the channel's current CIK + 1 K15; loosening (recomputed, not trusted from `change_class`) also an independent-role K08 not held by that K15 holder, and the time lock |
//! | MEMBER_EPOCH | the member's current K08 (ADR-030) |
//! | ROLE_LABEL_CERT | an OVERSIGHT member's K08 (GOVERNANCE_ROLES, ADR-036(3)) |
//! | OBJECTION | resolution: 2 distinct OVERSIGHT K08; an objection itself only blocks activation, so it is honoured whoever signed it (fail-safe) |
//! | REVOCATION | honoured whoever signed it: it can only remove keys (fail-safe) |
//!
//! Continuity (§14.4 rule 1) is enforced for every entry of every type per
//! `(entry_type, subject_id)`. Any entry that fails is fatal for the whole
//! snapshot (a log that contains an invalid entry is evidence of compromise;
//! fail closed, §12.6). ML-DSA-65 halves of hybrid signatures are **not**
//! verified (no ML-DSA in `candor-core`; see SPEC-NOTES).
//!
//! The CBOR body layouts (field numbers) and the subject-id derivations are
//! implementation decisions documented in SPEC-NOTES ("Key Directory entry
//! encoding"); 04 §14.2 names the fields but not their numbers.

use std::collections::BTreeMap;

use super::directory::{
    ChannelView, CoiPolicy, MemberEpochKey, RosterMember, RosterVersion, SnapshotError,
    UserKeyEntry, WitnessKey,
};
use super::merkle::leaf_hash;
use crate::proto::cbor::{CborError, Dec, MapKeys};
use candor_core::Suite;
use candor_core::hash::{KeyKind, key_id, sha256};
use candor_core::sig::verify_strict;

/// Signing context of a KD entry (04 §14.2).
pub const SIG_CONTEXT: &[u8] = b"candor/v1/kd-entry\x00";
/// Maximum `entry_bytes` (VR-12).
pub const MAX_ENTRY_BYTES: usize = 64 * 1024;
/// Maximum SignedKDEntry (entry plus at most [`MAX_SIGS`] signatures).
pub const MAX_SIGNED_ENTRY_BYTES: usize = 128 * 1024;
/// Maximum log size per snapshot (VR-12).
pub const MAX_LOG_ENTRIES: usize = 1_000_000;
/// Maximum total bytes of all entries in one snapshot.
pub const MAX_LOG_BYTES: usize = 512 * 1024 * 1024;
/// Maximum signatures per entry.
pub const MAX_SIGS: usize = 8;
/// Minimum time lock for loosening roster / COI entries (ADR-036(2)): 3 days.
pub const MIN_TIMELOCK_DAYS: u32 = 3;
/// Minimum time lock for orphan CHANNEL_IDENTITY entries (§14.4 rule 7): 7 days.
pub const MIN_ORPHAN_TIMELOCK_DAYS: u32 = 7;

/// Signature algorithms (04 §14.2).
pub mod alg {
    /// Ed25519 (`signer_key_id` = the 32-byte public key).
    pub const ED25519: u64 = 1;
    /// ML-DSA-65 (not verifiable by the sealer yet).
    pub const ML_DSA_65: u64 = 2;
    /// ECDSA-P384 (not used by any rule the sealer checks).
    pub const ECDSA_P384: u64 = 3;
}

/// Entry types (04 §14.2).
#[allow(missing_docs)]
pub mod ty {
    pub const ORG_ROOT: u8 = 0x01;
    pub const LOG_KEY: u8 = 0x02;
    pub const KEY_ADMIN: u8 = 0x03;
    pub const USER_KEYS: u8 = 0x04;
    pub const CHANNEL_IDENTITY: u8 = 0x05;
    pub const CHANNEL_ROSTER: u8 = 0x06;
    pub const MEMBER_EPOCH: u8 = 0x07;
    pub const CUSTODIAN_GROUP: u8 = 0x08;
    pub const REVOCATION: u8 = 0x0C;
    pub const COI_POLICY: u8 = 0x0F;
    pub const ROLE_LABEL_CERT: u8 = 0x10;
    pub const GOVERNANCE_ROLES: u8 = 0x11;
    pub const OBJECTION: u8 = 0x12;
    pub const DISPOSITION_KEY: u8 = 0x1A;
    /// Highest defined type.
    pub const MAX: u8 = 0x1B;
}

/// Roster capability bits (`caps`, 04 §14.2 CHANNEL_ROSTER member).
pub mod caps {
    /// `read_intake` (Triage Set).
    pub const READ_INTAKE: u64 = 1;
    /// `channel_admin`.
    pub const CHANNEL_ADMIN: u64 = 2;
    /// `investigate`.
    pub const INVESTIGATE: u64 = 4;
}

const SUBJECT_MEMBER_EPOCH: &[u8] = b"candor/v1/kd-subject/member-epoch";
const SUBJECT_ROLE_LABEL: &[u8] = b"candor/v1/kd-subject/role-label";
const SUBJECT_OBJECTION: &[u8] = b"candor/v1/kd-subject/objection";

/// `subject_id` of a MEMBER_EPOCH entry: `H(label ‖ channel ‖ user ‖ u32be epoch)`.
#[must_use]
pub fn member_epoch_subject(channel: &[u8; 16], user: &[u8; 16], epoch: u32) -> [u8; 32] {
    sha256(&[SUBJECT_MEMBER_EPOCH, channel, user, &epoch.to_be_bytes()])
}

/// `subject_id` of a ROLE_LABEL_CERT entry: `H(label ‖ channel ‖ u16be role_label)`.
#[must_use]
pub fn role_label_subject(channel: &[u8; 16], role_label: u16) -> [u8; 32] {
    sha256(&[SUBJECT_ROLE_LABEL, channel, &role_label.to_be_bytes()])
}

/// `subject_id` of an OBJECTION entry: `H(label ‖ channel ‖ objected entry hash)`.
#[must_use]
pub fn objection_subject(channel: &[u8; 16], objected: &[u8; 32]) -> [u8; 32] {
    sha256(&[SUBJECT_OBJECTION, channel, objected])
}

/// The message an entry signature covers: `"candor/v1/kd-entry\0" ‖ entry_bytes`.
#[must_use]
pub fn signing_message(entry_bytes: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(SIG_CONTEXT.len().saturating_add(entry_bytes.len()));
    m.extend_from_slice(SIG_CONTEXT);
    m.extend_from_slice(entry_bytes);
    m
}

/// Entry hash: the Merkle leaf hash of the SignedKDEntry bytes (04 §14.2). It
/// is what `prev_subject_entry_hash`, roster `user_keys_entry_hash` and the
/// Recipient List refer to.
#[must_use]
pub fn entry_hash(signed_entry: &[u8]) -> [u8; 32] {
    leaf_hash(signed_entry)
}

/// What the verifier needs besides the log.
pub(crate) struct VerifyCtx<'a> {
    pub tenant_id: [u8; 16],
    pub suite: Suite,
    pub deployment_salt: &'a [u8; 32],
    /// K01 pinned at install (VR-1).
    pub pinned_k01: &'a [u8; 32],
    /// Leaves at index ≥ this were appended after the high-water-mark
    /// checkpoint was issued, i.e. on or after `hwm_issued_day`.
    pub hwm_tree_size: u64,
    pub hwm_issued_day: u32,
}

/// What the verified log yields.
pub(crate) struct LogView {
    pub log_key: [u8; 32],
    pub witnesses: Vec<WitnessKey>,
    pub w_total: usize,
    pub w_external: usize,
    pub custodian_pk: Vec<u8>,
    pub disposition_pk: Vec<u8>,
    pub channels: Vec<ChannelView>,
    pub user_keys: Vec<UserKeyEntry>,
}

fn bad<E>(_: E) -> SnapshotError {
    SnapshotError::Entry
}

fn need(ok: bool) -> Result<(), SnapshotError> {
    if ok {
        Ok(())
    } else {
        Err(SnapshotError::Entry)
    }
}

// ---------------------------------------------------------------------------
// Parsing

struct Header<'a> {
    ty: u8,
    subject: &'a [u8],
    seq: u64,
    prev: Option<[u8; 32]>,
    not_before: u32,
    suite: u16,
}

/// A SignedKDEntry with its verified Ed25519 signers.
struct Signed<'a> {
    hash: [u8; 32],
    entry: &'a [u8],
    signers: Vec<[u8; 32]>,
}

impl Signed<'_> {
    fn has(&self, pk: &[u8; 32]) -> bool {
        self.signers.iter().any(|s| s == pk)
    }
}

fn parse_signed(bytes: &[u8]) -> Result<Signed<'_>, SnapshotError> {
    if bytes.len() > MAX_SIGNED_ENTRY_BYTES {
        return Err(SnapshotError::Entry);
    }
    let mut d = Dec::new(bytes);
    let mut m = d.map(2).map_err(bad)?;
    d.req(&mut m, 1).map_err(bad)?;
    let entry = d.bytes(MAX_ENTRY_BYTES).map_err(bad)?;
    d.req(&mut m, 2).map_err(bad)?;
    let n = d.array(MAX_SIGS).map_err(bad)?;
    need(n >= 1)?;
    let msg = signing_message(entry);
    let mut signers: Vec<[u8; 32]> = Vec::with_capacity(n);
    for _ in 0..n {
        let mut s = d.map(3).map_err(bad)?;
        d.req(&mut s, 1).map_err(bad)?;
        let key = d.bytes(64).map_err(bad)?;
        d.req(&mut s, 2).map_err(bad)?;
        let a = d.uint_max(alg::ECDSA_P384).map_err(bad)?;
        d.req(&mut s, 3).map_err(bad)?;
        let sig = d.bytes(4_096).map_err(bad)?;
        d.end_map(s).map_err(bad)?;
        match a {
            alg::ED25519 => {
                let pk: [u8; 32] = key.try_into().map_err(bad)?;
                let sig: [u8; 64] = sig.try_into().map_err(bad)?;
                // An invalid signature anywhere in the log is fatal.
                verify_strict(&pk, &msg, &sig).map_err(bad)?;
                if !signers.contains(&pk) {
                    signers.push(pk);
                }
            }
            alg::ML_DSA_65 | alg::ECDSA_P384 => {}
            _ => return Err(SnapshotError::Entry),
        }
    }
    d.end_map(m).map_err(bad)?;
    d.finish().map_err(bad)?;
    Ok(Signed {
        hash: entry_hash(bytes),
        entry,
        signers,
    })
}

fn parse_header<'a>(
    d: &mut Dec<'a>,
    m: &mut MapKeys,
    tenant: &[u8; 16],
) -> Result<Header<'a>, CborError> {
    d.req(m, 1)?;
    let ty = d.u8()?;
    d.req(m, 2)?;
    if d.uint()? != 1 {
        return Err(CborError::Limit);
    }
    d.req(m, 3)?;
    if &d.bytes_n::<16>()? != tenant {
        return Err(CborError::Limit);
    }
    d.req(m, 4)?;
    let subject = d.bytes(32)?;
    if subject.len() != 16 && subject.len() != 32 {
        return Err(CborError::Limit);
    }
    d.req(m, 5)?;
    let seq = d.uint()?;
    d.req(m, 6)?;
    let prev = if d.null()? {
        None
    } else {
        Some(d.bytes_n::<32>()?)
    };
    d.req(m, 7)?;
    let not_before = d.u32()?;
    d.req(m, 8)?;
    if !d.null()? {
        d.u32()?;
    }
    d.req(m, 9)?;
    let suite = d.u16()?;
    d.req(m, 10)?;
    Ok(Header {
        ty,
        subject,
        seq,
        prev,
        not_before,
        suite,
    })
}

fn u16_array(d: &mut Dec<'_>, max: usize) -> Result<Vec<u16>, CborError> {
    let n = d.array(max)?;
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(d.u16()?);
    }
    Ok(v)
}

fn hash_array(d: &mut Dec<'_>, max: usize) -> Result<Vec<[u8; 32]>, CborError> {
    let n = d.array(max)?;
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(d.bytes_n::<32>()?);
    }
    Ok(v)
}

fn opt_bytes16(d: &mut Dec<'_>) -> Result<Option<[u8; 16]>, CborError> {
    if d.null()? {
        Ok(None)
    } else {
        Ok(Some(d.bytes_n::<16>()?))
    }
}

struct OrgRoot {
    pk: [u8; 32],
    suites: Vec<u16>,
    salt: [u8; 32],
    witnesses: Vec<WitnessKey>,
    w_total: u64,
    w_external: u64,
}

fn body_org_root(d: &mut Dec<'_>) -> Result<OrgRoot, CborError> {
    let mut m = d.map(9)?;
    d.req(&mut m, 1)?;
    let pk = d.bytes_n::<32>()?;
    d.req(&mut m, 2)?;
    d.bytes(4_096)?; // ML-DSA-65 public key (not used)
    d.req(&mut m, 3)?;
    let suites = u16_array(d, 8)?;
    d.req(&mut m, 4)?;
    let salt = d.bytes_n::<32>()?;
    d.req(&mut m, 5)?;
    d.uint()?; // kdf_version
    d.req(&mut m, 6)?;
    let n = d.array(32)?;
    let mut witnesses = Vec::with_capacity(n);
    for _ in 0..n {
        let mut w = d.map(6)?;
        d.req(&mut w, 1)?;
        d.text(128)?;
        d.req(&mut w, 2)?;
        let pk = d.bytes_n::<32>()?;
        d.req(&mut w, 3)?;
        let role = d.uint_max(1)?;
        d.req(&mut w, 4)?;
        let external_org = d.bool()?;
        d.req(&mut w, 5)?;
        d.bool()?;
        d.req(&mut w, 6)?;
        d.text(256)?;
        d.end_map(w)?;
        // Only witnesses cosign checkpoints; watchers do not count (VR-2).
        if role == 0 {
            witnesses.push(WitnessKey {
                pk,
                external: external_org,
            });
        }
    }
    d.req(&mut m, 7)?;
    let w_total = d.uint_max(32)?;
    d.req(&mut m, 8)?;
    let w_external = d.uint_max(32)?;
    d.req(&mut m, 9)?;
    d.uint()?; // policy flags
    d.end_map(m)?;
    Ok(OrgRoot {
        pk,
        suites,
        salt,
        witnesses,
        w_total,
        w_external,
    })
}

/// `{1: pk (32), 2: <field>}` bodies (LOG_KEY, KEY_ADMIN).
fn body_pk_and<T>(
    d: &mut Dec<'_>,
    second: impl FnOnce(&mut Dec<'_>) -> Result<T, CborError>,
) -> Result<([u8; 32], T), CborError> {
    let mut m = d.map(2)?;
    d.req(&mut m, 1)?;
    let pk = d.bytes_n::<32>()?;
    d.req(&mut m, 2)?;
    let t = second(d)?;
    d.end_map(m)?;
    Ok((pk, t))
}

struct UserKeys {
    k08: [u8; 32],
    key_ids: Vec<Vec<u8>>,
    oob_verified_by: [u8; 16],
    authenticators: u64,
}

fn body_user_keys(d: &mut Dec<'_>) -> Result<UserKeys, CborError> {
    let mut m = d.map(9)?;
    d.req(&mut m, 1)?;
    let k08 = d.bytes_n::<32>()?;
    d.req(&mut m, 2)?;
    d.bytes(4_096)?; // K09
    d.req(&mut m, 3)?;
    let n = d.array(8)?;
    let mut key_ids = Vec::with_capacity(n);
    for _ in 0..n {
        key_ids.push(d.bytes(32)?.to_vec());
    }
    d.req(&mut m, 4)?;
    d.text(128)?;
    d.req(&mut m, 5)?;
    d.uint()?;
    d.req(&mut m, 6)?;
    let authenticators = d.uint()?;
    d.req(&mut m, 7)?;
    hash_array(d, 16)?;
    d.req(&mut m, 8)?;
    d.uint()?;
    d.req(&mut m, 9)?;
    let oob_verified_by = d.bytes_n::<16>()?;
    d.end_map(m)?;
    Ok(UserKeys {
        k08,
        key_ids,
        oob_verified_by,
        authenticators,
    })
}

fn body_channel_identity(d: &mut Dec<'_>) -> Result<([u8; 32], bool, u32), CborError> {
    let mut m = d.map(3)?;
    d.req(&mut m, 1)?;
    let pk = d.bytes_n::<32>()?;
    d.req(&mut m, 2)?;
    let orphan = d.bool()?;
    d.req(&mut m, 3)?;
    let activation = d.u32()?;
    d.end_map(m)?;
    Ok((pk, orphan, activation))
}

struct RawMember {
    user_id: [u8; 16],
    user_keys_hash: [u8; 32],
    role_label: u16,
    cert_hash: [u8; 32],
    caps: u64,
}

struct Roster {
    version: u64,
    activation: u32,
    declared_loosening: bool,
    members: Vec<RawMember>,
    independent_route: Option<[u8; 16]>,
}

/// Members per roster entry (Triage Set ≤ 16 persons plus other roles).
const MAX_ROSTER_MEMBERS: usize = 256;

fn body_roster(d: &mut Dec<'_>) -> Result<Roster, CborError> {
    let mut m = d.map(9)?;
    d.req(&mut m, 1)?;
    let version = d.uint()?;
    d.req(&mut m, 2)?;
    let activation = d.u32()?;
    d.req(&mut m, 3)?;
    let declared_loosening = d.uint_max(1)? == 1;
    d.req(&mut m, 4)?;
    let n = d.array(MAX_ROSTER_MEMBERS)?;
    let mut members = Vec::with_capacity(n);
    for _ in 0..n {
        let mut e = d.map(6)?;
        d.req(&mut e, 1)?;
        let user_id = d.bytes_n::<16>()?;
        d.req(&mut e, 2)?;
        let user_keys_hash = d.bytes_n::<32>()?;
        d.req(&mut e, 3)?;
        let role_label = d.u16()?;
        d.req(&mut e, 4)?;
        let cert_hash = d.bytes_n::<32>()?;
        d.req(&mut e, 5)?;
        let caps = d.uint_max(7)?;
        d.req(&mut e, 6)?;
        d.u32()?; // member_since_day
        d.end_map(e)?;
        members.push(RawMember {
            user_id,
            user_keys_hash,
            role_label,
            cert_hash,
            caps,
        });
    }
    d.req(&mut m, 5)?;
    d.uint_max(1)?; // channel_type
    d.req(&mut m, 6)?;
    let independent_route = opt_bytes16(d)?;
    d.req(&mut m, 7)?;
    let mut r = d.map(3)?;
    d.req(&mut r, 1)?;
    d.bool()?;
    d.req(&mut r, 2)?;
    if !d.null()? {
        d.bytes_n::<32>()?;
    }
    d.req(&mut r, 3)?;
    u16_array(d, 16)?;
    d.end_map(r)?;
    d.req(&mut m, 8)?;
    d.bytes_n::<32>()?; // custodian_entry_hash
    d.req(&mut m, 9)?;
    d.bool()?; // names_published
    d.end_map(m)?;
    Ok(Roster {
        version,
        activation,
        declared_loosening,
        members,
        independent_route,
    })
}

struct MekBody {
    channel: [u8; 16],
    user: [u8; 16],
    epoch: u32,
    pk: Vec<u8>,
    key_id: [u8; 32],
    from: u32,
    until: u32,
    user_keys_hash: [u8; 32],
}

fn body_member_epoch(d: &mut Dec<'_>) -> Result<MekBody, CborError> {
    let mut m = d.map(9)?;
    d.req(&mut m, 1)?;
    let channel = d.bytes_n::<16>()?;
    d.req(&mut m, 2)?;
    let user = d.bytes_n::<16>()?;
    d.req(&mut m, 3)?;
    d.u16()?; // role_label
    d.req(&mut m, 4)?;
    let epoch = d.u32()?;
    d.req(&mut m, 5)?;
    let pk = d.bytes(4_096)?.to_vec();
    d.req(&mut m, 6)?;
    let key_id = d.bytes_n::<32>()?;
    d.req(&mut m, 7)?;
    let from = d.u32()?;
    d.req(&mut m, 8)?;
    let until = d.u32()?;
    d.req(&mut m, 9)?;
    let user_keys_hash = d.bytes_n::<32>()?;
    d.end_map(m)?;
    Ok(MekBody {
        channel,
        user,
        epoch,
        pk,
        key_id,
        from,
        until,
        user_keys_hash,
    })
}

/// `{1: pk, 2: key_id, 3: <field>}` (CUSTODIAN_GROUP adds 4).
fn body_custodian(d: &mut Dec<'_>) -> Result<Vec<u8>, CborError> {
    let mut m = d.map(4)?;
    d.req(&mut m, 1)?;
    let pk = d.bytes(4_096)?.to_vec();
    d.req(&mut m, 2)?;
    d.bytes_n::<32>()?;
    d.req(&mut m, 3)?;
    let n = d.array(16)?;
    for _ in 0..n {
        d.text(128)?;
    }
    d.req(&mut m, 4)?;
    d.uint()?;
    d.end_map(m)?;
    Ok(pk)
}

fn body_disposition(d: &mut Dec<'_>) -> Result<(Vec<u8>, u16), CborError> {
    let mut m = d.map(3)?;
    d.req(&mut m, 1)?;
    let pk = d.bytes(4_096)?.to_vec();
    d.req(&mut m, 2)?;
    d.bytes_n::<32>()?;
    d.req(&mut m, 3)?;
    let suite = d.u16()?;
    d.end_map(m)?;
    Ok((pk, suite))
}

fn body_revocation(d: &mut Dec<'_>) -> Result<Vec<u8>, CborError> {
    let mut m = d.map(3)?;
    d.req(&mut m, 1)?;
    let k = d.bytes(32)?.to_vec();
    d.req(&mut m, 2)?;
    d.uint()?;
    d.req(&mut m, 3)?;
    d.u32()?;
    d.end_map(m)?;
    Ok(k)
}

struct Coi {
    activation: u32,
    declared_loosening: bool,
    categories: Vec<(u16, Vec<u16>)>,
    selectable: Vec<u16>,
}

fn body_coi(d: &mut Dec<'_>) -> Result<Coi, CborError> {
    let mut m = d.map(5)?;
    d.req(&mut m, 1)?;
    d.uint()?; // policy_version
    d.req(&mut m, 2)?;
    let activation = d.u32()?;
    d.req(&mut m, 3)?;
    let declared_loosening = d.uint_max(1)? == 1;
    d.req(&mut m, 4)?;
    let n = d.array(64)?;
    let mut categories = Vec::with_capacity(n);
    for _ in 0..n {
        let mut c = d.map(3)?;
        d.req(&mut c, 1)?;
        let id = d.u16()?;
        d.req(&mut c, 2)?;
        d.text(128)?;
        d.req(&mut c, 3)?;
        let ex = u16_array(d, 64)?;
        d.end_map(c)?;
        categories.push((id, ex));
    }
    d.req(&mut m, 5)?;
    let selectable = u16_array(d, 64)?;
    d.end_map(m)?;
    Ok(Coi {
        activation,
        declared_loosening,
        categories,
        selectable,
    })
}

struct Cert {
    channel: [u8; 16],
    label: u16,
    independent: bool,
    valid_until: u32,
}

fn body_cert(d: &mut Dec<'_>) -> Result<Cert, CborError> {
    let mut m = d.map(5)?;
    d.req(&mut m, 1)?;
    let channel = d.bytes_n::<16>()?;
    d.req(&mut m, 2)?;
    let label = d.u16()?;
    d.req(&mut m, 3)?;
    let independent = d.bool()?;
    d.req(&mut m, 4)?;
    d.uint()?; // body type
    d.req(&mut m, 5)?;
    let valid_until = d.u32()?;
    d.end_map(m)?;
    Ok(Cert {
        channel,
        label,
        independent,
        valid_until,
    })
}

struct Gov {
    oversight: Vec<[u8; 32]>,
    independent: Vec<[u8; 32]>,
    lock_days: u32,
    orphan_days: u32,
}

fn body_gov(d: &mut Dec<'_>) -> Result<Gov, CborError> {
    let mut m = d.map(7)?;
    d.req(&mut m, 1)?;
    let oversight = hash_array(d, 32)?;
    d.req(&mut m, 2)?;
    let independent = hash_array(d, 64)?;
    d.req(&mut m, 3)?;
    let mut s = d.map(2)?;
    d.req(&mut s, 1)?;
    d.uint()?;
    d.req(&mut s, 2)?;
    let n = d.array(32)?;
    for _ in 0..n {
        let mut e = d.map(2)?;
        d.req(&mut e, 1)?;
        d.bytes_n::<32>()?;
        d.req(&mut e, 2)?;
        d.bool()?;
        d.end_map(e)?;
    }
    d.end_map(s)?;
    d.req(&mut m, 4)?;
    d.bool()?;
    d.req(&mut m, 5)?;
    if !d.null()? {
        d.text(128)?;
    }
    d.req(&mut m, 6)?;
    let lock_days = d.u32()?;
    d.req(&mut m, 7)?;
    let orphan_days = d.u32()?;
    d.end_map(m)?;
    Ok(Gov {
        oversight,
        independent,
        lock_days: lock_days.max(MIN_TIMELOCK_DAYS),
        orphan_days: orphan_days.max(MIN_ORPHAN_TIMELOCK_DAYS),
    })
}

fn body_objection(d: &mut Dec<'_>) -> Result<([u8; 16], [u8; 32], bool), CborError> {
    let mut m = d.map(4)?;
    d.req(&mut m, 1)?;
    let channel = d.bytes_n::<16>()?;
    d.req(&mut m, 2)?;
    let objected = d.bytes_n::<32>()?;
    d.req(&mut m, 3)?;
    d.uint()?;
    d.req(&mut m, 4)?;
    let resolved = d.bool()?;
    d.end_map(m)?;
    Ok((channel, objected, resolved))
}

// ---------------------------------------------------------------------------
// State

struct UserVer {
    user_id: [u8; 16],
    entry_hash: [u8; 32],
    k08: [u8; 32],
    key_ids: Vec<Vec<u8>>,
}

struct Cik {
    pk: [u8; 32],
    orphan: bool,
    activation: u32,
    entry_hash: [u8; 32],
}

struct RosterRec {
    entry_hash: [u8; 32],
    version: u64,
    activation: u32,
    loosening: bool,
    members: Vec<RawMember>,
    independent_route: Option<[u8; 16]>,
    /// Signed under an orphan CIK (activation then also needs the CIK's).
    orphan_cik: Option<[u8; 32]>,
}

struct CoiRec {
    entry_hash: [u8; 32],
    activation: u32,
    loosening: bool,
    categories: Vec<(u16, Vec<u16>)>,
    selectable: Vec<u16>,
    orphan_cik: Option<[u8; 32]>,
}

#[derive(Default)]
struct Chan {
    ciks: Vec<Cik>,
    rosters: Vec<RosterRec>,
    coi: Vec<CoiRec>,
}

struct CertRec {
    independent: bool,
    valid_until: u32,
}

struct MekRec {
    channel: [u8; 16],
    user: [u8; 16],
    epoch: u32,
    from: u32,
    until: u32,
    pk: Vec<u8>,
    key_id: [u8; 32],
    signer: [u8; 32],
    usable_suite: bool,
}

struct State<'c> {
    ctx: &'c VerifyCtx<'c>,
    suite_id: u16,
    leaf: u64,
    chains: BTreeMap<(u8, Vec<u8>), (u64, [u8; 32])>,
    k01: Vec<[u8; 32]>,
    org: Option<OrgRoot>,
    log_key: Option<[u8; 32]>,
    admins: BTreeMap<[u8; 16], [u8; 32]>,
    users: Vec<UserVer>,
    user_current: BTreeMap<[u8; 16], usize>,
    user_by_hash: BTreeMap<[u8; 32], usize>,
    gov: Option<Gov>,
    channels: BTreeMap<[u8; 16], Chan>,
    /// cert subject → latest cert.
    certs: BTreeMap<[u8; 32], CertRec>,
    /// cert entry hash → cert subject.
    cert_hashes: BTreeMap<[u8; 32], [u8; 32]>,
    meks: Vec<MekRec>,
    /// revoked key id / public key → leaf of the first revocation.
    revoked: BTreeMap<Vec<u8>, u64>,
    /// objected entry hash → still blocking.
    objections: BTreeMap<[u8; 32], bool>,
    custodian: Option<Vec<u8>>,
    disposition: Option<Vec<u8>>,
}

impl<'c> State<'c> {
    fn new(ctx: &'c VerifyCtx<'c>) -> Self {
        Self {
            ctx,
            suite_id: u16::from_be_bytes(ctx.suite.to_be_bytes()),
            leaf: 0,
            chains: BTreeMap::new(),
            k01: Vec::new(),
            org: None,
            log_key: None,
            admins: BTreeMap::new(),
            users: Vec::new(),
            user_current: BTreeMap::new(),
            user_by_hash: BTreeMap::new(),
            gov: None,
            channels: BTreeMap::new(),
            certs: BTreeMap::new(),
            cert_hashes: BTreeMap::new(),
            meks: Vec::new(),
            revoked: BTreeMap::new(),
            objections: BTreeMap::new(),
            custodian: None,
            disposition: None,
        }
    }

    /// A key is usable for an entry at `leaf` unless it was revoked by an
    /// earlier leaf (VR-11, by log order).
    fn usable_at(&self, key: &[u8], leaf: u64) -> bool {
        self.revoked.get(key).is_none_or(|r| *r >= leaf)
    }

    fn usable(&self, key: &[u8]) -> bool {
        self.usable_at(key, self.leaf)
    }

    fn k01_signed(&self, e: &Signed<'_>) -> bool {
        self.k01.last().is_some_and(|k| self.usable(k) && e.has(k))
    }

    /// Distinct admin (K15) subjects that signed `e`.
    fn admin_signers(&self, e: &Signed<'_>) -> Vec<[u8; 16]> {
        self.admins
            .iter()
            .filter(|(_, pk)| e.has(pk) && self.usable(pk.as_slice()))
            .map(|(id, _)| *id)
            .collect()
    }

    /// The user's current, unrevoked K08.
    fn user_k08(&self, user: &[u8; 16]) -> Option<[u8; 32]> {
        let u = self.users.get(*self.user_current.get(user)?)?;
        let revoked = !self.usable(&u.k08) || u.key_ids.iter().any(|k| !self.usable(k));
        (!revoked).then_some(u.k08)
    }

    fn signing_users(&self, e: &Signed<'_>, hashes: &[[u8; 32]]) -> Vec<[u8; 16]> {
        let mut out = Vec::new();
        for h in hashes {
            let Some(u) = self.user_by_hash.get(h).and_then(|i| self.users.get(*i)) else {
                continue;
            };
            if self.user_k08(&u.user_id).is_some_and(|k| e.has(&k)) && !out.contains(&u.user_id) {
                out.push(u.user_id);
            }
        }
        out
    }

    fn oversight_signers(&self, e: &Signed<'_>) -> Vec<[u8; 16]> {
        self.gov
            .as_ref()
            .map_or_else(Vec::new, |g| self.signing_users(e, &g.oversight))
    }

    /// Independent-role approvers (OVERSIGHT or GOVERNANCE_ROLES independent
    /// members) that signed `e`.
    fn independent_signers(&self, e: &Signed<'_>) -> Vec<[u8; 16]> {
        let Some(g) = &self.gov else {
            return Vec::new();
        };
        let mut v = self.signing_users(e, &g.oversight);
        for u in self.signing_users(e, &g.independent) {
            if !v.contains(&u) {
                v.push(u);
            }
        }
        v
    }

    /// Time lock (ADR-036(2), §14.4 rule 7): `activation ≥ not_before + D`, and
    /// for leaves appended after the high-water-mark checkpoint (whose
    /// inclusion day is therefore ≥ that checkpoint's day) also
    /// `activation ≥ hwm_issued_day + D`, so a backdated `not_before` cannot
    /// shorten the lock below what the sealer itself observed.
    fn time_locked(&self, h: &Header<'_>, activation: u32, days: u32) -> bool {
        let floor = h.not_before.saturating_add(days);
        let observed = if self.leaf >= self.ctx.hwm_tree_size {
            self.ctx.hwm_issued_day.saturating_add(days)
        } else {
            0
        };
        activation >= floor && activation >= observed
    }

    /// Loosening approvals: an independent-role approver who is not the K15
    /// holder that signed (ADR-036(2), §14.4 rule 3), and the time lock.
    fn loosening_ok(&self, e: &Signed<'_>, h: &Header<'_>, activation: u32) -> bool {
        let Some(g) = &self.gov else {
            return false;
        };
        let admins = self.admin_signers(e);
        let indep = self.independent_signers(e);
        let distinct = indep.iter().any(|a| admins.iter().any(|k| k != a));
        distinct && self.time_locked(h, activation, g.lock_days)
    }

    /// The channel's current CIK for an entry at this leaf.
    fn cik(&self, channel: &[u8; 16]) -> Option<&Cik> {
        let c = self.channels.get(channel)?.ciks.last()?;
        self.usable(&c.pk).then_some(c)
    }

    fn continuity(&mut self, h: &Header<'_>, hash: [u8; 32]) -> Result<(), SnapshotError> {
        let key = (h.ty, h.subject.to_vec());
        match self.chains.get(&key) {
            None => need(h.seq == 1 && h.prev.is_none())?,
            Some((seq, prev)) => {
                need(Some(h.seq) == seq.checked_add(1) && h.prev.as_ref() == Some(prev))?;
            }
        }
        self.chains.insert(key, (h.seq, hash));
        Ok(())
    }

    fn apply(&mut self, bytes: &[u8]) -> Result<(), SnapshotError> {
        let e = parse_signed(bytes)?;
        let mut d = Dec::new(e.entry);
        let mut m = d.map(10).map_err(bad)?;
        let h = parse_header(&mut d, &mut m, &self.ctx.tenant_id).map_err(bad)?;
        need(h.ty >= ty::ORG_ROOT && h.ty <= ty::MAX)?;
        self.continuity(&h, e.hash)?;
        self.body(&mut d, &e, &h)?;
        d.end_map(m).map_err(bad)?;
        d.finish().map_err(bad)
    }

    fn subject16(h: &Header<'_>) -> Result<[u8; 16], SnapshotError> {
        h.subject.try_into().map_err(bad)
    }

    fn body(
        &mut self,
        d: &mut Dec<'_>,
        e: &Signed<'_>,
        h: &Header<'_>,
    ) -> Result<(), SnapshotError> {
        match h.ty {
            ty::ORG_ROOT => {
                need(h.subject == self.ctx.tenant_id)?;
                let b = body_org_root(d).map_err(bad)?;
                need(e.has(&b.pk))?;
                if let Some(prev) = self.k01.last() {
                    // Rotation: the old K01 signs the new ORG_ROOT (VR-1).
                    need(e.has(prev) && self.usable(prev))?;
                }
                self.k01.push(b.pk);
                self.org = Some(b);
            }
            ty::LOG_KEY => {
                let (pk, _) = body_pk_and(d, |d| d.text(256).map(|_| ())).map_err(bad)?;
                need(self.k01_signed(e))?;
                self.log_key = Some(pk);
            }
            ty::KEY_ADMIN => {
                let subject = Self::subject16(h)?;
                let (pk, _) = body_pk_and(d, |d| d.u16()).map_err(bad)?;
                need(self.k01_signed(e))?;
                self.admins.insert(subject, pk);
            }
            ty::USER_KEYS => self.user_keys(d, e, h)?,
            ty::CHANNEL_IDENTITY => self.channel_identity(d, e, h)?,
            ty::CHANNEL_ROSTER => self.roster(d, e, h)?,
            ty::MEMBER_EPOCH => self.member_epoch(d, e, h)?,
            ty::COI_POLICY => self.coi(d, e, h)?,
            ty::CUSTODIAN_GROUP => {
                need(h.subject == self.ctx.tenant_id)?;
                let pk = body_custodian(d).map_err(bad)?;
                need(self.k01_signed(e))?;
                self.custodian = (h.suite == self.suite_id).then_some(pk);
            }
            ty::DISPOSITION_KEY => {
                need(h.subject == self.ctx.tenant_id)?;
                let (pk, suite) = body_disposition(d).map_err(bad)?;
                need(self.k01_signed(e) && suite == h.suite)?;
                self.disposition = (h.suite == self.suite_id).then_some(pk);
            }
            ty::REVOCATION => {
                let k = body_revocation(d).map_err(bad)?;
                need(k.as_slice() == h.subject)?;
                let leaf = self.leaf;
                self.revoked.entry(k).or_insert(leaf);
            }
            ty::ROLE_LABEL_CERT => {
                let c = body_cert(d).map_err(bad)?;
                let subject = role_label_subject(&c.channel, c.label);
                need(h.subject == subject.as_slice())?;
                need(!self.oversight_signers(e).is_empty())?;
                self.cert_hashes.insert(e.hash, subject);
                self.certs.insert(
                    subject,
                    CertRec {
                        independent: c.independent,
                        valid_until: c.valid_until,
                    },
                );
            }
            ty::GOVERNANCE_ROLES => {
                need(h.subject == self.ctx.tenant_id)?;
                let g = body_gov(d).map_err(bad)?;
                need(self.k01_signed(e) && !g.oversight.is_empty())?;
                self.gov = Some(g);
            }
            ty::OBJECTION => {
                let (channel, objected, resolved) = body_objection(d).map_err(bad)?;
                need(h.subject == objection_subject(&channel, &objected).as_slice())?;
                if resolved {
                    // Resolution: two OVERSIGHT members (§14.4 rule 8).
                    need(self.oversight_signers(e).len() >= 2)?;
                }
                self.objections.insert(objected, !resolved);
            }
            _ => d.skip().map_err(bad)?,
        }
        Ok(())
    }

    fn user_keys(
        &mut self,
        d: &mut Dec<'_>,
        e: &Signed<'_>,
        h: &Header<'_>,
    ) -> Result<(), SnapshotError> {
        let user_id = Self::subject16(h)?;
        let b = body_user_keys(d).map_err(bad)?;
        need(e.has(&b.k08) && b.authenticators >= 2)?;
        let admins = self.admin_signers(e);
        need(!admins.is_empty())?;
        // Out-of-band verifier: another user's K08, not the K15 holder that
        // signed; K01 stands in for the first users of a tenant (bootstrap).
        let oob = b.oob_verified_by != user_id
            && admins.iter().any(|a| *a != b.oob_verified_by)
            && self.user_k08(&b.oob_verified_by).is_some_and(|k| e.has(&k));
        need(oob || self.k01_signed(e))?;
        let idx = self.users.len();
        self.users.push(UserVer {
            user_id,
            entry_hash: e.hash,
            k08: b.k08,
            key_ids: b.key_ids,
        });
        self.user_current.insert(user_id, idx);
        self.user_by_hash.insert(e.hash, idx);
        Ok(())
    }

    fn channel_identity(
        &mut self,
        d: &mut Dec<'_>,
        e: &Signed<'_>,
        h: &Header<'_>,
    ) -> Result<(), SnapshotError> {
        let channel = Self::subject16(h)?;
        let (pk, orphan, activation) = body_channel_identity(d).map_err(bad)?;
        let admins = self.admin_signers(e).len();
        let oversight = !self.oversight_signers(e).is_empty();
        if orphan {
            let days = self
                .gov
                .as_ref()
                .map_or(MIN_ORPHAN_TIMELOCK_DAYS, |g| g.orphan_days);
            need(self.k01_signed(e) && admins >= 2 && oversight)?;
            need(self.time_locked(h, activation, days))?;
        } else if h.seq == 1 {
            let creator = self
                .user_current
                .keys()
                .any(|u| self.user_k08(u).is_some_and(|k| e.has(&k)));
            need(creator && admins >= 2 && oversight)?;
        } else {
            let prev = self.cik(&channel).map(|c| c.pk);
            need(prev.is_some_and(|p| e.has(&p)) && admins >= 1)?;
        }
        self.channels.entry(channel).or_default().ciks.push(Cik {
            pk,
            orphan,
            activation: if orphan { activation } else { 0 },
            entry_hash: e.hash,
        });
        Ok(())
    }

    /// CIK + 1 K15 (§14.4 rule 3); returns the orphan CIK hash if the signing
    /// CIK is an orphan re-key.
    fn cik_signed(
        &self,
        channel: &[u8; 16],
        e: &Signed<'_>,
    ) -> Result<Option<[u8; 32]>, SnapshotError> {
        let cik = self.cik(channel).ok_or(SnapshotError::Entry)?;
        need(e.has(&cik.pk) && !self.admin_signers(e).is_empty())?;
        Ok(cik.orphan.then_some(cik.entry_hash))
    }

    fn effective_activation(&self, channel: &[u8; 16], loosening: bool, activation: u32) -> u32 {
        // Tightening is active on inclusion (§14.4 rule 7).
        let base = if loosening { activation } else { 0 };
        let cik = self
            .cik(channel)
            .filter(|c| c.orphan)
            .map_or(0, |c| c.activation);
        base.max(cik)
    }

    fn roster(
        &mut self,
        d: &mut Dec<'_>,
        e: &Signed<'_>,
        h: &Header<'_>,
    ) -> Result<(), SnapshotError> {
        let channel = Self::subject16(h)?;
        let r = body_roster(d).map_err(bad)?;
        let orphan_cik = self.cik_signed(&channel, e)?;
        // Members reference verified USER_KEYS entries of the same user, and
        // Triage Set members a ROLE_LABEL_CERT for their label in this channel.
        let mut triage: Vec<[u8; 16]> = Vec::with_capacity(r.members.len());
        for mbr in &r.members {
            let u = self
                .user_by_hash
                .get(&mbr.user_keys_hash)
                .and_then(|i| self.users.get(*i));
            need(u.is_some_and(|u| u.user_id == mbr.user_id))?;
            if mbr.caps & caps::READ_INTAKE != 0 {
                let subject = role_label_subject(&channel, mbr.role_label);
                need(self.cert_hashes.get(&mbr.cert_hash) == Some(&subject))?;
                if !triage.contains(&mbr.user_id) {
                    triage.push(mbr.user_id);
                }
            }
        }
        // §14.4 rule 5: 2..16 read_intake members (persons).
        need((2..=candor_core::slots::SLOT_COUNT).contains(&triage.len()))?;
        let prev = self.channels.get(&channel).and_then(|c| c.rosters.last());
        let computed = prev.is_none_or(|p| roster_loosens(p, &r));
        // A declared tightening that adds anything is invalid; a declared
        // loosening is always treated as loosening.
        need(r.declared_loosening || !computed)?;
        let loosening = r.declared_loosening || computed;
        if loosening {
            need(self.loosening_ok(e, h, r.activation))?;
        }
        if let Some(p) = prev {
            need(r.version > p.version)?;
        }
        let activation = self.effective_activation(&channel, loosening, r.activation);
        self.channels
            .entry(channel)
            .or_default()
            .rosters
            .push(RosterRec {
                entry_hash: e.hash,
                version: r.version,
                activation,
                loosening,
                members: r.members,
                independent_route: r.independent_route,
                orphan_cik,
            });
        Ok(())
    }

    fn coi(
        &mut self,
        d: &mut Dec<'_>,
        e: &Signed<'_>,
        h: &Header<'_>,
    ) -> Result<(), SnapshotError> {
        let channel = Self::subject16(h)?;
        let c = body_coi(d).map_err(bad)?;
        let orphan_cik = self.cik_signed(&channel, e)?;
        let prev = self.channels.get(&channel).and_then(|ch| ch.coi.last());
        let computed = prev.is_some_and(|p| coi_loosens(p, &c));
        need(c.declared_loosening || !computed)?;
        let loosening = c.declared_loosening || computed;
        if loosening {
            need(self.loosening_ok(e, h, c.activation))?;
        }
        let activation = self.effective_activation(&channel, loosening, c.activation);
        self.channels.entry(channel).or_default().coi.push(CoiRec {
            entry_hash: e.hash,
            activation,
            loosening,
            categories: c.categories,
            selectable: c.selectable,
            orphan_cik,
        });
        Ok(())
    }

    fn member_epoch(
        &mut self,
        d: &mut Dec<'_>,
        e: &Signed<'_>,
        h: &Header<'_>,
    ) -> Result<(), SnapshotError> {
        let b = body_member_epoch(d).map_err(bad)?;
        need(h.subject == member_epoch_subject(&b.channel, &b.user, b.epoch).as_slice())?;
        // ADR-030: signed by the member's current K08.
        let k08 = self.user_k08(&b.user).ok_or(SnapshotError::Entry)?;
        need(e.has(&k08))?;
        let u = self
            .user_by_hash
            .get(&b.user_keys_hash)
            .and_then(|i| self.users.get(*i));
        need(u.is_some_and(|u| u.user_id == b.user))?;
        // The key id the Recipient List carries must be the one of this key.
        let suite = Suite::from_id(h.suite).map_err(bad)?;
        need(key_id(suite, KeyKind::Mek, &b.pk) == b.key_id)?;
        need(b.from < b.until)?;
        self.meks.push(MekRec {
            channel: b.channel,
            user: b.user,
            epoch: b.epoch,
            from: b.from,
            until: b.until,
            pk: b.pk,
            key_id: b.key_id,
            signer: k08,
            usable_suite: h.suite == self.suite_id,
        });
        Ok(())
    }

    fn blocked(&self, hash: &[u8; 32]) -> bool {
        self.objections.get(hash).copied().unwrap_or(false)
    }

    fn finish(self) -> Result<LogView, SnapshotError> {
        let org = self.org.as_ref().ok_or(SnapshotError::Invalid)?;
        // VR-1: the pinned K01 is in the ORG_ROOT chain (later roots are
        // rotation-signed by their predecessor).
        if !self.k01.iter().any(|k| k == self.ctx.pinned_k01) {
            return Err(SnapshotError::Signature);
        }
        if &org.salt != self.ctx.deployment_salt {
            return Err(SnapshotError::Invalid);
        }
        if !org.suites.contains(&self.suite_id) {
            return Err(SnapshotError::Suite);
        }
        let log_key = self
            .log_key
            .filter(|k| self.usable(k))
            .ok_or(SnapshotError::Signature)?;
        let mut channels = Vec::with_capacity(self.channels.len());
        for (id, ch) in &self.channels {
            if ch.rosters.is_empty() {
                continue;
            }
            channels.push(self.channel_view(*id, ch));
        }
        let mut user_keys = Vec::with_capacity(self.users.len());
        for u in &self.users {
            let revoked = !self.usable(&u.k08) || u.key_ids.iter().any(|k| !self.usable(k));
            if !revoked {
                user_keys.push(UserKeyEntry {
                    entry_hash: u.entry_hash,
                    user_id: u.user_id,
                    sig_pk: u.k08,
                });
            }
        }
        Ok(LogView {
            log_key,
            witnesses: org.witnesses.clone(),
            w_total: usize::try_from(org.w_total).map_err(bad)?,
            w_external: usize::try_from(org.w_external).map_err(bad)?,
            custodian_pk: self.custodian.clone().unwrap_or_default(),
            disposition_pk: self.disposition.clone().unwrap_or_default(),
            channels,
            user_keys,
        })
    }

    fn channel_view(&self, id: [u8; 16], ch: &Chan) -> ChannelView {
        let orphan_blocked = |o: &Option<[u8; 32]>| o.as_ref().is_some_and(|h| self.blocked(h));
        let rosters = ch
            .rosters
            .iter()
            // An objected loosening entry (or anything under an objected
            // orphan CIK) never activates (§14.4 rules 7–8).
            .filter(|r| {
                !(orphan_blocked(&r.orphan_cik) || r.loosening && self.blocked(&r.entry_hash))
            })
            .map(|r| RosterVersion {
                entry_hash: r.entry_hash,
                roster_version: r.version,
                activation_day: r.activation,
                independent_route: r.independent_route,
                members: r
                    .members
                    .iter()
                    .map(|m| {
                        let cert = self.certs.get(&role_label_subject(&id, m.role_label));
                        RosterMember {
                            user_id: m.user_id,
                            role_label: m.role_label,
                            read_intake: m.caps & caps::READ_INTAKE != 0,
                            // §14.4 rule 5: a current *independent* certificate.
                            label_certified_until: cert
                                .filter(|c| c.independent)
                                .map(|c| c.valid_until),
                        }
                    })
                    .collect(),
            })
            .collect();
        let coi_policies = ch
            .coi
            .iter()
            .filter(|c| {
                !(orphan_blocked(&c.orphan_cik) || c.loosening && self.blocked(&c.entry_hash))
            })
            .map(|c| CoiPolicy {
                entry_hash: c.entry_hash,
                effective_day: c.activation,
                categories: c.categories.clone(),
            })
            .collect();
        // Usable only while signed by the member's *current* K08 and neither
        // the MEK nor that K08 is revoked (§12.1 step 6, VR-11).
        let live = |k: &MekRec| self.usable(&k.key_id) && self.user_k08(&k.user) == Some(k.signer);
        let mut live_count: BTreeMap<([u8; 16], u32), usize> = BTreeMap::new();
        for k in self.meks.iter().filter(|k| k.channel == id && live(k)) {
            let c = live_count.entry((k.user, k.epoch)).or_insert(0);
            *c = c.saturating_add(1);
        }
        let meks = self
            .meks
            .iter()
            .filter(|k| k.channel == id && k.usable_suite)
            .map(|k| {
                // §14.4 rule 5: at most one unrevoked MEMBER_EPOCH per
                // (channel, member, epoch). More than one is ambiguous: none
                // of them is used (fail closed).
                let unrevoked = live_count.get(&(k.user, k.epoch)).copied().unwrap_or(0);
                MemberEpochKey {
                    user_id: k.user,
                    epoch_id: k.epoch,
                    valid_from_day: k.from,
                    valid_until_day: k.until,
                    revoked: !live(k) || unrevoked > 1,
                    public_key: k.pk.clone(),
                }
            })
            .collect();
        ChannelView {
            channel_id: id,
            enabled: true,
            rosters,
            coi_policies,
            meks,
        }
    }
}

/// §14.4 rule 7 / ADR-036(2): any addition, any `read_intake` or
/// `channel_admin` grant, any role-label change or a changed independent route
/// is loosening.
fn roster_loosens(prev: &RosterRec, next: &Roster) -> bool {
    let grants = caps::READ_INTAKE | caps::CHANNEL_ADMIN;
    let had = |user: &[u8; 16], label: u16| {
        prev.members
            .iter()
            .any(|p| &p.user_id == user && p.role_label == label)
    };
    let had_caps = |user: &[u8; 16]| {
        prev.members
            .iter()
            .filter(|p| &p.user_id == user)
            .fold(0u64, |a, p| a | p.caps)
    };
    next.independent_route != prev.independent_route
        || next.members.iter().any(|m| {
            !had(&m.user_id, m.role_label) || (m.caps & grants) & !had_caps(&m.user_id) != 0
        })
}

/// §14.2 COI_POLICY: loosening if any category's excluded set is not a superset
/// of the previous version's (including a removed category) or a
/// source-selectable role was removed.
fn coi_loosens(prev: &CoiRec, next: &Coi) -> bool {
    let cat_loosened = prev.categories.iter().any(|(id, ex)| {
        next.categories
            .iter()
            .find(|(n, _)| n == id)
            .is_none_or(|(_, nx)| ex.iter().any(|l| !nx.contains(l)))
    });
    cat_loosened || prev.selectable.iter().any(|r| !next.selectable.contains(r))
}

/// Verify every entry of the log in leaf order and derive the sealer's view.
pub(crate) fn verify_log(
    entries: &[Vec<u8>],
    ctx: &VerifyCtx<'_>,
) -> Result<LogView, SnapshotError> {
    let mut st = State::new(ctx);
    for (i, e) in entries.iter().enumerate() {
        st.leaf = u64::try_from(i).map_err(bad)?;
        st.apply(e)?;
    }
    st.leaf = u64::try_from(entries.len()).map_err(bad)?;
    st.finish()
}
