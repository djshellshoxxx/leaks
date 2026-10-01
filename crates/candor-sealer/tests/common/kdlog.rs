// SPDX-License-Identifier: AGPL-3.0-or-later
//! A test Key Directory (C-14 stand-in): a high-level model of the directory
//! (the shape the sealer used to accept as a free-standing view) and a log
//! builder that turns it into real, signed KD entries (04 §14.2) with
//! continuity, time locks, role-label certificates and governance, plus signed
//! checkpoints and consistency proofs. The sealer derives its view from these
//! entries only (AUD-RM2-SEA-19).
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc
)]

use std::collections::HashMap;

use candor_core::Suite;
use candor_core::hash::{KeyKind, key_id};
use candor_core::sig::SigningKey;
use candor_sealer::proto::cbor::Value;
use candor_sealer::server::directory::{
    Cosignature, SignedCheckpoint, SnapshotBundle, cosignature_message, merkle,
};
use candor_sealer::server::kd::{self, caps, ty};

use super::{Member, SALT, TENANT, TODAY};

// --- the model -------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterMember {
    pub user_id: [u8; 16],
    pub role_label: u16,
    pub read_intake: bool,
    /// Day from which this row is in the roster (rows sharing a day form one
    /// roster version; later days are later, loosening versions).
    pub effective_day: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoiPolicy {
    /// Ignored (the real entry hash is the leaf hash).
    pub entry_hash: [u8; 32],
    pub effective_day: u32,
    pub categories: Vec<(u16, Vec<u16>)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberEpochKey {
    pub user_id: [u8; 16],
    pub epoch_id: u32,
    pub valid_from_day: u32,
    pub valid_until_day: u32,
    /// Emits a REVOCATION for the key.
    pub revoked: bool,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelView {
    pub channel_id: [u8; 16],
    pub enabled: bool,
    pub members: Vec<RosterMember>,
    pub coi_policies: Vec<CoiPolicy>,
    pub meks: Vec<MemberEpochKey>,
    pub independent_route: Option<[u8; 16]>,
}

/// The directory a test wants. `tree_size` is a minimum: the builder pads
/// with filler entries to reach it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectorySnapshot {
    pub snapshot_version: u64,
    pub tree_size: u64,
    pub issued_hour: u64,
    pub suite: Suite,
    pub custodian_pk: Vec<u8>,
    pub disposition_pk: Vec<u8>,
    pub channels: Vec<ChannelView>,
}

/// Ensure the next sync grows the log to at least `tree_size`.
pub fn resize(v: &mut DirectorySnapshot, tree_size: u64) {
    v.tree_size = tree_size;
}

// --- keys --------------------------------------------------------------------

pub const ADMIN1: [u8; 16] = [0xa1; 16];
pub const ADMIN2: [u8; 16] = [0xa2; 16];
pub const OVERSIGHT: [u8; 16] = [0x0f; 16];
pub const LOG_ID: [u8; 16] = [0x10; 16];

pub fn k01() -> SigningKey {
    SigningKey::from_seed(&[0x01; 32])
}
/// The ML-DSA-65 half of K01 (AUD-RM2-SEA-27).
pub fn k01_mldsa() -> &'static ml_dsa::SigningKey<ml_dsa::MlDsa65> {
    static K: std::sync::OnceLock<ml_dsa::SigningKey<ml_dsa::MlDsa65>> = std::sync::OnceLock::new();
    K.get_or_init(|| ml_dsa::SigningKey::from_seed(&ml_dsa::B32::from([0x01; 32])))
}

/// Encoded ML-DSA-65 verifying key of K01.
pub fn k01_mldsa_pk() -> Vec<u8> {
    k01_mldsa().expanded_key().verifying_key().encode().to_vec()
}

/// An ML-DSA-65 signature entry `{1: SHA-256(pk), 2: 2, 3: sig}` by `sk`.
pub fn mldsa_sig(sk: &ml_dsa::SigningKey<ml_dsa::MlDsa65>, msg: &[u8]) -> Value {
    let pk = sk.expanded_key().verifying_key().encode();
    let sig = sk
        .expanded_key()
        .sign_deterministic(msg, &[])
        .unwrap()
        .encode();
    m(vec![
        (1, b(&candor_core::hash::sha256(&[pk.as_slice()]))),
        (2, u(kd::alg::ML_DSA_65)),
        (3, b(sig.as_slice())),
    ])
}

pub fn log_key() -> SigningKey {
    SigningKey::from_seed(&[0x4c; 32])
}
pub fn admin1() -> SigningKey {
    SigningKey::from_seed(&[0xa1; 32])
}
pub fn admin2() -> SigningKey {
    SigningKey::from_seed(&[0xa2; 32])
}
pub fn oversight_k08() -> SigningKey {
    SigningKey::from_seed(&[0x0f; 32])
}
pub fn cik() -> SigningKey {
    SigningKey::from_seed(&[0xc1; 32])
}
pub fn witness(n: u8) -> SigningKey {
    SigningKey::from_seed(&[0x70 + n; 32])
}

// --- raw entry encoding ------------------------------------------------------

pub fn b(x: &[u8]) -> Value {
    Value::bytes(x)
}
pub fn u(x: u64) -> Value {
    Value::U(x)
}
pub fn t(x: &str) -> Value {
    Value::text(x)
}
pub fn m(kv: Vec<(u64, Value)>) -> Value {
    Value::M(kv)
}
pub fn a(v: Vec<Value>) -> Value {
    Value::A(v)
}

/// Encode a KDEntry (04 §14.2).
pub fn kd_entry(
    entry_type: u8,
    subject: &[u8],
    seq: u64,
    prev: Option<[u8; 32]>,
    not_before: u32,
    suite: u16,
    body: Value,
) -> Vec<u8> {
    m(vec![
        (1, u(u64::from(entry_type))),
        (2, u(1)),
        (3, b(&TENANT)),
        (4, b(subject)),
        (5, u(seq)),
        (6, prev.map_or(Value::Null, |p| b(&p))),
        (7, u(u64::from(not_before))),
        (8, Value::Null),
        (9, u(u64::from(suite))),
        (10, body),
    ])
    .encode()
    .unwrap()
    .to_vec()
}

/// Sign entry bytes into a SignedKDEntry with Ed25519 signers; K01 also
/// signs with its ML-DSA-65 half (hybrid, 04 §14.2).
pub fn signed_entry(entry: &[u8], signers: &[&SigningKey]) -> Vec<u8> {
    let msg = kd::signing_message(entry);
    let k01_pk = k01().verifying_key_bytes();
    let mut sigs: Vec<Value> = signers
        .iter()
        .map(|k| {
            m(vec![
                (1, b(&k.verifying_key_bytes())),
                (2, u(kd::alg::ED25519)),
                (3, b(&k.sign(&msg))),
            ])
        })
        .collect();
    if signers.iter().any(|k| k.verifying_key_bytes() == k01_pk) {
        sigs.push(mldsa_sig(k01_mldsa(), &msg));
    }
    m(vec![(1, b(entry)), (2, a(sigs))])
        .encode()
        .unwrap()
        .to_vec()
}

const STD: u16 = 1;

// --- the log -------------------------------------------------------------------

/// Roster rows: (user, role label, caps).
pub type Rows = Vec<([u8; 16], u16, u64)>;

#[derive(Clone)]
pub struct TestLog {
    pub entries: Vec<Vec<u8>>,
    chains: HashMap<(u8, Vec<u8>), (u64, [u8; 32])>,
    last_body: HashMap<(u8, Vec<u8>), Vec<u8>>,
    pub user_hash: HashMap<[u8; 16], [u8; 32]>,
    cert_hash: HashMap<([u8; 16], u16), [u8; 32]>,
    /// Last roster rows emitted per channel (user, label, caps).
    roster_rows: HashMap<[u8; 16], Rows>,
    roster_version: HashMap<[u8; 16], u64>,
    coi_emitted: HashMap<[u8; 16], Vec<Vec<u8>>>,
    routes: HashMap<[u8; 16], Option<[u8; 16]>>,
    revoked: Vec<Vec<u8>>,
    filler: u64,
    /// Entry hashes of the CHANNEL_ROSTER / COI_POLICY entries per channel.
    pub roster_hashes: HashMap<[u8; 16], Vec<[u8; 32]>>,
    pub coi_hashes: HashMap<[u8; 16], Vec<[u8; 32]>>,
    /// Issued day of the last bundle (the sealer's high-water-mark day).
    pub last_issued_day: Option<u32>,
    /// Size of the log when the last bundle was built.
    pub last_size: usize,
}

impl Default for TestLog {
    fn default() -> Self {
        Self::new()
    }
}

impl TestLog {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            chains: HashMap::new(),
            last_body: HashMap::new(),
            user_hash: HashMap::new(),
            cert_hash: HashMap::new(),
            roster_rows: HashMap::new(),
            roster_version: HashMap::new(),
            coi_emitted: HashMap::new(),
            routes: HashMap::new(),
            revoked: Vec::new(),
            filler: 0,
            roster_hashes: HashMap::new(),
            coi_hashes: HashMap::new(),
            last_issued_day: None,
            last_size: 0,
        }
    }

    /// Append an entry with correct continuity; returns its entry hash.
    pub fn append(
        &mut self,
        entry_type: u8,
        subject: &[u8],
        not_before: u32,
        body: Value,
        signers: &[&SigningKey],
    ) -> [u8; 32] {
        let key = (entry_type, subject.to_vec());
        let (seq, prev) = match self.chains.get(&key) {
            None => (1, None),
            Some((s, h)) => (s + 1, Some(*h)),
        };
        let body_bytes = body.encode().unwrap().to_vec();
        let e = kd_entry(entry_type, subject, seq, prev, not_before, STD, body);
        let s = signed_entry(&e, signers);
        let h = kd::entry_hash(&s);
        self.entries.push(s);
        self.chains.insert(key.clone(), (seq, h));
        self.last_body.insert(key, body_bytes);
        h
    }

    /// Append unless the latest entry for the subject has the same body.
    fn append_if_changed(
        &mut self,
        entry_type: u8,
        subject: &[u8],
        not_before: u32,
        body: Value,
        signers: &[&SigningKey],
    ) -> [u8; 32] {
        let key = (entry_type, subject.to_vec());
        let bytes = body.encode().unwrap().to_vec();
        if self.last_body.get(&key) == Some(&bytes) {
            return self.chains[&key].1;
        }
        self.append(entry_type, subject, not_before, body, signers)
    }

    pub fn push_raw(&mut self, signed: Vec<u8>) {
        self.entries.push(signed);
    }

    fn user_keys_body(k08: &SigningKey, oob: [u8; 16]) -> Value {
        m(vec![
            (1, b(&k08.verifying_key_bytes())),
            (2, b(&[0x09; 32])),
            (3, a(vec![])),
            (4, t("member")),
            (5, u(1)),
            (6, u(2)),
            (7, a(vec![])),
            (8, u(0)),
            (9, b(&oob)),
        ])
    }

    fn bootstrap(&mut self, custodian: &[u8], disposition: &[u8]) {
        let (k01, a1, a2, ov) = (k01(), admin1(), admin2(), oversight_k08());
        let witnesses: Vec<Value> = (0..3u8)
            .map(|n| {
                m(vec![
                    (1, t("witness")),
                    (2, b(&witness(n).verifying_key_bytes())),
                    (3, u(0)),
                    (4, Value::Bool(n == 2)),
                    (5, Value::Bool(false)),
                    (6, t("w.onion")),
                ])
            })
            .collect();
        self.append(
            ty::ORG_ROOT,
            &TENANT,
            0,
            m(vec![
                (1, b(&k01.verifying_key_bytes())),
                (2, b(&k01_mldsa_pk())),
                (3, a(vec![u(1)])),
                (4, b(&SALT)),
                (5, u(1)),
                (6, a(witnesses)),
                (7, u(0)),
                (8, u(0)),
                (9, u(0)),
            ]),
            &[&k01],
        );
        self.append(
            ty::LOG_KEY,
            &LOG_ID,
            0,
            m(vec![
                (1, b(&log_key().verifying_key_bytes())),
                (2, t("log")),
            ]),
            &[&k01],
        );
        for (id, k) in [(ADMIN1, &a1), (ADMIN2, &a2)] {
            self.append(
                ty::KEY_ADMIN,
                &id,
                0,
                m(vec![(1, b(&k.verifying_key_bytes())), (2, u(1))]),
                &[&k01],
            );
        }
        // The OVERSIGHT member (bootstrap: K01 stands in for the oob verifier).
        let h = self.append(
            ty::USER_KEYS,
            &OVERSIGHT,
            0,
            Self::user_keys_body(&ov, ADMIN2),
            &[&ov, &a1, &k01],
        );
        self.user_hash.insert(OVERSIGHT, h);
        self.append(
            ty::GOVERNANCE_ROLES,
            &TENANT,
            0,
            m(vec![
                (1, a(vec![b(&h)])),
                (2, a(vec![])),
                (3, m(vec![(1, u(1)), (2, a(vec![]))])),
                (4, Value::Bool(false)),
                (5, Value::Null),
                (6, u(3)),
                (7, u(7)),
            ]),
            &[&k01],
        );
        self.set_custodian(custodian);
        self.set_disposition(disposition);
    }

    pub fn set_custodian(&mut self, pk: &[u8]) {
        let k01 = k01();
        self.append_if_changed(
            ty::CUSTODIAN_GROUP,
            &TENANT,
            0,
            m(vec![
                (1, b(pk)),
                (2, b(&[0; 32])),
                (3, a(vec![t("custodian")])),
                (4, u(1)),
            ]),
            &[&k01],
        );
    }

    pub fn set_disposition(&mut self, pk: &[u8]) {
        let k01 = k01();
        self.append_if_changed(
            ty::DISPOSITION_KEY,
            &TENANT,
            0,
            m(vec![(1, b(pk)), (2, b(&[0; 32])), (3, u(1))]),
            &[&k01],
        );
    }

    /// USER_KEYS for a member (own K08 + K15 + oob verifier = OVERSIGHT).
    pub fn add_user(&mut self, user: [u8; 16], k08: &SigningKey) -> [u8; 32] {
        let (a1, ov) = (admin1(), oversight_k08());
        let h = self.append_if_changed(
            ty::USER_KEYS,
            &user,
            0,
            Self::user_keys_body(k08, OVERSIGHT),
            &[k08, &a1, &ov],
        );
        self.user_hash.insert(user, h);
        h
    }

    pub fn cert_body(channel: &[u8; 16], label: u16, independent: bool, until: u32) -> Value {
        m(vec![
            (1, b(channel)),
            (2, u(u64::from(label))),
            (3, Value::Bool(independent)),
            (4, u(1)),
            (5, u(u64::from(until))),
        ])
    }

    pub fn cert(&mut self, channel: [u8; 16], label: u16) -> [u8; 32] {
        let ov = oversight_k08();
        let subject = kd::role_label_subject(&channel, label);
        let h = self.append_if_changed(
            ty::ROLE_LABEL_CERT,
            &subject,
            0,
            Self::cert_body(&channel, label, true, TODAY + 365),
            &[&ov],
        );
        self.cert_hash.insert((channel, label), h);
        h
    }

    /// The earliest activation a loosening entry appended now may have.
    fn min_activation(&self, wanted: u32) -> u32 {
        match self.last_issued_day {
            Some(d) => wanted.max(d + 3),
            None => wanted,
        }
    }

    fn roster_entry(
        &mut self,
        channel: [u8; 16],
        rows: &[([u8; 16], u16, u64)],
        activation: u32,
        route: Option<[u8; 16]>,
    ) {
        let prev = self.roster_rows.get(&channel).cloned();
        let prev_route = self.routes.get(&channel).copied();
        let loosening = match &prev {
            None => true,
            Some(p) => {
                prev_route != Some(route)
                    || rows.iter().any(|(uid, l, c)| {
                        let had_caps = p
                            .iter()
                            .filter(|(pu, _, _)| pu == uid)
                            .fold(0, |acc, (_, _, pc)| acc | pc);
                        !p.iter().any(|(pu, pl, _)| pu == uid && pl == l)
                            || (c & (caps::READ_INTAKE | caps::CHANNEL_ADMIN)) & !had_caps != 0
                    })
            }
        };
        let activation = if loosening {
            self.min_activation(activation.max(3))
        } else {
            activation
        };
        let version = self.roster_version.get(&channel).copied().unwrap_or(0) + 1;
        let body = self.roster_body(channel, rows, activation, loosening, route, version);
        let (c, a1, ov) = (cik(), admin1(), oversight_k08());
        let h = self.append(
            ty::CHANNEL_ROSTER,
            &channel,
            activation.saturating_sub(3),
            body,
            &[&c, &a1, &ov],
        );
        self.roster_hashes.entry(channel).or_default().push(h);
        self.roster_rows.insert(channel, rows.to_vec());
        self.roster_version.insert(channel, version);
        self.routes.insert(channel, route);
    }

    /// The last roster rows emitted for `channel`.
    pub fn rows(&self, channel: &[u8; 16]) -> Vec<([u8; 16], u16, u64)> {
        self.roster_rows.get(channel).cloned().unwrap_or_default()
    }

    /// The next roster version number for `channel`.
    pub fn next_roster_version(&self, channel: &[u8; 16]) -> u64 {
        self.roster_version.get(channel).copied().unwrap_or(0) + 1
    }

    /// A CHANNEL_ROSTER body (rows: user, label, caps).
    pub fn roster_body(
        &self,
        channel: [u8; 16],
        rows: &[([u8; 16], u16, u64)],
        activation: u32,
        loosening: bool,
        route: Option<[u8; 16]>,
        version: u64,
    ) -> Value {
        let members: Vec<Value> = rows
            .iter()
            .map(|(uid, label, c)| {
                let cert = self
                    .cert_hash
                    .get(&(channel, *label))
                    .copied()
                    .unwrap_or([0; 32]);
                m(vec![
                    (1, b(uid)),
                    (2, b(&self.user_hash[uid])),
                    (3, u(u64::from(*label))),
                    (4, b(&cert)),
                    (5, u(*c)),
                    (6, u(0)),
                ])
            })
            .collect();
        m(vec![
            (1, u(version)),
            (2, u(u64::from(activation))),
            (3, u(u64::from(loosening))),
            (4, a(members)),
            (5, u(0)),
            (6, route.map_or(Value::Null, |r| b(&r))),
            (
                7,
                m(vec![
                    (1, Value::Bool(false)),
                    (2, Value::Null),
                    (3, a(vec![])),
                ]),
            ),
            (8, b(&[0; 32])),
            (9, Value::Bool(false)),
        ])
    }

    fn coi_entry(&mut self, channel: [u8; 16], p: &CoiPolicy, prev: Option<&CoiPolicy>) {
        let loosening = prev.is_some_and(|q| {
            q.categories.iter().any(|(id, ex)| {
                p.categories
                    .iter()
                    .find(|(n, _)| n == id)
                    .is_none_or(|(_, nx)| ex.iter().any(|l| !nx.contains(l)))
            })
        });
        let activation = if loosening {
            self.min_activation(p.effective_day)
        } else {
            p.effective_day
        };
        let cats = p
            .categories
            .iter()
            .map(|(id, ex)| {
                m(vec![
                    (1, u(u64::from(*id))),
                    (2, t("category")),
                    (3, a(ex.iter().map(|l| u(u64::from(*l))).collect())),
                ])
            })
            .collect();
        let body = m(vec![
            (1, u(1)),
            (2, u(u64::from(activation))),
            (3, u(u64::from(loosening))),
            (4, a(cats)),
            (5, a(vec![])),
        ]);
        let (c, a1, ov) = (cik(), admin1(), oversight_k08());
        let h = self.append(
            ty::COI_POLICY,
            &channel,
            activation.saturating_sub(3),
            body,
            &[&c, &a1, &ov],
        );
        self.coi_hashes.entry(channel).or_default().push(h);
    }

    pub fn mek_body(channel: &[u8; 16], k: &MemberEpochKey, user_hash: &[u8; 32]) -> Value {
        let kid = key_id(Suite::CandorStd1, KeyKind::Mek, &k.public_key);
        m(vec![
            (1, b(channel)),
            (2, b(&k.user_id)),
            (3, u(1)),
            (4, u(u64::from(k.epoch_id))),
            (5, b(&k.public_key)),
            (6, b(&kid)),
            (7, u(u64::from(k.valid_from_day))),
            (8, u(u64::from(k.valid_until_day))),
            (9, b(user_hash)),
        ])
    }

    fn filler(&mut self) {
        self.filler += 1;
        let mut subject = [0u8; 16];
        subject[..8].copy_from_slice(&self.filler.to_be_bytes());
        let a1 = admin1();
        // CLIENT_RELEASE (0x0B): a type the sealer skips.
        self.append(0x0b, &subject, 0, m(vec![(1, t("filler"))]), &[&a1]);
    }

    /// Make the log reflect `view` (appending only what changed).
    pub fn sync(&mut self, view: &DirectorySnapshot, members: &[Member]) {
        if self.entries.is_empty() {
            self.bootstrap(&view.custodian_pk, &view.disposition_pk);
        } else {
            self.set_custodian(&view.custodian_pk);
            self.set_disposition(&view.disposition_pk);
        }
        let k08_of = |uid: &[u8; 16]| {
            members
                .iter()
                .find(|mm| &mm.user_id == uid)
                .map(|mm| &mm.k08)
        };
        for ch in &view.channels {
            let users: Vec<[u8; 16]> = {
                let mut v: Vec<[u8; 16]> = ch.members.iter().map(|r| r.user_id).collect();
                v.sort_unstable();
                v.dedup();
                v
            };
            for uid in &users {
                // Roster rows for users without a Desk get a derived key.
                let fallback = SigningKey::from_seed(&[uid[0]; 32]);
                self.add_user(*uid, k08_of(uid).unwrap_or(&fallback));
            }
            if !self
                .chains
                .contains_key(&(ty::CHANNEL_IDENTITY, ch.channel_id.to_vec()))
            {
                let (c, a1, a2, ov) = (cik(), admin1(), admin2(), oversight_k08());
                self.append(
                    ty::CHANNEL_IDENTITY,
                    &ch.channel_id,
                    0,
                    m(vec![
                        (1, b(&c.verifying_key_bytes())),
                        (2, Value::Bool(false)),
                        (3, u(0)),
                    ]),
                    &[&ov, &a1, &a2],
                );
            }
            for r in ch.members.iter().filter(|r| r.read_intake) {
                self.cert(ch.channel_id, r.role_label);
            }
            // Roster versions by effective day.
            let mut days: Vec<u32> = ch.members.iter().map(|r| r.effective_day).collect();
            days.sort_unstable();
            days.dedup();
            let rows_for = |d: u32| -> Vec<([u8; 16], u16, u64)> {
                ch.members
                    .iter()
                    .filter(|r| r.effective_day <= d)
                    .map(|r| {
                        let c = if r.read_intake {
                            caps::READ_INTAKE
                        } else {
                            caps::INVESTIGATE
                        };
                        (r.user_id, r.role_label, c)
                    })
                    .collect()
            };
            let first = !self.roster_rows.contains_key(&ch.channel_id);
            if first {
                for d in &days {
                    self.roster_entry(ch.channel_id, &rows_for(*d), *d, ch.independent_route);
                }
            } else if let Some(d) = days.last() {
                let rows = rows_for(*d);
                let same = self.roster_rows.get(&ch.channel_id) == Some(&rows)
                    && self.routes.get(&ch.channel_id) == Some(&ch.independent_route);
                if !same {
                    self.roster_entry(ch.channel_id, &rows, *d, ch.independent_route);
                }
            }
            // COI policies, in order, beyond those already emitted.
            let emitted = self
                .coi_emitted
                .get(&ch.channel_id)
                .cloned()
                .unwrap_or_default();
            for (i, p) in ch.coi_policies.iter().enumerate() {
                let key = format!("{:?}{:?}", p.effective_day, p.categories).into_bytes();
                if emitted.get(i) == Some(&key) {
                    continue;
                }
                let prev = i.checked_sub(1).and_then(|j| ch.coi_policies.get(j));
                self.coi_entry(ch.channel_id, p, prev);
                self.coi_emitted.entry(ch.channel_id).or_default().push(key);
            }
            // MEKs.
            for k in &ch.meks {
                let Some(k08) = k08_of(&k.user_id) else {
                    continue;
                };
                let subject = kd::member_epoch_subject(&ch.channel_id, &k.user_id, k.epoch_id);
                let uh = self.user_hash[&k.user_id];
                self.append_if_changed(
                    ty::MEMBER_EPOCH,
                    &subject,
                    0,
                    Self::mek_body(&ch.channel_id, k, &uh),
                    &[k08],
                );
                let kid = key_id(Suite::CandorStd1, KeyKind::Mek, &k.public_key).to_vec();
                if k.revoked && !self.revoked.contains(&kid) {
                    // Revoked by the member's own K08 (an authorised signer).
                    self.append(
                        ty::REVOCATION,
                        &kid,
                        0,
                        m(vec![(1, b(&kid)), (2, u(1)), (3, u(u64::from(TODAY)))]),
                        &[k08],
                    );
                    self.revoked.push(kid);
                }
            }
        }
        while (self.entries.len() as u64) < view.tree_size {
            self.filler();
        }
    }

    /// The Merkle root of the first `n` entries.
    pub fn root(&self, n: usize) -> [u8; 32] {
        merkle::root(&self.leaves(n))
    }

    pub fn leaves(&self, n: usize) -> Vec<[u8; 32]> {
        self.entries[..n]
            .iter()
            .map(|e| kd::entry_hash(e))
            .collect()
    }

    /// A bundle over the first `n` entries with a LOG_KEY-signed checkpoint and
    /// a consistency proof from `from` (0 = none).
    pub fn bundle_prefix(
        &self,
        n: usize,
        issued_hour: u64,
        snapshot_version: u64,
        from: u64,
        disabled: Vec<[u8; 16]>,
    ) -> SnapshotBundle {
        let leaves = self.leaves(n);
        let mut cp = SignedCheckpoint {
            tree_size: n as u64,
            root_hash: merkle::root(&leaves),
            issued_hour,
            log_sig: [0; 64],
            cosignatures: vec![],
        };
        cp.log_sig = log_key().sign(&cp.note_body(&TENANT).unwrap());
        let proof = if from == 0 || from == n as u64 {
            vec![]
        } else {
            merkle::consistency_proof(from as usize, &leaves)
        };
        SnapshotBundle {
            snapshot_version,
            checkpoint: cp,
            consistency_proof: proof,
            entries: self.entries[..n].to_vec(),
            disabled_channels: disabled,
        }
    }

    /// Bundle of the whole log for `view`'s checkpoint data.
    pub fn bundle(&mut self, view: &DirectorySnapshot, from: u64) -> SnapshotBundle {
        let disabled = view
            .channels
            .iter()
            .filter(|c| !c.enabled)
            .map(|c| c.channel_id)
            .collect();
        let n = self.entries.len();
        self.last_issued_day = Some((view.issued_hour / 24) as u32);
        self.last_size = n;
        self.bundle_prefix(n, view.issued_hour, view.snapshot_version, from, disabled)
    }
}

/// A witness cosignature over a bundle's checkpoint (C2SP form).
pub fn cosign(k: &SigningKey, bundle: &SnapshotBundle) -> Cosignature {
    let body = bundle.checkpoint.note_body(&TENANT).unwrap();
    Cosignature {
        witness_pk: k.verifying_key_bytes(),
        timestamp: 1_700_000_000,
        sig: k.sign(&cosignature_message(&body, 1_700_000_000)),
    }
}
