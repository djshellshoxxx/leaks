// SPDX-License-Identifier: AGPL-3.0-or-later
//! ST-043 `fuzz_sealer_ipc` (IMPL-RM2 §2.3, AUD-RM2-SEA-09/23).
//!
//! The first input byte selects a mode:
//! * `0`: decoders — arbitrary bytes never panic or over-allocate in
//!   `decode_request` / `decode_response` / `frame_len`, and any request that
//!   decodes re-encodes byte-identically (canonical CBOR only);
//! * `1`: raw frames — the input is split into length-prefixed frames and every
//!   request that decodes is fed to one long-lived `Sealer` (Argon2id ops
//!   skipped);
//! * `2`, `3`: **structure-aware** — the bytes drive a generator
//!   (`arbitrary::Unstructured`) of valid, stateful request sequences over four
//!   session handles: drafts with NFC-expanding text, COI ticks and identities,
//!   uploads, passphrase generation and confirmation with the real words,
//!   sealing (recipient selection, the group builder, chaff-shaped bundles),
//!   account batches, login, prefs and replies, rotation. Every request goes
//!   through `encode_request` → `decode_request` (round trip asserted) →
//!   `Sealer::handle`. Mode `3` additionally allows one Argon2id operation
//!   (`SEAL_FINISH`, `LOGIN_DERIVE` or `ROTATE_FINISH`) per input: candor-core
//!   deliberately exposes no way to lower the Argon2id parameters (CRYPTO-043),
//!   so these inputs run at the real cost.
//!
//! The directory is a real signed Key Directory log (the test builder of
//! `tests/common/kdlog.rs`), installed through `install_snapshot`. A seed
//! corpus is in `fuzz/seeds/fuzz_sealer_ipc/` (see `gen_seeds`).
#![no_main]

use std::sync::{Arc, Mutex, OnceLock};

use candor_core::Suite;
use candor_core::kem::KemKeyPair;
use candor_core::passphrase::Wordlist;
use candor_core::sig::SigningKey;
use candor_safefs::{RootPolicy, SafeRoot};
use candor_sealer::proto::{
    Coi, DraftSet, MAX_FRAME_LEN, Mode, Op, PendingReply, Request, Response, SecretBytes,
    SecretText, SecretWords, SessionHandle, decode_request, decode_response, encode_request,
    frame_len,
};
use candor_sealer::server::clock::{Clock, ClockError};
use candor_sealer::server::directory::DirectoryTrust;
use candor_sealer::server::hardening::InsecureDevMode;
use candor_sealer::server::sink::{AccountUpsert, EnvelopeGroup, EnvelopeSink, SinkError};
use candor_sealer::server::{ChaffConfig, Limits, Sealer, SealerConfig};
use libfuzzer_sys::arbitrary::{Result as AResult, Unstructured};
use libfuzzer_sys::fuzz_target;

#[path = "../../tests/common/kdlog.rs"]
mod kdlog;

const TENANT: [u8; 16] = [0x11; 16];
const CHANNEL: [u8; 16] = [0x22; 16];
const SALT: [u8; 32] = [0x44; 32];
const TODAY: u32 = 20_000;

/// What the test log builder needs of a member.
struct Member {
    user_id: [u8; 16],
    k08: SigningKey,
}

struct FixedClock;
impl Clock for FixedClock {
    fn today(&self) -> Result<u32, ClockError> {
        Ok(TODAY)
    }
}

/// Accepts everything; keeps the last account's `prefs_ct` for `LOAD_PREFS`.
#[derive(Default)]
struct NullSink {
    prefs_ct: Mutex<Option<Vec<u8>>>,
}
impl EnvelopeSink for NullSink {
    fn commit_envelope_group(
        &self,
        group: EnvelopeGroup,
        _: u32,
        _: u32,
        _: u8,
    ) -> Result<(), SinkError> {
        // Read the sealed bundle like a store would.
        if let candor_sealer::server::sink::Blob::Staged(b) = &group.bundle.blob {
            b.read_to_vec()?;
        }
        Ok(())
    }
    fn upsert_account(&self, a: AccountUpsert) -> Result<(), SinkError> {
        if let Ok(mut p) = self.prefs_ct.lock() {
            *p = Some(a.account.prefs_ct);
        }
        Ok(())
    }
}

struct Harness {
    rt: tokio::runtime::Runtime,
    sealer: Sealer,
    sink: Arc<NullSink>,
    words: &'static Wordlist,
}

fn harness() -> &'static Harness {
    static H: OnceLock<Harness> = OnceLock::new();
    H.get_or_init(|| {
        use std::os::unix::fs::PermissionsExt; // safefs-lint: allow(fuzz harness setup)
        let dir = std::env::temp_dir().join(format!("candor-sealer-fuzz-{}", std::process::id())); // safefs-lint: allow(fuzz harness setup)
        let _ = std::fs::create_dir(&dir); // safefs-lint: allow(fuzz harness setup)
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap(); // safefs-lint: allow(fuzz harness setup)
        let staging: &'static SafeRoot =
            Box::leak(Box::new(SafeRoot::open(&dir, RootPolicy::Staging).unwrap()));
        let mut audit = candor_log::AuditLog::new(
            candor_log::ids::TenantRef::generate().unwrap(),
            candor_log::codes::HostRole::Intake,
            candor_log::SoftwareSigner::from_seed(&zeroize::Zeroizing::new([9; 32])),
            candor_log::SystemClock,
            candor_log::CheckpointPolicy::DEFAULT,
        );
        audit.set_primary_sink(Box::new(candor_log::sink::MemorySink::new()));
        let cfg = SealerConfig {
            tenant_id: TENANT,
            deployment_salt: SALT,
            suite: Suite::CandorStd1,
            allowed_peer_uid: 4242,
            limits: Limits::default(),
            chaff: ChaffConfig {
                enabled: false,
                ..ChaffConfig::default()
            },
            directory_trust: DirectoryTrust {
                tenant_id: TENANT,
                org_root_pk: kdlog::k01().verifying_key_bytes(),
                epoch_origin_day: TODAY - 2,
                min_cosignatures: 0,
                min_external: 0,
            },
            enable_note_real: true,
            insecure_dev: Some(InsecureDevMode::acknowledge(&mut audit).unwrap()),
        };
        let sink = Arc::new(NullSink::default());
        let sealer = Sealer::new(
            cfg,
            SigningKey::from_seed(&[0x35; 32]),
            staging,
            Arc::new(FixedClock),
            sink.clone(),
        )
        .unwrap();
        // A real signed directory: 3 Triage Set members (labels 1..3) and one
        // investigator (label 4); category 7 excludes label 2.
        let members: Vec<Member> = (1..=4u8)
            .map(|i| Member {
                user_id: [i; 16],
                k08: SigningKey::from_seed(&[0x80 + i; 32]),
            })
            .collect();
        let meks: Vec<KemKeyPair> = (0..3)
            .map(|_| KemKeyPair::generate(Suite::CandorStd1).unwrap())
            .collect();
        let custodian = KemKeyPair::generate(Suite::CandorStd1).unwrap();
        let disposition = KemKeyPair::generate(Suite::CandorStd1).unwrap();
        let view = kdlog::DirectorySnapshot {
            snapshot_version: 1,
            tree_size: 0,
            issued_hour: u64::from(TODAY) * 24 + 3,
            suite: Suite::CandorStd1,
            custodian_pk: custodian.public.to_bytes(),
            disposition_pk: disposition.public.to_bytes(),
            channels: vec![kdlog::ChannelView {
                channel_id: CHANNEL,
                enabled: true,
                members: members
                    .iter()
                    .map(|m| kdlog::RosterMember {
                        user_id: m.user_id,
                        role_label: u16::from(m.user_id[0]),
                        read_intake: m.user_id[0] <= 3,
                        effective_day: TODAY - 30,
                    })
                    .collect(),
                coi_policies: vec![kdlog::CoiPolicy {
                    entry_hash: [0; 32],
                    effective_day: TODAY - 10,
                    categories: vec![(7, vec![2])],
                }],
                meks: meks
                    .iter()
                    .enumerate()
                    .map(|(i, k)| kdlog::MemberEpochKey {
                        user_id: [i as u8 + 1; 16],
                        epoch_id: 0,
                        valid_from_day: TODAY - 2,
                        valid_until_day: TODAY + 5,
                        revoked: false,
                        public_key: k.public.to_bytes(),
                    })
                    .collect(),
                independent_route: Some([0x33; 16]),
            }],
        };
        let mut log = kdlog::TestLog::new();
        log.sync(&view, &members);
        sealer
            .install_snapshot(log.bundle(&view, 0), |_| true)
            .unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        Harness {
            rt,
            sealer,
            sink,
            words: Wordlist::eff_large().unwrap(),
        }
    })
}

const OPS: [Op; 21] = [
    Op::Hello,
    Op::SessionOpen,
    Op::DraftSet,
    Op::DraftGet,
    Op::GenAccount,
    Op::LoginDerive,
    Op::LoginSign,
    Op::LoadPrefs,
    Op::ConfirmPassphrase,
    Op::RotatePassphrase,
    Op::RotateFinish,
    Op::PartBegin,
    Op::PartChunk,
    Op::SealFinish,
    Op::SealAbort,
    Op::PartDrop,
    Op::NoteReal,
    Op::OpenReply,
    Op::Zeroize,
    Op::Touch,
    Op::Status,
];

fn decoders(data: &[u8]) {
    if let Ok((rid, req)) = decode_request(data) {
        let again = encode_request(rid, &req).unwrap();
        assert_eq!(&again[..], data, "non-canonical request accepted");
    }
    for op in OPS {
        let _ = decode_response(op, data);
    }
    if let Some(p) = data.first_chunk::<4>() {
        if let Ok(n) = frame_len(*p) {
            assert!((1..=MAX_FRAME_LEN).contains(&n));
        }
    }
}

fn is_derive(req: &Request) -> bool {
    matches!(
        req,
        Request::LoginDerive { .. } | Request::SealFinish { .. } | Request::RotateFinish { .. }
    )
}

fn raw_frames(h: &Harness, data: &[u8]) {
    let mut opened: Vec<SessionHandle> = Vec::new();
    let mut rest = data;
    while let Some((p, tail)) = rest.split_first_chunk::<4>() {
        let n = usize::try_from(u32::from_be_bytes(*p)).unwrap_or(usize::MAX);
        let Some(body) = tail.get(..n) else { break };
        rest = &tail[n..];
        let Ok((_, req)) = decode_request(body) else {
            continue;
        };
        if let Request::SessionOpen { sess, .. } = &req {
            opened.push(*sess);
        }
        if !is_derive(&req) {
            let _ = h.rt.block_on(h.sealer.handle(req));
        }
    }
    zeroize(h, opened);
}

/// Leave no session behind (the table is bounded and long-lived).
fn zeroize(h: &Harness, handles: impl IntoIterator<Item = SessionHandle>) {
    for sess in handles {
        let _ = h.rt.block_on(h.sealer.handle(Request::Zeroize { sess }));
    }
}

/// Per-input generator state (learned from responses).
#[derive(Default)]
struct Gen {
    words: Option<Vec<u16>>,
    positions: Option<[u8; 3]>,
    part: Option<[u8; 16]>,
    derive_budget: u8,
}

/// Up to `max` arbitrary bytes.
fn blob(u: &mut Unstructured<'_>, max: usize) -> AResult<Vec<u8>> {
    let n = u.int_in_range(0..=max)?;
    Ok(u.bytes(n)?.to_vec())
}

/// Text from a small alphabet that includes NFC-expanding, composing and
/// multi-byte characters, so the draft caps are probed on both sides.
fn text(u: &mut Unstructured<'_>, max_chars: usize) -> AResult<String> {
    const ALPHABET: [&str; 10] = ["a", "Z", " ", "\u{0958}", "e\u{0301}", "\u{00e9}", "ß", "😀", "\n", "<"];
    let n = u.int_in_range(0..=max_chars)?;
    let mut s = String::new();
    for _ in 0..n {
        s.push_str(ALPHABET[u.choose_index(ALPHABET.len())?]);
    }
    // Occasionally a long run (close to the 40 KiB cap after NFC).
    if u.ratio(1u8, 16)? {
        let c = ALPHABET[u.choose_index(ALPHABET.len())?];
        let reps = u.int_in_range(1_000..=14_000)?;
        s.push_str(&c.repeat(reps));
    }
    Ok(s)
}

fn labels(u: &mut Unstructured<'_>, max: usize) -> AResult<Vec<u16>> {
    let n = u.int_in_range(0..=max)?;
    let mut v: Vec<u16> = (0..n)
        .map(|_| u.int_in_range(0..=9u16))
        .collect::<AResult<_>>()?;
    v.sort_unstable();
    v.dedup();
    Ok(v)
}

fn request(h: &Harness, g: &mut Gen, u: &mut Unstructured<'_>) -> AResult<Request> {
    let sess = SessionHandle([u.int_in_range(0..=3u8)?; 16]);
    let channel = if u.ratio(15u8, 16)? { CHANNEL } else { [u.arbitrary::<u8>()?; 16] };
    Ok(match u.int_in_range(0..=20u8)? {
        0 => Request::Hello { proto: if u.ratio(7u8, 8)? { 1 } else { u.arbitrary()? } },
        1 | 2 => Request::SessionOpen { sess, channel_id: channel },
        3 | 4 => {
            let mode = match u.int_in_range(0..=2u8)? {
                0 => Mode::Anonymous,
                1 => Mode::Confidential,
                _ => Mode::Identified,
            };
            let nf = u.int_in_range(0..=3u16)?;
            let fields = (1..=nf)
                .map(|id| Ok((id, SecretText::new(&text(u, 40)?))))
                .collect::<AResult<Vec<_>>>()?;
            let identity = if u.arbitrary()? { Some(SecretText::new(&text(u, 60)?)) } else { None };
            let coi = if u.arbitrary()? {
                Some(Coi {
                    excluded_labels: zeroize::Zeroizing::new(labels(u, 4)?),
                    categories: zeroize::Zeroizing::new(if u.arbitrary()? { vec![7] } else { labels(u, 2)? }),
                })
            } else {
                None
            };
            Request::DraftSet(DraftSet {
                sess,
                mode,
                message: SecretText::new(&text(u, 200)?),
                fields,
                identity,
                coi,
            })
        }
        5 => Request::DraftGet { sess },
        6 | 7 => Request::GenAccount { sess },
        8 | 9 => {
            let words = match (&g.words, g.positions, u.ratio(3u8, 4)?) {
                (Some(w), Some(p), true) => p.iter().map(|i| w.get(usize::from(*i)).copied().unwrap_or(0)).collect(),
                _ => (0..3).map(|_| u.int_in_range(0..=7_771u16)).collect::<AResult<_>>()?,
            };
            Request::ConfirmPassphrase { sess, words: SecretWords(zeroize::Zeroizing::new(words)) }
        }
        10 | 11 => Request::PartBegin {
            sess,
            declared_len: u.int_in_range(0..=300_000u64)?,
            display_name: SecretText::new(&text(u, 20)?),
            media_type: SecretText::new("application/octet-stream"),
        },
        12 | 13 => {
            let part = match g.part {
                Some(p) if u.ratio(7u8, 8)? => p,
                _ => u.arbitrary()?,
            };
            let n = u.int_in_range(0..=70_000usize)?;
            let byte = u.arbitrary::<u8>()?;
            Request::PartChunk { sess, part, data: SecretBytes::from_slice(&vec![byte; n]), last: u.arbitrary()? }
        }
        14 => Request::PartDrop { sess, part: g.part.unwrap_or([0; 16]) },
        15 => Request::SealAbort { sess },
        16 => {
            if g.derive_budget > 0 && u.arbitrary()? {
                g.derive_budget -= 1;
                match u.int_in_range(0..=2u8)? {
                    0 | 1 => Request::SealFinish { sess, delayed_delivery: u.arbitrary()? },
                    _ => {
                        let phrase = g
                            .words
                            .as_ref()
                            .map(|w| {
                                w.iter()
                                    .map(|i| h.words.get(usize::from(*i)).unwrap_or("x"))
                                    .collect::<Vec<_>>()
                                    .join(" ")
                            })
                            .unwrap_or_default();
                        Request::LoginDerive { sess, passphrase: SecretBytes::from_slice(phrase.as_bytes()) }
                    }
                }
            } else {
                Request::Touch { sess }
            }
        }
        17 => match u.int_in_range(0..=3u8)? {
            0 => Request::LoginSign { sess, challenge: u.arbitrary()? },
            1 => {
                let ct = h.sink.prefs_ct.lock().ok().and_then(|p| p.clone()).unwrap_or_default();
                let ct = if u.arbitrary()? { ct } else { blob(u, 64)? };
                Request::LoadPrefs { sess, prefs_ct: ct }
            }
            2 => Request::RotatePassphrase { sess },
            _ => {
                if g.derive_budget > 0 && u.arbitrary()? {
                    g.derive_budget -= 1;
                    let n = u.int_in_range(0..=2usize)?;
                    let replies = (0..n)
                        .map(|_| Ok(PendingReply { object_hash: u.arbitrary()?, stanza: blob(u, 200)? }))
                        .collect::<AResult<_>>()?;
                    Request::RotateFinish { sess, replies }
                } else {
                    Request::Status
                }
            }
        },
        18 => Request::OpenReply { sess, entry: blob(u, 400)? },
        19 => Request::NoteReal { channel_id: channel, first_object_hash: u.arbitrary()? },
        _ => {
            if u.arbitrary()? {
                Request::Zeroize { sess }
            } else {
                Request::Status
            }
        }
    })
}

fn structured(h: &Harness, data: &[u8], allow_derive: bool) {
    let mut u = Unstructured::new(data);
    let mut g = Gen {
        derive_budget: u8::from(allow_derive),
        ..Gen::default()
    };
    let steps = u.int_in_range(1..=32u8).unwrap_or(1);
    for rid in 0..u32::from(steps) {
        let Ok(req) = request(h, &mut g, &mut u) else { break };
        // The generator may exceed a decoder limit (oversized chunk, too many
        // labels, an over-budget draft): such frames are refused by the
        // decoder, as the sealer's listener would. Whatever decodes must round
        // trip exactly.
        let Ok(bytes) = encode_request(rid, &req) else { continue };
        let Ok((rid2, req2)) = decode_request(&bytes) else { continue };
        assert_eq!(rid2, rid);
        assert!(req2 == req, "request round trip");
        let sealed = matches!(req2, Request::SealFinish { .. });
        match h.rt.block_on(h.sealer.handle(req2)) {
            Response::Words { words, confirm_positions } => {
                g.words = Some(words.0.to_vec());
                g.positions = Some(confirm_positions);
            }
            Response::Confirm { confirm_positions: Some(p), .. } => g.positions = Some(p),
            Response::Part { part } => g.part = Some(part),
            Response::Sealed { .. } if sealed => {
                let _ = h.sealer.flush_accounts();
            }
            _ => {}
        }
    }
    zeroize(h, (0..=3u8).map(|s| SessionHandle([s; 16])));
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    match mode % 4 {
        0 => decoders(rest),
        1 => raw_frames(harness(), rest),
        2 => structured(harness(), rest, false),
        _ => structured(harness(), rest, true),
    }
});
