// SPDX-License-Identifier: AGPL-3.0-or-later
//! ST-043 `fuzz_sealer_ipc` (IMPL-RM2 §2.3, AUD-RM2-SEA-09).
//!
//! 1. Decoder: arbitrary bytes never panic or over-allocate in
//!    `decode_request` / `decode_response` / `frame_len`, and any request that
//!    decodes re-encodes byte-identically (canonical CBOR only).
//! 2. State machine: the input is split into length-prefixed frames; every
//!    request that decodes is fed to one long-lived `Sealer` (in-memory sink,
//!    tmpfs-like staging under the temp dir, verified test directory). Ops that
//!    run Argon2id (`LOGIN_DERIVE`, `SEAL_FINISH`, `ROTATE_FINISH`) are skipped to
//!    keep executions fast; everything else must never panic.
#![no_main]

use std::sync::{Arc, OnceLock};

use candor_core::Suite;
use candor_core::kem::KemKeyPair;
use candor_core::sig::SigningKey;
use candor_safefs::{RootPolicy, SafeRoot};
use candor_sealer::proto::{
    MAX_FRAME_LEN, Op, Request, decode_request, decode_response, encode_request, frame_len,
};
use candor_sealer::server::clock::{Clock, ClockError};
use candor_sealer::server::directory::{
    ChannelView, DirectorySnapshot, DirectoryTrust, MemberEpochKey, RosterMember, SignedCheckpoint,
    SnapshotBundle, merkle,
};
use candor_sealer::server::hardening::InsecureDevMode;
use candor_sealer::server::sink::{AccountUpsert, EnvelopeGroup, EnvelopeSink, SinkError};
use candor_sealer::server::{ChaffConfig, Limits, Sealer, SealerConfig};
use libfuzzer_sys::fuzz_target;

const TENANT: [u8; 16] = [0x11; 16];
const CHANNEL: [u8; 16] = [0x22; 16];
const TODAY: u32 = 20_000;

struct FixedClock;
impl Clock for FixedClock {
    fn today(&self) -> Result<u32, ClockError> {
        Ok(TODAY)
    }
}

/// Accepts everything and deletes staged blobs (keeps memory flat).
struct NullSink(&'static SafeRoot);
impl EnvelopeSink for NullSink {
    fn commit_envelope_group(
        &self,
        group: EnvelopeGroup,
        _: u32,
        _: u32,
        _: u8,
    ) -> Result<(), SinkError> {
        if let candor_sealer::server::sink::Blob::Staged { id, .. } = &group.bundle.blob {
            let _ = self.0.remove(id, candor_safefs::SlotTime::utc_day_start(0));
        }
        Ok(())
    }
    fn upsert_account(&self, _: AccountUpsert) -> Result<(), SinkError> {
        Ok(())
    }
}

struct Harness {
    rt: tokio::runtime::Runtime,
    sealer: Sealer,
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
        let log_key = SigningKey::from_seed(&[0x4c; 32]);
        let mut audit = candor_log::AuditLog::new(
            candor_log::ids::TenantRef::derive(&candor_log::ids::AuditIdKey::new([3; 32]), b"t"),
            candor_log::codes::HostRole::Intake,
            candor_log::SoftwareSigner::from_seed(&zeroize::Zeroizing::new([9; 32])),
            candor_log::SystemClock,
            candor_log::CheckpointPolicy::DEFAULT,
        );
        audit.set_primary_sink(Box::new(candor_log::sink::MemorySink::new()));
        let cfg = SealerConfig {
            tenant_id: TENANT,
            deployment_salt: [0x44; 32],
            suite: Suite::CandorStd1,
            allowed_peer_uid: 4242,
            limits: Limits::default(),
            chaff: ChaffConfig {
                enabled: false,
                ..ChaffConfig::default()
            },
            directory_trust: DirectoryTrust {
                tenant_id: TENANT,
                log_keys: vec![log_key.verifying_key_bytes()],
                witnesses: vec![],
                min_cosignatures: 0,
                min_external: 0,
            },
            enable_note_real: true,
            insecure_dev: Some(InsecureDevMode::acknowledge(&mut audit).unwrap()),
        };
        let sealer = Sealer::new(
            cfg,
            SigningKey::from_seed(&[0x35; 32]),
            staging,
            Arc::new(FixedClock),
            Arc::new(NullSink(staging)),
        )
        .unwrap();
        let members: Vec<(u8, KemKeyPair)> = (1..=3u8)
            .map(|i| (i, KemKeyPair::generate(Suite::CandorStd1).unwrap()))
            .collect();
        let custodian = KemKeyPair::generate(Suite::CandorStd1).unwrap();
        let disposition = KemKeyPair::generate(Suite::CandorStd1).unwrap();
        let leaves: Vec<[u8; 32]> = (0..10u64)
            .map(|i| merkle::leaf_hash(&i.to_be_bytes()))
            .collect();
        let view = DirectorySnapshot {
            snapshot_version: 1,
            tree_size: 10,
            root_hash: merkle::root(&leaves),
            issued_hour: u64::from(TODAY) * 24,
            suite: Suite::CandorStd1,
            epoch_origin_day: TODAY,
            custodian_pk: custodian.public.to_bytes(),
            disposition_pk: disposition.public.to_bytes(),
            channels: vec![ChannelView {
                channel_id: CHANNEL,
                enabled: true,
                roster_entry_hash: [5; 32],
                roster_version: 1,
                members: members
                    .iter()
                    .map(|(i, _)| RosterMember {
                        user_id: [*i; 16],
                        role_label: u16::from(*i),
                        read_intake: true,
                        effective_day: 0,
                    })
                    .collect(),
                coi_policies: vec![],
                meks: members
                    .iter()
                    .map(|(i, k)| MemberEpochKey {
                        user_id: [*i; 16],
                        epoch_id: 0,
                        valid_from_day: TODAY,
                        valid_until_day: TODAY + 7,
                        revoked: false,
                        public_key: k.public.to_bytes(),
                    })
                    .collect(),
                independent_route: None,
            }],
            user_keys: vec![],
        };
        let mut cp = SignedCheckpoint {
            tree_size: view.tree_size,
            root_hash: view.root_hash,
            issued_hour: view.issued_hour,
            log_sig: [0; 64],
            cosignatures: vec![],
        };
        cp.log_sig = log_key.sign(&cp.note_body(&TENANT).unwrap());
        sealer
            .install_snapshot(
                SnapshotBundle {
                    view,
                    checkpoint: cp,
                    consistency_proof: vec![],
                },
                |_| true,
            )
            .unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        Harness { rt, sealer }
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

fuzz_target!(|data: &[u8]| {
    // 1. Decoders on the raw input.
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
    // 2. State machine over the frames in the input.
    let h = harness();
    let mut rest = data;
    while let Some((p, tail)) = rest.split_first_chunk::<4>() {
        let n = usize::try_from(u32::from_be_bytes(*p)).unwrap_or(usize::MAX);
        let Some(body) = tail.get(..n) else { break };
        rest = &tail[n..];
        let Ok((_, req)) = decode_request(body) else {
            continue;
        };
        if matches!(
            req,
            Request::LoginDerive { .. } | Request::SealFinish { .. } | Request::RotateFinish { .. }
        ) {
            continue;
        }
        let _ = h.rt.block_on(h.sealer.handle(req));
    }
});
