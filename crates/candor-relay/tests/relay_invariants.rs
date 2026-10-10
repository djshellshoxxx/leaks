// SPDX-License-Identifier: AGPL-3.0-or-later

use candor_relay::{
    Backpressure, ImportObject, ImportValidator, RelayAuthError, RelayAuthenticator, RelaySchedule,
    ValidationError,
};
use ed25519_dalek::{Signer, SigningKey};

fn signed_request(
    key: &SigningKey,
    method: &str,
    path: &str,
    body: &[u8],
    counter: u64,
) -> [u8; 64] {
    let message = candor_relay::request_signing_message(method, path, body, counter);
    key.sign(&message).to_bytes()
}

#[test]
fn st_rm3_relay_rejects_replayed_or_non_increasing_counters() {
    let signing = SigningKey::from_bytes(&[7_u8; 32]);
    let verifying = signing.verifying_key();
    let mut auth = RelayAuthenticator::new(verifying, 41);
    let sig = signed_request(&signing, "POST", "/relay/v1/batches/claim", b"claim", 42);

    assert_eq!(
        auth.verify("POST", "/relay/v1/batches/claim", b"claim", 42, &sig),
        Ok(())
    );
    assert_eq!(
        auth.verify("POST", "/relay/v1/batches/claim", b"claim", 42, &sig),
        Err(RelayAuthError::Replay)
    );

    let lower = signed_request(&signing, "POST", "/relay/v1/batches/claim", b"claim", 40);
    assert_eq!(
        auth.verify("POST", "/relay/v1/batches/claim", b"claim", 40, &lower),
        Err(RelayAuthError::Replay)
    );
}

#[test]
fn st_rm3_relay_signature_binds_method_path_body_and_counter() {
    let signing = SigningKey::from_bytes(&[9_u8; 32]);
    let verifying = signing.verifying_key();
    let mut auth = RelayAuthenticator::new(verifying, 0);
    let sig = signed_request(&signing, "GET", "/relay/v1/health", b"", 1);

    assert_eq!(auth.verify("GET", "/relay/v1/health", b"", 1, &sig), Ok(()));

    let mut auth = RelayAuthenticator::new(signing.verifying_key(), 0);
    assert_eq!(
        auth.verify("POST", "/relay/v1/health", b"", 1, &sig),
        Err(RelayAuthError::BadSignature)
    );
}

#[test]
fn st_rm3_relay_validator_accepts_only_tenant_channels_current_epochs_and_bounded_parts() {
    let validator = ImportValidator::new([11_u8, 12_u8], 20, [65_536_u64, 262_144_u64]);
    let valid = ImportObject {
        channel_id: 11,
        epoch_index: 18,
        header_slot_count: 16,
        header_ct_len: 8_000,
        manifest_ct_len: 64_000,
        part_padded_sizes: vec![65_536, 262_144],
    };
    assert_eq!(validator.validate(&valid), Ok(()));

    let mut wrong_channel = valid.clone();
    wrong_channel.channel_id = 99;
    assert_eq!(
        validator.validate(&wrong_channel),
        Err(ValidationError::Channel)
    );

    let mut old_epoch = valid.clone();
    old_epoch.epoch_index = 16;
    assert_eq!(validator.validate(&old_epoch), Err(ValidationError::Epoch));

    let mut wrong_slots = valid.clone();
    wrong_slots.header_slot_count = 15;
    assert_eq!(
        validator.validate(&wrong_slots),
        Err(ValidationError::HeaderSlots)
    );

    let mut huge_manifest = valid.clone();
    huge_manifest.manifest_ct_len = 65_537;
    assert_eq!(
        validator.validate(&huge_manifest),
        Err(ValidationError::ManifestSize)
    );

    let mut too_many_parts = valid.clone();
    too_many_parts.part_padded_sizes = vec![65_536; 33];
    assert_eq!(
        validator.validate(&too_many_parts),
        Err(ValidationError::PartCount)
    );

    let mut non_bucket = valid;
    non_bucket.part_padded_sizes = vec![123_456];
    assert_eq!(
        validator.validate(&non_bucket),
        Err(ValidationError::PartBucket)
    );
}

#[test]
fn st_rm3_relay_backpressure_matches_spec_thresholds() {
    assert!(!Backpressure::new(10, 50_000).must_stop());
    assert!(Backpressure::new(9, 0).must_stop());
    assert!(Backpressure::new(100, 50_001).must_stop());
}

#[test]
fn st_rm3_relay_schedule_never_turns_control_cycles_into_import_slots() {
    let schedule = RelaySchedule::new([30_u16, 390_u16, 750_u16, 1_110_u16], 15);

    assert!(schedule.is_import_slot(30));
    assert!(schedule.is_import_slot(1_110));
    assert!(!schedule.is_import_slot(15));
    assert!(schedule.is_control_cycle(15));
    assert!(schedule.is_control_cycle(75));
    assert!(!schedule.is_control_cycle(30));
}

#[test]
fn st_rm3_relay_header_and_manifest_limits_are_exact() {
    let validator = ImportValidator::new([1_u8], 10, [65_536_u64]);
    let base = ImportObject {
        channel_id: 1,
        epoch_index: 10,
        header_slot_count: 16,
        header_ct_len: 8_192,
        manifest_ct_len: 65_536,
        part_padded_sizes: vec![65_536],
    };
    assert_eq!(validator.validate(&base), Ok(()));

    let mut header_too_large = base.clone();
    header_too_large.header_ct_len = 8_193;
    assert_eq!(
        validator.validate(&header_too_large),
        Err(ValidationError::HeaderSize)
    );

    let mut manifest_too_large = base;
    manifest_too_large.manifest_ct_len = 65_537;
    assert_eq!(
        validator.validate(&manifest_too_large),
        Err(ValidationError::ManifestSize)
    );
}
