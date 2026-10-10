// SPDX-License-Identifier: AGPL-3.0-or-later

use candor_relay::{
    DEFAULT_MAX_PENDING_IMPORTS, ImportObject, ImportValidator, IntakeEndpoint, RelayError,
    RelayGuard, RelaySchedule, ValidationError,
};

fn endpoint() -> IntakeEndpoint {
    IntakeEndpoint {
        address: [0_u8; 16],
        port: 8443,
    }
}

#[test]
fn st_rm3_backpressure_threshold_is_strictly_greater_than_50k_pending() {
    let guard = RelayGuard::new(endpoint(), DEFAULT_MAX_PENDING_IMPORTS);
    assert_eq!(guard.may_claim(50_000, 10), Ok(()));
    assert_eq!(guard.may_claim(50_001, 10), Err(RelayError::Backpressure));
    assert_eq!(guard.may_claim(0, 9), Err(RelayError::Backpressure));
}

#[test]
fn st_rm3_relay_validates_hostile_intake_metadata_before_import() {
    let validator = ImportValidator::new([11_u8, 12_u8], 20, [65_536_u64, 262_144_u64]);
    let valid = ImportObject {
        channel_id: 11,
        epoch_index: 18,
        header_slot_count: 16,
        header_ct_len: 8_192,
        manifest_ct_len: 65_536,
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

    let mut header_too_large = valid.clone();
    header_too_large.header_ct_len = 8_193;
    assert_eq!(
        validator.validate(&header_too_large),
        Err(ValidationError::HeaderSize)
    );

    let mut manifest_too_large = valid.clone();
    manifest_too_large.manifest_ct_len = 65_537;
    assert_eq!(
        validator.validate(&manifest_too_large),
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
fn st_rm3_import_slots_and_control_cycles_are_separate() {
    let schedule = RelaySchedule::new([30_u16, 390_u16, 750_u16, 1_110_u16], 15);
    assert!(schedule.is_import_slot(30));
    assert!(schedule.is_import_slot(390));
    assert!(!schedule.is_import_slot(15));
    assert!(schedule.is_control_cycle(15));
    assert!(schedule.is_control_cycle(75));
    assert!(!schedule.is_control_cycle(30));
}
