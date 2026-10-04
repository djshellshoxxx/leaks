// SPDX-License-Identifier: AGPL-3.0-or-later

use candor_ekv::{ErasureVault, VaultError, WrapContext};

fn ctx(tenant: u128, case: u128, recipient: u128) -> WrapContext {
    WrapContext {
        tenant_id: tenant,
        case_id: case,
        key_epoch: 3,
        recipient_key_id: recipient,
    }
}

#[test]
fn st_rm3_ekv_seal_and_unseal_round_trip_inside_case_boundary() {
    let mut vault = ErasureVault::new();
    vault.create(1, 10).unwrap();
    let context = ctx(1, 10, 99);
    let outer = vault.seal(&context, b"inner-wrap").unwrap();
    assert_ne!(outer.as_slice(), b"inner-wrap");
    assert_eq!(vault.unseal(&context, &outer), Ok(b"inner-wrap".to_vec()));
}

#[test]
fn st_rm3_ekv_aad_binds_tenant_case_epoch_and_recipient() {
    let mut vault = ErasureVault::new();
    vault.create(1, 10).unwrap();
    let context = ctx(1, 10, 99);
    let outer = vault.seal(&context, b"inner-wrap").unwrap();

    assert_eq!(vault.unseal(&ctx(2, 10, 99), &outer), Err(VaultError::NoKey));
    assert_eq!(vault.unseal(&ctx(1, 11, 99), &outer), Err(VaultError::NoKey));

    let mut wrong_recipient = context;
    wrong_recipient.recipient_key_id = 100;
    assert_eq!(vault.unseal(&wrong_recipient, &outer), Err(VaultError::Authentication));

    let mut wrong_epoch = context;
    wrong_epoch.key_epoch = 4;
    assert_eq!(vault.unseal(&wrong_epoch, &outer), Err(VaultError::Authentication));
}

#[test]
fn st_rm3_destroy_makes_old_outer_wraps_permanently_unreadable() {
    let mut vault = ErasureVault::new();
    vault.create(1, 10).unwrap();
    let context = ctx(1, 10, 99);
    let outer = vault.seal(&context, b"inner-wrap").unwrap();

    vault.destroy(1, 10).unwrap();
    assert_eq!(vault.unseal(&context, &outer), Err(VaultError::Destroyed));
    assert_eq!(vault.seal(&context, b"new"), Err(VaultError::Destroyed));
}

#[test]
fn st_rm3_rekey_missing_creates_fresh_key_but_never_revives_old_ciphertext() {
    let mut vault = ErasureVault::new();
    vault.create(1, 10).unwrap();
    let context = ctx(1, 10, 99);
    let old_outer = vault.seal(&context, b"old").unwrap();
    vault.simulate_missing_key_for_restore_test(1, 10).unwrap();

    vault.rekey_missing(1, 10).unwrap();
    assert_eq!(vault.unseal(&context, &old_outer), Err(VaultError::Authentication));
    let new_outer = vault.seal(&context, b"new").unwrap();
    assert_eq!(vault.unseal(&context, &new_outer), Ok(b"new".to_vec()));
}

#[test]
fn st_rm3_duplicate_create_fails_closed() {
    let mut vault = ErasureVault::new();
    vault.create(1, 10).unwrap();
    assert_eq!(vault.create(1, 10), Err(VaultError::AlreadyExists));
}
