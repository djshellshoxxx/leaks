// SPDX-License-Identifier: AGPL-3.0-or-later

use candor_ekv::{ApproverId, ErasureVault, VaultError, WrapContext};

fn context(tenant_id: u128, case_id: u128, recipient_key_id: u128) -> WrapContext {
    WrapContext {
        tenant_id,
        case_id,
        key_epoch: 3,
        recipient_key_id,
    }
}

#[test]
fn st_rm3_ekv_generates_per_case_key_and_seals_inner_wrap() {
    let mut vault = ErasureVault::new();
    let handle = vault.create_case(1, 10).unwrap();
    let ctx = context(1, 10, 99);
    let outer = vault.seal(handle, ctx, b"inner-wrap").unwrap();
    assert_ne!(outer.as_slice(), b"inner-wrap");
    assert_eq!(vault.unseal(handle, ctx, &outer), Ok(b"inner-wrap".to_vec()));
}

#[test]
fn st_rm3_aad_binds_tenant_case_epoch_and_recipient() {
    let mut vault = ErasureVault::new();
    let handle = vault.create_case(1, 10).unwrap();
    let ctx = context(1, 10, 99);
    let outer = vault.seal(handle, ctx, b"inner-wrap").unwrap();

    assert_eq!(
        vault.unseal(handle, context(2, 10, 99), &outer),
        Err(VaultError::WrongCase)
    );
    assert_eq!(
        vault.unseal(handle, context(1, 11, 99), &outer),
        Err(VaultError::WrongCase)
    );

    let mut wrong_epoch = ctx;
    wrong_epoch.key_epoch = 4;
    assert_eq!(
        vault.unseal(handle, wrong_epoch, &outer),
        Err(VaultError::Authentication)
    );

    let mut wrong_recipient = ctx;
    wrong_recipient.recipient_key_id = 100;
    assert_eq!(
        vault.unseal(handle, wrong_recipient, &outer),
        Err(VaultError::Authentication)
    );
}

#[test]
fn st_rm3_destroy_makes_old_outer_wraps_unreadable() {
    let mut vault = ErasureVault::new();
    let handle = vault.create_case(1, 10).unwrap();
    let ctx = context(1, 10, 99);
    let outer = vault.seal(handle, ctx, b"inner-wrap").unwrap();

    assert_eq!(vault.approve_destroy(handle, ApproverId(1)), Ok(false));
    assert_eq!(vault.approve_destroy(handle, ApproverId(2)), Ok(true));
    assert_eq!(vault.unseal(handle, ctx, &outer), Err(VaultError::Destroyed));
    assert_eq!(vault.seal(handle, ctx, b"new"), Err(VaultError::Destroyed));
}

#[test]
fn st_rm3_restore_rekey_never_revives_old_ciphertext() {
    let mut vault = ErasureVault::new();
    let handle = vault.create_case(1, 10).unwrap();
    let ctx = context(1, 10, 99);
    let old_outer = vault.seal(handle, ctx, b"old").unwrap();

    vault.mark_missing_for_restore(handle).unwrap();
    assert_eq!(vault.unseal(handle, ctx, &old_outer), Err(VaultError::Missing));
    vault.rekey_missing(handle).unwrap();
    assert_eq!(
        vault.unseal(handle, ctx, &old_outer),
        Err(VaultError::Authentication)
    );

    let new_outer = vault.seal(handle, ctx, b"new").unwrap();
    assert_eq!(vault.unseal(handle, ctx, &new_outer), Ok(b"new".to_vec()));
}

#[test]
fn st_rm3_duplicate_case_key_creation_fails_closed() {
    let mut vault = ErasureVault::new();
    assert!(vault.create_case(1, 10).is_ok());
    assert_eq!(vault.create_case(1, 10), Err(VaultError::AlreadyExists));
}
