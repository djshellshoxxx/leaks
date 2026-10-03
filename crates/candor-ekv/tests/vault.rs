// SPDX-License-Identifier: AGPL-3.0-or-later
use candor_ekv::{ApproverId, ErasureVault, KeyHandle, VaultError};

fn created(vault: &mut ErasureVault, key: [u8; 32]) -> Option<KeyHandle> {
    match vault.create(key) {
        Ok(handle) => Some(handle),
        Err(_) => None,
    }
}

#[test]
fn destruction_requires_two_distinct_approvers() {
    let mut vault = ErasureVault::new();
    let Some(handle) = created(&mut vault, [7; 32]) else {
        assert!(false, "key creation must succeed");
        return;
    };
    assert_eq!(vault.approve_destroy(handle, ApproverId(1)), Ok(false));
    assert_eq!(
        vault.approve_destroy(handle, ApproverId(1)),
        Err(VaultError::DuplicateApprover)
    );
    assert_eq!(vault.approve_destroy(handle, ApproverId(2)), Ok(true));
    assert_eq!(vault.key(handle), Err(VaultError::Destroyed));
}

#[test]
fn destruction_is_irreversible_and_idempotent() {
    let mut vault = ErasureVault::new();
    let Some(handle) = created(&mut vault, [9; 32]) else {
        assert!(false, "key creation must succeed");
        return;
    };
    assert_eq!(vault.approve_destroy(handle, ApproverId(4)), Ok(false));
    assert_eq!(vault.approve_destroy(handle, ApproverId(5)), Ok(true));
    assert_eq!(vault.approve_destroy(handle, ApproverId(6)), Ok(true));
    assert_eq!(vault.key(handle), Err(VaultError::Destroyed));
}

#[test]
fn handles_do_not_expose_key_material_in_debug() {
    let mut vault = ErasureVault::new();
    let Some(handle) = created(&mut vault, [0xab; 32]) else {
        assert!(false, "key creation must succeed");
        return;
    };
    let rendered = format!("{handle:?}");
    assert!(!rendered.contains("171"));
    assert!(!rendered.contains("ab"));
}
