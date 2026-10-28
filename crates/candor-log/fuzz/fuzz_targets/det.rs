// SPDX-License-Identifier: AGPL-3.0-or-later
//! Harness helper: deterministic identifiers for reproducible fixtures and
//! seeds. Re-implements the documented `IdToken` MAC under the harness's
//! own (public, test-only) key; production code cannot do this without the
//! deployment's secret `AuditIdKey`.
#![allow(dead_code)]

use candor_log::ids::{AuditIdKey, IdToken};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

pub const KEY: [u8; 32] = [1; 32];

pub fn key() -> AuditIdKey {
    AuditIdKey::new(KEY)
}

/// Token for `<ty>` with id bytes `[n; 16]`.
pub fn token(ty: &str, n: u8) -> IdToken {
    let id = [n; 16];
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(&KEY).expect("hmac key");
    m.update(format!("candor/v1/audit/id-token/{ty}").as_bytes());
    m.update(&[0]);
    m.update(&id);
    let tag = m.finalize().into_bytes();
    let mut t = [0u8; 32];
    t[..16].copy_from_slice(&id);
    t[16..].copy_from_slice(&tag[..16]);
    IdToken::from_bytes(t)
}

macro_rules! det {
    ($f:ident, $t:ident) => {
        pub fn $f(n: u8) -> candor_log::ids::$t {
            candor_log::ids::$t::unseal(&key(), &token(stringify!($t), n)).expect("token")
        }
    };
}
det!(tenant, TenantRef);
det!(user, UserRef);
det!(case, CaseRef);
det!(receipt, ReceiptId);
