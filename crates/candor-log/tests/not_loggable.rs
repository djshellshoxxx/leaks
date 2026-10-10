// SPDX-License-Identifier: AGPL-3.0-or-later
//! Marker tests (LOG-001, LOG-002, P-01, P-02, P-05, P-07): prohibited data
//! types cannot be audit fields, and sensitive wrappers cannot be
//! formatted. Each assertion fails to *compile* if the property breaks
//! (ambiguity trick: two blanket impls collide when the trait is
//! implemented). The trybuild suite in `compile_fail.rs` shows the
//! corresponding compiler errors.

use candor_log::AuditField;
use candor_log::sensitive::Sensitive;

/// Compile-time "does not implement" assertion.
macro_rules! assert_not_impl {
    ($t:ty: $tr:path) => {
        const _: fn() = || {
            trait AmbiguousIfImpl<A> {
                fn some_item() {}
            }
            impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
            #[allow(dead_code)]
            struct Invalid;
            impl<T: ?Sized + $tr> AmbiguousIfImpl<Invalid> for T {}
            let _ = <$t as AmbiguousIfImpl<_>>::some_item;
        };
    };
}

// A source IP string, header, filename or body cannot be passed as a field.
assert_not_impl!(String: AuditField);
assert_not_impl!(&'static str: AuditField);
assert_not_impl!(std::net::IpAddr: AuditField);
assert_not_impl!(std::net::SocketAddr: AuditField);
assert_not_impl!(std::path::PathBuf: AuditField);
assert_not_impl!(Vec<u8>: AuditField);
// Sizes and raw times: no bare integers or SystemTime.
assert_not_impl!(u64: AuditField);
assert_not_impl!(usize: AuditField);
assert_not_impl!(std::time::SystemTime: AuditField);
// Sensitive wrappers: not loggable, not printable, not serializable.
assert_not_impl!(Sensitive<String>: AuditField);
assert_not_impl!(Sensitive<String>: core::fmt::Debug);
assert_not_impl!(Sensitive<String>: core::fmt::Display);
assert_not_impl!(Sensitive<String>: serde::Serialize);
assert_not_impl!(candor_log::ids::DaySalt: core::fmt::Debug);

#[test]
fn sensitive_values_usable_but_not_loggable() {
    let ip: candor_log::sensitive::IpAddrText = Sensitive::new(String::from("203.0.113.7"));
    assert_eq!(ip.expose().len(), 11);
}
