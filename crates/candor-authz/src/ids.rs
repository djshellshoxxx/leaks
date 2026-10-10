// SPDX-License-Identifier: AGPL-3.0-or-later
//! Opaque identifiers (08 §3.2: random 128-bit IDs) and the blinded COI tag
//! (04 §9.11). `Debug` output is redacted so that no identifier reaches a
//! log, error or panic message through this crate (20 §7, THR-020).

use subtle::ConstantTimeEq;

macro_rules! id16 {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub [u8; 16]);

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($name), "(..)"))
            }
        }
    };
}

id16!(
    /// Tenant identifier. Every decision checks it (15 §5.3, ADR-021).
    TenantId
);
id16!(
    /// Case identifier (`cs_…`).
    CaseId
);
id16!(
    /// Staff account identifier (`us_…`).
    UserId
);
id16!(
    /// Person reference: two accounts of one person share it (15 §5.1, §5.12).
    PersonRef
);
id16!(
    /// Channel identifier (`ch_…`).
    ChannelId
);
id16!(
    /// Department identifier (ABAC `department_scope`).
    DepartmentId
);
id16!(
    /// Import envelope identifier (`ie_…`).
    EnvelopeId
);

/// A recipient key identifier as published in C-14 (32 bytes).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId(pub [u8; 32]);

impl core::fmt::Debug for KeyId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KeyId(..)")
    }
}

/// Blinded COI exclusion tag `HMAC(K_case_excl_v, "candor/coi-excl/tag" ‖ tenant ‖ user)`
/// (04 §9.11, ADR-037(3)). C-22 never computes tags and never learns whose
/// tag it holds; it only tests set membership in constant time.
#[derive(Clone, Copy)]
pub struct ExclTag(pub [u8; 32]);

impl ExclTag {
    /// Constant-time equality (no early exit on the first differing byte).
    #[must_use]
    pub fn ct_eq(&self, other: &ExclTag) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl core::fmt::Debug for ExclTag {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ExclTag(..)")
    }
}

/// Day number (days since 1970-01-01, date-only per ADR-010). Grant expiry and
/// role-assignment validity are day-granular (15 §5.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Day(pub u32);

/// Trusted monotonic seconds supplied by the caller (ADR-046(11): staff
/// exact times are permitted in session, step-up, approval and break-glass
/// state only). Never derived from request input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Seconds(pub u64);

/// Digest of the canonical operation descriptor that a step-up assertion or a
/// dual-control approval is bound to (15 §4.7, §5.8).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpDigest(pub [u8; 32]);

impl core::fmt::Debug for OpDigest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OpDigest(..)")
    }
}
