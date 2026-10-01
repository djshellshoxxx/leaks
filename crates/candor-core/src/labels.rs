// SPDX-License-Identifier: Apache-2.0 OR MIT
//! HKDF label and domain-separation registry (§10, CRYPTO-012).
//!
//! Every `candor/...` byte string used anywhere in this crate is defined here and
//! nowhere else. The unit tests reject duplicate values; `tests/label_registry.rs`
//! rejects any `candor/` string literal in another source file of this crate
//! ("unregistered literal", CI job `label-registry`).
//! Labels that are a prefix followed by a fixed-width suffix (suite, index, table id)
//! are registered as their prefix.

/// How a registered string is used. One string may have several uses (for example
/// `candor/v1/wrap/case` is both an HKDF `info` and an AAD prefix, §13.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelUse {
    /// HKDF-Expand `info` (possibly followed by a fixed-width suffix).
    HkdfInfo,
    /// HKDF-Extract salt.
    HkdfSalt,
    /// HPKE `info` prefix.
    HpkeInfo,
    /// AEAD AAD prefix.
    Aad,
    /// Hash domain separator.
    HashDomain,
    /// Signature context prefix.
    SignatureContext,
}

/// One registry entry.
#[derive(Debug, Clone, Copy)]
pub struct Label {
    /// Constant name in this module.
    pub name: &'static str,
    /// The exact bytes.
    pub value: &'static [u8],
    /// Uses.
    pub uses: &'static [LabelUse],
    /// Spec reference.
    pub spec: &'static str,
}

macro_rules! labels {
    ($( $(#[$m:meta])* $name:ident = $value:literal, [$($use:ident),+], $spec:literal; )+) => {
        $( $(#[$m])* pub const $name: &[u8] = $value; )+
        /// The complete registry.
        pub const REGISTRY: &[Label] = &[
            $( Label { name: stringify!($name), value: $value, uses: &[$(LabelUse::$use),+], spec: $spec }, )+
        ];
    };
}

labels! {
    /// STREAM key `‖ suite` (§13.3).
    PAYLOAD = b"candor/v1/payload", [HkdfInfo], "§10, §13.3";
    /// Header MAC key `‖ suite` (§13.1).
    HEADER_MAC = b"candor/v1/header-mac", [HkdfInfo], "§10, §13.1";
    /// Dummy-slot KEM seed and encapsulation randomness `‖ u8 i` (§13.2).
    DUMMY_SLOT = b"candor/v1/dummy-slot", [HkdfInfo], "§10, §13.2";
    /// Dummy-slot plaintext `‖ u8 i` (§13.2).
    DUMMY_SLOT_PT = b"candor/v1/dummy-slot-pt", [HkdfInfo], "§10, §13.2";
    /// Erasure-Key layer AEAD key and AAD prefix (§9.10, §13.2).
    EK_LAYER = b"candor/v1/ek-layer", [HkdfInfo, Aad], "§10, §13.2";
    /// EKV at-rest key (§9.10).
    EKV_MASTER = b"candor/v1/ekv/master", [HkdfInfo], "§10";
    /// Case record key `‖ u16 table_id` (§13.8).
    CASE_RECORD = b"candor/v1/case/record/", [HkdfInfo], "§10, §13.8";
    /// Desk keystore key K11 (§9.4) and keystore AAD prefix (§9.9).
    DESK_KEYSTORE = b"candor/v1/desk/keystore", [HkdfInfo, Aad], "§10, §9.9";
    /// Source lookup id (§11.3).
    SOURCE_LOOKUP_ID = b"candor/v1/source/lookup-id", [HkdfInfo], "§10, §11.3";
    /// Source auth Ed25519 seed (§11.3).
    SOURCE_AUTH_ED25519 = b"candor/v1/source/auth-ed25519", [HkdfInfo], "§10, §11.3";
    /// Source signing Ed25519 seed (§11.3).
    SOURCE_SIGN_ED25519 = b"candor/v1/source/sign-ed25519", [HkdfInfo], "§10, §11.3";
    /// Source KEM seed `‖ suite` (§11.3).
    SOURCE_KEM_SEED = b"candor/v1/source/kem-seed", [HkdfInfo], "§10, §11.3";
    /// Source mailbox id `‖ u32 report_index` (§11.3).
    SOURCE_MAILBOX = b"candor/v1/source/mailbox/", [HkdfInfo], "§10, §11.3";
    /// Backup archive key (§17).
    BACKUP_OBJECT = b"candor/v1/backup/object", [HkdfInfo], "§10";
    /// Export payload key.
    EXPORT_PACKAGE = b"candor/v1/export/package", [HkdfInfo], "§10";
    /// Source web session MAC key (15).
    SESSION_SOURCE_WEB = b"candor/v1/session/source-web", [HkdfInfo], "§10";
    /// K_prefs (§11.3) and `prefs_ct` AAD prefix (§9.9).
    SOURCE_PREFS = b"candor/v1/source/prefs", [HkdfInfo, Aad], "§10, §11.3, §9.9";
    /// Tier W staged part STREAM key (§9.13).
    STAGE_PART = b"candor/v1/stage/part", [HkdfInfo], "§10, §9.13";
    /// Blinded COI exclusion key (ADR-037(3); only label outside `candor/v1/`).
    COI_EXCL = b"candor/coi-excl/v1", [HkdfInfo], "§10, §9.11";
    /// Per-authenticator keystore slot key and AAD prefix (§9.4, §9.9).
    DESK_KEYSTORE_SLOT = b"candor/v1/desk/keystore-slot", [HkdfInfo, Aad], "§10, §9.9";
    /// TEE report-data domain separator (§9.14).
    SEALER_ATTEST = b"candor/v1/sealer-attest", [HashDomain], "§10, §9.14";
    /// Per-case metadata key K43 and its AAD prefix (§9.10a).
    EK_META = b"candor/v1/ek-meta", [HkdfInfo, Aad], "§10, §9.10a";
    /// Desk case-key cache AAD prefix (§9.10).
    DESK_CASE_KEY_CACHE = b"candor/v1/desk/case-key-cache", [Aad], "§10, §9.10";
    /// Chaff CK derivation (§12.7).
    CHAFF_SEED = b"candor/v1/chaff/seed", [HkdfInfo], "§10, §12.7";
    /// HPKE info prefix for `disposition_ct` (§12.7).
    WRAP_DISPOSITION = b"candor/v1/wrap/disposition", [HpkeInfo], "§10, §12.7";
    /// HPKE info prefix for MANAGED audit exports (§9.15).
    WRAP_AUDIT_EXPORT = b"candor/v1/wrap/audit-export", [HpkeInfo], "§10, §9.15";
    /// Source App vault key K44 (§11.8).
    SOURCE_APP_VAULT = b"candor/v1/source-app/vault", [HkdfInfo], "§10, §11.8";
    /// Intake deletion list signature context (§18.6).
    INTAKE_DELETION_LIST = b"candor/v1/intake/deletion-list", [SignatureContext], "§10";
    /// Audit hash-chain domain separator (20).
    AUDIT_CHAIN = b"candor/v1/audit/chain", [HashDomain], "§10";

    /// Source PRK extract salt (§11.3) and source-derived key salt.
    SOURCE_SALT_LABEL = b"candor/v1/source", [HkdfSalt], "§10, §11.3";
    /// Case record / CASE_AEAD extract salt (§13.2, §13.8).
    CASE_SALT = b"candor/v1/case", [HkdfSalt], "§10, §13.2";

    /// Deployment-salt hash domain (§11.3).
    SOURCE_SALT_DOMAIN = b"candor/v1/source-salt", [HashDomain], "§11.3";
    /// `lookup_tag` hash domain (§11.4).
    LOOKUP_TAG = b"candor/v1/lookup-tag", [HashDomain], "§11.4";
    /// `key_id` hash domain (§13.2).
    KEY_ID = b"candor/v1/key-id", [HashDomain], "§13.2";
    /// Case-key bound_hash domain (§13.2).
    CASEKEY_BOUND = b"candor/v1/casekey", [HashDomain], "§13.2";
    /// Channel-key bound_hash domain (§13.2).
    CHANKEY_BOUND = b"candor/v1/chankey", [HashDomain], "§13.2";

    /// Slot AAD prefix (§13.2).
    SLOT_AAD = b"candor/v1/slot", [Aad], "§13.2, §9.9";
    /// Encrypted record AAD prefix (§13.8).
    RECORD_AAD = b"candor/v1/rec", [Aad], "§13.8";

    /// HPKE info: CK to a Member Epoch Key (§9.9, §13.2).
    WRAP_MEMBER_EPOCH = b"candor/v1/wrap/member-epoch", [HpkeInfo], "§9.9, §13.2";
    /// HPKE info: identity CK to K13 (§9.9, §13.2).
    WRAP_CUSTODIAN = b"candor/v1/wrap/custodian", [HpkeInfo], "§9.9, §13.2";
    /// CASE_AEAD wrap key info and AAD prefix (§9.9, §13.2).
    WRAP_CASE = b"candor/v1/wrap/case", [HkdfInfo, Aad], "§9.9, §13.2";
    /// HPKE info: reply CK to the source (§9.9, §13.5).
    WRAP_REPLY = b"candor/v1/wrap/reply", [HpkeInfo], "§9.9, §13.5";
    /// HPKE info: viewer job (§9.9, §13.7).
    WRAP_VIEWER_JOB = b"candor/v1/wrap/viewer-job", [HpkeInfo], "§9.9, §13.7";
    /// HPKE info: case key to K09/K14 (§9.9).
    WRAP_CASEKEY = b"candor/v1/wrap/casekey", [HpkeInfo], "§9.9";
    /// HPKE info: CIK private to K09 (§9.9).
    WRAP_CHANNEL = b"candor/v1/wrap/channel", [HpkeInfo], "§9.9";
    /// HPKE info: K13 private to custodian K09 (§9.9).
    WRAP_CUSTODIAN_GROUP = b"candor/v1/wrap/custodian-group", [HpkeInfo], "§9.9";
    /// HPKE info: routing_ct to K37 (§9.9, §9.12).
    WRAP_ROUTING = b"candor/v1/wrap/routing", [HpkeInfo], "§9.9";
    /// HPKE info: Export Package CK to K38/K30 (§9.9).
    WRAP_CONNECTOR = b"candor/v1/wrap/connector", [HpkeInfo], "§9.9";

    /// Source authentication challenge signature (§11.5).
    SIG_SOURCE_AUTH = b"candor/v1/source-auth", [SignatureContext], "§11.5";
    /// SUBMISSION source signature (§13.4).
    SIG_SUBMISSION = b"candor/v1/submission-sig", [SignatureContext], "§13.4";
    /// SOURCE_MESSAGE source signature (§13.4).
    SIG_SOURCE_MESSAGE = b"candor/v1/source-message-sig", [SignatureContext], "§13.4";
    /// Tier W sealer signature (§13.4).
    SIG_SEALER = b"candor/v1/sealer-sig", [SignatureContext], "§13.4";
    /// Reply signature (§13.5).
    SIG_REPLY = b"candor/v1/reply-sig", [SignatureContext], "§13.5";
}

/// Look up a registry entry by value.
#[must_use]
pub fn lookup(value: &[u8]) -> Option<&'static Label> {
    REGISTRY.iter().find(|l| l.value == value)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]
    use super::*;
    use std::collections::HashSet;

    /// CRYPTO-012 / CI job `label-registry`: no duplicate values or names.
    #[test]
    fn registry_has_no_duplicates() {
        let mut values = HashSet::new();
        let mut names = HashSet::new();
        for l in REGISTRY {
            assert!(values.insert(l.value), "duplicate label value {:?}", String::from_utf8_lossy(l.value));
            assert!(names.insert(l.name), "duplicate label name {}", l.name);
        }
    }

    /// The duplicate check itself must fire on a duplicate.
    #[test]
    fn duplicate_detection_works() {
        let dup = [REGISTRY[0], REGISTRY[0]];
        let mut values = HashSet::new();
        let ok = dup.iter().all(|l| values.insert(l.value));
        assert!(!ok);
    }

    #[test]
    fn labels_are_ascii_and_namespaced() {
        for l in REGISTRY {
            assert!(l.value.is_ascii(), "{}", l.name);
            assert!(l.value.starts_with(b"candor/"), "{}", l.name);
            // Only COI_EXCL is outside candor/v1/ (fixed by ADR-037(3)).
            if l.name != "COI_EXCL" {
                assert!(l.value.starts_with(b"candor/v1/"), "{}", l.name);
            }
            assert!(!l.uses.is_empty());
        }
    }
}
