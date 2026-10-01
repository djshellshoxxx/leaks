// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Wrap Stanza (§13.2, ST-040): decoder never panics and round-trips; every open
//! path runs with the fixed fuzz keys/contexts, so seeded HPKE_BASE, CASE_AEAD and
//! CASEKEY_EK stanzas reach HPKE open, XChaCha open and the nested inner-stanza checks.
#![no_main]
#[path = "common.rs"]
mod common;

use candor_core::secret::{CaseKey, ErasureKey};
use candor_core::stanza::{HpkeWrapContext, WrapStanza};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = WrapStanza::decode(data) else {
        return;
    };
    assert_eq!(s.encode().expect("re-encode"), data);
    let sk = &common::member().private;
    let reply = HpkeWrapContext::Reply {
        tenant_id: common::TENANT,
        channel_id: common::CHANNEL,
        mailbox_id: common::MAILBOX,
    };
    let _ = s.open_hpke_ck(sk, &reply, &common::OBJECT_HASH);
    let _ = s.unwrap_case_key(sk, common::TENANT, common::CASE_ID, common::VERSION);
    let _ = s.open_case_aead(
        &CaseKey::from_bytes(common::CASE_KEY),
        common::TENANT,
        common::CASE_ID,
        common::VERSION,
        &common::OBJECT_HASH,
    );
    if let Ok(inner) = s.open_casekey_ek(
        &ErasureKey::from_bytes(common::EK),
        common::TENANT,
        common::CASE_ID,
        common::VERSION,
    ) {
        let _ = inner.unwrap_case_key(sk, common::TENANT, common::CASE_ID, common::VERSION);
    }
});
