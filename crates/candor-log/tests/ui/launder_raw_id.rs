// SPDX-License-Identifier: AGPL-3.0-or-later
// AUD-RM1-LOG-03 / AUD-RM1-LOG-17: raw bytes (an IP address) cannot become
// an identifier or value hash: no `from_bytes`, no keyed `derive` of
// caller bytes, no unkeyed digest, no checkpoint-derived constructors.
use candor_log::chain::SignedCheckpoint;
use candor_log::field::{Seq, SeqRange};
use candor_log::ids::{AuditIdKey, CaseRef, Hash32, HashPurpose};

fn launder(cp: &SignedCheckpoint, key: &ed25519_dalek::VerifyingKey) {
    let ip6: [u8; 16] = std::net::Ipv6Addr::LOCALHOST.octets();
    let k = AuditIdKey::new([0; 32]);
    let _a = CaseRef::from_bytes(ip6);
    let _b = CaseRef::derive(&k, &ip6);
    let _c = Hash32::digest(b"203.0.113.7");
    let _d = Hash32::derive(&k, HashPurpose::Query, b"203.0.113.7");
    let _e = Hash32::checkpoint_root(cp, key);
    let _f = Seq::checkpoint_end(cp);
    let _g = SeqRange::of_checkpoint(cp);
}

fn main() {}
