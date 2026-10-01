// SPDX-License-Identifier: AGPL-3.0-or-later
// AUD-RM1-LOG-03: raw bytes (an IPv6 address) cannot become an identifier,
// and there is no unkeyed digest constructor for value hashes.
use candor_log::ids::{CaseRef, Hash32};

fn main() {
    let ip6: [u8; 16] = std::net::Ipv6Addr::LOCALHOST.octets();
    let _c = CaseRef::from_bytes(ip6);
    let _h = Hash32::digest(b"203.0.113.7");
}
