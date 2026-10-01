// SPDX-License-Identifier: AGPL-3.0-or-later
//! The PROXY protocol line tor writes at the start of every onion stream with
//! `HiddenServiceExportCircuitID haproxy` (16 §7.1, deploy/intake/torrc):
//!
//! ```text
//! PROXY TCP6 fc00:dead:beef:4dad::HHHH:LLLL ::1 SPORT VPORT\r\n
//! ```
//!
//! where `HHHH:LLLL` is the 32-bit global circuit identifier in lowercase hex
//! (tor `export_hs_client_circuit_id`). The parser accepts exactly this shape
//! (≤ [`MAX_PROXY_LINE`] bytes) and returns only the circuit id, which the
//! caller turns into a keyed [`crate::ratelimit::CircuitToken`] at once. A
//! connection without a valid line is closed without a response (fail
//! closed: a stream that did not come through tor's onion service is never
//! served; NET-001, NET-012). Nothing else from the line is kept.

use crate::limits::MAX_PROXY_LINE;

const PREFIX: &[u8] = b"PROXY TCP6 fc00:dead:beef:4dad::";

fn hex16(s: &[u8]) -> Option<u32> {
    if s.is_empty() || s.len() > 4 {
        return None;
    }
    s.iter().try_fold(0u32, |acc, c| {
        let d = match c {
            b'0'..=b'9' => c.checked_sub(b'0')?,
            b'a'..=b'f' => c.checked_sub(b'a')?.checked_add(10)?,
            _ => return None,
        };
        acc.checked_mul(16)?.checked_add(u32::from(d))
    })
}

fn port(s: &[u8]) -> bool {
    !s.is_empty()
        && s.len() <= 5
        && s.iter().all(u8::is_ascii_digit)
        && (s.len() == 1 || s.first() != Some(&b'0'))
        && core::str::from_utf8(s)
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .is_some_and(|v| v <= 65_535)
}

/// Parse one PROXY line (with its CRLF). Returns the circuit id.
#[must_use]
pub fn parse_proxy_line(line: &[u8]) -> Option<u32> {
    if line.len() > MAX_PROXY_LINE {
        return None;
    }
    let rest = line.strip_suffix(b"\r\n")?.strip_prefix(PREFIX)?;
    let mut f = rest.split(|b| *b == b' ');
    let (Some(addr_tail), Some(dst), Some(sport), Some(dport), None) =
        (f.next(), f.next(), f.next(), f.next(), f.next())
    else {
        return None;
    };
    if dst != b"::1" || !port(sport) || !port(dport) {
        return None;
    }
    let mut a = addr_tail.split(|b| *b == b':');
    let (Some(hi), Some(lo), None) = (a.next(), a.next(), a.next()) else {
        return None;
    };
    let hi = hex16(hi)?;
    let lo = hex16(lo)?;
    hi.checked_mul(0x1_0000)?.checked_add(lo)
}

/// Index just past the first CRLF, if within [`MAX_PROXY_LINE`].
#[must_use]
pub fn find_line_end(buf: &[u8]) -> Option<usize> {
    buf.windows(2)
        .take(MAX_PROXY_LINE)
        .position(|w| w == b"\r\n")
        .and_then(|i| i.checked_add(2))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn tor_format() {
        assert_eq!(
            parse_proxy_line(b"PROXY TCP6 fc00:dead:beef:4dad::0:29a ::1 666 80\r\n"),
            Some(0x29a)
        );
        assert_eq!(
            parse_proxy_line(b"PROXY TCP6 fc00:dead:beef:4dad::ffff:ffff ::1 65535 80\r\n"),
            Some(u32::MAX)
        );
    }

    #[test]
    fn strict() {
        for bad in [
            &b"PROXY TCP4 1.2.3.4 1.2.3.4 1 80\r\n"[..],
            b"PROXY TCP6 fc00:dead:beef:4dad::0:29a ::1 666 80\n",
            b"PROXY TCP6 fc00:dead:beef:4dad::0:29A ::1 666 80\r\n",
            b"PROXY TCP6 fc00:dead:beef:4dad::00000:1 ::1 666 80\r\n",
            b"PROXY TCP6 fc00:dead:beef:4dad::1 ::1 666 80\r\n",
            b"PROXY TCP6 fc00:dead:beef:4dad::0:1 ::2 666 80\r\n",
            b"PROXY TCP6 fc00:dead:beef:4dad::0:1 ::1 65536 80\r\n",
            b"PROXY TCP6 fc00:dead:beef:4dad::0:1 ::1 01 80\r\n",
            b"PROXY TCP6 fc00:dead:beef:4dad::0:1 ::1 1 80 x\r\n",
            b"PROXY TCP6 fc00:dead:beef:4dad::0:1  ::1 1 80\r\n",
            b"PROXY UNKNOWN\r\n",
            b"GET / HTTP/1.1\r\n",
        ] {
            assert_eq!(
                parse_proxy_line(bad),
                None,
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
        assert_eq!(find_line_end(b"abc\r\nrest"), Some(5));
        assert_eq!(find_line_end(&[b'a'; 200]), None);
    }

    proptest::proptest! {
        #[test]
        fn total(data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..200)) {
            let _ = parse_proxy_line(&data);
            let _ = find_line_end(&data);
        }

        #[test]
        fn roundtrip(id in proptest::prelude::any::<u32>(), sp in 0u32..=65535) {
            let line = format!("PROXY TCP6 fc00:dead:beef:4dad::{:x}:{:x} ::1 {} 80\r\n", id >> 16, id & 0xffff, sp);
            proptest::prop_assert_eq!(parse_proxy_line(line.as_bytes()), Some(id));
        }
    }
}
