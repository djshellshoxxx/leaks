// SPDX-License-Identifier: AGPL-3.0-or-later
//! Size-class and response-padding conformance tests extracted without assertion changes.

use super::*;

// ST: SUI-005 / SUI-069 / SUI-078 — worst-case optional content still fits its class.
#[test]
fn max_content_fits_size_classes() {
    for (s, l) in all_cases() {
        let vm = max_content(sample_view_model(s, Mode::Anonymous, false));
        let p = render(s, &vm, &l).unwrap_or_else(|e| panic!("{} {}: {e:?}", s.spec_id(), l.tag()));
        assert_eq!(p.body.len(), p.class.bytes());
    }
}

#[test]
fn robots_padded() {
    let p = robots_txt();
    assert_eq!(p.body.len(), SizeClass::P1.bytes());
}

// ST: SUI-005 — the largest P1 page (S02) keeps headroom in every built-in locale.
#[test]
fn s02_budget_report() {
    for l in Locale::ALL {
        let vm = max_content(sample_view_model(Screen::Safety, Mode::Anonymous, false));
        let p = render(Screen::Safety, &vm, &l).unwrap();
        assert!(
            p.unpadded_len <= SizeClass::P1.max_unpadded(),
            "{}",
            l.tag()
        );
        println!(
            "S02 {}: {} of {} bytes",
            l.tag(),
            p.unpadded_len,
            SizeClass::P1.max_unpadded()
        );
    }
}
