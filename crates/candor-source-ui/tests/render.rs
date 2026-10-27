// SPDX-License-Identifier: AGPL-3.0-or-later
//! Render-level conformance tests for the Tier W source UI.
//! Requirement IDs refer to `specs/11-FRONTEND-SOURCE.md` (SUI-*), `26-ACCESSIBILITY.md`
//! (A11Y-*, I18N-*) and `08-API.md` (API-*).

// Test-only: reads the crate's own template sources and prints budget reports (no source
// data); the ADR-027 safefs/logging bans in `clippy.toml` target shipped code.
#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

#[path = "support/preview.rs"]
#[allow(dead_code)]
mod preview;

#[path = "render/content.rs"]
mod content;
#[path = "render/forms.rs"]
mod forms;
#[path = "render/layout.rs"]
mod layout;
#[path = "render/locale.rs"]
mod locale;
#[path = "render/security.rs"]
mod security;

use candor_source_ui::*;
use preview::{all_cases, sample_view_model};
use scraper::{ElementRef, Html, Selector};

fn sel(s: &str) -> Selector {
    Selector::parse(s).unwrap()
}

fn body(p: &Page) -> String {
    String::from_utf8(p.body.to_vec()).unwrap()
}

/// Removes Fluent bidi isolates (U+2068/U+2069) for text comparisons.
fn plain(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, '\u{2068}' | '\u{2069}'))
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn text_of(e: ElementRef<'_>) -> String {
    plain(&e.text().collect::<String>())
}

fn variants() -> Vec<(Screen, Locale, Mode, bool)> {
    let mut v = Vec::new();
    for (s, l) in all_cases() {
        for m in [Mode::Anonymous, Mode::Confidential, Mode::Identified] {
            v.push((s, l, m, false));
        }
        v.push((s, l, Mode::Anonymous, true));
    }
    v
}

fn render_ok(s: Screen, l: Locale, m: Mode, err: bool) -> (Page, String) {
    let vm = sample_view_model(s, m, err);
    let p = render(s, &vm, &l)
        .unwrap_or_else(|e| panic!("{} {} {m:?} err={err}: {e:?}", s.spec_id(), l.tag()));
    let b = body(&p);
    (p, b)
}

/// Worst-case content: every optional statement and every warning banner (SUI-069, SUI-078).
fn max_content(mut vm: ViewModel) -> ViewModel {
    let d = Day::new(2026, 9, 1).unwrap();
    vm.ctx.banners = Banners {
        operator_statement: OperatorStatement::Stale { last: d },
        incident: Some(IncidentNotice {
            date: d,
            text: "We found an unauthorised change on 2026-09-01 and rebuilt the server.".into(),
            capture: None,
        }),
        roster_changes: vec![
            RosterChange {
                channel: "Audit Committee".into(),
                effective: d,
            },
            RosterChange {
                channel: "Ethics Office".into(),
                effective: d,
            },
        ],
    };
    let dep = &mut vm.deployment;
    dep.recovery = Some(RecoveryQuorum {
        holders: "the General Counsel, the Audit Committee Chair and the Ombudsperson".into(),
        k: 2,
    });
    dep.reduced_sod_oversight = Some("External Ombudsperson".into());
    dep.oversight_label = Some("The Regulator".into());
    dep.alternative_label = Some("Hotline 0800 000 000".into());
    dep.jurisdiction_rights_text =
        Some("You may also report to the National Whistleblowing Authority.".into());
    dep.jurisdiction_retaliation_text =
        Some("Retaliation is unlawful under the Whistleblower Protection Act.".into());
    dep.high_profile = true;
    dep.failover_notice = true;
    vm
}

fn has_text(b: &str, needle: &str) -> bool {
    plain(
        &Html::parse_document(b)
            .root_element()
            .text()
            .collect::<String>(),
    )
    .contains(needle)
}
