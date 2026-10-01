// SPDX-License-Identifier: AGPL-3.0-or-later
//! Safety-tip conformance tests (`specs/11a-SOURCE-SAFETY-TIPS.md`, TIP-*).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss
)]

use candor_source_ui::preview::sample_view_model;
use candor_source_ui::*;
use scraper::{ElementRef, Html, Selector};

/// The English master tip catalog (compiled into the crate from the same file).
const TIPS_FTL: &str = include_str!("../locales/en/tips.ftl");

fn sel(s: &str) -> Selector {
    Selector::parse(s).unwrap()
}

fn render_html(s: Screen, l: Locale, m: Mode, err: bool) -> String {
    let vm = sample_view_model(s, m, err);
    let p = render(s, &vm, &l)
        .unwrap_or_else(|e| panic!("{} {} {m:?} {err}: {e:?}", s.spec_id(), l.tag()));
    String::from_utf8(p.body.to_vec()).unwrap()
}

fn aside(html: &Html) -> ElementRef<'_> {
    static ASIDE: std::sync::LazyLock<Selector> =
        std::sync::LazyLock::new(|| Selector::parse("main aside.tips").unwrap());
    let mut it = html.select(&ASIDE);
    let a = it.next().expect("tips region");
    assert!(it.next().is_none(), "one tips region");
    a
}

fn plain(e: ElementRef<'_>) -> String {
    e.text()
        .collect::<String>()
        .chars()
        .filter(|c| !matches!(c, '\u{2068}' | '\u{2069}'))
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// `(key, text)` of every message in the tip catalog, with `**` markup removed.
fn tip_messages() -> Vec<(String, String)> {
    TIPS_FTL
        .lines()
        .filter_map(|l| {
            let (k, v) = l.split_once(" = ")?;
            k.starts_with("tip-")
                .then(|| (k.to_owned(), v.replace("**", "").trim().to_owned()))
        })
        .collect()
}

fn words(t: &str) -> Vec<&str> {
    t.split(|c: char| c.is_whitespace() || c == '/')
        .filter(|w| w.chars().any(char::is_alphanumeric))
        .collect()
}

/// Rough English syllable count (vowel groups, silent final "e").
fn syllables(w: &str) -> usize {
    let w: String = w
        .chars()
        .filter(char::is_ascii_alphabetic)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if w.is_empty() {
        return 1;
    }
    let mut n = 0;
    let mut prev = false;
    for c in w.chars() {
        let v = "aeiouy".contains(c);
        if v && !prev {
            n += 1;
        }
        prev = v;
    }
    if w.ends_with('e') && !w.ends_with("le") && !w.ends_with("ee") && n > 1 {
        n -= 1;
    }
    n.max(1)
}

/// Heuristic Flesch–Kincaid grade level.
fn fk_grade(t: &str) -> f64 {
    let ws = words(t);
    let sentences = t.matches(['.', '?', '!', ':']).count().max(1);
    let syl: usize = ws.iter().map(|w| syllables(w)).sum();
    0.39 * (ws.len() as f64 / sentences as f64) + 11.8 * (syl as f64 / ws.len() as f64) - 15.59
}

// ST: TIP-001 / TIP-002 / TIP-011 — every screen renders its 1–3 tips in every locale, mode and
// error state; NORMAL text always visible; HIGHER-RISK text only in <details>; the region is
// identical across modes and error states.
#[test]
fn every_screen_has_tips() {
    for s in Screen::ALL {
        for l in Locale::ALL {
            let mut first: Option<String> = None;
            for (m, err) in [
                (Mode::Anonymous, false),
                (Mode::Confidential, false),
                (Mode::Identified, false),
                (Mode::Anonymous, true),
            ] {
                let b = render_html(s, l, m, err);
                let html = Html::parse_document(&b);
                let a = aside(&html);
                let id = format!("{} {} {m:?} {err}", s.spec_id(), l.tag());
                let tips: Vec<_> = a.select(&sel("div.tip")).collect();
                assert_eq!(tips.len(), s.tips().len(), "{id}");
                assert!((1..=3).contains(&tips.len()), "{id}");
                for t in &tips {
                    let p = t.select(&sel(":scope > p")).next().expect("normal tip");
                    assert!(!plain(p).is_empty(), "{id}: empty normal tip");
                    let details: Vec<_> = t.select(&sel(":scope > details")).collect();
                    if s == Screen::Safety {
                        assert!(details.is_empty(), "{id}: S02 links to S02b instead");
                    } else {
                        assert_eq!(details.len(), 1, "{id}: one <details>");
                        let d = details[0];
                        assert!(d.value().attr("open").is_none(), "{id}: details closed");
                        assert_eq!(d.select(&sel("summary")).count(), 1, "{id}");
                        assert!(!plain(d.select(&sel("p")).next().unwrap()).is_empty());
                    }
                }
                let region = a.html();
                match &first {
                    None => first = Some(region),
                    Some(f) => assert_eq!(f, &region, "{id}: tips must be static per screen"),
                }
            }
        }
    }
}

// ST: TIP-003 — word limits (English master).
#[test]
fn word_limits() {
    let msgs = tip_messages();
    let mut n = 0;
    for (k, v) in &msgs {
        let count = words(v).len();
        if k.ends_with("-n") {
            assert!(count <= 25, "{k}: {count} words");
            n += 1;
        } else if k.ends_with("-h") {
            assert!(count <= 80, "{k}: {count} words");
        }
    }
    assert_eq!(n, Tip::ALL.len());
}

// ST: TIP-003 — readability (heuristic Flesch–Kincaid: NORMAL ≤ 8, HIGHER-RISK ≤ 10; 05 GP-9).
#[test]
fn readability() {
    for (k, v) in tip_messages() {
        let g = fk_grade(&v);
        if k.ends_with("-n") {
            assert!(g <= 8.0, "{k}: grade {g:.1}");
        } else if k.ends_with("-h") {
            assert!(g <= 10.0, "{k}: grade {g:.1}");
        }
    }
}

// ST: TIP-004 — every page stays within its size class in every locale with worst-case
// optional content (all banners and statements).
#[test]
fn budgets_all_locales() {
    let d = Day::new(2026, 9, 1).unwrap();
    for s in Screen::ALL {
        for l in Locale::ALL {
            let mut vm = sample_view_model(s, Mode::Anonymous, false);
            vm.ctx.banners = Banners {
                operator_statement: OperatorStatement::Stale { last: d },
                incident: Some(IncidentNotice {
                    date: d,
                    text: "We found an unauthorised change and rebuilt the server.".into(),
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
                holders: "the General Counsel, the Audit Committee Chair and the Ombudsperson"
                    .into(),
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
            let p = render(s, &vm, &l)
                .unwrap_or_else(|e| panic!("{} {}: {e:?}", s.spec_id(), l.tag()));
            assert!(p.unpadded_len <= p.class.max_unpadded());
            assert_eq!(p.body.len(), p.class.bytes());
            if p.class == SizeClass::P1 && l == Locale::EnXA {
                println!(
                    "{} en-XA (P1): {} of {}",
                    s.spec_id(),
                    p.unpadded_len,
                    SizeClass::P1.max_unpadded()
                );
            }
        }
    }
}

// ST: TIP-005 — no external URLs or clickable clearnet links in tips; only allow-listed
// same-origin routes; the Leave page tip has no link at all.
#[test]
fn no_external_urls() {
    for s in Screen::ALL {
        for l in Locale::ALL {
            let b = render_html(s, l, Mode::Anonymous, false);
            let html = Html::parse_document(&b);
            let a = aside(&html);
            let lower = a.html().to_ascii_lowercase();
            for bad in ["http:", "https:", "://", "www.", ".onion", "mailto:", "tel:", "?"] {
                assert!(!lower.contains(bad), "{} {}: {bad}", s.spec_id(), l.tag());
            }
            let links: Vec<_> = a.select(&sel("a")).collect();
            if matches!(s, Screen::Leave | Screen::SafetyTips) {
                assert!(links.is_empty(), "{}: no link", s.spec_id());
            } else {
                assert_eq!(links.len(), 1, "{} {}", s.spec_id(), l.tag());
                let href = links[0].value().attr("href").unwrap();
                assert_eq!(href, format!("/{}{}", l.tag(), Route::SafetyTips.path()));
                assert!(Route::SafetyTips.accepts_get());
            }
        }
    }
    for (k, v) in tip_messages() {
        let low = v.to_ascii_lowercase();
        for bad in ["http", "://", "www.", ".onion", ".org", ".com", ".net"] {
            assert!(!low.contains(bad), "{k}: {bad}");
        }
    }
}

// ST: TIP-006 — tip strings are sec:critical (the limits detail is tier0).
#[test]
fn catalog_classes() {
    for t in Tip::ALL {
        for k in [t.title_key(), t.normal_key(), t.high_key()] {
            let c = string_class(&k).unwrap_or_else(|| panic!("{k} missing"));
            assert_ne!(c, StringClass::Ui, "{k}");
        }
    }
    assert_eq!(string_class("tip-limits-h"), Some(StringClass::Tier0));
    assert_eq!(
        string_class("tip-high-summary"),
        Some(StringClass::Critical)
    );
}

// ST: TIP-007 — honest, calm wording: no absolute claims, no fear language, no exclamations.
#[test]
fn honest_wording_lint() {
    const BANNED: &[&str] = &[
        "guarantee",
        "untraceable",
        "100%",
        "100 %",
        "100 percent",
        "completely anonymous",
        "fully anonymous",
        "totally anonymous",
        "perfectly",
        "bulletproof",
        "impossible to trace",
        "can't be traced",
        "cannot be traced",
        "never be found",
        "never be identified",
        "military-grade",
        "100% safe",
        "totally safe",
        "completely safe",
        "act now",
        "hurry",
        "urgent",
        "you will be caught",
        "prison",
        "jail",
        "terrifying",
    ];
    let mut texts: Vec<(String, String)> = tip_messages();
    for s in Screen::ALL {
        let b = render_html(s, Locale::En, Mode::Anonymous, false);
        let html = Html::parse_document(&b);
        texts.push((s.spec_id().to_owned(), plain(aside(&html))));
    }
    for (k, v) in texts {
        let low = v.to_lowercase();
        for w in BANNED {
            assert!(!low.contains(w), "{k}: banned wording {w:?}");
        }
        assert!(!v.contains('!'), "{k}: exclamation mark");
        assert!(
            !v.split_whitespace()
                .any(|w| w.len() > 3 && w.chars().all(|c| c.is_ascii_uppercase())),
            "{k}: shouting"
        );
    }
}

// ST: TIP-008 — no form controls, pre-ticked boxes, counters or feedback widgets in tips.
#[test]
fn no_controls_in_tips() {
    for s in Screen::ALL {
        let b = render_html(s, Locale::En, Mode::Anonymous, false);
        let html = Html::parse_document(&b);
        let a = aside(&html);
        for bad in [
            "input", "button", "select", "textarea", "form", "[checked]", "img", "svg",
        ] {
            assert_eq!(a.select(&sel(bad)).count(), 0, "{}: {bad}", s.spec_id());
        }
        assert!(a.select(&sel("details[open]")).next().is_none());
    }
}

// ST: TIP-010 — S02b lists every tip with both tracks; reached from S02 by a same-origin link.
#[test]
fn s02b_lists_all() {
    let b = render_html(Screen::SafetyTips, Locale::En, Mode::Anonymous, false);
    let html = Html::parse_document(&b);
    for t in Tip::ALL {
        let sec = html
            .select(&sel(&format!("section#{}", t.anchor())))
            .next()
            .unwrap_or_else(|| panic!("{t:?}"));
        assert_eq!(sec.select(&sel("div.tip > details")).count(), 1, "{t:?}");
    }
    let b = render_html(Screen::Safety, Locale::En, Mode::Anonymous, false);
    assert!(b.contains("href=\"/en/safety/tips\""));
}

// ST: TIP-013 — the region is a labelled complementary landmark after the task content.
#[test]
fn region_is_labelled_landmark() {
    for s in Screen::ALL {
        let b = render_html(s, Locale::En, Mode::Anonymous, false);
        let html = Html::parse_document(&b);
        let a = aside(&html);
        assert_eq!(a.value().attr("aria-labelledby"), Some("tips-h"));
        let h = html.select(&sel("#tips-h")).next().unwrap();
        assert_eq!(h.value().name(), "h2");
        assert_eq!(plain(h), "Staying safe on this page");
        let h1 = b.find("<h1").unwrap();
        let region = b.find("<aside class=\"box tips\"").unwrap();
        assert!(h1 < region, "{}: tips after the task content", s.spec_id());
    }
}

// The readability heuristic itself.
#[test]
fn fk_heuristic_sane() {
    assert!(fk_grade("The cat sat on the mat.") < 2.0);
    assert!(
        fk_grade(
            "Organizational accountability necessitates comprehensive institutional \
             investigation procedures."
        ) > 12.0
    );
    assert_eq!(syllables("phone"), 1);
    assert_eq!(syllables("passphrase"), 2);
}
