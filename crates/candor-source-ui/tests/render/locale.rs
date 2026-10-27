// SPDX-License-Identifier: AGPL-3.0-or-later
//! Locale conformance: every screen per locale, structure, RTL, dates, template text and string classes.

use std::collections::HashSet;

use candor_source_ui::*;
use scraper::Html;

use super::{has_text, plain, render_ok, sel, text_of, variants};

// ST: SUI-052 / I18N-005 locale gate — every screen renders for every locale, every mode and the
// error state, without missing catalog keys.
#[test]
fn every_screen_renders_for_every_locale() {
    let mut n = 0;
    for (s, l, m, e) in variants() {
        render_ok(s, l, m, e);
        n += 1;
    }
    assert!(n >= 36 * 4 * 4);
}

// ST: SUI-043 / A11Y-004 — well-formed HTML (html5ever reports no parse errors), unique ids,
// lang/dir, one h1, skip link, landmarks.
#[test]
fn well_formed_and_structured() {
    for (s, l, m, e) in variants() {
        let (_, b) = render_ok(s, l, m, e);
        let id = format!("{} {} {m:?} {e}", s.spec_id(), l.tag());
        let html = Html::parse_document(&b);
        assert!(
            html.errors.is_empty(),
            "{id}: parse errors {:?}",
            html.errors
        );
        let root = html.select(&sel("html")).next().unwrap();
        assert_eq!(root.value().attr("lang"), Some(l.tag()), "{id}");
        assert_eq!(root.value().attr("dir"), Some(l.dir().as_str()), "{id}");
        assert_eq!(html.select(&sel("h1")).count(), 1, "{id}: one h1");
        let skip = html.select(&sel("a.skip")).next().expect("skip link");
        assert_eq!(skip.value().attr("href"), Some("#main"));
        assert_eq!(html.select(&sel("main#main")).count(), 1, "{id}");
        assert_eq!(html.select(&sel("header")).count(), 1, "{id}");
        let mut ids = HashSet::new();
        for el in html.select(&sel("[id]")) {
            let v = el.value().attr("id").unwrap();
            assert!(ids.insert(v.to_owned()), "{id}: duplicate id {v}");
        }
        for el in html.select(&sel("[aria-describedby], [aria-labelledby], label[for]")) {
            for attr in ["aria-describedby", "aria-labelledby", "for"] {
                if let Some(refs) = el.value().attr(attr) {
                    for r in refs.split_whitespace() {
                        assert!(ids.contains(r), "{id}: {attr} -> missing #{r}");
                    }
                }
            }
        }
        for a in html.select(&sel("a[href^='#']")) {
            let target = &a.value().attr("href").unwrap()[1..];
            assert!(ids.contains(target), "{id}: link to missing #{target}");
        }
        // Title: mode word first (11 §5.2 rule 2), after an optional error prefix.
        let title = text_of(html.select(&sel("title")).next().unwrap());
        assert!(!title.is_empty(), "{id}");
        if l == Locale::En {
            let t = title.strip_prefix("Error: ").unwrap_or(&title);
            let word = match m {
                Mode::Anonymous => "ANONYMOUS",
                Mode::Identified => "IDENTIFIED",
                _ => "CONFIDENTIAL",
            };
            assert!(t.starts_with(word), "{id}: title {title}");
        }
    }
}

// ST: SUI-042 / I18N-010 — RTL layout with LTR passphrase and isolated user content.
#[test]
fn rtl_locale() {
    let (_, b) = render_ok(Screen::Review, Locale::ArXB, Mode::Anonymous, false);
    let h = Html::parse_document(&b);
    assert_eq!(h.select(&sel("html[dir=rtl][lang=ar-XB]")).count(), 1);
    assert!(h.select(&sel("p.ut[dir=auto]")).next().is_some());
    let css = stylesheet();
    for physical in [
        "margin-left",
        "margin-right",
        "padding-left",
        "padding-right",
        "text-align:left",
        "text-align:right",
        "float:",
        "left:",
        "right:",
    ] {
        assert!(!css.contains(physical), "physical property {physical}");
    }
}

// ST: SUI-054 / SUI-030 — day-granular dates, no clock times.
#[test]
fn dates_day_only() {
    let (_, b) = render_ok(Screen::Inbox, Locale::En, Mode::Anonymous, false);
    assert!(has_text(
        &b,
        "Message from Audit Committee team, 2026-10-04 (UTC)"
    ));
    let text = plain(
        &Html::parse_document(&b)
            .root_element()
            .text()
            .collect::<String>(),
    );
    assert!(!text.contains("unread") && !text.contains("last visit"));
}

// ST: I18N-001 — no hard-coded user-facing text in templates (all text comes from catalogs).
#[test]
fn templates_have_no_hard_coded_text() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/templates");
    let entries = std::fs::read_dir(dir); // safefs-lint: allow(test reads crate's own template sources)
    for entry in entries.unwrap() {
        let path = entry.unwrap().path();
        let src = std::fs::read_to_string(&path).unwrap(); // safefs-lint: allow(test reads crate's own template sources)
        let mut s = String::new();
        let mut rest = src.as_str();
        // Strip template blocks/expressions/comments, then tags.
        while let Some(i) = rest.find('{') {
            s.push_str(&rest[..i]);
            let close = match rest[i..].chars().nth(1) {
                Some('{') => "}}",
                Some('%') => "%}",
                Some('#') => "#}",
                _ => {
                    s.push('{');
                    rest = &rest[i + 1..];
                    continue;
                }
            };
            let end = rest[i..].find(close).unwrap() + i + 2;
            rest = &rest[end..];
        }
        s.push_str(rest);
        let mut text = String::new();
        let mut in_tag = false;
        for c in s.chars() {
            match c {
                '<' => in_tag = true,
                '>' => in_tag = false,
                c if !in_tag => text.push(c),
                _ => {}
            }
        }
        let leftover: String = text.chars().filter(|c| c.is_alphabetic()).collect();
        assert!(
            leftover.is_empty() || leftover == "DOCTYPEhtml",
            "{}: hard-coded text {leftover:?}",
            path.display()
        );
    }
}

// ST: 26 §12.2 / I18N-004 — security-critical strings are flagged.
#[test]
fn security_critical_strings_flagged() {
    let keys = catalog_keys().unwrap();
    assert!(keys.len() > 300);
    for k in &keys {
        let c = string_class(k).unwrap();
        let must_tier0 = k.starts_with("sui-mode-word")
            || (k.starts_with("sui-mode-") && !k.ends_with("-region"))
            || k.starts_with("sui-wb-") && !k.ends_with("-link") && k != "sui-wb-region"
            || k.contains("honesty")
            || k == "sui-status-noverify"
            || k.starts_with("sui-concerns-explain")
            || k == "sui-concerns-who-sees"
            || k.starts_with("sui-id-confirm")
            || k.starts_with("sui-cred-")
                && !matches!(
                    k.as_str(),
                    "sui-cred-step"
                        | "sui-cred-h2"
                        | "sui-cred-oneline"
                        | "sui-cred-spell"
                        | "sui-cred-next"
                )
            || k.starts_with("sui-send-")
            || k == "sui-rotate-explain"
            || k.starts_with("sui-close-")
                && !matches!(
                    k.as_str(),
                    "sui-close-step" | "sui-close-passphrase" | "sui-close-yes" | "sui-close-no"
                )
            || k.starts_with("sui-end-discard") && !k.ends_with("-yes") && !k.ends_with("-no");
        if must_tier0 {
            assert_eq!(c, StringClass::Tier0, "{k} must be tier0");
        }
        let gc_card = k.starts_with("sops-")
            && !k.starts_with("sops-group-")
            && !matches!(k.as_str(), "sops-high-summary" | "sops-real-case");
        if gc_card {
            assert_ne!(c, StringClass::Ui, "{k} must be sec:critical");
        }
    }
    assert_eq!(string_class("no-such-key"), None);
}
