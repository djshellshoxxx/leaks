// SPDX-License-Identifier: AGPL-3.0-or-later
//! Render-level conformance tests for the Tier W source UI.
//! Requirement IDs refer to `specs/11-FRONTEND-SOURCE.md` (SUI-*), `26-ACCESSIBILITY.md`
//! (A11Y-*, I18N-*) and `08-API.md` (API-*).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::HashSet;

use candor_source_ui::preview::{all_cases, sample_view_model};
use candor_source_ui::*;
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

// ST: SUI-005 / SUI-069 / SUI-078 — worst-case optional content still fits its class.
#[test]
fn max_content_fits_size_classes() {
    for (s, l) in all_cases() {
        let vm = max_content(sample_view_model(s, Mode::Anonymous, false));
        let p = render(s, &vm, &l).unwrap_or_else(|e| panic!("{} {}: {e:?}", s.spec_id(), l.tag()));
        assert_eq!(p.body.len(), p.class.bytes());
    }
}

// ST: SUI-001, SUI-003, SUI-006, SUI-037, SUI-039, SUI-050, DP-10, DP-13 — template output scan.
#[test]
fn no_script_handlers_external_urls_or_inline_styles() {
    let attr_on = regex_lite_on();
    for (s, l, m, e) in variants() {
        let (_, b) = render_ok(s, l, m, e);
        let lower = b.to_ascii_lowercase();
        let id = format!("{} {} {m:?} {e}", s.spec_id(), l.tag());
        for bad in [
            "<script",
            "javascript:",
            "<iframe",
            "<object",
            "<embed",
            "<video",
            "<audio",
            "<img",
            "http-equiv",
            "localstorage",
            "sessionstorage",
            "indexeddb",
            "serviceworker",
            "<link rel=\"stylesheet",
            "@import",
            "url(",
            "<base",
        ] {
            assert!(!lower.contains(bad), "{id}: found {bad}");
        }
        assert_eq!(lower.matches("<style").count(), 1, "{id}: one <style> only");
        assert!(!attr_on(&lower), "{id}: on*= attribute");
        assert!(!lower.contains(" style="), "{id}: style attribute");
        let html = Html::parse_document(&b);
        for el in html.select(&sel("*")) {
            for (name, value) in el.value().attrs() {
                assert!(
                    !matches!(name, "capture" | "style" | "download" | "ping" | "srcset")
                        && !name.starts_with("on"),
                    "{id}: attribute {name}"
                );
                if matches!(name, "href" | "src" | "action" | "formaction") {
                    let ok = value.starts_with('/') && !value.starts_with("//")
                        || value.starts_with('#')
                        || (name == "href" && value == "data:,");
                    assert!(ok, "{id}: {name}={value}");
                    assert!(!value.contains('?'), "{id}: query string in {value}");
                }
            }
        }
    }
}

fn regex_lite_on() -> impl Fn(&str) -> bool {
    // Detects ` on<letters>=` attribute syntax.
    |s: &str| {
        let b = s.as_bytes();
        let mut i = 0;
        while i + 3 < b.len() {
            if (b[i] == b' ' || b[i] == b'\n' || b[i] == b'\t')
                && b[i + 1] == b'o'
                && b[i + 2] == b'n'
            {
                let mut j = i + 3;
                while j < b.len() && b[j].is_ascii_lowercase() {
                    j += 1;
                }
                if j > i + 3 && j < b.len() && b[j] == b'=' {
                    // Inside a tag only: find the last '<' or '>' before i.
                    let before = &s[..i];
                    if before.rfind('<') > before.rfind('>') {
                        return true;
                    }
                }
            }
            i += 1;
        }
        false
    }
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

// ST: SUI-043 / WCAG 1.3.1, 3.3.2, 4.1.2 — every form control has an associated label and every
// button has an accessible name.
#[test]
fn every_control_is_labelled() {
    for (s, l, m, e) in variants() {
        let (_, b) = render_ok(s, l, m, e);
        let id = format!("{} {} {m:?} {e}", s.spec_id(), l.tag());
        let html = Html::parse_document(&b);
        let labels: HashSet<String> = html
            .select(&sel("label[for]"))
            .filter(|l| !text_of(*l).is_empty())
            .map(|l| l.value().attr("for").unwrap().to_owned())
            .collect();
        for c in html.select(&sel("input, select, textarea")) {
            let v = c.value();
            if v.attr("type") == Some("hidden") {
                continue;
            }
            let named =
                v.attr("aria-label").is_some() || v.id().is_some_and(|i| labels.contains(i));
            assert!(named, "{id}: unlabelled control {:?}", v.attr("name"));
        }
        for btn in html.select(&sel("button")) {
            assert!(!text_of(btn).is_empty(), "{id}: empty button");
        }
        for a in html.select(&sel("a")) {
            assert!(!text_of(a).is_empty(), "{id}: empty link");
        }
        for fs in html.select(&sel("fieldset")) {
            assert!(
                fs.select(&sel("legend")).next().is_some(),
                "{id}: fieldset without legend"
            );
        }
        // ADP-14: hidden fields only for the form token and navigation values.
        for h in html.select(&sel("input[type=hidden]")) {
            let n = h.value().attr("name").unwrap();
            assert!(
                [
                    "csrf",
                    "nav",
                    "step",
                    "action",
                    "part_index",
                    "reply_index",
                    "page"
                ]
                .contains(&n),
                "{id}: hidden field {n}"
            );
        }
    }
}

// ST: SUI-005 / API-009 — padding lands exactly on the class; class by method and cookie only.
#[test]
fn size_classes_exact() {
    for (s, l, m, e) in variants() {
        let (p, b) = render_ok(s, l, m, e);
        let vm = sample_view_model(s, m, e);
        let expect = if s == Screen::MethodNotAllowed {
            SizeClass::P1
        } else {
            SizeClass::for_request(vm.ctx.method, vm.ctx.has_session_cookie)
        };
        assert_eq!(p.class, expect);
        assert_eq!(p.body.len(), expect.bytes());
        assert_eq!(b.len(), expect.bytes());
        assert_eq!(
            p.header("Content-Length"),
            Some(expect.bytes().to_string().as_str())
        );
        assert!(p.unpadded_len <= expect.max_unpadded());
        assert!(
            b.trim_end().ends_with("--></body>\n</html>"),
            "{}",
            s.spec_id()
        );
    }
}

// ST: SUI-005 — sizes do not depend on content (inbox with 0 vs 20 messages; short vs long review).
#[test]
fn size_independent_of_content() {
    let l = Locale::En;
    let mut a = sample_view_model(Screen::Inbox, Mode::Anonymous, false);
    a.inbox.messages.clear();
    let mut b = a.clone();
    for i in 0..20u8 {
        b.inbox.messages.push(InboxMessage {
            sender: "Team".into(),
            date: Day::new(2026, 10, 1 + i).unwrap(),
            text: "x".repeat(2000),
        });
    }
    let pa = render(Screen::Inbox, &a, &l).unwrap();
    let pb = render(Screen::Inbox, &b, &l).unwrap();
    assert_eq!(pa.body.len(), pb.body.len());
    let mut wrong = sample_view_model(Screen::Login, Mode::Anonymous, true);
    wrong.ctx.method = Method::Post;
    let mut right = sample_view_model(Screen::Inbox, Mode::Anonymous, false);
    right.ctx.method = Method::Post;
    right.ctx.has_session_cookie = false;
    let pw = render(Screen::Login, &wrong, &l).unwrap();
    let pr = render(Screen::Inbox, &right, &l).unwrap();
    assert_eq!(pw.body.len(), pr.body.len(), "wrong vs right passphrase");
}

// ST: SUI-002, SUI-036, SUI-055 — exact header set; CSP pins the served stylesheet.
#[test]
fn response_headers() {
    for (s, l, m, e) in variants() {
        let (p, b) = render_ok(s, l, m, e);
        for h in PROHIBITED_HEADERS {
            assert!(p.header(h).is_none(), "{h}");
        }
        assert_eq!(p.header("Cache-Control"), Some("no-store, max-age=0"));
        assert_eq!(p.header("Referrer-Policy"), Some("no-referrer"));
        assert_eq!(p.header("X-Content-Type-Options"), Some("nosniff"));
        assert_eq!(p.header("X-Frame-Options"), Some("DENY"));
        assert_eq!(p.header("Cross-Origin-Opener-Policy"), Some("same-origin"));
        assert_eq!(
            p.header("Cross-Origin-Embedder-Policy"),
            Some("require-corp")
        );
        assert_eq!(
            p.header("Cross-Origin-Resource-Policy"),
            Some("same-origin")
        );
        assert_eq!(p.header("Origin-Agent-Cluster"), Some("?1"));
        assert_eq!(p.header("Content-Language"), Some(l.tag()));
        assert!(
            p.header("Permissions-Policy")
                .unwrap()
                .contains("camera=()")
        );
        assert_eq!(p.header("Content-Type"), Some("text/html; charset=utf-8"));
        let csp = p.header("Content-Security-Policy").unwrap();
        assert_eq!(csp, content_security_policy());
        // The CSP hash covers exactly the bytes inside <style>.
        let start = b.find("<style>").unwrap() + "<style>".len();
        let end = b.find("</style>").unwrap();
        assert_eq!(&b[start..end], STYLESHEET);
        assert!(csp.contains(stylesheet_hash()));
        assert_eq!(p.header("Clear-Site-Data").is_some(), s.clears_site_data());
        assert_eq!(p.status, s.status());
    }
}

// ST: SUI-015 / SUI-075 — mode banner text present and correct per mode, first in <header>.
#[test]
fn mode_banner_per_mode() {
    let expected = [
        (
            Mode::Anonymous,
            "ANONYMOUS — Candor does not collect who you are. Your writing and files can still identify you.",
        ),
        (
            Mode::Confidential,
            "CONFIDENTIAL — NOT ANONYMOUS — You told us who you are. Your name is locked so that only the Ethics Office identity custodians can open it, with a recorded reason. The people handling your report can read everything else you write.",
        ),
        (
            Mode::ConfidentialIdentitySeen,
            "CONFIDENTIAL — NOT ANONYMOUS — The people handling your report have read a message that said who you are. Case team knows.",
        ),
        (
            Mode::Identified,
            "IDENTIFIED — NOT ANONYMOUS — Your name will be shown to the people handling your report.",
        ),
        (
            Mode::Clearnet,
            "NOT ANONYMOUS — This website can see your internet address. To report anonymously, use Tor Browser: abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion",
        ),
    ];
    for s in Screen::ALL {
        for (m, text) in expected {
            let vm = sample_view_model(s, m, false);
            let p = render(s, &vm, &Locale::En).unwrap();
            let html = Html::parse_document(&body(&p));
            let header = html.select(&sel("header")).next().unwrap();
            let first = header
                .children()
                .filter_map(ElementRef::wrap)
                .next()
                .unwrap();
            assert!(first.value().classes().any(|c| c == "mode"), "banner first");
            let banner = text_of(first.select(&sel("p")).next().unwrap());
            assert_eq!(banner, text, "{} {m:?}", s.spec_id());
            let tier = first.select(&sel("p.tier")).next();
            assert_eq!(tier.is_some(), m != Mode::Clearnet);
            if m.is_disclosed() && m != Mode::Clearnet {
                assert!(banner.contains("NOT ANONYMOUS"), "non-color cue");
            }
        }
    }
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

const HONESTY: &str = "If the intake server is compromised or legally compelled while you use the website (no-JavaScript) version, what you type, and your passphrase when you log in, can be captured. For the highest risk, use the Candor Source App.";

// ST: SUI-064, SUI-066, SUI-051, SUI-077, SUI-065 — fixed strings per screen.
#[test]
fn required_strings_per_screen() {
    for s in [Screen::Landing, Screen::Status, Screen::Login] {
        let (_, b) = render_ok(s, Locale::En, Mode::Anonymous, false);
        assert!(has_text(&b, HONESTY), "SUI-064 {}", s.spec_id());
    }
    for s in Screen::ALL {
        let (_, b) = render_ok(s, Locale::En, Mode::Anonymous, false);
        assert_eq!(
            b.contains("class=\"warn js-warning\""),
            s.shows_js_warning(),
            "SUI-051 {}",
            s.spec_id()
        );
    }
    let (_, b) = render_ok(Screen::Status, Locale::En, Mode::Anonymous, false);
    assert!(has_text(
        &b,
        "Checking these values does not protect a report sent from this website; only the Candor app checks them before encrypting."
    ));
    assert!(has_text(&b, "the server looks up your mailbox"));
    assert!(has_text(&b, "(as listed by this site)"));
    let (_, b) = render_ok(Screen::Files, Locale::En, Mode::Anonymous, false);
    assert!(has_text(
        &b,
        "can recognise a large upload by its size and time"
    ));
    let (_, b) = render_ok(Screen::Concerns, Locale::En, Mode::Anonymous, false);
    assert!(has_text(
        &b,
        "Your answers are encrypted and seen only by the independent triage team, who use them to keep the people involved away from your report. They may still suggest what your report is about."
    ));
    assert!(has_text(
        &b,
        "If you tick your own manager, the triage team will know which team you work in."
    ));
    for s in [
        Screen::NewReport,
        Screen::Files,
        Screen::Review,
        Screen::ServerError,
    ] {
        let (_, b) = render_ok(s, Locale::En, Mode::Anonymous, false);
        assert!(
            has_text(&b, "Your draft is kept only in the server's memory"),
            "SUI-061 {}",
            s.spec_id()
        );
    }
    let (_, b) = render_ok(Screen::Inbox, Locale::En, Mode::Anonymous, false);
    assert!(has_text(
        &b,
        "Replies stay here for 30 days after they arrive."
    ));
    let (_, b) = render_ok(Screen::Conversation, Locale::En, Mode::Anonymous, false);
    assert!(has_text(
        &b,
        "The team should never ask you to move to email, phone or chat."
    ));
    assert!(has_text(
        &b,
        "Your messages go only to people who could read your first report"
    ));
}

// ST: SUI-016 — send buttons name the mode.
#[test]
fn send_buttons_name_mode() {
    for (m, label) in [
        (Mode::Anonymous, "Send anonymously"),
        (Mode::Confidential, "Send confidentially (with my name)"),
        (Mode::Identified, "Send with my name"),
    ] {
        let (_, b) = render_ok(Screen::Confirm, Locale::En, m, false);
        let html = Html::parse_document(&b);
        let primary = html.select(&sel("button.btn-primary")).next().unwrap();
        assert_eq!(text_of(primary), label);
    }
    let (_, b) = render_ok(Screen::Conversation, Locale::En, Mode::Confidential, false);
    assert!(has_text(&b, "Send message (confidential)"));
}

// ST: ADP-01, ADP-12, SUI-021, SUI-025 — privacy-protective defaults.
#[test]
fn privacy_defaults() {
    let (_, b) = render_ok(Screen::NewReport, Locale::En, Mode::Anonymous, false);
    let h = Html::parse_document(&b);
    let checked: Vec<_> = h
        .select(&sel("input[name=mode][checked]"))
        .map(|e| e.value().attr("value").unwrap().to_owned())
        .collect();
    assert_eq!(checked, ["anonymous"]);
    let (_, b) = render_ok(Screen::Concerns, Locale::En, Mode::Anonymous, false);
    let h = Html::parse_document(&b);
    assert_eq!(h.select(&sel("input[name=coi_label]")).count(), 3);
    assert_eq!(h.select(&sel("input[name=coi_label][checked]")).count(), 0);
    let (_, b) = render_ok(Screen::Files, Locale::En, Mode::Anonymous, false);
    let h = Html::parse_document(&b);
    let f = h.select(&sel("input[type=file]")).next().unwrap();
    assert!(f.value().attr("accept").is_none() && f.value().attr("capture").is_none());
    assert!(
        h.select(&sel("input[name=neutral_names][checked]"))
            .next()
            .is_some()
    );
    let (_, b) = render_ok(Screen::Review, Locale::En, Mode::Anonymous, false);
    let h = Html::parse_document(&b);
    let d: Vec<_> = h
        .select(&sel("input[name=delayed_delivery][checked]"))
        .map(|e| e.value().attr("value").unwrap().to_owned())
        .collect();
    assert_eq!(d, ["false"]);
    // Invisible-character notice: "Remove them" is the first button (05 §8.5a).
    let section = h.select(&sel("section")).next().unwrap();
    let first_btn = section
        .select(&sel("form button"))
        .find(|b| b.value().attr("value") == Some("normalize"))
        .unwrap();
    assert_eq!(text_of(first_btn), "Remove them");
}

// ST: SUI-029 / SUI-042 — passphrase display.
#[test]
fn passphrase_display() {
    for l in Locale::ALL {
        let (_, b) = render_ok(Screen::Credential, l, Mode::Anonymous, false);
        let h = Html::parse_document(&b);
        let ol = h.select(&sel("ol.phrase")).next().unwrap();
        assert_eq!(ol.value().attr("dir"), Some("ltr"));
        assert_eq!(ol.value().attr("lang"), Some("en"));
        assert_eq!(ol.select(&sel("li")).count(), 10);
        let line = h.select(&sel("input[readonly]")).next().unwrap();
        assert_eq!(
            line.value().attr("value"),
            Some("cobalt ripple anthem gravel sonnet mosaic tundra whistle ember lantern")
        );
        assert!(
            h.select(&sel("details ol li"))
                .any(|li| text_of(li) == "c o b a l t")
        );
        // No download, print, QR, email or scripted copy affordances (SOPS-022).
        for el in h.select(&sel("main a, main button")) {
            let t = text_of(el).to_lowercase();
            for bad in ["download", "print", "qr", "email", "copy to clipboard"] {
                assert!(!t.contains(bad), "{bad}: {t}");
            }
            assert!(el.value().attr("download").is_none());
            assert!(!el.value().attr("href").unwrap_or("").starts_with("mailto:"));
        }
        // Passphrase never in the title (08 SW-08).
        let title = text_of(h.select(&sel("title")).next().unwrap());
        assert!(!title.contains("cobalt"));
    }
    let mut vm = sample_view_model(Screen::Credential, Mode::Anonymous, false);
    vm.credential.passphrase.words.clear();
    assert_eq!(
        render(Screen::Credential, &vm, &Locale::En).unwrap_err(),
        RenderError::MissingData("passphrase")
    );
    // Debug output never shows the words.
    let dbg = format!(
        "{:?}",
        sample_view_model(Screen::Credential, Mode::Anonymous, false)
    );
    assert!(!dbg.contains("cobalt"));
    let page = render(Screen::Credential, &vm_cred(), &Locale::En).unwrap();
    assert!(!format!("{page:?}").contains("cobalt"));
}

fn vm_cred() -> ViewModel {
    sample_view_model(Screen::Credential, Mode::Anonymous, false)
}

// ST: SUI-063 / S10c — exhausted attempts leave only "Get a new passphrase" and "Discard".
#[test]
fn confirm_exhausted() {
    let mut vm = sample_view_model(Screen::Confirm, Mode::Anonymous, false);
    vm.confirm.attempts_exhausted = true;
    let b = body(&render(Screen::Confirm, &vm, &Locale::En).unwrap());
    let h = Html::parse_document(&b);
    assert_eq!(h.select(&sel("input[name=w_a]")).count(), 0);
    assert!(has_text(&b, "Get a new passphrase"));
    assert!(has_text(&b, "Discard this report"));
}

// ST: SUI-022 — error pattern.
#[test]
fn error_pattern() {
    for s in [
        Screen::Questionnaire,
        Screen::Login,
        Screen::NewReport,
        Screen::Confirm,
    ] {
        let (_, b) = render_ok(s, Locale::En, Mode::Anonymous, true);
        let h = Html::parse_document(&b);
        let title = text_of(h.select(&sel("title")).next().unwrap());
        assert!(title.starts_with("Error: "), "{title}");
        let main = h.select(&sel("main")).next().unwrap();
        let mut kids = main.children().filter_map(ElementRef::wrap);
        assert_eq!(kids.next().unwrap().value().name(), "h1");
        let summary = kids.next().unwrap();
        assert!(summary.value().classes().any(|c| c == "error-summary"));
        assert!(summary.value().attr("autofocus").is_some());
        assert_eq!(summary.value().attr("tabindex"), Some("-1"));
        assert!(text_of(summary).starts_with("There is a problem"));
        for a in summary.select(&sel("a")) {
            let target = &a.value().attr("href").unwrap()[1..];
            let field = &target[2..];
            let ctl = h.select(&sel(&format!("#{target}"))).next().unwrap();
            let invalid = ctl.value().attr("aria-invalid") == Some("true")
                || h.select(&sel(&format!("#e-{field}"))).next().is_some();
            assert!(invalid, "{} {target}", s.spec_id());
        }
    }
}

// ST: SUI-023 — all user/recipient content is escaped and never interpreted.
#[test]
fn hostile_content_is_escaped() {
    let evil =
        "<script>alert(1)</script><img src=x onerror=alert(1)>\"'&{{x}}**b**javascript:alert(1)";
    for s in Screen::ALL {
        let mut vm = sample_view_model(s, Mode::Confidential, false);
        vm.ctx.org = evil.into();
        vm.landing.purpose = evil.into();
        vm.deployment.custodian_label = evil.into();
        vm.inbox.messages[0].text = evil.into();
        vm.inbox.messages[0].sender = evil.into();
        vm.conversation.messages[0].text = evil.into();
        vm.conversation.draft_text = evil.into();
        vm.files.files[0].name = evil.into();
        vm.review.answers[0].answer = evil.into();
        vm.review.channel = evil.into();
        vm.concerns.roles[0] = evil.into();
        vm.identity.full_name = evil.into();
        vm.status.channels[0].triage[0] = evil.into();
        let b = body(&render(s, &vm, &Locale::En).unwrap());
        let lower = b.to_ascii_lowercase();
        assert!(!lower.contains("<script"), "{}", s.spec_id());
        assert!(!lower.contains("<img"), "{}", s.spec_id());
        assert!(
            !lower.contains("<strong>b</strong>"),
            "{}: markup in user content",
            s.spec_id()
        );
        assert!(
            Html::parse_document(&b).errors.is_empty(),
            "{}",
            s.spec_id()
        );
    }
}

// ST: SUI-069 — warning banners.
#[test]
fn warning_banners() {
    let d = Day::new(2026, 8, 1).unwrap();
    let mut vm = sample_view_model(Screen::Landing, Mode::Anonymous, false);
    let b = body(&render(Screen::Landing, &vm, &Locale::En).unwrap());
    assert!(
        !b.contains("class=\"warn\""),
        "no banners when all is current"
    );
    vm.ctx.banners.operator_statement = OperatorStatement::Missing;
    let b = body(&render(Screen::Landing, &vm, &Locale::En).unwrap());
    assert!(has_text(&b, "Last statement: none."));
    vm.ctx.banners.operator_statement = OperatorStatement::Stale { last: d };
    vm.ctx.banners.incident = Some(IncidentNotice {
        date: d,
        text: "notice".into(),
        capture: None,
    });
    vm.ctx.banners.roster_changes.push(RosterChange {
        channel: "Audit".into(),
        effective: d,
    });
    let b = body(&render(Screen::Landing, &vm, &Locale::En).unwrap());
    assert!(has_text(&b, "Last statement: 2026-08-01."));
    assert!(has_text(
        &b,
        "declared a security incident affecting this site, dated 2026-08-01"
    ));
    assert!(has_text(
        &b,
        "The list of people who receive reports in Audit is changing on 2026-08-01"
    ));
    vm.ctx.banners.incident = Some(IncidentNotice {
        date: d,
        text: "notice".into(),
        capture: Some(CaptureNotice {
            day: d,
            approver_label: "the Independent Approver".into(),
        }),
    });
    let b = body(&render(Screen::Landing, &vm, &Locale::En).unwrap());
    assert!(has_text(
        &b,
        "Security notice. On 2026-08-01 the operator made an incident-response recording"
    ));
    assert!(
        !has_text(&b, "declared a security incident"),
        "WB-2c replaces WB-2"
    );
}

// ST: SUI-078 / SUI-079 / SUI-080 — configuration-driven disclosures.
#[test]
fn configuration_disclosures() {
    let mut vm = sample_view_model(Screen::Landing, Mode::Anonymous, false);
    let b = body(&render(Screen::Landing, &vm, &Locale::En).unwrap());
    assert!(!has_text(&b, "backup key"));
    assert!(!has_text(&b, "reduced separation of duties"));
    vm = max_content(vm);
    let b = body(&render(Screen::Landing, &vm, &Locale::En).unwrap());
    assert!(has_text(&b, "can unlock reports (2 of them together)"));
    assert!(has_text(&b, "reduced separation of duties"));
    assert!(has_text(
        &b,
        "Can't use Tor Browser? Hotline 0800 000 000 — this is NOT ANONYMOUS."
    ));
    let mut vm = sample_view_model(Screen::CloseMailbox, Mode::Anonymous, false);
    let b = body(&render(Screen::CloseMailbox, &vm, &Locale::En).unwrap());
    assert!(has_text(&b, "deleted within 14 days"));
    assert!(has_text(&b, "that timing could still point to you"));
    vm.deployment.intake_backup_days = None;
    let b = body(&render(Screen::CloseMailbox, &vm, &Locale::En).unwrap());
    assert!(has_text(&b, "This server keeps no backups of them."));
}

// ST: SUI-042 / I18N-010 — RTL layout with LTR passphrase and isolated user content.
#[test]
fn rtl_locale() {
    let (_, b) = render_ok(Screen::Review, Locale::ArXB, Mode::Anonymous, false);
    let h = Html::parse_document(&b);
    assert_eq!(h.select(&sel("html[dir=rtl][lang=ar-XB]")).count(), 1);
    assert!(h.select(&sel("p.ut[dir=auto]")).next().is_some());
    let css = STYLESHEET;
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

// ST: A11Y-009 / A11Y-018 / 11 §12 — stylesheet obligations.
#[test]
fn stylesheet_obligations() {
    let css = STYLESHEET;
    assert!(css.len() <= MAX_CSS_BYTES);
    assert!(css.contains(":focus-visible{outline:3px solid"));
    assert!(css.contains("outline-offset:2px"));
    assert!(css.contains("@media (prefers-reduced-motion:reduce)"));
    assert!(css.contains("@media (forced-colors:active)"));
    assert!(css.contains("@media (scripting:enabled)"));
    assert!(css.contains("system-ui"));
    assert!(!css.contains("position:fixed") && !css.contains("position:sticky"));
    assert!(!css.contains("@font-face") && !css.contains("url("));
    assert!(!css.contains("outline:none}") || css.contains("main:focus{outline:none}"));
    // Inline SVG budget (11 §5.4).
    let (_, b) = render_ok(Screen::Landing, Locale::En, Mode::Anonymous, false);
    let svg: usize = b
        .match_indices("<svg")
        .map(|(i, _)| b[i..].find("</svg>").unwrap() + 6)
        .sum();
    assert!(svg <= MAX_SVG_BYTES);
}

// ST: I18N-001 — no hard-coded user-facing text in templates (all text comes from catalogs).
#[test]
fn templates_have_no_hard_coded_text() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/templates");
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let src = std::fs::read_to_string(&path).unwrap();
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

// ST: SUI-041 — locale only from the path allow-list.
#[test]
fn locale_allow_list() {
    for l in Locale::ALL {
        assert_eq!(Locale::from_tag(l.tag()), Some(l));
    }
    for bad in ["", "EN", "en-us", "fr", "../en", "en/", "ar"] {
        assert_eq!(Locale::from_tag(bad), None);
    }
    assert!(!Locale::En.is_pseudo());
    assert!(Locale::EnXA.is_pseudo());
}

// ST: invalid ids are rejected instead of being rendered (fail closed).
#[test]
fn invalid_ids_rejected() {
    let mut vm = sample_view_model(Screen::Questionnaire, Mode::Anonymous, false);
    vm.questionnaire.questions[0].id = "x\" onmouseover=\"a".into();
    assert!(matches!(
        render(Screen::Questionnaire, &vm, &Locale::En),
        Err(RenderError::InvalidId(_))
    ));
    let mut vm = sample_view_model(Screen::Landing, Mode::Anonymous, false);
    vm.ctx.form_token = Some("<x>".into());
    assert!(matches!(
        render(Screen::Landing, &vm, &Locale::En),
        Err(RenderError::InvalidId(_))
    ));
    let mut vm = sample_view_model(Screen::NewReport, Mode::Anonymous, false);
    vm.new_report.channels[0].id = "a b".into();
    assert!(render(Screen::NewReport, &vm, &Locale::En).is_err());
}

// ST: SUI-018-adjacent / ADP-03 — S05b confirmation offers two equally styled buttons.
#[test]
fn identity_confirmation_equal_buttons() {
    let (_, b) = render_ok(Screen::IdentityConfirm, Locale::En, Mode::Anonymous, false);
    let h = Html::parse_document(&b);
    let btns: Vec<_> = h.select(&sel("main .pair button")).collect();
    assert_eq!(btns.len(), 2);
    assert_eq!(btns[0].value().attr("class"), btns[1].value().attr("class"));
    assert_eq!(text_of(btns[0]), "No, stay anonymous");
    assert_eq!(text_of(btns[1]), "Yes, share who I am");
}

// ST: Leave page — no links except "Back to start" (11 §7 Leave).
#[test]
fn leave_page_minimal() {
    let (p, b) = render_ok(Screen::Leave, Locale::En, Mode::Anonymous, false);
    let h = Html::parse_document(&b);
    let links: Vec<_> = h
        .select(&sel("a"))
        .filter(|a| a.value().attr("class") != Some("skip"))
        .collect();
    assert_eq!(links.len(), 1);
    assert_eq!(text_of(links[0]), "Back to start");
    assert!(p.header("Clear-Site-Data").is_some());
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

#[test]
fn robots_padded() {
    let p = robots_txt();
    assert_eq!(p.body.len(), SizeClass::P1.bytes());
}

mod prop {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]
        // ST: SUI-023 / SUI-005 — arbitrary team and source text is escaped, parses cleanly, and
        // never changes the response size.
        #[test]
        fn arbitrary_text_is_inert(text in any::<String>(), sender in "[^\u{0}]{0,40}") {
            let mut vm = sample_view_model(Screen::Conversation, Mode::Anonymous, false);
            vm.conversation.messages[0].text = text.clone();
            vm.conversation.messages[0].sender = sender;
            vm.conversation.draft_text = text;
            let p = render(Screen::Conversation, &vm, &Locale::En).unwrap();
            prop_assert_eq!(p.body.len(), SizeClass::P2.bytes());
            let b = body(&p);
            prop_assert!(!b.to_ascii_lowercase().contains("<script"));
            let h = Html::parse_document(&b);
            prop_assert_eq!(h.select(&sel("article")).count(), 2);
        }
    }
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
