// SPDX-License-Identifier: AGPL-3.0-or-later
//! Form conformance: labelled controls, buttons, identity confirmation, passphrase display,
//! exhausted attempts, error pattern and part navigation.

use std::collections::HashSet;

use candor_source_ui::*;
use scraper::{ElementRef, Html};
use zeroize::Zeroizing;

use super::preview::sample_view_model;
use super::{body, has_text, render_ok, sel, text_of, variants};

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
                    "page",
                    // AUD-RM1-SUI-01: questions shown on a part, and the byte range of a piece.
                    "shown",
                    "piece"
                ]
                .contains(&n),
                "{id}: hidden field {n}"
            );
        }
    }
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

// ST: AUD-RM1-SUI-07 — the one-line passphrase field carries the clipboard warning, linked with
// aria-describedby.
#[test]
fn passphrase_copy_warning() {
    for s in [Screen::Credential, Screen::RotateCredential] {
        let (_, b) = render_ok(s, Locale::En, Mode::Anonymous, false);
        let h = Html::parse_document(&b);
        let line = h.select(&sel("#f-phrase_line")).next().unwrap();
        assert_eq!(line.value().attr("aria-describedby"), Some("h-phrase_line"));
        let hint = h.select(&sel("#h-phrase_line")).next().unwrap();
        assert!(text_of(hint).contains("keep or sync what you copy"));
    }
    assert_eq!(
        string_class("sui-cred-copy-warning"),
        Some(StringClass::Tier0)
    );
}

// ST: AUD-RM1-SUI-12 — on every part of S12, the part-navigation buttons belong to a
// url-encoded form without a file input, so moving between parts never uploads a chosen file;
// the file input is alone in its own multipart form (08 SW-13) with no navigation or send button.
#[test]
fn s12_navigation_never_posts_a_file() {
    let mut vm = sample_view_model(Screen::Conversation, Mode::Anonymous, false);
    vm.conversation.draft_text = Zeroizing::new("&".repeat(60_000));
    vm.ctx.part = 0;
    let first = render(Screen::Conversation, &vm, &Locale::En).unwrap();
    assert!(first.parts >= 2);
    let mut saw_file = false;
    let mut saw_prev = false;
    for part in 0..first.parts {
        vm.ctx.part = u16::try_from(part).unwrap();
        let b = body(&render(Screen::Conversation, &vm, &Locale::En).unwrap());
        let h = Html::parse_document(&b);
        for f in h.select(&sel("form")) {
            let id = f.value().attr("id").unwrap_or("");
            let owned = |q: &str| {
                f.select(&sel(q)).count()
                    + if id.is_empty() {
                        0
                    } else {
                        h.select(&sel(&format!("{q}[form={id}]"))).count()
                    }
            };
            let files = owned("input[type=file]");
            let nav = owned("button[name=part]");
            let send = owned("button[name=action][value=send]");
            let multipart = f.value().attr("enctype") == Some("multipart/form-data");
            if files > 0 {
                saw_file = true;
                assert!(multipart && nav == 0 && send == 0, "file form is separate");
                assert_eq!(owned("textarea"), 0);
            }
            if nav > 0 || send > 0 {
                assert!(
                    !multipart && files == 0,
                    "navigation/send form posts no file"
                );
            }
            saw_prev |= nav > 0 && part + 1 == first.parts;
        }
    }
    assert!(saw_file && saw_prev);
}
