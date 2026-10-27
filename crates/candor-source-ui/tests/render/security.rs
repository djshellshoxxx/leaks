// SPDX-License-Identifier: AGPL-3.0-or-later
//! Security conformance: output scan, escaping, CSRF tokens, bidi, locale allow-list, ids, leave page.

use super::preview::sample_view_model;
use super::{body, render_ok, sel, text_of, variants};
use candor_source_ui::*;
use scraper::Html;
use zeroize::Zeroizing;

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
        vm.inbox.messages[0].text = Zeroizing::new(evil.into());
        vm.inbox.messages[0].sender = Zeroizing::new(evil.into());
        vm.conversation.messages[0].text = Zeroizing::new(evil.into());
        vm.conversation.draft_text = Zeroizing::new(evil.into());
        vm.files.files[0].name = Zeroizing::new(evil.into());
        vm.review.answers[0].answer = Zeroizing::new(evil.into());
        vm.review.channel = evil.into();
        vm.concerns.roles[0] = evil.into();
        vm.identity.full_name = Zeroizing::new(evil.into());
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

// ST: AUD-RM1-SUI-06 / 11 §5.7 / ADR-051(4) — every <form> on every page (pre-session ones
// included: S11 login, Leave, S01–S03) carries exactly one hidden `csrf` token field, and a page
// with a form but no token fails closed.
#[test]
fn every_form_carries_a_token() {
    let forms = sel("form");
    let tok = sel("input[type=hidden][name=csrf]");
    let mut n = 0usize;
    for (s, l, m, e) in variants() {
        let (_, b) = render_ok(s, l, m, e);
        let h = Html::parse_document(&b);
        for f in h.select(&forms) {
            n += 1;
            let toks: Vec<_> = f.select(&tok).collect();
            assert_eq!(
                toks.len(),
                1,
                "{} {}: form without one token",
                s.spec_id(),
                l.tag()
            );
            assert_eq!(toks[0].value().attr("value"), m_token(&s));
        }
        let mut vm = sample_view_model(s, m, e);
        vm.ctx.form_token = None;
        if b.contains("<form") {
            assert_eq!(
                render(s, &vm, &l).err(),
                Some(RenderError::MissingData("form token")),
                "{}",
                s.spec_id()
            );
        }
    }
    assert!(n > 0);
    // The Leave *page* has no form; its Leave *button* is on S02 and in the footer.
    for s in [
        Screen::Login,
        Screen::Landing,
        Screen::Safety,
        Screen::Status,
    ] {
        let (_, b) = render_ok(s, Locale::En, Mode::Anonymous, false);
        assert!(b.contains("name=\"csrf\""), "{}", s.spec_id());
    }
}

fn m_token(s: &Screen) -> Option<&'static str> {
    let vm = sample_view_model(*s, Mode::Anonymous, false);
    Some(if vm.ctx.has_session_cookie {
        "Zm9ybS10b2tlbi1zYW1wbGU"
    } else {
        "cHJlLXNlc3Npb24tdG9rZW4"
    })
}

// ST: AUD-RM1-SUI-10 — bidi controls in team messages and sender labels are shown as U+FFFD,
// and each message is framed (`article.msg`).
#[test]
fn team_message_bidi_neutralised() {
    let mut vm = sample_view_model(Screen::Inbox, Mode::Anonymous, false);
    vm.inbox.messages[0].text = Zeroizing::new("a\u{202E}b\u{2066}c\u{202A}d".into());
    vm.inbox.messages[0].sender = Zeroizing::new("Team\u{202E}\u{2069}".into());
    let b = body(&render(Screen::Inbox, &vm, &Locale::En).unwrap());
    let h = Html::parse_document(&b);
    let arts: Vec<_> = h.select(&sel("article.msg")).collect();
    assert_eq!(arts.len(), 2);
    let t = arts[0].text().collect::<String>();
    assert!(t.contains("a\u{FFFD}b\u{FFFD}c\u{FFFD}d"), "{t:?}");
    assert!(t.contains("Team\u{FFFD}\u{FFFD}"));
    // (U+2068/U+2069 also appear as Fluent's own isolation around placeables.)
    for c in ['\u{202A}', '\u{202E}', '\u{2066}'] {
        assert!(!t.contains(c));
    }
    assert!(stylesheet().contains("article.msg{border:"));
}

// ST: SUI-041 — locale only from the path allow-list.
#[test]
fn locale_allow_list() {
    for l in Locale::ALL {
        assert_eq!(Locale::ALL.iter().filter(|x| x.tag() == l.tag()).count(), 1);
        // AUD-RM1-SUI-04: production routing never resolves a pseudo-locale.
        let prod = Locale::from_tag(l.tag());
        assert_eq!(prod.is_some(), !l.is_pseudo(), "{}", l.tag());
    }
    assert_eq!(Locale::PRODUCTION.to_vec(), vec![Locale::En]);
    assert!(Locale::PRODUCTION.iter().all(|l| !l.is_pseudo()));
    // The default language list offers production locales only.
    let mut vm = sample_view_model(Screen::Landing, Mode::Anonymous, false);
    vm.ctx.offered_locales.clear();
    let b = body(&render(Screen::Landing, &vm, &Locale::En).unwrap());
    let h = Html::parse_document(&b);
    let tags: Vec<_> = h
        .select(&sel("footer a[hreflang]"))
        .map(|a| a.value().attr("hreflang").unwrap().to_owned())
        .collect();
    assert_eq!(tags, vec!["en"]);
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
    vm.ctx.form_token = Some(Zeroizing::new("<x>".into()));
    assert!(matches!(
        render(Screen::Landing, &vm, &Locale::En),
        Err(RenderError::InvalidId(_))
    ));
    let mut vm = sample_view_model(Screen::NewReport, Mode::Anonymous, false);
    vm.new_report.channels[0].id = "a b".into();
    assert!(render(Screen::NewReport, &vm, &Locale::En).is_err());
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
            vm.conversation.messages[0].text = Zeroizing::new(text.clone());
            vm.conversation.messages[0].sender = Zeroizing::new(sender);
            vm.conversation.draft_text = Zeroizing::new(text);
            let p = render(Screen::Conversation, &vm, &Locale::En).unwrap();
            prop_assert_eq!(p.body.len(), SizeClass::P2.bytes());
            let b = body(&p);
            prop_assert!(!b.to_ascii_lowercase().contains("<script"));
            let h = Html::parse_document(&b);
            prop_assert_eq!(h.select(&sel("article")).count(), 2);
        }
    }
}
