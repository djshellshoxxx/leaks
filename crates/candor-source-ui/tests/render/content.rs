// SPDX-License-Identifier: AGPL-3.0-or-later
//! Content conformance: required strings, disclosures, warnings, privacy defaults and mode banner.

use candor_source_ui::*;
use scraper::{ElementRef, Html};

use super::preview::sample_view_model;
use super::{body, has_text, max_content, render_ok, sel, text_of};

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

// ST: AUD-RM1-SUI-10 — the password-manager tip names a device only the source uses.
#[test]
fn password_manager_tip_wording() {
    let (_, b) = render_ok(Screen::SafetyTips, Locale::En, Mode::Anonymous, false);
    assert!(has_text(
        &b,
        "A password manager is fine only on a device only you use, and only if it does not sync online."
    ));
}
