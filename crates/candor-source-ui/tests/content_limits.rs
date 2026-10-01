// SPDX-License-Identifier: AGPL-3.0-or-later
//! AUD-RM1-SUI-01 regression tests: worst-case escaping at the spec input limits (11 §5.7) never
//! pushes a page past its size class (11 §5.4, ADR-051(2)), never fails the render, and never
//! drops text. Long content is split into parts; every byte is on exactly one part.
//!
//! Limits used (11 §5.7): long text 60,000 chars / 65,536 bytes UTF-8; short text 500 chars;
//! total per report 98,304 bytes; one S12 message 64 KiB (§5.4 rule 2); S05b fields 200/500
//! chars; S06 descriptions 500 chars. Escapable characters expand up to 5× (`&` → `&amp;`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

#[path = "support/preview.rs"]
#[allow(dead_code)]
mod preview;

use std::collections::HashSet;

use candor_source_ui::*;
use preview::sample_view_model;
use scraper::{Html, Selector};

const LONG_BYTES: usize = 65_536;
const LONG_CHARS: usize = 60_000;
const REPORT_BYTES: usize = 98_304;
const SHORT_CHARS: usize = 500;

/// Characters with the largest escaped size (`&`, `"`, `'` → 5 bytes; `<` → 4 bytes).
const WORST: [char; 4] = ['&', '"', '\'', '<'];

fn sel(s: &str) -> Selector {
    Selector::parse(s).unwrap()
}

fn rep(c: char, n: usize) -> String {
    std::iter::repeat_n(c, n).collect()
}

/// Mixed worst-case text: escapable characters with line breaks and a few words, so cuts can
/// land on whitespace as well as inside runs.
fn mixed(c: char, bytes: usize) -> String {
    let unit = format!("{}\n{} x\r\n", rep(c, 37), rep(c, 11));
    let mut s = String::new();
    while s.len() + unit.len() <= bytes {
        s.push_str(&unit);
    }
    s.push_str(&rep(c, bytes - s.len()));
    s
}

/// Renders every part of `screen`; checks exact class size, parse cleanliness, unique ids and
/// the clamp of an out-of-range part. Returns the bodies.
fn all_parts(s: Screen, vm: &ViewModel, l: Locale) -> Vec<String> {
    let mut vm = vm.clone();
    vm.ctx.part = 0;
    let first =
        render(s, &vm, &l).unwrap_or_else(|e| panic!("{} {} part 0: {e:?}", s.spec_id(), l.tag()));
    let n = first.parts;
    assert!(n >= 1);
    let mut out = Vec::new();
    for k in 0..n {
        vm.ctx.part = u16::try_from(k).unwrap();
        let p = render(s, &vm, &l)
            .unwrap_or_else(|e| panic!("{} {} part {k}: {e:?}", s.spec_id(), l.tag()));
        assert_eq!(p.part, k);
        assert_eq!(p.parts, n);
        assert_eq!(p.body.len(), p.class.bytes(), "{} {}", s.spec_id(), l.tag());
        assert_eq!(
            p.class,
            SizeClass::for_request(vm.ctx.method, vm.ctx.has_session_cookie),
            "class must not depend on content"
        );
        let b = String::from_utf8(p.body.to_vec()).unwrap();
        let h = Html::parse_document(&b);
        assert!(
            h.errors.is_empty(),
            "{} {} part {k}: {:?}",
            s.spec_id(),
            l.tag(),
            h.errors
        );
        let mut ids = HashSet::new();
        for el in h.select(&sel("[id]")) {
            let v = el.value().attr("id").unwrap();
            assert!(
                ids.insert(v.to_owned()),
                "{}: duplicate id {v}",
                s.spec_id()
            );
        }
        if n > 1 {
            // Navigation to the neighbouring parts is always present.
            let values: Vec<String> = h
                .select(&sel("button[name=part]"))
                .map(|b| b.value().attr("value").unwrap().to_owned())
                .collect();
            if k > 0 {
                assert!(
                    values.contains(&(k - 1).to_string()),
                    "{}: no previous",
                    s.spec_id()
                );
            }
            if k + 1 < n {
                assert!(
                    values.contains(&(k + 1).to_string()),
                    "{}: no next",
                    s.spec_id()
                );
            }
        }
        out.push(b);
    }
    vm.ctx.part = u16::try_from(n + 3).unwrap_or(u16::MAX);
    let clamped = render(s, &vm, &l).unwrap();
    assert_eq!(clamped.part, n - 1, "out-of-range part is clamped");
    out
}

/// HTML parsing turns CR LF and lone CR into LF (as browsers do); compare on LF text.
fn nl(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\r', "\n")
}

/// Texts of `selector` across all parts, in order.
fn texts(bodies: &[String], selector: &str) -> Vec<String> {
    let s = sel(selector);
    bodies
        .iter()
        .flat_map(|b| {
            Html::parse_document(b)
                .select(&s)
                .map(|e| e.text().collect::<String>())
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Rebuilds an editable value from its pieces: each part carries one control named `name` and,
/// when split, a `piece` field with the byte range. Asserts the pieces cover `original` exactly.
fn rebuild(bodies: &[String], name: &str, original: &str) {
    let ctl = sel(&format!(
        "textarea[name={name}], input[type=text][name={name}]"
    ));
    let piece = sel("input[name=piece]");
    let mut next = 0usize;
    let mut seen = 0usize;
    let norm = nl;
    for b in bodies {
        let h = Html::parse_document(b);
        let ctls: Vec<_> = h.select(&ctl).collect();
        if ctls.is_empty() {
            continue;
        }
        assert_eq!(ctls.len(), 1, "one {name} control per part");
        let el = ctls[0];
        let value = if el.value().name() == "textarea" {
            el.text().collect::<String>()
        } else {
            el.value().attr("value").unwrap_or("").to_owned()
        };
        let pieces: Vec<_> = h
            .select(&piece)
            .filter_map(|p| parse_piece(p.value().attr("value").unwrap()))
            .filter(|p| p.field == name)
            .collect();
        match pieces.as_slice() {
            [] => {
                assert_eq!(seen, 0, "{name}: whole value must be the only control");
                assert_eq!(norm(&value), norm(original), "{name}: whole value");
                next = original.len();
            }
            [p] => {
                let (start, end, total) = (&p.start, &p.end, &p.total);
                assert_eq!(*total, original.len());
                // AUD-RM1-SUI-11: the piece is MAC-bound to the stored value: it splices back
                // under the session key, and is refused for a same-length modified value.
                let key = preview::sample_piece_key();
                let piece_text = &original[*start..*end];
                assert_eq!(
                    splice_piece(&key, name, original, p, piece_text)
                        .unwrap()
                        .as_str(),
                    original
                );
                if let Some(c) = original.chars().next() {
                    let swapped = if c == 'x' { "y" } else { "x" };
                    if c.len_utf8() == 1 {
                        let changed = format!("{swapped}{}", &original[1..]);
                        assert_eq!(
                            splice_piece(&key, name, &changed, p, piece_text).err(),
                            Some(SpliceError::Stale)
                        );
                    }
                }
                assert_eq!(*start, next, "{name}: pieces contiguous");
                assert_eq!(
                    norm(&value),
                    norm(&original[*start..*end]),
                    "{name}: piece text"
                );
                next = *end;
            }
            _ => panic!("{name}: more than one piece on a part"),
        }
        seen += 1;
    }
    assert!(seen > 0, "{name}: control missing");
    assert_eq!(next, original.len(), "{name}: pieces cover the value");
}

fn s05_vm(c: char) -> (ViewModel, String, String, String) {
    let mut vm = sample_view_model(Screen::Questionnaire, Mode::Anonymous, false);
    // A builder step with two long-text questions (per-report total 98,304 bytes) and a short one.
    let what = mixed(c, LONG_BYTES);
    let who = rep(c, REPORT_BYTES - LONG_BYTES - SHORT_CHARS);
    let where_ = rep(c, SHORT_CHARS);
    let qs = &mut vm.questionnaire.questions;
    qs.retain(|q| q.id != "when");
    for q in qs.iter_mut() {
        match q.id.as_str() {
            "what" => q.value = vec![what.clone()],
            "where" => q.value = vec![where_.clone()],
            _ => {}
        }
    }
    qs.push(Question {
        id: "who".into(),
        label: Text::Key("sui-q-who"),
        hint: None,
        kind: QuestionKind::LongText,
        required: false,
        value: vec![who.clone()],
    });
    (vm, what, who, where_)
}

fn s08_vm(c: char) -> (ViewModel, Vec<String>) {
    let mut vm = sample_view_model(Screen::Review, Mode::Anonymous, false);
    let a = mixed(c, LONG_BYTES);
    let b = rep(c, REPORT_BYTES - LONG_BYTES - SHORT_CHARS);
    let w = rep(c, SHORT_CHARS);
    vm.review.answers = vec![
        ReviewAnswer {
            question: Text::Key("sui-q-what"),
            step: 4,
            answer: a.clone(),
        },
        ReviewAnswer {
            question: Text::Key("sui-q-where"),
            step: 4,
            answer: w.clone(),
        },
        ReviewAnswer {
            question: Text::Key("sui-q-who"),
            step: 5,
            answer: b.clone(),
        },
    ];
    for f in &mut vm.review.files {
        f.name = rep(c, 1_000);
    }
    vm.review.hints = (0..300)
        .map(|i| IdentityHint {
            kind: HintKind::Email,
            field: Text::Key("sui-q-what"),
            step: 4,
            line: i,
        })
        .collect();
    (vm, vec![a, w, b])
}

fn thread(c: char) -> (Vec<InboxMessage>, String) {
    let big = mixed(c, LONG_BYTES);
    let mut msgs: Vec<InboxMessage> = (1..=6)
        .map(|i| InboxMessage {
            sender: "Audit Committee team".into(),
            date: Day::new(2026, 10, i).unwrap(),
            text: format!("Ordinary reply {i}."),
        })
        .collect();
    // A hostile staff message: maximum size, worst escaping, bidi overrides, huge sender.
    msgs.insert(
        2,
        InboxMessage {
            sender: format!("\u{202E}{}", rep(c, 5_000)),
            date: Day::new(2026, 10, 9).unwrap(),
            text: big.clone(),
        },
    );
    (msgs, big)
}

// ST: AUD-RM1-SUI-01 / 11 §5.7 — S05 step at the per-report maximum with worst-case escaping, in
// every locale: renders in parts; every piece maps back to the stored value.
#[test]
fn s05_worst_case_fits_and_is_complete() {
    for l in Locale::ALL {
        for c in WORST {
            let (vm, what, who, where_) = s05_vm(c);
            let bodies = all_parts(Screen::Questionnaire, &vm, l);
            assert!(bodies.len() > 1, "split expected");
            rebuild(&bodies, "what", &what);
            rebuild(&bodies, "who", &who);
            rebuild(&bodies, "where", &where_);
            for b in &bodies {
                assert!(b.contains("name=\"shown\""));
            }
        }
    }
}

// ST: AUD-RM1-SUI-01 — S08 with 98,304 bytes of worst-case answers, long file names and many
// identity hints: every part fits P2 and the answers are shown in full across the parts; the
// send button is only on the last part.
#[test]
fn s08_worst_case_fits_and_is_complete() {
    for l in Locale::ALL {
        for c in WORST {
            let (vm, answers) = s08_vm(c);
            let bodies = all_parts(Screen::Review, &vm, l);
            assert!(bodies.len() > 1);
            assert_eq!(
                nl(&texts(&bodies, "dd p.ut").concat()),
                nl(&answers.concat())
            );
            let hints = texts(&bodies, "section li").len();
            assert_eq!(hints, 300);
            for (k, b) in bodies.iter().enumerate() {
                let send = b.contains("value=\"send\"");
                assert_eq!(send, k + 1 == bodies.len(), "send only on the last part");
            }
        }
    }
}

// ST: AUD-RM1-SUI-01 — the audit's measured cases (S08 with 10 % quotation marks; all `"`).
#[test]
fn s08_audit_cases() {
    let mut text = String::new();
    while text.len() < REPORT_BYTES {
        text.push_str("He said \"no\". ");
    }
    text.truncate(REPORT_BYTES);
    for t in [text, rep('"', REPORT_BYTES), rep('&', REPORT_BYTES)] {
        let mut vm = sample_view_model(Screen::Review, Mode::Anonymous, false);
        vm.review.answers.truncate(1);
        vm.review.answers[0].answer = t.clone();
        let bodies = all_parts(Screen::Review, &vm, Locale::En);
        assert_eq!(nl(&texts(&bodies, "dd p.ut").concat()), nl(&t));
    }
}

// ST: AUD-RM1-SUI-01 — a hostile 64 KiB staff message of `&`/`"`/`'`/`<` with bidi overrides and
// a huge sender label cannot lock the source out: S11 and S12 render every part, all other
// messages are shown, and the long one is shown in full across parts.
#[test]
fn inbox_and_conversation_survive_hostile_message() {
    for l in Locale::ALL {
        for c in WORST {
            let (msgs, big) = thread(c);
            let mut vm = sample_view_model(Screen::Inbox, Mode::Anonymous, false);
            vm.inbox.messages = msgs.clone();
            let bodies = all_parts(Screen::Inbox, &vm, l);
            let shown = texts(&bodies, "article.msg p.ut");
            let expect: Vec<String> = msgs.iter().map(|m| m.text.clone()).collect();
            assert_eq!(nl(&shown.concat()), nl(&expect.concat()), "inbox complete");
            assert!(shown.iter().any(|t| t == "Ordinary reply 6."));
            if l != Locale::ArXB {
                // (ar-XB wraps its own catalog text in RLO … PDF.)
                for t in texts(&bodies, "article") {
                    assert!(!t.contains('\u{202E}'), "bidi override neutralised");
                }
            }

            let mut vm = sample_view_model(Screen::Conversation, Mode::Anonymous, false);
            vm.conversation.messages = msgs;
            let draft = mixed(c, LONG_BYTES);
            vm.conversation.draft_text = draft.clone();
            let bodies = all_parts(Screen::Conversation, &vm, l);
            assert_eq!(
                nl(&texts(&bodies, "article.msg p.ut").concat()),
                nl(&expect.concat())
            );
            rebuild(&bodies, "text", &draft);
            let last = bodies.last().unwrap();
            assert!(last.contains("value=\"send\""), "send on the last part");
            assert!(bodies.len() > 2, "{} bytes split into parts", big.len());
        }
    }
}

// ST: AUD-RM1-SUI-01 — S12 restored drafts at 60,000 chars of each worst character.
#[test]
fn conversation_draft_audit_cases() {
    for c in WORST {
        let mut vm = sample_view_model(Screen::Conversation, Mode::Anonymous, false);
        let draft = rep(c, LONG_CHARS);
        vm.conversation.draft_text = draft.clone();
        let bodies = all_parts(Screen::Conversation, &vm, Locale::En);
        rebuild(&bodies, "text", &draft);
    }
}

// ST: AUD-RM1-SUI-01 — S06/S07 with many files, long names and maximum descriptions.
#[test]
fn files_worst_case() {
    for l in Locale::ALL {
        for c in WORST {
            for screen in [Screen::Files, Screen::MetadataWarning] {
                let mut vm = sample_view_model(screen, Mode::Anonymous, false);
                vm.files.files = (0..60)
                    .map(|i| AttachedFile {
                        name: format!("{}{i}.pdf", rep(c, 300)),
                        size_bytes: 1_000_000,
                        description: rep(c, SHORT_CHARS),
                    })
                    .collect();
                let bodies = all_parts(screen, &vm, l);
                let rows = texts(&bodies, "tbody tr").len();
                assert_eq!(rows, 60, "{}", screen.spec_id());
                if screen == Screen::Files {
                    let descs: usize = bodies
                        .iter()
                        .map(|b| {
                            Html::parse_document(b)
                                .select(&sel("input[form=desc-form][type=text]"))
                                .filter(|e| e.value().attr("value") == Some(&rep(c, SHORT_CHARS)))
                                .count()
                        })
                        .sum();
                    assert_eq!(descs, 60, "every description shown in full");
                }
            }
        }
    }
}

/// Every source- or team-controlled text field at its spec maximum, worst-case characters.
fn worst_everything(s: Screen, c: char) -> ViewModel {
    let mut vm = sample_view_model(s, Mode::Confidential, false);
    for q in &mut vm.questionnaire.questions {
        match q.kind {
            QuestionKind::LongText => q.value = vec![rep(c, LONG_BYTES)],
            QuestionKind::ShortText => q.value = vec![rep(c, SHORT_CHARS)],
            _ => {}
        }
    }
    vm.identity.full_name = rep(c, 200);
    vm.identity.role = rep(c, 200);
    vm.identity.contact_other_value = rep(c, SHORT_CHARS);
    for f in vm.files.files.iter_mut().chain(vm.review.files.iter_mut()) {
        f.name = rep(c, 255);
        f.description = rep(c, SHORT_CHARS);
    }
    let (s08, _) = s08_vm(c);
    vm.review.answers = s08.review.answers;
    let (msgs, _) = thread(c);
    vm.inbox.messages = msgs.clone();
    vm.conversation.messages = msgs;
    vm.conversation.draft_text = rep(c, LONG_CHARS);
    vm
}

// ST: AUD-RM1-SUI-01 / SUI-005 — every screen, every locale, every worst-case character, every
// content field at its maximum: no render error, every part exactly its size class.
#[test]
fn every_screen_every_locale_worst_case() {
    for s in Screen::ALL {
        for l in Locale::ALL {
            for c in WORST {
                let vm = worst_everything(s, c);
                all_parts(s, &vm, l);
            }
        }
    }
}

// ST: AUD-RM1-SUI-01 — robustness beyond the limits: a 1 MiB message still renders in parts
// (no failure page; the class never grows).
#[test]
fn far_over_limit_still_paged() {
    let mut vm = sample_view_model(Screen::Inbox, Mode::Anonymous, false);
    vm.inbox.messages[0].text = rep('&', 1 << 20);
    let bodies = all_parts(Screen::Inbox, &vm, Locale::En);
    assert!(bodies.len() >= 40);
    let total: usize = texts(&bodies, "article.msg p.ut")
        .iter()
        .map(String::len)
        .sum();
    assert_eq!(
        total,
        (1 << 20) + vm.inbox.messages[1].text.len(),
        "nothing dropped"
    );
}

// ST: AUD-RM1-SUI-01 — escaped_len matches what the page carries.
#[test]
fn escaped_len_is_exact() {
    assert_eq!(
        escaped_len("a&b\"c'd<e>f"),
        1 + 5 + 1 + 5 + 1 + 5 + 1 + 4 + 1 + 4 + 1
    );
    assert_eq!(escaped_len("é😀"), "é😀".len());
}
