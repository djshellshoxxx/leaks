// SPDX-License-Identifier: AGPL-3.0-or-later
//! AUD-RM1-SUI-02 regression tests: view-model types that can hold source text, identity data,
//! file names, team messages, the form token or the source's choices never derive `Debug`, and
//! `{:?}` of a fully populated view model shows none of that data (SG-21).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "support/preview.rs"]
#[allow(dead_code)]
mod preview;

use candor_source_ui::*;
use preview::sample_view_model;
use zeroize::Zeroizing;

const MODEL_SRC: &str = include_str!("../src/model.rs");

/// Types that may derive `Debug`: enums, flags, days, deployment configuration and catalog
/// references. Anything else in `model.rs` must use the redacted implementation.
const MAY_DERIVE_DEBUG: &[&str] = &[
    "Mode",
    "Method",
    "Day",
    "SessionTimers",
    "OperatorStatement",
    "IncidentNotice",
    "CaptureNotice",
    "RosterChange",
    "Banners",
    "DeploymentInfo",
    "RecoveryQuorum",
    "ChannelRoles",
    "LandingData",
    "StatusData",
    "ChannelOption",
    "NoReaderData",
    "QuestionKind",
    "Text",
    "ChoiceOption",
    "HintKind",
    "CredentialData",
    "ConfirmData",
    "CaseStatus",
    "LoginData",
    "BusyData",
];

/// Lint: every `#[derive(..Debug..)]` in `model.rs` is on an allow-listed type.
#[test]
fn sensitive_types_do_not_derive_debug() {
    let lines: Vec<&str> = MODEL_SRC.lines().collect();
    let mut checked = 0;
    for (i, l) in lines.iter().enumerate() {
        let l = l.trim();
        if !(l.starts_with("#[derive(") && l.contains("Debug")) {
            continue;
        }
        let item = lines[i + 1..]
            .iter()
            .map(|s| s.trim())
            .find(|s| s.starts_with("pub struct") || s.starts_with("pub enum"))
            .unwrap();
        let name = item
            .split_whitespace()
            .nth(2)
            .unwrap()
            .trim_end_matches(['{', ';', '(', '<']);
        assert!(
            MAY_DERIVE_DEBUG.contains(&name),
            "{name} derives Debug; give it a redacted Debug (AUD-RM1-SUI-02)"
        );
        checked += 1;
    }
    assert!(checked >= 20);
}

// SG-21: `{:?}` of a view model full of sentinel values shows none of them.
#[test]
fn debug_output_has_no_content() {
    const S: &str = "SENTINEL-7f3a";
    let mut vm = sample_view_model(Screen::Review, Mode::Confidential, true);
    vm.ctx.form_token = Some(Zeroizing::new(S.into()));
    vm.identity.full_name = Zeroizing::new(S.into());
    vm.identity.role = Zeroizing::new(S.into());
    vm.identity.contact_other_value = Zeroizing::new(S.into());
    vm.files.files[0].name = Zeroizing::new(S.into());
    vm.files.files[0].description = Zeroizing::new(S.into());
    vm.review.answers[0].answer = Zeroizing::new(S.into());
    vm.review.files[0].name = Zeroizing::new(S.into());
    vm.review.kept_out = vec![S.into()];
    vm.inbox.messages[0].text = Zeroizing::new(S.into());
    vm.inbox.messages[0].sender = Zeroizing::new(S.into());
    vm.conversation.messages[0].text = Zeroizing::new(S.into());
    vm.conversation.draft_text = Zeroizing::new(S.into());
    vm.questionnaire.questions[0].value = vec![Zeroizing::new(S.into())];
    vm.concerns.ticked = vec![7];
    vm.new_report.selected_channel = Some(S.into());
    vm.ctx.errors = vec![FieldError {
        field: "what".into(),
        message: Msg::new("sui-q-what").arg("x", S),
    }];
    let all = [
        format!("{vm:?}"),
        format!("{:?}", vm.ctx),
        format!("{:?}", vm.identity),
        format!("{:?}", vm.files),
        format!("{:?}", vm.files.files),
        format!("{:?}", vm.review),
        format!("{:?}", vm.review.answers),
        format!("{:?}", vm.inbox),
        format!("{:?}", vm.inbox.messages),
        format!("{:?}", vm.conversation),
        format!("{:?}", vm.questionnaire),
        format!("{:?}", vm.questionnaire.questions),
        format!("{:?}", vm.new_report),
        format!("{:?}", vm.ctx.errors),
        format!("{:?}", vm.credential),
    ];
    for d in all {
        assert!(!d.contains(S), "{d}");
        assert!(!d.contains("cobalt"), "{d}");
    }
    assert_eq!(
        format!("{:?}", vm.ctx.errors[0].message),
        "Msg { key: \"sui-q-what\", args: [1 redacted] }"
    );
}
