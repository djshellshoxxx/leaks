// SPDX-License-Identifier: AGPL-3.0-or-later
//! Sample view models for previews (`examples/render_all.rs`) and tests. All data is fictional;
//! the sample passphrase is a fixed, public test value and must never be used as a credential.
//!
//! Dev-only: this file is included with `#[path]` by the integration tests and the example and is
//! never part of the library, so no build of the server (including `--all-features`) contains it
//! (AUD-RM1-SUI-09/-13).

use zeroize::Zeroizing;

use candor_source_ui::*;

fn day(y: u16, m: u8, d: u8) -> Day {
    Day::new(y, m, d).unwrap_or(Day::EPOCH)
}

fn channel(id: &str, name: &str, desc: &str, available: bool, independent: bool) -> ChannelOption {
    ChannelOption {
        id: id.to_owned(),
        name: name.to_owned(),
        description: desc.to_owned(),
        languages: "EN, FR".to_owned(),
        triage: vec![
            "Audit Committee Chair".to_owned(),
            "External Counsel".to_owned(),
        ],
        allows_confidential: true,
        allows_identified: true,
        available,
        independent_route: independent,
    }
}

/// The fixed, public test piece key (AUD-RM1-SUI-11). Never a production value.
pub fn sample_piece_key() -> PieceKey {
    PieceKey::new([0x5a; 32])
}

/// A sample view model for `screen` in `mode`, with or without errors.
pub fn sample_view_model(screen: Screen, mode: Mode, with_errors: bool) -> ViewModel {
    let mut vm = ViewModel::default();
    let session = !matches!(
        screen,
        Screen::Landing
            | Screen::Safety
            | Screen::SafetyTips
            | Screen::Status
            | Screen::Login
            | Screen::Leave
            | Screen::NotFound
            | Screen::Maintenance
            | Screen::MethodNotAllowed
    );
    vm.ctx = PageContext {
        method: Method::Get,
        has_session_cookie: session,
        mode,
        org: "Example Org".to_owned(),
        form_token: Some("Zm9ybS10b2tlbi1zYW1wbGU".to_owned()),
        piece_key: Some(sample_piece_key()),
        session: session.then_some(SessionTimers {
            abs_remaining_secs: 5_400,
        }),
        banners: Banners {
            operator_statement: OperatorStatement::Current {
                issued: day(2026, 9, 12),
            },
            incident: None,
            roster_changes: Vec::new(),
        },
        errors: Vec::new(),
        page_error: None,
        text_kept: false,
        // Previews and CI list every built-in locale (worst-case footer size).
        offered_locales: Locale::ALL.to_vec(),
        part: 0,
    };
    vm.deployment = DeploymentInfo {
        onion_address: "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion".to_owned(),
        info_site_address: "speakup.example.org".to_owned(),
        project_onion_address: "candorprojectxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion"
            .to_owned(),
        custodian_label: "the Ethics Office identity custodians".to_owned(),
        high_profile: false,
        recovery: None,
        reduced_sod_oversight: None,
        oversight_label: None,
        break_glass_roles: Some("the General Counsel and the Audit Committee Chair".to_owned()),
        alternative_label: None,
        jurisdiction_rights_text: None,
        jurisdiction_retaliation_text: None,
        external_bodies: vec!["National Whistleblowing Authority".to_owned()],
        ack_days: 7,
        passphrase_words: 10,
        intake_backup_days: Some(14),
        failover_notice: false,
    };
    vm.landing.purpose = "Tell the Audit Committee about fraud or misconduct. Your report goes to people who are independent of management.".to_owned();
    vm.status.channels = vec![ChannelRoles {
        channel: "Audit Committee".to_owned(),
        triage: vec![
            "Audit Committee Chair".to_owned(),
            "External Counsel".to_owned(),
        ],
        others: vec!["Internal Audit investigators".to_owned()],
    }];
    vm.new_report = NewReportData {
        channels: vec![
            channel(
                "audit",
                "Audit Committee",
                "Fraud and accounting",
                true,
                true,
            ),
            channel("ethics", "Ethics Office", "Workplace conduct", false, false),
        ],
        selected_channel: None,
        selected_mode: Mode::Anonymous,
        snapshot_stale: false,
    };
    vm.concerns = ConcernsData {
        triage: vec![
            "Audit Committee Chair".to_owned(),
            "External Counsel".to_owned(),
        ],
        roles: vec![
            "Chief Financial Officer".to_owned(),
            "Head of Internal Audit".to_owned(),
            "HR Investigations Lead".to_owned(),
        ],
        ticked: Vec::new(),
        load_failed: false,
    };
    vm.no_reader.alternatives = vec![
        channel(
            "board",
            "Board Audit Committee",
            "Independent of management",
            true,
            true,
        ),
        channel(
            "ombuds",
            "External Ombudsperson",
            "Outside the organization",
            true,
            false,
        ),
    ];
    let cats = vec![
        ChoiceOption {
            value: "fraud".to_owned(),
            label: Text::Custom("Fraud or accounting".to_owned()),
        },
        ChoiceOption {
            value: "safety".to_owned(),
            label: Text::Custom("Health and safety".to_owned()),
        },
    ];
    vm.questionnaire = QuestionnaireData {
        step: 4,
        questions: default_questionnaire_step(4, &cats, &[2026, 2025, 2024, 2023]),
    };
    vm.identity = IdentityData {
        target: if mode == Mode::Identified {
            Mode::Identified
        } else {
            Mode::Confidential
        },
        full_name: String::new(),
        role: String::new(),
        contact_other: true,
        contact_other_value: String::new(),
    };
    let files = vec![
        AttachedFile {
            name: "file-01.pdf".to_owned(),
            size_bytes: 2_100_000,
            description: String::new(),
        },
        AttachedFile {
            name: "file-02.jpg".to_owned(),
            size_bytes: 3_400_000,
            description: "Photo of the notice board".to_owned(),
        },
    ];
    vm.files = FilesData {
        files: files.clone(),
        max_files: 20,
        max_file_bytes: 4_000_000_000,
        max_total_bytes: 8_000_000_000,
        neutral_names: true,
    };
    vm.review = ReviewData {
        channel: "Audit Committee".to_owned(),
        first_readers: vec!["Audit Committee Chair".to_owned(), "External Counsel".to_owned()],
        others: vec!["Internal Audit investigators".to_owned()],
        kept_out: vec!["Chief Financial Officer".to_owned()],
        kept_out_auto: 1,
        answers: vec![
            ReviewAnswer {
                question: Text::Key("sui-q-what"),
                step: 4,
                answer: "In March the quarterly figures were changed.\nThe old version is on the shared drive. <b>not bold</b>".to_owned(),
            },
            ReviewAnswer {
                question: Text::Key("sui-q-where"),
                step: 4,
                answer: String::new(),
            },
        ],
        files,
        hints: vec![IdentityHint {
            kind: HintKind::Email,
            field: Text::Key("sui-q-what"),
            step: 4,
            line: 3,
        }],
        invisible_chars: 14,
        delayed_delivery: false,
        has_identity: mode.is_disclosed(),
    };
    vm.credential.passphrase = Passphrase {
        words: [
            "cobalt", "ripple", "anthem", "gravel", "sonnet", "mosaic", "tundra", "whistle",
            "ember", "lantern",
        ]
        .iter()
        .map(|w| Zeroizing::new((*w).to_owned()))
        .collect(),
        wordlist_lang: "en".to_owned(),
    };
    vm.confirm = ConfirmData {
        positions: [2, 5, 9],
        attempts_exhausted: false,
    };
    vm.sent = Some(SentData {
        sent: day(2026, 9, 30),
        delayed: true,
    });
    let msgs = vec![
        InboxMessage {
            sender: "Audit Committee team".to_owned(),
            date: day(2026, 10, 4),
            text: "Thank you. We have received your report and will look into it.\nhttps://example.org is shown as text.".to_owned(),
        },
        InboxMessage {
            sender: "Audit Committee team".to_owned(),
            date: day(2026, 10, 1),
            text: "Your report was received.".to_owned(),
        },
    ];
    vm.inbox = InboxData {
        status: CaseStatus::Acknowledged,
        messages: msgs.clone(),
        rotation_offer: false,
    };
    vm.conversation = ConversationData {
        messages: msgs,
        draft_text: String::new(),
        delayed_delivery: false,
        just_sent: false,
        refused_route: None,
        has_older: true,
        has_newer: false,
        page: 0,
    };
    vm.busy = BusyData {
        retry: Some(Route::Review),
        at_submit: false,
    };
    if !session {
        // Session-less pages carry a pre-session token bound to a pre-session cookie
        // (AUD-RM1-SUI-06; every form has a token).
        vm.ctx.form_token = Some("cHJlLXNlc3Npb24tdG9rZW4".to_owned());
    }
    // Responses to POST-only routes.
    if matches!(
        screen,
        Screen::Credential
            | Screen::Confirm
            | Screen::Sent
            | Screen::RotateCredential
            | Screen::RotateConfirm
            | Screen::RotateDone
            | Screen::Discarded
            | Screen::Closed
            | Screen::DeleteRequested
            | Screen::Leave
            | Screen::Busy
            | Screen::NoReader
            | Screen::IdentityConfirm
            | Screen::ModeChanged
    ) {
        vm.ctx.method = Method::Post;
    }
    if with_errors {
        add_errors(&mut vm, screen);
    }
    vm
}

fn add_errors(vm: &mut ViewModel, screen: Screen) {
    let fe = |field: &str, key: &'static str| FieldError {
        field: field.to_owned(),
        message: Msg::new(key),
    };
    let errs = match screen {
        Screen::NewReport => vec![fe("channel_id", "sui-new-err-channel")],
        Screen::Questionnaire => vec![
            fe("what", "sui-q-err-what"),
            FieldError {
                field: "where".to_owned(),
                message: Msg::new("sui-q-err-too-long").arg("max", 500u64),
            },
        ],
        Screen::Identity => vec![fe("full_name", "sui-id-err-name")],
        Screen::Files => vec![FieldError {
            field: "file".to_owned(),
            message: Msg::new("sui-files-err-too-large")
                .arg("max_file", "4 GB")
                .arg("max_total", "8 GB"),
        }],
        Screen::Confirm | Screen::RotateConfirm => vec![fe("w_b", "sui-confirm-mismatch")],
        Screen::Login | Screen::RotateExplain | Screen::CloseMailbox => {
            vec![fe("passphrase", "sui-login-err-auth")]
        }
        Screen::Conversation => vec![fe("text", "sui-conv-err-empty")],
        _ => Vec::new(),
    };
    if errs.is_empty() {
        // Screens without fields on the page report a page-level error (on S08 the missing
        // answers are reached with the Edit buttons).
        vm.ctx.page_error = Some(Msg::new(if screen == Screen::Review {
            "sui-review-err-missing"
        } else {
            "sui-error-not-sent"
        }));
    }
    vm.ctx.errors = errs;
    vm.ctx.text_kept = true;
}

/// Every (screen, locale) pair, for previews and tests.
pub fn all_cases() -> Vec<(Screen, Locale)> {
    let mut v = Vec::new();
    for s in Screen::ALL {
        for l in Locale::ALL {
            v.push((s, l));
        }
    }
    v
}
