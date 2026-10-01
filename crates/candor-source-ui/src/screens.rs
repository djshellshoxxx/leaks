// SPDX-License-Identifier: AGPL-3.0-or-later
//! Screens (11 §7) and their askama templates (one template per screen).

use askama::Template;

use crate::model::{Mode, OperatorStatement, ViewModel};
use crate::paging::Region;
use crate::routes::Route;
use crate::view::PageView;

/// A Tier W screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Screen {
    /// S01 Landing.
    Landing,
    /// S02 Safety Check.
    Safety,
    /// S02b Safety tips for each step (11a; ADR-051(2) linked sub-page of S02).
    SafetyTips,
    /// S03 Anonymity Status.
    Status,
    /// S04 Create Report.
    NewReport,
    /// S04b "Is your report about any of these people?".
    Concerns,
    /// S04b-X "No one left to read your report first".
    NoReader,
    /// S05 Questionnaire step.
    Questionnaire,
    /// S05b page 1 (fields).
    Identity,
    /// S05b page 2 (confirmation).
    IdentityConfirm,
    /// Mode-change confirmation page (11 §5.2 rule 3; S05b "Your report is now …").
    ModeChanged,
    /// S06 Attach Evidence.
    Files,
    /// S07 Metadata Warning.
    MetadataWarning,
    /// S08 Review.
    Review,
    /// S10 Recovery Credential.
    Credential,
    /// S10c Confirm and send.
    Confirm,
    /// S10s Report sent.
    Sent,
    /// S11 login (also the wrong-passphrase page).
    Login,
    /// S11 inbox.
    Inbox,
    /// S11r explanation and current-passphrase form.
    RotateExplain,
    /// S11r new passphrase (S10-style).
    RotateCredential,
    /// S11r 3-word confirmation (S10c-style).
    RotateConfirm,
    /// S11r done.
    RotateDone,
    /// S12 Secure Conversation.
    Conversation,
    /// S13 Discard draft.
    Discard,
    /// S13 discard done.
    Discarded,
    /// S13 Close mailbox.
    CloseMailbox,
    /// S13 mailbox closed.
    Closed,
    /// S13 Ask the team to delete my report.
    AskDelete,
    /// S13 delete request sent.
    DeleteRequested,
    /// Leave page.
    Leave,
    /// S90 Busy (429).
    Busy,
    /// S91 Not found (404).
    NotFound,
    /// S92 Error (500).
    ServerError,
    /// S93 Maintenance (503).
    Maintenance,
    /// S94 Signed out.
    SignedOut,
    /// 405 page (SUI-056; always P1).
    MethodNotAllowed,
}

impl Screen {
    /// All screens.
    pub const ALL: [Screen; 37] = [
        Screen::Landing,
        Screen::Safety,
        Screen::SafetyTips,
        Screen::Status,
        Screen::NewReport,
        Screen::Concerns,
        Screen::NoReader,
        Screen::Questionnaire,
        Screen::Identity,
        Screen::IdentityConfirm,
        Screen::ModeChanged,
        Screen::Files,
        Screen::MetadataWarning,
        Screen::Review,
        Screen::Credential,
        Screen::Confirm,
        Screen::Sent,
        Screen::Login,
        Screen::Inbox,
        Screen::RotateExplain,
        Screen::RotateCredential,
        Screen::RotateConfirm,
        Screen::RotateDone,
        Screen::Conversation,
        Screen::Discard,
        Screen::Discarded,
        Screen::CloseMailbox,
        Screen::Closed,
        Screen::AskDelete,
        Screen::DeleteRequested,
        Screen::Leave,
        Screen::Busy,
        Screen::NotFound,
        Screen::ServerError,
        Screen::Maintenance,
        Screen::SignedOut,
        Screen::MethodNotAllowed,
    ];

    /// Spec screen id.
    pub fn spec_id(self) -> &'static str {
        match self {
            Screen::Landing => "S01",
            Screen::Safety => "S02",
            Screen::SafetyTips => "S02b",
            Screen::Status => "S03",
            Screen::NewReport => "S04",
            Screen::Concerns => "S04b",
            Screen::NoReader => "S04b-X",
            Screen::Questionnaire => "S05",
            Screen::Identity => "S05b-1",
            Screen::IdentityConfirm => "S05b-2",
            Screen::ModeChanged => "S05b-3",
            Screen::Files => "S06",
            Screen::MetadataWarning => "S07",
            Screen::Review => "S08",
            Screen::Credential => "S10",
            Screen::Confirm => "S10c",
            Screen::Sent => "S10s",
            Screen::Login => "S11-login",
            Screen::Inbox => "S11-inbox",
            Screen::RotateExplain => "S11r-1",
            Screen::RotateCredential => "S11r-2",
            Screen::RotateConfirm => "S11r-3",
            Screen::RotateDone => "S11r-4",
            Screen::Conversation => "S12",
            Screen::Discard => "S13-discard",
            Screen::Discarded => "S13-discarded",
            Screen::CloseMailbox => "S13-close",
            Screen::Closed => "S13-closed",
            Screen::AskDelete => "S13-ask-delete",
            Screen::DeleteRequested => "S13-delete-requested",
            Screen::Leave => "leave",
            Screen::Busy => "S90",
            Screen::NotFound => "S91",
            Screen::ServerError => "S92",
            Screen::Maintenance => "S93",
            Screen::SignedOut => "S94",
            Screen::MethodNotAllowed => "S405",
        }
    }

    /// HTTP status (11 §5.9).
    pub fn status(self) -> u16 {
        match self {
            Screen::Busy => 429,
            Screen::NotFound => 404,
            Screen::ServerError => 500,
            Screen::Maintenance => 503,
            Screen::MethodNotAllowed => 405,
            _ => 200,
        }
    }

    /// Sends `Clear-Site-Data` (SUI-036: logout/leave, discard, close, submit completion).
    pub fn clears_site_data(self) -> bool {
        matches!(
            self,
            Screen::Leave | Screen::Discarded | Screen::Closed | Screen::Sent | Screen::SignedOut
        )
    }

    /// Leave page: no links except "Back to start" (11 §7 Leave).
    pub(crate) fn minimal_chrome(self) -> bool {
        matches!(self, Screen::Leave)
    }

    /// The GET route a language link points to. POST-only screens fall back to the nearest
    /// GET route of the same flow (the draft is bound to the session, not the language).
    pub(crate) fn language_route(self) -> Route {
        match self {
            Screen::Landing
            | Screen::Leave
            | Screen::NotFound
            | Screen::ServerError
            | Screen::Maintenance
            | Screen::SignedOut
            | Screen::MethodNotAllowed
            | Screen::Discarded
            | Screen::Closed => Route::Landing,
            Screen::Safety => Route::Safety,
            Screen::SafetyTips => Route::SafetyTips,
            Screen::Status => Route::Status,
            Screen::NewReport | Screen::NoReader => Route::New,
            Screen::Concerns => Route::Concerns,
            Screen::Questionnaire | Screen::ModeChanged => Route::Questionnaire,
            Screen::Identity | Screen::IdentityConfirm => Route::Identity,
            Screen::Files => Route::Files,
            Screen::MetadataWarning => Route::FilesCheck,
            Screen::Review | Screen::Credential | Screen::Confirm | Screen::Busy => Route::Review,
            Screen::Sent | Screen::Login => Route::Login,
            Screen::Inbox
            | Screen::RotateCredential
            | Screen::RotateConfirm
            | Screen::RotateDone => Route::Inbox,
            Screen::RotateExplain => Route::Rotate,
            Screen::Conversation | Screen::DeleteRequested => Route::Conversation,
            Screen::Discard | Screen::CloseMailbox | Screen::AskDelete => Route::End,
        }
    }

    /// Progress step (11 §5.8), if any.
    pub(crate) fn progress_step(self, vm: &ViewModel) -> Option<u8> {
        match self {
            Screen::NewReport => Some(1),
            Screen::Concerns => Some(2),
            Screen::Questionnaire => Some(vm.questionnaire.step.clamp(3, 6)),
            Screen::Files | Screen::MetadataWarning => Some(7),
            Screen::Review => Some(8),
            _ => None,
        }
    }

    /// Catalog key of the step name used in `<title>`.
    pub(crate) fn title_key(self, vm: &ViewModel) -> String {
        if let Some(n) = self.progress_step(vm) {
            return format!("sui-step-{n}");
        }
        match self {
            Screen::Landing => "sui-landing-step",
            Screen::Safety => "sui-safety-step",
            Screen::SafetyTips => "tip-page-step",
            Screen::Status => "sui-status-step",
            Screen::NoReader => "sui-step-2",
            Screen::Identity | Screen::IdentityConfirm | Screen::ModeChanged => "sui-id-step",
            Screen::Credential | Screen::RotateCredential => "sui-cred-step",
            Screen::Confirm | Screen::RotateConfirm => "sui-confirm-step",
            Screen::Sent => "sui-sent-step",
            Screen::Login => "sui-login-step",
            Screen::Inbox => "sui-inbox-step",
            Screen::RotateExplain | Screen::RotateDone => "sui-rot-step",
            Screen::Conversation => "sui-conv-step",
            Screen::Discard | Screen::Discarded => "sui-end-step",
            Screen::CloseMailbox | Screen::Closed => "sui-close-step",
            Screen::AskDelete | Screen::DeleteRequested => "sui-askdel-step",
            Screen::Leave => "sui-leave-step",
            Screen::Busy => "sui-busy-step",
            Screen::NotFound => "sui-notfound-step",
            Screen::ServerError => "sui-error-step",
            Screen::Maintenance => "sui-maint-step",
            Screen::SignedOut => "sui-signedout-step",
            Screen::MethodNotAllowed => "sui-method-step",
            // Progress screens are handled above.
            Screen::NewReport
            | Screen::Concerns
            | Screen::Questionnaire
            | Screen::Files
            | Screen::MetadataWarning
            | Screen::Review => "sui-landing-step",
        }
        .to_owned()
    }

    /// Whether the screen shows the CSS-only JavaScript warning (SUI-051).
    pub fn shows_js_warning(self) -> bool {
        matches!(
            self,
            Screen::Landing
                | Screen::Status
                | Screen::Login
                | Screen::Credential
                | Screen::RotateCredential
        )
    }
}

macro_rules! templates {
    ($($name:ident => $path:literal),* $(,)?) => {
        $(
            #[derive(Template)]
            #[template(path = $path)]
            pub(crate) struct $name<'a> {
                pub(crate) p: &'a PageView<'a>,
            }
        )*
    };
}

templates! {
    LandingTpl => "s01_landing.html",
    SafetyTpl => "s02_safety.html",
    SafetyTipsTpl => "s02b_tips.html",
    StatusTpl => "s03_status.html",
    NewReportTpl => "s04_new.html",
    ConcernsTpl => "s04b_concerns.html",
    NoReaderTpl => "s04b_x_no_reader.html",
    QuestionnaireTpl => "s05_questionnaire.html",
    IdentityTpl => "s05b_identity.html",
    IdentityConfirmTpl => "s05b_confirm.html",
    ModeChangedTpl => "s05b_mode_changed.html",
    FilesTpl => "s06_files.html",
    MetadataTpl => "s07_metadata.html",
    ReviewTpl => "s08_review.html",
    CredentialTpl => "s10_credential.html",
    ConfirmTpl => "s10c_confirm.html",
    SentTpl => "s10s_sent.html",
    LoginTpl => "s11_login.html",
    InboxTpl => "s11_inbox.html",
    RotateExplainTpl => "s11r_explain.html",
    RotateDoneTpl => "s11r_done.html",
    ConversationTpl => "s12_conversation.html",
    DiscardTpl => "s13_discard.html",
    DiscardedTpl => "s13_discarded.html",
    CloseTpl => "s13_close.html",
    ClosedTpl => "s13_closed.html",
    AskDeleteTpl => "s13_ask_delete.html",
    DeleteRequestedTpl => "s13_delete_requested.html",
    LeaveTpl => "leave.html",
    BusyTpl => "s90_busy.html",
    NotFoundTpl => "s91_not_found.html",
    ServerErrorTpl => "s92_error.html",
    MaintenanceTpl => "s93_maintenance.html",
    SignedOutTpl => "s94_signed_out.html",
    MethodTpl => "s405_method.html",
}

/// Renders the screen's template (unpadded HTML) into `w`.
pub(crate) fn render_template(
    p: &PageView<'_>,
    w: &mut dyn core::fmt::Write,
) -> Result<(), askama::Error> {
    match p.screen {
        Screen::Landing => LandingTpl { p }.render_into(w),
        Screen::Safety => SafetyTpl { p }.render_into(w),
        Screen::SafetyTips => SafetyTipsTpl { p }.render_into(w),
        Screen::Status => StatusTpl { p }.render_into(w),
        Screen::NewReport => NewReportTpl { p }.render_into(w),
        Screen::Concerns => ConcernsTpl { p }.render_into(w),
        Screen::NoReader => NoReaderTpl { p }.render_into(w),
        Screen::Questionnaire => QuestionnaireTpl { p }.render_into(w),
        Screen::Identity => IdentityTpl { p }.render_into(w),
        Screen::IdentityConfirm => IdentityConfirmTpl { p }.render_into(w),
        Screen::ModeChanged => ModeChangedTpl { p }.render_into(w),
        Screen::Files => FilesTpl { p }.render_into(w),
        Screen::MetadataWarning => MetadataTpl { p }.render_into(w),
        Screen::Review => ReviewTpl { p }.render_into(w),
        Screen::Credential | Screen::RotateCredential => CredentialTpl { p }.render_into(w),
        Screen::Confirm | Screen::RotateConfirm => ConfirmTpl { p }.render_into(w),
        Screen::Sent => SentTpl { p }.render_into(w),
        Screen::Login => LoginTpl { p }.render_into(w),
        Screen::Inbox => InboxTpl { p }.render_into(w),
        Screen::RotateExplain => RotateExplainTpl { p }.render_into(w),
        Screen::RotateDone => RotateDoneTpl { p }.render_into(w),
        Screen::Conversation => ConversationTpl { p }.render_into(w),
        Screen::Discard => DiscardTpl { p }.render_into(w),
        Screen::Discarded => DiscardedTpl { p }.render_into(w),
        Screen::CloseMailbox => CloseTpl { p }.render_into(w),
        Screen::Closed => ClosedTpl { p }.render_into(w),
        Screen::AskDelete => AskDeleteTpl { p }.render_into(w),
        Screen::DeleteRequested => DeleteRequestedTpl { p }.render_into(w),
        Screen::Leave => LeaveTpl { p }.render_into(w),
        Screen::Busy => BusyTpl { p }.render_into(w),
        Screen::NotFound => NotFoundTpl { p }.render_into(w),
        Screen::ServerError => ServerErrorTpl { p }.render_into(w),
        Screen::Maintenance => MaintenanceTpl { p }.render_into(w),
        Screen::SignedOut => SignedOutTpl { p }.render_into(w),
        Screen::MethodNotAllowed => MethodTpl { p }.render_into(w),
    }
}
