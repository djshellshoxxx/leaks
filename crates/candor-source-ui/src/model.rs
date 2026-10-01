// SPDX-License-Identifier: AGPL-3.0-or-later
//! View-model types: everything a Tier W page can show.
//!
//! The view model is filled by C-06/C-07 from the RAM session record and the
//! verified Key Directory snapshot. It never contains wall-clock times (only
//! UTC days, ADR-010) and never contains identifiers that would end up in URLs
//! (DP-13). All strings in it are treated as untrusted and HTML-escaped by the
//! templates (SUI-023).

use core::fmt;

use zeroize::Zeroizing;

/// The source's protection mode (11 §5.2, ADR-002, ADR-047(5)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Default on every onion page until identity is disclosed.
    #[default]
    Anonymous,
    /// Identity disclosed and locked for custodians (S05b).
    Confidential,
    /// CONFIDENTIAL, and the case team has read a message containing the identity (ANON-010).
    ConfidentialIdentitySeen,
    /// The source chose to have the name shown to the case team (ADR-047(5)).
    Identified,
    /// C-38 Confidential Clearnet Intake only. Rendered for completeness of the banner set;
    /// the onion templates never offer it as a choice (SUI-018).
    Clearnet,
}

impl PartialEq<Mode> for &Mode {
    fn eq(&self, other: &Mode) -> bool {
        **self == *other
    }
}

impl Mode {
    /// All modes, for tests and previews.
    pub const ALL: [Mode; 5] = [
        Mode::Anonymous,
        Mode::Confidential,
        Mode::ConfidentialIdentitySeen,
        Mode::Identified,
        Mode::Clearnet,
    ];

    /// Catalog key of the mode word that leads `<title>` (11 §5.2 rule 2).
    pub(crate) fn word_key(self) -> &'static str {
        match self {
            Mode::Anonymous => "sui-mode-word-anonymous",
            Mode::Confidential | Mode::ConfidentialIdentitySeen => "sui-mode-word-confidential",
            Mode::Identified => "sui-mode-word-identified",
            Mode::Clearnet => "sui-mode-word-clearnet",
        }
    }

    /// Catalog key of the banner sentence (`sui.mode.*`, tier0).
    pub(crate) fn banner_key(self) -> &'static str {
        match self {
            Mode::Anonymous => "sui-mode-anonymous",
            Mode::Confidential => "sui-mode-confidential",
            Mode::ConfidentialIdentitySeen => "sui-mode-confidential-seen",
            Mode::Identified => "sui-mode-identified",
            Mode::Clearnet => "sui-mode-clearnet",
        }
    }

    /// CSS class carrying the non-color cue (border style and pattern).
    pub(crate) fn css_class(self) -> &'static str {
        match self {
            Mode::Anonymous => "mode-anon",
            Mode::Confidential | Mode::ConfidentialIdentitySeen | Mode::Clearnet => "mode-conf",
            Mode::Identified => "mode-ident",
        }
    }

    /// Catalog key of the mode-labelled final send button (11 §5.2 rule 4, SUI-016).
    pub(crate) fn send_key(self) -> &'static str {
        match self {
            Mode::Anonymous => "sui-send-anonymous",
            Mode::Confidential | Mode::ConfidentialIdentitySeen | Mode::Clearnet => {
                "sui-send-confidential"
            }
            Mode::Identified => "sui-send-identified",
        }
    }

    /// Catalog key of the mode-labelled message send button (S12).
    pub(crate) fn message_send_key(self) -> &'static str {
        match self {
            Mode::Anonymous => "sui-conv-send-anonymous",
            Mode::Confidential | Mode::ConfidentialIdentitySeen | Mode::Clearnet => {
                "sui-conv-send-confidential"
            }
            Mode::Identified => "sui-conv-send-identified",
        }
    }

    /// True for every mode in which the source is not anonymous.
    pub fn is_disclosed(self) -> bool {
        !matches!(self, Mode::Anonymous)
    }
}

/// HTTP request method, as far as it determines the size class (11 §5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Method {
    /// GET.
    #[default]
    Get,
    /// HEAD (same headers and class as GET; the server omits the body).
    Head,
    /// POST.
    Post,
}

/// A UTC calendar day (ADR-010: day granularity; times are never shown).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Day {
    year: u16,
    month: u8,
    day: u8,
}

impl Day {
    /// 1970-01-01.
    pub const EPOCH: Day = Day {
        year: 1970,
        month: 1,
        day: 1,
    };

    /// Builds a day; returns `None` for impossible dates.
    pub fn new(year: u16, month: u8, day: u8) -> Option<Day> {
        let leap =
            (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400);
        let max = match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if leap => 29,
            2 => 28,
            _ => return None,
        };
        if day == 0 || day > max || !(1970..=9999).contains(&year) {
            return None;
        }
        Some(Day { year, month, day })
    }

    /// The year.
    pub fn year(self) -> u16 {
        self.year
    }
}

impl fmt::Display for Day {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

/// Session timers needed for the CSS-only timeout warnings (11 §5.6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionTimers {
    /// Seconds left until `T_ABS` (computed by C-06 from the monotonic deadline).
    pub abs_remaining_secs: u32,
}

/// Operator-statement state from the Key Directory snapshot (WB-1, ADR-035 §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OperatorStatement {
    /// A valid quorum-signed statement no older than 30 days + 3 days grace.
    Current {
        /// Day of the newest statement.
        issued: Day,
    },
    /// Older than the grace period.
    Stale {
        /// Day of the newest statement.
        last: Day,
    },
    /// No valid statement at all.
    #[default]
    Missing,
}

/// An INCIDENT_NOTICE newer than 90 days (WB-2 / WB-2c, ADR-035 §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncidentNotice {
    /// Day of the notice.
    pub date: Day,
    /// Notice text, rendered as plain text on S03.
    pub text: String,
    /// Set for a cosigned capture notice (E-MEM/E-NET, `31` IR-033): WB-2c replaces WB-2.
    pub capture: Option<CaptureNotice>,
}

/// Details for the WB-2c capture-performed banner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureNotice {
    /// Day of the capture.
    pub day: Day,
    /// Label of the Independent Approver role.
    pub approver_label: String,
}

/// A pending or recent (≤ 30 days) time-locked roster change (WB-3, ADR-036 §2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterChange {
    /// Channel name.
    pub channel: String,
    /// Effective day.
    pub effective: Day,
}

/// Inputs for the warning banners shown on every page (11 §5.2.1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Banners {
    /// WB-1 input.
    pub operator_statement: OperatorStatement,
    /// WB-2 / WB-2c input.
    pub incident: Option<IncidentNotice>,
    /// WB-3 inputs.
    pub roster_changes: Vec<RosterChange>,
}

/// One field error (11 §5.7). `field` is the question/control id.
#[derive(Clone, PartialEq, Eq)]
pub struct FieldError {
    /// Control id (validated `[a-z0-9_]{1,32}`).
    pub field: String,
    /// Message to show.
    pub message: Msg,
}

/// A catalog message with arguments.
#[derive(Clone, PartialEq, Eq)]
pub struct Msg {
    /// Catalog key.
    pub key: &'static str,
    /// Named arguments.
    pub args: Vec<(&'static str, Arg)>,
}

impl Msg {
    /// A message without arguments.
    pub fn new(key: &'static str) -> Msg {
        Msg {
            key,
            args: Vec::new(),
        }
    }

    /// Adds an argument.
    #[must_use]
    pub fn arg(mut self, name: &'static str, value: impl Into<Arg>) -> Msg {
        self.args.push((name, value.into()));
        self
    }
}

/// A message argument.
#[derive(Clone, PartialEq, Eq)]
pub enum Arg {
    /// Untrusted text (escaped on output).
    Text(String),
    /// A count (used by plural selectors).
    Num(u64),
}

impl From<&str> for Arg {
    fn from(v: &str) -> Arg {
        Arg::Text(v.to_owned())
    }
}
impl From<String> for Arg {
    fn from(v: String) -> Arg {
        Arg::Text(v)
    }
}
impl From<u64> for Arg {
    fn from(v: u64) -> Arg {
        Arg::Num(v)
    }
}
impl From<&String> for Arg {
    fn from(v: &String) -> Arg {
        Arg::Text(v.clone())
    }
}
impl From<&&str> for Arg {
    fn from(v: &&str) -> Arg {
        Arg::Text((*v).to_owned())
    }
}
impl From<&u64> for Arg {
    fn from(v: &u64) -> Arg {
        Arg::Num(*v)
    }
}
impl From<&u32> for Arg {
    fn from(v: &u32) -> Arg {
        Arg::Num(u64::from(*v))
    }
}
impl From<&&u32> for Arg {
    fn from(v: &&u32) -> Arg {
        Arg::Num(u64::from(**v))
    }
}
impl From<u32> for Arg {
    fn from(v: u32) -> Arg {
        Arg::Num(u64::from(v))
    }
}

/// Data common to every page.
#[derive(Clone, Default)]
pub struct PageContext {
    /// Request method (with `has_session_cookie`, the only size-class input, 11 §5.4).
    pub method: Method,
    /// Whether the request carried the `__Host-cs` session cookie.
    pub has_session_cookie: bool,
    /// Current mode for the banner.
    pub mode: Mode,
    /// Organisation label (deployment configuration).
    pub org: String,
    /// Single-use form token, rendered as the hidden `csrf` field in **every** form
    /// (ADR-051(4); 11 §5.7 calls it `ft`). Pre-session pages (S01, S02, S03, S11 login, Leave,
    /// error pages) carry a pre-session token that C-06 binds to a short-lived pre-session
    /// cookie (AUD-RM1-SUI-06). Rendering a page that contains a form fails closed with
    /// `RenderError::MissingData("form token")` when this is `None`.
    pub form_token: Option<String>,
    /// Per-session key binding `piece` fields of long values to the stored value
    /// (AUD-RM1-SUI-11). Required when a long draft or answer is split into pieces; the render
    /// fails closed with `RenderError::MissingData("piece key")` otherwise.
    pub piece_key: Option<crate::PieceKey>,
    /// Session timers, when the page is rendered inside a session.
    pub session: Option<SessionTimers>,
    /// Warning banner inputs.
    pub banners: Banners,
    /// Field errors; non-empty turns the page into an error page (§5.7).
    pub errors: Vec<FieldError>,
    /// Page-level error not tied to a field (e.g. "Your report was not sent").
    pub page_error: Option<Msg>,
    /// Whether posted text was kept in RAM after an error (§5.7 "Your text is kept").
    pub text_kept: bool,
    /// Locales offered in the language list (allow-list; empty = the production locales,
    /// [`crate::Locale::PRODUCTION`]; pseudo-locales are never offered by default).
    pub offered_locales: Vec<crate::Locale>,
    /// Part of a multi-part page to show (0-based, from the `part` button; clamped to the last
    /// part). Long source and team text is split into parts instead of being cut
    /// (AUD-RM1-SUI-01).
    pub part: u16,
}

/// Configuration-derived statements used by guidance cards and S01/S03 (05 GC-01).
#[derive(Debug, Clone, Default)]
pub struct DeploymentInfo {
    /// Onion address of this site (56 chars + `.onion`), shown in groups on S03.
    pub onion_address: String,
    /// Clearnet information site address, as plain text.
    pub info_site_address: String,
    /// The Candor project's distribution onion address, as plain text (ADR-041).
    pub project_onion_address: String,
    /// Identity custodian label (S04, S05b, banner).
    pub custodian_label: String,
    /// HIGH profile (week granularity, rotation offer at every login).
    pub high_profile: bool,
    /// Recovery quorum, if enabled (ADR-013, ADR-044 §3).
    pub recovery: Option<RecoveryQuorum>,
    /// Small-organisation mode (ADR-045): external oversight label.
    pub reduced_sod_oversight: Option<String>,
    /// OVERSIGHT silent member label, if configured.
    pub oversight_label: Option<String>,
    /// Break-glass approver roles, if configured.
    pub break_glass_roles: Option<String>,
    /// Plain-text alternative for people who cannot use Tor (C-38 or hotline).
    pub alternative_label: Option<String>,
    /// Jurisdiction rights text (legal class; customer content).
    pub jurisdiction_rights_text: Option<String>,
    /// Jurisdiction retaliation text (legal class; customer content).
    pub jurisdiction_retaliation_text: Option<String>,
    /// External bodies named in the jurisdiction pack (plain text, no links).
    pub external_bodies: Vec<String>,
    /// Acknowledgement SLA in days (S10s, GC-33).
    pub ack_days: u32,
    /// Number of passphrase words for the default list (10 for EFF large).
    pub passphrase_words: u32,
    /// Intake backup retention in days; `None` = the intake keeps no backups (SUI-080).
    pub intake_backup_days: Option<u32>,
    /// Declared outage/failover window is active (`sui.login.failover`).
    pub failover_notice: bool,
}

/// An enabled recovery quorum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryQuorum {
    /// Holder role labels.
    pub holders: String,
    /// Threshold.
    pub k: u32,
}

/// Role labels of one channel (from the Key Directory snapshot; "as listed by this site").
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChannelRoles {
    /// Channel name.
    pub channel: String,
    /// Triage Set role labels (first readers, ADR-037).
    pub triage: Vec<String>,
    /// Other role labels the first readers may involve.
    pub others: Vec<String>,
}

/// S01 Landing data.
#[derive(Debug, Clone, Default)]
pub struct LandingData {
    /// Two-sentence channel purpose (customer content).
    pub purpose: String,
}

/// S03 Anonymity Status data.
#[derive(Debug, Clone, Default)]
pub struct StatusData {
    /// Per-channel role labels.
    pub channels: Vec<ChannelRoles>,
}

/// A channel option on S04.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChannelOption {
    /// Channel id (form value; validated `[A-Za-z0-9_-]{1,64}`).
    pub id: String,
    /// Channel name.
    pub name: String,
    /// Handling-body description.
    pub description: String,
    /// Languages, as display text.
    pub languages: String,
    /// Triage Set role labels.
    pub triage: Vec<String>,
    /// CONFIDENTIAL allowed.
    pub allows_confidential: bool,
    /// IDENTIFIED allowed (ADR-047(5)).
    pub allows_identified: bool,
    /// False when no Triage Set member holds a valid epoch key, or the snapshot is stale (fail closed).
    pub available: bool,
    /// Designated independent fallback channel (listed first on S04b-X).
    pub independent_route: bool,
}

/// S04 Create Report data.
#[derive(Clone, Default)]
pub struct NewReportData {
    /// Channel options (one option = implicit, not shown).
    pub channels: Vec<ChannelOption>,
    /// Selected channel id (re-render).
    pub selected_channel: Option<String>,
    /// Selected mode (default ANONYMOUS, ADP-01).
    pub selected_mode: Mode,
    /// Snapshot older than 7 days: all channels unavailable (SUI-084).
    pub snapshot_stale: bool,
}

/// S04b data.
#[derive(Clone, Default)]
pub struct ConcernsData {
    /// Triage Set role labels of the chosen channel.
    pub triage: Vec<String>,
    /// Role labels offered as checkboxes; value = index (u16, `coi_label`).
    pub roles: Vec<String>,
    /// Indices currently ticked (re-render). Default: none (ADR-030).
    pub ticked: Vec<u16>,
    /// The role list could not be loaded: fail closed, no form (S04b errors).
    pub load_failed: bool,
}

/// S04b-X data.
#[derive(Debug, Clone, Default)]
pub struct NoReaderData {
    /// Independent channels with ≥ 1 eligible Triage Set member (fallback first).
    pub alternatives: Vec<ChannelOption>,
}

/// A question type permitted in the builder (S05; SUI-020).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuestionKind {
    /// Short text (≤ 500 chars).
    ShortText,
    /// Long text (≤ 60,000 chars).
    LongText,
    /// Single choice (radio group).
    SingleChoice(Vec<ChoiceOption>),
    /// Multiple choice (checkbox group).
    MultiChoice(Vec<ChoiceOption>),
    /// Month + year selects with "still happening" and "not sure".
    MonthYear {
        /// Years offered (newest first; C-06 supplies them so no future year is offered).
        years: Vec<u16>,
    },
    /// Yes / No / Not sure.
    YesNoNotSure,
}

/// Display text that is either a catalog message or customer content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Text {
    /// Catalog message key.
    Key(&'static str),
    /// Customer-authored, already-localized text (rendered with `dir="auto"`).
    Custom(String),
}

/// A choice option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChoiceOption {
    /// Form value (allow-listed `[a-z0-9_-]{1,32}`).
    pub value: String,
    /// Label.
    pub label: Text,
}

/// A question and its current value.
#[derive(Clone, PartialEq, Eq)]
pub struct Question {
    /// Field id (`[a-z0-9_]{1,32}`), used as form name and element id.
    pub id: String,
    /// Label (the question).
    pub label: Text,
    /// Optional hint.
    pub hint: Option<Text>,
    /// Kind.
    pub kind: QuestionKind,
    /// Required.
    pub required: bool,
    /// Current value(s): text, selected choice values, or `[month, year, flags...]`.
    pub value: Vec<String>,
}

/// S05 Questionnaire data.
#[derive(Clone, Default)]
pub struct QuestionnaireData {
    /// Step number (3..=6 for the default template; carried in the form body).
    pub step: u8,
    /// Questions on this step (≤ 7, DP-2).
    pub questions: Vec<Question>,
}

/// S05b data.
#[derive(Clone, Default)]
pub struct IdentityData {
    /// The mode being chosen (CONFIDENTIAL or IDENTIFIED).
    pub target: Mode,
    /// Current name value (re-render).
    pub full_name: String,
    /// Current role value.
    pub role: String,
    /// "Also by another way" was chosen: show the extra field.
    pub contact_other: bool,
    /// Current other-contact value.
    pub contact_other_value: String,
}

/// An attached file (S06/S07/S08).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct AttachedFile {
    /// Neutral (or opted-in original) display name.
    pub name: String,
    /// Size in bytes (shown rounded to MB).
    pub size_bytes: u64,
    /// Optional description.
    pub description: String,
}

/// S06 data.
#[derive(Clone, Default)]
pub struct FilesData {
    /// Files attached in this session.
    pub files: Vec<AttachedFile>,
    /// Maximum number of files.
    pub max_files: u32,
    /// Per-file cap in bytes.
    pub max_file_bytes: u64,
    /// Total cap in bytes.
    pub max_total_bytes: u64,
    /// Filename replacement checkbox state (default ON, ADP-12).
    pub neutral_names: bool,
}

/// An answer row on S08.
#[derive(Clone, PartialEq, Eq)]
pub struct ReviewAnswer {
    /// The question.
    pub question: Text,
    /// Step to edit.
    pub step: u8,
    /// The answer as plain text (escaped; `white-space: pre-wrap`).
    pub answer: String,
}

/// The kind of an identity hint (05 §8.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HintKind {
    /// Email address.
    Email,
    /// Phone number.
    Phone,
    /// URL with user-like path.
    Url,
    /// `@handle`.
    Handle,
    /// Channel-configured pattern (e.g. employee ID).
    Pattern,
    /// First-person identity phrase.
    Phrase,
    /// Sign-off line.
    SignOff,
}

impl HintKind {
    pub(crate) fn key(self) -> &'static str {
        match self {
            HintKind::Email => "sui-hint-email",
            HintKind::Phone => "sui-hint-phone",
            HintKind::Url => "sui-hint-url",
            HintKind::Handle => "sui-hint-handle",
            HintKind::Pattern => "sui-hint-pattern",
            HintKind::Phrase => "sui-hint-phrase",
            HintKind::SignOff => "sui-hint-signoff",
        }
    }
}

/// An identity hint (non-blocking).
#[derive(Clone, PartialEq, Eq)]
pub struct IdentityHint {
    /// Kind.
    pub kind: HintKind,
    /// The question it was found in.
    pub field: Text,
    /// Step of that question.
    pub step: u8,
    /// 1-based line.
    pub line: u32,
}

/// S08 data.
#[derive(Clone, Default)]
pub struct ReviewData {
    /// Channel name.
    pub channel: String,
    /// Eligible Triage Set after ticks and COI map.
    pub first_readers: Vec<String>,
    /// Others the first readers may ask.
    pub others: Vec<String>,
    /// Roles the source ticked.
    pub kept_out: Vec<String>,
    /// Number of roles kept out automatically by the COI map.
    pub kept_out_auto: u32,
    /// Answers.
    pub answers: Vec<ReviewAnswer>,
    /// Files.
    pub files: Vec<AttachedFile>,
    /// Identity hints.
    pub hints: Vec<IdentityHint>,
    /// Number of invisible/look-alike characters (05 §8.5a).
    pub invisible_chars: u32,
    /// Delivery-timing choice: random delay selected.
    pub delayed_delivery: bool,
    /// The draft holds an identity block (show "Remove my name").
    pub has_identity: bool,
}

/// A generated passphrase shown once (S10). Zeroized on drop; never printed by `Debug`.
#[derive(Clone, Default)]
pub struct Passphrase {
    /// The words.
    pub words: Vec<Zeroizing<String>>,
    /// BCP 47 language of the wordlist (`en` for the EFF list).
    pub wordlist_lang: String,
}

impl fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Passphrase")
            .field("words", &format_args!("[redacted; {}]", self.words.len()))
            .field("wordlist_lang", &self.wordlist_lang)
            .finish()
    }
}

/// S10 / S11r-new data.
#[derive(Debug, Clone, Default)]
pub struct CredentialData {
    /// The passphrase.
    pub passphrase: Passphrase,
}

/// S10c / S11r-confirm data.
#[derive(Debug, Clone, Default)]
pub struct ConfirmData {
    /// The three 1-based word positions chosen by C-07.
    pub positions: [u8; 3],
    /// 3 failed attempts: only "Get a new passphrase" and "Discard" remain.
    pub attempts_exhausted: bool,
}

/// S10s data.
#[derive(Clone)]
pub struct SentData {
    /// Day sent (UTC).
    pub sent: Day,
    /// Delayed delivery chosen.
    pub delayed: bool,
}

/// Source-visible case status (14; coarse set).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CaseStatus {
    /// Received.
    #[default]
    Received,
    /// Acknowledged.
    Acknowledged,
    /// In progress.
    InProgress,
    /// Closed.
    Closed,
}

impl CaseStatus {
    pub(crate) fn key(self) -> &'static str {
        match self {
            CaseStatus::Received => "sui-case-received",
            CaseStatus::Acknowledged => "sui-case-acknowledged",
            CaseStatus::InProgress => "sui-case-in-progress",
            CaseStatus::Closed => "sui-case-closed",
        }
    }
}

/// A message from the team.
#[derive(Clone, PartialEq, Eq)]
pub struct InboxMessage {
    /// Sender label (team or display name).
    pub sender: String,
    /// Day (UTC).
    pub date: Day,
    /// Plain text.
    pub text: String,
}

/// S11 login data.
#[derive(Debug, Clone, Default)]
pub struct LoginData {
    /// Show `n` separate boxes (`layout=ten`).
    pub ten_boxes: bool,
    /// The source was signed out and an unsent message is kept (§5.6).
    pub restored_draft: bool,
}

/// S11 inbox / S12 data.
#[derive(Clone, Default)]
pub struct InboxData {
    /// Coarse status.
    pub status: CaseStatus,
    /// Messages, newest first (C-06 orders them; the template keeps order).
    pub messages: Vec<InboxMessage>,
    /// Show the HIGH-profile rotation offer (at login only).
    pub rotation_offer: bool,
}

/// S12 data.
#[derive(Clone, Default)]
pub struct ConversationData {
    /// Thread page (newest first).
    pub messages: Vec<InboxMessage>,
    /// Unsent text (restored after re-authentication or error).
    pub draft_text: String,
    /// Delayed delivery selected.
    pub delayed_delivery: bool,
    /// "Your message was sent" notice.
    pub just_sent: bool,
    /// Follow-up fail-closed: label of the independent route channel.
    pub refused_route: Option<String>,
    /// A page of older messages exists.
    pub has_older: bool,
    /// A page of newer messages exists.
    pub has_newer: bool,
    /// Current page index (form value for pagination).
    pub page: u16,
}

/// S90 data.
#[derive(Debug, Clone, Default)]
pub struct BusyData {
    /// Same action to re-POST (allow-listed route).
    pub retry: Option<crate::Route>,
    /// Busy at the final send (S10c): add the "not sent yet" sentence.
    pub at_submit: bool,
}

/// All per-screen data. Each screen reads only its own part; the rest stays default.
#[derive(Clone, Default)]
pub struct ViewModel {
    /// Common page data.
    pub ctx: PageContext,
    /// Deployment statements.
    pub deployment: DeploymentInfo,
    /// S01.
    pub landing: LandingData,
    /// S03.
    pub status: StatusData,
    /// S04.
    pub new_report: NewReportData,
    /// S04b.
    pub concerns: ConcernsData,
    /// S04b-X.
    pub no_reader: NoReaderData,
    /// S05.
    pub questionnaire: QuestionnaireData,
    /// S05b.
    pub identity: IdentityData,
    /// S06 / S07.
    pub files: FilesData,
    /// S08.
    pub review: ReviewData,
    /// S10 / S11r.
    pub credential: CredentialData,
    /// S10c / S11r.
    pub confirm: ConfirmData,
    /// S10s.
    pub sent: Option<SentData>,
    /// S11 login.
    pub login: LoginData,
    /// S11 inbox.
    pub inbox: InboxData,
    /// S12.
    pub conversation: ConversationData,
    /// S90.
    pub busy: BusyData,
}

/// The default questionnaire template (11 §7 S05) for `step` 3..=6.
///
/// `categories` are the channel's categories (an "Other" option is appended); `years` are the
/// selectable years, newest first, supplied by C-06 so that no future year is offered.
pub fn default_questionnaire_step(
    step: u8,
    categories: &[ChoiceOption],
    years: &[u16],
) -> Vec<Question> {
    let opt = |value: &str, key: &'static str| ChoiceOption {
        value: value.to_owned(),
        label: Text::Key(key),
    };
    let q = |id: &str, label: &'static str, hint: Option<&'static str>, kind, required| Question {
        id: id.to_owned(),
        label: Text::Key(label),
        hint: hint.map(Text::Key),
        kind,
        required,
        value: Vec::new(),
    };
    match step {
        3 => {
            let mut cats = categories.to_vec();
            cats.push(opt("other", "sui-q-category-other"));
            vec![q(
                "category",
                "sui-q-category",
                None,
                QuestionKind::SingleChoice(cats),
                true,
            )]
        }
        4 => vec![
            q(
                "what",
                "sui-q-what",
                Some("sui-q-what-hint"),
                QuestionKind::LongText,
                true,
            ),
            q(
                "when",
                "sui-q-when",
                None,
                QuestionKind::MonthYear {
                    years: years.to_vec(),
                },
                false,
            ),
            q(
                "where",
                "sui-q-where",
                Some("sui-q-where-hint"),
                QuestionKind::ShortText,
                false,
            ),
        ],
        5 => vec![
            q(
                "who",
                "sui-q-who",
                Some("sui-q-who-hint"),
                QuestionKind::LongText,
                false,
            ),
            q(
                "how_know",
                "sui-q-how",
                None,
                QuestionKind::MultiChoice(vec![
                    opt("saw", "sui-q-how-saw"),
                    opt("told", "sui-q-how-told"),
                    opt("documents", "sui-q-how-documents"),
                    opt("other", "sui-q-how-other"),
                ]),
                false,
            ),
        ],
        6 => vec![
            q(
                "people_know",
                "sui-q-people",
                Some("sui-q-people-hint"),
                QuestionKind::SingleChoice(vec![
                    opt("1-5", "sui-q-people-few"),
                    opt("6-20", "sui-q-people-some"),
                    opt("more-20", "sui-q-people-many"),
                    opt("unsure", "sui-q-people-unsure"),
                ]),
                false,
            ),
            q(
                "reported_before",
                "sui-q-before",
                None,
                QuestionKind::YesNoNotSure,
                false,
            ),
            q(
                "anything_else",
                "sui-q-else",
                None,
                QuestionKind::LongText,
                false,
            ),
        ],
        _ => Vec::new(),
    }
}

/// Debug output for types that can hold source text, identity data, file names, team messages,
/// the form token or the source's choices: the type name only (AUD-RM1-SUI-02, SG-21). These
/// types must never derive `Debug`; `tests/debug_redaction.rs` enforces this.
macro_rules! redacted_debug {
    ($($t:ident),* $(,)?) => {
        $(
            impl fmt::Debug for $t {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str(concat!(stringify!($t), " { [redacted] }"))
                }
            }
        )*
    };
}

redacted_debug!(
    Arg,
    PageContext,
    NewReportData,
    ConcernsData,
    Question,
    QuestionnaireData,
    IdentityData,
    AttachedFile,
    FilesData,
    ReviewAnswer,
    IdentityHint,
    ReviewData,
    SentData,
    InboxMessage,
    InboxData,
    ConversationData,
    ViewModel,
);

impl fmt::Debug for Msg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The catalog key is a constant; argument values may be untrusted.
        f.debug_struct("Msg")
            .field("key", &self.key)
            .field("args", &format_args!("[{} redacted]", self.args.len()))
            .finish()
    }
}

impl fmt::Debug for FieldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FieldError")
            .field("field", &self.field)
            .field("message", &self.message)
            .finish()
    }
}
