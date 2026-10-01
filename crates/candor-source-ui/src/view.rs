// SPDX-License-Identifier: AGPL-3.0-or-later
//! `PageView`: the object every template receives. It formats catalog messages for the page
//! locale, records missing keys (rendering then fails closed), and builds allow-listed URLs.

use core::cell::RefCell;
use core::fmt;

use crate::guidance::{Block, Card, Group, JurisdictionText};
use crate::locale::{Catalog, Locale};
use crate::model::{
    Arg, AttachedFile, ChannelOption, FieldError, Mode, Msg, OperatorStatement, Question,
    QuestionKind, Text, ViewModel,
};
use crate::routes::Route;
use crate::screens::Screen;

/// HTML-escapes text for element content and attribute values.
pub(crate) fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// Private-use character standing in for `*` in untrusted placeables while bold markup is
/// applied. The catalog never contains it.
const SHIELD: &str = "\u{E000}";

/// Escapes, then turns `**x**` pairs into `<strong>x</strong>`. An unpaired marker stays text.
pub(crate) fn escape_marked(s: &str) -> String {
    let parts: Vec<&str> = s.split("**").collect();
    let pairs = parts.len().saturating_sub(1) / 2;
    let mut out = String::with_capacity(s.len().saturating_add(32));
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            let open = i % 2 == 1;
            let paired = (i.saturating_add(1)) / 2 <= pairs;
            match (paired, open) {
                (true, true) => out.push_str("<strong>"),
                (true, false) => out.push_str("</strong>"),
                (false, _) => out.push_str("**"),
            }
        }
        out.push_str(&escape(part));
    }
    out
}

/// Validates an element/field id (`[a-z0-9_]{1,32}`).
pub(crate) fn valid_id(id: &str) -> bool {
    (1..=32).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Validates a form value (`[A-Za-z0-9_-]{1,64}`).
pub(crate) fn valid_value(v: &str) -> bool {
    (1..=64).contains(&v.len())
        && v
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Formats a byte count for display (decimal units, rounded; 11 S06 "size shown in MB rounded").
pub(crate) fn size_parts(bytes: u64) -> (&'static str, u64) {
    const MB: u64 = 1_000_000;
    const GB: u64 = 1_000_000_000;
    if bytes >= GB && bytes % GB == 0 {
        ("sui-size-gb", bytes / GB)
    } else if bytes < MB / 2 {
        ("sui-size-small", 0)
    } else {
        ("sui-size-mb", bytes.saturating_add(MB / 2) / MB)
    }
}

/// Accepts a route by value or by reference (askama binds loop/`if let` values by reference).
pub(crate) trait AsRoute {
    fn route(&self) -> Route;
}
impl AsRoute for Route {
    fn route(&self) -> Route {
        *self
    }
}
impl AsRoute for &Route {
    fn route(&self) -> Route {
        **self
    }
}
impl AsRoute for &&Route {
    fn route(&self) -> Route {
        ***self
    }
}

pub(crate) struct PageView<'a> {
    pub(crate) locale: Locale,
    pub(crate) vm: &'a ViewModel,
    pub(crate) screen: Screen,
    pub(crate) css: &'static str,
    pub(crate) title: String,
    cat: &'static Catalog,
    missing: RefCell<Vec<String>>,
}

impl fmt::Debug for PageView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PageView")
            .field("locale", &self.locale)
            .field("screen", &self.screen)
            .finish_non_exhaustive()
    }
}

impl<'a> PageView<'a> {
    pub(crate) fn new(
        locale: Locale,
        vm: &'a ViewModel,
        screen: Screen,
        cat: &'static Catalog,
        css: &'static str,
    ) -> PageView<'a> {
        PageView {
            locale,
            vm,
            screen,
            css,
            title: String::new(),
            cat,
            missing: RefCell::new(Vec::new()),
        }
    }

    pub(crate) fn take_missing(&self) -> Vec<String> {
        self.missing.take()
    }

    fn fmt_args(&self, key: &str, args: &[(&str, Arg)]) -> String {
        self.fmt_in(self.locale, key, args)
    }

    fn fmt_in(&self, locale: Locale, key: &str, args: &[(&str, Arg)]) -> String {
        match self.cat.format(locale, key, args) {
            Some(s) => s,
            None => {
                self.missing.borrow_mut().push(key.to_owned());
                String::new()
            }
        }
    }

    // ---- message helpers used by templates -------------------------------------------

    /// Plain message (escaped by the template).
    pub(crate) fn t(&self, key: &str) -> String {
        self.fmt_args(key, &[])
    }

    pub(crate) fn t1(&self, key: &str, n1: &str, v1: impl Into<Arg>) -> String {
        self.fmt_args(key, &[(n1, v1.into())])
    }

    pub(crate) fn t2(
        &self,
        key: &str,
        n1: &str,
        v1: impl Into<Arg>,
        n2: &str,
        v2: impl Into<Arg>,
    ) -> String {
        self.fmt_args(key, &[(n1, v1.into()), (n2, v2.into())])
    }

    pub(crate) fn t3(
        &self,
        key: &str,
        n1: &str,
        v1: impl Into<Arg>,
        n2: &str,
        v2: impl Into<Arg>,
        n3: &str,
        v3: impl Into<Arg>,
    ) -> String {
        self.fmt_args(key, &[(n1, v1.into()), (n2, v2.into()), (n3, v3.into())])
    }

    /// `<title>`: "{Mode} · {Step} · {Org} secure reporting" (11 §5.1).
    pub(crate) fn fmt_title(&self, mode: &str, step: &str) -> String {
        self.t3("sui-title", "mode", mode, "step", step, "org", self.org())
    }

    /// One identity-hint notice (05 §8.5).
    pub(crate) fn fmt_hint(&self, h: &crate::model::IdentityHint) -> String {
        let kind = self.t(h.kind.key());
        let field = self.text_plain(&h.field);
        self.t3("sui-review-hint", "kind", kind, "field", field, "line", h.line)
    }

    /// The three S10c fields with their 1-based word positions.
    pub(crate) fn confirm_fields(&self) -> Vec<(&'static str, u64)> {
        let [a, b, c] = self.vm.confirm.positions;
        vec![
            ("w_a", u64::from(a)),
            ("w_b", u64::from(b)),
            ("w_c", u64::from(c)),
        ]
    }

    /// Marked message: returns escaped HTML with `<strong>`; templates use `|safe`.
    pub(crate) fn tm(&self, key: &str) -> String {
        escape_marked(&self.t(key))
    }

    pub(crate) fn tm1(&self, key: &str, n1: &str, v1: impl Into<Arg>) -> String {
        self.marked(key, &[(n1, v1.into())])
    }

    /// Formats a marked message whose arguments may be untrusted: `*` in argument text is
    /// shielded so that only catalog text can produce `<strong>`.
    pub(crate) fn marked(&self, key: &str, args: &[(&str, Arg)]) -> String {
        let shielded: Vec<(&str, Arg)> = args
            .iter()
            .map(|(n, v)| {
                let v = match v {
                    Arg::Text(t) => Arg::Text(t.replace('*', SHIELD)),
                    Arg::Num(n) => Arg::Num(*n),
                };
                (*n, v)
            })
            .collect();
        escape_marked(&self.fmt_args(key, &shielded)).replace(SHIELD, "*")
    }

    /// A `Msg` from the view model.
    pub(crate) fn msg(&self, m: &Msg) -> String {
        let args: Vec<(&str, Arg)> = m.args.iter().map(|(n, v)| (*n, v.clone())).collect();
        self.fmt_args(m.key, &args)
    }

    /// Text that is either a catalog key or customer content. Returns escaped HTML;
    /// customer content is isolated in `<bdi>` (DP-7).
    pub(crate) fn text_html(&self, t: &Text) -> String {
        match t {
            Text::Key(k) => escape(&self.t(k)),
            Text::Custom(s) => format!("<bdi>{}</bdi>", escape(s)),
        }
    }

    /// Plain text version of `Text` (for argument use; escaped later).
    pub(crate) fn text_plain(&self, t: &Text) -> String {
        match t {
            Text::Key(k) => self.t(k),
            Text::Custom(s) => s.clone(),
        }
    }

    /// Joins a list of labels with the localized separator.
    pub(crate) fn join(&self, items: &[String]) -> String {
        let sep = self.t("sui-list-sep");
        items.join(&sep)
    }

    pub(crate) fn org(&self) -> &str {
        &self.vm.ctx.org
    }

    pub(crate) fn custodian(&self) -> &str {
        &self.vm.deployment.custodian_label
    }

    pub(crate) fn words(&self) -> u64 {
        u64::from(self.vm.deployment.passphrase_words)
    }

    pub(crate) fn profile(&self) -> &'static str {
        if self.vm.deployment.high_profile {
            "high"
        } else {
            "standard"
        }
    }

    // ---- URLs -------------------------------------------------------------------------

    /// `/{lang}{path}` for an allow-listed route.
    pub(crate) fn href(&self, r: impl AsRoute) -> String {
        format!("/{}{}", self.locale.tag(), r.route().path())
    }

    pub(crate) fn any_unavailable(&self) -> bool {
        self.vm.new_report.channels.iter().any(|c| !c.available)
    }

    pub(crate) fn allow_conf(&self) -> bool {
        self.vm.new_report.channels.iter().any(|c| c.allows_confidential)
    }

    pub(crate) fn allow_ident(&self) -> bool {
        self.vm.new_report.channels.iter().any(|c| c.allows_identified)
    }

    pub(crate) fn lang(&self) -> &'static str {
        self.locale.tag()
    }

    pub(crate) fn dir(&self) -> &'static str {
        self.locale.dir().as_str()
    }

    /// Language list: (tag, own-language name, href, is_current).
    pub(crate) fn languages(&self) -> Vec<(&'static str, String, String, bool)> {
        let offered: Vec<Locale> = if self.vm.ctx.offered_locales.is_empty() {
            Locale::ALL.to_vec()
        } else {
            self.vm.ctx.offered_locales.clone()
        };
        let route = self.screen.language_route();
        offered
            .into_iter()
            .map(|l| {
                (
                    l.tag(),
                    self.fmt_in(l, "sui-lang-name", &[]),
                    format!("/{}{}", l.tag(), route.path()),
                    l == self.locale,
                )
            })
            .collect()
    }

    // ---- layout data --------------------------------------------------------------------

    pub(crate) fn mode(&self) -> Mode {
        self.vm.ctx.mode
    }

    pub(crate) fn banner_html(&self) -> String {
        let m = self.mode();
        match m {
            Mode::Confidential => self.marked(
                m.banner_key(),
                &[("custodian", Arg::Text(self.custodian().to_owned()))],
            ),
            Mode::Clearnet => self.marked(
                m.banner_key(),
                &[(
                    "onion",
                    Arg::Text(self.vm.deployment.onion_address.clone()),
                )],
            ),
            _ => self.marked(m.banner_key(), &[]),
        }
    }

    pub(crate) fn minimal(&self) -> bool {
        self.screen.minimal_chrome()
    }

    pub(crate) fn wb_operator(&self) -> Option<String> {
        match self.vm.ctx.banners.operator_statement {
            OperatorStatement::Current { .. } => None,
            OperatorStatement::Stale { last } => {
                Some(self.t1("sui-wb-operator", "last", last.to_string()))
            }
            OperatorStatement::Missing => {
                let none = self.t("sui-wb-operator-none");
                Some(self.t1("sui-wb-operator", "last", none))
            }
        }
    }

    pub(crate) fn wb_incident(&self) -> Option<String> {
        let inc = self.vm.ctx.banners.incident.as_ref()?;
        Some(match &inc.capture {
            Some(c) => self.t2(
                "sui-wb-capture",
                "day",
                c.day.to_string(),
                "approver",
                c.approver_label.as_str(),
            ),
            None => self.t1("sui-wb-incident", "date", inc.date.to_string()),
        })
    }

    pub(crate) fn wb_incident_is_capture(&self) -> bool {
        self.vm
            .ctx
            .banners
            .incident
            .as_ref()
            .is_some_and(|i| i.capture.is_some())
    }

    pub(crate) fn wb_roster(&self) -> Vec<String> {
        self.vm
            .ctx
            .banners
            .roster_changes
            .iter()
            .map(|r| {
                self.t2(
                    "sui-wb-roster",
                    "channel",
                    r.channel.as_str(),
                    "date",
                    r.effective.to_string(),
                )
            })
            .collect()
    }

    pub(crate) fn has_warnings(&self) -> bool {
        let b = &self.vm.ctx.banners;
        !matches!(b.operator_statement, OperatorStatement::Current { .. })
            || b.incident.is_some()
            || !b.roster_changes.is_empty()
    }

    /// Progress step (1..=8) for this page, if it is part of the report steps.
    pub(crate) fn step(&self) -> Option<u8> {
        self.screen.progress_step(self.vm)
    }

    /// Steps for the progress nav: (n, name, route, state) with state 0 done, 1 current, 2 upcoming.
    pub(crate) fn steps(&self) -> Vec<(u8, String, String, u8)> {
        let cur = self.step().unwrap_or(0);
        (1u8..=8)
            .map(|n| {
                let route = match n {
                    1 => Route::New,
                    2 => Route::Concerns,
                    3..=6 => Route::Questionnaire,
                    7 => Route::Files,
                    _ => Route::Review,
                };
                let state = match n.cmp(&cur) {
                    core::cmp::Ordering::Less => 0,
                    core::cmp::Ordering::Equal => 1,
                    core::cmp::Ordering::Greater => 2,
                };
                (n, self.t(&format!("sui-step-{n}")), self.href(route), state)
            })
            .collect()
    }

    pub(crate) fn step_label(&self) -> String {
        match self.step() {
            Some(n) => {
                let name = self.t(&format!("sui-step-{n}"));
                self.fmt_args(
                    "sui-step-label",
                    &[
                        ("n", Arg::Num(u64::from(n))),
                        ("total", Arg::Num(8)),
                        ("name", Arg::Text(name)),
                    ],
                )
            }
            None => String::new(),
        }
    }

    /// CSS class revealing the absolute-timeout warning at `T_ABS − 10 min` (11 §5.6.1),
    /// rounded down to 5-minute steps so it never appears late.
    pub(crate) fn abs_warn_class(&self) -> String {
        let secs = self.vm.ctx.session.map_or(0, |s| s.abs_remaining_secs);
        let mins = secs.saturating_sub(600) / 60;
        let bucket = (mins / 5).saturating_mul(5).min(110);
        format!("tw tw-a{bucket}")
    }

    pub(crate) fn in_session(&self) -> bool {
        self.vm.ctx.session.is_some()
    }

    pub(crate) fn form_token(&self) -> Option<&str> {
        self.vm.ctx.form_token.as_deref()
    }

    // ---- errors ----------------------------------------------------------------------

    pub(crate) fn errors(&self) -> &[FieldError] {
        &self.vm.ctx.errors
    }

    pub(crate) fn has_error_summary(&self) -> bool {
        !self.vm.ctx.errors.is_empty() || self.vm.ctx.page_error.is_some()
    }

    pub(crate) fn field_error(&self, id: &str) -> Option<String> {
        self.vm
            .ctx
            .errors
            .iter()
            .find(|e| e.field == id)
            .map(|e| self.msg(&e.message))
    }

    pub(crate) fn has_field_error(&self, id: &str) -> bool {
        self.vm.ctx.errors.iter().any(|e| e.field == id)
    }

    /// `aria-describedby` value for a field: hint id (if any) then error id (if any).
    pub(crate) fn describedby(&self, id: &str, has_hint: bool) -> String {
        let mut v = Vec::new();
        if has_hint {
            v.push(format!("h-{id}"));
        }
        if self.has_field_error(id) {
            v.push(format!("e-{id}"));
        }
        v.join(" ")
    }

    // ---- questionnaire ---------------------------------------------------------------

    pub(crate) fn q_has_hint(&self, q: &Question) -> bool {
        q.hint.is_some()
            || matches!(q.kind, QuestionKind::LongText | QuestionKind::MonthYear { .. })
    }

    pub(crate) fn q_maxlen(&self, q: &Question) -> u64 {
        match q.kind {
            QuestionKind::LongText => 60_000,
            _ => 500,
        }
    }

    pub(crate) fn q_value(&self, q: &Question) -> String {
        q.value.first().cloned().unwrap_or_default()
    }

    pub(crate) fn q_selected(&self, q: &Question, value: &str) -> bool {
        q.value.iter().any(|v| v == value)
    }

    /// Month/year selected values and flags for a MonthYear question:
    /// value = [month, year, "ongoing"?, "unsure"?].
    pub(crate) fn q_month(&self, q: &Question) -> String {
        q.value.first().cloned().unwrap_or_default()
    }

    pub(crate) fn q_year(&self, q: &Question) -> String {
        q.value.get(1).cloned().unwrap_or_default()
    }

    pub(crate) fn months(&self) -> Vec<(String, String)> {
        (1u8..=12)
            .map(|m| (m.to_string(), self.t(&format!("sui-month-{m}"))))
            .collect()
    }

    pub(crate) fn yes_no(&self) -> Vec<(&'static str, String)> {
        vec![
            ("yes", self.t("sui-yn-yes")),
            ("no", self.t("sui-yn-no")),
            ("unsure", self.t("sui-yn-unsure")),
        ]
    }

    // ---- channels, files, cards -------------------------------------------------------

    pub(crate) fn channel_selected(
        &self,
        c: &ChannelOption,
        index: impl core::borrow::Borrow<usize>,
    ) -> bool {
        let index = *index.borrow();
        match &self.vm.new_report.selected_channel {
            Some(sel) => sel == &c.id,
            None => index == 0 && c.available,
        }
    }

    pub(crate) fn file_size(&self, f: &AttachedFile) -> String {
        self.size(f.size_bytes)
    }

    pub(crate) fn size(&self, bytes: impl core::borrow::Borrow<u64>) -> String {
        let (key, n) = size_parts(*bytes.borrow());
        self.t1(key, "n", n)
    }

    pub(crate) fn file_classes(&self, f: &AttachedFile) -> Vec<crate::files::FileClass> {
        crate::files::classify(&f.name)
    }

    pub(crate) fn file_class_names(&self, f: &AttachedFile) -> String {
        let names: Vec<String> = self
            .file_classes(f)
            .iter()
            .map(|c| self.t(c.name_key()))
            .collect();
        self.join(&names)
    }

    pub(crate) fn groups(&self) -> &'static [Group] {
        crate::guidance::GROUPS
    }

    pub(crate) fn card(&self, id: &str) -> Option<Card> {
        match id {
            "GC-01" => Some(crate::guidance::GC01),
            "GC-03" => Some(crate::guidance::GC03),
            "GC-30" => Some(crate::guidance::GC30),
            "GC-32" => Some(crate::guidance::GC32),
            "GC-35" => Some(crate::guidance::GC35),
            "GC-39" => Some(crate::guidance::GC39),
            _ => None,
        }
    }

    /// Renders one card block to HTML (escaped + bold markup).
    pub(crate) fn block_html(&self, b: &Block) -> String {
        match b {
            Block::P(k) => format!("<p>{}</p>", self.tm(k)),
            Block::List(items) => {
                let mut s = String::from("<ul>");
                for k in *items {
                    s.push_str("<li>");
                    s.push_str(&self.tm(k));
                    s.push_str("</li>");
                }
                s.push_str("</ul>");
                s
            }
            Block::Dynamic(k) => {
                let html = self.dynamic(k);
                if html.is_empty() {
                    String::new()
                } else {
                    format!("<p>{html}</p>")
                }
            }
            Block::Jurisdiction(which) => {
                let d = &self.vm.deployment;
                let t = match which {
                    JurisdictionText::Rights => d.jurisdiction_rights_text.as_deref(),
                    JurisdictionText::Retaliation => d.jurisdiction_retaliation_text.as_deref(),
                };
                match t {
                    Some(t) if !t.is_empty() => format!("<p dir=\"auto\">{}</p>", escape(t)),
                    _ => String::new(),
                }
            }
        }
    }

    /// Dynamic card paragraphs, filled from signed configuration (05 GC-01 placeholders).
    /// Returns escaped HTML.
    fn dynamic(&self, key: &str) -> String {
        let d = &self.vm.deployment;
        let text = |v: &str| Arg::Text(v.to_owned());
        match key {
            "sops-limits-n1" | "sops-timing-h1" => {
                self.marked(key, &[("profile", text(self.profile()))])
            }
            "sops-limits-n4" => {
                let Some(ch) = self.vm.status.channels.first() else {
                    return String::new();
                };
                let mut s = self.marked(
                    key,
                    &[
                        ("triage", Arg::Text(self.join(&ch.triage))),
                        ("others", Arg::Text(self.join(&ch.others))),
                    ],
                );
                for extra in self.config_statements() {
                    s.push(' ');
                    s.push_str(&escape(&extra));
                }
                s
            }
            "sops-passphrase-n1" => self.marked(key, &[("n", Arg::Num(self.words()))]),
            "sops-return-n1" => self.marked(key, &[("days", Arg::Num(u64::from(d.ack_days)))]),
            "sops-censorship-n2" => self.marked(key, &[("info", text(&d.info_site_address))]),
            "sops-tier-n2" => self.marked(
                key,
                &[
                    ("address", text(&d.project_onion_address)),
                    ("org", text(self.org())),
                ],
            ),
            _ => self.tm(key),
        }
    }

    /// `{oversight_statement} {break_glass_statement} {recovery_escrow_statement}
    /// {reduced_sod_statement}` (05 GC-01).
    pub(crate) fn config_statements(&self) -> Vec<String> {
        let d = &self.vm.deployment;
        let mut v = Vec::new();
        if let Some(l) = &d.oversight_label {
            v.push(self.t1("sops-limits-oversight", "label", l.as_str()));
        }
        if let Some(r) = &d.break_glass_roles {
            v.push(self.t1("sops-limits-breakglass", "roles", r.as_str()));
        }
        v.push(self.escrow_statement());
        if let Some(l) = &d.reduced_sod_oversight {
            v.push(self.t1("sops-limits-reduced-sod", "label", l.as_str()));
        }
        v
    }

    pub(crate) fn escrow_statement(&self) -> String {
        match &self.vm.deployment.recovery {
            Some(r) => self.t2(
                "sops-limits-escrow",
                "holders",
                r.holders.as_str(),
                "k",
                r.k,
            ),
            None => self.t("sops-limits-escrow-none"),
        }
    }

    /// The onion address in 4-character groups (S03).
    pub(crate) fn onion_groups(&self) -> Vec<String> {
        let a = &self.vm.deployment.onion_address;
        let (host, suffix) = a.strip_suffix(".onion").map_or((a.as_str(), ""), |h| (h, ".onion"));
        let chars: Vec<char> = host.chars().collect();
        let mut groups: Vec<String> = chars.chunks(4).map(|c| c.iter().collect()).collect();
        if !suffix.is_empty() {
            groups.push(suffix.to_owned());
        }
        groups
    }

    /// Spelled-out word: letters separated by spaces (S10 `<details>`).
    pub(crate) fn spell(&self, w: &str) -> String {
        let letters: Vec<String> = w.chars().map(|c| c.to_string()).collect();
        letters.join(" ")
    }

    /// The passphrase words on one line (S10 read-only field). Zeroized by the caller's page
    /// buffer; this temporary is zeroized on drop.
    pub(crate) fn passphrase_line(&self) -> zeroize::Zeroizing<String> {
        let words: Vec<&str> = self
            .vm
            .credential
            .passphrase
            .words
            .iter()
            .map(|w| w.as_str())
            .collect();
        zeroize::Zeroizing::new(words.join(" "))
    }

    pub(crate) fn wordlist_lang(&self) -> &str {
        let l = self.vm.credential.passphrase.wordlist_lang.as_str();
        if l.is_empty() { "en" } else { l }
    }

    pub(crate) fn passphrase_len(&self) -> u64 {
        u64::try_from(self.vm.credential.passphrase.words.len()).unwrap_or(u64::MAX)
    }

    /// Positions to render as login boxes when `layout=ten`.
    pub(crate) fn login_boxes(&self) -> Vec<u32> {
        (1..=self.vm.deployment.passphrase_words.clamp(1, 64)).collect()
    }
}
