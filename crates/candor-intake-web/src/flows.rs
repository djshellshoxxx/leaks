// SPDX-License-Identifier: AGPL-3.0-or-later
//! Per-route flows (11 §6–§7; 08 SW-01..SW-30). Every draft value lives in
//! the sealer (ADR-034): a POST reads the draft (`DRAFT_GET`), applies the
//! form and writes it back (`DRAFT_SET`); the web keeps only the flow phase.
//! Passphrase words exist in web memory only while the S10 page is rendered
//! (zeroizing buffers, dropped with the response).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use candor_core::passphrase::{Wordlist, normalize};
use candor_intake_store::{AccountId, StoredReply};
use candor_sealer::proto::{
    self as sp, Coi, DraftSet, DraftView, ErrorCode, PendingReply, Request, Response, SecretBytes,
    SecretText, SecretWords, SessionHandle,
};
use candor_source_ui::{
    self as ui, Arg, AttachedFile, ChoiceOption, FieldError, IdentityData, InboxMessage, Msg,
    Passphrase, Question, QuestionKind, ReviewAnswer, Route, Screen, ViewModel,
};
use zeroize::Zeroizing;

use crate::app::{Fail, FormFail, Out, Reply, Rq, SessionKeysRef, Web};
use crate::config::{ChannelConfig, StoreReads};
use crate::form::Form;
use crate::limits::{
    INBOX_FIXED, MAX_FORM_FIELDS, SEALER_KDF_TIMEOUT, SEALER_OP_TIMEOUT, SEALER_SEAL_TIMEOUT,
    UPLOAD_CHUNK,
};
use crate::multipart::{Event, Multipart, boundary_from_content_type};
use crate::ratelimit::Class;
use crate::routes::{PostAuth, RouteDecl, desc_index};
use crate::server::BodyReader;
use crate::session::{Confirm, Phase, WebSession};
use crate::token::{random, token_eq};

/// Questionnaire field ids in the sealer draft (sorted ascending).
const Q_FIELDS: [(&str, u16); 9] = [
    ("category", 1),
    ("what", 2),
    ("when", 3),
    ("where", 4),
    ("who", 5),
    ("how_know", 6),
    ("people_know", 7),
    ("reported_before", 8),
    ("anything_else", 9),
];
/// S06 per-file descriptions: field `DESC_BASE + n`.
const DESC_BASE: u16 = 100;
/// Questionnaire steps of the default template (11 §7 S05).
const FIRST_STEP: u8 = 3;
const LAST_STEP: u8 = 6;
/// Fixed text of the S13 "ask the team to delete my report" message.
const ASK_DELETE_TEXT: &str = "The source asks that this report be deleted.";

/// Sealer outcome mapped for the flows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SealFail {
    Page(Fail),
    /// A size limit in the sealer (draft too large).
    Limit,
    /// No eligible first reader / channel unavailable (fail closed, ADR-037(1)).
    NoReader(Option<[u8; 16]>),
    /// The request reached the sealer but no reply came in time: the
    /// outcome is unknown (AUD-RM2-SEA-01). Outside `SEAL_FINISH` this is
    /// handled like the busy page.
    Unconfirmed,
}

impl From<Fail> for SealFail {
    fn from(f: Fail) -> Self {
        Self::Page(f)
    }
}

type Fields = BTreeMap<u16, Zeroizing<String>>;

fn fields_of(v: &DraftView) -> Fields {
    v.fields
        .iter()
        .map(|(k, t)| (*k, Zeroizing::new(t.expose().to_owned())))
        .collect()
}

fn sp_mode(m: ui::Mode) -> sp::Mode {
    match m {
        ui::Mode::Confidential | ui::Mode::ConfidentialIdentitySeen => sp::Mode::Confidential,
        ui::Mode::Identified => sp::Mode::Identified,
        ui::Mode::Anonymous | ui::Mode::Clearnet => sp::Mode::Anonymous,
    }
}

/// UTC civil date of an epoch day (H. Hinnant's algorithm, checked).
pub(crate) fn ui_day(epoch_day: u32) -> Option<ui::Day> {
    let z = u64::from(epoch_day).checked_add(719_468)?;
    let era = z.checked_div(146_097)?;
    let doe = z.checked_sub(era.checked_mul(146_097)?)?;
    let yoe = doe
        .checked_sub(doe.checked_div(1460)?)?
        .checked_add(doe.checked_div(36_524)?)?
        .checked_sub(doe.checked_div(146_096)?)?
        .checked_div(365)?;
    let doy = doe.checked_sub(
        yoe.checked_mul(365)?
            .checked_add(yoe.checked_div(4)?)?
            .checked_sub(yoe.checked_div(100)?)?,
    )?;
    let mp = doy.checked_mul(5)?.checked_add(2)?.checked_div(153)?;
    let d = doy
        .checked_sub(mp.checked_mul(153)?.checked_add(2)?.checked_div(5)?)?
        .checked_add(1)?;
    let m = if mp < 10 {
        mp.checked_add(3)?
    } else {
        mp.checked_sub(9)?
    };
    let y = yoe
        .checked_add(era.checked_mul(400)?)?
        .checked_add(u64::from(m <= 2))?;
    ui::Day::new(
        u16::try_from(y).ok()?,
        u8::try_from(m).ok()?,
        u8::try_from(d).ok()?,
    )
}

/// The word-list index of a typed word (normalised as at login), scanning
/// the whole list without early exit; `u16::MAX` if absent (a guaranteed
/// mismatch in the sealer's constant-time compare).
fn word_index(list: &Wordlist, typed: &str) -> u16 {
    let Ok(n) = normalize(typed) else {
        return u16::MAX;
    };
    let mut found = u16::MAX;
    for i in 0..list.len() {
        let hit = list
            .get(i)
            .is_some_and(|w| candor_core::kdf::ct_eq(w.as_bytes(), n.as_bytes()));
        if hit {
            found = u16::try_from(i).unwrap_or(u16::MAX);
        }
    }
    found
}

/// `SealedObject ‖ stanza` → `(object_hash, stanza)` for `ROTATE_FINISH`.
fn pending_reply(ct: &[u8]) -> Option<PendingReply> {
    use candor_core::header::{CoreHeader, HEADER_LEN, HEADER_MAC_LEN};
    let header = CoreHeader::decode(ct.get(..HEADER_LEN)?).ok()?;
    let obj_len = usize::try_from(header.expected_payload_len().ok()?)
        .ok()?
        .checked_add(HEADER_LEN.checked_add(HEADER_MAC_LEN)?)?;
    let parsed = candor_core::object::parse(ct.get(..obj_len)?).ok()?;
    let stanza = ct.get(obj_len..)?;
    if stanza.is_empty() || stanza.len() > sp::MAX_STANZA_LEN {
        return None;
    }
    Some(PendingReply {
        object_hash: parsed.object_hash(),
        stanza: stanza.to_vec(),
    })
}

/// A dead-drop entry for `OPEN_REPLY`: `u32be(len) ‖ SealedObject ‖ stanza`.
fn entry_of(ct: &[u8]) -> Option<Vec<u8>> {
    let len = u32::try_from(ct.len()).ok()?;
    let total = ct.len().checked_add(4)?;
    if total > sp::MAX_REPLY_ENTRY_LEN {
        return None;
    }
    let mut v = Vec::with_capacity(total);
    v.extend_from_slice(&len.to_be_bytes());
    v.extend_from_slice(ct);
    Some(v)
}

fn parse_u16(s: Option<&str>) -> Option<u16> {
    let s = s?;
    if s.is_empty() || s.len() > 5 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

fn identity_block(full_name: &str, role: &str, contact_other: Option<&str>) -> Zeroizing<String> {
    let mut s = Zeroizing::new(String::with_capacity(
        full_name
            .len()
            .saturating_add(role.len())
            .saturating_add(contact_other.map_or(0, str::len))
            .saturating_add(16),
    ));
    s.push_str(full_name);
    s.push('\n');
    s.push_str(role);
    s.push('\n');
    match contact_other {
        Some(c) => {
            s.push_str("other\n");
            s.push_str(c);
        }
        None => s.push_str("mailbox\n"),
    }
    s
}

/// Clears `WebSession::uploading` when an upload ends, on every path
/// (AUD-RM2-WEB-07).
struct UploadFlag<'a> {
    sessions: &'a crate::session::Sessions,
    table: [u8; 32],
}

impl Drop for UploadFlag<'_> {
    fn drop(&mut self) {
        let _ = self
            .sessions
            .with(&self.table, Instant::now(), false, |s| s.uploading = false);
    }
}

/// Space-joined answer values, built once in an exactly sized zeroizing
/// buffer (AUD-RM2-WEB-01: no plain `String` copies of source text).
fn join_z(values: &[Zeroizing<String>]) -> Zeroizing<String> {
    let len = values
        .iter()
        .fold(0usize, |a, v| a.saturating_add(v.len()).saturating_add(1));
    let mut out = Zeroizing::new(String::with_capacity(len));
    for (i, v) in values.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(v);
    }
    out
}

fn identity_data(block: Option<&SecretText>, target: ui::Mode) -> IdentityData {
    let mut d = IdentityData {
        target,
        ..IdentityData::default()
    };
    if let Some(b) = block {
        let mut it = b.expose().split('\n');
        // AUD-RM2-WEB-01: straight into zeroizing buffers.
        d.full_name = Zeroizing::new(it.next().unwrap_or_default().to_owned());
        d.role = Zeroizing::new(it.next().unwrap_or_default().to_owned());
        d.contact_other = it.next() == Some("other");
        d.contact_other_value = Zeroizing::new(it.next().unwrap_or_default().to_owned());
    }
    d
}

impl<S: StoreReads + 'static> Web<S> {
    // -------------------------------------------------------------- sealer

    pub(crate) async fn call(&self, req: &Request, t: Duration) -> Result<Response, SealFail> {
        let r = self.sealer.call(req, t).await;
        self.note_sealer(&r);
        r.map_err(|e| match e {
            crate::sealer::SealerError::Unavailable => SealFail::Page(Fail::Busy),
            crate::sealer::SealerError::NoReply => SealFail::Unconfirmed,
            crate::sealer::SealerError::Code(code, alt) => match code {
                ErrorCode::Busy => SealFail::Page(Fail::Busy),
                ErrorCode::UnknownSession => SealFail::Page(Fail::Gone),
                ErrorCode::Limit => SealFail::Limit,
                ErrorCode::NoEligibleTriage | ErrorCode::Unavailable => SealFail::NoReader(alt),
                ErrorCode::BadState
                | ErrorCode::NotConfirmed
                | ErrorCode::Crypto
                | ErrorCode::Internal
                | ErrorCode::BadFrame => SealFail::Page(Fail::Error),
            },
        })
    }

    async fn draft(&self, h: SessionHandle) -> Result<DraftView, SealFail> {
        match self
            .call(&Request::DraftGet { sess: h }, SEALER_OP_TIMEOUT)
            .await?
        {
            Response::Draft(v) => Ok(*v),
            _ => Err(SealFail::Page(Fail::Error)),
        }
    }

    async fn put_draft(
        &self,
        h: SessionHandle,
        mode: sp::Mode,
        message: &SecretText,
        fields: &Fields,
        identity: Option<SecretText>,
        coi: Option<Coi>,
    ) -> Result<(), SealFail> {
        let ds = DraftSet {
            sess: h,
            mode,
            message: message.clone(),
            fields: fields
                .iter()
                .filter(|(_, v)| !v.is_empty())
                .map(|(k, v)| (*k, SecretText::new(v)))
                .collect(),
            identity,
            coi,
        };
        match self.call(&Request::DraftSet(ds), SEALER_OP_TIMEOUT).await? {
            Response::Empty => Ok(()),
            _ => Err(SealFail::Page(Fail::Error)),
        }
    }

    async fn simple(&self, req: Request) -> Result<(), SealFail> {
        let t = SEALER_OP_TIMEOUT;
        match self.call(&req, t).await? {
            Response::Empty => Ok(()),
            _ => Err(SealFail::Page(Fail::Error)),
        }
    }

    /// Best-effort `ZEROIZE` (the sealer's own timers end it anyway).
    async fn zeroize(&self, h: SessionHandle) {
        let _ = self.simple(Request::Zeroize { sess: h }).await;
    }

    fn channel(&self, id: Option<[u8; 16]>) -> Option<&ChannelConfig> {
        let id = id?;
        self.cfg.site.channels.iter().find(|c| c.id == id)
    }

    fn years(&self) -> Vec<u16> {
        let this = self
            .clock
            .today()
            .and_then(ui_day)
            .map_or(2026, ui::Day::year);
        (0..30u16).filter_map(|i| this.checked_sub(i)).collect()
    }

    fn step_questions(&self, ch: Option<&ChannelConfig>, step: u8, f: &Fields) -> Vec<Question> {
        let cats: Vec<ChoiceOption> = ch
            .map(|c| c.categories.iter().map(|(_, o)| o.clone()).collect())
            .unwrap_or_default();
        let mut qs = ui::default_questionnaire_step(step, &cats, &self.years());
        for q in &mut qs {
            let Some(id) = Q_FIELDS.iter().find(|(n, _)| *n == q.id).map(|(_, i)| *i) else {
                continue;
            };
            let Some(v) = f.get(&id) else { continue };
            q.value = match q.kind {
                QuestionKind::MultiChoice(_) | QuestionKind::MonthYear { .. } => v
                    .split('\n')
                    .map(|s| Zeroizing::new(s.to_owned()))
                    .collect(),
                _ => vec![Zeroizing::new(v.as_str().to_owned())],
            };
        }
        qs
    }

    fn files_of(&self, v: &DraftView, f: &Fields) -> Vec<AttachedFile> {
        v.parts
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let n = u16::try_from(i).unwrap_or(u16::MAX);
                AttachedFile {
                    // The web never sees file names (sealer RAM only).
                    name: Zeroizing::new(format!("#{}", i.saturating_add(1))),
                    size_bytes: p.size_bucket,
                    description: f
                        .get(&DESC_BASE.saturating_add(n))
                        .map(|s| Zeroizing::new(s.as_str().to_owned()))
                        .unwrap_or_default(),
                }
            })
            .collect()
    }

    fn fill_files(&self, vm: &mut ViewModel, v: &DraftView, f: &Fields) {
        vm.files.files = self.files_of(v, f);
        vm.files.max_files = self.cfg.max_files;
        vm.files.max_file_bytes = self.cfg.max_file_bytes;
        vm.files.max_total_bytes = self
            .cfg
            .max_file_bytes
            .saturating_mul(u64::from(self.cfg.max_files));
    }

    fn fill_review(
        &self,
        vm: &mut ViewModel,
        ch: Option<&ChannelConfig>,
        v: &DraftView,
        delayed: bool,
    ) {
        let f = fields_of(v);
        if let Some(c) = ch {
            vm.review.channel = c.option.name.clone();
            vm.review.first_readers = c.option.triage.clone();
            let ticked: &[u16] = v.coi.as_ref().map_or(&[], |c| c.excluded_labels.as_slice());
            vm.review.kept_out = c
                .roles
                .iter()
                .filter(|(id, _)| ticked.contains(id))
                .map(|(_, l)| l.clone())
                .collect();
            vm.review.others = c
                .roles
                .iter()
                .filter(|(id, _)| !ticked.contains(id))
                .map(|(_, l)| l.clone())
                .collect();
        }
        for step in FIRST_STEP..=LAST_STEP {
            for q in self.step_questions(ch, step, &f) {
                if q.value.iter().all(|v| v.is_empty()) {
                    continue;
                }
                vm.review.answers.push(ReviewAnswer {
                    question: q.label.clone(),
                    step,
                    answer: join_z(&q.value),
                });
            }
        }
        vm.review.files = self.files_of(v, &f);
        vm.review.delayed_delivery = delayed;
        vm.review.has_identity = v.identity.is_some();
    }

    /// Render a drafting screen from the current draft.
    async fn draft_screen(
        &self,
        rq: &Rq<'_>,
        k: SessionKeysRef,
        screen: Screen,
        fill: impl FnOnce(&mut ViewModel),
    ) -> Reply {
        let v = match self.draft(k.sealer).await {
            Ok(v) => v,
            Err(e) => return self.seal_fail(rq, e),
        };
        let Ok((out, ch_id, step, delayed, mode)) = self.with_session(&k, |s| {
            (
                Self::out_session(s, Instant::now()),
                s.channel,
                s.step,
                s.delayed,
                s.mode,
            )
        }) else {
            return self.fail(rq, Fail::Gone);
        };
        let ch = self.channel(ch_id);
        let f = fields_of(&v);
        self.page(rq, out, screen, |vm| {
            match screen {
                Screen::Concerns => {
                    if let Some(c) = ch {
                        vm.concerns.triage = c.option.triage.clone();
                        vm.concerns.roles = c.roles.iter().map(|(_, l)| l.clone()).collect();
                        let t: &[u16] =
                            v.coi.as_ref().map_or(&[], |c| c.excluded_labels.as_slice());
                        vm.concerns.ticked = c
                            .roles
                            .iter()
                            .enumerate()
                            .filter(|(_, (id, _))| t.contains(id))
                            .filter_map(|(i, _)| u16::try_from(i).ok())
                            .collect();
                    } else {
                        vm.concerns.load_failed = true;
                    }
                }
                Screen::Questionnaire => {
                    vm.questionnaire.step = step;
                    vm.questionnaire.questions = self.step_questions(ch, step, &f);
                }
                Screen::Identity | Screen::IdentityConfirm => {
                    let target = if mode.is_disclosed() {
                        mode
                    } else {
                        ui::Mode::Confidential
                    };
                    vm.identity = identity_data(v.identity.as_ref(), target);
                }
                Screen::Files | Screen::MetadataWarning => self.fill_files(vm, &v, &f),
                Screen::Review => self.fill_review(vm, ch, &v, delayed),
                _ => {}
            }
            fill(vm);
        })
    }

    pub(crate) fn seal_fail(&self, rq: &Rq<'_>, e: SealFail) -> Reply {
        match e {
            SealFail::Page(f) => self.fail(rq, f),
            SealFail::Limit => self.fail(rq, Fail::Error),
            SealFail::NoReader(alt) => self.no_reader(rq, alt),
            // Outside SEAL_FINISH: as before, the busy page.
            SealFail::Unconfirmed => self.fail(rq, Fail::Busy),
        }
    }

    fn no_reader(&self, rq: &Rq<'_>, alt: Option<[u8; 16]>) -> Reply {
        let out = self.out_any(rq);
        let alts: Vec<_> = self
            .cfg
            .site
            .channels
            .iter()
            .filter(|c| Some(c.id) == alt || c.option.independent_route)
            .map(|c| c.option.clone())
            .collect();
        self.page(rq, out, Screen::NoReader, |vm| {
            vm.no_reader.alternatives = alts
        })
    }

    // ------------------------------------------------------------------ GET

    pub(crate) async fn get(&self, rq: &Rq<'_>, decl: &RouteDecl) -> Reply {
        let session_out = || -> Option<Out> {
            let k = rq.keys.as_ref()?;
            if !rq.live {
                return None;
            }
            self.sessions
                .with(&k.table, Instant::now(), false, |s| {
                    Self::out_session(s, Instant::now())
                })
                .ok()
        };
        let public = |screen: Screen| -> Reply {
            let out = match session_out() {
                Some(o) => o,
                None => match self.out_pre(rq) {
                    Ok(o) => o,
                    Err(f) => return self.fail(rq, f),
                },
            };
            self.page(rq, out, screen, |_| ())
        };
        match decl.route {
            Route::Landing => public(Screen::Landing),
            Route::Safety => public(Screen::Safety),
            Route::SafetyTips => public(Screen::SafetyTips),
            Route::Status => public(Screen::Status),
            Route::New => public(Screen::NewReport),
            Route::Login => public(Screen::Login),
            Route::Concerns
            | Route::Questionnaire
            | Route::Identity
            | Route::Files
            | Route::FilesCheck
            | Route::Review => {
                let k = match self.require_session(rq) {
                    Ok(k) => k,
                    Err(f) => return self.fail(rq, f),
                };
                let Ok(phase) = self.with_session(&k, |s| s.phase) else {
                    return self.fail(rq, Fail::Gone);
                };
                if phase != Phase::Drafting {
                    return self.fail(rq, Fail::NotFound);
                }
                let screen = match decl.route {
                    Route::Concerns => Screen::Concerns,
                    Route::Questionnaire => Screen::Questionnaire,
                    Route::Identity => Screen::Identity,
                    Route::Files => Screen::Files,
                    Route::FilesCheck => Screen::MetadataWarning,
                    _ => Screen::Review,
                };
                self.draft_screen(rq, k, screen, |_| ()).await
            }
            Route::End => {
                let k = match self.require_session(rq) {
                    Ok(k) => k,
                    Err(f) => return self.fail(rq, f),
                };
                let Ok((phase, out)) =
                    self.with_session(&k, |s| (s.phase, Self::out_session(s, Instant::now())))
                else {
                    return self.fail(rq, Fail::Gone);
                };
                let screen = match phase {
                    Phase::Drafting | Phase::Credential | Phase::Confirming => Screen::Discard,
                    Phase::SignedIn | Phase::RotateCredential | Phase::RotateConfirming => {
                        Screen::CloseMailbox
                    }
                    Phase::Submitted => return self.fail(rq, Fail::NotFound),
                };
                self.page(rq, out, screen, |_| ())
            }
            Route::Inbox | Route::Conversation | Route::Rotate => {
                let k = match self.signed_in(rq) {
                    Ok(k) => k,
                    Err(f) => return self.fail(rq, f),
                };
                match decl.route {
                    Route::Inbox => self.inbox(rq, k, None, |_| ()).await,
                    Route::Conversation => self.conversation(rq, k, |_| ()).await,
                    _ => {
                        let Ok(out) =
                            self.with_session(&k, |s| Self::out_session(s, Instant::now()))
                        else {
                            return self.fail(rq, Fail::Gone);
                        };
                        self.page(rq, out, Screen::RotateExplain, |_| ())
                    }
                }
            }
            Route::Check
            | Route::NewPhrase
            | Route::Submit
            | Route::RotateConfirm
            | Route::Leave
            | Route::Extend => self.page(rq, self.out_any(rq), Screen::MethodNotAllowed, |_| ()),
        }
    }

    fn signed_in(&self, rq: &Rq<'_>) -> Result<SessionKeysRef, Fail> {
        let k = self.require_session(rq)?;
        let ok = self.with_session(&k, |s| {
            matches!(
                s.phase,
                Phase::SignedIn | Phase::RotateCredential | Phase::RotateConfirming
            ) && s.account.is_some()
        })?;
        if ok { Ok(k) } else { Err(Fail::NotFound) }
    }

    // ---------------------------------------------------------- inbox / S12

    async fn messages(&self, k: SessionKeysRef) -> Result<Vec<InboxMessage>, Fail> {
        let account = self
            .with_session(&k, |s| s.account)?
            .ok_or(Fail::NotFound)?;
        let replies = self.store.mailbox(account).await;
        self.note_store(replies.is_ok());
        let replies = replies.map_err(|_| Fail::Busy)?;
        let mut views = Vec::with_capacity(INBOX_FIXED);
        // Always INBOX_FIXED openings, real entries first then dummies, so the
        // sealer work does not depend on how many replies exist (08 §3.8).
        for i in 0..INBOX_FIXED {
            let entry = match replies.get(i).and_then(|r| entry_of(&r.reply_ct)) {
                Some(e) => e,
                None => {
                    let mut d = vec![0u8; 1024];
                    random(&mut d).map_err(|_| Fail::Error)?;
                    d
                }
            };
            let r = self
                .call(
                    &Request::OpenReply {
                        sess: k.sealer,
                        entry,
                    },
                    SEALER_OP_TIMEOUT,
                )
                .await;
            match r {
                Ok(Response::Reply(Some(v))) => views.push(v),
                Ok(Response::Reply(None)) => {}
                Ok(_) => return Err(Fail::Error),
                Err(SealFail::Page(f)) => return Err(f),
                Err(_) => return Err(Fail::Error),
            }
        }
        views.sort_by(|a, b| (b.day, b.reply_seq).cmp(&(a.day, a.reply_seq)));
        Ok(views
            .into_iter()
            .filter_map(|v| {
                Some(InboxMessage {
                    sender: Zeroizing::new(v.role_label.expose().to_owned()),
                    date: ui_day(v.day)?,
                    text: Zeroizing::new(v.body.expose().to_owned()),
                })
            })
            .collect())
    }

    pub(crate) async fn inbox(
        &self,
        rq: &Rq<'_>,
        k: SessionKeysRef,
        set_cookie: Option<Zeroizing<String>>,
        fill: impl FnOnce(&mut ViewModel),
    ) -> Reply {
        let msgs = match self.messages(k).await {
            Ok(m) => m,
            Err(f) => return self.fail(rq, f),
        };
        let Ok(mut out) = self.with_session(&k, |s| Self::out_session(s, Instant::now())) else {
            return self.fail(rq, Fail::Gone);
        };
        out.set_cookie = set_cookie;
        let high = self.cfg.site.deployment.high_profile;
        self.page(rq, out, Screen::Inbox, |vm| {
            vm.inbox.messages = msgs;
            vm.inbox.rotation_offer = high;
            fill(vm);
        })
    }

    async fn conversation(
        &self,
        rq: &Rq<'_>,
        k: SessionKeysRef,
        fill: impl FnOnce(&mut ViewModel),
    ) -> Reply {
        let msgs = match self.messages(k).await {
            Ok(m) => m,
            Err(f) => return self.fail(rq, f),
        };
        let Ok((out, delayed)) =
            self.with_session(&k, |s| (Self::out_session(s, Instant::now()), s.delayed))
        else {
            return self.fail(rq, Fail::Gone);
        };
        self.page(rq, out, Screen::Conversation, |vm| {
            vm.conversation.messages = msgs;
            vm.conversation.delayed_delivery = delayed;
            fill(vm);
        })
    }

    // ----------------------------------------------------------------- POST

    pub(crate) async fn post(
        &self,
        rq: &Rq<'_>,
        decl: &RouteDecl,
        auth: PostAuth,
        body: &mut BodyReader,
    ) -> Reply {
        let ct = rq.head.content_type.as_deref().unwrap_or_default();
        if decl.post.is_some_and(|p| p.multipart)
            && let Some(boundary) = boundary_from_content_type(ct)
        {
            return self.upload(rq, decl.route, &boundary, body).await;
        }
        let form = match self.read_form(rq, decl, auth, body).await {
            Ok(f) => f,
            Err(FormFail::Page(f)) => return self.fail(rq, f),
            Err(FormFail::Field(name)) => return self.field_too_long(rq, decl.route, name).await,
        };
        if form.get("nav") == Some("retry") && decl.get {
            // S90 "Try again": re-render the route's page.
            return self.get(rq, decl).await;
        }
        match decl.route {
            Route::New => self.post_new(rq, &form).await,
            Route::Login => self.post_login(rq, &form).await,
            Route::Leave => {
                let k = rq
                    .keys
                    .as_ref()
                    .filter(|_| rq.live)
                    .map(|k| (k.table, k.sealer));
                self.leave(rq, k).await
            }
            _ => {
                let k = match self.require_session(rq) {
                    Ok(k) => k,
                    Err(f) => return self.fail(rq, f),
                };
                self.post_session(rq, decl.route, k, &form).await
            }
        }
    }

    async fn field_too_long(&self, rq: &Rq<'_>, route: Route, name: &'static str) -> Reply {
        let (screen, key) = match route {
            Route::Questionnaire => (Screen::Questionnaire, "sui-q-err-too-long"),
            Route::Identity => (Screen::Identity, "sui-id-err-too-long"),
            Route::Conversation => (Screen::Conversation, "sui-q-err-too-long"),
            Route::Login => (Screen::Login, "sui-login-err-auth"),
            _ => return self.fail(rq, Fail::Error),
        };
        let err = FieldError {
            field: name.to_owned(),
            message: Msg::new(key).arg("max", 60_000u32),
        };
        match self.require_session(rq) {
            Ok(k) if screen != Screen::Login && screen != Screen::Conversation => {
                self.draft_screen(rq, k, screen, |vm| vm.ctx.errors.push(err))
                    .await
            }
            Ok(k) if screen == Screen::Conversation => {
                self.conversation(rq, k, |vm| vm.ctx.errors.push(err)).await
            }
            _ if screen == Screen::Login => {
                let out = self.out_any(rq);
                self.page(rq, out, Screen::Login, |vm| vm.ctx.errors.push(err))
            }
            Ok(_) | Err(_) => self.fail(rq, Fail::Error),
        }
    }

    async fn leave(&self, rq: &Rq<'_>, k: Option<([u8; 32], SessionHandle)>) -> Reply {
        if let Some((table, h)) = k {
            self.zeroize(h).await;
            self.sessions.remove(&table);
        }
        // Clear-Site-Data clears the cookies; no new cookie is set.
        let out = Out {
            set_cookie: None,
            token: Zeroizing::new("0".repeat(64)),
            piece: None,
            timers: None,
            mode: ui::Mode::Anonymous,
            has_session: false,
        };
        self.page(rq, out, Screen::Leave, |_| ())
    }

    /// SW-03: start a report (pre-session token; new session and cookie).
    async fn post_new(&self, rq: &Rq<'_>, form: &Form) -> Reply {
        let chosen = form.get("channel_id").and_then(|id| {
            self.cfg
                .site
                .channels
                .iter()
                .find(|c| token_eq(id, &c.option.id))
        });
        let mode = match form.get("mode") {
            None | Some("anonymous") => ui::Mode::Anonymous,
            Some("confidential") => ui::Mode::Confidential,
            Some("identified") => ui::Mode::Identified,
            Some(_) => return self.fail(rq, Fail::Error),
        };
        let reshow = |field: &str, key: &'static str| {
            let out = match self.out_pre(rq) {
                Ok(o) => o,
                Err(f) => return self.fail(rq, f),
            };
            let err = Self::field_error(field, key);
            self.page(rq, out, Screen::NewReport, |vm| {
                vm.new_report.selected_mode = mode;
                vm.ctx.errors.push(err);
            })
        };
        let Some(ch) = chosen.filter(|c| c.option.available) else {
            return reshow("channel_id", "sui-new-err-channel");
        };
        let allowed = match mode {
            ui::Mode::Confidential => ch.option.allows_confidential,
            ui::Mode::Identified => ch.option.allows_identified,
            _ => true,
        };
        if !allowed {
            return reshow("mode", "sui-new-err-mode");
        }
        // A request that already had a session: end it first (fixation-proof).
        if let Some(k) = rq.keys.as_ref().filter(|_| rq.live) {
            self.zeroize(k.sealer).await;
            self.sessions.remove(&k.table);
        }
        match self.store.serving_allowed().await {
            Ok(true) => self.note_store(true),
            _ => {
                self.note_store(false);
                return self.fail(rq, Fail::Busy);
            }
        }
        let (k, cookie, mut s) = match self.new_session(Phase::Drafting) {
            Ok(v) => v,
            Err(f) => return self.fail(rq, f),
        };
        let open = Request::SessionOpen {
            sess: k.sealer,
            channel_id: ch.id,
        };
        if let Err(e) = self.simple(open).await {
            return self.seal_fail(rq, e);
        }
        // The chosen mode stays in the web session until S05b confirms it;
        // the sealer draft stays ANONYMOUS until then.
        s.channel = Some(ch.id);
        s.mode = mode;
        let mut out = Self::out_session(&s, Instant::now());
        out.set_cookie = Some(cookie);
        self.sessions.insert(k.table, s);
        let triage = ch.option.triage.clone();
        let roles: Vec<String> = ch.roles.iter().map(|(_, l)| l.clone()).collect();
        self.page(rq, out, Screen::Concerns, |vm| {
            vm.concerns.triage = triage;
            vm.concerns.roles = roles;
        })
    }

    /// SW-10: login (the caller applies the latency floor on every outcome).
    async fn post_login(&self, rq: &Rq<'_>, form: &Form) -> Reply {
        let words = self.cfg.site.deployment.passphrase_words;
        if form.get("action") != Some("login") {
            // Layout switch only: no authentication attempt (11 S11).
            let ten = form.get("layout") == Some("ten");
            let out = self.out_any(rq);
            return self.page(rq, out, Screen::Login, |vm| vm.login.ten_boxes = ten);
        }
        let ten = form.all("passphrase").count() > 1;
        let login_err = |msg: Msg| {
            let out = self.out_any(rq);
            self.page(rq, out, Screen::Login, |vm| {
                vm.login.ten_boxes = ten;
                vm.ctx.errors.push(FieldError {
                    field: "passphrase".to_owned(),
                    message: msg,
                });
            })
        };
        // Join the boxes (or take the single field) and normalise as C-07
        // does (ADR-047(6)); the passphrase lives only in zeroizing buffers.
        let mut joined = Zeroizing::new(String::with_capacity(sp::MAX_PASSPHRASE_LEN));
        for (i, w) in form.all("passphrase").enumerate() {
            if i > 0 {
                joined.push(' ');
            }
            if joined.len().saturating_add(w.len()) > sp::MAX_PASSPHRASE_LEN {
                return login_err(Msg::new("sui-login-err-auth"));
            }
            joined.push_str(w);
        }
        let Ok(norm) = normalize(&joined) else {
            return login_err(Msg::new("sui-login-err-auth"));
        };
        drop(joined);
        let Ok(list) = Wordlist::eff_large() else {
            return self.fail(rq, Fail::Error);
        };
        let got = if norm.is_empty() {
            0
        } else {
            norm.split(' ').count()
        };
        if usize::try_from(words).ok() != Some(got) {
            return login_err(
                Msg::new("sui-login-err-count")
                    .arg("n", words)
                    .arg("got", u32::try_from(got).unwrap_or(u32::MAX)),
            );
        }
        for (i, w) in norm.split(' ').enumerate() {
            if word_index(list, w) == u16::MAX {
                let pos = u32::try_from(i.saturating_add(1)).unwrap_or(u32::MAX);
                return login_err(Msg::new("sui-login-err-word").arg("i", pos));
            }
        }
        match self.store.serving_allowed().await {
            Ok(true) => self.note_store(true),
            _ => {
                self.note_store(false);
                return self.fail(rq, Fail::Busy);
            }
        }
        let (k, cookie, mut s) = match self.new_session(Phase::SignedIn) {
            Ok(v) => v,
            Err(f) => return self.fail(rq, f),
        };
        let derive = Request::LoginDerive {
            sess: k.sealer,
            passphrase: SecretBytes::from_slice(norm.as_bytes()),
        };
        drop(norm);
        let tag = match self.call(&derive, SEALER_KDF_TIMEOUT).await {
            Ok(Response::Locator { lookup_tag }) => Zeroizing::new(lookup_tag),
            Ok(_) => return self.fail(rq, Fail::Error),
            Err(e) => return self.seal_fail(rq, e),
        };
        let account = self.store.account(*tag).await;
        self.note_store(account.is_ok());
        let Ok(account) = account else {
            self.zeroize(k.sealer).await;
            return self.fail(rq, Fail::Busy);
        };
        // Uniform challenge and verification for known and unknown locators
        // (07 §5.3): the same calls run, against a dummy key when unknown.
        let mut challenge = [0u8; 32];
        if random(&mut challenge).is_err() {
            self.zeroize(k.sealer).await;
            return self.fail(rq, Fail::Error);
        }
        let sig = match self
            .call(
                &Request::LoginSign {
                    sess: k.sealer,
                    challenge,
                },
                SEALER_OP_TIMEOUT,
            )
            .await
        {
            Ok(Response::Signature { sig }) => sig,
            Ok(_) => {
                self.zeroize(k.sealer).await;
                return self.fail(rq, Fail::Error);
            }
            Err(e) => {
                self.zeroize(k.sealer).await;
                return self.seal_fail(rq, e);
            }
        };
        let pk = account.as_ref().map_or(self.dummy_auth_pk(), |a| a.auth_pk);
        let mut msg = Vec::with_capacity(96);
        msg.extend_from_slice(candor_core::labels::SIG_SOURCE_AUTH);
        msg.extend_from_slice(&challenge);
        msg.extend_from_slice(&self.cfg.tenant_id);
        msg.extend_from_slice(b"source-web");
        let verified = candor_core::sig::verify_strict(&pk, &msg, &sig).is_ok();
        let Some(acct) = account.filter(|_| verified) else {
            self.zeroize(k.sealer).await;
            return login_err(Msg::new("sui-login-err-auth"));
        };
        let prefs = Request::LoadPrefs {
            sess: k.sealer,
            prefs_ct: acct.prefs_ct,
        };
        if let Err(e) = self.simple(prefs).await {
            self.zeroize(k.sealer).await;
            return match e {
                SealFail::Page(Fail::Error) => login_err(Msg::new("sui-login-err-auth")),
                e => self.seal_fail(rq, e),
            };
        }
        // Fixation-proof: any previous session of this browser ends.
        if let Some(old) = rq.keys.as_ref().filter(|_| rq.live) {
            self.zeroize(old.sealer).await;
            self.sessions.remove(&old.table);
        }
        s.account = Some(acct.account_id);
        s.lookup_tag = Some(tag);
        self.sessions.insert(k.table, s);
        self.inbox(rq, k, Some(cookie), |_| ()).await
    }

    fn dummy_auth_pk(&self) -> [u8; 32] {
        self.dummy_pk
    }

    /// POSTs that need a live session.
    async fn post_session(
        &self,
        rq: &Rq<'_>,
        route: Route,
        k: SessionKeysRef,
        form: &Form,
    ) -> Reply {
        let Ok(phase) = self.with_session(&k, |s| s.phase) else {
            return self.fail(rq, Fail::Gone);
        };
        match (route, phase) {
            (Route::Extend, _) => self.post_extend(rq, k, phase).await,
            (Route::End, _) => self.post_end(rq, k, phase, form).await,
            (Route::Concerns, Phase::Drafting) => self.post_concerns(rq, k, form).await,
            (Route::Questionnaire, Phase::Drafting) => self.post_questionnaire(rq, k, form).await,
            (Route::Identity, Phase::Drafting) => self.post_identity(rq, k, form).await,
            (Route::Files, Phase::Drafting) => self.post_files(rq, k, form).await,
            (Route::FilesCheck, Phase::Drafting) => {
                let screen = if form.get("action") == Some("change") {
                    Screen::Files
                } else {
                    Screen::Review
                };
                self.draft_screen(rq, k, screen, |_| ()).await
            }
            (Route::Review, Phase::Drafting) => self.post_review(rq, k, form).await,
            (Route::Check, Phase::Credential | Phase::Confirming) => {
                self.confirm_page(rq, k, Phase::Confirming, Screen::Confirm, None)
            }
            (Route::Check, Phase::RotateCredential | Phase::RotateConfirming) => {
                self.confirm_page(rq, k, Phase::RotateConfirming, Screen::RotateConfirm, None)
            }
            (Route::NewPhrase, Phase::Credential | Phase::Confirming) => {
                self.gen_phrase(rq, k, false).await
            }
            (Route::NewPhrase, Phase::RotateCredential | Phase::RotateConfirming) => {
                self.gen_phrase(rq, k, true).await
            }
            (Route::Submit, Phase::Confirming) => self.post_submit(rq, k, form).await,
            (Route::Submit, Phase::Submitted) => self.sent_page(rq, k),
            (Route::RotateConfirm, Phase::RotateConfirming) => {
                self.post_rotate_confirm(rq, k, form).await
            }
            (Route::Inbox, Phase::SignedIn | Phase::RotateCredential | Phase::RotateConfirming) => {
                if form.get("action") == Some("rotate-passphrase") {
                    if !self
                        .limiter
                        .allow(rq.circuit, Class::Rotate, Instant::now())
                    {
                        return self.fail(rq, Fail::Busy);
                    }
                    self.post_rotate(rq, k, form).await
                } else {
                    let part = parse_u16(form.get("part")).unwrap_or(0);
                    self.inbox(rq, k, None, |vm| vm.ctx.part = part).await
                }
            }
            (Route::Conversation, Phase::SignedIn) => self.post_conversation(rq, k, form).await,
            _ => self.fail(rq, Fail::NotFound),
        }
    }

    async fn post_extend(&self, rq: &Rq<'_>, k: SessionKeysRef, phase: Phase) -> Reply {
        if phase != Phase::Submitted
            && let Err(e) = self.simple(Request::Touch { sess: k.sealer }).await
        {
            return self.seal_fail(rq, e);
        }
        match phase {
            Phase::Drafting => {
                self.draft_screen(rq, k, Screen::Questionnaire, |_| ())
                    .await
            }
            Phase::Credential | Phase::Confirming => {
                self.confirm_page(rq, k, Phase::Confirming, Screen::Confirm, None)
            }
            Phase::RotateCredential | Phase::RotateConfirming => {
                self.confirm_page(rq, k, Phase::RotateConfirming, Screen::RotateConfirm, None)
            }
            Phase::Submitted => self.sent_page(rq, k),
            Phase::SignedIn => self.inbox(rq, k, None, |_| ()).await,
        }
    }

    async fn post_end(&self, rq: &Rq<'_>, k: SessionKeysRef, phase: Phase, form: &Form) -> Reply {
        let drafting = matches!(
            phase,
            Phase::Drafting | Phase::Credential | Phase::Confirming
        );
        match (form.get("action"), drafting) {
            (Some("discard"), true) => {
                let _ = self.simple(Request::SealAbort { sess: k.sealer }).await;
                self.zeroize(k.sealer).await;
                self.sessions.remove(&k.table);
                self.leave_like(rq, Screen::Discarded)
            }
            (Some("keep"), true) => self.draft_screen(rq, k, Screen::Review, |_| ()).await,
            (Some("keep"), false) => self.inbox(rq, k, None, |_| ()).await,
            (Some("ask-delete"), false) => {
                let Ok(out) = self.with_session(&k, |s| Self::out_session(s, Instant::now()))
                else {
                    return self.fail(rq, Fail::Gone);
                };
                self.page(rq, out, Screen::AskDelete, |_| ())
            }
            (Some("ask-delete-confirm"), false) => {
                // 11 S13 variant 3: a structured message to the team, sealed
                // like any follow-up (only to the original eligible set).
                match self.send_followup(k, ASK_DELETE_TEXT, false).await {
                    Ok(()) => {
                        let Ok(out) =
                            self.with_session(&k, |s| Self::out_session(s, Instant::now()))
                        else {
                            return self.fail(rq, Fail::Gone);
                        };
                        self.page(rq, out, Screen::DeleteRequested, |_| ())
                    }
                    Err(e) => self.seal_fail(rq, e),
                }
            }
            // Close mailbox (SW-15) needs SEAL_SIGNAL in the sealer and a
            // K31-signed deletion in the store; neither is available to the
            // web yet. Refuse uniformly rather than half-delete (SPEC-NOTES
            // open item O-1).
            _ => self.fail(rq, Fail::Error),
        }
    }

    fn leave_like(&self, rq: &Rq<'_>, screen: Screen) -> Reply {
        let out = Out {
            set_cookie: None,
            token: Zeroizing::new("0".repeat(64)),
            piece: None,
            timers: None,
            mode: ui::Mode::Anonymous,
            has_session: false,
        };
        self.page(rq, out, screen, |_| ())
    }

    async fn post_concerns(&self, rq: &Rq<'_>, k: SessionKeysRef, form: &Form) -> Reply {
        let Ok((ch_id, mode)) = self.with_session(&k, |s| (s.channel, s.mode)) else {
            return self.fail(rq, Fail::Gone);
        };
        let Some(ch) = self.channel(ch_id) else {
            return self.fail(rq, Fail::Error);
        };
        let mut labels: Vec<u16> = Vec::new();
        for v in form.all("coi_label") {
            let Some(id) = parse_u16(Some(v))
                .and_then(|i| ch.roles.get(usize::from(i)))
                .map(|(id, _)| *id)
            else {
                return self.fail(rq, Fail::Error);
            };
            labels.push(id);
        }
        labels.sort_unstable();
        labels.dedup();
        if labels.len() > sp::MAX_COI_LABELS {
            return self.fail(rq, Fail::Error);
        }
        let v = match self.draft(k.sealer).await {
            Ok(v) => v,
            Err(e) => return self.seal_fail(rq, e),
        };
        let categories = v
            .coi
            .as_ref()
            .map(|c| c.categories.clone())
            .unwrap_or_default();
        let coi = Coi {
            excluded_labels: Zeroizing::new(labels),
            categories,
        };
        if let Err(e) = self
            .put_draft(
                k.sealer,
                v.mode,
                &v.message,
                &fields_of(&v),
                v.identity.clone(),
                Some(coi),
            )
            .await
        {
            return self.seal_fail(rq, e);
        }
        let next = if mode.is_disclosed() {
            Screen::Identity
        } else {
            Screen::Questionnaire
        };
        self.draft_screen(rq, k, next, |_| ()).await
    }

    async fn post_identity(&self, rq: &Rq<'_>, k: SessionKeysRef, form: &Form) -> Reply {
        let Ok(mode) = self.with_session(&k, |s| s.mode) else {
            return self.fail(rq, Fail::Gone);
        };
        let target = if mode.is_disclosed() {
            mode
        } else {
            ui::Mode::Confidential
        };
        let v = match self.draft(k.sealer).await {
            Ok(v) => v,
            Err(e) => return self.seal_fail(rq, e),
        };
        let f = fields_of(&v);
        match form.get("nav") {
            Some("next") => {
                let name = form.get("full_name").unwrap_or_default();
                if name.trim().is_empty() {
                    let err = Self::field_error("full_name", "sui-id-err-name");
                    return self
                        .draft_screen(rq, k, Screen::Identity, |vm| vm.ctx.errors.push(err))
                        .await;
                }
                let other = (form.get("contact") == Some("other"))
                    .then(|| form.get("contact_other").unwrap_or_default());
                let block = identity_block(name, form.get("role_dept").unwrap_or_default(), other);
                let id = Some(SecretText::new(&block));
                if let Err(e) = self
                    .put_draft(k.sealer, sp_mode(target), &v.message, &f, id, v.coi.clone())
                    .await
                {
                    return self.seal_fail(rq, e);
                }
                let _ = self.with_session(&k, |s| s.mode = target);
                // Disclosure mode changed: new CSRF token (lead decision 3).
                if let Err(f) = self.rotate_token(&k) {
                    return self.fail(rq, f);
                }
                self.draft_screen(rq, k, Screen::IdentityConfirm, |_| ())
                    .await
            }
            Some("confirm") => self.draft_screen(rq, k, Screen::ModeChanged, |_| ()).await,
            Some("decline" | "remove") => {
                // Back to ANONYMOUS: the sealer zeroizes the identity block.
                if let Err(e) = self
                    .put_draft(
                        k.sealer,
                        sp::Mode::Anonymous,
                        &v.message,
                        &f,
                        None,
                        v.coi.clone(),
                    )
                    .await
                {
                    return self.seal_fail(rq, e);
                }
                let _ = self.with_session(&k, |s| s.mode = ui::Mode::Anonymous);
                if let Err(f) = self.rotate_token(&k) {
                    return self.fail(rq, f);
                }
                let next = if form.get("nav") == Some("remove") {
                    Screen::Review
                } else {
                    Screen::Questionnaire
                };
                self.draft_screen(rq, k, next, |_| ()).await
            }
            _ => self.fail(rq, Fail::Error),
        }
    }

    async fn post_questionnaire(&self, rq: &Rq<'_>, k: SessionKeysRef, form: &Form) -> Reply {
        let Ok((ch_id, cur)) = self.with_session(&k, |s| (s.channel, s.step)) else {
            return self.fail(rq, Fail::Gone);
        };
        let ch = self.channel(ch_id);
        let step = parse_u16(form.get("step"))
            .and_then(|s| u8::try_from(s).ok())
            .filter(|s| (FIRST_STEP..=LAST_STEP).contains(s))
            .unwrap_or(cur);
        let v = match self.draft(k.sealer).await {
            Ok(v) => v,
            Err(e) => return self.seal_fail(rq, e),
        };
        let mut f = fields_of(&v);
        let questions = self.step_questions(ch, step, &f);
        let shown: Vec<&str> = form.all("shown").collect();
        let piece_key = match self.with_session(&k, |s| s.piece_key()) {
            Ok(p) => p,
            Err(e) => return self.fail(rq, e),
        };
        let mut errors: Vec<FieldError> = Vec::new();
        let nav = form.get("nav").unwrap_or("next");
        // Only the questions shown on the posted part change (source-ui
        // contract item 2); without `shown`, the whole step.
        for q in questions
            .iter()
            .filter(|q| shown.is_empty() || shown.contains(&q.id.as_str()))
        {
            let Some(fid) = Q_FIELDS.iter().find(|(n, _)| *n == q.id).map(|(_, i)| *i) else {
                continue;
            };
            let opts = |o: &[ChoiceOption], v: &str| o.iter().any(|c| c.value == v);
            let new: Option<Zeroizing<String>> = match &q.kind {
                QuestionKind::ShortText | QuestionKind::LongText => {
                    let posted = form.get(&q.id).unwrap_or_default();
                    let piece = form
                        .all("piece")
                        .filter_map(ui::parse_piece)
                        .find(|p| p.field == q.id);
                    match piece {
                        Some(p) => {
                            let stored = f
                                .get(&fid)
                                .map(|s| s.as_str().to_owned())
                                .unwrap_or_default();
                            let stored = Zeroizing::new(stored);
                            match ui::splice_piece(&piece_key, &q.id, &stored, &p, posted) {
                                Ok(s) => Some(Zeroizing::new(s.as_str().to_owned())),
                                Err(_) => {
                                    errors.push(Self::field_error(&q.id, "sui-q-err-required"));
                                    None
                                }
                            }
                        }
                        None => Some(Zeroizing::new(posted.to_owned())),
                    }
                }
                QuestionKind::SingleChoice(o) => {
                    let val = form.get(&q.id).unwrap_or_default();
                    if val.is_empty() || opts(o, val) {
                        Some(Zeroizing::new(val.to_owned()))
                    } else {
                        errors.push(Self::field_error(&q.id, "sui-q-err-choice"));
                        None
                    }
                }
                QuestionKind::YesNoNotSure => {
                    let val = form.get(&q.id).unwrap_or_default();
                    if matches!(val, "" | "yes" | "no" | "unsure") {
                        Some(Zeroizing::new(val.to_owned()))
                    } else {
                        errors.push(Self::field_error(&q.id, "sui-q-err-choice"));
                        None
                    }
                }
                QuestionKind::MultiChoice(o) => {
                    let vals: Vec<&str> = form.all(&q.id).collect();
                    if vals.iter().all(|v| opts(o, v)) {
                        Some(Zeroizing::new(vals.join("\n")))
                    } else {
                        errors.push(Self::field_error(&q.id, "sui-q-err-choice"));
                        None
                    }
                }
                QuestionKind::MonthYear { years } => {
                    let m = form.get("when_month").unwrap_or_default();
                    let y = form.get("when_year").unwrap_or_default();
                    let m_ok =
                        m.is_empty() || parse_u16(Some(m)).is_some_and(|v| (1..=12).contains(&v));
                    let y_ok =
                        y.is_empty() || parse_u16(Some(y)).is_some_and(|v| years.contains(&v));
                    if !(m_ok && y_ok) {
                        errors.push(Self::field_error(&q.id, "sui-q-err-choice"));
                        None
                    } else {
                        let mut parts = vec![m.to_owned(), y.to_owned()];
                        if form.get("when_ongoing") == Some("1") {
                            parts.push("ongoing".to_owned());
                        }
                        if form.get("when_unsure") == Some("1") {
                            parts.push("unsure".to_owned());
                        }
                        let joined = parts.join("\n");
                        Some(Zeroizing::new(if joined.trim().is_empty() {
                            String::new()
                        } else {
                            joined
                        }))
                    }
                }
            };
            if let Some(n) = new {
                if n.is_empty() {
                    f.remove(&fid);
                } else {
                    f.insert(fid, n);
                }
            }
        }
        // Category → the COI category list (ADR-030/037).
        let mut coi = v.coi.clone().unwrap_or_default();
        if step == FIRST_STEP {
            let cat = f.get(&1).map(|s| s.as_str().to_owned()).unwrap_or_default();
            let ids: Vec<u16> = ch
                .map(|c| {
                    c.categories
                        .iter()
                        .filter(|(_, o)| o.value == cat)
                        .map(|(id, _)| *id)
                        .collect()
                })
                .unwrap_or_default();
            coi.categories = Zeroizing::new(ids);
        }
        let mut next = step;
        if errors.is_empty() {
            match self
                .put_draft(
                    k.sealer,
                    v.mode,
                    &v.message,
                    &f,
                    v.identity.clone(),
                    Some(coi),
                )
                .await
            {
                Ok(()) => {}
                Err(SealFail::Limit) => {
                    let id = questions
                        .iter()
                        .find(|q| q.kind == QuestionKind::LongText)
                        .map_or("what", |q| q.id.as_str());
                    errors.push(FieldError {
                        field: id.to_owned(),
                        message: Msg::new("sui-q-err-too-long").arg(
                            "max",
                            Arg::Num(u64::try_from(sp::MAX_DRAFT_TEXT).unwrap_or(0)),
                        ),
                    });
                }
                Err(e) => return self.seal_fail(rq, e),
            }
        }
        if errors.is_empty() {
            match nav {
                "next" => {
                    let missing: Vec<&Question> = questions
                        .iter()
                        .filter(|q| q.required)
                        .filter(|q| {
                            Q_FIELDS
                                .iter()
                                .find(|(n, _)| *n == q.id)
                                .is_none_or(|(_, id)| f.get(id).is_none_or(|v| v.trim().is_empty()))
                        })
                        .collect();
                    for q in missing {
                        let key = if q.id == "what" {
                            "sui-q-err-what"
                        } else {
                            "sui-q-err-required"
                        };
                        errors.push(Self::field_error(&q.id, key));
                    }
                    if errors.is_empty() {
                        if step >= LAST_STEP {
                            let _ = self.with_session(&k, |s| s.step = LAST_STEP);
                            return self.draft_screen(rq, k, Screen::Files, |_| ()).await;
                        }
                        next = step.saturating_add(1);
                    }
                }
                "back" => {
                    if step <= FIRST_STEP {
                        return self.draft_screen(rq, k, Screen::Concerns, |_| ()).await;
                    }
                    next = step.saturating_sub(1);
                }
                "goto" => next = step,
                _ => {}
            }
        }
        let _ = self.with_session(&k, |s| s.step = next);
        let part = parse_u16(form.get("part")).unwrap_or(0);
        let kept = !errors.is_empty();
        self.draft_screen(rq, k, Screen::Questionnaire, |vm| {
            vm.ctx.part = part;
            vm.ctx.text_kept = kept;
            vm.ctx.errors = errors;
        })
        .await
    }

    async fn post_files(&self, rq: &Rq<'_>, k: SessionKeysRef, form: &Form) -> Reply {
        let v = match self.draft(k.sealer).await {
            Ok(v) => v,
            Err(e) => return self.seal_fail(rq, e),
        };
        let mut f = fields_of(&v);
        if form.get("action") == Some("remove") {
            let Some(p) =
                parse_u16(form.get("part_index")).and_then(|i| v.parts.get(usize::from(i)))
            else {
                return self.fail(rq, Fail::Error);
            };
            if let Err(e) = self
                .simple(Request::PartDrop {
                    sess: k.sealer,
                    part: p.part,
                })
                .await
            {
                return self.seal_fail(rq, e);
            }
            return self.draft_screen(rq, k, Screen::Files, |_| ()).await;
        }
        // Descriptions (desc_N) of the files shown on this part.
        let mut changed = false;
        for name in form.names() {
            if let Some(n) = desc_index(name) {
                if usize::from(n) >= v.parts.len() || usize::from(n) >= MAX_FORM_FIELDS {
                    return self.fail(rq, Fail::Error);
                }
                let val = form.get(name).unwrap_or_default();
                let id = DESC_BASE.saturating_add(n);
                if val.is_empty() {
                    f.remove(&id);
                } else {
                    f.insert(id, Zeroizing::new(val.to_owned()));
                }
                changed = true;
            }
        }
        if changed
            && let Err(e) = self
                .put_draft(
                    k.sealer,
                    v.mode,
                    &v.message,
                    &f,
                    v.identity.clone(),
                    v.coi.clone(),
                )
                .await
        {
            return self.seal_fail(rq, e);
        }
        if form.get("nav") == Some("continue") {
            let screen = if v.parts.is_empty() {
                Screen::Review
            } else {
                Screen::MetadataWarning
            };
            return self.draft_screen(rq, k, screen, |_| ()).await;
        }
        let part = parse_u16(form.get("part")).unwrap_or(0);
        self.draft_screen(rq, k, Screen::Files, |vm| vm.ctx.part = part)
            .await
    }

    async fn post_review(&self, rq: &Rq<'_>, k: SessionKeysRef, form: &Form) -> Reply {
        if let Some(d) = form.get("delayed_delivery") {
            let _ = self.with_session(&k, |s| s.delayed = d == "true");
        }
        if form.get("action") != Some("send") {
            let part = parse_u16(form.get("part")).unwrap_or(0);
            return self
                .draft_screen(rq, k, Screen::Review, |vm| vm.ctx.part = part)
                .await;
        }
        let v = match self.draft(k.sealer).await {
            Ok(v) => v,
            Err(e) => return self.seal_fail(rq, e),
        };
        let f = fields_of(&v);
        if f.get(&1).is_none_or(|s| s.is_empty()) || f.get(&2).is_none_or(|s| s.trim().is_empty()) {
            let msg = Msg::new("sui-review-err-missing");
            return self
                .draft_screen(rq, k, Screen::Review, |vm| vm.ctx.page_error = Some(msg))
                .await;
        }
        self.gen_phrase(rq, k, false).await
    }

    /// S09/SW-25 (and S11r): generate a passphrase in the sealer and render
    /// it once (S10). The words exist here only for this render.
    async fn gen_phrase(&self, rq: &Rq<'_>, k: SessionKeysRef, rotation: bool) -> Reply {
        let req = if rotation {
            Request::RotatePassphrase { sess: k.sealer }
        } else {
            Request::GenAccount { sess: k.sealer }
        };
        let (words, positions) = match self.call(&req, SEALER_OP_TIMEOUT).await {
            Ok(Response::Words {
                words,
                confirm_positions,
            }) => (words, confirm_positions),
            Ok(_) => return self.fail(rq, Fail::Error),
            Err(e) => return self.seal_fail(rq, e),
        };
        let Ok(list) = Wordlist::eff_large() else {
            return self.fail(rq, Fail::Error);
        };
        let mut shown = Vec::with_capacity(words.0.len());
        for i in words.0.iter() {
            let Some(w) = list.get(usize::from(*i)) else {
                return self.fail(rq, Fail::Error);
            };
            shown.push(Zeroizing::new(w.to_owned()));
        }
        drop(words);
        let phase = if rotation {
            Phase::RotateCredential
        } else {
            Phase::Credential
        };
        let Ok(out) = self.with_session(&k, |s| {
            s.phase = phase;
            s.confirm = Confirm {
                positions,
                exhausted: false,
                failures: 0,
            };
            Self::out_session(s, Instant::now())
        }) else {
            return self.fail(rq, Fail::Gone);
        };
        let screen = if rotation {
            Screen::RotateCredential
        } else {
            Screen::Credential
        };
        self.page(rq, out, screen, |vm| {
            vm.credential.passphrase = Passphrase {
                words: shown,
                wordlist_lang: "en".to_owned(),
            };
        })
    }

    fn confirm_page(
        &self,
        rq: &Rq<'_>,
        k: SessionKeysRef,
        phase: Phase,
        screen: Screen,
        err: Option<Msg>,
    ) -> Reply {
        let Ok((out, c)) = self.with_session(&k, |s| {
            s.phase = phase;
            (Self::out_session(s, Instant::now()), s.confirm)
        }) else {
            return self.fail(rq, Fail::Gone);
        };
        let [a, b, cc] = c.positions;
        self.page(rq, out, screen, |vm| {
            vm.confirm.positions = [
                a.saturating_add(1),
                b.saturating_add(1),
                cc.saturating_add(1),
            ];
            vm.confirm.attempts_exhausted = c.exhausted;
            vm.ctx.page_error = err;
        })
    }

    async fn confirm_words(
        &self,
        k: SessionKeysRef,
        form: &Form,
    ) -> Result<Option<[u8; 3]>, SealFail> {
        let list = Wordlist::eff_large().map_err(|_| SealFail::Page(Fail::Error))?;
        let mut idx = Zeroizing::new(Vec::with_capacity(3));
        for n in ["w_a", "w_b", "w_c"] {
            idx.push(word_index(list, form.get(n).unwrap_or_default()));
        }
        let req = Request::ConfirmPassphrase {
            sess: k.sealer,
            words: SecretWords(idx),
        };
        match self.call(&req, SEALER_OP_TIMEOUT).await? {
            Response::Confirm { ok: true, .. } => Ok(None),
            Response::Confirm {
                ok: false,
                confirm_positions: Some(p),
            } => Ok(Some(p)),
            Response::Confirm {
                ok: false,
                confirm_positions: None,
            } => Err(SealFail::Page(Fail::Gone)),
            _ => Err(SealFail::Page(Fail::Error)),
        }
    }

    /// SW-26: confirmation and the final send.
    async fn post_submit(&self, rq: &Rq<'_>, k: SessionKeysRef, form: &Form) -> Reply {
        // IMPL-RM2-020: no submission without a sane independent clock.
        let Some(today) = self.clock.today() else {
            return self.busy_at_submit(rq);
        };
        // 11 S10c: after 3 failed attempts only "new passphrase" and
        // "discard" remain; further words are not sent to the sealer.
        if self
            .with_session(&k, |s| s.confirm.exhausted)
            .unwrap_or(true)
        {
            return self.confirm_page(rq, k, Phase::Confirming, Screen::Confirm, None);
        }
        match self.confirm_words(k, form).await {
            Ok(None) => {}
            Ok(Some(p)) => {
                let _ = self.with_session(&k, |s| {
                    s.confirm.positions = p;
                    s.confirm.failures = s.confirm.failures.saturating_add(1);
                    s.confirm.exhausted = s.confirm.failures >= 3;
                });
                return self.confirm_page(
                    rq,
                    k,
                    Phase::Confirming,
                    Screen::Confirm,
                    Some(Msg::new("sui-confirm-mismatch")),
                );
            }
            Err(SealFail::Page(Fail::Gone)) => {
                // Attempts exhausted: the sealer erased the draft and the
                // passphrase (07 §5.2). Say so honestly.
                self.sessions.remove(&k.table);
                return self.leave_like(rq, Screen::Discarded);
            }
            Err(e) => return self.seal_fail(rq, e),
        }
        let Ok(delayed) = self.with_session(&k, |s| s.delayed) else {
            return self.fail(rq, Fail::Gone);
        };
        let seal = Request::SealFinish {
            sess: k.sealer,
            delayed_delivery: delayed,
        };
        match self.call(&seal, SEALER_SEAL_TIMEOUT).await {
            Ok(Response::Sealed { .. }) => {}
            Ok(_) => return self.fail(rq, Fail::Error),
            Err(SealFail::Page(Fail::Busy)) => return self.busy_at_submit(rq),
            Err(SealFail::NoReader(alt)) => return self.no_reader(rq, alt),
            // AUD-RM2-SEA-01: SEAL_FINISH was sent but not answered in time;
            // the sealer may still deliver (its store hand-over retries and is
            // idempotent). Never say "not sent" then. A second submit cannot
            // send twice: the sealer consumes the draft once.
            Err(SealFail::Unconfirmed) => {
                let msg = Msg::new("sui-error-unconfirmed");
                return self.confirm_page(rq, k, Phase::Confirming, Screen::Confirm, Some(msg));
            }
            Err(_) => {
                let msg = Msg::new("sui-error-not-sent");
                return self.confirm_page(rq, k, Phase::Confirming, Screen::Confirm, Some(msg));
            }
        }
        let _ = self.with_session(&k, |s| {
            s.phase = Phase::Submitted;
            s.sent = Some((today, delayed));
        });
        // No token rotation here: `Submitted` grants the session nothing new
        // (it can only re-render S10s; the inbox needs a login, which makes a
        // new session and token), and the unchanged token keeps a retried
        // submit after a lost response idempotent (SPEC-NOTES decision 4).
        // Nothing more to do in the sealer for this session.
        self.zeroize(k.sealer).await;
        self.sent_page(rq, k)
    }

    /// Rotate the session's CSRF token on an authority or privilege change
    /// (lead decision 3). A CSPRNG failure ends the session (fail closed: the
    /// old token must not stay valid).
    fn rotate_token(&self, k: &SessionKeysRef) -> Result<(), Fail> {
        match self.with_session(k, WebSession::rotate_csrf) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => {
                self.sessions.remove(&k.table);
                Err(Fail::Error)
            }
            Err(f) => Err(f),
        }
    }

    fn busy_at_submit(&self, rq: &Rq<'_>) -> Reply {
        let out = self.out_any(rq);
        self.page(rq, out, Screen::Busy, |vm| {
            vm.busy.retry = Some(Route::Submit);
            vm.busy.at_submit = true;
        })
    }

    fn sent_page(&self, rq: &Rq<'_>, k: SessionKeysRef) -> Reply {
        let Ok((out, sent)) =
            self.with_session(&k, |s| (Self::out_session(s, Instant::now()), s.sent))
        else {
            return self.fail(rq, Fail::Gone);
        };
        let Some((day, delayed)) = sent else {
            return self.fail(rq, Fail::Error);
        };
        let Some(d) = ui_day(day) else {
            return self.fail(rq, Fail::Error);
        };
        self.page(rq, out, Screen::Sent, |vm| {
            vm.sent = Some(ui::SentData { sent: d, delayed });
        })
    }

    /// SW-22: re-entry of the current passphrase, then a new one.
    async fn post_rotate(&self, rq: &Rq<'_>, k: SessionKeysRef, form: &Form) -> Reply {
        let wrong = |me: &Self| {
            let Ok(out) = me.with_session(&k, |s| Self::out_session(s, Instant::now())) else {
                return me.fail(rq, Fail::Gone);
            };
            let err = Self::field_error("passphrase", "sui-login-err-auth");
            me.page(rq, out, Screen::RotateExplain, |vm| vm.ctx.errors.push(err))
        };
        let Ok(norm) = normalize(form.get("passphrase").unwrap_or_default()) else {
            return wrong(self);
        };
        // Derive under a throw-away handle and compare the locator in
        // constant time with the signed-in account's.
        let mut tmp = [0u8; 16];
        if random(&mut tmp).is_err() {
            return self.fail(rq, Fail::Error);
        }
        let tmp = SessionHandle(tmp);
        let derive = Request::LoginDerive {
            sess: tmp,
            passphrase: SecretBytes::from_slice(norm.as_bytes()),
        };
        drop(norm);
        let r = self.call(&derive, SEALER_KDF_TIMEOUT).await;
        self.zeroize(tmp).await;
        let tag = match r {
            Ok(Response::Locator { lookup_tag }) => Zeroizing::new(lookup_tag),
            Ok(_) => return self.fail(rq, Fail::Error),
            Err(e) => return self.seal_fail(rq, e),
        };
        let same = self
            .with_session(&k, |s| {
                s.lookup_tag
                    .as_ref()
                    .is_some_and(|t| candor_core::kdf::ct_eq(t.as_ref(), tag.as_ref()))
            })
            .unwrap_or(false);
        if !same {
            return wrong(self);
        }
        self.gen_phrase(rq, k, true).await
    }

    /// SW-28: confirm the new passphrase and finish the rotation.
    async fn post_rotate_confirm(&self, rq: &Rq<'_>, k: SessionKeysRef, form: &Form) -> Reply {
        match self.confirm_words(k, form).await {
            Ok(None) => {}
            Ok(Some(p)) => {
                let _ = self.with_session(&k, |s| s.confirm.positions = p);
                return self.confirm_page(
                    rq,
                    k,
                    Phase::RotateConfirming,
                    Screen::RotateConfirm,
                    Some(Msg::new("sui-confirm-mismatch")),
                );
            }
            Err(SealFail::Page(Fail::Gone)) => {
                // Only the pending rotation was dropped; the session stays.
                let _ = self.with_session(&k, |s| s.phase = Phase::SignedIn);
                let Ok(out) = self.with_session(&k, |s| Self::out_session(s, Instant::now()))
                else {
                    return self.fail(rq, Fail::Gone);
                };
                let msg = Msg::new("sui-confirm-exhausted");
                return self.page(rq, out, Screen::RotateExplain, |vm| {
                    vm.ctx.page_error = Some(msg)
                });
            }
            Err(e) => return self.seal_fail(rq, e),
        }
        let account: Option<AccountId> = self.with_session(&k, |s| s.account).ok().flatten();
        let Some(account) = account else {
            return self.fail(rq, Fail::Gone);
        };
        let replies: Vec<StoredReply> = match self.store.mailbox(account).await {
            Ok(r) => {
                self.note_store(true);
                r
            }
            Err(_) => {
                self.note_store(false);
                return self.fail(rq, Fail::Busy);
            }
        };
        let pending: Vec<PendingReply> = replies
            .iter()
            .take(sp::MAX_ROTATE_REPLIES)
            .filter_map(|r| pending_reply(&r.reply_ct))
            .collect();
        let fin = Request::RotateFinish {
            sess: k.sealer,
            replies: pending,
        };
        let tag = match self.call(&fin, SEALER_SEAL_TIMEOUT).await {
            Ok(Response::Locator { lookup_tag }) => Zeroizing::new(lookup_tag),
            Ok(_) => return self.fail(rq, Fail::Error),
            Err(SealFail::NoReader(alt)) => return self.no_reader(rq, alt),
            Err(e) => return self.seal_fail(rq, e),
        };
        let _ = self.with_session(&k, |s| {
            s.lookup_tag = Some(tag);
            s.phase = Phase::SignedIn;
        });
        // New authority: new CSRF token (fail closed).
        if let Err(f) = self.rotate_token(&k) {
            return self.fail(rq, f);
        }
        let Ok(out) = self.with_session(&k, |s| Self::out_session(s, Instant::now())) else {
            return self.fail(rq, Fail::Gone);
        };
        self.page(rq, out, Screen::RotateDone, |_| ())
    }

    async fn send_followup(
        &self,
        k: SessionKeysRef,
        text: &str,
        delayed: bool,
    ) -> Result<(), SealFail> {
        let msg = SecretText::new(text);
        self.put_draft(
            k.sealer,
            sp::Mode::Anonymous,
            &msg,
            &Fields::new(),
            None,
            None,
        )
        .await?;
        let seal = Request::SealFinish {
            sess: k.sealer,
            delayed_delivery: delayed,
        };
        match self.call(&seal, SEALER_SEAL_TIMEOUT).await? {
            Response::Sealed { .. } => Ok(()),
            _ => Err(SealFail::Page(Fail::Error)),
        }
    }

    /// SW-12 / SW-14: follow-up messages and S12 navigation.
    async fn post_conversation(&self, rq: &Rq<'_>, k: SessionKeysRef, form: &Form) -> Reply {
        if let Some(d) = form.get("delayed_delivery") {
            let _ = self.with_session(&k, |s| s.delayed = d == "true");
        }
        let delayed = self.with_session(&k, |s| s.delayed).unwrap_or(false);
        let posted = form.get("text");
        // A piece of a long draft is spliced into the stored text first,
        // before any action (source-ui contract item 3).
        let text: Option<Zeroizing<String>> =
            match (posted, form.get("piece").and_then(ui::parse_piece)) {
                (Some(t), Some(p)) => {
                    let v = match self.draft(k.sealer).await {
                        Ok(v) => v,
                        Err(e) => return self.seal_fail(rq, e),
                    };
                    let Ok(key) = self.with_session(&k, |s| s.piece_key()) else {
                        return self.fail(rq, Fail::Gone);
                    };
                    match ui::splice_piece(&key, "text", v.message.expose(), &p, t) {
                        Ok(s) => Some(Zeroizing::new(s.as_str().to_owned())),
                        Err(_) => {
                            let err = Self::field_error("text", "sui-conv-err-empty");
                            let kept = Zeroizing::new(t.to_owned());
                            return self
                                .conversation(rq, k, |vm| {
                                    vm.ctx.errors.push(err);
                                    vm.ctx.text_kept = true;
                                    vm.conversation.draft_text = kept;
                                })
                                .await;
                        }
                    }
                }
                (Some(t), None) => Some(Zeroizing::new(t.to_owned())),
                (None, _) => None,
            };
        match form.get("action") {
            Some("send") => {
                let Some(t) = text.filter(|t| !t.trim().is_empty()) else {
                    let err = Self::field_error("text", "sui-conv-err-empty");
                    return self.conversation(rq, k, |vm| vm.ctx.errors.push(err)).await;
                };
                match self.send_followup(k, &t, delayed).await {
                    Ok(()) => {
                        self.conversation(rq, k, |vm| vm.conversation.just_sent = true)
                            .await
                    }
                    Err(SealFail::NoReader(alt)) => {
                        let label = self
                            .cfg
                            .site
                            .channels
                            .iter()
                            .find(|c| Some(c.id) == alt || c.option.independent_route)
                            .map(|c| c.option.name.clone());
                        let kept = t.clone();
                        self.conversation(rq, k, |vm| {
                            vm.conversation.refused_route = label;
                            vm.conversation.draft_text = kept;
                            vm.ctx.text_kept = true;
                        })
                        .await
                    }
                    Err(SealFail::Limit) => {
                        let err = FieldError {
                            field: "text".to_owned(),
                            message: Msg::new("sui-q-err-too-long").arg("max", 40_960u32),
                        };
                        let kept = t.clone();
                        self.conversation(rq, k, |vm| {
                            vm.ctx.errors.push(err);
                            vm.conversation.draft_text = kept;
                            vm.ctx.text_kept = true;
                        })
                        .await
                    }
                    Err(e) => self.seal_fail(rq, e),
                }
            }
            // SW-14 needs a K31-signed store deletion the web cannot make
            // (SPEC-NOTES open item O-1): refused uniformly.
            Some("reply-delete") => self.fail(rq, Fail::Error),
            Some(_) => self.fail(rq, Fail::Error),
            None => {
                // Part / page navigation: keep the draft text in sealer RAM.
                if let Some(t) = text {
                    let r = self
                        .put_draft(
                            k.sealer,
                            sp::Mode::Anonymous,
                            &SecretText::new(&t),
                            &Fields::new(),
                            None,
                            None,
                        )
                        .await;
                    if let Err(e) = r {
                        return self.seal_fail(rq, e);
                    }
                }
                let part = parse_u16(form.get("part")).unwrap_or(0);
                let draft = match self.draft(k.sealer).await {
                    Ok(v) => Zeroizing::new(v.message.expose().to_owned()),
                    Err(e) => return self.seal_fail(rq, e),
                };
                self.conversation(rq, k, |vm| {
                    vm.ctx.part = part;
                    vm.conversation.draft_text = draft;
                })
                .await
            }
        }
    }

    // --------------------------------------------------------------- upload

    /// SW-06 / SW-13: one file per request, streamed to the sealer in
    /// ≤ 64 KiB chunks; the CSRF token must be the first part (checked
    /// before any byte is forwarded); no filename on disk, no sniffing.
    async fn upload(
        &self,
        rq: &Rq<'_>,
        route: Route,
        boundary: &str,
        body: &mut BodyReader,
    ) -> Reply {
        let k = match self.require_session(rq) {
            Ok(k) => k,
            Err(f) => return self.fail(rq, f),
        };
        let Ok(phase) = self.with_session(&k, |s| s.phase) else {
            return self.fail(rq, Fail::Gone);
        };
        let screen = match (route, phase) {
            (Route::Files, Phase::Drafting) => Screen::Files,
            (Route::Conversation, Phase::SignedIn) => Screen::Conversation,
            _ => return self.fail(rq, Fail::NotFound),
        };
        if !self
            .limiter
            .allow(rq.circuit, Class::Upload, Instant::now())
        {
            return self.fail(rq, Fail::Busy);
        }
        // AUD-RM2-WEB-07: a bounded number of uploads service-wide, and one
        // at a time per session; both are released when this returns.
        let Ok(_slot) = Arc::clone(&self.uploads).try_acquire_owned() else {
            return self.fail(rq, Fail::Busy);
        };
        match self.with_session(&k, |s| core::mem::replace(&mut s.uploading, true)) {
            Ok(false) => {}
            Ok(true) => return self.fail(rq, Fail::Busy),
            Err(f) => return self.fail(rq, f),
        }
        let _one = UploadFlag {
            sessions: &self.sessions,
            table: k.table,
        };
        body.allow_upload_time();
        let declared = body.content_length();
        let r = self.upload_inner(rq, k, boundary, body, declared).await;
        let err = match r {
            Ok(()) => None,
            Err(UploadFail::Page(f)) => return self.fail(rq, f),
            Err(UploadFail::Field(key)) => Some(key),
        };
        let max = self.cfg.max_file_bytes;
        let files = self.cfg.max_files;
        let fill = move |vm: &mut ViewModel| {
            if let Some(key) = err {
                let mut m = Msg::new(key);
                if key == "sui-files-err-too-large" {
                    m = m
                        .arg("max_file", ui::Arg::Num(max))
                        .arg("max_total", ui::Arg::Num(max));
                } else if key == "sui-files-err-count" {
                    m = m.arg("max_files", files);
                }
                vm.ctx.errors.push(FieldError {
                    field: "file".to_owned(),
                    message: m,
                });
            }
        };
        if screen == Screen::Files {
            self.draft_screen(rq, k, screen, fill).await
        } else {
            self.conversation(rq, k, fill).await
        }
    }

    async fn upload_inner(
        &self,
        rq: &Rq<'_>,
        k: SessionKeysRef,
        boundary: &str,
        body: &mut BodyReader,
        declared: u64,
    ) -> Result<(), UploadFail> {
        // Size from Content-Length; reported only after the token part has
        // been checked (AUD-RM2-WEB-08: no session-dependent output before
        // CSRF), and before any file byte is read or forwarded.
        let overhead: u64 = 64 * 1024;
        let too_large = declared > self.cfg.max_file_bytes.saturating_add(overhead);
        let mut mp = Multipart::new(boundary);
        let mut state = UpState::ExpectCsrf;
        let mut csrf = Zeroizing::new(String::new());
        let mut part: Option<[u8; 16]> = None;
        let mut held: Option<Zeroizing<Vec<u8>>> = None;
        let mut pending_file: Option<(Zeroizing<String>, Zeroizing<String>)> = None;
        let mut action_ok = false;
        let mut cur = String::new();
        let res: Result<(), UploadFail> = async {
            loop {
                while let Some(ev) = mp.next_event().map_err(|_| UploadFail::Page(Fail::Error))? {
                    match ev {
                        Event::Part(h) => {
                            cur = h.name.clone();
                            match (state, h.name.as_str(), h.filename) {
                                (UpState::ExpectCsrf, "csrf", None) => {}
                                (UpState::AfterCsrf, "file", Some(name)) => {
                                    if part.is_some() || pending_file.is_some() {
                                        return Err(UploadFail::Page(Fail::Error));
                                    }
                                    let ct = h.content_type.unwrap_or_else(|| {
                                        Zeroizing::new("application/octet-stream".to_owned())
                                    });
                                    pending_file = Some((name, ct));
                                }
                                (UpState::AfterCsrf, "neutral_names" | "action", None) => {}
                                _ => return Err(UploadFail::Page(Fail::Error)),
                            }
                        }
                        Event::Data(d) => match cur.as_str() {
                            "csrf" => {
                                if csrf.len().saturating_add(d.len()) > 64 {
                                    return Err(UploadFail::Page(Fail::Error));
                                }
                                csrf.push_str(
                                    core::str::from_utf8(&d)
                                        .map_err(|_| UploadFail::Page(Fail::Error))?,
                                );
                            }
                            "file" => {
                                if part.is_none() {
                                    // First bytes: count check, then PART_BEGIN.
                                    let v = self.draft(k.sealer).await.map_err(map_seal)?;
                                    if v.parts.len()
                                        >= usize::try_from(self.cfg.max_files).unwrap_or(0)
                                    {
                                        return Err(UploadFail::Field("sui-files-err-count"));
                                    }
                                    let (name, ct) =
                                        pending_file.take().ok_or(UploadFail::Page(Fail::Error))?;
                                    let begin = Request::PartBegin {
                                        sess: k.sealer,
                                        declared_len: declared,
                                        display_name: SecretText::new(&name),
                                        media_type: SecretText::new(&ct),
                                    };
                                    match self
                                        .call(&begin, SEALER_OP_TIMEOUT)
                                        .await
                                        .map_err(map_seal)?
                                    {
                                        Response::Part { part: p } => part = Some(p),
                                        _ => return Err(UploadFail::Page(Fail::Error)),
                                    }
                                }
                                if let Some(prev) = held.replace(d) {
                                    self.chunk(k, part, prev, false).await?;
                                }
                            }
                            "neutral_names" => {}
                            "action" => action_ok = d.as_slice() == b"upload",
                            _ => return Err(UploadFail::Page(Fail::Error)),
                        },
                        Event::PartEnd => {
                            if cur == "csrf" {
                                // The token gates everything after it.
                                self.check_csrf(rq, PostAuth::Session, Some(&csrf))
                                    .map_err(UploadFail::Page)?;
                                if too_large {
                                    return Err(UploadFail::Field("sui-files-err-too-large"));
                                }
                                state = UpState::AfterCsrf;
                            } else if cur == "file" {
                                match held.take() {
                                    Some(last) => self.chunk(k, part, last, true).await?,
                                    None => return Err(UploadFail::Field("sui-files-err-empty")),
                                }
                            }
                        }
                        Event::End => {}
                    }
                }
                if mp.finished() {
                    break;
                }
                let room = mp.room().min(UPLOAD_CHUNK);
                match body.next(room).await {
                    Ok(Some(b)) => mp.feed(&b).map_err(|_| UploadFail::Page(Fail::Error))?,
                    Ok(None) => {
                        mp.finish()
                            .map_err(|_| UploadFail::Field("sui-files-err-stopped"))?;
                        break;
                    }
                    Err(_) => return Err(UploadFail::Field("sui-files-err-stopped")),
                }
            }
            // Trailing bytes after the closing delimiter.
            if let Ok(Some(rest)) = body.next(16).await
                && !rest.is_empty()
            {
                mp.feed(&rest).map_err(|_| UploadFail::Page(Fail::Error))?;
                mp.finish().map_err(|_| UploadFail::Page(Fail::Error))?;
            }
            if state != UpState::AfterCsrf || !action_ok {
                return Err(UploadFail::Page(Fail::Error));
            }
            if part.is_none() {
                return Err(UploadFail::Field("sui-files-err-empty"));
            }
            Ok(())
        }
        .await;
        if res.is_err()
            && let Some(p) = part
        {
            // Never keep half a file.
            let _ = self
                .simple(Request::PartDrop {
                    sess: k.sealer,
                    part: p,
                })
                .await;
        }
        res
    }

    async fn chunk(
        &self,
        k: SessionKeysRef,
        part: Option<[u8; 16]>,
        data: Zeroizing<Vec<u8>>,
        last: bool,
    ) -> Result<(), UploadFail> {
        let part = part.ok_or(UploadFail::Page(Fail::Error))?;
        let req = Request::PartChunk {
            sess: k.sealer,
            part,
            data: SecretBytes(data),
            last,
        };
        match self.call(&req, SEALER_OP_TIMEOUT).await.map_err(map_seal)? {
            Response::Empty => Ok(()),
            _ => Err(UploadFail::Page(Fail::Error)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpState {
    ExpectCsrf,
    AfterCsrf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UploadFail {
    Page(Fail),
    Field(&'static str),
}

fn map_seal(e: SealFail) -> UploadFail {
    match e {
        SealFail::Page(f) => UploadFail::Page(f),
        SealFail::Limit => UploadFail::Field("sui-files-err-too-large"),
        SealFail::NoReader(_) | SealFail::Unconfirmed => UploadFail::Page(Fail::Busy),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn civil_dates() {
        assert_eq!(ui_day(0).unwrap().to_string(), "1970-01-01");
        assert_eq!(ui_day(20_362).unwrap().to_string(), "2025-10-01");
        assert_eq!(ui_day(20_727).unwrap().to_string(), "2026-10-01");
        assert_eq!(ui_day(11_016).unwrap().to_string(), "2000-02-29");
        assert!(ui_day(u32::MAX).is_none());
    }

    #[test]
    fn word_lookup_scans_the_list() {
        let l = Wordlist::eff_large().unwrap();
        assert_eq!(word_index(l, "abacus"), 0);
        assert_eq!(word_index(l, " ZOOM "), 7771);
        assert_eq!(word_index(l, "notaword"), u16::MAX);
    }

    #[test]
    fn identity_roundtrip() {
        let b = identity_block("A Name", "Role", Some("Signal"));
        let d = identity_data(Some(&SecretText::new(&b)), ui::Mode::Confidential);
        assert_eq!((d.full_name.as_str(), d.role.as_str()), ("A Name", "Role"));
        assert!(d.contact_other);
        assert_eq!(d.contact_other_value.as_str(), "Signal");
    }

    #[test]
    fn entry_framing() {
        let e = entry_of(&[1, 2, 3]).unwrap();
        assert_eq!(e, vec![0, 0, 0, 3, 1, 2, 3]);
        assert!(entry_of(&vec![0u8; sp::MAX_REPLY_ENTRY_LEN]).is_none());
        assert!(pending_reply(&[0u8; 10]).is_none());
    }
}
