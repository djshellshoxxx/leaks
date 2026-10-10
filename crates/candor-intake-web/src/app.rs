// SPDX-License-Identifier: AGPL-3.0-or-later
//! The service object, request context, page rendering and the route
//! dispatch with its security checks (deny by default, ADR-029; CSRF and
//! origin checks before any state change, 08 §3.7; uniform error pages,
//! 08 §3.4). The per-route flows are in `flows.rs`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use candor_source_ui::{
    self as ui, FieldError, Locale, Mode, Msg, Page, Route, Screen, SessionTimers, ViewModel,
};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

use crate::config::{ConfigError, DayClock, StoreReads, WebConfig, validate};
use crate::form::{Form, FormError, is_urlencoded, parse_form};
use crate::http::{Method, RequestHead, serialize_head};
use crate::limits::{MAX_CONNECTIONS, MAX_FORM_BODY, MAX_OVERFLOW_CONNECTIONS};
use crate::ratelimit::{CircuitToken, Class, Limiter};
use crate::routes::{self, PostAuth, RouteDecl};
use crate::sealer::{SealerClient, SealerError};
use crate::server::BodyReader;
use crate::session::{Lookup, Phase, Sessions, WebSession};
use crate::token::{
    PreSessionKey, SessionKeys, hex, origin_ok, pre_set_cookie, random, session_keys, token_eq,
    unhex32,
};

/// A response ready for the wire: the exact head and the padded body.
pub struct Reply {
    /// Serialized head (exactly the class head length).
    pub head: Zeroizing<Vec<u8>>,
    /// Padded body.
    pub body: ReplyBody,
}

impl core::fmt::Debug for Reply {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Reply([{} + {} bytes redacted])",
            self.head.len(),
            self.body.as_slice().len()
        )
    }
}

/// Body storage: rendered pages are zeroized on drop; static pages shared.
pub enum ReplyBody {
    /// A rendered page.
    Owned(Zeroizing<Vec<u8>>),
    /// A page shared between requests (contains nothing secret).
    Shared(Arc<[u8]>),
}

impl core::fmt::Debug for ReplyBody {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ReplyBody([{} bytes redacted])", self.as_slice().len())
    }
}

impl ReplyBody {
    /// The bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Owned(v) => v.as_slice(),
            Self::Shared(a) => a,
        }
    }
}

/// Last known reachability of the dependencies (coarse health for the
/// integrator; no counts, nothing source-derived beyond up/down).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Health {
    /// The last sealer call did not fail with "unavailable".
    pub sealer_up: bool,
    /// The last store call succeeded.
    pub store_up: bool,
}

/// Why a flow stopped: each maps to one uniform page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fail {
    /// Busy page (capacity, rate, sealer or store unavailable, clock).
    Busy,
    /// The session is gone (sealer forgot it): signed-out page.
    Gone,
    /// Uniform error page (CSRF, malformed, internal).
    Error,
    /// Uniform not-found page.
    NotFound,
}

/// The per-request view of the client: only what the specs allow us to use.
pub(crate) struct Rq<'a> {
    pub head: &'a RequestHead,
    pub method: ui::Method,
    pub locale: Locale,
    pub circuit: CircuitToken,
    pub received: Instant,
    /// Keys derived from a well-formed `__Host-cs` cookie.
    pub keys: Option<SessionKeys>,
    /// The session is live (checked once per request, idle timer reset).
    pub live: bool,
}

impl Rq<'_> {
    pub fn has_cookie(&self) -> bool {
        self.head.session_cookie_present
    }
}

/// What the page needs from the session layer.
pub(crate) struct Out {
    pub set_cookie: Option<Zeroizing<String>>,
    pub token: Zeroizing<String>,
    pub piece: Option<[u8; 32]>,
    pub timers: Option<SessionTimers>,
    pub mode: Mode,
    /// The response carries a session cookie class P2 even though the request
    /// had none (a newly created session answers a POST: P2 anyway).
    pub has_session: bool,
}

/// The Source Web Service.
pub struct Web<S: StoreReads> {
    pub(crate) cfg: WebConfig,
    pub(crate) origin: String,
    pub(crate) sealer: SealerClient,
    pub(crate) store: S,
    pub(crate) clock: Arc<dyn DayClock>,
    pub(crate) sessions: Sessions,
    pub(crate) limiter: Limiter,
    pub(crate) pre: PreSessionKey,
    /// Leave tokens of the cookie-clearing screens (AUD-RM2-WEB-04).
    pub(crate) leave: crate::token::LeaveTokens,
    pub(crate) started: Instant,
    pub(crate) serving: Arc<Semaphore>,
    pub(crate) overflow: Arc<Semaphore>,
    /// Uploads in progress (AUD-RM2-WEB-07).
    pub(crate) uploads: Arc<Semaphore>,
    fallback_p1: Arc<[u8]>,
    fallback_p2: Arc<[u8]>,
    sealer_up: AtomicBool,
    store_up: AtomicBool,
    /// Public key of a random throw-away key: the verification target for
    /// unknown locators, so both login paths do the same work (07 §5.3).
    pub(crate) dummy_pk: [u8; 32],
}

impl<S: StoreReads> core::fmt::Debug for Web<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Web")
    }
}

/// Fixed token in the last-resort error page (its forms cannot succeed).
const FALLBACK_TOKEN: &str = "0000000000000000000000000000000000000000000000000000000000000000";

impl<S: StoreReads + 'static> Web<S> {
    /// Build the service. Validates the configuration and renders the
    /// last-resort error pages once (start is refused if any fails).
    pub fn new(
        cfg: WebConfig,
        sealer: SealerClient,
        store: S,
        clock: Arc<dyn DayClock>,
    ) -> Result<Arc<Self>, ConfigError> {
        validate(&cfg)?;
        let now = Instant::now();
        let limiter = Limiter::new(cfg.global, now).map_err(|_| ConfigError("rng"))?;
        let pre = PreSessionKey::generate().map_err(|_| ConfigError("rng"))?;
        let leave = crate::token::LeaveTokens::generate().map_err(|_| ConfigError("rng"))?;
        let origin = cfg.origin();
        let mut web = Self {
            cfg,
            origin,
            sealer,
            store,
            clock,
            sessions: Sessions::new(),
            limiter,
            pre,
            leave,
            started: now,
            serving: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            overflow: Arc::new(Semaphore::new(MAX_OVERFLOW_CONNECTIONS)),
            uploads: Arc::new(Semaphore::new(crate::limits::MAX_CONCURRENT_UPLOADS)),
            fallback_p1: Arc::from(Vec::new()),
            fallback_p2: Arc::from(Vec::new()),
            sealer_up: AtomicBool::new(true),
            store_up: AtomicBool::new(true),
            dummy_pk: candor_core::sig::SigningKey::generate()
                .map_err(|_| ConfigError("rng"))?
                .verifying_key_bytes(),
        };
        web.fallback_p1 = web
            .fallback_page(ui::Method::Get, false)
            .ok_or(ConfigError("fallback page"))?;
        web.fallback_p2 = web
            .fallback_page(ui::Method::Post, true)
            .ok_or(ConfigError("fallback page"))?;
        // Every fixed page must render (start-time check, fail closed).
        for screen in [
            Screen::Landing,
            Screen::Safety,
            Screen::SafetyTips,
            Screen::Status,
        ] {
            let mut vm = web.base_vm(ui::Method::Get, false, Locale::En, None);
            web.fill_static(screen, &mut vm);
            vm.ctx.form_token = Some(Zeroizing::new(FALLBACK_TOKEN.to_owned()));
            ui::render(screen, &vm, &Locale::En).map_err(|_| ConfigError("site content"))?;
        }
        Ok(Arc::new(web))
    }

    /// Last known dependency reachability.
    #[must_use]
    pub fn health(&self) -> Health {
        Health {
            sealer_up: self.sealer_up.load(Ordering::Relaxed),
            store_up: self.store_up.load(Ordering::Relaxed),
        }
    }

    /// Remove expired sessions (also done on access); run periodically.
    pub fn reap(&self) -> usize {
        self.sessions.reap(Instant::now())
    }

    pub(crate) fn note_sealer(&self, r: &Result<candor_sealer::proto::Response, SealerError>) {
        self.sealer_up.store(
            !matches!(r, Err(SealerError::Unavailable)),
            Ordering::Relaxed,
        );
    }

    pub(crate) fn note_store(&self, ok: bool) {
        self.store_up.store(ok, Ordering::Relaxed);
    }

    fn fallback_page(&self, method: ui::Method, cookie: bool) -> Option<Arc<[u8]>> {
        let mut vm = self.base_vm(method, cookie, Locale::En, None);
        vm.ctx.form_token = Some(Zeroizing::new(FALLBACK_TOKEN.to_owned()));
        let mut page = ui::render(Screen::ServerError, &vm, &Locale::En).ok()?;
        ui::finalize_headers(&mut page, None).ok()?;
        let head = serialize_head(&page)?;
        let mut all = Vec::with_capacity(head.len().saturating_add(page.body.len()));
        all.extend_from_slice(&head);
        all.extend_from_slice(&page.body);
        Some(Arc::from(all))
    }

    /// The last-resort reply (status 500, the class of the request).
    pub(crate) fn fallback(&self, post_or_cookie: bool) -> Reply {
        let all = if post_or_cookie {
            &self.fallback_p2
        } else {
            &self.fallback_p1
        };
        let head_len = ui::SizeClass::P1.head_bytes();
        let head = Zeroizing::new(all.get(..head_len).unwrap_or_default().to_vec());
        let body: Arc<[u8]> = Arc::from(all.get(head_len..).unwrap_or_default());
        Reply {
            head,
            body: ReplyBody::Shared(body),
        }
    }

    pub(crate) fn secs(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    // ---------------------------------------------------------------- rendering

    pub(crate) fn base_vm(
        &self,
        method: ui::Method,
        cookie: bool,
        _locale: Locale,
        out: Option<&Out>,
    ) -> ViewModel {
        let mut vm = ViewModel::default();
        vm.ctx.method = method;
        vm.ctx.has_session_cookie = cookie;
        vm.ctx.org = self.cfg.site.org.clone();
        vm.ctx.banners = self.cfg.site.banners.clone();
        vm.deployment = self.cfg.site.deployment.clone();
        if let Some(o) = out {
            vm.ctx.mode = o.mode;
            vm.ctx.form_token = Some(o.token.clone());
            vm.ctx.piece_key = o.piece.map(ui::PieceKey::new);
            vm.ctx.session = o.timers;
        }
        vm
    }

    /// Static page data (S01, S03, S04).
    pub(crate) fn fill_static(&self, screen: Screen, vm: &mut ViewModel) {
        match screen {
            Screen::Landing => vm.landing = self.cfg.site.landing.clone(),
            Screen::Status => vm.status = self.cfg.site.status.clone(),
            Screen::NewReport => {
                vm.new_report.channels = self
                    .cfg
                    .site
                    .channels
                    .iter()
                    .map(|c| c.option.clone())
                    .collect();
            }
            _ => {}
        }
    }

    /// Context for a request without a live session: a pre-session token
    /// bound to the (reused or new) `__Host-cpre` cookie, which is (re)set.
    pub(crate) fn out_pre(&self, rq: &Rq<'_>) -> Result<Out, Fail> {
        let cpre = match rq.head.pre_cookie.as_ref() {
            Some(c) => Zeroizing::new(c.as_str().to_owned()),
            None => {
                let mut b = Zeroizing::new([0u8; 32]);
                random(b.as_mut()).map_err(|_| Fail::Error)?;
                hex(b.as_ref())
            }
        };
        Ok(Out {
            set_cookie: Some(pre_set_cookie(&cpre)),
            token: self.pre.token(&cpre, self.secs()),
            piece: None,
            timers: None,
            mode: Mode::Anonymous,
            has_session: false,
        })
    }

    pub(crate) fn out_session(s: &WebSession, now: Instant) -> Out {
        Out {
            set_cookie: None,
            token: Zeroizing::new(s.csrf.as_str().to_owned()),
            piece: Some(*s.piece_key),
            timers: Some(SessionTimers {
                abs_remaining_secs: s.abs_remaining_secs(now),
            }),
            mode: s.mode,
            has_session: true,
        }
    }

    /// The context for an error page: the live session's token if any, else
    /// a pre-session token.
    pub(crate) fn out_any(&self, rq: &Rq<'_>) -> Out {
        if let Some(k) = rq.keys.as_ref()
            && rq.live
            && let Ok(o) = self.sessions.with(&k.table, Instant::now(), false, |s| {
                Self::out_session(s, Instant::now())
            })
        {
            return o;
        }
        self.out_pre(rq).unwrap_or(Out {
            set_cookie: None,
            token: Zeroizing::new(FALLBACK_TOKEN.to_owned()),
            piece: None,
            timers: None,
            mode: Mode::Anonymous,
            has_session: false,
        })
    }

    /// Render `screen` with `fill` applied to the view model.
    pub(crate) fn page(
        &self,
        rq: &Rq<'_>,
        out: Out,
        screen: Screen,
        fill: impl FnOnce(&mut ViewModel),
    ) -> Reply {
        let mut out = out;
        if screen.clears_site_data() {
            // The cookies are gone after this response: the only form that
            // can still be posted (Leave) carries the leave token instead of
            // a session or pre-session token (same length, same size).
            // The Leave page itself has no form: nothing to issue.
            if screen != Screen::Leave {
                match self.leave.issue(Instant::now()) {
                    Ok(t) => out.token = t,
                    Err(_) => {
                        return self.fallback(rq.method == ui::Method::Post || rq.has_cookie());
                    }
                }
            }
        }
        let cookie = rq.has_cookie() || (out.has_session && rq.method == ui::Method::Post);
        let mut vm = self.base_vm(rq.method, cookie, rq.locale, Some(&out));
        self.fill_static(screen, &mut vm);
        fill(&mut vm);
        let fallback = || self.fallback(rq.method == ui::Method::Post || rq.has_cookie());
        let Ok(mut page) = ui::render(screen, &vm, &rq.locale) else {
            return fallback();
        };
        drop(vm);
        if ui::finalize_headers(&mut page, out.set_cookie.as_deref().map(String::as_str)).is_err() {
            return fallback();
        }
        Self::wire(page).unwrap_or_else(fallback)
    }

    fn wire(page: Page) -> Option<Reply> {
        let head = serialize_head(&page)?;
        let mut page = page;
        let body = core::mem::replace(&mut page.body, Zeroizing::new(Vec::new()));
        Some(Reply {
            head,
            body: ReplyBody::Owned(body),
        })
    }

    /// A static page that is not HTML (robots.txt) or a fixed document.
    fn robots(&self) -> Reply {
        let page = ui::robots_txt();
        Self::wire(page).unwrap_or_else(|| self.fallback(false))
    }

    /// The uniform page for a failure.
    pub(crate) fn fail(&self, rq: &Rq<'_>, f: Fail) -> Reply {
        let out = self.out_any(rq);
        match f {
            Fail::Busy => {
                let retry = (rq.method == ui::Method::Post)
                    .then(|| {
                        rq.head
                            .path
                            .as_deref()
                            .and_then(routes::lookup)
                            .map(|(_, d)| d.route)
                    })
                    .flatten();
                self.page(rq, out, Screen::Busy, |vm| vm.busy.retry = retry)
            }
            Fail::Gone => {
                if let Some(k) = rq.keys.as_ref() {
                    self.sessions.remove(&k.table);
                }
                self.page(rq, out, Screen::SignedOut, |_| ())
            }
            Fail::Error => self.page(rq, out, Screen::ServerError, |_| ()),
            Fail::NotFound => self.page(rq, out, Screen::NotFound, |_| ()),
        }
    }

    /// A field error on a page.
    pub(crate) fn field_error(field: &str, key: &'static str) -> FieldError {
        FieldError {
            field: field.to_owned(),
            message: Msg::new(key),
        }
    }

    // ------------------------------------------------------------ dispatch

    /// Handle one parsed request. Returns the reply and the body reader (for
    /// draining unread bytes after the response).
    pub(crate) async fn handle(
        self: Arc<Self>,
        head: RequestHead,
        circuit: CircuitToken,
        received: Instant,
        mut body: BodyReader,
    ) -> (Reply, BodyReader) {
        let reply = self.dispatch(&head, circuit, received, &mut body).await;
        (reply, body)
    }

    async fn dispatch(
        &self,
        head: &RequestHead,
        circuit: CircuitToken,
        received: Instant,
        body: &mut BodyReader,
    ) -> Reply {
        let method = match head.method {
            Method::Get => ui::Method::Get,
            Method::Head => ui::Method::Head,
            Method::Post => ui::Method::Post,
        };
        let keys = head
            .session_cookie
            .as_ref()
            .and_then(|c| unhex32(c))
            .map(|cs| session_keys(&cs));
        let now = Instant::now();
        let live = keys
            .as_ref()
            .is_some_and(|k| self.sessions.with(&k.table, now, true, |_| ()).is_ok());
        let path = head.path.as_deref();
        let locale = path
            .and_then(|p| p.strip_prefix('/'))
            .and_then(|p| p.split('/').next())
            .and_then(Locale::from_tag)
            .unwrap_or(Locale::En);
        let rq = Rq {
            head,
            method,
            locale,
            circuit,
            received,
            keys,
            live,
        };
        // Every request costs one token of the per-circuit and global
        // request buckets (07 §11, 16 §13 L4).
        if !self.limiter.allow(circuit, Class::Request, now) {
            return self.fail(&rq, Fail::Busy);
        }
        // Routes outside /{lang}/.
        match path {
            Some("/robots.txt") if method != ui::Method::Post => return self.robots(),
            Some("/.well-known/candor/manifest") if method != ui::Method::Post => {
                return match self.cfg.manifest.as_ref() {
                    Some(m) => manifest_reply(m),
                    None => self.fail(&rq, Fail::NotFound),
                };
            }
            Some("/.well-known/candor/health") if method != ui::Method::Post => {
                return self.health_reply(&rq);
            }
            _ => {}
        }
        let Some((_, decl)) = path.and_then(routes::lookup) else {
            return self.fail(&rq, Fail::NotFound);
        };
        // 07 §11 / 11 §5.4 rule 7: every POST response of the login and
        // rotation routes (SW-10, SW-22, SW-28) is released no earlier than
        // the floor, whatever the outcome: success, wrong passphrase, unknown
        // account, malformed form, CSRF failure, rate limit or busy.
        if method == ui::Method::Post
            && matches!(
                decl.route,
                Route::Login | Route::Inbox | Route::RotateConfirm
            )
        {
            // AUD-RM2-WEB-06: the floor runs from the end of the full
            // request (head and body), not from accept.
            body.buffer_all(crate::limits::MAX_FORM_BODY).await;
            let complete = Instant::now().max(received);
            let reply = self.dispatch_route(&rq, decl, now, body).await;
            self.login_floor(complete).await;
            return reply;
        }
        self.dispatch_route(&rq, decl, now, body).await
    }

    async fn dispatch_route(
        &self,
        rq: &Rq<'_>,
        decl: &'static RouteDecl,
        now: Instant,
        body: &mut BodyReader,
    ) -> Reply {
        let head = rq.head;
        let method = rq.method;
        let circuit = rq.circuit;
        match method {
            ui::Method::Get | ui::Method::Head => {
                if !decl.get {
                    return self.page(rq, self.out_any(rq), Screen::MethodNotAllowed, |_| ());
                }
                self.get(rq, decl).await
            }
            ui::Method::Post => {
                let Some(post) = decl.post else {
                    return self.page(rq, self.out_any(rq), Screen::MethodNotAllowed, |_| ());
                };
                // 08 §3.7 + tightening: before anything else (no body read).
                if !origin_ok(&head.origin, head.fetch_site, &self.origin) {
                    return self.fail(rq, Fail::Error);
                }
                if let Some(c) = post.rate
                    && !self.limiter.allow(circuit, c, now)
                {
                    return self.fail(rq, Fail::Busy);
                }
                self.post(rq, decl, post.auth, body).await
            }
        }
    }

    fn health_reply(&self, rq: &Rq<'_>) -> Reply {
        // A fixed P1 page that never touches the sealer or the store
        // (16 §15): the landing page without any session context.
        let out = Out {
            set_cookie: None,
            token: Zeroizing::new(FALLBACK_TOKEN.to_owned()),
            piece: None,
            timers: None,
            mode: Mode::Anonymous,
            has_session: false,
        };
        let rq2 = Rq {
            head: rq.head,
            method: ui::Method::Get,
            locale: Locale::En,
            circuit: rq.circuit,
            received: rq.received,
            keys: None,
            live: false,
        };
        let mut r = self.page(&rq2, out, Screen::Landing, |_| ());
        if rq.method == ui::Method::Head {
            r.body = ReplyBody::Shared(Arc::from(Vec::new()));
        }
        r
    }

    /// Read and parse a URL-encoded body for `route`, then check the CSRF
    /// token. Returns the form and whether the request runs in a live session.
    pub(crate) async fn read_form(
        &self,
        rq: &Rq<'_>,
        decl: &RouteDecl,
        auth: PostAuth,
        body: &mut BodyReader,
    ) -> Result<Form, FormFail> {
        let ct = rq.head.content_type.as_deref().unwrap_or_default();
        if !is_urlencoded(ct) {
            return Err(FormFail::Page(Fail::Error));
        }
        let raw = body
            .read_all(MAX_FORM_BODY)
            .await
            .map_err(|_| FormFail::Page(Fail::Error))?;
        let route = decl.route;
        let form = match parse_form(&raw, &|n| routes::rule(route, n)) {
            Ok(f) => f,
            Err(FormError::TooLong(f) | FormError::Invalid(f)) => {
                // The token must still be checked before we show anything
                // that depends on the session: re-parse leniently is not
                // possible, so a field error is reported only with a valid
                // token (checked by the caller from the raw body).
                let tok = csrf_from_raw(&raw);
                self.check_csrf(rq, auth, tok.as_deref().map(String::as_str))
                    .map_err(FormFail::Page)?;
                return Err(FormFail::Field(f));
            }
            Err(_) => return Err(FormFail::Page(Fail::Error)),
        };
        self.check_csrf(rq, auth, form.get("csrf"))
            .map_err(FormFail::Page)?;
        Ok(form)
    }

    /// CSRF: a live session needs its token; otherwise a route that allows
    /// pre-session posts needs the pre-session token bound to the cookie.
    pub(crate) fn check_csrf(
        &self,
        rq: &Rq<'_>,
        auth: PostAuth,
        posted: Option<&str>,
    ) -> Result<(), Fail> {
        let posted = posted.unwrap_or_default();
        if rq.live
            && let Some(k) = rq.keys.as_ref()
        {
            let ok = self
                .sessions
                .with(&k.table, Instant::now(), false, |s| {
                    token_eq(posted, &s.csrf)
                })
                .map_err(|_| Fail::Gone)?;
            return if ok { Ok(()) } else { Err(Fail::Error) };
        }
        match auth {
            PostAuth::Session => {
                if rq.has_cookie() {
                    Err(Fail::Gone)
                } else {
                    Err(Fail::Error)
                }
            }
            // AUD-RM2-WEB-03: a stale session cookie (idle expiry, an
            // unhonoured Clear-Site-Data) must never turn the Leave panic
            // button into an error. Without a live session Leave changes no
            // state, so the Leave page is rendered whatever token the page
            // the source was on carried (its session token is gone).
            PostAuth::Leave if rq.has_cookie() => Ok(()),
            PostAuth::Leave if rq.head.pre_cookie.is_none() => {
                if self.leave.verify(posted, Instant::now()) {
                    Ok(())
                } else {
                    Err(Fail::Error)
                }
            }
            PostAuth::PreOrSession | PostAuth::Leave => {
                let Some(cpre) = rq.head.pre_cookie.as_ref() else {
                    return Err(Fail::Error);
                };
                if self.pre.verify(cpre, posted, self.secs()) {
                    Ok(())
                } else {
                    Err(Fail::Error)
                }
            }
        }
    }

    /// The live session's handle, or the failure for a request without one.
    pub(crate) fn require_session(&self, rq: &Rq<'_>) -> Result<SessionKeysRef, Fail> {
        match rq.keys.as_ref() {
            Some(k) if rq.live => Ok(SessionKeysRef {
                table: k.table,
                sealer: k.sealer,
            }),
            Some(_) => Err(Fail::Gone),
            None if rq.has_cookie() => Err(Fail::Gone),
            None => Err(Fail::NotFound),
        }
    }

    /// Run `f` on the live session.
    pub(crate) fn with_session<T>(
        &self,
        k: &SessionKeysRef,
        f: impl FnOnce(&mut WebSession) -> T,
    ) -> Result<T, Fail> {
        self.sessions
            .with(&k.table, Instant::now(), false, f)
            .map_err(|e| match e {
                Lookup::Gone | Lookup::Live => Fail::Gone,
            })
    }

    /// Create a new session: fresh `cs`, its keys and the `Set-Cookie`.
    pub(crate) fn new_session(
        &self,
        phase: Phase,
    ) -> Result<(SessionKeysRef, Zeroizing<String>, WebSession), Fail> {
        let mut cs = Zeroizing::new([0u8; 32]);
        random(cs.as_mut()).map_err(|_| Fail::Error)?;
        let keys = session_keys(&cs);
        let cookie = crate::token::session_set_cookie(&hex(cs.as_ref()));
        let s = WebSession::new(phase, Instant::now()).map_err(|_| Fail::Error)?;
        Ok((
            SessionKeysRef {
                table: keys.table,
                sealer: keys.sealer,
            },
            cookie,
            s,
        ))
    }

    /// Wait for the login floor: release at `max(complete + floor, now) +
    /// U(0, 250 ms)`, where `complete` is when the full request was received
    /// and `now` is when the work finished (07 §11; 11 §5.4 rule 7;
    /// AUD-RM2-WEB-06). The jitter is always added, also when the work ran
    /// past the floor, so the release time never shows the work's duration
    /// exactly.
    pub(crate) async fn login_floor(&self, complete: Instant) {
        let mut b = [0u8; 2];
        let jitter = if random(&mut b).is_ok() {
            u64::from(u16::from_le_bytes(b))
                .checked_rem(crate::limits::LOGIN_JITTER_MS.saturating_add(1))
                .unwrap_or(0)
        } else {
            crate::limits::LOGIN_JITTER_MS
        };
        let release = floor_release(complete, self.cfg.login_floor, Instant::now(), jitter);
        if let Some(t) = release {
            tokio::time::sleep_until(t.into()).await;
        }
    }
}

/// Release time of a floored response (AUD-RM2-WEB-06):
/// `max(complete + floor, done) + jitter_ms`; the jitter is added in both
/// cases, so a release never equals the end of the work exactly.
pub(crate) fn floor_release(
    complete: Instant,
    floor: Duration,
    done: Instant,
    jitter_ms: u64,
) -> Option<Instant> {
    complete
        .checked_add(floor)
        .map(|f| f.max(done))
        .and_then(|t| t.checked_add(Duration::from_millis(jitter_ms)))
}

#[cfg(test)]
mod floor_tests {
    #![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
    use super::*;

    #[test]
    fn floor_then_jitter_on_every_path() {
        let t0 = Instant::now();
        let floor = Duration::from_secs(3);
        // Work inside the floor: floor + jitter from the complete request.
        let r = floor_release(t0, floor, t0 + Duration::from_secs(1), 120).unwrap();
        assert_eq!(r, t0 + floor + Duration::from_millis(120));
        // Work past the floor: the jitter still follows the work.
        let done = t0 + Duration::from_secs(5);
        let r = floor_release(t0, floor, done, 80).unwrap();
        assert_eq!(r, done + Duration::from_millis(80));
        assert!(r > done);
    }
}

/// Handle copied out of [`SessionKeys`] (both values are needed per request).
#[derive(Clone, Copy)]
pub(crate) struct SessionKeysRef {
    pub table: [u8; 32],
    pub sealer: candor_sealer::proto::SessionHandle,
}

/// A failed form read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FormFail {
    /// Uniform page.
    Page(Fail),
    /// A text field over its limit or with forbidden characters (token OK).
    Field(&'static str),
}

/// Find `csrf=<token>` in a raw body without validating the other fields
/// (tokens are `[0-9a-f]{64}`; anything else is "absent").
fn csrf_from_raw(raw: &[u8]) -> Option<Zeroizing<String>> {
    raw.split(|b| *b == b'&').find_map(|p| {
        let v = p.strip_prefix(b"csrf=")?;
        crate::http::valid_cookie_value(v)
            .then(|| {
                core::str::from_utf8(v)
                    .ok()
                    .map(|s| Zeroizing::new(s.to_owned()))
            })
            .flatten()
    })
}

fn manifest_reply(m: &Arc<[u8]>) -> Reply {
    // SW-23: byte-exact, identical for everyone, exempt from P1/P2 padding;
    // fixed header set without cookie or date.
    let mut head = Zeroizing::new(Vec::with_capacity(256));
    head.extend_from_slice(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: ",
    );
    head.extend_from_slice(m.len().to_string().as_bytes());
    head.extend_from_slice(
        b"\r\nCache-Control: no-store, max-age=0\r\nX-Content-Type-Options: nosniff\r\nCross-Origin-Resource-Policy: same-origin\r\nReferrer-Policy: no-referrer\r\n\r\n",
    );
    Reply {
        head,
        body: ReplyBody::Shared(Arc::clone(m)),
    }
}

/// Render an error page on a request whose head could not be parsed (no
/// session context at all; a fresh pre-session cookie is set).
pub(crate) fn head_error_reply<S: StoreReads + 'static>(
    web: &Web<S>,
    kind: crate::http::HeadErrorKind,
    is_head: bool,
    post: bool,
    cookie: bool,
    circuit: CircuitToken,
) -> Reply {
    let head = RequestHead {
        method: if post {
            Method::Post
        } else if is_head {
            Method::Head
        } else {
            Method::Get
        },
        path: None,
        content_length: None,
        content_type: None,
        origin: crate::http::OriginHeader::Absent,
        fetch_site: crate::http::FetchSite::Absent,
        session_cookie_present: cookie,
        session_cookie: None,
        pre_cookie: None,
    };
    let rq = Rq {
        head: &head,
        method: if post {
            ui::Method::Post
        } else if is_head {
            ui::Method::Head
        } else {
            ui::Method::Get
        },
        locale: Locale::En,
        circuit,
        received: Instant::now(),
        keys: None,
        live: false,
    };
    match kind {
        crate::http::HeadErrorKind::MethodNotAllowed => {
            let out = web.out_any(&rq);
            web.page(&rq, out, Screen::MethodNotAllowed, |_| ())
        }
        crate::http::HeadErrorKind::Malformed => web.fail(&rq, Fail::Error),
    }
}

/// The busy page for a connection over the serving cap: the request's size
/// class, no session lookup (ADR-038(5): the same page as every other busy).
pub(crate) fn busy_reply<S: StoreReads + 'static>(
    web: &Web<S>,
    head: &RequestHead,
    circuit: CircuitToken,
) -> Reply {
    let rq = Rq {
        head,
        method: match head.method {
            Method::Get => ui::Method::Get,
            Method::Head => ui::Method::Head,
            Method::Post => ui::Method::Post,
        },
        locale: Locale::En,
        circuit,
        received: Instant::now(),
        keys: None,
        live: false,
    };
    web.fail(&rq, Fail::Busy)
}

/// The route of a path, for tests and the registry lint.
#[must_use]
pub fn route_of(path: &str) -> Option<Route> {
    routes::lookup(path).map(|(_, d)| d.route)
}
