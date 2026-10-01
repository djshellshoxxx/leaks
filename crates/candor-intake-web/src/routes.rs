// SPDX-License-Identifier: AGPL-3.0-or-later
//! The route registry (07 §5.1 "Router", ADR-029, IMPL-RM2-013; ST-065):
//! deny by default, every route declared once with its audience, its GET
//! access, its POST authorisation, rate class and field allow-list. GET is
//! side-effect-free on every route. Paths are `/{lang}{route}` with the
//! language from the allow-list only; `/` is the landing page.

use candor_source_ui::{Locale, Route};

use crate::form::{Kind, Rule};
use crate::limits::MAX_FORM_FIELDS;
use crate::ratelimit::Class;

/// The only audience on this listener (ADR-029). `source-app` routes
/// (`/app/v1/`) are not served by this crate (RM-8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Audience {
    /// Tier W HTML forms.
    SourceWeb,
}

/// Who may POST.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostAuth {
    /// A live session and its CSRF token.
    Session,
    /// A live session, or the pre-session token bound to `__Host-cpre`.
    PreOrSession,
    /// Leave: as [`PostAuth::PreOrSession`]; with no cookie at all (the
    /// cookie-clearing screens' Leave form), the stateless leave token.
    Leave,
}

/// POST declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PostDecl {
    /// Authorisation.
    pub auth: PostAuth,
    /// Route rate class (besides the per-request bucket).
    pub rate: Option<Class>,
    /// Multipart uploads accepted (S06, S12).
    pub multipart: bool,
}

/// One declared route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteDecl {
    /// The route.
    pub route: Route,
    /// Audience.
    pub audience: Audience,
    /// GET/HEAD accepted (side-effect-free).
    pub get: bool,
    /// POST declaration.
    pub post: Option<PostDecl>,
}

const fn d(route: Route, get: bool, post: Option<PostDecl>) -> RouteDecl {
    RouteDecl {
        route,
        audience: Audience::SourceWeb,
        get,
        post,
    }
}

const fn p(auth: PostAuth, rate: Option<Class>) -> Option<PostDecl> {
    Some(PostDecl {
        auth,
        rate,
        multipart: false,
    })
}

const S: PostAuth = PostAuth::Session;

/// The registry (11 §5.5, 08 SW-01..SW-30). Every [`Route`] appears exactly
/// once (tested).
pub const REGISTRY: [RouteDecl; 22] = [
    d(Route::Landing, true, None),
    d(Route::Safety, true, None),
    d(Route::SafetyTips, true, None),
    d(Route::Status, true, None),
    d(
        Route::New,
        true,
        p(PostAuth::PreOrSession, Some(Class::NewSession)),
    ),
    d(Route::Concerns, true, p(S, None)),
    d(Route::Questionnaire, true, p(S, None)),
    d(Route::Identity, true, p(S, None)),
    d(
        Route::Files,
        true,
        Some(PostDecl {
            auth: S,
            rate: None,
            multipart: true,
        }),
    ),
    d(Route::FilesCheck, true, p(S, None)),
    d(Route::Review, true, p(S, Some(Class::Review))),
    d(Route::Check, false, p(S, None)),
    d(Route::NewPhrase, false, p(S, Some(Class::NewPhrase))),
    d(Route::Submit, false, p(S, Some(Class::Submit))),
    d(
        Route::Login,
        true,
        p(PostAuth::PreOrSession, Some(Class::Login)),
    ),
    d(Route::Inbox, true, p(S, None)),
    d(
        Route::Conversation,
        true,
        Some(PostDecl {
            auth: S,
            rate: None,
            multipart: true,
        }),
    ),
    d(Route::Rotate, true, None),
    d(Route::RotateConfirm, false, p(S, Some(Class::Rotate))),
    d(Route::End, true, p(S, Some(Class::End))),
    // Leave: also without any cookie (nothing to end), but always with a
    // valid token (SPEC-NOTES decision 5).
    d(Route::Leave, false, p(PostAuth::Leave, None)),
    d(Route::Extend, false, p(S, Some(Class::Extend))),
];

/// Resolve a request path to its declaration. `/` and `/{lang}/` are the
/// landing page; everything else must be `/{lang}{route}` exactly.
#[must_use]
pub fn lookup(path: &str) -> Option<(&'static str, &'static RouteDecl)> {
    if path == "/" {
        return REGISTRY.first().map(|r| ("/", r));
    }
    let rest = path.strip_prefix('/')?;
    let (tag, tail) = match rest.split_once('/') {
        Some((t, r)) => (t, r),
        None => return None,
    };
    Locale::from_tag(tag)?;
    REGISTRY.iter().find_map(|r| {
        let p = r.route.path();
        (p.strip_prefix('/') == Some(tail)).then_some((p, r))
    })
}

const TOKEN: Kind = Kind::Token;
const OPT: Kind = Kind::OptToken;

/// The field allow-list of a route (deny by default). Fields shared by
/// every form: `csrf`, and `nav=retry` from the busy page.
#[must_use]
pub fn rule(route: Route, n: &str) -> Option<Rule> {
    match n {
        "csrf" => return rule_c("csrf", TOKEN, false),
        "nav" => return rule_c("nav", TOKEN, false),
        _ => {}
    }
    match route {
        Route::New => match n {
            "channel_id" => rule_c("channel_id", TOKEN, false),
            "mode" => rule_c("mode", TOKEN, false),
            _ => None,
        },
        Route::Concerns => match n {
            "coi_label" => rule_c("coi_label", TOKEN, true),
            "coi_category" => rule_c("coi_category", TOKEN, true),
            _ => None,
        },
        Route::Questionnaire => match n {
            "step" => rule_c("step", TOKEN, false),
            "part" => rule_c("part", TOKEN, false),
            "shown" => rule_c("shown", TOKEN, true),
            "piece" => rule_c("piece", TOKEN, true),
            "category" | "people_know" | "reported_before" | "when_month" | "when_year" => {
                rule_c(static_name(n), OPT, false)
            }
            "when_ongoing" | "when_unsure" => rule_c(static_name(n), TOKEN, false),
            "how_know" => rule_c("how_know", TOKEN, true),
            "what" | "who" | "anything_else" => rule_c(static_name(n), Kind::Long, false),
            "where" => rule_c("where", Kind::Short, false),
            _ => None,
        },
        Route::Identity => match n {
            "full_name" => rule_c("full_name", Kind::Name, false),
            "role_dept" => rule_c("role_dept", Kind::Name, false),
            "contact" => rule_c("contact", TOKEN, false),
            "contact_other" => rule_c("contact_other", Kind::Short, false),
            _ => None,
        },
        Route::Files => match n {
            "action" => rule_c("action", TOKEN, false),
            "part_index" => rule_c("part_index", TOKEN, false),
            "part" => rule_c("part", TOKEN, false),
            "neutral_names" => rule_c("neutral_names", TOKEN, false),
            _ => desc_index(n).map(|_| Rule {
                name: "desc",
                kind: Kind::Short,
                multi: false,
            }),
        },
        Route::FilesCheck => match n {
            "action" => rule_c("action", TOKEN, false),
            _ => None,
        },
        Route::Review => match n {
            "action" => rule_c("action", TOKEN, false),
            "delayed_delivery" => rule_c("delayed_delivery", TOKEN, false),
            "step" => rule_c("step", TOKEN, false),
            "part" => rule_c("part", TOKEN, false),
            _ => None,
        },
        Route::Submit | Route::RotateConfirm => match n {
            "w_a" => rule_c("w_a", Kind::Word, false),
            "w_b" => rule_c("w_b", Kind::Word, false),
            "w_c" => rule_c("w_c", Kind::Word, false),
            _ => None,
        },
        Route::Login => match n {
            // One field, or one per word in the ten-box layout.
            "passphrase" => rule_c(
                "passphrase",
                Kind::Secret {
                    max: candor_sealer::proto::MAX_PASSPHRASE_LEN,
                },
                true,
            ),
            "action" => rule_c("action", TOKEN, false),
            "layout" => rule_c("layout", TOKEN, false),
            _ => None,
        },
        Route::Inbox => match n {
            "action" => rule_c("action", TOKEN, false),
            "part" => rule_c("part", TOKEN, false),
            "passphrase" => rule_c(
                "passphrase",
                Kind::Secret {
                    max: candor_sealer::proto::MAX_PASSPHRASE_LEN,
                },
                false,
            ),
            _ => None,
        },
        Route::Conversation => match n {
            "text" => rule_c("text", Kind::Long, false),
            "piece" => rule_c("piece", TOKEN, false),
            "delayed_delivery" => rule_c("delayed_delivery", TOKEN, false),
            "action" => rule_c("action", TOKEN, false),
            "page" => rule_c("page", TOKEN, false),
            "part" => rule_c("part", TOKEN, false),
            "reply_index" => rule_c("reply_index", TOKEN, false),
            _ => None,
        },
        Route::End => match n {
            "action" => rule_c("action", TOKEN, false),
            "passphrase" => rule_c(
                "passphrase",
                Kind::Secret {
                    max: candor_sealer::proto::MAX_PASSPHRASE_LEN,
                },
                false,
            ),
            _ => None,
        },
        Route::Landing
        | Route::Safety
        | Route::SafetyTips
        | Route::Status
        | Route::Check
        | Route::NewPhrase
        | Route::Rotate
        | Route::Leave
        | Route::Extend => None,
    }
}

fn rule_c(name: &'static str, kind: Kind, multi: bool) -> Option<Rule> {
    Some(Rule { name, kind, multi })
}

fn static_name(n: &str) -> &'static str {
    const NAMES: [&str; 12] = [
        "category",
        "people_know",
        "reported_before",
        "when_month",
        "when_year",
        "when_ongoing",
        "when_unsure",
        "what",
        "who",
        "anything_else",
        "where",
        "how_know",
    ];
    NAMES.iter().find(|x| **x == n).copied().unwrap_or("field")
}

/// `desc_N` with `N` in `0..MAX_FORM_FIELDS` (S06 per-file descriptions).
#[must_use]
pub fn desc_index(n: &str) -> Option<u16> {
    let d = n.strip_prefix("desc_")?;
    if d.is_empty() || d.len() > 3 || !d.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if d.len() > 1 && d.starts_with('0') {
        return None;
    }
    let v: u16 = d.parse().ok()?;
    (usize::from(v) < MAX_FORM_FIELDS).then_some(v)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn all_routes() -> Vec<Route> {
        // Exhaustive: a new Route variant fails to compile here until it is
        // declared (route-registry lint, ST-065, IMPL-RM2-013).
        let check = |r: Route| match r {
            Route::Landing
            | Route::Safety
            | Route::SafetyTips
            | Route::Status
            | Route::New
            | Route::Concerns
            | Route::Questionnaire
            | Route::Identity
            | Route::Files
            | Route::FilesCheck
            | Route::Review
            | Route::Check
            | Route::NewPhrase
            | Route::Submit
            | Route::Login
            | Route::Inbox
            | Route::Conversation
            | Route::Rotate
            | Route::RotateConfirm
            | Route::End
            | Route::Leave
            | Route::Extend => r,
        };
        REGISTRY.iter().map(|d| check(d.route)).collect()
    }

    /// ST-065 / IMPL-RM2-013: every route declared exactly once, audience
    /// source-web, GET only where source-ui allows it, POST always CSRF-bound.
    #[test]
    fn registry_complete_and_consistent() {
        let routes = all_routes();
        assert_eq!(routes.len(), 22);
        for (i, r) in routes.iter().enumerate() {
            assert_eq!(routes.iter().filter(|x| *x == r).count(), 1, "{r:?} twice");
            let d = REGISTRY[i];
            assert_eq!(d.audience, Audience::SourceWeb);
            assert_eq!(d.get, r.accepts_get(), "{r:?} GET declaration");
            assert!(d.get || d.post.is_some(), "{r:?} unreachable");
        }
        // Every path resolves to its own declaration.
        for d in &REGISTRY {
            let path = format!("/en{}", d.route.path());
            assert_eq!(lookup(&path).unwrap().1.route, d.route);
        }
    }

    #[test]
    fn unknown_paths_are_not_routes() {
        for p in [
            "",
            "/en",
            "/en//",
            "/de/",
            "/en/q/",
            "/en/Q",
            "/en/static/x.css",
            "/en/../en/",
            "/app/v1/replies",
            "/en/saved",
            "/en/keys",
            "/en/verify",
            "/.well-known/x",
        ] {
            assert!(lookup(p).is_none(), "{p}");
        }
        assert_eq!(lookup("/").unwrap().1.route, Route::Landing);
        assert_eq!(lookup("/en/").unwrap().1.route, Route::Landing);
        assert_eq!(
            lookup("/en/safety/tips").unwrap().1.route,
            Route::SafetyTips
        );
    }

    /// Deny by default: every route accepts only its own fields.
    #[test]
    fn field_allow_lists() {
        assert!(rule(Route::Login, "passphrase").is_some());
        assert!(rule(Route::Login, "channel_id").is_none());
        assert!(rule(Route::Leave, "passphrase").is_none());
        assert!(rule(Route::Leave, "csrf").is_some());
        assert!(rule(Route::Files, "desc_31").is_some());
        assert!(rule(Route::Files, "desc_01").is_none());
        assert!(rule(Route::Files, "desc_128").is_none());
        assert_eq!(desc_index("desc_7"), Some(7));
    }
}
