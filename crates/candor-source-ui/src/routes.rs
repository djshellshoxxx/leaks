// SPDX-License-Identifier: AGPL-3.0-or-later
//! Route allow-list (11 §5.5, 08 SW-*). Paths carry no identifiers or state (DP-13, SUI-014);
//! every link and form action in the templates is built from this enum.

/// A Tier W route below `/{lang}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// `/` (SW-01).
    Landing,
    /// `/safety` (SW-18).
    Safety,
    /// `/status` (SW-17).
    Status,
    /// `/new` (SW-02/03).
    New,
    /// `/concerns` (SW-02).
    Concerns,
    /// `/q` (SW-05).
    Questionnaire,
    /// `/identity` (SW-05).
    Identity,
    /// `/files` (SW-06/07).
    Files,
    /// `/files/check` (SW-29).
    FilesCheck,
    /// `/review` (SW-08).
    Review,
    /// `/check` (SW-24).
    Check,
    /// `/newphrase` (SW-25).
    NewPhrase,
    /// `/submit` (SW-26).
    Submit,
    /// `/login` (SW-10).
    Login,
    /// `/inbox` (SW-11, SW-22).
    Inbox,
    /// `/conversation` (SW-12..14).
    Conversation,
    /// `/rotate` (SW-27).
    Rotate,
    /// `/rotate/confirm` (SW-28).
    RotateConfirm,
    /// `/end` (SW-15).
    End,
    /// `/leave` (SW-16).
    Leave,
    /// `/extend` (SW-21).
    Extend,
}

impl Route {
    /// Path below the language prefix.
    pub fn path(self) -> &'static str {
        match self {
            Route::Landing => "/",
            Route::Safety => "/safety",
            Route::Status => "/status",
            Route::New => "/new",
            Route::Concerns => "/concerns",
            Route::Questionnaire => "/q",
            Route::Identity => "/identity",
            Route::Files => "/files",
            Route::FilesCheck => "/files/check",
            Route::Review => "/review",
            Route::Check => "/check",
            Route::NewPhrase => "/newphrase",
            Route::Submit => "/submit",
            Route::Login => "/login",
            Route::Inbox => "/inbox",
            Route::Conversation => "/conversation",
            Route::Rotate => "/rotate",
            Route::RotateConfirm => "/rotate/confirm",
            Route::End => "/end",
            Route::Leave => "/leave",
            Route::Extend => "/extend",
        }
    }

    /// Whether GET is accepted on this route (11 §5.5). Links may only point at GET routes.
    pub fn accepts_get(self) -> bool {
        !matches!(
            self,
            Route::Check
                | Route::NewPhrase
                | Route::Submit
                | Route::RotateConfirm
                | Route::Leave
                | Route::Extend
        )
    }
}
