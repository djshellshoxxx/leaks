// SPDX-License-Identifier: AGPL-3.0-or-later
//! Per-screen safety tips (`specs/11a-SOURCE-SAFETY-TIPS.md`).
//!
//! Each screen shows one to three tips in a "Staying safe on this page" region. A tip has a
//! short NORMAL text that is always visible and a HIGHER-RISK detail inside a native
//! `<details>` element, so the reader's risk track is never sent to the server (05 GP-1,
//! 05 §8.1). Text lives in `locales/*/tips.ftl`; this table only maps screens to tips.
//!
//! The Safety Check (S02) has no room for the details in its P1 budget (ADR-051(2)), so it shows
//! the NORMAL text only and links to the S02b page, which lists every tip with its details.

use crate::screens::Screen;

/// One tip topic. Catalog keys are `tip-<topic>-title`, `tip-<topic>-n` and `tip-<topic>-h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tip {
    /// Device: own device, never a work device (05 GC-04/05/41).
    Device,
    /// Network: never a work network; bridges reduce but do not hide Tor use (GC-09/10).
    Network,
    /// Tor Browser at Safest; no VPN or other-browser substitute (GC-06/07).
    Browser,
    /// Physical place: screens, cameras, phone location (GC-12).
    Place,
    /// No log-ins; research hygiene (GC-13/14).
    Accounts,
    /// Timing after document access; delayed delivery (GC-34, ADR-038(4)).
    Timing,
    /// Describe rather than send; unique copies / canary traps (GC-22..26).
    Files,
    /// Hidden file data; filename replacement (GC-22/23/24/29).
    Metadata,
    /// Printing, tracking dots, screenshots, photos of screens (GC-20/27/28).
    Print,
    /// Details only a few people know (GC-30).
    Writing,
    /// Stylometry (GC-31).
    Style,
    /// AI tools, translators, grammar checkers (GC-16).
    Ai,
    /// Mode choice; never pressured to identify (ADR-047(5), ADP-01).
    Mode,
    /// S04b ticks can narrow down the source (GC-40).
    Concerns,
    /// Passphrase handling (GC-32).
    Passphrase,
    /// Return visits (GC-33).
    Return,
    /// Keep the conversation here (GC-36).
    Conversation,
    /// Behaviour after sending.
    After,
    /// Device seizure (GC-35).
    Seizure,
    /// New Identity and close (Leave, GC-07).
    Leave,
    /// Errors and outages: no retry storms, never fall back to unsafe paths.
    Errors,
    /// What the platform cannot protect against (GC-01, ADR-035(5)).
    Limits,
}

impl Tip {
    /// Every tip, in the reading order of the S02b page.
    pub const ALL: [Tip; 22] = [
        Tip::Limits,
        Tip::Device,
        Tip::Network,
        Tip::Browser,
        Tip::Place,
        Tip::Accounts,
        Tip::Timing,
        Tip::Files,
        Tip::Metadata,
        Tip::Print,
        Tip::Writing,
        Tip::Style,
        Tip::Ai,
        Tip::Mode,
        Tip::Concerns,
        Tip::Passphrase,
        Tip::Return,
        Tip::Conversation,
        Tip::After,
        Tip::Seizure,
        Tip::Leave,
        Tip::Errors,
    ];

    /// Topic slug used in catalog keys and element ids.
    pub fn topic(self) -> &'static str {
        match self {
            Tip::Device => "device",
            Tip::Network => "network",
            Tip::Browser => "browser",
            Tip::Place => "place",
            Tip::Accounts => "accounts",
            Tip::Timing => "timing",
            Tip::Files => "files",
            Tip::Metadata => "metadata",
            Tip::Print => "print",
            Tip::Writing => "writing",
            Tip::Style => "style",
            Tip::Ai => "ai",
            Tip::Mode => "mode",
            Tip::Concerns => "concerns",
            Tip::Passphrase => "passphrase",
            Tip::Return => "return",
            Tip::Conversation => "conversation",
            Tip::After => "after",
            Tip::Seizure => "seizure",
            Tip::Leave => "leave",
            Tip::Errors => "errors",
            Tip::Limits => "limits",
        }
    }

    /// Heading key (S02b).
    pub fn title_key(self) -> String {
        format!("tip-{}-title", self.topic())
    }

    /// NORMAL text key (always visible).
    pub fn normal_key(self) -> String {
        format!("tip-{}-n", self.topic())
    }

    /// HIGHER-RISK text key (inside `<details>`).
    pub fn high_key(self) -> String {
        format!("tip-{}-h", self.topic())
    }

    /// Element id on the S02b page.
    pub fn anchor(self) -> String {
        format!("tip-{}", self.topic())
    }
}

impl Screen {
    /// The tips shown on this screen (11a §4), one to three, most important first.
    pub fn tips(self) -> &'static [Tip] {
        use Tip::*;
        match self {
            Screen::Landing => &[Device, Network, Limits],
            Screen::Safety => &[Timing],
            Screen::SafetyTips => &[Limits],
            Screen::Status => &[Limits, Browser],
            Screen::NewReport => &[Mode, Place],
            Screen::Concerns => &[Concerns],
            Screen::NoReader => &[Concerns, Limits],
            Screen::Questionnaire => &[Writing, Style, Ai],
            Screen::Identity | Screen::IdentityConfirm | Screen::ModeChanged => &[Mode],
            Screen::Files => &[Files, Metadata, Print],
            Screen::MetadataWarning => &[Metadata, Files],
            Screen::Review => &[Timing, Writing],
            Screen::Credential | Screen::RotateCredential => &[Passphrase, Seizure],
            Screen::Confirm | Screen::RotateConfirm => &[Passphrase],
            Screen::Sent => &[After, Return],
            Screen::Login => &[Return, Network],
            Screen::Inbox => &[Return, After],
            Screen::RotateExplain | Screen::RotateDone => &[Passphrase],
            Screen::Conversation => &[Conversation, Style],
            Screen::Discard | Screen::Discarded => &[Seizure],
            Screen::CloseMailbox | Screen::Closed => &[Seizure, After],
            Screen::AskDelete | Screen::DeleteRequested => &[After, Seizure],
            Screen::Leave => &[Leave],
            Screen::SignedOut => &[Leave, Return],
            Screen::Busy
            | Screen::NotFound
            | Screen::ServerError
            | Screen::Maintenance
            | Screen::MethodNotAllowed => &[Errors],
        }
    }

    /// Whether tip details are rendered inline (`<details>`). S02 links to S02b instead
    /// (ADR-051(2): S02 must fit P1 in every shipped locale).
    pub(crate) fn inline_tip_details(self) -> bool {
        !matches!(self, Screen::Safety)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // ST: TIP-001 — every screen has one to three tips, without duplicates.
    #[test]
    fn one_to_three_tips_per_screen() {
        for s in Screen::ALL {
            let t = s.tips();
            assert!((1..=3).contains(&t.len()), "{}", s.spec_id());
            let set: HashSet<_> = t.iter().collect();
            assert_eq!(set.len(), t.len(), "{}", s.spec_id());
        }
    }

    // ST: TIP-009 — every tip topic is placed on at least one screen besides S02b.
    #[test]
    fn every_tip_is_placed() {
        for tip in Tip::ALL {
            assert!(
                Screen::ALL
                    .iter()
                    .filter(|s| **s != Screen::SafetyTips)
                    .any(|s| s.tips().contains(&tip)),
                "{tip:?}"
            );
        }
        let set: HashSet<_> = Tip::ALL.iter().map(|t| t.topic()).collect();
        assert_eq!(set.len(), Tip::ALL.len());
    }
}
