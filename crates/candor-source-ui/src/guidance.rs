// SPDX-License-Identifier: AGPL-3.0-or-later
//! Guidance card layout (05 §6). Text lives in `locales/*/sops.ftl`; this table only says which
//! paragraphs, list items and higher-risk paragraphs each card has, and how cards are grouped.

/// One block of a card.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Block {
    /// A paragraph (catalog key).
    P(&'static str),
    /// A bulleted list (catalog keys).
    List(&'static [&'static str]),
    /// Paragraph filled with deployment arguments by the renderer (keyed by the catalog key).
    Dynamic(&'static str),
    /// Customer-authored jurisdiction text (legal class), if configured.
    Jurisdiction(JurisdictionText),
}

/// Which jurisdiction-pack text a card embeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JurisdictionText {
    /// `{jurisdiction_rights_text}` (GC-03).
    Rights,
    /// `{jurisdiction_retaliation_text}` (GC-37).
    Retaliation,
}

/// A guidance card.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Card {
    /// Card id, e.g. "GC-04" (used as the element id `gc-04`).
    pub id: &'static str,
    /// Title key.
    pub title: &'static str,
    /// Normal-track blocks.
    pub normal: &'static [Block],
    /// Higher-risk blocks (rendered in a nested `<details>`).
    pub high: &'static [Block],
}

impl Card {
    /// HTML id.
    pub fn anchor(&self) -> String {
        self.id.to_ascii_lowercase()
    }
}

/// A group of cards (A–J).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Group {
    /// Title key.
    pub title: &'static str,
    /// Cards.
    pub cards: &'static [Card],
}

use Block::{Dynamic, Jurisdiction, List, P};

const fn card(
    id: &'static str,
    title: &'static str,
    normal: &'static [Block],
    high: &'static [Block],
) -> Card {
    Card {
        id,
        title,
        normal,
        high,
    }
}

/// Card GC-01 (also used on S03 "What protects you and what does not").
pub(crate) const GC01: Card = card(
    "GC-01",
    "sops-limits-title",
    &[
        Dynamic("sops-limits-n1"),
        P("sops-limits-n2"),
        P("sops-limits-n3"),
        Dynamic("sops-limits-n4"),
    ],
    &[],
);

/// Card GC-30 (also behind "What details could point to me?" on S05).
pub(crate) const GC30: Card = card(
    "GC-30",
    "sops-content-title",
    &[
        P("sops-content-n1"),
        P("sops-content-n2"),
        List(&["sops-content-li1", "sops-content-li2", "sops-content-li3"]),
    ],
    &[P("sops-content-h1")],
);

/// Card GC-32 (shown in full on S10).
pub(crate) const GC32: Card = card(
    "GC-32",
    "sops-passphrase-title",
    &[
        Dynamic("sops-passphrase-n1"),
        List(&[
            "sops-passphrase-li1",
            "sops-passphrase-li2",
            "sops-passphrase-li3",
            "sops-passphrase-li4",
        ]),
    ],
    &[P("sops-passphrase-h1")],
);

/// Card GC-39 (S11 login, S13).
pub(crate) const GC39: Card = card(
    "GC-39",
    "sops-lostphrase-title",
    &[P("sops-lostphrase-n1")],
    &[],
);

/// Card GC-35 (S13).
pub(crate) const GC35: Card = card(
    "GC-35",
    "sops-seizure-title",
    &[
        P("sops-seizure-n1"),
        List(&[
            "sops-seizure-li1",
            "sops-seizure-li2",
            "sops-seizure-li3",
            "sops-seizure-li4",
            "sops-seizure-li5",
        ]),
    ],
    &[P("sops-seizure-h1")],
);

/// Card GC-03 (Landing footer line, Safety Check, S13).
pub(crate) const GC03: Card = card(
    "GC-03",
    "sops-legal-title",
    &[
        P("sops-legal-n1"),
        Jurisdiction(JurisdictionText::Rights),
        P("sops-legal-n2"),
    ],
    &[],
);

/// All groups shown on S02, in reading order. GC-02 is rendered with the self-selection text.
pub(crate) const GROUPS: &[Group] = &[
    Group {
        title: "sops-group-a",
        cards: &[GC01, GC03],
    },
    Group {
        title: "sops-group-b",
        cards: &[
            card(
                "GC-04",
                "sops-device-title",
                &[P("sops-device-n1")],
                &[P("sops-device-h1")],
            ),
            card(
                "GC-05",
                "sops-managed-title",
                &[P("sops-managed-n1"), P("sops-managed-n2")],
                &[P("sops-managed-h1")],
            ),
            card(
                "GC-06",
                "sops-browser-title",
                &[
                    P("sops-browser-n1"),
                    P("sops-browser-n2"),
                    List(&[
                        "sops-browser-li1",
                        "sops-browser-li2",
                        "sops-browser-li3",
                        "sops-browser-li4",
                    ]),
                ],
                &[P("sops-browser-h1")],
            ),
            card(
                "GC-07",
                "sops-safest-title",
                &[P("sops-safest-n1"), P("sops-safest-n2")],
                &[P("sops-safest-h1")],
            ),
            card(
                "GC-08",
                "sops-tails-title",
                &[P("sops-tails-n1")],
                &[P("sops-tails-h1")],
            ),
            card(
                "GC-38",
                "sops-tier-title",
                &[
                    P("sops-tier-n1"),
                    List(&["sops-tier-li1", "sops-tier-li2"]),
                    Dynamic("sops-tier-n2"),
                ],
                &[P("sops-tier-h1")],
            ),
        ],
    },
    Group {
        title: "sops-group-c",
        cards: &[
            card(
                "GC-09",
                "sops-torvisible-title",
                &[
                    P("sops-torvisible-n1"),
                    P("sops-torvisible-n2"),
                    P("sops-torvisible-n3"),
                ],
                &[P("sops-torvisible-h1")],
            ),
            card(
                "GC-10",
                "sops-bridges-title",
                &[P("sops-bridges-n1")],
                &[P("sops-bridges-h1")],
            ),
            card(
                "GC-11",
                "sops-censorship-title",
                &[P("sops-censorship-n1"), Dynamic("sops-censorship-n2")],
                &[P("sops-censorship-h1")],
            ),
            card(
                "GC-12",
                "sops-place-title",
                &[P("sops-place-n1")],
                &[P("sops-place-h1")],
            ),
        ],
    },
    Group {
        title: "sops-group-d",
        cards: &[
            card(
                "GC-13",
                "sops-research-title",
                &[P("sops-research-n1")],
                &[P("sops-research-h1")],
            ),
            card(
                "GC-14",
                "sops-accounts-title",
                &[P("sops-accounts-n1")],
                &[P("sops-accounts-h1")],
            ),
            card(
                "GC-15",
                "sops-cloud-title",
                &[P("sops-cloud-n1"), P("sops-cloud-n2")],
                &[P("sops-cloud-h1")],
            ),
            card(
                "GC-16",
                "sops-ai-title",
                &[
                    P("sops-ai-n1"),
                    List(&["sops-ai-li1", "sops-ai-li2", "sops-ai-li3", "sops-ai-li4"]),
                    P("sops-ai-n2"),
                ],
                &[P("sops-ai-h1")],
            ),
        ],
    },
    Group {
        title: "sops-group-e",
        cards: &[
            card(
                "GC-17",
                "sops-history-title",
                &[P("sops-history-n1")],
                &[P("sops-history-h1")],
            ),
            card(
                "GC-18",
                "sops-traces-title",
                &[P("sops-traces-n1")],
                &[P("sops-traces-h1")],
            ),
        ],
    },
    Group {
        title: "sops-group-f",
        cards: &[
            card(
                "GC-19",
                "sops-monitoring-title",
                &[P("sops-monitoring-n1")],
                &[P("sops-monitoring-h1")],
            ),
            card(
                "GC-20",
                "sops-print-title",
                &[P("sops-print-n1"), P("sops-print-n2")],
                &[P("sops-print-h1")],
            ),
            card(
                "GC-21",
                "sops-usb-title",
                &[P("sops-usb-n1")],
                &[P("sops-usb-h1")],
            ),
        ],
    },
    Group {
        title: "sops-group-g",
        cards: &[
            card(
                "GC-22",
                "sops-exif-title",
                &[P("sops-exif-n1"), P("sops-exif-n2"), P("sops-exif-n3")],
                &[P("sops-exif-h1")],
            ),
            card(
                "GC-23",
                "sops-docmeta-title",
                &[P("sops-docmeta-n1"), P("sops-docmeta-n2")],
                &[P("sops-docmeta-h1")],
            ),
            card(
                "GC-24",
                "sops-filenames-title",
                &[P("sops-filenames-n1")],
                &[P("sops-filenames-h1")],
            ),
            card(
                "GC-25",
                "sops-canary-title",
                &[P("sops-canary-n1")],
                &[P("sops-canary-h1")],
            ),
            card(
                "GC-26",
                "sops-watermark-title",
                &[P("sops-watermark-n1")],
                &[P("sops-watermark-h1")],
            ),
            card("GC-27", "sops-dots-title", &[P("sops-dots-n1")], &[]),
            card(
                "GC-28",
                "sops-screenshots-title",
                &[P("sops-screenshots-n1")],
                &[P("sops-screenshots-h1")],
            ),
            card(
                "GC-29",
                "sops-background-title",
                &[P("sops-background-n1")],
                &[P("sops-background-h1")],
            ),
        ],
    },
    Group {
        title: "sops-group-h",
        cards: &[
            GC30,
            card(
                "GC-31",
                "sops-style-title",
                &[P("sops-style-n1")],
                &[P("sops-style-h1")],
            ),
        ],
    },
    Group {
        title: "sops-group-i",
        cards: &[
            GC32,
            card(
                "GC-33",
                "sops-return-title",
                &[Dynamic("sops-return-n1"), P("sops-return-n2")],
                &[P("sops-return-h1")],
            ),
            card(
                "GC-34",
                "sops-timing-title",
                &[P("sops-timing-n1"), P("sops-timing-n2")],
                &[Dynamic("sops-timing-h1")],
            ),
            GC35,
            card(
                "GC-36",
                "sops-sidechannel-title",
                &[P("sops-sidechannel-n1"), P("sops-sidechannel-n2")],
                &[],
            ),
            card(
                "GC-37",
                "sops-retaliation-title",
                &[
                    P("sops-retaliation-n1"),
                    Jurisdiction(JurisdictionText::Retaliation),
                ],
                &[],
            ),
        ],
    },
    Group {
        title: "sops-group-j",
        cards: &[
            GC39,
            card(
                "GC-40",
                "sops-selfhint-title",
                &[P("sops-selfhint-n1")],
                &[],
            ),
            card(
                "GC-41",
                "sops-phoneonly-title",
                &[P("sops-phoneonly-n1")],
                &[P("sops-phoneonly-h1")],
            ),
            card(
                "GC-42",
                "sops-warnings-title",
                &[P("sops-warnings-n1")],
                &[],
            ),
            card(
                "GC-43",
                "sops-firstcontact-title",
                &[P("sops-firstcontact-n1")],
                &[],
            ),
            card(
                "GC-44",
                "sops-appvault-title",
                &[P("sops-appvault-n1")],
                &[P("sops-appvault-h1")],
            ),
            card(
                "GC-45",
                "sops-identified-title",
                &[P("sops-identified-n1")],
                &[],
            ),
        ],
    },
];
