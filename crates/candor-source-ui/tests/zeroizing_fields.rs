// SPDX-License-Identifier: AGPL-3.0-or-later
//! AUD-RM2-WEB-01 regression tests: every view-model field that carries the
//! source's text, identity data, file names or descriptions, team replies or
//! the form token is a `Zeroizing<String>`, so dropping the model after the
//! response wipes it (the rendered body is zeroizing too, `Page::body`).
//!
//! `unsafe_code` is forbidden workspace-wide, so the wipe itself is not
//! observed with an allocator probe; instead the types are pinned at compile
//! time and in the source, and the zeroize crate supplies the wipe.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "support/preview.rs"]
#[allow(dead_code)]
mod preview;

use candor_source_ui::*;
use preview::sample_view_model;
use zeroize::Zeroizing;

const MODEL_SRC: &str = include_str!("../src/model.rs");

/// (struct, field) pairs that carry source or team plaintext or a secret.
const SECRET_FIELDS: &[(&str, &str)] = &[
    ("PageContext", "form_token"),
    ("Question", "value"),
    ("IdentityData", "full_name"),
    ("IdentityData", "role"),
    ("IdentityData", "contact_other_value"),
    ("AttachedFile", "name"),
    ("AttachedFile", "description"),
    ("ReviewAnswer", "answer"),
    ("InboxMessage", "sender"),
    ("InboxMessage", "text"),
    ("ConversationData", "draft_text"),
];

fn z(_: &Zeroizing<String>) {}

/// Compile-time pin: each field below only type-checks as `Zeroizing<String>`.
#[test]
fn text_fields_are_zeroizing_types() {
    let vm = sample_view_model(Screen::Review, Mode::Confidential, true);
    if let Some(t) = &vm.ctx.form_token {
        z(t);
    }
    for q in &vm.questionnaire.questions {
        q.value.iter().for_each(z);
    }
    z(&vm.identity.full_name);
    z(&vm.identity.role);
    z(&vm.identity.contact_other_value);
    for f in vm.files.files.iter().chain(vm.review.files.iter()) {
        z(&f.name);
        z(&f.description);
    }
    vm.review.answers.iter().for_each(|a| z(&a.answer));
    for m in vm
        .inbox
        .messages
        .iter()
        .chain(vm.conversation.messages.iter())
    {
        z(&m.sender);
        z(&m.text);
    }
    z(&vm.conversation.draft_text);
}

/// Source pin: the declarations in `model.rs` say `Zeroizing<String>`.
#[test]
fn model_declares_zeroizing_text_fields() {
    for (ty, field) in SECRET_FIELDS {
        let start = MODEL_SRC
            .find(&format!("pub struct {ty} "))
            .unwrap_or_else(|| panic!("struct {ty}"));
        let body = &MODEL_SRC[start..];
        let end = body.find("\n}").expect("struct end");
        let decl = body[..end]
            .lines()
            .find(|l| l.trim_start().starts_with(&format!("pub {field}:")))
            .unwrap_or_else(|| panic!("{ty}.{field}"));
        assert!(
            decl.contains("Zeroizing<String>"),
            "{ty}.{field} must be Zeroizing<String> (AUD-RM2-WEB-01): {decl}"
        );
    }
}

/// Rendering every screen that shows such fields works with zeroizing
/// values, and the output buffer is the zeroizing `Page::body`.
#[test]
fn screens_render_from_zeroizing_fields() {
    let locale = Locale::En;
    for screen in [
        Screen::Questionnaire,
        Screen::Identity,
        Screen::Files,
        Screen::Review,
        Screen::Inbox,
        Screen::Conversation,
    ] {
        let vm = sample_view_model(screen, Mode::Confidential, false);
        let page = render(screen, &vm, &locale).unwrap();
        let body: &Zeroizing<Vec<u8>> = &page.body;
        assert!(!body.is_empty());
    }
}
