// SPDX-License-Identifier: AGPL-3.0-or-later
//! Item templates and builders for the paged regions (AUD-RM1-SUI-01; see [`crate::paging`]).
//!
//! Every item is rendered on its own into a fixed-capacity, zeroizing buffer. An item that does
//! not fit the part budget is split into pieces of its text (by escaped length); each piece is
//! labelled "(part i of n)" and fills a part on its own.

use core::ops::Range;

use askama::Template;
use zeroize::Zeroizing;

use crate::RenderError;
use crate::model::{AttachedFile, Day, IdentityHint, Question, QuestionKind, ReviewAnswer};
use crate::page::{OverBudget, SizeClass};
use crate::paging::{
    CappedWriter, ITEM_SLACK, Item, MAX_PARTS, MIN_PIECE, Region, piece_value, split_escaped,
};
use crate::routes::Route;
use crate::screens::Screen;
use crate::view::{PageView, escape_z, label, neutralize_bidi};

/// Display numbers of a piece ("part n of total").
#[derive(Clone, Copy)]
pub(crate) struct PieceNo {
    pub(crate) n: u64,
    pub(crate) total: u64,
}

/// Widest piece numbers, used when measuring a piece's fixed overhead.
fn widest() -> PieceNo {
    let m = u64::try_from(MAX_PARTS).unwrap_or(u64::MAX);
    PieceNo { n: m, total: m }
}

#[derive(Template)]
#[template(path = "seg_message.html")]
struct MessageSeg<'a> {
    p: &'a PageView<'a>,
    index: usize,
    sender: &'a str,
    date: Day,
    text: &'a str,
    piece: Option<PieceNo>,
    deletable: bool,
}

#[derive(Template)]
#[template(path = "seg_composer.html")]
struct ComposerSeg<'a> {
    p: &'a PageView<'a>,
    text: &'a str,
    piece: Option<PieceNo>,
    piece_value: &'a str,
}

#[derive(Template)]
#[template(path = "seg_answer.html")]
struct AnswerSeg<'a> {
    p: &'a PageView<'a>,
    a: &'a ReviewAnswer,
    text: &'a str,
    piece: Option<PieceNo>,
}

#[derive(Template)]
#[template(path = "seg_review_file.html")]
struct ReviewFileSeg<'a> {
    p: &'a PageView<'a>,
    f: &'a AttachedFile,
    name: &'a str,
}

#[derive(Template)]
#[template(path = "seg_hint.html")]
struct HintSeg<'a> {
    p: &'a PageView<'a>,
    h: &'a IdentityHint,
}

#[derive(Template)]
#[template(path = "seg_file_row.html")]
struct FileRowSeg<'a> {
    p: &'a PageView<'a>,
    f: &'a AttachedFile,
    index: usize,
    name: &'a str,
}

#[derive(Template)]
#[template(path = "seg_meta_row.html")]
struct MetaRowSeg<'a> {
    p: &'a PageView<'a>,
    f: &'a AttachedFile,
    name: &'a str,
}

#[derive(Template)]
#[template(path = "seg_question.html")]
struct QuestionSeg<'a> {
    p: &'a PageView<'a>,
    q: &'a Question,
    val: &'a str,
    piece: Option<PieceNo>,
    piece_value: &'a str,
}

/// Renders `t` into a buffer of at most `cap` bytes. `Ok(None)` means it does not fit. The
/// result is copied into an exactly sized zeroizing buffer; the large one is zeroized.
pub(crate) fn render_capped<T: Template + ?Sized>(
    t: &T,
    cap: usize,
) -> Result<Option<Zeroizing<String>>, RenderError> {
    let mut w = CappedWriter::new(cap);
    match t.render_into(&mut w) {
        Ok(()) => {
            let big = w.into_inner();
            let mut out = Zeroizing::new(String::with_capacity(big.len()));
            out.push_str(&big);
            Ok(Some(out))
        }
        Err(_) if w.overflow => Ok(None),
        Err(e) => Err(RenderError::Template(e.to_string())),
    }
}

/// Build context: the per-item byte budget and the page class (for errors).
struct Ctx {
    budget: usize,
    class: SizeClass,
}

impl Ctx {
    fn over(&self) -> RenderError {
        RenderError::OverBudget(OverBudget {
            len: self.budget,
            class: self.class,
        })
    }

    /// Item capacity: the part budget minus the per-item slack.
    fn cap(&self) -> usize {
        self.budget.saturating_sub(ITEM_SLACK)
    }

    /// Renders an item that cannot be split; it must fit.
    fn fixed<T: Template>(&self, region: Region, t: &T) -> Result<Item, RenderError> {
        let html = render_capped(t, self.cap())?.ok_or_else(|| self.over())?;
        Ok(Item {
            region,
            html,
            exclusive: false,
        })
    }

    /// Renders an item whole if it fits, else as pieces of `text`.
    ///
    /// `render(text_html, piece, range)` renders the item with already escaped text; `piece`
    /// and `range` are `None` for the whole item.
    fn splittable<F>(&self, region: Region, text: &str, render: F) -> Result<Vec<Item>, RenderError>
    where
        F: Fn(
            &str,
            Option<PieceNo>,
            Option<&Range<usize>>,
            usize,
        ) -> Result<Option<Zeroizing<String>>, RenderError>,
    {
        let cap = self.cap();
        let item = |html, exclusive| Item {
            region,
            html,
            exclusive,
        };
        let whole = escape_z(text);
        if let Some(html) = render(&whole, None, None, cap)? {
            return Ok(vec![item(html, false)]);
        }
        drop(whole);
        // Fixed overhead of a piece: empty text, widest numbers and offsets.
        let wide = usize::try_from(999_999_999u64).unwrap_or(usize::MAX);
        let probe = wide..wide;
        let overhead = render("", Some(widest()), Some(&probe), cap)?
            .map(|h| h.len())
            .ok_or_else(|| self.over())?;
        let avail = cap.saturating_sub(overhead);
        if avail < MIN_PIECE {
            return Err(self.over());
        }
        let ranges = split_escaped(text, avail);
        let total = u64::try_from(ranges.len()).unwrap_or(u64::MAX);
        let mut out = Vec::with_capacity(ranges.len());
        for (i, r) in ranges.iter().enumerate() {
            let chunk = text.get(r.clone()).ok_or_else(|| self.over())?;
            let esc = escape_z(chunk);
            let n = u64::try_from(i).unwrap_or(u64::MAX).saturating_add(1);
            let html = render(&esc, Some(PieceNo { n, total }), Some(r), cap)?
                .ok_or_else(|| self.over())?;
            out.push(item(html, true));
        }
        Ok(out)
    }
}

/// The hidden `piece` value for `range` of `stored` (empty for a whole value). Fails closed
/// without a session piece key (AUD-RM1-SUI-11).
fn piece_field(
    p: &PageView<'_>,
    field: &str,
    range: Option<&Range<usize>>,
    stored: &str,
) -> Result<Zeroizing<String>, RenderError> {
    let Some(r) = range else {
        return Ok(Zeroizing::default());
    };
    let key =
        p.vm.ctx
            .piece_key
            .as_ref()
            .ok_or(RenderError::MissingData("piece key"))?;
    piece_value(key, field, r, stored)
        .map(Zeroizing::new)
        .ok_or(RenderError::MissingData("piece key"))
}

/// Builds the items of a paged screen. `budget` is the room left on a part after the chrome.
pub(crate) fn build(
    p: &PageView<'_>,
    budget: usize,
    class: SizeClass,
) -> Result<Vec<Item>, RenderError> {
    let cx = Ctx { budget, class };
    let vm = p.vm;
    let mut items = Vec::new();
    match p.screen {
        Screen::Questionnaire => {
            for q in &vm.questionnaire.questions {
                let text_kind = matches!(q.kind, QuestionKind::ShortText | QuestionKind::LongText);
                let value = if text_kind {
                    q.value.first().map_or("", |v| v.as_str())
                } else {
                    ""
                };
                items.extend(cx.splittable(
                    Region::Questions,
                    value,
                    |val, piece, range, cap| {
                        if piece.is_some() && !text_kind {
                            return Ok(None);
                        }
                        let pv = piece_field(p, &q.id, range, value)?;
                        render_capped(
                            &QuestionSeg {
                                p,
                                q,
                                val,
                                piece,
                                piece_value: &pv,
                            },
                            cap,
                        )
                    },
                )?);
            }
        }
        Screen::Review => {
            let r = &vm.review;
            for a in &r.answers {
                items.extend(cx.splittable(
                    Region::Answers,
                    &a.answer,
                    |text, piece, _, cap| render_capped(&AnswerSeg { p, a, text, piece }, cap),
                )?);
            }
            for f in &r.files {
                let name = label(&f.name);
                items.push(cx.fixed(Region::ReviewFiles, &ReviewFileSeg { p, f, name: &name })?);
            }
            for h in &r.hints {
                items.push(cx.fixed(Region::Hints, &HintSeg { p, h })?);
            }
        }
        Screen::Inbox | Screen::Conversation => {
            let deletable = p.screen == Screen::Conversation;
            let msgs = if deletable {
                &vm.conversation.messages
            } else {
                &vm.inbox.messages
            };
            for (index, m) in msgs.iter().enumerate() {
                let sender = label(&m.sender);
                let text = neutralize_bidi(&m.text);
                items.extend(
                    cx.splittable(Region::Messages, &text, |text, piece, _, cap| {
                        render_capped(
                            &MessageSeg {
                                p,
                                index,
                                sender: &sender,
                                date: m.date,
                                text,
                                piece,
                                deletable,
                            },
                            cap,
                        )
                    })?,
                );
            }
            if deletable {
                let draft = &vm.conversation.draft_text;
                items.extend(cx.splittable(
                    Region::Composer,
                    draft,
                    |text, piece, range, cap| {
                        let pv = piece_field(p, "text", range, draft)?;
                        render_capped(
                            &ComposerSeg {
                                p,
                                text,
                                piece,
                                piece_value: &pv,
                            },
                            cap,
                        )
                    },
                )?);
            }
        }
        Screen::Files => {
            for (index, f) in vm.files.files.iter().enumerate() {
                let name = label(&f.name);
                items.push(cx.fixed(
                    Region::FileRows,
                    &FileRowSeg {
                        p,
                        f,
                        index,
                        name: &name,
                    },
                )?);
            }
        }
        Screen::MetadataWarning => {
            for f in &vm.files.files {
                let name = label(&f.name);
                items.push(cx.fixed(Region::MetaRows, &MetaRowSeg { p, f, name: &name })?);
            }
        }
        _ => {}
    }
    Ok(items)
}

/// Screens with paged regions.
pub(crate) fn is_paged(s: Screen) -> bool {
    matches!(
        s,
        Screen::Questionnaire
            | Screen::Review
            | Screen::Inbox
            | Screen::Conversation
            | Screen::Files
            | Screen::MetadataWarning
    )
}
