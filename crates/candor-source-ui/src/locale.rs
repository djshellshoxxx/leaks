// SPDX-License-Identifier: AGPL-3.0-or-later
//! Locales and Fluent message catalogs (11 §11, 26 §12).
//!
//! The English master catalog is compiled in. Pseudo-locales (26 §12.4) are generated from it
//! by Fluent text transforms, so they are always complete and exercise length expansion
//! (`en-XA`), right-to-left layout (`ar-XB`) and long-word wrapping (`en-XL`).
//!
//! Fluent identifiers cannot contain dots, so the spec key `sui.mode.anonymous` is the Fluent
//! id `sui-mode-anonymous` (and `sops.limits` is `sops-limits`).
//!
//! Every message carries a class comment (`# @class tier0` / `# @class critical`); messages
//! without one are `ui`. The class drives the translation review process (26 §12.2).

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::LazyLock;

use fluent_bundle::concurrent::FluentBundle;
use fluent_bundle::{FluentArgs, FluentResource, FluentValue};
use fluent_syntax::ast;
use unic_langid::LanguageIdentifier;

use crate::model::Arg;

/// English master catalog sources (one file per namespace).
const EN_SOURCES: [(&str, &str); 2] = [
    ("sui.ftl", include_str!("../locales/en/sui.ftl")),
    ("sops.ftl", include_str!("../locales/en/sops.ftl")),
];

/// Text direction of a locale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    /// Left to right.
    Ltr,
    /// Right to left.
    Rtl,
}

impl Dir {
    /// HTML `dir` attribute value.
    pub fn as_str(self) -> &'static str {
        match self {
            Dir::Ltr => "ltr",
            Dir::Rtl => "rtl",
        }
    }
}

/// A built-in locale. Selected only by the URL path prefix (SUI-041), never negotiated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Locale {
    /// English master.
    En,
    /// Pseudo-locale: accented, ~+40 % length, `⟦…⟧` delimiters.
    EnXA,
    /// Pseudo-locale: right-to-left.
    ArXB,
    /// Pseudo-locale: long compound words.
    EnXL,
}

impl Locale {
    /// All built-in locales.
    pub const ALL: [Locale; 4] = [Locale::En, Locale::EnXA, Locale::ArXB, Locale::EnXL];

    /// BCP 47 tag, also the URL path prefix.
    pub fn tag(self) -> &'static str {
        match self {
            Locale::En => "en",
            Locale::EnXA => "en-XA",
            Locale::ArXB => "ar-XB",
            Locale::EnXL => "en-XL",
        }
    }

    /// Text direction.
    pub fn dir(self) -> Dir {
        match self {
            Locale::ArXB => Dir::Rtl,
            Locale::En | Locale::EnXA | Locale::EnXL => Dir::Ltr,
        }
    }

    /// Parses a path prefix against the allow-list (exact match only).
    pub fn from_tag(tag: &str) -> Option<Locale> {
        Locale::ALL.into_iter().find(|l| l.tag() == tag)
    }

    /// Pseudo-locales are for CI and preview only; they must not be enabled in production
    /// (26 I18N-005: a locale is enabled only when its Tier-0 strings are reviewed).
    pub fn is_pseudo(self) -> bool {
        !matches!(self, Locale::En)
    }

    fn index(self) -> usize {
        match self {
            Locale::En => 0,
            Locale::EnXA => 1,
            Locale::ArXB => 2,
            Locale::EnXL => 3,
        }
    }
}

/// Review class of a catalog string (26 §12.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringClass {
    /// `sec:critical tier0`.
    Tier0,
    /// `sec:critical`.
    Critical,
    /// `ui`.
    Ui,
}

/// Catalog construction failure (a build defect; surfaced as a render error, never a panic).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogError(pub String);

pub(crate) struct Catalog {
    bundles: Vec<FluentBundle<FluentResource>>,
    classes: HashMap<String, StringClass>,
}

static CATALOG: LazyLock<Result<Catalog, CatalogError>> = LazyLock::new(build_catalog);

pub(crate) fn catalog() -> Result<&'static Catalog, CatalogError> {
    CATALOG.as_ref().map_err(Clone::clone)
}

fn parse_resources() -> Result<Vec<FluentResource>, CatalogError> {
    let mut out = Vec::new();
    for (name, src) in EN_SOURCES {
        match FluentResource::try_new(src.to_owned()) {
            Ok(r) => out.push(r),
            Err((_, errs)) => {
                return Err(CatalogError(format!("{name}: {} parse error(s): {errs:?}", errs.len())));
            }
        }
    }
    Ok(out)
}

fn class_of(comment: Option<&ast::Comment<&str>>) -> StringClass {
    let Some(c) = comment else {
        return StringClass::Ui;
    };
    let mut class = StringClass::Ui;
    for line in &c.content {
        let line = line.trim();
        if line == "@class tier0" {
            class = StringClass::Tier0;
        } else if line == "@class critical" && class != StringClass::Tier0 {
            class = StringClass::Critical;
        }
    }
    class
}

fn build_catalog() -> Result<Catalog, CatalogError> {
    let mut classes = HashMap::new();
    for res in parse_resources()? {
        for entry in res.entries() {
            if let ast::Entry::Message(m) = entry {
                if classes
                    .insert(m.id.name.to_owned(), class_of(m.comment.as_ref()))
                    .is_some()
                {
                    return Err(CatalogError(format!("duplicate key {}", m.id.name)));
                }
            }
        }
    }
    let mut bundles = Vec::new();
    for locale in Locale::ALL {
        let langid: LanguageIdentifier = locale
            .tag()
            .parse()
            .map_err(|_| CatalogError(format!("bad tag {}", locale.tag())))?;
        let mut bundle = FluentBundle::new_concurrent(vec![langid]);
        bundle.set_use_isolating(true);
        match locale {
            Locale::En => {}
            Locale::EnXA => bundle.set_transform(Some(pseudo_xa)),
            Locale::ArXB => bundle.set_transform(Some(pseudo_xb)),
            Locale::EnXL => bundle.set_transform(Some(pseudo_xl)),
        }
        for res in parse_resources()? {
            bundle
                .add_resource(res)
                .map_err(|e| CatalogError(format!("add_resource: {e:?}")))?;
        }
        bundles.push(bundle);
    }
    Ok(Catalog { bundles, classes })
}

impl Catalog {
    /// Formats a message. Returns `None` if the key or any referenced argument is missing.
    pub(crate) fn format(&self, locale: Locale, key: &str, args: &[(&str, Arg)]) -> Option<String> {
        let bundle = self.bundles.get(locale.index())?;
        let pattern = bundle.get_message(key)?.value()?;
        let mut fargs = FluentArgs::new();
        for (name, value) in args {
            match value {
                Arg::Text(s) => fargs.set(*name, FluentValue::from(s.as_str())),
                Arg::Num(n) => fargs.set(*name, FluentValue::from(*n)),
            }
        }
        let mut errors = Vec::new();
        let text = bundle.format_pattern(pattern, Some(&fargs), &mut errors);
        if !errors.is_empty() {
            return None;
        }
        let text = text.into_owned();
        Some(match locale {
            Locale::EnXA => format!("⟦{text}⟧"),
            _ => text,
        })
    }

    pub(crate) fn class(&self, key: &str) -> Option<StringClass> {
        self.classes.get(key).copied()
    }

    pub(crate) fn keys(&self) -> impl Iterator<Item = &str> {
        self.classes.keys().map(String::as_str)
    }
}

/// Review class of a catalog key (Fluent id), or `None` if the key does not exist.
pub fn string_class(key: &str) -> Option<StringClass> {
    catalog().ok()?.class(key)
}

/// All catalog keys (Fluent ids) of the English master.
pub fn catalog_keys() -> Result<Vec<String>, CatalogError> {
    let mut v: Vec<String> = catalog()?.keys().map(str::to_owned).collect();
    v.sort();
    Ok(v)
}

fn accent(c: char) -> char {
    match c {
        'a' => 'á',
        'e' => 'é',
        'i' => 'í',
        'o' => 'ö',
        'u' => 'ü',
        'y' => 'ý',
        'c' => 'ç',
        'n' => 'ñ',
        's' => 'š',
        'z' => 'ž',
        'A' => 'Å',
        'E' => 'É',
        'I' => 'Î',
        'O' => 'Ö',
        'U' => 'Û',
        'C' => 'Ç',
        'N' => 'Ñ',
        'S' => 'Š',
        other => other,
    }
}

/// en-XA: accent letters and double vowels (≈ +40 % length, 26 §12.4).
fn pseudo_xa(s: &str) -> Cow<'_, str> {
    let mut out = String::with_capacity(s.len().saturating_mul(2));
    for c in s.chars() {
        out.push(accent(c));
        if matches!(c, 'a' | 'e' | 'i' | 'o' | 'u' | 'A' | 'E' | 'I' | 'O' | 'U') {
            out.push(accent(c));
        }
    }
    Cow::Owned(out)
}

/// ar-XB: force right-to-left rendering of every text element (RLO … PDF).
fn pseudo_xb(s: &str) -> Cow<'_, str> {
    if s.trim().is_empty() {
        return Cow::Borrowed(s);
    }
    Cow::Owned(format!("\u{202E}{s}\u{202C}"))
}

/// en-XL: words of ≥ 9 letters become compound words of up to 30 characters.
fn pseudo_xl(s: &str) -> Cow<'_, str> {
    let mut out = String::with_capacity(s.len().saturating_mul(2));
    let mut word = String::new();
    let flush = |word: &mut String, out: &mut String| {
        let n = word.chars().count();
        out.push_str(word);
        if n >= 9 {
            let mut len = n;
            let mut extra = word.chars().cycle();
            while len < 30 {
                if let Some(c) = extra.next() {
                    out.extend(c.to_lowercase());
                }
                len = len.saturating_add(1);
            }
        }
        word.clear();
    };
    for c in s.chars() {
        if c.is_alphabetic() {
            word.push(c);
        } else {
            flush(&mut word, &mut out);
            out.push(c);
        }
    }
    flush(&mut word, &mut out);
    Cow::Owned(out)
}
