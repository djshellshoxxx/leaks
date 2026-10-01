// SPDX-License-Identifier: AGPL-3.0-or-later
use askama::Template;
pub struct P;
impl P { pub fn t(&self, k: &str) -> String { format!("<{k}>") } pub fn t1(&self, k: &str, a: &str, v: impl std::fmt::Display) -> String { format!("{k}{a}{v}") } }
#[derive(Template)]
#[template(source = "{% extends \"layout.html\" %}{% block main %}<p>{{ p.t(\"x\") }} {{ p.t1(\"y\", \"n\", 3) }}</p>{% for w in words %}{{ loop.index }}{{ w }}{% endfor %}{% endblock %}", ext = "html")]
pub struct T<'a> { pub p: &'a P, pub words: &'a [String] }
pub fn go() -> String { T { p: &P, words: &["a".into()] }.render().unwrap_or_default() }
