// SPDX-License-Identifier: AGPL-3.0-or-later
//! Renders every screen in every locale (and every mode for the layout, plus error states) to
//! `target/source-ui-preview/` for manual review. Run with
//! `cargo run -p candor-source-ui --example render_all`.

use std::fs;
use std::path::PathBuf;

use candor_source_ui::preview::sample_view_model;
use candor_source_ui::{Locale, Mode, Screen, render};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target"));
    let out = target.join("source-ui-preview");
    fs::create_dir_all(&out)?;
    let mut index = String::from(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Candor source UI preview</title></head><body><h1>Candor source UI preview</h1><ul>\n",
    );
    let mut count = 0usize;
    for locale in Locale::ALL {
        for screen in Screen::ALL {
            for (mode, errors) in [
                (Mode::Anonymous, false),
                (Mode::Anonymous, true),
                (Mode::Confidential, false),
                (Mode::Identified, false),
            ] {
                if errors && screen.status() != 200 {
                    continue;
                }
                let vm = sample_view_model(screen, mode, errors);
                let page = match render(screen, &vm, &locale) { Ok(p) => p, Err(e) => { eprintln!("FAIL {} {} {:?} {}: {:?}", locale.tag(), screen.spec_id(), mode, errors, e); continue; } };
                let name = format!(
                    "{}_{}_{:?}{}.html",
                    locale.tag(),
                    screen.spec_id(),
                    mode,
                    if errors { "_error" } else { "" }
                );
                fs::write(out.join(&name), &page.body[..])?;
                index.push_str(&format!(
                    "<li><a href=\"{name}\">{name}</a> ({} bytes unpadded, class {:?}, status {})</li>\n",
                    page.unpadded_len, page.class, page.status
                ));
                count += 1;
            }
        }
    }
    index.push_str("</ul></body></html>\n");
    fs::write(out.join("index.html"), index)?;
    println!("wrote {count} pages to {}", out.display());
    Ok(())
}
