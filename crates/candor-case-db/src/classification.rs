// SPDX-License-Identifier: AGPL-3.0-or-later
//! The column-classification file (09 §3, §8 L5): one row per column of every
//! table, `schema<TAB>table<TAB>column<TAB>class<TAB>ciphertext`. Loaded into
//! `candor.column_class` by the migrator and compared with the live catalog by
//! the schema lint (static and at service open).

use crate::error::{DbError, Result};

/// The embedded classification file.
pub const CLASSIFICATION_TSV: &str = include_str!("../classification.tsv");

/// 09 §3 data class.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum DataClass {
    /// Source-sensitive.
    SS,
    /// Content (always ciphertext).
    CT,
    /// Workflow.
    WF,
    /// Security.
    SEC,
    /// System.
    SYS,
}

impl DataClass {
    /// Text form as stored in `candor.column_class`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SS => "SS",
            Self::CT => "CT",
            Self::WF => "WF",
            Self::SEC => "SEC",
            Self::SYS => "SYS",
        }
    }
    /// Parse the text form.
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "SS" => Self::SS,
            "CT" => Self::CT,
            "WF" => Self::WF,
            "SEC" => Self::SEC,
            "SYS" => Self::SYS,
            _ => return Err(DbError::InvalidInput("data class")),
        })
    }
}

/// One classification row.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ClassRow {
    /// Schema name.
    pub schema: String,
    /// Table name.
    pub table: String,
    /// Column name.
    pub column: String,
    /// Class.
    pub class: DataClass,
    /// Whether the column holds ciphertext the server cannot open.
    pub ciphertext: bool,
}

fn ident_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
}

/// Strict parse: five tab-separated fields per row, identifiers lowercase
/// `[a-z0-9_]{1,63}`, class ∈ {SS, CT, WF, SEC, SYS}, ciphertext ∈
/// {true, false}, no duplicate columns, comments start with `#`.
pub fn parse_classification(text: &str) -> Result<Vec<ClassRow>> {
    let mut out: Vec<ClassRow> = Vec::new();
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.split('\t');
        let (Some(s), Some(t), Some(c), Some(k), Some(x), None) = (
            it.next(),
            it.next(),
            it.next(),
            it.next(),
            it.next(),
            it.next(),
        ) else {
            return Err(DbError::InvalidInput("classification row shape"));
        };
        if !ident_ok(s) || !ident_ok(t) || !ident_ok(c) {
            return Err(DbError::InvalidInput("classification identifier"));
        }
        let ciphertext = match x {
            "true" => true,
            "false" => false,
            _ => return Err(DbError::InvalidInput("classification flag")),
        };
        let row = ClassRow {
            schema: s.to_string(),
            table: t.to_string(),
            column: c.to_string(),
            class: DataClass::parse(k)?,
            ciphertext,
        };
        if out
            .iter()
            .any(|r| r.schema == row.schema && r.table == row.table && r.column == row.column)
        {
            return Err(DbError::InvalidInput("classification duplicate"));
        }
        out.push(row);
    }
    if out.is_empty() {
        return Err(DbError::InvalidInput("classification empty"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_file_parses() {
        let rows = parse_classification(CLASSIFICATION_TSV).unwrap();
        assert!(rows.len() > 400);
    }

    #[test]
    fn rejects_malformed() {
        assert!(parse_classification("core\tcase\tx\tCT\n").is_err());
        assert!(parse_classification("core\tcase\tx\tXX\ttrue\n").is_err());
        assert!(parse_classification("core\tcase\tx\tCT\tyes\n").is_err());
        assert!(parse_classification("Core\tcase\tx\tCT\ttrue\n").is_err());
        assert!(
            parse_classification("core\tcase\tx\tCT\ttrue\ncore\tcase\tx\tCT\ttrue\n").is_err()
        );
        assert!(parse_classification("# only\n").is_err());
        assert!(parse_classification("core\tcase\tx\tCT\ttrue\textra\n").is_err());
    }
}
