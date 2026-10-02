// SPDX-License-Identifier: AGPL-3.0-or-later
//! File classes for the S07 metadata warning (05 §7.2). Tier W classifies by extension only;
//! the server never parses files (ADR-012).

/// A file class with its own warning lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileClass {
    /// Photo.
    Photo,
    /// Screenshot-like (png, always shown with Photo).
    Screenshot,
    /// Office document.
    Office,
    /// PDF.
    Pdf,
    /// Possible scan of paper (additional line).
    Scan,
    /// Audio or video.
    AudioVideo,
    /// Archive.
    Archive,
    /// Email.
    Email,
    /// Anything else.
    Other,
}

impl FileClass {
    pub(crate) fn name_key(self) -> &'static str {
        match self {
            FileClass::Photo => "sui-class-photo",
            FileClass::Screenshot => "sui-class-screenshot",
            FileClass::Office => "sui-class-office",
            FileClass::Pdf => "sui-class-pdf",
            FileClass::Scan => "sui-class-scan",
            FileClass::AudioVideo => "sui-class-av",
            FileClass::Archive => "sui-class-archive",
            FileClass::Email => "sui-class-email",
            FileClass::Other => "sui-class-other",
        }
    }

    pub(crate) fn risk_keys(self) -> &'static [&'static str] {
        match self {
            FileClass::Photo => &[
                "sui-risk-photo-location",
                "sui-risk-photo-background",
                "sui-risk-photo-camera",
            ],
            FileClass::Screenshot => &["sui-risk-screenshot"],
            FileClass::Office => &["sui-risk-office-meta", "sui-risk-office-canary"],
            FileClass::Pdf => &["sui-risk-pdf-meta", "sui-risk-pdf-dots"],
            FileClass::Scan => &["sui-risk-scan"],
            FileClass::AudioVideo => &["sui-risk-av-meta", "sui-risk-av-voices"],
            FileClass::Archive => &["sui-risk-archive"],
            FileClass::Email => &["sui-risk-email"],
            FileClass::Other => &["sui-risk-other"],
        }
    }
}

/// Lower-cased extension of a display name (`[a-z0-9]{1,8}`, else none; 05 §8.3).
fn extension(name: &str) -> Option<String> {
    let (_, ext) = name.rsplit_once('.')?;
    let ext = ext.to_ascii_lowercase();
    if ext.is_empty() || ext.len() > 8 || !ext.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return None;
    }
    Some(ext)
}

/// Classes for a file name, primary class first (05 §7.2 table, including the png
/// Screenshot line and the pdf/tiff/jpg Scan line).
pub fn classify(name: &str) -> Vec<FileClass> {
    let Some(ext) = extension(name) else {
        return vec![FileClass::Other];
    };
    let mut out = Vec::new();
    match ext.as_str() {
        "jpg" | "jpeg" | "heic" | "heif" | "png" | "webp" | "tiff" | "dng" | "avif" => {
            out.push(FileClass::Photo);
        }
        "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "odt" | "ods" | "odp" | "rtf" => {
            out.push(FileClass::Office);
        }
        "pdf" => out.push(FileClass::Pdf),
        "mp3" | "m4a" | "wav" | "ogg" | "mp4" | "mov" | "webm" | "mkv" => {
            out.push(FileClass::AudioVideo);
        }
        "zip" | "7z" | "rar" | "tar" | "gz" => out.push(FileClass::Archive),
        "eml" | "msg" => out.push(FileClass::Email),
        _ => out.push(FileClass::Other),
    }
    if ext == "png" {
        out.push(FileClass::Screenshot);
    }
    if matches!(ext.as_str(), "pdf" | "tiff" | "jpg") {
        out.push(FileClass::Scan);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn table_05_7_2() {
        assert_eq!(classify("file-01.JPG"), [FileClass::Photo, FileClass::Scan]);
        assert_eq!(classify("a.png"), [FileClass::Photo, FileClass::Screenshot]);
        assert_eq!(classify("a.pdf"), [FileClass::Pdf, FileClass::Scan]);
        assert_eq!(classify("a.docx"), [FileClass::Office]);
        assert_eq!(classify("a.tar.gz"), [FileClass::Archive]);
        assert_eq!(classify("a.eml"), [FileClass::Email]);
        assert_eq!(classify("a.mkv"), [FileClass::AudioVideo]);
        assert_eq!(classify("noext"), [FileClass::Other]);
        assert_eq!(classify("a."), [FileClass::Other]);
        assert_eq!(classify("a.verylongext"), [FileClass::Other]);
        assert_eq!(classify("a.p\u{0131}f"), [FileClass::Other]);
    }

    proptest! {
        #[test]
        fn classify_never_panics_and_is_nonempty(name in ".{0,64}") {
            let c = classify(&name);
            prop_assert!(!c.is_empty());
        }
    }
}
