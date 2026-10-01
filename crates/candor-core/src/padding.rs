// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Padding buckets (§13.6, ADR-011, CRYPTO-013/014).

use crate::error::{Error, Result};
use crate::header::ObjectType;
use zeroize::Zeroizing;

/// Message bucket unit.
pub const MESSAGE_BUCKET_UNIT: u64 = 4096;
/// Largest message bucket (SUBMISSION, SOURCE_MESSAGE, REPLY).
pub const MESSAGE_MAX: u64 = 65536;
/// Largest IDENTITY bucket.
pub const IDENTITY_MAX: u64 = 4 * 4096;
/// First file bucket b_0.
pub const FILE_BUCKET_0: u64 = 262_144;
/// Alignment of file buckets.
pub const FILE_BUCKET_ALIGN: u64 = 65_536;
/// Ceiling on file content across all profiles (16 GiB, EE maximum per 10 §5;
/// profiles enforce their lower limits before sealing). The last legal bucket is the
/// first bucket ≥ this value.
pub const FILE_CONTENT_MAX: u64 = 16 * 1024 * 1024 * 1024;

/// Next file bucket: `b_{j+1} = 65536 × ceil(1.25 × b_j / 65536)` computed exactly as
/// `65536 × ceil(5 × b_j / 262144)`.
fn next_file_bucket(b: u64) -> Option<u64> {
    let num = b.checked_mul(5)?;
    let den = FILE_BUCKET_ALIGN.checked_mul(4)?;
    num.div_ceil(den).checked_mul(FILE_BUCKET_ALIGN)
}

/// Iterator over the legal file buckets, ascending.
pub fn file_buckets() -> impl Iterator<Item = u64> {
    let mut cur = Some(FILE_BUCKET_0);
    let mut done = false;
    core::iter::from_fn(move || {
        if done {
            return None;
        }
        let b = cur?;
        if b >= FILE_CONTENT_MAX {
            done = true;
        }
        cur = next_file_bucket(b);
        Some(b)
    })
}

/// Whether `len` is a legal `padded_plaintext_len` for `t` (§13.1 reader check).
#[must_use]
pub fn is_legal_bucket(t: ObjectType, len: u64) -> bool {
    match t {
        ObjectType::Submission | ObjectType::SourceMessage | ObjectType::Reply => {
            len != 0 && len % MESSAGE_BUCKET_UNIT == 0 && len <= MESSAGE_MAX
        }
        ObjectType::Identity => len != 0 && len % MESSAGE_BUCKET_UNIT == 0 && len <= IDENTITY_MAX,
        ObjectType::AttachmentBundle
        | ObjectType::CaseAttachment
        | ObjectType::CaseDocument
        | ObjectType::ExportPackage => file_buckets().take_while(|b| *b <= len).any(|b| b == len),
    }
}

/// Smallest legal bucket that holds `content_len` bytes.
pub fn bucket_for(t: ObjectType, content_len: u64) -> Result<u64> {
    match t {
        ObjectType::Submission | ObjectType::SourceMessage | ObjectType::Reply | ObjectType::Identity => {
            let max = if t == ObjectType::Identity { IDENTITY_MAX } else { MESSAGE_MAX };
            let b = content_len
                .max(1)
                .div_ceil(MESSAGE_BUCKET_UNIT)
                .checked_mul(MESSAGE_BUCKET_UNIT)
                .ok_or(Error::TooLarge)?;
            if b > max { Err(Error::TooLarge) } else { Ok(b) }
        }
        _ => file_buckets().find(|b| *b >= content_len).ok_or(Error::TooLarge),
    }
}

/// Zero-pad `content` to its bucket. The caller's content must already carry its own
/// length (e.g. `u32be(cbor_len) ‖ cbor`, §13.4); padding bytes are zero and lie
/// inside the AEAD.
pub fn pad(t: ObjectType, content: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let len = u64::try_from(content.len()).map_err(|_| Error::TooLarge)?;
    let b = usize::try_from(bucket_for(t, len)?).map_err(|_| Error::TooLarge)?;
    let mut v = Zeroizing::new(Vec::with_capacity(b));
    v.extend_from_slice(content);
    v.resize(b, 0);
    Ok(v)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
    use super::*;

    /// CRYPTO-014 bucket computation vectors.
    #[test]
    fn file_bucket_series() {
        let v: Vec<u64> = file_buckets().take(6).collect();
        // 262144; 65536*ceil(327680/65536)=327680; 65536*ceil(409600/65536)=7*65536=458752;
        // 65536*ceil(573440/65536)=9*65536=589824; 65536*ceil(737280/65536)=12*65536=786432;
        // 65536*ceil(983040/65536)=15*65536=983040
        assert_eq!(v, vec![262_144, 327_680, 458_752, 589_824, 786_432, 983_040]);
        let all: Vec<u64> = file_buckets().collect();
        assert!(all.windows(2).all(|w| w[0] < w[1]));
        assert!(all.iter().all(|b| b % 65536 == 0));
        let last = *all.last().unwrap();
        assert!(last >= FILE_CONTENT_MAX);
        assert!(all[all.len() - 2] < FILE_CONTENT_MAX);
        // Overhead bound: 25 % + 64 KiB (§13.6).
        for w in all.windows(2) {
            assert!(w[1] <= w[0] + w[0] / 4 + 65536);
        }
    }

    #[test]
    fn message_buckets() {
        assert!(is_legal_bucket(ObjectType::Submission, 4096));
        assert!(is_legal_bucket(ObjectType::Reply, 65536));
        assert!(!is_legal_bucket(ObjectType::Reply, 65536 + 4096));
        assert!(!is_legal_bucket(ObjectType::Reply, 0));
        assert!(!is_legal_bucket(ObjectType::Reply, 4097));
        assert!(is_legal_bucket(ObjectType::Identity, 16384));
        assert!(!is_legal_bucket(ObjectType::Identity, 20480));
        assert_eq!(bucket_for(ObjectType::Submission, 0).unwrap(), 4096);
        assert_eq!(bucket_for(ObjectType::Submission, 4097).unwrap(), 8192);
        assert_eq!(bucket_for(ObjectType::Submission, 65537), Err(Error::TooLarge));
        assert_eq!(bucket_for(ObjectType::AttachmentBundle, 0).unwrap(), 262_144);
        assert_eq!(bucket_for(ObjectType::AttachmentBundle, 262_145).unwrap(), 327_680);
        assert!(is_legal_bucket(ObjectType::CaseDocument, 327_680));
        assert!(!is_legal_bucket(ObjectType::CaseDocument, 393_216));
        assert_eq!(bucket_for(ObjectType::ExportPackage, u64::MAX), Err(Error::TooLarge));
    }

    #[test]
    fn pad_zero_fills() {
        let p = pad(ObjectType::Submission, b"abc").unwrap();
        assert_eq!(p.len(), 4096);
        assert_eq!(&p[..3], b"abc");
        assert!(p[3..].iter().all(|b| *b == 0));
    }

    proptest::proptest! {
        /// CRYPTO-013 size-class property: every padded length is a legal bucket.
        #[test]
        fn padded_len_is_legal(n in 0u64..70_000) {
            match bucket_for(ObjectType::SourceMessage, n) {
                Ok(b) => { proptest::prop_assert!(is_legal_bucket(ObjectType::SourceMessage, b)); proptest::prop_assert!(b >= n); }
                Err(_) => proptest::prop_assert!(n > MESSAGE_MAX),
            }
        }

        #[test]
        fn file_bucket_legal(n in 0u64..(1u64 << 36)) {
            if let Ok(b) = bucket_for(ObjectType::AttachmentBundle, n) {
                proptest::prop_assert!(is_legal_bucket(ObjectType::AttachmentBundle, b));
                proptest::prop_assert!(b >= n);
            }
        }
    }
}
