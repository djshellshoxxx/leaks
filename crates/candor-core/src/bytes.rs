// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Bounds-checked big-endian reader for hostile input. Never panics.

use crate::error::{Error, Result};

#[derive(Debug)]
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let (head, tail) = self.buf.split_at_checked(n).ok_or(Error::Length)?;
        self.buf = tail;
        Ok(head)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| Error::Length)
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(u8::from_be_bytes(self.array::<1>()?))
    }

    pub(crate) fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array::<2>()?))
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array::<4>()?))
    }

    pub(crate) fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array::<8>()?))
    }

    pub(crate) fn remaining(&self) -> usize {
        self.buf.len()
    }

    pub(crate) fn rest(self) -> &'a [u8] {
        self.buf
    }

    /// Require that the input has been fully consumed.
    pub(crate) fn finish(self) -> Result<()> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(Error::Malformed("trailing data"))
        }
    }
}

/// Concatenate byte slices.
pub(crate) fn concat(parts: &[&[u8]]) -> Vec<u8> {
    let len = parts.iter().fold(0usize, |a, p| a.saturating_add(p.len()));
    let mut v = Vec::with_capacity(len);
    for p in parts {
        v.extend_from_slice(p);
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_bounds() {
        let mut r = Reader::new(&[1, 2, 3]);
        assert_eq!(r.u16(), Ok(0x0102));
        assert_eq!(r.u16(), Err(Error::Length));
        assert_eq!(r.u8(), Ok(3));
        assert!(r.finish().is_ok());
        let r = Reader::new(&[1]);
        assert!(r.finish().is_err());
    }
}
