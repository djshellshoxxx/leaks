// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Payload STREAM (§13.3, CRYPTO-007/009): ChaCha20-Poly1305 over 64 KiB chunks with
//! `nonce_i = u88be(i) ‖ last_flag`.
//!
//! Two decryption APIs:
//! * [`decrypt`]: buffered; returns plaintext only after **every** chunk, including the
//!   final one, has verified. On any failure no plaintext is returned.
//! * [`StreamDecryptor`] / [`ChunkReader`]: chunk iterator. Each yielded chunk has
//!   passed its own tag check, but the stream as a whole is authentic only after
//!   `finish()` returns `Ok`. Consumers that must not act on partial data (C-17,
//!   exports) MUST buffer (encrypted scratch) and discard everything unless `finish()`
//!   succeeds (§8, §13.3). After any error the decryptor is poisoned.

use crate::aead::{chacha_open, chacha_seal};
use crate::error::{Error, Result};
use crate::secret::AeadKey;
use crate::suite::AEAD_TAG_LEN;
use zeroize::Zeroizing;

/// Plaintext chunk size (64 KiB).
pub const CHUNK_SIZE: usize = 65_536;
/// Ciphertext size of a full chunk.
pub const CHUNK_CT_SIZE: usize = CHUNK_SIZE + AEAD_TAG_LEN;
const CHUNK_SIZE_U64: u64 = 65_536;
const TAG_U64: u64 = 16;

/// Number of chunks: `n = max(1, ceil(len / 65536))`.
#[must_use]
pub fn chunk_count(plaintext_len: u64) -> u64 {
    plaintext_len.div_ceil(CHUNK_SIZE_U64).max(1)
}

/// Exact ciphertext length for a plaintext length.
pub fn ciphertext_len(plaintext_len: u64) -> Result<u64> {
    chunk_count(plaintext_len)
        .checked_mul(TAG_U64)
        .and_then(|t| t.checked_add(plaintext_len))
        .ok_or(Error::TooLarge)
}

/// Plaintext length of chunk `i` (callers guarantee `i < n`).
fn chunk_plain_len(plaintext_len: u64, i: u64) -> Result<usize> {
    let n = chunk_count(plaintext_len);
    let len = if i.checked_add(1) == Some(n) {
        let before = i.checked_mul(CHUNK_SIZE_U64).ok_or(Error::Internal)?;
        plaintext_len.checked_sub(before).ok_or(Error::Internal)?
    } else if i < n {
        CHUNK_SIZE_U64
    } else {
        return Err(Error::Stream("chunk index out of range"));
    };
    usize::try_from(len).map_err(|_| Error::TooLarge)
}

/// `nonce_i = u88be(i) ‖ (0x01 if last else 0x00)`.
#[must_use]
pub fn chunk_nonce(i: u64, last: bool) -> [u8; 12] {
    let mut n = [0u8; 12];
    let (ctr, flag) = n.split_at_mut(11);
    if let Some(tail) = ctr.get_mut(3..) {
        tail.copy_from_slice(&i.to_be_bytes());
    }
    if let Some(f) = flag.first_mut() {
        *f = u8::from(last);
    }
    n
}

/// Incremental STREAM encryptor for a payload of known length.
pub struct StreamEncryptor {
    key: AeadKey,
    plaintext_len: u64,
    n: u64,
    next: u64,
}

impl core::fmt::Debug for StreamEncryptor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StreamEncryptor")
            .field("next", &self.next)
            .field("n", &self.n)
            .finish_non_exhaustive()
    }
}

impl StreamEncryptor {
    /// New encryptor for `plaintext_len` bytes.
    #[must_use]
    pub fn new(key: AeadKey, plaintext_len: u64) -> Self {
        Self {
            key,
            plaintext_len,
            n: chunk_count(plaintext_len),
            next: 0,
        }
    }

    /// Encrypt the next chunk. Every chunk except the last must be exactly 64 KiB;
    /// the last must be exactly the remaining length.
    pub fn encrypt_chunk(&mut self, chunk: &[u8]) -> Result<Vec<u8>> {
        if self.next >= self.n {
            return Err(Error::Stream("all chunks already encrypted"));
        }
        if chunk.len() != chunk_plain_len(self.plaintext_len, self.next)? {
            return Err(Error::Stream("wrong chunk length"));
        }
        let last = self.next.checked_add(1) == Some(self.n);
        let ct = chacha_seal(&self.key, &chunk_nonce(self.next, last), &[], chunk)?;
        self.next = self.next.checked_add(1).ok_or(Error::Internal)?;
        Ok(ct)
    }

    /// Require that all chunks were produced.
    pub fn finish(self) -> Result<()> {
        if self.next == self.n {
            Ok(())
        } else {
            Err(Error::Stream("incomplete"))
        }
    }
}

/// Encrypt a whole payload.
pub fn encrypt(key: AeadKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    let len = u64::try_from(plaintext.len()).map_err(|_| Error::TooLarge)?;
    let total = usize::try_from(ciphertext_len(len)?).map_err(|_| Error::TooLarge)?;
    let mut enc = StreamEncryptor::new(key, len);
    let mut out = Vec::with_capacity(total);
    if plaintext.is_empty() {
        out.extend_from_slice(&enc.encrypt_chunk(&[])?);
    } else {
        for c in plaintext.chunks(CHUNK_SIZE) {
            out.extend_from_slice(&enc.encrypt_chunk(c)?);
        }
    }
    enc.finish()?;
    Ok(out)
}

/// Chunk-at-a-time STREAM decryptor. See the module documentation for the release
/// semantics.
pub struct StreamDecryptor {
    key: AeadKey,
    plaintext_len: u64,
    n: u64,
    next: u64,
    poisoned: bool,
}

impl core::fmt::Debug for StreamDecryptor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StreamDecryptor")
            .field("next", &self.next)
            .field("n", &self.n)
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

impl StreamDecryptor {
    /// New decryptor for a payload whose plaintext length is `plaintext_len` (from the
    /// authenticated CoreHeader).
    #[must_use]
    pub fn new(key: AeadKey, plaintext_len: u64) -> Self {
        Self {
            key,
            plaintext_len,
            n: chunk_count(plaintext_len),
            next: 0,
            poisoned: false,
        }
    }

    /// Expected ciphertext length of the next chunk, or `None` when complete.
    #[must_use]
    pub fn next_chunk_ct_len(&self) -> Option<usize> {
        if self.poisoned || self.next >= self.n {
            return None;
        }
        chunk_plain_len(self.plaintext_len, self.next)
            .ok()?
            .checked_add(AEAD_TAG_LEN)
    }

    /// Decrypt the next chunk. The returned plaintext has passed this chunk's tag
    /// check. Any error poisons the decryptor.
    pub fn decrypt_chunk(&mut self, ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let r = self.decrypt_chunk_inner(ct);
        if r.is_err() {
            self.poisoned = true;
        }
        r
    }

    fn decrypt_chunk_inner(&mut self, ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if self.poisoned {
            return Err(Error::Stream("poisoned"));
        }
        let expected = self
            .next_chunk_ct_len()
            .ok_or(Error::Stream("trailing chunk"))?;
        if ct.len() != expected {
            return Err(Error::Stream("wrong chunk length"));
        }
        let last = self.next.checked_add(1) == Some(self.n);
        let pt = chacha_open(&self.key, &chunk_nonce(self.next, last), &[], ct)?;
        self.next = self.next.checked_add(1).ok_or(Error::Internal)?;
        Ok(pt)
    }

    /// Final verification: every chunk including the final-flagged one verified.
    pub fn finish(self) -> Result<()> {
        if !self.poisoned && self.next == self.n {
            Ok(())
        } else {
            Err(Error::Stream("truncated"))
        }
    }

    /// Random access: decrypt chunk `i` independently (seek = i × 65552). The caller
    /// gains no whole-stream guarantee from this.
    pub fn decrypt_chunk_at(
        key: &AeadKey,
        plaintext_len: u64,
        i: u64,
        ct: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let n = chunk_count(plaintext_len);
        let expected = chunk_plain_len(plaintext_len, i)?
            .checked_add(AEAD_TAG_LEN)
            .ok_or(Error::Internal)?;
        if ct.len() != expected {
            return Err(Error::Stream("wrong chunk length"));
        }
        chacha_open(key, &chunk_nonce(i, i.checked_add(1) == Some(n)), &[], ct)
    }

    /// Wrap a reader to iterate verified chunks.
    pub fn reader<R: std::io::Read>(self, r: R) -> ChunkReader<R> {
        ChunkReader { dec: self, r }
    }
}

/// Iterator of verified chunks read from an `io::Read`; call [`ChunkReader::finish`]
/// after the iterator is exhausted to check the final flag and trailing data.
pub struct ChunkReader<R> {
    dec: StreamDecryptor,
    r: R,
}

impl<R> core::fmt::Debug for ChunkReader<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChunkReader")
            .field("dec", &self.dec)
            .finish_non_exhaustive()
    }
}

impl<R: std::io::Read> Iterator for ChunkReader<R> {
    type Item = Result<Zeroizing<Vec<u8>>>;

    fn next(&mut self) -> Option<Self::Item> {
        let len = self.dec.next_chunk_ct_len()?;
        let mut buf = vec![0u8; len];
        if self.r.read_exact(&mut buf).is_err() {
            self.dec.poisoned = true;
            return Some(Err(Error::Stream("truncated")));
        }
        Some(self.dec.decrypt_chunk(&buf))
    }
}

impl<R: std::io::Read> ChunkReader<R> {
    /// Verify that the stream is complete and that no data follows the final chunk.
    pub fn finish(mut self) -> Result<()> {
        let mut probe = [0u8; 1];
        loop {
            match self.r.read(&mut probe) {
                Ok(0) => break,
                Ok(_) => return Err(Error::Stream("trailing data")),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return Err(Error::Stream("read error")),
            }
        }
        self.dec.finish()
    }
}

/// Buffered decryption: returns plaintext only if the ciphertext has exactly the
/// expected length and every chunk, including the final one, verifies.
pub fn decrypt(key: AeadKey, plaintext_len: u64, ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let expected = ciphertext_len(plaintext_len)?;
    if u64::try_from(ct.len()).ok() != Some(expected) {
        return Err(Error::Stream("wrong payload length"));
    }
    let cap = usize::try_from(plaintext_len).map_err(|_| Error::TooLarge)?;
    let mut out = Zeroizing::new(Vec::with_capacity(cap));
    let mut dec = StreamDecryptor::new(key, plaintext_len);
    let mut rest = ct;
    while let Some(len) = dec.next_chunk_ct_len() {
        let (chunk, tail) = rest
            .split_at_checked(len)
            .ok_or(Error::Stream("truncated"))?;
        out.extend_from_slice(&dec.decrypt_chunk(chunk)?);
        rest = tail;
    }
    if !rest.is_empty() {
        return Err(Error::Stream("trailing data"));
    }
    dec.finish()?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::*;
    use proptest::prelude::*;

    fn key() -> AeadKey {
        AeadKey::from_bytes([0x42; 32])
    }

    #[test]
    fn nonce_layout() {
        assert_eq!(chunk_nonce(0, false), [0; 12]);
        assert_eq!(chunk_nonce(1, true), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1]);
        assert_eq!(chunk_nonce(0x0102, false)[9..], [1, 2, 0]);
    }

    #[test]
    fn lengths() {
        assert_eq!(chunk_count(0), 1);
        assert_eq!(ciphertext_len(0).unwrap(), 16);
        assert_eq!(ciphertext_len(65536).unwrap(), 65552);
        assert_eq!(ciphertext_len(65537).unwrap(), 65537 + 32);
        assert!(ciphertext_len(u64::MAX).is_err());
    }

    #[test]
    fn empty_roundtrip() {
        let ct = encrypt(key(), &[]).unwrap();
        assert_eq!(ct.len(), 16);
        assert!(decrypt(key(), 0, &ct).unwrap().is_empty());
    }

    /// CRYPTO-007 negative vectors: truncated, reordered, no_final, trailing, duplication.
    #[test]
    fn negative_vectors() {
        let pt: Vec<u8> = (0..(3 * CHUNK_SIZE + 10)).map(|i| i as u8).collect();
        let len = pt.len() as u64;
        let ct = encrypt(key(), &pt).unwrap();
        assert_eq!(decrypt(key(), len, &ct).unwrap().as_slice(), pt.as_slice());
        // truncated (drop final chunk) — also with the header length adjusted
        let trunc = &ct[..3 * CHUNK_CT_SIZE];
        assert!(decrypt(key(), len, trunc).is_err());
        assert!(
            decrypt(key(), 3 * CHUNK_SIZE as u64, trunc).is_err(),
            "no_final: missing final flag"
        );
        // reordered
        let mut re = ct.clone();
        re[..CHUNK_CT_SIZE].copy_from_slice(&ct[CHUNK_CT_SIZE..2 * CHUNK_CT_SIZE]);
        re[CHUNK_CT_SIZE..2 * CHUNK_CT_SIZE].copy_from_slice(&ct[..CHUNK_CT_SIZE]);
        assert!(decrypt(key(), len, &re).is_err());
        // duplicated chunk
        let mut dup = ct.clone();
        dup[CHUNK_CT_SIZE..2 * CHUNK_CT_SIZE].copy_from_slice(&ct[..CHUNK_CT_SIZE]);
        assert!(decrypt(key(), len, &dup).is_err());
        // trailing
        let mut tr = ct.clone();
        tr.push(0);
        assert!(decrypt(key(), len, &tr).is_err());
    }

    /// CRYPTO-009: a tampered last chunk yields zero bytes from the buffered API, and
    /// the chunk reader's finish() fails.
    #[test]
    fn tampered_final_chunk_releases_nothing() {
        let pt = vec![7u8; 2 * CHUNK_SIZE + 5];
        let len = pt.len() as u64;
        let mut ct = encrypt(key(), &pt).unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x80;
        assert!(decrypt(key(), len, &ct).is_err());
        let mut rd = StreamDecryptor::new(key(), len).reader(&ct[..]);
        let mut ok_chunks = 0;
        let mut failed = false;
        for c in rd.by_ref() {
            match c {
                Ok(_) => ok_chunks += 1,
                Err(_) => failed = true,
            }
        }
        assert_eq!(ok_chunks, 2);
        assert!(failed);
        assert!(rd.finish().is_err());
    }

    #[test]
    fn chunk_reader_detects_trailing_and_truncation() {
        let pt = vec![1u8; CHUNK_SIZE + 1];
        let len = pt.len() as u64;
        let ct = encrypt(key(), &pt).unwrap();
        let mut rd = StreamDecryptor::new(key(), len).reader(&ct[..]);
        let got: Vec<u8> = rd.by_ref().flat_map(|c| c.unwrap().to_vec()).collect();
        assert_eq!(got, pt);
        assert!(rd.finish().is_ok());
        let mut tr = ct.clone();
        tr.push(9);
        let mut rd = StreamDecryptor::new(key(), len).reader(&tr[..]);
        rd.by_ref().for_each(drop);
        assert!(rd.finish().is_err());
        let mut rd = StreamDecryptor::new(key(), len).reader(&ct[..ct.len() - 1]);
        assert!(rd.by_ref().any(|c| c.is_err()));
        assert!(rd.finish().is_err());
    }

    #[test]
    fn poisoning_and_random_access() {
        let pt = vec![3u8; 2 * CHUNK_SIZE];
        let ct = encrypt(key(), &pt).unwrap();
        let mut d = StreamDecryptor::new(key(), pt.len() as u64);
        assert!(d.decrypt_chunk(&ct[CHUNK_CT_SIZE..]).is_err());
        assert!(d.decrypt_chunk(&ct[..CHUNK_CT_SIZE]).is_err(), "poisoned");
        let c1 =
            StreamDecryptor::decrypt_chunk_at(&key(), pt.len() as u64, 1, &ct[CHUNK_CT_SIZE..])
                .unwrap();
        assert_eq!(c1.len(), CHUNK_SIZE);
        assert!(
            StreamDecryptor::decrypt_chunk_at(&key(), pt.len() as u64, 2, &ct[CHUNK_CT_SIZE..])
                .is_err()
        );
    }

    #[test]
    fn encryptor_enforces_lengths() {
        let mut e = StreamEncryptor::new(key(), 10);
        assert!(e.encrypt_chunk(&[0; 9]).is_err());
        assert!(e.encrypt_chunk(&[0; 10]).is_ok());
        assert!(e.encrypt_chunk(&[]).is_err());
        assert!(e.finish().is_ok());
        let e = StreamEncryptor::new(key(), 10);
        assert!(e.finish().is_err());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]
        /// ST-024: round trip at chunk boundaries ±1; any single bit flip fails.
        #[test]
        fn roundtrip_and_bitflip(extra in 0usize..3, k in 0usize..3, bit in proptest::prelude::any::<usize>()) {
            let len = (k * CHUNK_SIZE + extra).saturating_sub(1);
            let pt: Vec<u8> = (0..len).map(|i| (i * 31) as u8).collect();
            let ct = encrypt(key(), &pt).unwrap();
            let back = decrypt(key(), len as u64, &ct).unwrap();
            prop_assert_eq!(back.as_slice(), pt.as_slice());
            let mut bad = ct.clone();
            let b = bit % (bad.len() * 8);
            bad[b / 8] ^= 1 << (b % 8);
            prop_assert!(decrypt(key(), len as u64, &bad).is_err());
        }

        /// ST-041: arbitrary bytes never decrypt and never panic.
        #[test]
        fn arbitrary_ct(bytes in proptest::collection::vec(any::<u8>(), 0..200), len in 0u64..200) {
            prop_assert!(decrypt(key(), len, &bytes).is_err());
        }
    }
}
