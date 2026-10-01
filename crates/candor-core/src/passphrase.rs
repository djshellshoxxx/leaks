// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Source passphrase scheme (§11.1–§11.3, ADR-005, ADR-046(7), ADR-047(6)).

use crate::error::{Error, Result};
use crate::hash::{lookup_tag, sha256};
use crate::kdf::{hkdf_expand, hkdf_extract};
use crate::kem::{KemKeyPair, KemPrivateKey, KemPublicKey};
use crate::labels;
use crate::rand::{OsRandom, RandomSource, uniform_below};
use crate::secret::{AeadKey, Secret32};
use crate::sig::{SigningKey, sign_with_context};
use crate::suite::Suite;
use std::sync::OnceLock;
use subtle::{Choice, ConstantTimeEq};
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

/// The official EFF large wordlist (7,776 entries, dice-number ‖ TAB ‖ word per line).
const EFF_LARGE_TXT: &str = include_str!("../data/eff_large_wordlist.txt");

/// SHA-256 of `data/eff_large_wordlist.txt` (the official file
/// <https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt>; see SPEC-NOTES for
/// provenance).
pub const EFF_LARGE_WORDLIST_SHA256: &str =
    "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e";

/// The four entries of the official EFF large list that contain a hyphen and are
/// therefore excluded under §11.1(b) (a hyphen is a separator after normalization).
pub const EFF_LARGE_EXCLUDED: [&str; 4] = ["drop-down", "felt-tip", "t-shirt", "yo-yo"];

/// Words used from the EFF large list (7,776 − 4). `10 × log2(7772) ≈ 129.24` bits.
pub const EFF_LARGE_USED_LEN: usize = 7772;

/// Minimum wordlist size (§11.1).
pub const MIN_WORDLIST_LEN: usize = 2048;

/// Argon2id memory cost in KiB (ADR-046(7)).
pub const ARGON2_M_KIB: u32 = 65_536;
/// Argon2id iterations.
pub const ARGON2_T: u32 = 3;
/// Argon2id lanes.
pub const ARGON2_P: u32 = 1;

/// Longest accepted passphrase input in bytes, checked before anything is allocated
/// (AUD-RM1-CORE-03). Ten EFF words need at most ~100 bytes.
pub const MAX_PASSPHRASE_INPUT_LEN: usize = 1024;

/// Longest accepted wordlist entry in bytes after normalization.
pub const MAX_WORD_LEN: usize = 32;

/// Upper bound on the UTF-8 byte expansion of NFKC (U+FDFA expands to 18 code
/// points). The NFKC buffer is sized `input × 18` and never grows; output beyond it
/// fails closed with [`Error::Length`].
const NFKC_MAX_EXPANSION: usize = 18;

/// Fixed-width word slot for constant-time membership tests: `u8 len ‖ word ‖ 0…`.
const WORD_SLOT_LEN: usize = 1 + MAX_WORD_LEN;

/// A validated wordlist. Words are stored normalized.
#[derive(Debug, Clone)]
pub struct Wordlist {
    words: Vec<String>,
    slots: Vec<[u8; WORD_SLOT_LEN]>,
    word_count: usize,
    max_word_len: usize,
}

/// Encode a token into a fixed-width slot. Over-long tokens get the length byte
/// 0xFF, which no list word has, so they never match.
fn word_slot(word: &[u8]) -> Zeroizing<[u8; WORD_SLOT_LEN]> {
    let mut slot = Zeroizing::new([0u8; WORD_SLOT_LEN]);
    let (len, body) = slot.split_at_mut(1);
    match (u8::try_from(word.len()), body.get_mut(..word.len())) {
        (Ok(l), Some(dst)) => {
            len.copy_from_slice(&[l]);
            dst.copy_from_slice(word);
        }
        _ => len.copy_from_slice(&[0xFF]),
    }
    slot
}

/// A zeroizing `String` whose capacity is reserved once, before any secret byte is
/// written (AUD-RM1-CORE-03).
fn fixed_buffer(capacity: usize) -> Result<Zeroizing<String>> {
    let mut s = Zeroizing::new(String::new());
    s.try_reserve_exact(capacity).map_err(|_| Error::Length)?;
    Ok(s)
}

/// Push without ever reallocating: fails closed if the reserved capacity would be
/// exceeded.
fn push_bounded(buf: &mut String, c: char) -> Result<()> {
    if buf
        .len()
        .checked_add(c.len_utf8())
        .is_none_or(|n| n > buf.capacity())
    {
        return Err(Error::Length);
    }
    buf.push(c);
    Ok(())
}

fn push_str_bounded(buf: &mut String, s: &str) -> Result<()> {
    if buf
        .len()
        .checked_add(s.len())
        .is_none_or(|n| n > buf.capacity())
    {
        return Err(Error::Length);
    }
    buf.push_str(s);
    Ok(())
}

/// Smallest `w` with `N^w ≥ 2^128`, i.e. `ceil(128 / log2 N)` computed exactly.
fn words_for_128_bits(n: usize) -> Result<usize> {
    let n = u128::try_from(n).map_err(|_| Error::InvalidWordlist)?;
    if n < 2 {
        return Err(Error::InvalidWordlist);
    }
    let mut acc: u128 = 1;
    for w in 1..=128usize {
        match acc.checked_mul(n) {
            None => return Ok(w), // N^w ≥ 2^128
            Some(v) => acc = v,
        }
    }
    Err(Error::InvalidWordlist)
}

impl Wordlist {
    /// Build a list from words (§11.1): N ≥ 2048, unique after normalization, no
    /// separators after normalization, no empty entries.
    pub fn from_words<S: AsRef<str>>(words: &[S]) -> Result<Self> {
        if words.len() < MIN_WORDLIST_LEN || u32::try_from(words.len()).is_err() {
            return Err(Error::InvalidWordlist);
        }
        let mut out = Vec::with_capacity(words.len());
        let mut slots = Vec::with_capacity(words.len());
        let mut seen = std::collections::HashSet::with_capacity(words.len());
        let mut max_word_len = 0usize;
        for w in words {
            let n = normalize(w.as_ref()).map_err(|_| Error::InvalidWordlist)?;
            if n.is_empty()
                || n.len() > MAX_WORD_LEN
                || n.contains(' ')
                || !seen.insert(n.to_string())
            {
                return Err(Error::InvalidWordlist);
            }
            max_word_len = max_word_len.max(n.len());
            slots.push(*word_slot(n.as_bytes()));
            out.push(n.to_string());
        }
        let word_count = words_for_128_bits(out.len())?;
        Ok(Self {
            words: out,
            slots,
            word_count,
            max_word_len,
        })
    }

    /// The EFF large wordlist (English default; 7,776 words → 10 words, 129.25 bits).
    pub fn eff_large() -> Result<&'static Wordlist> {
        static LIST: OnceLock<Result<Wordlist>> = OnceLock::new();
        LIST.get_or_init(|| {
            if crate::kdf::ct_eq(
                hex_lower(&sha256(&[EFF_LARGE_TXT.as_bytes()])).as_bytes(),
                EFF_LARGE_WORDLIST_SHA256.as_bytes(),
            ) {
                let all: Vec<&str> = EFF_LARGE_TXT
                    .lines()
                    .filter_map(|l| l.split('\t').nth(1))
                    .collect();
                if all.len() != 7776 {
                    return Err(Error::InvalidWordlist);
                }
                // §11.1(b): entries containing a separator after normalization are
                // excluded (Implementation decision, SPEC-NOTES).
                let words: Vec<&str> = all
                    .into_iter()
                    .filter(|w| !EFF_LARGE_EXCLUDED.contains(w))
                    .collect();
                if words.len() != EFF_LARGE_USED_LEN {
                    return Err(Error::InvalidWordlist);
                }
                Wordlist::from_words(&words)
            } else {
                Err(Error::InvalidWordlist)
            }
        })
        .as_ref()
        .map_err(|e| *e)
    }

    /// Number of words.
    #[must_use]
    pub fn len(&self) -> usize {
        self.words.len()
    }

    /// Always false for a validated list.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.words.is_empty()
    }

    /// Words per passphrase: `ceil(128 / log2 N)`.
    #[must_use]
    pub fn word_count(&self) -> usize {
        self.word_count
    }

    /// Word at index.
    #[must_use]
    pub fn get(&self, i: usize) -> Option<&str> {
        self.words.get(i).map(String::as_str)
    }

    /// Usability check (§11.3): the normalized passphrase has exactly `word_count`
    /// tokens, each in this list. Derivation never depends on this.
    ///
    /// AUD-RM1-CORE-08: constant time in the passphrase content. Every token is
    /// compared with every word on fixed-width slots with `subtle`, without early
    /// exit; only the number of tokens (a length property) affects the running time.
    #[must_use]
    pub fn check(&self, passphrase: &str) -> bool {
        let Ok(n) = normalize(passphrase) else {
            return false;
        };
        let mut all = Choice::from(1u8);
        let mut count: u64 = 0;
        for tok in n.split(' ') {
            count = count.saturating_add(1);
            let slot = word_slot(tok.as_bytes());
            let mut found = Choice::from(0u8);
            for w in &self.slots {
                found |= w.as_slice().ct_eq(slot.as_slice());
            }
            all &= found;
        }
        let expected = u64::try_from(self.word_count).unwrap_or(u64::MAX);
        bool::from(all & count.ct_eq(&expected))
    }
}

fn hex_lower(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len().saturating_mul(2));
    for x in b {
        s.push(char::from(
            H.get(usize::from(x >> 4)).copied().unwrap_or(b'0'),
        ));
        s.push(char::from(
            H.get(usize::from(x & 0x0f)).copied().unwrap_or(b'0'),
        ));
    }
    s
}

/// A generated passphrase. Zeroized on drop; `Debug` redacted; no `Display`.
pub struct Passphrase(Zeroizing<String>);

impl core::fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Passphrase(<redacted>)")
    }
}

impl Passphrase {
    /// The passphrase text (words separated by single spaces).
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

/// Generate a passphrase: `word_count` words drawn uniformly and independently with
/// rejection sampling over `getrandom` output (§11.1).
pub fn generate(list: &Wordlist) -> Result<Passphrase> {
    generate_with(&mut OsRandom, list)
}

pub(crate) fn generate_with(rng: &mut dyn RandomSource, list: &Wordlist) -> Result<Passphrase> {
    let n = u32::try_from(list.len()).map_err(|_| Error::InvalidWordlist)?;
    // AUD-RM1-CORE-03: capacity for the longest possible passphrase is reserved before
    // the first word is written, so the buffer never reallocates.
    let cap = list
        .max_word_len
        .checked_add(1)
        .and_then(|w| w.checked_mul(list.word_count()))
        .ok_or(Error::Internal)?;
    let mut s = fixed_buffer(cap)?;
    let mut first: Option<usize> = None;
    let mut all_same = true;
    for i in 0..list.word_count() {
        let idx = usize::try_from(uniform_below(rng, n)?).map_err(|_| Error::Internal)?;
        all_same &= *first.get_or_insert(idx) == idx;
        if i > 0 {
            push_bounded(&mut s, ' ')?;
        }
        push_str_bounded(&mut s, list.get(idx).ok_or(Error::Internal)?)?;
    }
    // AUD-RM1-CORE-12: a stuck RNG below the rejection limit yields the same word every
    // time (probability N^-(w-1) ≈ 2^-116 for an honest RNG): fail closed.
    if all_same && list.word_count() > 1 {
        return Err(Error::Rng);
    }
    Ok(Passphrase(s))
}

fn is_separator(c: char) -> bool {
    c.is_whitespace() || c == '-' || c == ',' || ('\u{2010}'..='\u{2015}').contains(&c)
}

/// `normalize(p)` (§11.3, ADR-047(6)): NFKC; Unicode default full lowercase
/// (locale-independent); every maximal run of White_Space, U+002D, U+2010..U+2015 and
/// U+002C replaced by one U+0020; leading/trailing spaces stripped.
///
/// AUD-RM1-CORE-03: input longer than [`MAX_PASSPHRASE_INPUT_LEN`] bytes is rejected
/// with [`Error::Length`] before any allocation. Every intermediate (NFKC output,
/// lowercase output) lives in a zeroizing buffer whose capacity is fixed before the
/// first byte is written, so no reallocation leaves passphrase fragments in freed heap.
pub fn normalize(p: &str) -> Result<Zeroizing<String>> {
    if p.len() > MAX_PASSPHRASE_INPUT_LEN {
        return Err(Error::Length);
    }
    let mut nfkc = fixed_buffer(p.len().saturating_mul(NFKC_MAX_EXPANSION))?;
    for c in p.nfkc() {
        push_bounded(&mut nfkc, c)?;
    }
    let lower = lowercase_fixed(&nfkc)?;
    drop(nfkc);
    let mut out = fixed_buffer(lower.len())?;
    let mut pending_sep = false;
    for c in lower.chars() {
        if is_separator(c) {
            pending_sep = true;
        } else {
            if pending_sep && !out.is_empty() {
                push_bounded(&mut out, ' ')?;
            }
            pending_sep = false;
            push_bounded(&mut out, c)?;
        }
    }
    Ok(out)
}

/// KELVIN SIGN (3 bytes in UTF-8) lowercases to ASCII `k` (1 byte).
const SHRINK_PAD: char = '\u{212A}';

/// `str::to_lowercase` (Unicode default full lowercase incl. Final_Sigma) without a
/// reallocation of its output buffer.
///
/// `str::to_lowercase` writes into a buffer of capacity `input.len()`; it reallocates
/// only if some prefix of the output is longer than that. We compute the largest
/// prefix growth `g` exactly (σ/ς and Σ all take 2 bytes, so per-char lengths are
/// exact) and, if `g > 0`, append `' '` and `ceil(g / 2)` KELVIN SIGNs, each of which
/// shrinks by 2 bytes, then truncate the output back. The space before the padding
/// is neither cased nor case-ignorable, so Final_Sigma decisions are unchanged.
fn lowercase_fixed(src: &str) -> Result<Zeroizing<String>> {
    let mut in_len: usize = 0;
    let mut out_len: usize = 0;
    let mut max_growth: usize = 0;
    for c in src.chars() {
        in_len = in_len.checked_add(c.len_utf8()).ok_or(Error::Length)?;
        for l in c.to_lowercase() {
            out_len = out_len.checked_add(l.len_utf8()).ok_or(Error::Length)?;
        }
        max_growth = max_growth.max(out_len.saturating_sub(in_len));
    }
    let lower = if max_growth == 0 {
        Zeroizing::new(src.to_lowercase())
    } else {
        let pads = max_growth.div_ceil(2);
        let cap = pads
            .checked_mul(SHRINK_PAD.len_utf8())
            .and_then(|x| x.checked_add(1))
            .and_then(|x| x.checked_add(src.len()))
            .ok_or(Error::Length)?;
        let mut padded = fixed_buffer(cap)?;
        push_str_bounded(&mut padded, src)?;
        push_bounded(&mut padded, ' ')?;
        for _ in 0..pads {
            push_bounded(&mut padded, SHRINK_PAD)?;
        }
        let mut l = Zeroizing::new(padded.to_lowercase());
        // Bytes past `out_len` are the lowercased padding; truncation keeps the
        // allocation, which `Zeroizing` wipes in full on drop.
        if !l.is_char_boundary(out_len) {
            return Err(Error::Internal);
        }
        l.truncate(out_len);
        l
    };
    if lower.len() != out_len {
        return Err(Error::Internal);
    }
    Ok(lower)
}

/// `salt = SHA-256("candor/v1/source-salt" ‖ deployment_salt ‖ tenant_id)` (§11.3).
#[must_use]
pub fn source_salt(deployment_salt: &[u8; 32], tenant_id: &[u8; 16]) -> [u8; 32] {
    sha256(&[labels::SOURCE_SALT_DOMAIN, deployment_salt, tenant_id])
}

/// Caller-provided Argon2id working memory (AUD-RM1-CORE-02).
///
/// `argon2`'s own `hash_password_into` frees its 64 MiB block array without wiping it,
/// and with p = 1 the last block is the input to the final hash, so the seed could be
/// recomputed from freed or swapped memory. Derivations in this crate always run in an
/// arena that is allocated once (fallibly, at its final size) and wiped after every
/// derivation, whether it succeeded or not, and again on drop.
///
/// Keeping the arena out of swap is the process's job: the sealer (C-07) and the
/// Source App must `mlockall(MCL_CURRENT | MCL_FUTURE)` or run with
/// `LimitMEMLOCK` ≥ 64 MiB plus headroom and swap disabled (04 §11.5, 17 INFRA-013);
/// this crate is `forbid(unsafe_code)` and does not lock memory itself. A long-lived
/// process can keep one arena and pass it to [`SourceKeys::derive_in`], so the locked
/// region is reused instead of re-allocated.
pub struct Argon2Arena {
    blocks: Zeroizing<Vec<argon2::Block>>,
}

impl core::fmt::Debug for Argon2Arena {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Argon2Arena({} KiB)", self.blocks.len())
    }
}

impl Argon2Arena {
    /// Allocate an arena for the spec parameters (m = 65,536 KiB). Allocation failure
    /// returns [`Error::PasswordHash`] (fail closed).
    pub fn new() -> Result<Self> {
        Self::with_kib(ARGON2_M_KIB)
    }

    pub(crate) fn with_kib(m_kib: u32) -> Result<Self> {
        let n = usize::try_from(m_kib).map_err(|_| Error::PasswordHash)?;
        let mut v: Vec<argon2::Block> = Vec::new();
        v.try_reserve_exact(n).map_err(|_| Error::PasswordHash)?;
        v.resize(n, argon2::Block::new());
        Ok(Self {
            blocks: Zeroizing::new(v),
        })
    }

    /// Overwrite every block with zeros (the allocation is kept).
    fn wipe(&mut self) {
        for b in self.blocks.iter_mut() {
            b.zeroize();
        }
    }

    #[cfg(test)]
    pub(crate) fn is_zeroed(&self) -> bool {
        self.blocks
            .iter()
            .all(|b| b.as_ref().iter().all(|w| *w == 0))
    }
}

fn argon2id(
    arena: &mut Argon2Arena,
    password: &[u8],
    salt: &[u8; 32],
    m_kib: u32,
    t: u32,
    p: u32,
) -> Result<Secret32> {
    let params = argon2::Params::new(m_kib, t, p, Some(32)).map_err(|_| Error::PasswordHash)?;
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    let r =
        a.hash_password_into_with_memory(password, salt, out.as_mut(), arena.blocks.as_mut_slice());
    arena.wipe();
    r.map_err(|_| Error::PasswordHash)?;
    Ok(Secret32::from_bytes(*out))
}

/// All keys derived from a source passphrase (§11.3). Zeroized on drop.
pub struct SourceKeys {
    lookup_id: Secret32,
    auth: SigningKey,
    sign: SigningKey,
    kem: KemKeyPair,
    prk: Secret32,
    k_prefs: AeadKey,
}

impl core::fmt::Debug for SourceKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SourceKeys(<redacted>)")
    }
}

impl SourceKeys {
    /// Derive from a passphrase (normalized internally) for a tenant (§11.3):
    /// Argon2id(m = 65536 KiB, t = 3, p = 1, 32 B, v0x13) → seed → HKDF tree.
    ///
    /// Allocates a fresh [`Argon2Arena`] (wiped and freed afterwards); long-lived
    /// processes should use [`SourceKeys::derive_in`] with a reused, locked arena.
    /// Passphrases longer than [`MAX_PASSPHRASE_INPUT_LEN`] bytes fail with
    /// [`Error::Length`].
    pub fn derive(
        suite: Suite,
        passphrase: &str,
        deployment_salt: &[u8; 32],
        tenant_id: &[u8; 16],
    ) -> Result<Self> {
        suite.require_supported()?;
        let mut arena = Argon2Arena::new()?;
        Self::derive_in(&mut arena, suite, passphrase, deployment_salt, tenant_id)
    }

    /// [`SourceKeys::derive`] using caller-provided Argon2id memory, which is wiped
    /// before this returns (AUD-RM1-CORE-02).
    pub fn derive_in(
        arena: &mut Argon2Arena,
        suite: Suite,
        passphrase: &str,
        deployment_salt: &[u8; 32],
        tenant_id: &[u8; 16],
    ) -> Result<Self> {
        Self::derive_with_params(
            arena,
            suite,
            passphrase,
            deployment_salt,
            tenant_id,
            ARGON2_M_KIB,
            ARGON2_T,
            ARGON2_P,
        )
    }

    /// Derivation with explicit Argon2id parameters — crate-internal so the spec
    /// parameters can never be lowered by a caller (CRYPTO-043).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn derive_with_params(
        arena: &mut Argon2Arena,
        suite: Suite,
        passphrase: &str,
        deployment_salt: &[u8; 32],
        tenant_id: &[u8; 16],
        m_kib: u32,
        t: u32,
        p: u32,
    ) -> Result<Self> {
        suite.require_supported()?;
        let norm = normalize(passphrase)?;
        let salt = source_salt(deployment_salt, tenant_id);
        let seed = argon2id(arena, norm.as_bytes(), &salt, m_kib, t, p)?;
        drop(norm);
        Self::from_seed(suite, &seed)
    }

    fn from_seed(suite: Suite, seed: &Secret32) -> Result<Self> {
        let prk = hkdf_extract(labels::SOURCE_SALT_LABEL, seed.expose());
        let mut buf = Zeroizing::new([0u8; 32]);
        hkdf_expand(&prk, &[labels::SOURCE_LOOKUP_ID], buf.as_mut())?;
        // `*buf` copies are moved straight into zeroize-on-drop containers.
        let lookup_id = Secret32::from_bytes(*buf);
        hkdf_expand(&prk, &[labels::SOURCE_AUTH_ED25519], buf.as_mut())?;
        let auth = SigningKey::from_seed(&buf);
        hkdf_expand(&prk, &[labels::SOURCE_SIGN_ED25519], buf.as_mut())?;
        let sign = SigningKey::from_seed(&buf);
        hkdf_expand(
            &prk,
            &[labels::SOURCE_KEM_SEED, &suite.to_be_bytes()],
            buf.as_mut(),
        )?;
        let kem = KemKeyPair::derive(suite, buf.as_ref())?;
        hkdf_expand(&prk, &[labels::SOURCE_PREFS], buf.as_mut())?;
        let k_prefs = AeadKey::from_bytes(*buf);
        Ok(Self {
            lookup_id,
            auth,
            sign,
            kem,
            prk,
            k_prefs,
        })
    }

    /// `lookup_id` (secret; never stored server-side).
    #[must_use]
    pub fn lookup_id(&self) -> &Secret32 {
        &self.lookup_id
    }

    /// `lookup_tag = SHA-256("candor/v1/lookup-tag" ‖ lookup_id)` (§11.4).
    #[must_use]
    pub fn lookup_tag(&self) -> [u8; 32] {
        lookup_tag(self.lookup_id.expose())
    }

    /// Ed25519 auth key.
    #[must_use]
    pub fn auth_key(&self) -> &SigningKey {
        &self.auth
    }

    /// Ed25519 signing key.
    #[must_use]
    pub fn sign_key(&self) -> &SigningKey {
        &self.sign
    }

    /// X-Wing public key `src_pk`.
    #[must_use]
    pub fn kem_public_key(&self) -> &KemPublicKey {
        &self.kem.public
    }

    /// X-Wing private key `src_sk`.
    #[must_use]
    pub fn kem_private_key(&self) -> &KemPrivateKey {
        &self.kem.private
    }

    /// `mailbox_id[i] = HKDF-Expand(PRK, "candor/v1/source/mailbox/" ‖ u32be(i), 32)`.
    pub fn mailbox_id(&self, report_index: u32) -> Result<[u8; 32]> {
        let mut out = [0u8; 32];
        hkdf_expand(
            &self.prk,
            &[labels::SOURCE_MAILBOX, &report_index.to_be_bytes()],
            &mut out,
        )?;
        Ok(out)
    }

    /// `K_prefs` (AEAD key for `prefs_ct`).
    #[must_use]
    pub fn k_prefs(&self) -> &AeadKey {
        &self.k_prefs
    }

    /// Source authentication signature (§11.5):
    /// `Ed25519.Sign(auth_sk, "candor/v1/source-auth" ‖ challenge ‖ tenant_id ‖ audience)`.
    #[must_use]
    pub fn sign_auth_challenge(
        &self,
        challenge: &[u8; 32],
        tenant_id: &[u8; 16],
        audience: &[u8],
    ) -> [u8; 64] {
        sign_with_context(
            &self.auth,
            labels::SIG_SOURCE_AUTH,
            &[challenge, tenant_id, audience],
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::*;
    use crate::rand::TestRng;

    #[test]
    fn eff_list_loads_and_hash_matches() {
        let l = Wordlist::eff_large().unwrap();
        assert_eq!(l.len(), 7772);
        for w in EFF_LARGE_EXCLUDED {
            assert!(!l.check(w));
            assert!(EFF_LARGE_TXT.contains(&format!("\t{w}\n")));
        }
        assert_eq!(l.word_count(), 10);
        assert_eq!(l.get(0), Some("abacus"));
        assert_eq!(l.get(7771), Some("zoom"));
        assert_eq!(
            hex_lower(&sha256(&[EFF_LARGE_TXT.as_bytes()])),
            EFF_LARGE_WORDLIST_SHA256
        );
    }

    #[test]
    fn word_counts_per_spec_examples() {
        // §11.1: N = 7,776 → 10; N = 2,048 → 12; N = 4,096 → 11.
        assert_eq!(words_for_128_bits(7776).unwrap(), 10);
        assert_eq!(words_for_128_bits(2048).unwrap(), 12);
        assert_eq!(words_for_128_bits(4096).unwrap(), 11);
        assert_eq!(words_for_128_bits(65536).unwrap(), 8);
        assert_eq!(words_for_128_bits(65537).unwrap(), 8);
    }

    #[test]
    fn wordlist_validation() {
        let mut w: Vec<String> = (0..2048).map(|i| format!("w{i}")).collect();
        assert!(Wordlist::from_words(&w).is_ok());
        assert_eq!(
            Wordlist::from_words(&w[..2047]).err(),
            Some(Error::InvalidWordlist)
        );
        w[5] = "W1".into(); // duplicate of "w1" after normalization
        assert!(Wordlist::from_words(&w).is_err());
        w[5] = "a-b".into(); // separator after normalization
        assert!(Wordlist::from_words(&w).is_err());
        w[5] = " ".into();
        assert!(Wordlist::from_words(&w).is_err());
    }

    #[test]
    fn generation_uniform_shape() {
        let l = Wordlist::eff_large().unwrap();
        let mut rng = TestRng::new(40);
        let p = generate_with(&mut rng, l).unwrap();
        assert_eq!(p.expose().split(' ').count(), 10);
        assert!(l.check(p.expose()));
        assert_eq!(normalize(p.expose()).unwrap().as_str(), p.expose());
        assert_eq!(format!("{p:?}"), "Passphrase(<redacted>)");
        let os = generate(l).unwrap();
        assert!(l.check(os.expose()));
    }

    #[test]
    fn normalization_rules() {
        assert_eq!(
            normalize("  Abacus\t\u{2014}ZOOM,, ,kiwi- ")
                .unwrap()
                .as_str(),
            "abacus zoom kiwi"
        );
        // NFKC: fullwidth letters and ligatures fold.
        assert_eq!(
            normalize("\u{FF21}bacus \u{FB01}ve").unwrap().as_str(),
            "abacus five"
        );
        // Unicode lowercase is locale-independent (Turkish dotted I → "i̇").
        assert_eq!(normalize("\u{0130}").unwrap().as_str(), "i\u{0307}");
        assert_eq!(
            normalize("a\u{00A0}b\u{2003}c\u{2010}d\u{2015}e")
                .unwrap()
                .as_str(),
            "a b c d e"
        );
        assert_eq!(normalize("").unwrap().as_str(), "");
        assert_eq!(normalize(" - , ").unwrap().as_str(), "");
    }

    proptest::proptest! {
        /// ST-053: normalization is idempotent and never panics.
        #[test]
        fn normalize_idempotent(s in "\\PC{0,40}") {
            let a = normalize(&s).unwrap();
            let b = normalize(&a).unwrap();
            proptest::prop_assert_eq!(a.as_str(), b.as_str());
            proptest::prop_assert!(!a.starts_with(' ') && !a.ends_with(' ') && !a.contains("  "));
        }
    }

    #[test]
    fn derivation_tree_small_params() {
        // Small Argon2 parameters keep unit tests fast; the full parameters are
        // exercised by `derivation_full_params` and the published vectors.
        let k = SourceKeys::derive_with_params(
            &mut Argon2Arena::with_kib(64).unwrap(),
            Suite::CandorStd1,
            "Abacus  ZOOM",
            &[1; 32],
            &[2; 16],
            64,
            1,
            1,
        )
        .unwrap();
        let k2 = SourceKeys::derive_with_params(
            &mut Argon2Arena::with_kib(64).unwrap(),
            Suite::CandorStd1,
            "abacus zoom",
            &[1; 32],
            &[2; 16],
            64,
            1,
            1,
        )
        .unwrap();
        assert_eq!(
            k.lookup_tag(),
            k2.lookup_tag(),
            "normalization applied before derivation"
        );
        assert_eq!(k.kem_public_key(), k2.kem_public_key());
        assert_ne!(k.mailbox_id(0).unwrap(), k.mailbox_id(1).unwrap());
        // Tenant-bound salt: a passphrase is not portable across tenants.
        let k3 = SourceKeys::derive_with_params(
            &mut Argon2Arena::with_kib(64).unwrap(),
            Suite::CandorStd1,
            "abacus zoom",
            &[1; 32],
            &[3; 16],
            64,
            1,
            1,
        )
        .unwrap();
        assert_ne!(k.lookup_tag(), k3.lookup_tag());
        assert_ne!(
            k.auth_key().verifying_key_bytes(),
            k.sign_key().verifying_key_bytes()
        );
        let sig = k.sign_auth_challenge(&[7; 32], &[2; 16], b"source-app");
        let mut msg = labels::SIG_SOURCE_AUTH.to_vec();
        msg.extend_from_slice(&[7; 32]);
        msg.extend_from_slice(&[2; 16]);
        msg.extend_from_slice(b"source-app");
        assert!(crate::sig::verify_strict(&k.auth_key().verifying_key_bytes(), &msg, &sig).is_ok());
        assert_eq!(
            SourceKeys::derive_with_params(
                &mut Argon2Arena::with_kib(64).unwrap(),
                Suite::CandorFips1,
                "x",
                &[1; 32],
                &[2; 16],
                64,
                1,
                1
            )
            .err(),
            Some(Error::UnsupportedSuite)
        );
        assert_eq!(format!("{k:?}"), "SourceKeys(<redacted>)");
    }

    /// Reference implementation of §11.3 (the pre-AUD-RM1-CORE-03 code): used only to
    /// prove that the fixed-buffer implementation is byte-identical.
    fn normalize_reference(p: &str) -> String {
        let nfkc: String = p.nfkc().collect();
        let lower = nfkc.to_lowercase();
        let mut out = String::new();
        let mut pending_sep = false;
        for c in lower.chars() {
            if is_separator(c) {
                pending_sep = true;
            } else {
                if pending_sep && !out.is_empty() {
                    out.push(' ');
                }
                pending_sep = false;
                out.push(c);
            }
        }
        out
    }

    /// AUD-RM1-CORE-03: lowercasing never reallocates, including inputs whose
    /// lowercase form is longer (U+0130, U+023A, U+023E) and Final_Sigma contexts;
    /// the result equals `str::to_lowercase`.
    #[test]
    fn lowercase_fixed_never_reallocates() {
        let cases = [
            "abacus zoom",
            "\u{0130}",
            "\u{0130}\u{0130}\u{0130}ABC\u{023A}\u{023E}",
            "\u{023A}\u{023A}\u{023A}\u{023A}\u{023A}x\u{212A}\u{212A}",
            "\u{212A}\u{212A}\u{0130}\u{0130}\u{0130}\u{0130}",
            "ΟΔΟΣ",
            "ΟΔΟΣ ΟΔΟΣ'",
            "Σ",
            "AΣ\u{0130}",
            "ΑΣ\u{0301}",
        ];
        for c in cases {
            let l = lowercase_fixed(c).unwrap();
            assert_eq!(l.as_str(), c.to_lowercase(), "{c:?}");
            // `str::to_lowercase` allocates exactly `input.len()`; any reallocation
            // would have grown the capacity beyond what we passed in.
            let mut max_growth = 0usize;
            let (mut i, mut o) = (0usize, 0usize);
            for ch in c.chars() {
                i += ch.len_utf8();
                o += ch.to_lowercase().map(char::len_utf8).sum::<usize>();
                max_growth = max_growth.max(o.saturating_sub(i));
            }
            let expected_cap = if max_growth == 0 {
                c.len()
            } else {
                c.len() + 1 + 3 * max_growth.div_ceil(2)
            };
            assert_eq!(l.capacity(), expected_cap, "{c:?} reallocated");
        }
    }

    /// AUD-RM1-CORE-03: generation never grows its buffer (capacity reserved up front).
    #[test]
    fn generate_never_reallocates() {
        let l = Wordlist::eff_large().unwrap();
        let mut rng = TestRng::new(41);
        for _ in 0..20 {
            let p = generate_with(&mut rng, l).unwrap();
            assert_eq!(p.0.capacity(), (l.max_word_len + 1) * l.word_count());
        }
    }

    /// AUD-RM1-CORE-03: over-long input is refused before allocation; the limit is
    /// inclusive.
    #[test]
    fn normalize_rejects_overlong() {
        let ok = "a".repeat(MAX_PASSPHRASE_INPUT_LEN);
        assert_eq!(normalize(&ok).unwrap().len(), MAX_PASSPHRASE_INPUT_LEN);
        let long = "a".repeat(MAX_PASSPHRASE_INPUT_LEN + 1);
        assert_eq!(normalize(&long).err(), Some(Error::Length));
        assert_eq!(
            SourceKeys::derive_with_params(
                &mut Argon2Arena::with_kib(64).unwrap(),
                Suite::CandorStd1,
                &long,
                &[1; 32],
                &[2; 16],
                64,
                1,
                1
            )
            .err(),
            Some(Error::Length)
        );
        assert!(!Wordlist::eff_large().unwrap().check(&long));
        // Worst-case NFKC expansion (U+FDFA → 18 code points) fits the fixed buffer.
        let fdfa = "\u{FDFA}".repeat(MAX_PASSPHRASE_INPUT_LEN / 3);
        assert_eq!(
            normalize(&fdfa).unwrap().as_str(),
            normalize_reference(&fdfa)
        );
    }

    proptest::proptest! {
        /// AUD-RM1-CORE-03: the fixed-buffer `normalize` is byte-identical to the
        /// reference §11.3 implementation (including Greek sigma and expanding
        /// lowercase mappings).
        #[test]
        fn normalize_matches_reference(s in "[\\PC\u{0130}\u{023A}\u{023E}ΣΑΒ'\u{0301} -]{0,40}") {
            let got = normalize(&s).unwrap();
            proptest::prop_assert_eq!(got.as_str(), normalize_reference(&s));
        }
    }

    /// AUD-RM1-CORE-02: the arena is wiped after each derivation (success and error).
    #[test]
    fn argon2_arena_is_wiped() {
        let mut arena = Argon2Arena::with_kib(64).unwrap();
        assert!(arena.is_zeroed());
        let k = SourceKeys::derive_with_params(
            &mut arena,
            Suite::CandorStd1,
            "abacus zoom",
            &[1; 32],
            &[2; 16],
            64,
            1,
            1,
        )
        .unwrap();
        assert!(arena.is_zeroed());
        // The arena is really used: the same derivation in a fresh arena agrees.
        let k2 = SourceKeys::derive_with_params(
            &mut Argon2Arena::with_kib(64).unwrap(),
            Suite::CandorStd1,
            "abacus zoom",
            &[1; 32],
            &[2; 16],
            64,
            1,
            1,
        )
        .unwrap();
        assert_eq!(k.lookup_tag(), k2.lookup_tag());
        // Too-small arena: fails closed, still wiped.
        let mut small = Argon2Arena::with_kib(8).unwrap();
        assert_eq!(
            SourceKeys::derive_with_params(
                &mut small,
                Suite::CandorStd1,
                "abacus zoom",
                &[1; 32],
                &[2; 16],
                64,
                1,
                1
            )
            .err(),
            Some(Error::PasswordHash)
        );
        assert!(small.is_zeroed());
        assert_eq!(format!("{arena:?}"), "Argon2Arena(64 KiB)");
    }

    /// AUD-RM1-CORE-08: membership check is functionally unchanged.
    #[test]
    fn check_constant_time_semantics() {
        let l = Wordlist::eff_large().unwrap();
        let good = "abacus zoom abacus zoom abacus zoom abacus zoom abacus zoom";
        assert!(l.check(good));
        assert!(l.check("Abacus-ZOOM abacus zoom abacus zoom abacus zoom abacus  zoom"));
        assert!(!l.check("abacus zoom abacus zoom abacus zoom abacus zoom abacus"));
        assert!(!l.check(&format!("{good} zoom")));
        assert!(!l.check("abacus zoom abacus zoom abacus zoom abacus zoom abacus zoomx"));
        assert!(!l.check(&format!(
            "{} zoom abacus zoom abacus zoom abacus zoom abacus zoom",
            "a".repeat(40)
        )));
        assert!(!l.check(""));
    }

    /// AUD-RM1-CORE-12: a stuck RNG fails closed instead of hanging or producing a
    /// degenerate passphrase.
    #[test]
    fn stuck_rng_fails_closed() {
        struct Stuck(u8);
        impl RandomSource for Stuck {
            fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
                buf.fill(self.0);
                Ok(())
            }
        }
        let l = Wordlist::eff_large().unwrap();
        assert_eq!(generate_with(&mut Stuck(0xFF), l).err(), Some(Error::Rng));
        assert_eq!(generate_with(&mut Stuck(0x00), l).err(), Some(Error::Rng));
    }

    #[test]
    fn derivation_full_params() {
        // ADR-046(7) parameters (m = 64 MiB, t = 3, p = 1).
        let a = SourceKeys::derive(Suite::CandorStd1, "abacus zoom", &[1; 32], &[2; 16]).unwrap();
        let b = SourceKeys::derive_with_params(
            &mut Argon2Arena::with_kib(64).unwrap(),
            Suite::CandorStd1,
            "abacus zoom",
            &[1; 32],
            &[2; 16],
            64,
            1,
            1,
        )
        .unwrap();
        assert_ne!(a.lookup_tag(), b.lookup_tag());
    }

    /// ST-022: Argon2id RFC 9106 §5.3 test vector (via the `argon2` crate with secret and AD).
    #[test]
    fn argon2id_rfc9106() {
        let params = argon2::ParamsBuilder::new()
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .data(argon2::AssociatedData::new(&[4u8; 12]).unwrap())
            .output_len(32)
            .build()
            .unwrap();
        let a = argon2::Argon2::new_with_secret(
            &[3u8; 8],
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params,
        )
        .unwrap();
        let mut out = [0u8; 32];
        a.hash_password_into(&[1u8; 32], &[2u8; 16], &mut out)
            .unwrap();
        assert_eq!(
            hex::encode(out),
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        );
    }
}
