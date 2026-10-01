// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `candor-core` — the Candor shared cryptographic library (C-11).
//!
//! Implements suite CANDOR-STD-1 of `specs/04-CRYPTOGRAPHY.md` (§4.1): HPKE base mode
//! with X-Wing (KEM 0x647a) / HKDF-SHA256 / ChaCha20-Poly1305, STREAM payloads,
//! XChaCha20-Poly1305 records, HMAC-SHA-256 key commitment, Ed25519, Argon2id source
//! passphrases. CANDOR-FIPS-1 is recognised and rejected with
//! [`Error::UnsupportedSuite`].
//!
//! Module map (spec sections):
//! * [`suite`] §4 · [`labels`] §10 · [`passphrase`] §11.1–11.3
//! * [`header`] §13.1 · [`slots`] / [`stanza`] §13.2 · [`stream`] §13.3
//! * [`padding`] §13.6 · [`record`] §13.8 · [`hash`] key ids, evidence hashes
//! * [`object`] sealed-object assembly · [`selftest`] start-up KATs (CRYPTO-034)
//!
//! No `unsafe`; secrets are zeroized on drop and never printed; MAC/tag comparisons
//! are constant-time; parsers never panic on hostile input.

pub mod error;
pub mod suite;
pub mod labels;
pub mod secret;
pub mod hash;
pub mod kdf;
pub mod kem;
pub mod sig;
pub mod header;
pub mod padding;
pub mod stream;
pub mod slots;
pub mod stanza;
pub mod record;
pub mod passphrase;
pub mod object;
pub mod selftest;

mod aead;
mod bytes;
mod rand;

#[cfg(test)]
mod vectors;

pub use error::{Error, Result};
pub use suite::Suite;
/// Fill a buffer from the OS CSPRNG (the only randomness source, CRYPTO-033).
pub use rand::fill as fill_random;
