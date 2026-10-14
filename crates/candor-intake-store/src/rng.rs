// SPDX-License-Identifier: AGPL-3.0-or-later
//! OS CSPRNG access (getrandom, the same pinned version candor-core uses; its
//! `rand` module is crate-private). Mirrors candor-core's health check: a request
//! of ≥ 16 bytes that returns all zeros is a failure (04 §23.4). Fail closed.

use crate::error::{Result, StoreError};

/// Fill `buf` from the OS CSPRNG.
pub(crate) fn fill(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| StoreError::Rng)?;
    if buf.len() >= 16 && buf.iter().all(|b| *b == 0) {
        return Err(StoreError::Rng);
    }
    Ok(())
}
