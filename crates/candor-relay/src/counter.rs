// SPDX-License-Identifier: AGPL-3.0-or-later
//! The one monotonic request-counter rule (07 §5.4): shared by the transport guard and the
//! request authenticator so there is a single implementation to review.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CounterError {
    /// The last accepted counter is `u64::MAX`; the session or identity must be replaced.
    Exhausted,
    /// Zero, or not strictly greater than the last accepted counter.
    Replay,
}

/// Pure check; the caller commits `counter` as the new high-water mark only after every other
/// check on the request has passed.
pub(crate) const fn check_counter(last: u64, counter: u64) -> Result<(), CounterError> {
    if last == u64::MAX {
        return Err(CounterError::Exhausted);
    }
    if counter == 0 || counter <= last {
        return Err(CounterError::Replay);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strictly_increasing_and_non_zero() {
        assert_eq!(check_counter(0, 0), Err(CounterError::Replay));
        assert_eq!(check_counter(0, 1), Ok(()));
        assert_eq!(check_counter(5, 5), Err(CounterError::Replay));
        assert_eq!(check_counter(5, 4), Err(CounterError::Replay));
        assert_eq!(check_counter(5, 6), Ok(()));
        assert_eq!(check_counter(u64::MAX - 1, u64::MAX), Ok(()));
        assert_eq!(
            check_counter(u64::MAX, u64::MAX),
            Err(CounterError::Exhausted)
        );
        assert_eq!(check_counter(u64::MAX, 1), Err(CounterError::Exhausted));
    }
}
