// SPDX-License-Identifier: AGPL-3.0-or-later
#![forbid(unsafe_code)]

/// Maximum pending imports before relay pull must stop.
pub const DEFAULT_MAX_PENDING_IMPORTS: u64 = 50_000;
/// Minimum free capacity percentage required before claiming another batch.
pub const MIN_FREE_PERCENT: u8 = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IntakeEndpoint {
    pub address: [u8; 16],
    pub port: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayError {
    Replay,
    CounterExhausted,
    Backpressure,
    DestinationDenied,
    InboundDenied,
}

/// Enforces the non-cryptographic invariants around the authenticated relay protocol.
///
/// Signature and TLS verification live at the transport adapter. This guard is deliberately
/// small so the replay, backpressure and one-way network rules can be tested independently of
/// a socket implementation.
#[derive(Debug)]
pub struct RelayGuard {
    last_counter: u64,
    max_pending_imports: u64,
    intake: IntakeEndpoint,
}

impl RelayGuard {
    #[must_use]
    pub const fn new(intake: IntakeEndpoint, max_pending_imports: u64) -> Self {
        Self {
            last_counter: 0,
            max_pending_imports,
            intake,
        }
    }

    /// Accept a strictly increasing, non-zero request counter.
    ///
    /// Once `u64::MAX` has been accepted the counter cannot advance and the session must be
    /// replaced rather than wrapping.
    pub fn accept_counter(&mut self, counter: u64) -> Result<(), RelayError> {
        if self.last_counter == u64::MAX {
            return Err(RelayError::CounterExhausted);
        }
        if counter == 0 || counter <= self.last_counter {
            return Err(RelayError::Replay);
        }
        self.last_counter = counter;
        Ok(())
    }

    /// Apply the RM-3 import backpressure thresholds before a claim is made.
    pub const fn may_claim(
        &self,
        pending_imports: u64,
        free_percent: u8,
    ) -> Result<(), RelayError> {
        if pending_imports >= self.max_pending_imports || free_percent < MIN_FREE_PERCENT {
            return Err(RelayError::Backpressure);
        }
        Ok(())
    }

    /// The relay link may only target the single configured intake export endpoint.
    pub const fn allow_outbound(&self, destination: IntakeEndpoint) -> Result<(), RelayError> {
        if destination.port != self.intake.port || destination.address != self.intake.address {
            return Err(RelayError::DestinationDenied);
        }
        Ok(())
    }

    /// Intake-to-core application connections are prohibited; the core relay always initiates.
    pub const fn allow_inbound(&self) -> Result<(), RelayError> {
        Err(RelayError::InboundDenied)
    }

    #[must_use]
    pub const fn last_counter(&self) -> u64 {
        self.last_counter
    }
}
