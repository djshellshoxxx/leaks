// SPDX-License-Identifier: AGPL-3.0-or-later
#![forbid(unsafe_code)]

/// Maximum pending imports before relay pull must stop.
pub const DEFAULT_MAX_PENDING_IMPORTS: u64 = 50_000;

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

#[derive(Debug)]
pub struct RelayGuard {
    last_counter: u64,
    max_pending_imports: u64,
    intake: IntakeEndpoint,
}

impl RelayGuard {
    #[must_use]
    pub const fn new(intake: IntakeEndpoint, max_pending_imports: u64) -> Self {
        Self { last_counter: 0, max_pending_imports, intake }
    }

    pub fn accept_counter(&mut self, _counter: u64) -> Result<(), RelayError> {
        Ok(())
    }

    pub const fn may_claim(&self, _pending_imports: u64, _free_percent: u8) -> Result<(), RelayError> {
        Ok(())
    }

    pub const fn allow_outbound(&self, _destination: IntakeEndpoint) -> Result<(), RelayError> {
        Ok(())
    }

    pub const fn allow_inbound(&self) -> Result<(), RelayError> {
        Ok(())
    }

    #[must_use]
    pub const fn last_counter(&self) -> u64 {
        self.last_counter
    }
}
