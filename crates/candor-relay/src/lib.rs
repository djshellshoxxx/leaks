// SPDX-License-Identifier: AGPL-3.0-or-later
#![forbid(unsafe_code)]
//! Core-side relay (C-09) policy and state machines: request authentication, the monotonic
//! request counter, hostile-metadata validation, backpressure, the fixed import schedule and
//! the one-way transport policy (07 §5.4). No sockets, no TLS, no filesystem here: the transport
//! adapter owns those and calls into this crate.

mod auth;
mod counter;

pub use auth::{
    MAX_METHOD_LEN, MAX_PATH_LEN, REQUEST_SIGNING_LABEL, RelayAuthError, RelayAuthenticator,
    request_signing_message,
};
use counter::{CounterError, check_counter};

/// Maximum pending imports before relay pull must stop.
pub const DEFAULT_MAX_PENDING_IMPORTS: u64 = 50_000;
/// Minimum free capacity percentage required before claiming another batch.
pub const MIN_FREE_PERCENT: u8 = 10;
/// Exact number of header key slots required by the import format.
pub const HEADER_SLOT_COUNT: u8 = 16;
/// Maximum encrypted header size accepted by the core relay.
pub const MAX_HEADER_CT_LEN: u64 = 8 * 1024;
/// Maximum encrypted manifest size accepted by the core relay.
pub const MAX_MANIFEST_CT_LEN: u64 = 64 * 1024;
/// Maximum number of padded attachment parts in one import envelope.
pub const MAX_PARTS: usize = 32;

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

/// The 07 §5.4 backpressure rule: stop claiming when C-13 free space is below 10 % or more than
/// `max_pending` imports are pending.
const fn over_threshold(pending_imports: u64, max_pending: u64, free_percent: u8) -> bool {
    pending_imports > max_pending || free_percent < MIN_FREE_PERCENT
}

/// Enforces the non-cryptographic invariants around the authenticated relay protocol.
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
        check_counter(self.last_counter, counter).map_err(|error| match error {
            CounterError::Exhausted => RelayError::CounterExhausted,
            CounterError::Replay => RelayError::Replay,
        })?;
        self.last_counter = counter;
        Ok(())
    }

    /// Apply the RM-3 import backpressure thresholds before a claim is made.
    pub const fn may_claim(
        &self,
        pending_imports: u64,
        free_percent: u8,
    ) -> Result<(), RelayError> {
        if over_threshold(pending_imports, self.max_pending_imports, free_percent) {
            return Err(RelayError::Backpressure);
        }
        Ok(())
    }

    /// The relay link may only target the single configured intake export endpoint.
    pub fn allow_outbound(&self, destination: IntakeEndpoint) -> Result<(), RelayError> {
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

/// A snapshot of the two backpressure inputs at the start of a slot (07 §5.4): C-13 free space
/// and the `import_envelope` pending count, judged against the default thresholds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Backpressure {
    free_percent: u8,
    pending_imports: u64,
}

impl Backpressure {
    #[must_use]
    pub const fn new(free_percent: u8, pending_imports: u64) -> Self {
        Self {
            free_percent,
            pending_imports,
        }
    }

    /// `true` when the relay must stop claiming and raise `SYSTEM:relay_backpressure`.
    #[must_use]
    pub const fn must_stop(self) -> bool {
        over_threshold(
            self.pending_imports,
            DEFAULT_MAX_PENDING_IMPORTS,
            self.free_percent,
        )
    }
}

/// Metadata copied from the intake export index and treated as hostile until validated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportObject {
    pub channel_id: u8,
    pub epoch_index: u64,
    pub header_slot_count: u8,
    pub header_ct_len: u64,
    pub manifest_ct_len: u64,
    pub part_padded_sizes: Vec<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidationError {
    Channel,
    Epoch,
    HeaderSlots,
    HeaderSize,
    ManifestSize,
    PartCount,
    PartBucket,
}

/// Fail-closed validation for intake-controlled import metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportValidator {
    channels: Vec<u8>,
    current_epoch: u64,
    part_buckets: Vec<u64>,
}

impl ImportValidator {
    #[must_use]
    pub fn new<const C: usize, const B: usize>(
        channels: [u8; C],
        current_epoch: u64,
        part_buckets: [u64; B],
    ) -> Self {
        Self {
            channels: channels.to_vec(),
            current_epoch,
            part_buckets: part_buckets.to_vec(),
        }
    }

    pub fn validate(&self, object: &ImportObject) -> Result<(), ValidationError> {
        if !self.channels.contains(&object.channel_id) {
            return Err(ValidationError::Channel);
        }
        let oldest_epoch = self.current_epoch.saturating_sub(3);
        if object.epoch_index < oldest_epoch || object.epoch_index > self.current_epoch {
            return Err(ValidationError::Epoch);
        }
        if object.header_slot_count != HEADER_SLOT_COUNT {
            return Err(ValidationError::HeaderSlots);
        }
        if object.header_ct_len > MAX_HEADER_CT_LEN {
            return Err(ValidationError::HeaderSize);
        }
        if object.manifest_ct_len > MAX_MANIFEST_CT_LEN {
            return Err(ValidationError::ManifestSize);
        }
        if object.part_padded_sizes.len() > MAX_PARTS {
            return Err(ValidationError::PartCount);
        }
        if object
            .part_padded_sizes
            .iter()
            .any(|size| !self.part_buckets.contains(size))
        {
            return Err(ValidationError::PartBucket);
        }
        Ok(())
    }
}

/// Fixed-time relay schedule. Import slots never double as control-cycle claim times.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelaySchedule {
    import_minutes_utc: [u16; 4],
    control_minute: u16,
}

impl RelaySchedule {
    #[must_use]
    pub const fn new(import_minutes_utc: [u16; 4], control_minute: u16) -> Self {
        Self {
            import_minutes_utc,
            control_minute,
        }
    }

    #[must_use]
    pub fn is_import_slot(&self, minute_of_day: u16) -> bool {
        self.import_minutes_utc.contains(&minute_of_day)
    }

    #[must_use]
    pub fn is_control_cycle(&self, minute_of_day: u16) -> bool {
        minute_of_day < 1_440
            && minute_of_day % 60 == self.control_minute
            && !self.is_import_slot(minute_of_day)
    }
}
