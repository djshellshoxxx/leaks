// SPDX-License-Identifier: AGPL-3.0-or-later
//! Candor Intake Store (C-08): the [`IntakeStore`] trait owned by this crate,
//! a PostgreSQL implementation ([`PgIntakeStore`]) and an in-memory
//! implementation ([`MemoryStore`]) for tests of other crates.
//!
//! Specs: 09-DATABASE.md §5.1/§8/§10/§11; 07-BACKEND.md §5.3/§5.4/§6.3;
//! 08-API.md RL-01..RL-12, SA-19/SA-20; ADR-009/010/033/034/038/039/046/047.
//!
//! The store never reads a wall clock, never stores a time finer than a day,
//! never stores network identifiers, and returns content-free errors.

pub mod deaddrop;
pub mod deletion;
pub mod error;
pub mod lint;
pub mod memory;
pub mod pg;
mod rng;
pub mod staged;
pub mod store;
pub mod types;
mod validate;

pub use deaddrop::{
    DEFAULT_DUMMY_BUCKET_WEIGHTS, DeadDropConfig, DummyReplies, MIN_DUMMY_BUCKET_WEIGHT,
    RandomDummyReplies,
};
pub use deletion::{
    CoreReplyHasher, DeletionEntry, DeletionKind, DeletionSigner, Ed25519DeletionSigner,
    MAX_HEAD_AGE_DAYS, ReplyObjectHasher, SignedDeletionHead,
};
pub use error::{Result, StoreError};
pub use memory::{MEMORY_DEADDROP_CONFIG, MemoryStore};
pub use pg::{
    PgIntakeMaintenance, PgIntakeStore, migrate, schema_hash, vacuum_after_rewrite,
    vacuum_full_daily,
};
pub use store::{IntakeMaintenance, IntakeStore};
pub use types::*;
