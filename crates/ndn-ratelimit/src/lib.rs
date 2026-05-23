//! Admission-control rate limiting: [`TokenBucket`] primitive, sparse
//! `(face × prefix × direction)` [`RateLimitPolicyTable`], TOML loader,
//! and typed [`RateLimitMgmtHandler`] for other crates to call.
//!
//! Pipeline-stage and `/localhost/nfd/rate-limit/*` mgmt dispatch are
//! not wired in yet; see [`stage::EngineRateLimitHook`] for the seam.

#![allow(missing_docs)]

pub mod bucket;
pub mod config;
pub mod mgmt;
pub mod policy;
pub mod stage;

pub use bucket::{BucketOutcome, TokenBucket};
pub use config::{RateLimitConfig, RateLimitPolicyConfig};
pub use mgmt::{RateLimitListEntry, RateLimitMgmtHandler};
pub use policy::{
    BucketSpec, Cell, CellEntry, Direction, FaceRef, Overflow, RateLimitPolicy,
    RateLimitPolicyTable, SharedPolicyTable,
};
pub use stage::EngineRateLimitHook;

#[derive(Debug, thiserror::Error)]
pub enum RateLimitError {
    /// Bucket drained; packet must be NACK'd / dropped / queued per the
    /// cell's overflow action.
    #[error("rate limit exceeded for cell")]
    Exceeded,
    #[error("policy table at capacity")]
    TableFull,
    /// Cell key malformed (e.g. queue overflow without queue_max).
    #[error("invalid cell specification: {0}")]
    InvalidCell(&'static str),
    #[error("config error: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, RateLimitError>;
