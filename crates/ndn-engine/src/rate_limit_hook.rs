//! Pluggable rate-limit hook for the forwarding pipeline. This crate
//! defines the trait and decision shape; the policy table and bucket
//! logic live in `ndn-ratelimit`, installed via
//! [`crate::EngineBuilder::with_rate_limit_hook`].
//!
//! The pipeline invokes the hook inbound (after `TlvDecodeStage`, before
//! `CsLookupStage` / `PitMatchStage`) and outbound (before face dispatch).

use std::sync::Arc;

use ndn_packet::Name;
use ndn_transport::FaceId;

/// The hook uses kind to charge the right sub-bucket (PPS for Interest, BPS
/// for Data); `Decision::Nack` is only honoured for inbound Interests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketKind {
    Interest,
    Data,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Permit,
    Drop,
    /// NACK with reason=Congestion; only honoured on inbound Interests
    /// (falls back to silent drop elsewhere).
    Nack,
}

pub trait RateLimitHook: Send + Sync {
    fn check_inbound(
        &self,
        face: FaceId,
        name: &Name,
        kind: PacketKind,
        wire_bytes: usize,
    ) -> Decision;

    fn check_outbound(
        &self,
        face: FaceId,
        name: &Name,
        kind: PacketKind,
        wire_bytes: usize,
    ) -> Decision;
}

pub type SharedRateLimitHook = Arc<dyn RateLimitHook>;
