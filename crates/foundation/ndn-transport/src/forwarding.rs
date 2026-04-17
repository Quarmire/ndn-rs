//! Forwarding action types returned by strategies.
//!
//! Lives in `ndn-transport` so that `ndn-strategy` can use these types without
//! depending on `ndn-engine`, which would create a circular dependency.

use smallvec::SmallVec;

use crate::FaceId;

/// NDNLPv2 Nack reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NackReason {
    NoRoute,
    Duplicate,
    Congestion,
    NotYet,
}

/// The forwarding decision returned by a `Strategy`.
pub enum ForwardingAction {
    Forward(SmallVec<[FaceId; 4]>),
    ForwardAfter {
        faces: SmallVec<[FaceId; 4]>,
        delay: std::time::Duration,
    },
    Nack(NackReason),
    Suppress,
}
