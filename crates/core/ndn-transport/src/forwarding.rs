//! Forwarding action types returned by strategies.

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
    /// Flood to all eligible faces — the self-learning *discovery* Interest
    /// when no route is known. The engine expands this to the face set (the
    /// strategy has no face table); scope/split-horizon checks still apply.
    Broadcast,
}
