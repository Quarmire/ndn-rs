use smallvec::SmallVec;

use ndn_transport::FaceId;

/// Reason a packet was dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropReason {
    MalformedPacket,
    UnknownFace,
    LoopDetected,
    Suppressed,
    RateLimited,
    HopLimitExceeded,
    ScopeViolation,
    /// Incomplete fragment reassembly — waiting for more fragments.
    /// Not an error; suppresses noisy logging.
    FragmentCollect,
    Other,
}

/// Reason for a Nack.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NackReason {
    NoRoute,
    Duplicate,
    Congestion,
    NotYet,
}

/// The return value from a pipeline stage.
///
/// Ownership-based: `Continue` returns the context back to the runner.
/// All other variants consume the context, making it a compiler error to
/// use the context after it has been handed off.
pub enum Action {
    /// Pass context to the next stage.
    Continue(super::context::PacketContext),
    /// Forward the packet to the given faces and exit the pipeline.
    Send(super::context::PacketContext, SmallVec<[FaceId; 4]>),
    /// Satisfy pending PIT entries and exit the pipeline.
    Satisfy(super::context::PacketContext),
    /// Drop the packet silently.
    Drop(DropReason),
    /// Send a Nack back to the incoming face.
    Nack(super::context::PacketContext, NackReason),
}

#[cfg(test)]
mod tests {
    use super::*;
    use smallvec::smallvec;
    use ndn_transport::FaceId;
    use crate::context::PacketContext;
    use bytes::Bytes;

    #[test]
    fn drop_reason_variants_are_distinct() {
        let reasons = [
            DropReason::MalformedPacket,
            DropReason::UnknownFace,
            DropReason::LoopDetected,
            DropReason::Suppressed,
            DropReason::RateLimited,
            DropReason::HopLimitExceeded,
            DropReason::ScopeViolation,
            DropReason::FragmentCollect,
            DropReason::Other,
        ];
        for (i, a) in reasons.iter().enumerate() {
            for (j, b) in reasons.iter().enumerate() {
                assert_eq!(i == j, a == b);
            }
        }
    }

    #[test]
    fn nack_reason_variants_are_distinct() {
        let reasons = [
            NackReason::NoRoute,
            NackReason::Duplicate,
            NackReason::Congestion,
            NackReason::NotYet,
        ];
        for (i, a) in reasons.iter().enumerate() {
            for (j, b) in reasons.iter().enumerate() {
                assert_eq!(i == j, a == b);
            }
        }
    }

    fn ctx() -> PacketContext {
        PacketContext::new(Bytes::from_static(b"\x05\x01\x00"), FaceId(0), 0)
    }

    #[test]
    fn action_continue_wraps_context() {
        let a = Action::Continue(ctx());
        assert!(matches!(a, Action::Continue(_)));
    }

    #[test]
    fn action_drop_holds_reason() {
        let a = Action::Drop(DropReason::LoopDetected);
        assert!(matches!(a, Action::Drop(DropReason::LoopDetected)));
    }

    #[test]
    fn action_nack_holds_reason() {
        let a = Action::Nack(ctx(), NackReason::NoRoute);
        assert!(matches!(a, Action::Nack(_, NackReason::NoRoute)));
    }

    #[test]
    fn action_send_holds_faces() {
        let faces: SmallVec<[FaceId; 4]> = smallvec![FaceId(1), FaceId(2)];
        let a = Action::Send(ctx(), faces);
        if let Action::Send(_, f) = a {
            assert_eq!(f.len(), 2);
        } else {
            panic!("expected Send");
        }
    }

    #[test]
    fn forwarding_action_suppress() {
        assert!(matches!(ForwardingAction::Suppress, ForwardingAction::Suppress));
    }

    #[test]
    fn forwarding_action_forward_after() {
        let delay = std::time::Duration::from_millis(10);
        let a = ForwardingAction::ForwardAfter {
            faces: smallvec![FaceId(3)],
            delay,
        };
        if let ForwardingAction::ForwardAfter { faces, delay: d } = a {
            assert_eq!(faces.len(), 1);
            assert_eq!(d.as_millis(), 10);
        } else {
            panic!("expected ForwardAfter");
        }
    }
}

/// The forwarding decision returned by a `Strategy`.
pub enum ForwardingAction {
    /// Forward to these faces immediately.
    Forward(SmallVec<[FaceId; 4]>),
    /// Forward to these faces after `delay`.
    ForwardAfter {
        faces: SmallVec<[FaceId; 4]>,
        delay: std::time::Duration,
    },
    /// Send a Nack.
    Nack(NackReason),
    /// Suppress — do not forward (loop or policy decision).
    Suppress,
}
