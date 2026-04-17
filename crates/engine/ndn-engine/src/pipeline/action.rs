use smallvec::SmallVec;

use ndn_transport::FaceId;

// Re-export from ndn-transport where they are defined; both ndn-engine
// and ndn-strategy use these types, and ndn-strategy must not depend on
// ndn-engine to avoid a circular dependency.
pub use ndn_transport::{ForwardingAction, NackReason};

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
    /// Data packet failed signature/chain validation.
    ValidationFailed,
    /// Certificate fetch timed out during validation.
    ValidationTimeout,
    Other,
}

/// Ownership-based return from a pipeline stage: `Continue` returns the
/// context to the runner; all other variants consume it, making
/// use-after-hand-off a compile error.
pub enum Action {
    Continue(super::context::PacketContext),
    Send(super::context::PacketContext, SmallVec<[FaceId; 4]>),
    Satisfy(super::context::PacketContext),
    Drop(DropReason),
    Nack(super::context::PacketContext, NackReason),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::context::PacketContext;
    use bytes::Bytes;
    use ndn_transport::FaceId;
    use smallvec::smallvec;

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
            DropReason::ValidationFailed,
            DropReason::ValidationTimeout,
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
        assert!(matches!(
            ForwardingAction::Suppress,
            ForwardingAction::Suppress
        ));
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
