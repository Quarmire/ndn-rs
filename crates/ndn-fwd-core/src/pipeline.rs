//! Sans-IO forwarding pipeline — decisions, not I/O.
//!
//! The forwarding pipeline is expressed as pure decision functions: the I/O
//! shell extracts the inputs it already has (parsed wire fields, table lookup
//! results, the clock) and the core returns *what to do* — never touching a
//! socket, an allocator, or an async runtime. The shell then applies the table
//! mutations and emits the bytes.
//!
//! This is the "decide, don't do" seam. It single-sources the **decision tree**
//! — the order of the loop / hop-limit / route / split-horizon checks and which
//! drop reason each produces — which is exactly what otherwise drifts between
//! the native engine's pipeline stages and the embedded forwarder's inline
//! path. Storage abstraction (a `PitStore`/`FibStore` the core could mutate
//! directly) and Data-path decisions are the next bricks; see
//! `.claude/notes/embedded-ndn-modular-build-2026-05-22.md` § 2.

/// Why the forwarder declined to forward a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// HopLimit reached 0 — must not be forwarded.
    HopLimitExceeded,
    /// The Interest's nonce was already seen — a loop.
    DuplicateNonce,
    /// No FIB entry matches the name.
    NoRoute,
    /// The only nexthop is the face the Interest arrived on.
    SplitHorizon,
}

/// A single forwarding action a strategy asks the shell to enact for an
/// Interest. A strategy's output is a list of these (an empty list = suppress).
/// The shared sans-IO vocabulary: the core decides *what* to send and *when*;
/// the I/O shell (native runtime or embedded tick loop) performs the send and
/// owns the timer. `delay_ms` is relative; a shell without a scheduler may
/// degrade `After` to an immediate send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardAction<F> {
    /// Forward to `face` now.
    Now(F),
    /// Forward to `face` after `delay_ms`, unless suppressed (cancelled by
    /// overhearing the same Interest) before the timer fires.
    After(F, u32),
}

/// What to do with an incoming Interest, decided post-decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterestDecision<F> {
    /// Decline, with the reason (for tracing/measurements at the I/O layer).
    Drop(DropReason),
    /// Insert a PIT entry and forward to `nexthop`. `decrement_hop_limit` is
    /// set when the Interest carries a HopLimit TLV the shell must decrement
    /// before re-emitting.
    Forward {
        nexthop: F,
        decrement_hop_limit: bool,
    },
}

/// Inputs the Interest decision needs, gathered by the I/O shell from the wire
/// and the tables.
pub struct InterestInputs<F> {
    /// The decoded HopLimit, if the Interest carried the TLV.
    pub hop_limit: Option<u8>,
    /// Whether this nonce is already in the PIT / dead-nonce list (a loop).
    pub duplicate_nonce: bool,
    /// The FIB longest-prefix-match result, if any.
    pub nexthop: Option<F>,
    /// The face the Interest arrived on.
    pub incoming_face: F,
}

/// The Interest admission + forwarding decision, single-sourced.
///
/// Order: loop detection → hop-limit → route lookup → split-horizon. The inputs
/// are evaluated eagerly by the caller; a route lookup whose result is unused on
/// a loop/hop-limit drop is wasted but harmless (the constrained FIB this first
/// serves is a handful of entries).
pub fn decide_interest<F: PartialEq + Copy>(inputs: InterestInputs<F>) -> InterestDecision<F> {
    if inputs.duplicate_nonce {
        return InterestDecision::Drop(DropReason::DuplicateNonce);
    }
    if inputs.hop_limit == Some(0) {
        return InterestDecision::Drop(DropReason::HopLimitExceeded);
    }
    let Some(nexthop) = inputs.nexthop else {
        return InterestDecision::Drop(DropReason::NoRoute);
    };
    if nexthop == inputs.incoming_face {
        return InterestDecision::Drop(DropReason::SplitHorizon);
    }
    InterestDecision::Forward {
        nexthop,
        decrement_hop_limit: inputs.hop_limit.is_some(),
    }
}

/// Store-driven Interest decision: gathers the inputs from the FIB and PIT via
/// the [`crate::store`] traits, then delegates to [`decide_interest`].
///
/// This is the orchestration both backends will share. A nonce of 0 is treated
/// as absent (never a duplicate), matching NDN's optional-nonce semantics.
pub fn decide_interest_with<Fib, Pit, F>(
    fib: &Fib,
    pit: &Pit,
    components: &[&[u8]],
    hop_limit: Option<u8>,
    nonce: u32,
    incoming_face: F,
) -> InterestDecision<F>
where
    F: Copy + PartialEq,
    Fib: crate::store::FibStore<Face = F>,
    Pit: crate::store::PitStore<Face = F>,
{
    decide_interest(InterestInputs {
        hop_limit,
        duplicate_nonce: nonce != 0 && pit.has_nonce(nonce),
        nexthop: fib.lpm(components),
        incoming_face,
    })
}

/// What happened to an incoming Data, decided post-decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataDecision {
    /// The Data matched pending Interest(s); it was sent to the recorded
    /// downstream face(s) via the caller's closure.
    Satisfied,
    /// No PIT entry matched — the Data is unsolicited and is dropped (NDN does
    /// not cache unsolicited Data by default).
    Unsolicited,
}

/// Store-driven Data decision: satisfy any pending Interest(s) for the Data's
/// name through [`crate::store::PitStore::satisfy`], invoking `send_to` for each
/// recorded downstream face; on a match, admit the Data to the Content Store.
/// Reports whether anything matched.
///
/// Mirrors [`decide_interest_with`] for the Data path. Only solicited Data
/// (a PIT match) is cached — NDN does not cache unsolicited Data by default.
/// Forwarders without a Content Store pass [`crate::store::NoCs`], whose `admit`
/// is a no-op, so the same decision serves the cache-less floor.
pub fn decide_data<Pit, Cs, F>(
    pit: &mut Pit,
    cs: &mut Cs,
    components: &[&[u8]],
    wire: &[u8],
    freshness_ms: u32,
    now_ms: u32,
    send_to: impl FnMut(F),
) -> DataDecision
where
    F: Copy + PartialEq,
    Pit: crate::store::PitStore<Face = F>,
    Cs: crate::store::CsStore,
{
    if pit.satisfy(components, send_to) {
        cs.admit(components, wire, freshness_ms, now_ms);
        DataDecision::Satisfied
    } else {
        DataDecision::Unsolicited
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{CsStore, FibStore, PitStore};

    fn inputs(
        hop_limit: Option<u8>,
        duplicate_nonce: bool,
        nexthop: Option<u8>,
    ) -> InterestInputs<u8> {
        InterestInputs {
            hop_limit,
            duplicate_nonce,
            nexthop,
            incoming_face: 0,
        }
    }

    #[test]
    fn forwards_to_route() {
        assert_eq!(
            decide_interest(inputs(None, false, Some(1))),
            InterestDecision::Forward {
                nexthop: 1,
                decrement_hop_limit: false
            }
        );
    }

    #[test]
    fn forward_flags_hop_limit_present() {
        assert_eq!(
            decide_interest(inputs(Some(5), false, Some(1))),
            InterestDecision::Forward {
                nexthop: 1,
                decrement_hop_limit: true
            }
        );
    }

    #[test]
    fn loop_takes_precedence_over_everything() {
        // Duplicate nonce drops even with HopLimit 0 and a valid route present.
        assert_eq!(
            decide_interest(inputs(Some(0), true, Some(1))),
            InterestDecision::Drop(DropReason::DuplicateNonce)
        );
    }

    #[test]
    fn hop_limit_zero_dropped() {
        assert_eq!(
            decide_interest(inputs(Some(0), false, Some(1))),
            InterestDecision::Drop(DropReason::HopLimitExceeded)
        );
    }

    #[test]
    fn no_route_dropped() {
        assert_eq!(
            decide_interest(inputs(Some(5), false, None)),
            InterestDecision::Drop(DropReason::NoRoute)
        );
    }

    #[test]
    fn split_horizon_dropped() {
        // nexthop == incoming_face (0).
        assert_eq!(
            decide_interest(inputs(None, false, Some(0))),
            InterestDecision::Drop(DropReason::SplitHorizon)
        );
    }

    struct MockFib(Option<u8>);
    impl FibStore for MockFib {
        type Face = u8;
        fn lpm(&self, _components: &[&[u8]]) -> Option<u8> {
            self.0
        }
    }
    struct MockPit(u32);
    impl PitStore for MockPit {
        type Face = u8;
        fn has_nonce(&self, nonce: u32) -> bool {
            nonce == self.0
        }
        fn record_pending(&mut self, _: &[&[u8]], _: u8, _: u32, _: u32, _: u32) {}
        fn satisfy(&mut self, _: &[&[u8]], _: impl FnMut(u8)) -> bool {
            false
        }
        fn discard_pending(&mut self, _: &[&[u8]]) -> bool {
            false
        }
    }

    #[test]
    fn with_stores_forwards() {
        let decision = decide_interest_with(&MockFib(Some(2)), &MockPit(0), &[b"a"], None, 7, 1);
        assert_eq!(
            decision,
            InterestDecision::Forward {
                nexthop: 2,
                decrement_hop_limit: false
            }
        );
    }

    #[test]
    fn with_stores_detects_loop() {
        // PIT already holds nonce 7.
        let decision = decide_interest_with(&MockFib(Some(2)), &MockPit(7), &[b"a"], None, 7, 1);
        assert_eq!(decision, InterestDecision::Drop(DropReason::DuplicateNonce));
    }

    #[test]
    fn with_stores_nonce_zero_is_not_a_loop() {
        // nonce 0 is "absent" and never a duplicate even if the PIT reports it.
        let decision = decide_interest_with(&MockFib(Some(2)), &MockPit(0), &[b"a"], None, 0, 1);
        assert_eq!(
            decision,
            InterestDecision::Forward {
                nexthop: 2,
                decrement_hop_limit: false
            }
        );
    }

    /// A PIT that satisfies once with a single recorded downstream face.
    struct SatPit(Option<u8>);
    impl PitStore for SatPit {
        type Face = u8;
        fn has_nonce(&self, _: u32) -> bool {
            false
        }
        fn record_pending(&mut self, _: &[&[u8]], _: u8, _: u32, _: u32, _: u32) {}
        fn satisfy(&mut self, _: &[&[u8]], mut send_to: impl FnMut(u8)) -> bool {
            match self.0.take() {
                Some(face) => {
                    send_to(face);
                    true
                }
                None => false,
            }
        }
        fn discard_pending(&mut self, _: &[&[u8]]) -> bool {
            self.0.take().is_some()
        }
    }

    /// A CS that records whether `admit` was called.
    #[derive(Default)]
    struct RecCs {
        admitted: bool,
    }
    impl CsStore for RecCs {
        fn lookup(&self, _: &[&[u8]], _: u32) -> Option<&[u8]> {
            None
        }
        fn admit(&mut self, _: &[&[u8]], _: &[u8], _: u32, _: u32) {
            self.admitted = true;
        }
    }

    #[test]
    fn data_satisfies_sends_downstream_and_caches() {
        let mut pit = SatPit(Some(3));
        let mut cs = RecCs::default();
        let mut sent = None;
        let decision = decide_data(&mut pit, &mut cs, &[b"a"], b"wire", 1000, 0, |face| {
            sent = Some(face)
        });
        assert_eq!(decision, DataDecision::Satisfied);
        assert_eq!(sent, Some(3));
        assert!(cs.admitted, "solicited Data must be admitted to the CS");
    }

    #[test]
    fn decide_interest_matches_conformance_vectors() {
        // The sans-io side of the cross-impl pin: decide_interest must Forward
        // iff the case says so. The native engine is pinned to the same vectors
        // in ndn-engine/tests/forwarding_conformance.rs.
        const INCOMING: u8 = 1;
        const OTHER: u8 = 2;
        for case in crate::conformance::INTEREST_DECISION_CASES {
            let nexthop = if case.has_route {
                Some(if case.route_to_incoming {
                    INCOMING
                } else {
                    OTHER
                })
            } else {
                None
            };
            let decision = decide_interest(InterestInputs {
                hop_limit: case.hop_limit,
                duplicate_nonce: case.duplicate_nonce,
                nexthop,
                incoming_face: INCOMING,
            });
            let forwarded = matches!(decision, InterestDecision::Forward { .. });
            assert_eq!(forwarded, case.expect_forward, "case: {}", case.desc);
        }
    }

    #[test]
    fn unsolicited_data_dropped_and_not_cached() {
        let mut pit = SatPit(None);
        let mut cs = RecCs::default();
        let mut called = false;
        let decision = decide_data(&mut pit, &mut cs, &[b"a"], b"wire", 1000, 0, |_| {
            called = true
        });
        assert_eq!(decision, DataDecision::Unsolicited);
        assert!(!called, "no downstream send for unsolicited Data");
        assert!(!cs.admitted, "unsolicited Data must not be cached");
    }
}
