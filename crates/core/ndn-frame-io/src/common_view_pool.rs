//! Multi-receiver common-view pairing, keyed by [`EventId`].
//!
//! Named-time's M3 common-view offset ([`ndn_time::common_view`]) needs two receivers' [`RxObs`]
//! of *one* physical event; on a shared broadcast medium "the same event" is exactly an
//! [`EventId`] (a frame's content digest bound to its channel). This module does the matching a
//! single `common_view` call cannot: receivers stream their receptions in — each tagged with the
//! `EventId` it computed and its own `RxObs` — and every time a reception matches an event another
//! receiver already reported, the pool emits the inter-receiver clock offset between them.
//!
//! The transmitter's clock error and the common emission time cancel in each pair, so N receivers
//! of one beacon yield a mesh of pairwise offsets with no trusted transmitter. Per §M3 the results
//! are **not** distance-bounded (a relay re-radiating to one receiver defeats common-view — T1);
//! [`ndn_time::common_view`] forces that flag off, and this pool inherits it.

use std::collections::{HashMap, VecDeque};

use ndn_time::{Measured, MeasurementProvenance, RxObs, common_view};

use crate::EventId;

/// Identifies a receiver within a common-view group — an opaque, caller-chosen id (a face index, a
/// node id). Distinct physical receivers of one event MUST carry distinct ids; a repeated id is
/// treated as the same receiver re-reporting (its latest `RxObs` replaces the earlier one).
pub type ReceiverId = u64;

/// A common-view inter-receiver clock offset: `offset.value` is receiver `a`'s clock minus receiver
/// `b`'s, derived from both hearing one event ([`EventId`]). The transmitter's clock cancels; only
/// the difference of the two modelled propagation delays enters the uncertainty.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct InterReceiverOffset {
    /// The receiver whose clock is the minuend (`a − b`).
    pub a: ReceiverId,
    /// The receiver whose clock is the subtrahend.
    pub b: ReceiverId,
    /// The event both receivers heard.
    pub event: EventId,
    /// The offset `a − b`, ns, with uncertainty and provenance (`distance_bounded = false`).
    pub offset: Measured<i64>,
}

/// Pairs receptions of the same physical event across receivers to yield common-view offsets.
///
/// Bounded: holds at most `capacity` distinct in-flight events, evicting the oldest first, so a
/// reception whose partner never arrives cannot grow the pool without bound. Insert receptions with
/// [`observe`](Self::observe); each call returns the offsets the newcomer forms with receivers that
/// already reported the same event.
pub struct CommonViewPool {
    /// event → receptions, one entry per receiver id.
    pending: HashMap<EventId, Vec<(ReceiverId, RxObs)>>,
    /// First-seen order of events, for oldest-first eviction.
    order: VecDeque<EventId>,
    capacity: usize,
}

impl CommonViewPool {
    /// A pool holding at most `capacity` distinct in-flight events (clamped to ≥ 1).
    pub fn new(capacity: usize) -> Self {
        Self {
            pending: HashMap::new(),
            order: VecDeque::new(),
            capacity: capacity.max(1),
        }
    }

    /// Record `receiver`'s reception `obs` of `event`, and return the common-view offsets it forms
    /// with every *other* receiver that already reported the same event.
    ///
    /// `prop_diff_uncertainty_ns` is the error in the difference of the two receivers' modelled
    /// propagation delays (`a.prop − b.prop`); `prov` is the provenance to stamp on each resulting
    /// offset (its `distance_bounded` is forced off by [`common_view`]). A receiver re-reporting the
    /// same event replaces its earlier `RxObs` rather than pairing with itself.
    pub fn observe(
        &mut self,
        event: EventId,
        receiver: ReceiverId,
        obs: RxObs,
        prop_diff_uncertainty_ns: u64,
        prov: MeasurementProvenance,
    ) -> Vec<InterReceiverOffset> {
        let mut out = Vec::new();
        if let Some(existing) = self.pending.get(&event) {
            for &(r, o) in existing.iter() {
                if r == receiver {
                    continue;
                }
                // Newcomer is `a`, the earlier reception is `b`: offset = a − b = receiver − r.
                let offset = common_view(obs, o, prop_diff_uncertainty_ns, prov);
                out.push(InterReceiverOffset {
                    a: receiver,
                    b: r,
                    event,
                    offset,
                });
            }
        }

        match self.pending.get_mut(&event) {
            Some(v) => match v.iter_mut().find(|(r, _)| *r == receiver) {
                Some(slot) => slot.1 = obs,
                None => v.push((receiver, obs)),
            },
            None => {
                self.pending.insert(event, vec![(receiver, obs)]);
                self.order.push_back(event);
                self.evict();
            }
        }
        out
    }

    /// Number of distinct events currently held.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether the pool holds no events.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Drop the oldest events until within capacity.
    fn evict(&mut self) {
        while self.order.len() > self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.pending.remove(&old);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_time::{Authenticity, KeyId, PathId};

    fn prov() -> MeasurementProvenance {
        MeasurementProvenance {
            distance_bounded: false,
            replay_protected: true,
            authenticity: Authenticity::AuthenticatedDomainPeer(KeyId(1)),
            path: PathId(1),
        }
    }

    fn obs(stamp_ns: i64, prop_ns: u64) -> RxObs {
        RxObs {
            stamp_ns,
            prop_ns,
            prec_ns: 1_000,
        }
    }

    fn event(digest: u128) -> EventId {
        EventId {
            digest,
            channel: 36,
        }
    }

    #[test]
    fn pairs_two_receivers_of_one_event() {
        let mut pool = CommonViewPool::new(8);
        let ev = event(0xABCD);
        // First receiver: no partner yet.
        assert!(pool.observe(ev, 1, obs(2_000_000, 500), 100, prov()).is_empty());
        // Second receiver of the same event: one offset, 2 − 1.
        let out = pool.observe(ev, 2, obs(2_005_000, 500), 100, prov());
        assert_eq!(out.len(), 1);
        let o = out[0];
        assert_eq!((o.a, o.b), (2, 1));
        // Equal prop → offset = stamp_2 − stamp_1 = +5 µs.
        assert_eq!(o.offset.value, 5_000);
        assert!(!o.offset.prov.distance_bounded, "common-view can't bound T1");
    }

    #[test]
    fn third_receiver_pairs_with_both_priors() {
        let mut pool = CommonViewPool::new(8);
        let ev = event(1);
        pool.observe(ev, 10, obs(0, 0), 0, prov());
        pool.observe(ev, 20, obs(0, 0), 0, prov());
        let out = pool.observe(ev, 30, obs(0, 0), 0, prov());
        assert_eq!(out.len(), 2, "newcomer pairs with both earlier receivers");
        assert!(out.iter().any(|o| o.b == 10));
        assert!(out.iter().any(|o| o.b == 20));
    }

    #[test]
    fn different_events_do_not_pair() {
        let mut pool = CommonViewPool::new(8);
        pool.observe(event(1), 1, obs(0, 0), 0, prov());
        // Same content, different channel → different event → no pairing.
        let other_channel = EventId {
            digest: 1,
            channel: 149,
        };
        assert!(pool.observe(other_channel, 2, obs(0, 0), 0, prov()).is_empty());
    }

    #[test]
    fn same_receiver_reporting_twice_does_not_self_pair() {
        let mut pool = CommonViewPool::new(8);
        let ev = event(7);
        pool.observe(ev, 1, obs(0, 0), 0, prov());
        // Same receiver id again: updates its obs, no self-pair.
        assert!(pool.observe(ev, 1, obs(9_000, 0), 0, prov()).is_empty());
        assert_eq!(pool.len(), 1);
        // A genuine second receiver now sees the *updated* stamp.
        let out = pool.observe(ev, 2, obs(0, 0), 0, prov());
        assert_eq!(out[0].offset.value, -9_000, "2 − 1 with 1's latest stamp");
    }

    #[test]
    fn evicts_oldest_beyond_capacity() {
        let mut pool = CommonViewPool::new(2);
        pool.observe(event(1), 1, obs(0, 0), 0, prov());
        pool.observe(event(2), 1, obs(0, 0), 0, prov());
        pool.observe(event(3), 1, obs(0, 0), 0, prov()); // evicts event(1)
        assert_eq!(pool.len(), 2);
        // event(1)'s partner arrives too late — its record is gone, so no pairing.
        assert!(pool.observe(event(1), 2, obs(0, 0), 0, prov()).is_empty());
    }
}
