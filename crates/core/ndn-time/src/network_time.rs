//! Network-wide time from single-hop hardware common-view — the multi-hop layer over
//! [`RadioHwClock`](crate::RadioHwClock)/`ingest_common_view`.
//!
//! A single mesh beacon gives a node its offset to *one* neighbour's hardware clock (~0.5 µs, #74). To
//! agree on **one** timeline across a multi-hop mesh — including nodes out of the reference's range — the
//! offsets compose along a path, the way FTSP / STP's root election do, with no coordinator:
//!
//! - The network **reference** is the node with the **lowest id** (the ephemeral §2 nonce). Deterministic,
//!   so every node converges on the same reference with nothing negotiated.
//! - Each node advertises its current belief `(ref_id, stratum, offset_to_ref)` in its timing beacon,
//!   where `offset_to_ref` maps *its* hardware clock onto the reference timeline: `ref_time = my_tsf +
//!   offset_to_ref`. The reference itself advertises `(my_id, stratum 0, offset 0)`.
//! - A node hearing a neighbour composes: it measures the hardware offset to that neighbour
//!   (`nbr_tsf − my_rxtsfl`, the common-view pair) and adds the neighbour's advertised `offset_to_ref`:
//!   `my.offset_to_ref = (nbr_tsf − my_rxtsfl) + nbr.offset_to_ref`, `my.stratum = nbr.stratum + 1`.
//!   Each hop adds only the RX-stamp jitter, so a k-hop node tracks the reference to ~`k·0.5 µs`.
//! - **Election / loop-freedom:** adopt a candidate only if it is *strictly better* — lower `ref_id`, or
//!   equal `ref_id` at lower `stratum` (a shorter path to the same reference). A node with no better
//!   neighbour is its own reference at stratum 0. This is a shortest-path tree rooted at the lowest id;
//!   the strict-better rule prevents count-to-infinity loops within a stable topology.
//!
//! Soft-state (§7): the belief is recomputed from beacons; lose it and a node reverts to its own
//! reference and re-converges from the next beacons, with no time step (its underlying TSF is continuous).

/// A node's belief about the network timebase: which node is the reference, how many hops away, and the
/// offset that maps this node's hardware clock onto the reference timeline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefBelief {
    /// The elected reference node's id (lowest-id wins; the ephemeral nonce folded to u64).
    pub ref_id: u64,
    /// Hops to the reference (0 = this node *is* the reference).
    pub stratum: u8,
    /// `ref_time = local_tsf + offset_to_ref` (µs). Composes along the path to the reference.
    pub offset_to_ref: i64,
}

/// The multi-hop network-time state for one node.
#[derive(Clone, Copy, Debug)]
pub struct NetworkTime {
    my_id: u64,
    best: RefBelief,
}

impl NetworkTime {
    /// A node that starts as its own reference (stratum 0), until it hears a lower-id one.
    pub fn new(my_id: u64) -> Self {
        Self { my_id, best: RefBelief { ref_id: my_id, stratum: 0, offset_to_ref: 0 } }
    }

    /// Ingest a neighbour's advertised belief plus the **measured hardware offset to that neighbour**
    /// (`nbr_tsf − my_rxtsfl`, µs, from the common-view beacon pair). Composes the candidate path to the
    /// neighbour's reference and adopts it iff strictly better. Returns `true` if our belief changed.
    pub fn observe(&mut self, nbr_hw_offset_us: i64, nbr: RefBelief) -> bool {
        let cand = RefBelief {
            ref_id: nbr.ref_id,
            stratum: nbr.stratum.saturating_add(1),
            offset_to_ref: nbr_hw_offset_us.wrapping_add(nbr.offset_to_ref),
        };
        // A neighbour advertising *us* as its reference (a child) must never be adopted as our parent —
        // that is the loop. Since our own id is a valid reference at stratum 0, only a genuinely lower
        // ref_id, or a shorter path to our current same reference, wins.
        if cand.ref_id == self.my_id {
            return false;
        }
        if Self::better(&cand, &self.best) {
            self.best = cand;
            true
        } else if self.best.ref_id == cand.ref_id && self.best.stratum == cand.stratum {
            // Same reference and path length: refresh the offset (tracks drift) without a "changed" event.
            self.best.offset_to_ref = cand.offset_to_ref;
            false
        } else {
            false
        }
    }

    /// Strictly-better ordering: lower `ref_id` first, then lower `stratum`.
    fn better(cand: &RefBelief, cur: &RefBelief) -> bool {
        (cand.ref_id, cand.stratum) < (cur.ref_id, cur.stratum)
    }

    /// This node's current belief — also what it advertises in its own timing beacon so the next hop can
    /// compose off it.
    pub fn belief(&self) -> RefBelief {
        self.best
    }

    /// The offset (µs) that maps this node's local hardware clock onto the network reference timeline:
    /// `network_time = local_hw_now + offset_to_ref`.
    pub fn offset_to_ref(&self) -> i64 {
        self.best.offset_to_ref
    }

    /// Whether this node is the elected network reference (the root).
    pub fn is_reference(&self) -> bool {
        self.best.ref_id == self.my_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A line A(1) — B(2) — C(3): A is the lowest id, so all converge to A, C via B (2 hops).
    #[test]
    fn line_converges_to_the_lowest_id_reference() {
        let (mut a, mut b, mut c) = (NetworkTime::new(1), NetworkTime::new(2), NetworkTime::new(3));
        // A is alone → its own reference.
        assert!(a.is_reference());
        // B hears A. Say B's hardware offset to A is +1000 µs (A_tsf − B_rxtsfl).
        assert!(b.observe(1000, a.belief()));
        assert_eq!(b.belief(), RefBelief { ref_id: 1, stratum: 1, offset_to_ref: 1000 });
        assert!(!b.is_reference());
        // C hears B (C's hw offset to B = +2000). C composes to A via B: 2 hops, offset 2000 + 1000.
        assert!(c.observe(2000, b.belief()));
        assert_eq!(c.belief(), RefBelief { ref_id: 1, stratum: 2, offset_to_ref: 3000 });
        // C's network time = C_local + 3000 ≈ A's timeline (2 hops of composition).
        assert_eq!(c.offset_to_ref(), 3000);
    }

    #[test]
    fn prefers_shorter_path_and_ignores_children() {
        let mut c = NetworkTime::new(3);
        // C hears B(ref A, stratum 1, off 1000) via hw offset 2000 → stratum 2.
        c.observe(2000, RefBelief { ref_id: 1, stratum: 1, offset_to_ref: 1000 });
        assert_eq!(c.belief().stratum, 2);
        // C also hears A directly (ref A, stratum 0, off 0) via hw offset 500 → stratum 1, strictly better.
        assert!(c.observe(500, RefBelief { ref_id: 1, stratum: 0, offset_to_ref: 0 }));
        assert_eq!(c.belief(), RefBelief { ref_id: 1, stratum: 1, offset_to_ref: 500 });
        // A hearing C advertise A-as-ref must NOT adopt C as parent (loop / child).
        let mut a = NetworkTime::new(1);
        assert!(!a.observe(-500, c.belief()));
        assert!(a.is_reference());
    }

    #[test]
    fn a_higher_id_neighbour_does_not_displace_our_reference() {
        let mut a = NetworkTime::new(1);
        // A hears B(2) advertising itself → A keeps itself (lower id).
        assert!(!a.observe(1000, RefBelief { ref_id: 2, stratum: 0, offset_to_ref: 0 }));
        assert!(a.is_reference());
    }
}
