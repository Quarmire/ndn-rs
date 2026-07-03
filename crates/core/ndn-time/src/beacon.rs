//! Peer-derived samples — the pure adapter from a *validated* time beacon to a
//! discipline-loop input.
//!
//! A time beacon is a signed Data packet: a peer publishing its own
//! `(wall estimate ± uncertainty, capability, provenance)` under
//! `/<scope>/time/<node>`. **Validation and wire decode happen up in the
//! security/app layer** — by the time a beacon reaches here it is already a
//! trusted assertion (a `SafeData`). This module is only the pure conversion of
//! that trusted assertion into a [`PeerSample`] the [`discipline`](crate::discipline)
//! loop can combine, so it lives in the core with no I/O and no NDN dependency.
//!
//! This is the "PeerDerived source" of the design — but because it is pure it
//! belongs beside the loop it feeds, not in the I/O-backends crate.

use crate::capability::ClockCapability;
use crate::discipline::PeerSample;
use crate::interval::TimeInterval;
use crate::provenance::{Measured, MeasurementProvenance};

/// A validated time beacon received from a peer.
///
/// Holds the peer's assertion (`wall`, `cap`) and the circumstances of *our*
/// reception (`captured_mono_ns`, `prov`). The provenance is what the receiver
/// established — authenticated by which key, over which path, replay-protected?
/// — and it flows straight into the sample so the combiner's admission sees it.
#[derive(Clone, Copy, Debug)]
pub struct TimeBeacon {
    /// The peer's wall-clock estimate as an interval (its own `± uncertainty`).
    pub wall: TimeInterval,
    /// The peer's self-described clock capability (rides its signed beacon).
    pub cap: ClockCapability,
    /// Local monotonic clock (ns) when we received the beacon — anchors holdover
    /// aging and the skew regression downstream.
    pub captured_mono_ns: u64,
    /// The adversary exposure under which we received it (authenticity, path,
    /// replay). Established by the validating layer, carried through verbatim.
    pub prov: MeasurementProvenance,
}

impl TimeBeacon {
    /// Convert into a [`PeerSample`] given our current local wall estimate.
    ///
    /// The offset (`remote − local`) is `peer_wall − local_wall`, so that the
    /// discipline loop's `offset_to_wall` reconstructs exactly the peer's wall
    /// interval; the sample carries the peer's uncertainty and our reception
    /// provenance.
    ///
    /// Note: this treats the beacon's stated wall as the peer's estimate "as
    /// received". A beacon crosses a propagation delay; where that delay is
    /// significant relative to the uncertainty, prefer the one-way path
    /// ([`crate::measure::one_way`]) over a stamped beacon, or widen `wall` by
    /// the delay before constructing the beacon.
    pub fn into_peer_sample(&self, local_wall_ns: i64) -> PeerSample {
        let offset = self.wall.center_ns.saturating_sub(local_wall_ns);
        PeerSample {
            offset: Measured {
                value: offset,
                sigma_ns: self.wall.radius_ns,
                prov: self.prov,
            },
            captured_mono_ns: self.captured_mono_ns,
            cap: self.cap,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provenance::{Authenticity, KeyId, PathId};

    fn prov() -> MeasurementProvenance {
        MeasurementProvenance {
            distance_bounded: false,
            replay_protected: true,
            authenticity: Authenticity::AuthenticatedDomainPeer(KeyId(7)),
            path: PathId(3),
        }
    }

    #[test]
    fn beacon_becomes_a_sample_that_reconstructs_the_peer_wall() {
        // Peer asserts true wall = 1.700000005 s ± 2 µs; we are at 1.7 s local.
        let beacon = TimeBeacon {
            wall: TimeInterval::new(1_700_000_005_000, 2_000),
            cap: ClockCapability::gnss_disciplined(),
            captured_mono_ns: 42,
            prov: prov(),
        };
        let s = beacon.into_peer_sample(1_700_000_000_000);
        // offset = peer_wall − local_wall = +5 µs.
        assert_eq!(s.offset.value, 5_000);
        assert_eq!(s.offset.sigma_ns, 2_000, "peer uncertainty carried");
        assert_eq!(s.captured_mono_ns, 42);
        // The reception provenance flows into the sample for admission.
        assert!(s.offset.prov.authenticity.is_authenticated());

        // And offset_to_wall(sample, local_wall) reconstructs the peer's wall.
        let iv = crate::measure::offset_to_wall(&s.offset, 1_700_000_000_000);
        assert_eq!(iv.center_ns, 1_700_000_005_000);
        assert_eq!(iv.radius_ns, 2_000);
    }
}
