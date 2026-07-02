//! The **congestion-feedback bridge** — G1's closed-loop piece.
//!
//! A downstream forwarder's egress CoDel marking stamps an NDNLPv2 congestion mark
//! on Data flowing back; the engine decodes it into a `CongestionMark` tag. This
//! bridge turns those per-packet marks into the coarse per-face
//! [`LinkSignals::congestion`](ndn_signals_core::LinkSignals::congestion) that
//! [`CongestionAwareStrategy`](crate::CongestionAwareStrategy) reads — closing the
//! loop so the strategy steers Interests off a congesting upstream.
//!
//! Split into two handles sharing one accumulator:
//! - [`CongestionFeedback`] — the **hot-path** handle the dispatcher calls
//!   ([`observe`](CongestionFeedback::observe)) when a returning Data carries a mark.
//!   Only *marked* Data touch it (one sharded atomic add); the uncongested common
//!   case is free.
//! - [`CongestionSource`] — a [`SignalSource`] the engine's signal driver polls on a
//!   cadence: it reads+resets each face's mark count, classifies it to a
//!   [`CongestionLevel`], and **field-merges** it into the face's `LinkSignals`
//!   (without clobbering RSSI/RTT). **Decay is intrinsic**: a window with no marks
//!   classifies to "clear", so congestion drains back as the upstream recovers — no
//!   timestamp, no hot-path cost.

use std::sync::Arc;
// Atomics back the native DashMap counters; the wasm arm uses Mutex<HashMap>.
#[cfg(not(target_arch = "wasm32"))]
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

#[cfg(not(target_arch = "wasm32"))]
use dashmap::DashMap;
#[cfg(target_arch = "wasm32")]
use std::collections::HashMap;
#[cfg(target_arch = "wasm32")]
use std::sync::Mutex;

use ndn_signals_core::{CongestionLevel, SignalSource, SignalStore};
use ndn_transport::FaceId;

/// Tuning for the mark→level classification and cadence. Counts are marks observed
/// within one [`window`](Self::window); thresholds are heuristic (a coarse 3-level
/// signal) and deliberately simple — marks are *explicit* congestion indications, so
/// any marks mean some congestion and more marks mean more.
#[derive(Clone, Copy, Debug)]
pub struct CongestionConfig {
    /// Classification/decay cadence (also the source poll interval).
    pub window: Duration,
    /// `>= medium` marks in a window ⇒ at least [`CongestionLevel::Medium`].
    pub medium: u64,
    /// `>= high` marks in a window ⇒ [`CongestionLevel::High`].
    pub high: u64,
}

impl Default for CongestionConfig {
    fn default() -> Self {
        Self {
            window: Duration::from_millis(200),
            medium: 4,
            high: 13,
        }
    }
}

impl CongestionConfig {
    /// Map a window's mark count to a level. `0` ⇒ `None` (clear — the decay path).
    fn classify(&self, marks: u64) -> Option<CongestionLevel> {
        if marks == 0 {
            None
        } else if marks >= self.high {
            Some(CongestionLevel::High)
        } else if marks >= self.medium {
            Some(CongestionLevel::Medium)
        } else {
            Some(CongestionLevel::Low)
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
type Counts = DashMap<FaceId, AtomicU64>;
#[cfg(target_arch = "wasm32")]
type Counts = Mutex<HashMap<FaceId, u64>>;

/// Hot-path handle: increment a face's mark count. Cheap and lock-light; only called
/// for Data that actually carry a congestion mark.
pub struct CongestionFeedback {
    counts: Arc<Counts>,
}

impl CongestionFeedback {
    /// Record one congestion mark observed on `face`.
    pub fn observe(&self, face: FaceId) {
        #[cfg(not(target_arch = "wasm32"))]
        {
            // Fast path: a read-locked shard + an atomic add for an existing face.
            if let Some(c) = self.counts.get(&face) {
                c.fetch_add(1, Ordering::Relaxed);
            } else {
                self.counts
                    .entry(face)
                    .or_default()
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        #[cfg(target_arch = "wasm32")]
        {
            *self.counts.lock().unwrap().entry(face).or_default() += 1;
        }
    }
}

/// Off-path [`SignalSource`]: each poll drains the per-face counts and writes the
/// classified [`CongestionLevel`] into the shared signal store.
pub struct CongestionSource {
    counts: Arc<Counts>,
    cfg: CongestionConfig,
}

impl SignalSource<FaceId> for CongestionSource {
    fn name(&self) -> &str {
        "congestion-feedback"
    }

    fn interval(&self) -> Duration {
        self.cfg.window
    }

    fn poll(&mut self, store: &dyn SignalStore<FaceId>, _now_ms: u32) {
        // Snapshot+reset every face's count (drop the iterator before touching the
        // signal store, which is a different map).
        #[cfg(not(target_arch = "wasm32"))]
        let snapshot: Vec<(FaceId, u64)> = self
            .counts
            .iter()
            .map(|e| (*e.key(), e.value().swap(0, Ordering::Relaxed)))
            .collect();
        #[cfg(target_arch = "wasm32")]
        let snapshot: Vec<(FaceId, u64)> = {
            let mut g = self.counts.lock().unwrap();
            g.iter_mut()
                .map(|(k, v)| {
                    let n = *v;
                    *v = 0;
                    (*k, n)
                })
                .collect()
        };

        for (face, marks) in snapshot {
            let level = self.cfg.classify(marks);
            // Merge only the congestion field (don't touch updated_ms — the tick keeps
            // it fresh implicitly, so stamping it would lie about RSSI/RTT staleness).
            store.update_link(face, &mut |ls| ls.congestion = level);
            // A face that decayed to clear is dropped so idle faces stop churning;
            // re-created on the next mark. `remove_if` avoids losing a concurrent add.
            if marks == 0 {
                #[cfg(not(target_arch = "wasm32"))]
                self.counts
                    .remove_if(&face, |_, c| c.load(Ordering::Relaxed) == 0);
                #[cfg(target_arch = "wasm32")]
                {
                    let mut g = self.counts.lock().unwrap();
                    if g.get(&face).copied() == Some(0) {
                        g.remove(&face);
                    }
                }
            }
        }
    }
}

/// Build the bridge: a shared accumulator behind a [`CongestionFeedback`] (for the
/// dispatcher hot path) and a [`CongestionSource`] (for the engine's signal driver).
pub fn congestion_feedback(cfg: CongestionConfig) -> (CongestionFeedback, CongestionSource) {
    #[cfg(not(target_arch = "wasm32"))]
    let counts = Arc::new(DashMap::new());
    #[cfg(target_arch = "wasm32")]
    let counts = Arc::new(Mutex::new(HashMap::new()));
    (
        CongestionFeedback {
            counts: Arc::clone(&counts),
        },
        CongestionSource { counts, cfg },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signals::SignalsTable;
    use ndn_signals_core::SignalView;

    #[test]
    fn classify_thresholds() {
        let c = CongestionConfig::default();
        assert_eq!(c.classify(0), None);
        assert_eq!(c.classify(1), Some(CongestionLevel::Low));
        assert_eq!(c.classify(4), Some(CongestionLevel::Medium));
        assert_eq!(c.classify(13), Some(CongestionLevel::High));
        assert_eq!(c.classify(999), Some(CongestionLevel::High));
    }

    #[test]
    fn marks_become_congestion_then_decay() {
        let (fb, mut src) = congestion_feedback(CongestionConfig::default());
        let store = SignalsTable::new();
        let face = FaceId(7);

        // Many marks in a window ⇒ High.
        for _ in 0..20 {
            fb.observe(face);
        }
        src.poll(&store, 0);
        assert_eq!(
            store.link(face).and_then(|l| l.congestion),
            Some(CongestionLevel::High)
        );

        // A quiet window decays back to clear.
        src.poll(&store, 200);
        assert_eq!(store.link(face).and_then(|l| l.congestion), None);
    }

    #[test]
    fn congestion_merge_preserves_other_fields() {
        use ndn_signals_core::LinkSignals;
        let (fb, mut src) = congestion_feedback(CongestionConfig::default());
        let store = SignalsTable::new();
        let face = FaceId(3);
        // A radio source has already published RSSI for this face.
        store.set_link(
            face,
            LinkSignals {
                rssi_dbm: Some(-60),
                ..Default::default()
            },
        );
        for _ in 0..5 {
            fb.observe(face);
        }
        src.poll(&store, 0);
        let l = store.link(face).unwrap();
        assert_eq!(l.congestion, Some(CongestionLevel::Medium)); // bridge wrote this
        assert_eq!(l.rssi_dbm, Some(-60)); // …without clobbering RSSI
    }
}
