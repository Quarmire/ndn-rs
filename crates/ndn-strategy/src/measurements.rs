#[cfg(not(target_arch = "wasm32"))]
use dashmap::DashMap;
use ndn_packet::Name;
use ndn_transport::FaceId;
use std::collections::HashMap;
use std::sync::Arc;

/// EWMA RTT measurement for a (prefix, face) pair.
#[derive(Clone, Debug)]
pub struct EwmaRtt {
    /// Smoothed RTT in nanoseconds.
    pub srtt_ns: f64,
    /// RTT variance.
    pub rttvar_ns: f64,
    /// Number of samples.
    pub samples: u32,
}

impl EwmaRtt {
    /// Incorporate an RTT sample (nanoseconds) using EWMA smoothing.
    pub fn update(&mut self, sample_ns: f64) {
        const ALPHA: f64 = 0.125;
        const BETA: f64 = 0.25;
        if self.samples == 0 {
            self.srtt_ns = sample_ns;
            self.rttvar_ns = sample_ns / 2.0;
        } else {
            let diff = (sample_ns - self.srtt_ns).abs();
            self.rttvar_ns = (1.0 - BETA) * self.rttvar_ns + BETA * diff;
            self.srtt_ns = (1.0 - ALPHA) * self.srtt_ns + ALPHA * sample_ns;
        }
        self.samples += 1;
    }

    /// RTO estimate: srtt + 4 * rttvar.
    pub fn rto_ns(&self) -> f64 {
        self.srtt_ns + 4.0 * self.rttvar_ns
    }
}

impl Default for EwmaRtt {
    fn default() -> Self {
        Self {
            srtt_ns: 0.0,
            rttvar_ns: 0.0,
            samples: 0,
        }
    }
}

/// Per-prefix measurements entry.
#[derive(Clone, Debug, Default)]
pub struct MeasurementsEntry {
    /// Per-face RTT measurements.
    pub rtt_per_face: HashMap<FaceId, EwmaRtt>,
    /// EWMA satisfaction rate over the last N Interests (0.0–1.0).
    pub satisfaction_rate: f32,
    /// Timestamp of last update (ns since Unix epoch).
    pub last_updated: u64,
}

/// Concurrent measurements table — one entry per name prefix, keyed by the
/// longest-matching prefix used during the forwarding decision.
///
/// Updated on every Data arrival by the `MeasurementsUpdateStage`.
/// Read by strategies via `StrategyContext`.
///
/// On native targets uses `DashMap` for sharded concurrent access.
/// On `wasm32` uses a `Mutex<HashMap>` (single-threaded WASM has no contention).
pub struct MeasurementsTable {
    #[cfg(not(target_arch = "wasm32"))]
    entries: DashMap<Arc<Name>, MeasurementsEntry>,
    #[cfg(target_arch = "wasm32")]
    entries: std::sync::Mutex<HashMap<Arc<Name>, MeasurementsEntry>>,
}

impl MeasurementsTable {
    /// Create an empty measurements table.
    pub fn new() -> Self {
        Self {
            #[cfg(not(target_arch = "wasm32"))]
            entries: DashMap::new(),
            #[cfg(target_arch = "wasm32")]
            entries: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Look up the measurements entry for a name prefix, returning a clone.
    pub fn get(&self, name: &Arc<Name>) -> Option<MeasurementsEntry> {
        #[cfg(not(target_arch = "wasm32"))]
        return self.entries.get(name).map(|r| r.clone());
        #[cfg(target_arch = "wasm32")]
        return self.entries.lock().unwrap().get(name).cloned();
    }

    /// Record an RTT sample for a (prefix, face) pair, creating the entry if needed.
    pub fn update_rtt(&self, name: Arc<Name>, face: FaceId, rtt_ns: f64) {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let mut entry = self.entries.entry(name).or_default();
            entry.rtt_per_face.entry(face).or_default().update(rtt_ns);
            entry.last_updated = now_ns();
        }
        #[cfg(target_arch = "wasm32")]
        {
            let mut entries = self.entries.lock().unwrap();
            let entry = entries.entry(name).or_default();
            entry.rtt_per_face.entry(face).or_default().update(rtt_ns);
            entry.last_updated = now_ns();
        }
    }

    /// Record an Interest satisfaction outcome, updating the EWMA satisfaction rate.
    pub fn update_satisfaction(&self, name: Arc<Name>, satisfied: bool) {
        const ALPHA: f32 = 0.1;
        #[cfg(not(target_arch = "wasm32"))]
        {
            let mut entry = self.entries.entry(name).or_default();
            let sample = if satisfied { 1.0f32 } else { 0.0 };
            entry.satisfaction_rate = (1.0 - ALPHA) * entry.satisfaction_rate + ALPHA * sample;
            entry.last_updated = now_ns();
        }
        #[cfg(target_arch = "wasm32")]
        {
            let mut entries = self.entries.lock().unwrap();
            let entry = entries.entry(name).or_default();
            let sample = if satisfied { 1.0f32 } else { 0.0 };
            entry.satisfaction_rate = (1.0 - ALPHA) * entry.satisfaction_rate + ALPHA * sample;
            entry.last_updated = now_ns();
        }
    }
}

impl Default for MeasurementsTable {
    fn default() -> Self {
        Self::new()
    }
}

fn now_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_packet::Name;
    use ndn_transport::FaceId;
    use std::sync::Arc;

    #[test]
    fn ewma_first_sample_initialises_srtt() {
        let mut rtt = EwmaRtt::default();
        rtt.update(1_000_000.0); // 1 ms
        assert_eq!(rtt.srtt_ns, 1_000_000.0);
        assert_eq!(rtt.rttvar_ns, 500_000.0); // sample / 2
        assert_eq!(rtt.samples, 1);
    }

    #[test]
    fn ewma_second_sample_converges() {
        let mut rtt = EwmaRtt::default();
        rtt.update(1_000_000.0);
        rtt.update(1_000_000.0); // same RTT → SRTT unchanged
        assert_eq!(rtt.samples, 2);
        assert!((rtt.srtt_ns - 1_000_000.0).abs() < 1.0);
    }

    #[test]
    fn ewma_rto_is_srtt_plus_four_rttvar() {
        let mut rtt = EwmaRtt::default();
        rtt.update(1_000.0);
        let expected = rtt.srtt_ns + 4.0 * rtt.rttvar_ns;
        assert!((rtt.rto_ns() - expected).abs() < 1e-6);
    }

    #[test]
    fn measurements_table_update_rtt_creates_entry() {
        let table = MeasurementsTable::new();
        let name = Arc::new(Name::root());
        table.update_rtt(Arc::clone(&name), FaceId(1), 500_000.0);
        let entry = table.get(&name).expect("entry created");
        assert!(entry.rtt_per_face.contains_key(&FaceId(1)));
        assert!(entry.last_updated > 0);
    }

    #[test]
    fn measurements_table_update_satisfaction_converges() {
        let table = MeasurementsTable::new();
        let name = Arc::new(Name::root());
        // Repeated satisfied updates should drive rate toward 1.0
        for _ in 0..100 {
            table.update_satisfaction(Arc::clone(&name), true);
        }
        let entry = table.get(&name).unwrap();
        assert!(entry.satisfaction_rate > 0.9);
    }

    #[test]
    fn measurements_table_unsatisfied_drives_rate_to_zero() {
        let table = MeasurementsTable::new();
        let name = Arc::new(Name::root());
        // First push rate up...
        for _ in 0..50 {
            table.update_satisfaction(Arc::clone(&name), true);
        }
        // ...then push rate down
        for _ in 0..100 {
            table.update_satisfaction(Arc::clone(&name), false);
        }
        let entry = table.get(&name).unwrap();
        assert!(entry.satisfaction_rate < 0.1);
    }

    #[test]
    fn measurements_table_default_is_empty() {
        let table = MeasurementsTable::default();
        let name = Arc::new(Name::root());
        assert!(table.get(&name).is_none());
    }
}
