#[cfg(not(target_arch = "wasm32"))]
use dashmap::DashMap;
use ndn_packet::Name;
use ndn_transport::FaceId;
use std::collections::HashMap;
use std::sync::Arc;

/// EWMA RTT measurement for a (prefix, face) pair.
#[derive(Clone, Debug)]
pub struct EwmaRtt {
    pub srtt_ns: f64,
    pub rttvar_ns: f64,
    pub samples: u32,
}

impl EwmaRtt {
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

#[derive(Clone, Debug, Default)]
pub struct MeasurementsEntry {
    pub rtt_per_face: HashMap<FaceId, EwmaRtt>,
    pub satisfaction_rate: f32,
    pub last_updated: u64,
}

/// Upper bound on distinct prefixes a [`MeasurementsTable`] retains before
/// evicting the least-recently-updated entry. Bounds memory on a
/// public-facing forwarder: each unique Interest prefix would otherwise
/// allocate a permanent entry (the per-prefix EWMA state). NFD's
/// `table::Measurements` bounds lifetime per entry; we bound the table size
/// since the strategy reads a snapshot, not a live-extended record.
pub const DEFAULT_CAPACITY: usize = 16_384;

/// Concurrent measurements table, one entry per name prefix.
///
/// `DashMap` on native, `Mutex<HashMap>` on wasm32. Bounded to `capacity`
/// entries with least-recently-updated eviction (see [`DEFAULT_CAPACITY`]).
pub struct MeasurementsTable {
    #[cfg(not(target_arch = "wasm32"))]
    entries: DashMap<Arc<Name>, MeasurementsEntry>,
    #[cfg(target_arch = "wasm32")]
    entries: std::sync::Mutex<HashMap<Arc<Name>, MeasurementsEntry>>,
    capacity: usize,
}

impl MeasurementsTable {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// Construct with an explicit prefix capacity (LRU-by-update eviction).
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            #[cfg(not(target_arch = "wasm32"))]
            entries: DashMap::new(),
            #[cfg(target_arch = "wasm32")]
            entries: std::sync::Mutex::new(HashMap::new()),
            capacity: capacity.max(1),
        }
    }

    /// Number of retained prefixes (test/introspection).
    pub fn len(&self) -> usize {
        #[cfg(not(target_arch = "wasm32"))]
        return self.entries.len();
        #[cfg(target_arch = "wasm32")]
        return self.entries.lock().unwrap().len();
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Native: if inserting `incoming` would exceed `capacity`, drop the
    /// entry with the smallest `last_updated`. The key is collected before
    /// removal so no shard guard is held across `remove` (DashMap deadlock
    /// safety).
    #[cfg(not(target_arch = "wasm32"))]
    fn evict_if_full(&self, incoming: &Arc<Name>) {
        if self.entries.len() < self.capacity || self.entries.contains_key(incoming) {
            return;
        }
        let mut oldest: Option<(Arc<Name>, u64)> = None;
        for r in self.entries.iter() {
            let ts = r.value().last_updated;
            if oldest.as_ref().is_none_or(|(_, t)| ts < *t) {
                oldest = Some((Arc::clone(r.key()), ts));
            }
        }
        if let Some((victim, _)) = oldest {
            self.entries.remove(&victim);
        }
    }

    pub fn get(&self, name: &Arc<Name>) -> Option<MeasurementsEntry> {
        #[cfg(not(target_arch = "wasm32"))]
        return self.entries.get(name).map(|r| r.clone());
        #[cfg(target_arch = "wasm32")]
        return self.entries.lock().unwrap().get(name).cloned();
    }

    pub fn update_rtt(&self, name: Arc<Name>, face: FaceId, rtt_ns: f64) {
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.evict_if_full(&name);
            let mut entry = self.entries.entry(name).or_default();
            entry.rtt_per_face.entry(face).or_default().update(rtt_ns);
            entry.last_updated = now_ns();
        }
        #[cfg(target_arch = "wasm32")]
        {
            let mut entries = self.entries.lock().unwrap();
            evict_if_full_locked(&mut entries, &name, self.capacity);
            let entry = entries.entry(name).or_default();
            entry.rtt_per_face.entry(face).or_default().update(rtt_ns);
            entry.last_updated = now_ns();
        }
    }

    pub fn dump(&self) -> Vec<(Arc<Name>, MeasurementsEntry)> {
        #[cfg(not(target_arch = "wasm32"))]
        return self
            .entries
            .iter()
            .map(|r| (Arc::clone(r.key()), r.value().clone()))
            .collect();
        #[cfg(target_arch = "wasm32")]
        return self
            .entries
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (Arc::clone(k), v.clone()))
            .collect();
    }

    pub fn update_satisfaction(&self, name: Arc<Name>, satisfied: bool) {
        const ALPHA: f32 = 0.1;
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.evict_if_full(&name);
            let mut entry = self.entries.entry(name).or_default();
            let sample = if satisfied { 1.0f32 } else { 0.0 };
            entry.satisfaction_rate = (1.0 - ALPHA) * entry.satisfaction_rate + ALPHA * sample;
            entry.last_updated = now_ns();
        }
        #[cfg(target_arch = "wasm32")]
        {
            let mut entries = self.entries.lock().unwrap();
            evict_if_full_locked(&mut entries, &name, self.capacity);
            let entry = entries.entry(name).or_default();
            let sample = if satisfied { 1.0f32 } else { 0.0 };
            entry.satisfaction_rate = (1.0 - ALPHA) * entry.satisfaction_rate + ALPHA * sample;
            entry.last_updated = now_ns();
        }
    }
}

/// wasm32 eviction helper: drop the least-recently-updated entry when full.
#[cfg(target_arch = "wasm32")]
fn evict_if_full_locked(
    entries: &mut HashMap<Arc<Name>, MeasurementsEntry>,
    incoming: &Arc<Name>,
    capacity: usize,
) {
    if entries.len() < capacity || entries.contains_key(incoming) {
        return;
    }
    if let Some(victim) = entries
        .iter()
        .min_by_key(|(_, v)| v.last_updated)
        .map(|(k, _)| Arc::clone(k))
    {
        entries.remove(&victim);
    }
}

impl Default for MeasurementsTable {
    fn default() -> Self {
        Self::new()
    }
}

fn now_ns() -> u64 {
    use web_time::SystemTime;
    use web_time::UNIX_EPOCH;
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

    #[test]
    fn measurements_table_is_bounded_by_capacity() {
        // Inserting many distinct prefixes must not grow the table without
        // bound — the least-recently-updated entry is evicted at capacity.
        let table = MeasurementsTable::with_capacity(8);
        for i in 0..1000u32 {
            let name = Arc::new(format!("/m/{i}").parse::<Name>().unwrap());
            table.update_satisfaction(name, true);
        }
        assert!(
            table.len() <= 8,
            "table must stay within capacity, got {}",
            table.len()
        );
    }

    #[test]
    fn measurements_table_eviction_keeps_recent() {
        // An entry refreshed on every round stays the most-recently-updated,
        // so LRU-by-update eviction must never drop it.
        let table = MeasurementsTable::with_capacity(4);
        let keep = Arc::new("/hot/prefix".parse::<Name>().unwrap());
        table.update_satisfaction(Arc::clone(&keep), true);
        for i in 0..50u32 {
            let fill = Arc::new(format!("/cold/{i}").parse::<Name>().unwrap());
            table.update_satisfaction(fill, true);
            // Re-touch the hot prefix so it is newest going into the next round.
            table.update_satisfaction(Arc::clone(&keep), true);
        }
        assert!(table.len() <= 4);
        assert!(
            table.get(&keep).is_some(),
            "the continuously-refreshed entry must survive eviction"
        );
    }
}
