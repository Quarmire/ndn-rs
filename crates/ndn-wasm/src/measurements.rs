//! Measurements table for the WASM simulation.
//!
//! Tracks per-(prefix, face) EWMA RTT and per-prefix satisfaction rate.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// EWMA RTT measurement for a (prefix, face) pair.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EwmaRtt {
    pub srtt_ms: f64,
    pub rttvar_ms: f64,
    pub samples: u32,
}

impl EwmaRtt {
    pub fn update(&mut self, sample_ms: f64) {
        const ALPHA: f64 = 0.125;
        const BETA: f64 = 0.25;
        if self.samples == 0 {
            self.srtt_ms = sample_ms;
            self.rttvar_ms = sample_ms / 2.0;
        } else {
            let diff = (sample_ms - self.srtt_ms).abs();
            self.rttvar_ms = (1.0 - BETA) * self.rttvar_ms + BETA * diff;
            self.srtt_ms = (1.0 - ALPHA) * self.srtt_ms + ALPHA * sample_ms;
        }
        self.samples += 1;
    }

    pub fn rto_ms(&self) -> f64 {
        self.srtt_ms + 4.0 * self.rttvar_ms
    }
}

impl Default for EwmaRtt {
    fn default() -> Self {
        Self { srtt_ms: 0.0, rttvar_ms: 0.0, samples: 0 }
    }
}

/// Per-prefix measurements entry.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MeasurementsEntry {
    pub prefix: String,
    /// Per-face EWMA RTT (ms).
    pub rtt_per_face: HashMap<u32, EwmaRtt>,
    /// EWMA satisfaction rate (0.0–1.0).
    pub satisfaction_rate: f32,
}

/// Snapshot for JS display.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MeasurementsSnapshot {
    pub entries: Vec<MeasurementsEntry>,
}

/// The measurements table.
pub struct SimMeasurements {
    entries: HashMap<String, MeasurementsEntry>,
}

impl SimMeasurements {
    pub fn new() -> Self {
        Self { entries: HashMap::new() }
    }

    pub fn update_rtt(&mut self, prefix: &str, face_id: u32, rtt_ms: f64) {
        let entry = self.entries.entry(prefix.to_string()).or_insert_with(|| MeasurementsEntry {
            prefix: prefix.to_string(),
            ..Default::default()
        });
        entry.rtt_per_face.entry(face_id).or_default().update(rtt_ms);
    }

    pub fn update_satisfaction(&mut self, prefix: &str, satisfied: bool) {
        const ALPHA: f32 = 0.1;
        let entry = self.entries.entry(prefix.to_string()).or_insert_with(|| MeasurementsEntry {
            prefix: prefix.to_string(),
            ..Default::default()
        });
        let sample = if satisfied { 1.0f32 } else { 0.0 };
        entry.satisfaction_rate = (1.0 - ALPHA) * entry.satisfaction_rate + ALPHA * sample;
    }

    pub fn get_rtt(&self, prefix: &str, face_id: u32) -> Option<&EwmaRtt> {
        self.entries.get(prefix).and_then(|e| e.rtt_per_face.get(&face_id))
    }

    pub fn get_satisfaction(&self, prefix: &str) -> f32 {
        self.entries.get(prefix).map(|e| e.satisfaction_rate).unwrap_or(0.0)
    }

    pub fn snapshot(&self) -> MeasurementsSnapshot {
        let mut entries: Vec<MeasurementsEntry> = self.entries.values().cloned().collect();
        entries.sort_by(|a, b| a.prefix.cmp(&b.prefix));
        MeasurementsSnapshot { entries }
    }
}

impl Default for SimMeasurements {
    fn default() -> Self {
        Self::new()
    }
}
