//! Single-node NDN packet pipeline simulation with trace event emission.
//!
//! Mirrors the real ndn-engine pipeline stages:
//!   Interest: TlvDecode → CsLookup → PitCheck → Strategy → Dispatch
//!   Data:     TlvDecode → PitMatch → Validation → CsInsert → Dispatch
//!
//! Each stage emits a [`StageEvent`] describing what happened. These events
//! drive the animated packet bubble in the browser.

use serde::{Deserialize, Serialize};

use crate::cs::{CsSnapshot, SimCs};
use crate::fib::{FibEntry, SimFib};
use crate::pit::{PitSnapshot, SimPit};
use crate::measurements::SimMeasurements;

// ── Strategy type ────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StrategyType {
    BestRoute,
    Multicast,
    Suppress,
}

impl Default for StrategyType {
    fn default() -> Self {
        StrategyType::BestRoute
    }
}

// ── Trace event types ─────────────────────────────────────────────────────────

/// The outcome tag shown on a stage in the animation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StageEvent {
    pub stage: String,
    /// One of: Continue, Satisfy, Aggregate, Forward, Nack, Drop, CsHit
    pub action: String,
    /// Stage-specific diagnostic data (faces selected, PIT count, CS occupancy, etc.)
    pub detail: serde_json::Value,
}

/// Full trace of a single packet through the pipeline.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PipelineTrace {
    pub packet_type: String, // "Interest" | "Data"
    pub name: String,
    pub stages: Vec<StageEvent>,
    pub final_action: String,
    /// Decoded fields discovered at each stage (shown as TLV tag cloud on the bubble).
    pub decoded_fields: Vec<String>,
    /// CS state snapshot *after* the packet ran.
    pub cs_after: CsSnapshot,
    /// PIT state snapshot *after* the packet ran.
    pub pit_after: PitSnapshot,
    /// FIB entries that were consulted.
    pub fib_consulted: Vec<FibEntry>,
    /// Face IDs the packet was forwarded to (empty on cache hit or drop).
    pub forwarded_to: Vec<u32>,
}

// ── Simulation configuration ─────────────────────────────────────────────────

/// Knobs controlling a single pipeline run.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PipelineConfig {
    /// Use CS even if it would contain the entry (disable = always miss).
    pub cs_enabled: bool,
    /// Number of simulated downstream faces (controls Strategy display).
    pub face_count: u32,
    /// If true, the Interest finds an existing PIT entry (aggregation demo).
    pub pit_has_entry: bool,
    /// Forwarding strategy.
    pub strategy: StrategyType,
    /// Simulated RTT in ms (adds annotation, doesn't block).
    pub simulated_rtt_ms: u32,
    /// For Data packets: whether the signature is valid.
    pub sig_valid: bool,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            cs_enabled: true,
            face_count: 2,
            pit_has_entry: false,
            strategy: StrategyType::BestRoute,
            simulated_rtt_ms: 0,
            sig_valid: true,
        }
    }
}

// ── The pipeline runner ───────────────────────────────────────────────────────

/// Holds all forwarding table state for a single simulated router.
pub struct SimPipeline {
    pub fib: SimFib,
    pub pit: SimPit,
    pub cs: SimCs,
    pub measurements: SimMeasurements,
    /// Monotonically increasing fake clock (ms).
    pub now_ms: f64,
    /// Cumulative hit count for hit-rate display.
    pub hits: u32,
    pub total: u32,
}

impl SimPipeline {
    pub fn new(cs_capacity: usize) -> Self {
        let mut fib = SimFib::new();
        // Default route on face 0 for demonstration.
        fib.add_route("/", 0, 0);
        Self {
            fib,
            pit: SimPit::new(),
            cs: SimCs::new(cs_capacity),
            measurements: SimMeasurements::new(),
            now_ms: 0.0,
            hits: 0,
            total: 0,
        }
    }

    pub fn advance_clock(&mut self, delta_ms: f64) {
        self.now_ms += delta_ms;
        self.pit.evict_expired(self.now_ms);
    }

    pub fn set_now_ms(&mut self, now_ms: f64) {
        self.now_ms = now_ms;
    }

    // ── Interest pipeline ────────────────────────────────────────────────────

    /// Run an Interest through the pipeline and return a full trace.
    pub fn process_interest(
        &mut self,
        name: &str,
        can_be_prefix: bool,
        must_be_fresh: bool,
        nonce: u32,
        lifetime_ms: f64,
        in_face: u32,
        config: &PipelineConfig,
    ) -> PipelineTrace {
        let mut stages = Vec::new();
        let mut decoded_fields = Vec::new();
        self.total += 1;

        // ── Stage 1: TlvDecode ───────────────────────────────────────────────
        decoded_fields.push("Name".to_string());
        let detail = serde_json::json!({
            "name": name,
            "wireBytes": estimate_interest_wire_size(name, lifetime_ms),
            "fields": ["Name", "CanBePrefix", "MustBeFresh", "Nonce", "InterestLifetime"]
        });
        stages.push(StageEvent { stage: "TlvDecode".to_string(), action: "Continue".to_string(), detail });
        decoded_fields.extend_from_slice(&["CanBePrefix".to_string(), "MustBeFresh".to_string(), "Nonce".to_string(), "Lifetime".to_string()]);

        // ── Stage 2: CsLookup ────────────────────────────────────────────────
        let cs_hit = config.cs_enabled
            && self.cs.lookup(name, can_be_prefix, must_be_fresh, self.now_ms).is_some();

        let cs_occupancy = self.cs.len();
        let cs_capacity = self.cs.capacity;

        if cs_hit {
            self.hits += 1;
            let hit_entry = self.cs.lookup(name, can_be_prefix, must_be_fresh, self.now_ms).unwrap().clone();
            let detail = serde_json::json!({
                "result": "HIT",
                "matchedName": hit_entry.name,
                "csOccupancy": cs_occupancy,
                "csCapacity": cs_capacity,
                "hitRate": self.hit_rate(),
            });
            stages.push(StageEvent { stage: "CsLookup".to_string(), action: "CsHit".to_string(), detail });
            decoded_fields.push("→ Satisfied from cache".to_string());

            return PipelineTrace {
                packet_type: "Interest".to_string(),
                name: name.to_string(),
                stages,
                final_action: "Satisfied".to_string(),
                decoded_fields,
                cs_after: self.cs.snapshot(),
                pit_after: self.pit.snapshot(),
                fib_consulted: vec![],
                forwarded_to: vec![],
            };
        }

        let detail = serde_json::json!({
            "result": "MISS",
            "csOccupancy": cs_occupancy,
            "csCapacity": cs_capacity,
            "hitRate": self.hit_rate(),
        });
        stages.push(StageEvent { stage: "CsLookup".to_string(), action: "Continue".to_string(), detail });

        // ── Stage 3: PitCheck ────────────────────────────────────────────────
        // Check if we should force-aggregate (scenario: pit_has_entry).
        let existing = if config.pit_has_entry {
            Some("synthetic-aggregation")
        } else {
            self.pit.match_data(name).map(|_| "existing").or(None)
        };

        // Actually try to insert.
        let (is_new, did_aggregate) = if config.pit_has_entry && !is_new_entry(&self.pit, name, can_be_prefix, must_be_fresh) {
            // Already have an entry — simulate aggregation.
            (false, true)
        } else {
            self.pit.insert(name, can_be_prefix, must_be_fresh, in_face, nonce, self.now_ms, lifetime_ms)
        };
        let _ = existing;

        let pit_count = self.pit.len();
        let action = if !is_new { "Aggregate" } else { "Continue" };
        let detail = serde_json::json!({
            "isNew": is_new,
            "aggregated": did_aggregate || !is_new,
            "pitCount": pit_count,
            "inFace": in_face,
        });
        stages.push(StageEvent { stage: "PitCheck".to_string(), action: action.to_string(), detail });

        if !is_new {
            // Interest was aggregated — do not forward.
            decoded_fields.push("→ Aggregated in PIT".to_string());
            return PipelineTrace {
                packet_type: "Interest".to_string(),
                name: name.to_string(),
                stages,
                final_action: "Aggregated".to_string(),
                decoded_fields,
                cs_after: self.cs.snapshot(),
                pit_after: self.pit.snapshot(),
                fib_consulted: vec![],
                forwarded_to: vec![],
            };
        }

        // ── Stage 4: Strategy ────────────────────────────────────────────────
        let nexthops = self.fib.lpm(name);
        let fib_entry = if nexthops.is_empty() {
            None
        } else {
            Some(crate::fib::FibEntry {
                prefix: find_matching_prefix(&self.fib, name),
                nexthops: nexthops.clone(),
            })
        };

        let forwarded_faces: Vec<u32> = match &config.strategy {
            StrategyType::Suppress => {
                let detail = serde_json::json!({
                    "strategy": "Suppress",
                    "result": "Suppressed",
                });
                stages.push(StageEvent { stage: "Strategy".to_string(), action: "Suppress".to_string(), detail });
                decoded_fields.push("→ Suppressed by strategy".to_string());
                return PipelineTrace {
                    packet_type: "Interest".to_string(),
                    name: name.to_string(),
                    stages,
                    final_action: "Suppressed".to_string(),
                    decoded_fields,
                    cs_after: self.cs.snapshot(),
                    pit_after: self.pit.snapshot(),
                    fib_consulted: fib_entry.into_iter().collect(),
                    forwarded_to: vec![],
                };
            }
            StrategyType::BestRoute => {
                if nexthops.is_empty() {
                    let detail = serde_json::json!({
                        "strategy": "BestRoute",
                        "result": "Nack/NoRoute",
                        "fibMatch": null,
                    });
                    stages.push(StageEvent { stage: "Strategy".to_string(), action: "Nack".to_string(), detail });
                    decoded_fields.push("→ Nack (NoRoute)".to_string());
                    return PipelineTrace {
                        packet_type: "Interest".to_string(),
                        name: name.to_string(),
                        stages,
                        final_action: "NackNoRoute".to_string(),
                        decoded_fields,
                        cs_after: self.cs.snapshot(),
                        pit_after: self.pit.snapshot(),
                        fib_consulted: vec![],
                        forwarded_to: vec![],
                    };
                }
                // BestRoute: pick lowest-cost face, up to face_count.
                let mut sorted = nexthops.clone();
                sorted.sort_by_key(|nh| nh.cost);
                vec![sorted[0].face_id]
            }
            StrategyType::Multicast => {
                if nexthops.is_empty() {
                    let detail = serde_json::json!({
                        "strategy": "Multicast",
                        "result": "Nack/NoRoute",
                    });
                    stages.push(StageEvent { stage: "Strategy".to_string(), action: "Nack".to_string(), detail });
                    decoded_fields.push("→ Nack (NoRoute)".to_string());
                    return PipelineTrace {
                        packet_type: "Interest".to_string(),
                        name: name.to_string(),
                        stages,
                        final_action: "NackNoRoute".to_string(),
                        decoded_fields,
                        cs_after: self.cs.snapshot(),
                        pit_after: self.pit.snapshot(),
                        fib_consulted: vec![],
                        forwarded_to: vec![],
                    };
                }
                // Multicast: send to all nexthops, up to face_count.
                let max_faces = config.face_count as usize;
                nexthops.iter().take(max_faces).map(|nh| nh.face_id).collect()
            }
        };

        let fib_consulted: Vec<FibEntry> = fib_entry.into_iter().collect();
        let detail = serde_json::json!({
            "strategy": format!("{:?}", config.strategy),
            "result": "Forward",
            "faces": forwarded_faces,
            "fibMatch": fib_consulted.first().map(|e| &e.prefix),
            "simulatedRttMs": config.simulated_rtt_ms,
        });
        stages.push(StageEvent { stage: "Strategy".to_string(), action: "Forward".to_string(), detail });
        decoded_fields.push(format!("→ Forwarded to {} face(s)", forwarded_faces.len()));

        PipelineTrace {
            packet_type: "Interest".to_string(),
            name: name.to_string(),
            stages,
            final_action: "Forwarded".to_string(),
            decoded_fields,
            cs_after: self.cs.snapshot(),
            pit_after: self.pit.snapshot(),
            fib_consulted,
            forwarded_to: forwarded_faces,
        }
    }

    // ── Data pipeline ─────────────────────────────────────────────────────────

    /// Run a Data packet through the pipeline and return a full trace.
    pub fn process_data(
        &mut self,
        name: &str,
        content: &str,
        freshness_ms: u64,
        sig_type: &str,
        config: &PipelineConfig,
    ) -> PipelineTrace {
        let mut stages = Vec::new();
        let mut decoded_fields = Vec::new();

        // ── Stage 1: TlvDecode ───────────────────────────────────────────────
        decoded_fields.push("Name".to_string());
        let detail = serde_json::json!({
            "name": name,
            "wireBytes": estimate_data_wire_size(name, content),
            "fields": ["Name", "MetaInfo", "Content", "SignatureInfo", "SignatureValue"]
        });
        stages.push(StageEvent { stage: "TlvDecode".to_string(), action: "Continue".to_string(), detail });
        decoded_fields.extend_from_slice(&["MetaInfo".to_string(), "Content".to_string(), "SignatureInfo".to_string()]);

        // ── Stage 2: PIT match ───────────────────────────────────────────────
        let matched_entries = self.pit.remove_matching(name);
        let downstream_faces: Vec<u32> = matched_entries.iter().flat_map(|e| e.in_faces()).collect();

        if matched_entries.is_empty() {
            let detail = serde_json::json!({
                "result": "Unsolicited",
                "pitCount": self.pit.len(),
            });
            stages.push(StageEvent { stage: "PitMatch".to_string(), action: "Drop".to_string(), detail });
            decoded_fields.push("→ Dropped (unsolicited)".to_string());
            return PipelineTrace {
                packet_type: "Data".to_string(),
                name: name.to_string(),
                stages,
                final_action: "DroppedUnsolicited".to_string(),
                decoded_fields,
                cs_after: self.cs.snapshot(),
                pit_after: self.pit.snapshot(),
                fib_consulted: vec![],
                forwarded_to: vec![],
            };
        }

        let detail = serde_json::json!({
            "result": "Matched",
            "matchedEntries": matched_entries.len(),
            "downstreamFaces": downstream_faces,
        });
        stages.push(StageEvent { stage: "PitMatch".to_string(), action: "Continue".to_string(), detail });

        // ── Stage 3: Validation ───────────────────────────────────────────────
        decoded_fields.push("SignatureValue".to_string());
        if !config.sig_valid {
            let detail = serde_json::json!({
                "result": "FAIL",
                "sigType": sig_type,
                "reason": "Signature verification failed (simulated)",
            });
            stages.push(StageEvent { stage: "Validation".to_string(), action: "Drop".to_string(), detail });
            decoded_fields.push("→ Dropped (invalid signature)".to_string());
            // Update measurements: unsatisfied.
            let prefix = find_matching_prefix(&self.fib, name);
            self.measurements.update_satisfaction(&prefix, false);
            return PipelineTrace {
                packet_type: "Data".to_string(),
                name: name.to_string(),
                stages,
                final_action: "DroppedInvalidSig".to_string(),
                decoded_fields,
                cs_after: self.cs.snapshot(),
                pit_after: self.pit.snapshot(),
                fib_consulted: vec![],
                forwarded_to: vec![],
            };
        }

        let detail = serde_json::json!({
            "result": "PASS",
            "sigType": sig_type,
        });
        stages.push(StageEvent { stage: "Validation".to_string(), action: "Continue".to_string(), detail });

        // ── Stage 4: CsInsert + Dispatch ─────────────────────────────────────
        let content_bytes = content.len();
        self.cs.insert(
            name.to_string(),
            content.to_string(),
            content_bytes,
            freshness_ms,
            self.now_ms,
            sig_type.to_string(),
        );

        let detail = serde_json::json!({
            "inserted": true,
            "csOccupancy": self.cs.len(),
            "csCapacity": self.cs.capacity,
            "dispatchFaces": downstream_faces,
        });
        stages.push(StageEvent { stage: "CsInsert".to_string(), action: "Satisfy".to_string(), detail });
        decoded_fields.push(format!("→ Dispatched to {} face(s)", downstream_faces.len()));

        // Update measurements.
        let prefix = find_matching_prefix(&self.fib, name);
        self.measurements.update_satisfaction(&prefix, true);

        PipelineTrace {
            packet_type: "Data".to_string(),
            name: name.to_string(),
            stages,
            final_action: "Satisfied".to_string(),
            decoded_fields,
            cs_after: self.cs.snapshot(),
            pit_after: self.pit.snapshot(),
            fib_consulted: vec![],
            forwarded_to: downstream_faces,
        }
    }

    pub fn hit_rate(&self) -> f64 {
        if self.total == 0 { 0.0 } else { self.hits as f64 / self.total as f64 }
    }

    /// Force-populate the CS with an entry (for "CS already contains this name" scenario).
    pub fn seed_cs(&mut self, name: &str, content: &str, freshness_ms: u64) {
        self.cs.insert(
            name.to_string(),
            content.to_string(),
            content.len(),
            freshness_ms,
            self.now_ms,
            "DigestSha256".to_string(),
        );
    }

    /// Force-create a PIT entry (for "PIT already has a pending entry" scenario).
    pub fn seed_pit(&mut self, name: &str, in_face: u32) {
        self.pit.insert(name, false, false, in_face, 0xDEAD, self.now_ms, 4000.0);
    }

    pub fn reset(&mut self) {
        self.pit = SimPit::new();
        self.cs = SimCs::new(self.cs.capacity);
        self.measurements = SimMeasurements::new();
        self.hits = 0;
        self.total = 0;
        self.now_ms = 0.0;
    }
}

impl Default for SimPipeline {
    fn default() -> Self {
        Self::new(100)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn is_new_entry(pit: &SimPit, name: &str, _can_be_prefix: bool, _must_be_fresh: bool) -> bool {
    // Check by looking at match_data as a proxy (we can't call get_mut on an immutable ref here easily).
    // This is a simple heuristic: if any match exists for the name, it's not new.
    pit.match_data(name).is_none()
}

/// Public version used by the topology module.
pub fn find_matching_prefix_in_fib(fib: &SimFib, name: &str) -> String {
    find_matching_prefix(fib, name)
}

fn find_matching_prefix(fib: &SimFib, name: &str) -> String {
    // Return the prefix component of LPM result.
    let nexthops = fib.lpm(name);
    if nexthops.is_empty() {
        return "/".to_string();
    }
    // Walk the name components until LPM result changes.
    let parts = crate::fib::parse_name(name);
    let mut best = "/".to_string();
    for i in 1..=parts.len() {
        let sub = crate::fib::format_name(&parts[..i]);
        if !fib.lpm(&sub).is_empty() {
            best = sub;
        }
    }
    best
}

fn estimate_interest_wire_size(name: &str, lifetime_ms: f64) -> usize {
    // Rough TLV wire size: Name components + overhead.
    let name_len: usize = name.len() + 4; // TLV type + length + components
    let overhead = 12; // CanBePrefix(3) + MustBeFresh(3) + Nonce(6) + outer TLV(4)
    let lifetime_overhead = if lifetime_ms != 4000.0 { 6 } else { 0 };
    name_len + overhead + lifetime_overhead
}

fn estimate_data_wire_size(name: &str, content: &str) -> usize {
    name.len() + content.len() + 32 + 16 // name + content + sig(32) + overhead
}
