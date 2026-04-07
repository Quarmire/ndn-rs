//! ndn-wasm: WebAssembly bindings for in-browser NDN simulation.
//!
//! Exposes two main APIs to JavaScript:
//!
//! **`WasmPipeline`** — single-node pipeline simulation used by the Pipeline view.
//! Supports Interest/Data traces with configurable knobs (CS hit, PIT aggregation,
//! strategy selection, etc.).
//!
//! **`WasmTopology`** — multi-node network topology used by the Topology view.
//! Nodes are connected by simulated links; Interest/Data routing follows the
//! same pipeline logic and emits per-hop trace events for animation.
//!
//! **`tlv_*` functions** — stateless TLV encode/decode used by the Packet Explorer.

mod cs;
mod fib;
mod measurements;
mod pipeline;
mod pit;
mod tlv;
mod topology;

use wasm_bindgen::prelude::*;

use pipeline::{PipelineConfig, SimPipeline, StrategyType};
use topology::{NodeKind, SimTopology};

// ── Initialization ────────────────────────────────────────────────────────────

/// Initialize the WASM module (sets up panic hook for better error messages).
#[wasm_bindgen(start)]
pub fn init() {
    // Panic hook can be enabled by adding `console_error_panic_hook` feature.
}

// ═══════════════════════════════════════════════════════════════════════════
// WasmPipeline — single-node pipeline simulation
// ═══════════════════════════════════════════════════════════════════════════

/// Single-node NDN pipeline simulation.
///
/// Holds FIB, PIT, and CS state for a single router. Runs Interest and Data
/// packets through the pipeline stages and returns trace events as JSON.
#[wasm_bindgen]
pub struct WasmPipeline {
    inner: SimPipeline,
    config: PipelineConfig,
}

#[wasm_bindgen]
impl WasmPipeline {
    /// Create a new pipeline with the given Content Store capacity.
    #[wasm_bindgen(constructor)]
    pub fn new(cs_capacity: usize) -> WasmPipeline {
        WasmPipeline {
            inner: SimPipeline::new(cs_capacity),
            config: PipelineConfig::default(),
        }
    }

    // ── Clock ─────────────────────────────────────────────────────────────────

    /// Advance the simulated clock by `delta_ms` milliseconds.
    /// Also evicts expired PIT entries.
    pub fn advance_clock(&mut self, delta_ms: f64) {
        self.inner.advance_clock(delta_ms);
    }

    /// Set the clock to an absolute value (e.g. `Date.now()`).
    pub fn set_now_ms(&mut self, now_ms: f64) {
        self.inner.set_now_ms(now_ms);
    }

    // ── Configuration knobs ───────────────────────────────────────────────────

    pub fn set_cs_enabled(&mut self, enabled: bool) {
        self.config.cs_enabled = enabled;
    }

    pub fn set_face_count(&mut self, count: u32) {
        self.config.face_count = count;
    }

    pub fn set_pit_has_entry(&mut self, has_entry: bool) {
        self.config.pit_has_entry = has_entry;
    }

    /// Strategy: "BestRoute" | "Multicast" | "Suppress"
    pub fn set_strategy(&mut self, strategy: &str) {
        self.config.strategy = match strategy {
            "Multicast" => StrategyType::Multicast,
            "Suppress" => StrategyType::Suppress,
            _ => StrategyType::BestRoute,
        };
    }

    pub fn set_simulated_rtt_ms(&mut self, rtt_ms: u32) {
        self.config.simulated_rtt_ms = rtt_ms;
    }

    pub fn set_sig_valid(&mut self, valid: bool) {
        self.config.sig_valid = valid;
    }

    pub fn set_cs_capacity(&mut self, capacity: usize) {
        self.inner.cs = cs::SimCs::new(capacity);
    }

    // ── FIB management ────────────────────────────────────────────────────────

    /// Add a FIB route: prefix → face_id.
    pub fn add_fib_route(&mut self, prefix: &str, face_id: u32, cost: u32) {
        self.inner.fib.add_route(prefix, face_id, cost);
    }

    /// Remove all routes for a face.
    pub fn remove_fib_face(&mut self, face_id: u32) {
        self.inner.fib.remove_face(face_id);
    }

    // ── Scenario seeding ──────────────────────────────────────────────────────

    /// Pre-populate the CS with an entry (for "CS contains this name" scenario).
    pub fn seed_cs(&mut self, name: &str, content: &str, freshness_ms: u64) {
        self.inner.seed_cs(name, content, freshness_ms);
    }

    /// Remove a CS entry.
    pub fn remove_cs_entry(&mut self, name: &str) {
        self.inner.cs.remove(name);
    }

    /// Pre-create a PIT entry (for "PIT already has a pending entry" scenario).
    pub fn seed_pit(&mut self, name: &str, in_face: u32) {
        self.inner.seed_pit(name, in_face);
    }

    // ── Pipeline execution ────────────────────────────────────────────────────

    /// Run an Interest through the pipeline. Returns a JSON-encoded `PipelineTrace`.
    ///
    /// `nonce = 0` generates a pseudorandom nonce from the clock.
    pub fn process_interest(
        &mut self,
        name: &str,
        can_be_prefix: bool,
        must_be_fresh: bool,
        nonce: u32,
        lifetime_ms: f64,
    ) -> JsValue {
        let nonce = if nonce == 0 {
            (self.inner.now_ms as u32).wrapping_mul(1664525u32).wrapping_add(1013904223u32)
        } else {
            nonce
        };
        let trace = self.inner.process_interest(
            name, can_be_prefix, must_be_fresh, nonce, lifetime_ms, 0, &self.config,
        );
        serde_wasm_bindgen::to_value(&trace).unwrap_or(JsValue::NULL)
    }

    /// Run a Data packet through the pipeline. Returns a JSON-encoded `PipelineTrace`.
    pub fn process_data(
        &mut self,
        name: &str,
        content: &str,
        freshness_ms: u64,
        sig_type: &str,
    ) -> JsValue {
        let trace = self.inner.process_data(name, content, freshness_ms, sig_type, &self.config);
        serde_wasm_bindgen::to_value(&trace).unwrap_or(JsValue::NULL)
    }

    // ── State snapshots ───────────────────────────────────────────────────────

    /// Current CS state as a JSON array of `CsEntry`.
    pub fn cs_snapshot(&self) -> JsValue {
        serde_wasm_bindgen::to_value(&self.inner.cs.snapshot()).unwrap_or(JsValue::NULL)
    }

    /// Current PIT state as a JSON array of `PitEntry`.
    pub fn pit_snapshot(&self) -> JsValue {
        serde_wasm_bindgen::to_value(&self.inner.pit.snapshot()).unwrap_or(JsValue::NULL)
    }

    /// Current FIB state as a JSON array of `FibEntry`.
    pub fn fib_snapshot(&self) -> JsValue {
        serde_wasm_bindgen::to_value(&self.inner.fib.snapshot()).unwrap_or(JsValue::NULL)
    }

    /// Current measurements state.
    pub fn measurements_snapshot(&self) -> JsValue {
        serde_wasm_bindgen::to_value(&self.inner.measurements.snapshot()).unwrap_or(JsValue::NULL)
    }

    /// CS hit rate (0.0–1.0).
    pub fn hit_rate(&self) -> f64 {
        self.inner.hit_rate()
    }

    /// CS occupancy (number of entries).
    pub fn cs_occupancy(&self) -> usize {
        self.inner.cs.len()
    }

    /// PIT entry count.
    pub fn pit_count(&self) -> usize {
        self.inner.pit.len()
    }

    // ── Reset ─────────────────────────────────────────────────────────────────

    /// Reset PIT, CS, and measurements. Keeps FIB and config.
    pub fn reset(&mut self) {
        self.inner.reset();
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// WasmTopology — multi-node topology simulation
// ═══════════════════════════════════════════════════════════════════════════

/// Multi-node NDN network topology simulation.
///
/// Nodes are added and connected by links. Interest/Data routing uses
/// the same pipeline logic as `WasmPipeline` but propagates across the
/// topology. Returns per-hop trace events for animation.
#[wasm_bindgen]
pub struct WasmTopology {
    inner: SimTopology,
}

#[wasm_bindgen]
impl WasmTopology {
    #[wasm_bindgen(constructor)]
    pub fn new() -> WasmTopology {
        WasmTopology { inner: SimTopology::new() }
    }

    // ── Node management ───────────────────────────────────────────────────────

    /// Add a Router node. Returns its node ID.
    pub fn add_router(&mut self, name: &str) -> u32 {
        self.inner.add_node(NodeKind::Router, name)
    }

    /// Add a Consumer node. Returns its node ID.
    pub fn add_consumer(&mut self, name: &str) -> u32 {
        self.inner.add_node(NodeKind::Consumer, name)
    }

    /// Add a Producer node with a served prefix. Returns its node ID.
    pub fn add_producer(&mut self, name: &str, prefix: &str) -> u32 {
        let id = self.inner.add_node(NodeKind::Producer, name);
        self.inner.set_node_served_prefix(id, prefix);
        id
    }

    /// Add an additional served prefix to a node.
    pub fn add_served_prefix(&mut self, node_id: u32, prefix: &str) {
        self.inner.set_node_served_prefix(node_id, prefix);
    }

    /// Set the forwarding strategy on a node.
    pub fn set_strategy(&mut self, node_id: u32, strategy: &str) {
        let s = match strategy {
            "Multicast" => StrategyType::Multicast,
            "Suppress" => StrategyType::Suppress,
            _ => StrategyType::BestRoute,
        };
        self.inner.set_node_strategy(node_id, s);
    }

    /// Set the CS capacity on a node.
    pub fn set_cs_capacity(&mut self, node_id: u32, capacity: usize) {
        self.inner.set_node_cs_capacity(node_id, capacity);
    }

    // ── Link management ───────────────────────────────────────────────────────

    /// Connect two nodes. Returns the link ID.
    pub fn add_link(&mut self, node_a: u32, node_b: u32, delay_ms: u32, bandwidth_bps: f64, loss_rate: f64) -> u32 {
        self.inner.add_link(node_a, node_b, delay_ms, bandwidth_bps as u64, loss_rate)
    }

    // ── FIB management ────────────────────────────────────────────────────────

    /// Add a FIB route on a node via a link.
    pub fn add_fib_route(&mut self, node_id: u32, prefix: &str, link_id: u32, cost: u32) {
        self.inner.add_fib_route(node_id, prefix, link_id, cost);
    }

    /// Auto-configure all FIB routes by doing BFS from producer nodes.
    pub fn auto_configure_fib(&mut self) {
        self.inner.auto_configure_fib();
    }

    // ── Simulation ────────────────────────────────────────────────────────────

    /// Send an Interest from `from_node` for `interest_name`.
    /// Returns a JSON-encoded `TopologyTrace` with all per-hop events.
    pub fn send_interest(&mut self, from_node: u32, interest_name: &str) -> JsValue {
        let trace = self.inner.send_interest(from_node, interest_name);
        serde_wasm_bindgen::to_value(&trace).unwrap_or(JsValue::NULL)
    }

    /// Advance the simulation clock.
    pub fn advance_clock(&mut self, delta_ms: f64) {
        self.inner.advance_clock(delta_ms);
    }

    // ── Snapshots ─────────────────────────────────────────────────────────────

    pub fn pit_snapshot(&self, node_id: u32) -> JsValue {
        serde_wasm_bindgen::to_value(&self.inner.pit_snapshot(node_id)).unwrap_or(JsValue::NULL)
    }

    pub fn cs_snapshot(&self, node_id: u32) -> JsValue {
        serde_wasm_bindgen::to_value(&self.inner.cs_snapshot(node_id)).unwrap_or(JsValue::NULL)
    }

    pub fn fib_snapshot(&self, node_id: u32) -> JsValue {
        serde_wasm_bindgen::to_value(&self.inner.fib_snapshot(node_id)).unwrap_or(JsValue::NULL)
    }

    pub fn measurements_snapshot(&self, node_id: u32) -> JsValue {
        serde_wasm_bindgen::to_value(&self.inner.measurements_snapshot(node_id)).unwrap_or(JsValue::NULL)
    }

    /// JSON array of all nodes (for topology canvas rendering).
    pub fn nodes_snapshot(&self) -> JsValue {
        serde_wasm_bindgen::to_value(&self.inner.nodes_snapshot()).unwrap_or(JsValue::NULL)
    }

    /// JSON array of all links (for topology canvas rendering).
    pub fn links_snapshot(&self) -> JsValue {
        serde_wasm_bindgen::to_value(&self.inner.links_snapshot()).unwrap_or(JsValue::NULL)
    }

    // ── Reset ─────────────────────────────────────────────────────────────────

    /// Reset all PIT/CS/measurements state while keeping nodes and links.
    pub fn reset_state(&mut self) {
        self.inner.reset_state();
    }

    /// Completely clear the topology (nodes, links, everything).
    pub fn reset_all(&mut self) {
        self.inner.reset_all();
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TLV Packet Explorer — stateless encode/decode functions
// ═══════════════════════════════════════════════════════════════════════════

/// Encode an Interest packet. Returns hex bytes string (space-separated).
#[wasm_bindgen]
pub fn tlv_encode_interest(
    name: &str,
    can_be_prefix: bool,
    must_be_fresh: bool,
    nonce: u32,
    lifetime_ms: u32,
) -> String {
    let bytes = tlv::encode_interest(name, can_be_prefix, must_be_fresh, nonce, lifetime_ms as u64);
    tlv::bytes_to_hex(&bytes)
}

/// Encode a Data packet. Returns hex bytes string (space-separated).
#[wasm_bindgen]
pub fn tlv_encode_data(name: &str, content: &str, freshness_ms: u32) -> String {
    let bytes = tlv::encode_data(name, content.as_bytes(), freshness_ms as u64);
    tlv::bytes_to_hex(&bytes)
}

/// Parse a hex string into a TLV tree. Returns JSON-encoded `Vec<TlvNode>`.
///
/// Accepts hex with or without spaces (e.g. "0507 0308 6e64 6e" or "05070308...").
#[wasm_bindgen]
pub fn tlv_parse_hex(hex: &str) -> JsValue {
    match tlv::parse_hex(hex) {
        Ok(bytes) => {
            let tree = tlv::decode_tlv_tree(&bytes);
            serde_wasm_bindgen::to_value(&tree).unwrap_or(JsValue::NULL)
        }
        Err(e) => {
            let err = serde_json::json!({ "error": e });
            serde_wasm_bindgen::to_value(&err).unwrap_or(JsValue::NULL)
        }
    }
}

/// Return a human-readable name for a TLV type code.
#[wasm_bindgen]
pub fn tlv_type_name(typ: u32) -> String {
    tlv::type_name(typ as u64).to_string()
}

// ═══════════════════════════════════════════════════════════════════════════
// Pre-built scenario loader
// ═══════════════════════════════════════════════════════════════════════════

/// Load a pre-built topology scenario by name.
///
/// Returns a JSON description of what was created so the JS can render it.
/// Scenario names: "linear", "triangle-cache", "multipath", "aggregation",
///                 "discovery", "link-failure".
#[wasm_bindgen]
pub fn load_topology_scenario(topo: &mut WasmTopology, scenario: &str) -> JsValue {
    topo.inner.reset_all();
    let desc = match scenario {
        "linear" => scenario_linear(&mut topo.inner),
        "triangle-cache" => scenario_triangle_cache(&mut topo.inner),
        "multipath" => scenario_multipath(&mut topo.inner),
        "aggregation" => scenario_aggregation(&mut topo.inner),
        _ => scenario_linear(&mut topo.inner),
    };
    serde_wasm_bindgen::to_value(&desc).unwrap_or(JsValue::NULL)
}

#[derive(serde::Serialize)]
struct ScenarioDesc {
    name: String,
    description: String,
    consumer_node: u32,
    interest_name: String,
    nodes: Vec<topology::NodeSnapshot>,
    links: Vec<topology::SimLink>,
}

fn scenario_linear(topo: &mut SimTopology) -> ScenarioDesc {
    let consumer = topo.add_node(NodeKind::Consumer, "Consumer");
    let router = topo.add_node(NodeKind::Router, "Router");
    let producer = topo.add_node(NodeKind::Producer, "Producer");
    topo.set_node_served_prefix(producer, "/ndn/data");

    let l1 = topo.add_link(consumer, router, 10, 1_000_000, 0.0);
    let l2 = topo.add_link(router, producer, 10, 1_000_000, 0.0);

    topo.add_fib_route(consumer, "/ndn", l1, 0);
    topo.add_fib_route(router, "/ndn", l2, 0);

    ScenarioDesc {
        name: "linear".to_string(),
        description: "Consumer → Router → Producer (10ms RTT per hop)".to_string(),
        consumer_node: consumer,
        interest_name: "/ndn/data/hello".to_string(),
        nodes: topo.nodes_snapshot(),
        links: topo.links_snapshot(),
    }
}

fn scenario_triangle_cache(topo: &mut SimTopology) -> ScenarioDesc {
    let consumer = topo.add_node(NodeKind::Consumer, "Consumer");
    let router = topo.add_node(NodeKind::Router, "Router");
    let producer = topo.add_node(NodeKind::Producer, "Producer");
    topo.set_node_served_prefix(producer, "/ndn/media");
    topo.set_node_cs_capacity(router, 50);

    let l1 = topo.add_link(consumer, router, 5, 10_000_000, 0.0);
    let l2 = topo.add_link(router, producer, 20, 1_000_000, 0.0);

    topo.add_fib_route(consumer, "/ndn", l1, 0);
    topo.add_fib_route(router, "/ndn", l2, 0);

    ScenarioDesc {
        name: "triangle-cache".to_string(),
        description: "Send Interest twice — first fetches from Producer, second hits Router CS".to_string(),
        consumer_node: consumer,
        interest_name: "/ndn/media/video.mp4".to_string(),
        nodes: topo.nodes_snapshot(),
        links: topo.links_snapshot(),
    }
}

fn scenario_multipath(topo: &mut SimTopology) -> ScenarioDesc {
    let consumer = topo.add_node(NodeKind::Consumer, "Consumer");
    let router = topo.add_node(NodeKind::Router, "Router");
    let producer = topo.add_node(NodeKind::Producer, "Producer");
    topo.set_node_served_prefix(producer, "/ndn/stream");
    topo.set_node_strategy(router, StrategyType::Multicast);

    let l1 = topo.add_link(consumer, router, 5, 100_000_000, 0.0);
    let l2 = topo.add_link(router, producer, 10, 1_000_000, 0.0);
    // Second path (same producer for demo).
    let _l3 = topo.add_link(router, producer, 15, 512_000, 0.0);

    topo.add_fib_route(consumer, "/ndn", l1, 0);
    topo.add_fib_route(router, "/ndn", l2, 0);
    // Multicast also sends on l3.

    ScenarioDesc {
        name: "multipath".to_string(),
        description: "Router uses Multicast strategy — Interest forwarded on all nexthops".to_string(),
        consumer_node: consumer,
        interest_name: "/ndn/stream/live".to_string(),
        nodes: topo.nodes_snapshot(),
        links: topo.links_snapshot(),
    }
}

fn scenario_aggregation(topo: &mut SimTopology) -> ScenarioDesc {
    let consumer1 = topo.add_node(NodeKind::Consumer, "Consumer-1");
    let consumer2 = topo.add_node(NodeKind::Consumer, "Consumer-2");
    let router = topo.add_node(NodeKind::Router, "Router");
    let producer = topo.add_node(NodeKind::Producer, "Producer");
    topo.set_node_served_prefix(producer, "/ndn/shared");

    let l1 = topo.add_link(consumer1, router, 5, 10_000_000, 0.0);
    let l2 = topo.add_link(consumer2, router, 5, 10_000_000, 0.0);
    let l3 = topo.add_link(router, producer, 20, 1_000_000, 0.0);

    topo.add_fib_route(consumer1, "/ndn", l1, 0);
    topo.add_fib_route(consumer2, "/ndn", l2, 0);
    topo.add_fib_route(router, "/ndn", l3, 0);

    ScenarioDesc {
        name: "aggregation".to_string(),
        description: "Send same Interest from Consumer-1 then Consumer-2 — second collapses in Router PIT".to_string(),
        consumer_node: consumer1,
        interest_name: "/ndn/shared/data".to_string(),
        nodes: topo.nodes_snapshot(),
        links: topo.links_snapshot(),
    }
}
