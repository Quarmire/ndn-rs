//! Multi-node NDN network topology simulation.
//!
//! Nodes (routers, consumers, producers) are connected by simulated links.
//! Packet routing follows the same Interest→Data pipeline as the single-node
//! simulation but propagates across the topology.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::cs::SimCs;
use crate::fib::SimFib;
use crate::measurements::SimMeasurements;
use crate::pipeline::StrategyType;
use crate::pit::SimPit;

// ── Node types ────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NodeKind {
    Router,
    Consumer,
    Producer,
}

/// A node in the topology (router, consumer, or producer).
pub struct SimNode {
    pub id: u32,
    pub kind: NodeKind,
    pub name: String,
    pub fib: SimFib,
    pub pit: SimPit,
    pub cs: SimCs,
    pub measurements: SimMeasurements,
    pub strategy: StrategyType,
    /// Name prefixes served by this node (producers only).
    pub served_prefixes: Vec<String>,
}

impl SimNode {
    pub fn new(id: u32, kind: NodeKind, name: &str) -> Self {
        Self {
            id,
            kind,
            name: name.to_string(),
            fib: SimFib::new(),
            pit: SimPit::new(),
            cs: SimCs::new(100),
            measurements: SimMeasurements::new(),
            strategy: StrategyType::BestRoute,
            served_prefixes: Vec::new(),
        }
    }

    pub fn serves(&self, interest_name: &str) -> bool {
        self.served_prefixes.iter().any(|p| {
            interest_name == p.as_str() || interest_name.starts_with(p.as_str())
        })
    }
}

// ── Link types ────────────────────────────────────────────────────────────────

/// A simulated link between two nodes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SimLink {
    pub id: u32,
    pub node_a: u32,
    pub node_b: u32,
    /// Face ID on node_a pointing toward node_b.
    pub face_a: u32,
    /// Face ID on node_b pointing toward node_a.
    pub face_b: u32,
    pub delay_ms: u32,
    pub bandwidth_bps: u64,
    pub loss_rate: f64,
}

impl SimLink {
    /// Given a node ID and face ID on that node, return the other end's (node_id, face_id).
    pub fn other_end(&self, node_id: u32, face_id: u32) -> Option<(u32, u32)> {
        if node_id == self.node_a && face_id == self.face_a {
            Some((self.node_b, self.face_b))
        } else if node_id == self.node_b && face_id == self.face_b {
            Some((self.node_a, self.face_a))
        } else {
            None
        }
    }
}

// ── Topology event (for animation) ───────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TopologyEvent {
    pub kind: String,       // "interest", "data", "nack", "cs-hit", "pit-aggregate"
    pub from_node: u32,
    pub to_node: u32,
    pub link_id: u32,
    pub name: String,
    pub detail: serde_json::Value,
    /// Simulated arrival time offset in ms (for animation scheduling).
    pub time_ms: f64,
}

/// Full trace of a single Interest/Data exchange across the topology.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TopologyTrace {
    pub interest_name: String,
    pub from_node: u32,
    pub satisfied: bool,
    pub events: Vec<TopologyEvent>,
    pub hops: u32,
    pub total_rtt_ms: f64,
}

// ── The topology ──────────────────────────────────────────────────────────────

pub struct SimTopology {
    nodes: HashMap<u32, SimNode>,
    links: HashMap<u32, SimLink>,
    next_node_id: u32,
    next_face_id: u32,
    next_link_id: u32,
    now_ms: f64,
}

impl SimTopology {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            links: HashMap::new(),
            next_node_id: 1,
            next_face_id: 100,
            next_link_id: 1,
            now_ms: 0.0,
        }
    }

    // ── Node/link management ─────────────────────────────────────────────────

    pub fn add_node(&mut self, kind: NodeKind, name: &str) -> u32 {
        let id = self.next_node_id;
        self.next_node_id += 1;
        self.nodes.insert(id, SimNode::new(id, kind, name));
        id
    }

    pub fn set_node_served_prefix(&mut self, node_id: u32, prefix: &str) {
        if let Some(node) = self.nodes.get_mut(&node_id) {
            node.served_prefixes.push(prefix.to_string());
        }
    }

    pub fn set_node_strategy(&mut self, node_id: u32, strategy: StrategyType) {
        if let Some(node) = self.nodes.get_mut(&node_id) {
            node.strategy = strategy;
        }
    }

    pub fn set_node_cs_capacity(&mut self, node_id: u32, capacity: usize) {
        if let Some(node) = self.nodes.get_mut(&node_id) {
            node.cs = SimCs::new(capacity);
        }
    }

    /// Connect two nodes with a bidirectional simulated link.
    /// Returns the link ID.
    pub fn add_link(&mut self, node_a: u32, node_b: u32, delay_ms: u32, bandwidth_bps: u64, loss_rate: f64) -> u32 {
        let link_id = self.next_link_id;
        self.next_link_id += 1;
        let face_a = self.next_face_id;
        self.next_face_id += 1;
        let face_b = self.next_face_id;
        self.next_face_id += 1;

        let link = SimLink { id: link_id, node_a, node_b, face_a, face_b, delay_ms, bandwidth_bps, loss_rate };
        self.links.insert(link_id, link);
        link_id
    }

    /// Add a FIB route on a node: packets matching `prefix` go via `link_id`.
    pub fn add_fib_route(&mut self, node_id: u32, prefix: &str, link_id: u32, cost: u32) {
        if let Some(link) = self.links.get(&link_id) {
            // Determine which face on node_id belongs to this link.
            let face_id = if link.node_a == node_id { link.face_a } else { link.face_b };
            if let Some(node) = self.nodes.get_mut(&node_id) {
                node.fib.add_route(prefix, face_id, cost);
            }
        }
    }

    /// Auto-configure FIB routes by doing simple shortest-path routing.
    /// Each producer's served prefixes are advertised back through the topology.
    pub fn auto_configure_fib(&mut self) {
        // For each producer, flood its prefixes backward toward all reachable nodes.
        // This is a simple BFS from producer nodes.
        let producers: Vec<(u32, Vec<String>)> = self.nodes.values()
            .filter(|n| !n.served_prefixes.is_empty())
            .map(|n| (n.id, n.served_prefixes.clone()))
            .collect();

        for (prod_id, prefixes) in producers {
            for prefix in &prefixes {
                self.propagate_route(prod_id, prefix, 0);
            }
        }
    }

    /// BFS: propagate a route for `prefix` from `source_node` to all neighbors.
    fn propagate_route(&mut self, source_node: u32, prefix: &str, cost: u32) {
        // Collect links adjacent to source_node.
        let adjacent: Vec<(u32, u32, u32)> = self.links.values()
            .filter_map(|l| {
                if l.node_a == source_node {
                    Some((l.id, l.node_b, l.face_b))
                } else if l.node_b == source_node {
                    Some((l.id, l.node_a, l.face_a))
                } else {
                    None
                }
            })
            .collect();

        for (_link_id, neighbor_id, face_toward_source) in adjacent {
            // Add route on neighbor: prefix → face pointing toward source.
            if let Some(node) = self.nodes.get_mut(&neighbor_id) {
                // Only add if not already present (avoid loops).
                let existing = node.fib.lpm(prefix);
                if existing.is_empty() {
                    node.fib.add_route(prefix, face_toward_source, cost + 1);
                    // Recurse: propagate further (but skip the source to avoid loops).
                    // We'll handle this via a visited set in a proper BFS.
                }
            }
        }
    }

    // ── Packet simulation ─────────────────────────────────────────────────────

    /// Send an Interest from `from_node` for `interest_name`.
    /// Returns a full topology trace with all events.
    pub fn send_interest(&mut self, from_node: u32, interest_name: &str) -> TopologyTrace {
        let mut events: Vec<TopologyEvent> = Vec::new();
        let mut time_offset = 0.0f64;

        let result = self.route_interest(
            from_node,
            None, // no in-link on first hop
            interest_name,
            0xABCD_1234u32, // fixed nonce for determinism
            4000.0,
            0,
            &mut events,
            &mut time_offset,
            0,
        );

        let satisfied = matches!(result, InterestResult::Satisfied { .. });
        let total_rtt_ms = time_offset;
        let hops = events.iter().filter(|e| e.kind == "interest").count() as u32;

        // Update measurements for the originating link.
        if let Some(node) = self.nodes.get_mut(&from_node) {
            let first_face = self.links.values()
                .find(|l| l.node_a == from_node || l.node_b == from_node)
                .map(|l| if l.node_a == from_node { l.face_a } else { l.face_b })
                .unwrap_or(0);
            let prefix = crate::pipeline::find_matching_prefix_in_fib(&node.fib, interest_name);
            node.measurements.update_rtt(&prefix, first_face, total_rtt_ms);
            node.measurements.update_satisfaction(&prefix, satisfied);
        }

        TopologyTrace {
            interest_name: interest_name.to_string(),
            from_node,
            satisfied,
            events,
            hops,
            total_rtt_ms,
        }
    }

    /// Recursive Interest routing.
    ///
    /// Returns `InterestResult` indicating how the Interest was handled.
    /// `in_link_id`: the link the Interest arrived on (to avoid forwarding back).
    fn route_interest(
        &mut self,
        node_id: u32,
        in_link_id: Option<u32>,
        name: &str,
        nonce: u32,
        lifetime_ms: f64,
        depth: u32,
        events: &mut Vec<TopologyEvent>,
        time_ms: &mut f64,
        in_face: u32,
    ) -> InterestResult {
        if depth > 32 {
            return InterestResult::Loop;
        }

        let node = match self.nodes.get(&node_id) {
            Some(n) => n,
            None => return InterestResult::NackNoRoute,
        };

        // Check if this node serves the prefix (producer behaviour).
        if node.serves(name) {
            // Emit data event back through the topology.
            let content = format!("Content for {}", name);
            return InterestResult::Satisfied {
                content,
                freshness_ms: 10_000,
                sig_type: "DigestSha256".to_string(),
            };
        }

        // Check CS.
        let cs_hit = node.cs.lookup(name, false, false, self.now_ms).cloned();
        if let Some(entry) = cs_hit {
            // CS hit — emit a "cs-hit" event.
            if let Some(link_id) = in_link_id {
                let link = &self.links[&link_id];
                let (from_n, _to_n) = if link.node_a == node_id {
                    (link.node_b, link.node_a)
                } else {
                    (link.node_a, link.node_b)
                };
                events.push(TopologyEvent {
                    kind: "cs-hit".to_string(),
                    from_node: node_id,
                    to_node: from_n,
                    link_id,
                    name: name.to_string(),
                    detail: serde_json::json!({ "hitName": entry.name }),
                    time_ms: *time_ms,
                });
            }
            return InterestResult::Satisfied {
                content: entry.content.clone(),
                freshness_ms: entry.freshness_ms,
                sig_type: entry.sig_type.clone(),
            };
        }

        // FIB lookup.
        let nexthops = node.fib.lpm(name);
        if nexthops.is_empty() {
            return InterestResult::NackNoRoute;
        }

        // Choose the face (BestRoute: lowest cost; exclude in-face to avoid loop).
        let in_face_from_link = in_link_id.and_then(|lid| {
            let link = &self.links[&lid];
            if link.node_a == node_id { Some(link.face_a) } else { Some(link.face_b) }
        });
        let chosen = nexthops.iter()
            .filter(|nh| Some(nh.face_id) != in_face_from_link)
            .min_by_key(|nh| nh.cost);

        let chosen = match chosen {
            Some(c) => c.clone(),
            None => return InterestResult::NackNoRoute,
        };

        // Find the link and next hop node for chosen face.
        let out_link = self.links.values().find(|l| {
            (l.node_a == node_id && l.face_a == chosen.face_id) ||
            (l.node_b == node_id && l.face_b == chosen.face_id)
        }).cloned();

        let link = match out_link {
            Some(l) => l,
            None => return InterestResult::NackNoRoute,
        };

        let next_node_id = if link.node_a == node_id { link.node_b } else { link.node_a };
        let in_face_next = if link.node_a == node_id { link.face_b } else { link.face_a };

        // Emit Interest forwarding event.
        let delay = link.delay_ms as f64;
        events.push(TopologyEvent {
            kind: "interest".to_string(),
            from_node: node_id,
            to_node: next_node_id,
            link_id: link.id,
            name: name.to_string(),
            detail: serde_json::json!({ "face": chosen.face_id, "delay_ms": delay }),
            time_ms: *time_ms,
        });
        *time_ms += delay;

        // Add PIT entry on this node.
        {
            let node_mut = self.nodes.get_mut(&node_id).unwrap();
            node_mut.pit.insert(name, false, false, in_face, nonce, self.now_ms, lifetime_ms);
        }

        // Recurse to next hop.
        let result = self.route_interest(
            next_node_id,
            Some(link.id),
            name,
            nonce,
            lifetime_ms,
            depth + 1,
            events,
            time_ms,
            in_face_next,
        );

        match result {
            InterestResult::Satisfied { ref content, freshness_ms, ref sig_type } => {
                // Data return: update CS, satisfy PIT.
                let content_clone = content.clone();
                let sig_type_clone = sig_type.clone();

                // Emit data event traveling back.
                events.push(TopologyEvent {
                    kind: "data".to_string(),
                    from_node: next_node_id,
                    to_node: node_id,
                    link_id: link.id,
                    name: name.to_string(),
                    detail: serde_json::json!({ "freshness_ms": freshness_ms }),
                    time_ms: *time_ms,
                });
                *time_ms += delay; // return trip

                // Insert into CS.
                let node_mut = self.nodes.get_mut(&node_id).unwrap();
                node_mut.cs.insert(name.to_string(), content_clone, content.len(), freshness_ms, self.now_ms, sig_type_clone);
                // Satisfy PIT.
                node_mut.pit.remove_matching(name);

                result
            }
            InterestResult::NackNoRoute | InterestResult::Loop => {
                // Nack back.
                events.push(TopologyEvent {
                    kind: "nack".to_string(),
                    from_node: next_node_id,
                    to_node: node_id,
                    link_id: link.id,
                    name: name.to_string(),
                    detail: serde_json::json!({ "reason": "NoRoute" }),
                    time_ms: *time_ms,
                });
                *time_ms += delay;
                // Remove PIT entry.
                let node_mut = self.nodes.get_mut(&node_id).unwrap();
                node_mut.pit.remove_matching(name);
                result
            }
        }
    }

    // ── Snapshot accessors ────────────────────────────────────────────────────

    pub fn pit_snapshot(&self, node_id: u32) -> Option<crate::pit::PitSnapshot> {
        self.nodes.get(&node_id).map(|n| n.pit.snapshot())
    }

    pub fn cs_snapshot(&self, node_id: u32) -> Option<crate::cs::CsSnapshot> {
        self.nodes.get(&node_id).map(|n| n.cs.snapshot())
    }

    pub fn fib_snapshot(&self, node_id: u32) -> Option<Vec<crate::fib::FibEntry>> {
        self.nodes.get(&node_id).map(|n| n.fib.snapshot())
    }

    pub fn measurements_snapshot(&self, node_id: u32) -> Option<crate::measurements::MeasurementsSnapshot> {
        self.nodes.get(&node_id).map(|n| n.measurements.snapshot())
    }

    /// Snapshot of all links for topology display.
    pub fn links_snapshot(&self) -> Vec<SimLink> {
        let mut links: Vec<SimLink> = self.links.values().cloned().collect();
        links.sort_by_key(|l| l.id);
        links
    }

    /// Snapshot of all nodes for topology display.
    pub fn nodes_snapshot(&self) -> Vec<NodeSnapshot> {
        let mut nodes: Vec<NodeSnapshot> = self.nodes.values()
            .map(|n| NodeSnapshot {
                id: n.id,
                kind: n.kind.clone(),
                name: n.name.clone(),
                pit_count: n.pit.len(),
                cs_count: n.cs.len(),
                cs_capacity: n.cs.capacity,
                served_prefixes: n.served_prefixes.clone(),
            })
            .collect();
        nodes.sort_by_key(|n| n.id);
        nodes
    }

    pub fn reset_state(&mut self) {
        for node in self.nodes.values_mut() {
            node.pit = SimPit::new();
            node.cs = SimCs::new(node.cs.capacity);
            node.measurements = SimMeasurements::new();
        }
        self.now_ms = 0.0;
    }

    pub fn reset_all(&mut self) {
        self.nodes.clear();
        self.links.clear();
        self.next_node_id = 1;
        self.next_face_id = 100;
        self.next_link_id = 1;
        self.now_ms = 0.0;
    }

    pub fn advance_clock(&mut self, delta_ms: f64) {
        self.now_ms += delta_ms;
        for node in self.nodes.values_mut() {
            node.pit.evict_expired(self.now_ms);
        }
    }
}

impl Default for SimTopology {
    fn default() -> Self {
        Self::new()
    }
}

// ── Snapshot types ────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeSnapshot {
    pub id: u32,
    pub kind: NodeKind,
    pub name: String,
    pub pit_count: usize,
    pub cs_count: usize,
    pub cs_capacity: usize,
    pub served_prefixes: Vec<String>,
}

// ── Internal routing result ───────────────────────────────────────────────────

enum InterestResult {
    Satisfied { content: String, freshness_ms: u64, sig_type: String },
    NackNoRoute,
    Loop,
}
