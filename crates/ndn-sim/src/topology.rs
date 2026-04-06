//! `Simulation` — multi-node topology builder for in-process NDN simulations.
//!
//! Provides a high-level API for constructing networks of NDN forwarders
//! connected by [`SimLink`](crate::SimLink)s, starting them, and managing
//! their lifecycle.
//!
//! # Example
//!
//! ```rust,no_run
//! use ndn_sim::{Simulation, LinkConfig};
//! use ndn_engine::builder::EngineConfig;
//!
//! # async fn example() -> anyhow::Result<()> {
//! let mut sim = Simulation::new();
//!
//! let n1 = sim.add_node(EngineConfig::default());
//! let n2 = sim.add_node(EngineConfig::default());
//! let n3 = sim.add_node(EngineConfig::default());
//!
//! sim.link(n1, n2, LinkConfig::lan());
//! sim.link(n2, n3, LinkConfig::wifi());
//!
//! let mut running = sim.start().await?;
//!
//! running.add_route(n1, "/ndn/test", n2)?;
//! running.add_route(n2, "/ndn/test", n3)?;
//!
//! // ... run experiment ...
//!
//! running.shutdown().await;
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::str::FromStr;

use anyhow::{Result, bail};
use ndn_engine::ForwarderEngine;
use ndn_engine::builder::{EngineBuilder, EngineConfig};
use ndn_engine::engine::ShutdownHandle;
use ndn_packet::Name;
use ndn_transport::FaceId;
use tracing::info;

use crate::sim_link::{LinkConfig, SimLink};

/// Opaque handle to a node in the simulation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NodeId(pub usize);

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "node#{}", self.0)
    }
}

/// A pending link to be created when the simulation starts.
struct PendingLink {
    a: NodeId,
    b: NodeId,
    config: LinkConfig,
}

/// A pending FIB route to be installed when the simulation starts.
struct PendingRoute {
    node: NodeId,
    prefix: Name,
    nexthop_node: NodeId,
}

/// Builder for a multi-node simulation topology.
///
/// Nodes and links are registered, then [`start`](Self::start) instantiates
/// all engines, creates SimFaces, installs routes, and returns a
/// [`RunningSimulation`] handle.
pub struct Simulation {
    nodes: Vec<EngineConfig>,
    links: Vec<PendingLink>,
    routes: Vec<PendingRoute>,
    channel_buffer: usize,
}

impl Default for Simulation {
    fn default() -> Self {
        Self::new()
    }
}

impl Simulation {
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            links: Vec::new(),
            routes: Vec::new(),
            channel_buffer: 256,
        }
    }

    /// Set the channel buffer size for SimLinks (default: 256).
    pub fn channel_buffer(mut self, size: usize) -> Self {
        self.channel_buffer = size;
        self
    }

    /// Add a forwarding node and return its handle.
    pub fn add_node(&mut self, config: EngineConfig) -> NodeId {
        let id = NodeId(self.nodes.len());
        self.nodes.push(config);
        id
    }

    /// Connect two nodes with a symmetric link.
    pub fn link(&mut self, a: NodeId, b: NodeId, config: LinkConfig) {
        self.links.push(PendingLink { a, b, config });
    }

    /// Pre-install a FIB route: packets for `prefix` at `node` are forwarded
    /// toward `nexthop_node` (via the SimLink face connecting them).
    pub fn add_route(&mut self, node: NodeId, prefix: &str, nexthop_node: NodeId) {
        self.routes.push(PendingRoute {
            node,
            prefix: Name::from_str(prefix).expect("valid NDN name"),
            nexthop_node,
        });
    }

    /// Instantiate all engines, create links, install routes, and start.
    pub async fn start(self) -> Result<RunningSimulation> {
        let n = self.nodes.len();
        info!(nodes = n, links = self.links.len(), "Simulation: starting");

        // Build all engines.
        let mut engines = Vec::with_capacity(n);
        let mut handles = Vec::with_capacity(n);
        for config in self.nodes {
            let (engine, handle) = EngineBuilder::new(config).build().await?;
            engines.push(engine);
            handles.push(handle);
        }

        // Create SimLinks and add faces to engines.
        // Track which FaceId connects node A to node B, for route installation.
        // Key: (from_node, to_node) -> FaceId at from_node
        let mut face_map: HashMap<(NodeId, NodeId), FaceId> = HashMap::new();

        for link in &self.links {
            let a = link.a.0;
            let b = link.b.0;
            if a >= n || b >= n {
                bail!("link references non-existent node");
            }

            let id_a = engines[a].faces().alloc_id();
            let id_b = engines[b].faces().alloc_id();

            let (face_a, face_b) =
                SimLink::pair(id_a, id_b, link.config.clone(), self.channel_buffer);

            let cancel_a = handles[a].cancel_token();
            let cancel_b = handles[b].cancel_token();
            engines[a].add_face(face_a, cancel_a);
            engines[b].add_face(face_b, cancel_b);

            face_map.insert((link.a, link.b), id_a);
            face_map.insert((link.b, link.a), id_b);

            info!(
                node_a = a, face_a = %id_a,
                node_b = b, face_b = %id_b,
                "Simulation: link created"
            );
        }

        // Install FIB routes.
        for route in &self.routes {
            let face_id = face_map.get(&(route.node, route.nexthop_node));
            if let Some(&fid) = face_id {
                engines[route.node.0]
                    .fib()
                    .add_nexthop(&route.prefix, fid, 10);
                info!(
                    node = route.node.0, prefix = %route.prefix, face = %fid,
                    "Simulation: route installed"
                );
            } else {
                bail!(
                    "no link between {} and {} for route {}",
                    route.node,
                    route.nexthop_node,
                    route.prefix
                );
            }
        }

        Ok(RunningSimulation {
            engines,
            handles,
            face_map,
        })
    }
}

/// A running simulation with all engines active.
pub struct RunningSimulation {
    engines: Vec<ForwarderEngine>,
    handles: Vec<ShutdownHandle>,
    face_map: HashMap<(NodeId, NodeId), FaceId>,
}

impl RunningSimulation {
    /// Get the engine for a node.
    pub fn engine(&self, node: NodeId) -> &ForwarderEngine {
        &self.engines[node.0]
    }

    /// Get all engines.
    pub fn engines(&self) -> &[ForwarderEngine] {
        &self.engines
    }

    /// Number of nodes in the simulation.
    pub fn node_count(&self) -> usize {
        self.engines.len()
    }

    /// Add a FIB route at runtime.
    pub fn add_route(&self, node: NodeId, prefix: &str, nexthop: NodeId) -> Result<()> {
        let face_id = self
            .face_map
            .get(&(node, nexthop))
            .ok_or_else(|| anyhow::anyhow!("no link between {node} and {nexthop}"))?;
        let name = Name::from_str(prefix).expect("valid NDN name");
        self.engines[node.0].fib().add_nexthop(&name, *face_id, 10);
        Ok(())
    }

    /// Get the FaceId connecting `from` to `to`.
    pub fn face_between(&self, from: NodeId, to: NodeId) -> Option<FaceId> {
        self.face_map.get(&(from, to)).copied()
    }

    /// Shut down all engines.
    pub async fn shutdown(self) {
        for handle in self.handles {
            handle.shutdown().await;
        }
    }
}
