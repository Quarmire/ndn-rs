//! Single entry point for installing protocols (routing, discovery, mgmt
//! extensions) on the engine: each implements
//! [`InstallableProtocol::install`], which allocates faces, registers on
//! the engine's slots, and queues post-`build()` work via [`PostBuildQueue`].
//!
//! ```ignore
//! let mut builder = EngineBuilder::new(cfg);
//! let mut post = PostBuildQueue::new();
//! for protocol in enabled_protocols(&cfg) {
//!     protocol.install(&mut builder, &mut post);
//! }
//! let (engine, shutdown) = builder.build().await?;
//! post.apply(&engine, &cancel);
//! ```

use std::sync::Arc;

use ndn_packet::Name;
use ndn_transport::FaceId;
use tokio_util::sync::CancellationToken;

use crate::{EngineBuilder, ForwarderEngine};

/// A protocol that can be installed on an [`EngineBuilder`]. Implementers
/// are typically routing protocols, discovery protocols, or mgmt-extension
/// protocols (demo CA, NDNCERT issuer).
pub trait InstallableProtocol: Send + Sync + 'static {
    fn install(self: Arc<Self>, builder: &mut EngineBuilder, post_build: &mut PostBuildQueue);
}

type DeferredFn = Box<dyn FnOnce(&ForwarderEngine, &CancellationToken) + Send>;

enum PostBuildAction {
    AddFibEntry {
        prefix: Name,
        face_id: FaceId,
        cost: u32,
    },
    SeedNeighbor {
        peer: Name,
        face_id: FaceId,
    },
    Defer(DeferredFn),
}

/// Actions queued during `install()` and applied by the host after
/// [`EngineBuilder::build`] returns the live engine.
#[derive(Default)]
pub struct PostBuildQueue {
    actions: Vec<PostBuildAction>,
}

impl PostBuildQueue {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_fib_entry(&mut self, prefix: Name, face_id: FaceId, cost: u32) {
        self.actions.push(PostBuildAction::AddFibEntry {
            prefix,
            face_id,
            cost,
        });
    }

    /// Pre-seed the engine's neighbour table with a known peer reachable
    /// via `face_id`, in the `Established` state.
    pub fn seed_neighbor(&mut self, peer: Name, face_id: FaceId) {
        self.actions
            .push(PostBuildAction::SeedNeighbor { peer, face_id });
    }

    /// Defer arbitrary post-build work (e.g. spawning a `Producer::serve`
    /// task). The closure receives the live engine and the global cancel.
    pub fn defer<F>(&mut self, f: F)
    where
        F: FnOnce(&ForwarderEngine, &CancellationToken) + Send + 'static,
    {
        self.actions.push(PostBuildAction::Defer(Box::new(f)));
    }

    /// Apply every queued action against the live engine.
    pub fn apply(self, engine: &ForwarderEngine, cancel: &CancellationToken) {
        use ndn_discovery_core::{NeighborContext, NeighborUpdate};
        for action in self.actions {
            match action {
                PostBuildAction::AddFibEntry {
                    prefix,
                    face_id,
                    cost,
                } => {
                    engine.fib().add_nexthop(&prefix, face_id, cost);
                }
                PostBuildAction::SeedNeighbor { peer, face_id } => {
                    let mut entry = ndn_discovery_core::neighbor::NeighborEntry::new(peer);
                    entry.state = ndn_discovery_core::neighbor::NeighborState::Established {
                        last_seen: std::time::Instant::now(),
                    };
                    entry.faces.push((
                        face_id,
                        ndn_discovery_core::MacAddr::new([0; 6]),
                        String::new(),
                    ));
                    engine
                        .discovery_ctx()
                        .update_neighbor(NeighborUpdate::Upsert(entry));
                }
                PostBuildAction::Defer(f) => f(engine, cancel),
            }
        }
    }
}
