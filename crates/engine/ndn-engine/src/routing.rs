use std::sync::Arc;

use dashmap::DashMap;
use ndn_discovery::NeighborTable;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use ndn_transport::FaceTable;

use crate::{Fib, Rib};

pub struct RoutingHandle {
    pub rib: Arc<Rib>,
    pub fib: Arc<Fib>,
    pub faces: Arc<FaceTable>,
    pub neighbors: Arc<NeighborTable>,
}

/// A routing protocol that manages routes in the RIB.
///
/// Each protocol registers routes under a distinct `origin` value. Multiple
/// protocols run concurrently; the RIB computes the best nexthops across all
/// origins when building FIB entries.
pub trait RoutingProtocol: Send + Sync + 'static {
    /// Route origin value (must be unique per instance).
    /// Standard values in `ndn_config::control_parameters::origin`.
    fn origin(&self) -> u64;

    /// Start the protocol. Runs until `cancel` is cancelled.
    fn start(&self, handle: RoutingHandle, cancel: CancellationToken) -> JoinHandle<()>;
}

struct ProtocolHandle {
    cancel: CancellationToken,
    _task: JoinHandle<()>,
}

/// Manages a set of concurrently-running routing protocols.
pub struct RoutingManager {
    rib: Arc<Rib>,
    fib: Arc<Fib>,
    faces: Arc<FaceTable>,
    neighbors: Arc<NeighborTable>,
    handles: DashMap<u64, ProtocolHandle>,
    engine_cancel: CancellationToken,
}

impl RoutingManager {
    pub fn new(
        rib: Arc<Rib>,
        fib: Arc<Fib>,
        faces: Arc<FaceTable>,
        neighbors: Arc<NeighborTable>,
        engine_cancel: CancellationToken,
    ) -> Self {
        Self {
            rib,
            fib,
            faces,
            neighbors,
            handles: DashMap::new(),
            engine_cancel,
        }
    }

    pub fn enable(&self, proto: Arc<dyn RoutingProtocol>) {
        let origin = proto.origin();
        if self.handles.contains_key(&origin) {
            self.stop_and_flush(origin);
        }
        let cancel = self.engine_cancel.child_token();
        let handle = RoutingHandle {
            rib: Arc::clone(&self.rib),
            fib: Arc::clone(&self.fib),
            faces: Arc::clone(&self.faces),
            neighbors: Arc::clone(&self.neighbors),
        };
        let task = proto.start(handle, cancel.clone());
        self.handles.insert(
            origin,
            ProtocolHandle {
                cancel,
                _task: task,
            },
        );
        tracing::info!(origin, "routing protocol enabled");
    }

    pub fn disable(&self, origin: u64) -> bool {
        if self.handles.contains_key(&origin) {
            self.stop_and_flush(origin);
            tracing::info!(origin, "routing protocol disabled");
            true
        } else {
            false
        }
    }

    pub fn running_origins(&self) -> Vec<u64> {
        self.handles.iter().map(|e| *e.key()).collect()
    }

    pub fn running_count(&self) -> usize {
        self.handles.len()
    }

    fn stop_and_flush(&self, origin: u64) {
        if let Some((_, handle)) = self.handles.remove(&origin) {
            handle.cancel.cancel();
        }
        let affected = self.rib.flush_origin(origin);
        let n = affected.len();
        for prefix in &affected {
            self.rib.apply_to_fib(prefix, &self.fib);
        }
        if n > 0 {
            tracing::debug!(origin, prefixes = n, "RIB flushed for origin");
        }
    }
}

impl Drop for RoutingManager {
    fn drop(&mut self) {
        for entry in self.handles.iter() {
            entry.value().cancel.cancel();
        }
    }
}
