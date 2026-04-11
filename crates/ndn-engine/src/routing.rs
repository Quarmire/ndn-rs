use std::sync::Arc;

use dashmap::DashMap;
use ndn_discovery::NeighborTable;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use ndn_transport::FaceTable;

use crate::{Fib, Rib};

/// Engine handles passed to a routing protocol when it starts.
///
/// Bundles the shared tables a routing protocol needs to install routes and
/// query forwarding state. Passed by value to [`RoutingProtocol::start`].
pub struct RoutingHandle {
    /// Routing Information Base — the protocol writes routes here via
    /// `rib.add()` / `rib.remove()` and calls `rib.apply_to_fib()` to push
    /// updates into the FIB.
    pub rib: Arc<Rib>,
    /// Forwarding Information Base — needed for `rib.apply_to_fib()` calls.
    pub fib: Arc<Fib>,
    /// Face table — read to enumerate active faces (e.g. to broadcast updates).
    pub faces: Arc<FaceTable>,
    /// Neighbor table — read-only view of discovered peers and their faces.
    pub neighbors: Arc<NeighborTable>,
}

/// A routing protocol that manages routes in the RIB.
///
/// Implementations run as Tokio background tasks. Each protocol registers
/// routes under a distinct [`origin`] value, which the RIB uses to namespace
/// them. Multiple protocols run concurrently; the RIB computes the best
/// nexthops across all origins when building FIB entries.
///
/// # Object safety
///
/// The trait is object-safe. [`start`] takes `&self` — implementations clone
/// their internal state (typically held in an `Arc<Inner>`) to move into the
/// spawned task.
///
/// # Example
///
/// ```rust,ignore
/// struct MyProtocol { inner: Arc<MyState> }
///
/// impl RoutingProtocol for MyProtocol {
///     fn origin(&self) -> u64 { ndn_config::control_parameters::origin::STATIC }
///
///     fn start(&self, handle: RoutingHandle, cancel: CancellationToken) -> JoinHandle<()> {
///         let inner = Arc::clone(&self.inner);
///         tokio::spawn(async move {
///             inner.run(handle, cancel).await;
///         })
///     }
/// }
/// ```
///
/// [`origin`]: RoutingProtocol::origin
/// [`start`]: RoutingProtocol::start
pub trait RoutingProtocol: Send + Sync + 'static {
    /// Route origin value this protocol registers under.
    ///
    /// Each running instance must use a unique value. Standard values are in
    /// `ndn_config::control_parameters::origin` (e.g. `NLSR = 128`).
    /// Custom protocols should use values in the range 64–127.
    fn origin(&self) -> u64;

    /// Start the protocol as a Tokio background task.
    ///
    /// Should run until `cancel` is cancelled, then return. The implementation
    /// calls `handle.rib.add()` to register routes and
    /// `handle.rib.apply_to_fib()` to push changes into the FIB.
    ///
    /// Routes are automatically flushed from the RIB when the protocol is
    /// stopped via [`RoutingManager::disable`].
    fn start(&self, handle: RoutingHandle, cancel: CancellationToken) -> JoinHandle<()>;
}

struct ProtocolHandle {
    cancel: CancellationToken,
    /// The task handle. Dropped (not awaited) when the protocol is disabled,
    /// which keeps the task running briefly until it reaches a cancellation
    /// checkpoint.
    _task: JoinHandle<()>,
}

/// Manages a set of concurrently-running routing protocols.
///
/// # How it works
///
/// Each protocol is assigned a unique [`origin`] value. When enabled, the
/// manager starts the protocol as an independent Tokio task with a child
/// cancellation token. When disabled, the child token is cancelled (stopping
/// the task at its next `cancel.cancelled().await`) and all routes the
/// protocol registered are flushed from the RIB; the FIB is recomputed for
/// affected prefixes from any remaining protocols' routes.
///
/// # Multiple protocols
///
/// Running two protocols simultaneously is the normal case: for example, DVR
/// (origin 128) discovering routes for `/ndn/edu/…` and autoconf (origin 66)
/// advertising link-local routes. Both write to the RIB under their origin;
/// the RIB selects the lowest-cost nexthop per face when building FIB entries.
///
/// [`origin`]: RoutingProtocol::origin
pub struct RoutingManager {
    rib: Arc<Rib>,
    fib: Arc<Fib>,
    faces: Arc<FaceTable>,
    neighbors: Arc<NeighborTable>,
    handles: DashMap<u64, ProtocolHandle>,
    /// Parent cancellation token from the engine. Child tokens created from
    /// this are cancelled automatically when the engine shuts down.
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

    /// Start a routing protocol.
    ///
    /// Creates a child cancellation token from the engine token so the protocol
    /// is automatically stopped when the engine shuts down. If a protocol with
    /// the same origin is already running, it is stopped and its routes flushed
    /// before the new one starts.
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
        self.handles
            .insert(origin, ProtocolHandle { cancel, _task: task });
        tracing::info!(origin, "routing protocol enabled");
    }

    /// Stop a routing protocol and flush all routes it registered.
    ///
    /// Cancels the protocol's task (the task exits at its next cancellation
    /// checkpoint) and removes all routes registered under `origin` from the
    /// RIB. FIB entries for affected prefixes are recomputed from any remaining
    /// protocols' routes.
    ///
    /// Returns `true` if a protocol with that origin was running.
    pub fn disable(&self, origin: u64) -> bool {
        if self.handles.contains_key(&origin) {
            self.stop_and_flush(origin);
            tracing::info!(origin, "routing protocol disabled");
            true
        } else {
            false
        }
    }

    /// Returns the origin values of all currently-running protocols.
    pub fn running_origins(&self) -> Vec<u64> {
        self.handles.iter().map(|e| *e.key()).collect()
    }

    /// Returns the number of currently-running protocols.
    pub fn running_count(&self) -> usize {
        self.handles.len()
    }

    fn stop_and_flush(&self, origin: u64) {
        if let Some((_, handle)) = self.handles.remove(&origin) {
            handle.cancel.cancel();
            // `handle._task` is dropped here. The task continues briefly until
            // it observes the cancellation, then exits. We proceed immediately
            // to flush routes so the FIB is updated without delay.
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
