//! [`MobileEngine`] and [`MobileEngineBuilder`].

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
#[cfg(feature = "fjall")]
use std::sync::Arc;

use ndn_app::{Consumer, Producer};
use ndn_discovery::udp_nd::UdpNeighborDiscovery;
use ndn_discovery::{DiscoveryConfig, DiscoveryProfile};
use ndn_engine::{EngineBuilder, EngineConfig, ForwarderEngine, ShutdownHandle};
use ndn_face_local::{AppFace, AppHandle};
use ndn_face_net::{MulticastUdpFace, UdpFace};
use ndn_packet::Name;
use ndn_security::SecurityProfile;
use ndn_transport::{FaceId, FacePersistency};
use tokio_util::sync::CancellationToken;

/// Embedded NDN forwarder for mobile apps.
///
/// `MobileEngine` runs the forwarder in-process alongside the application.
/// It uses [`AppFace`] for app↔forwarder communication (zero IPC overhead)
/// and standard UDP/TCP faces for network connectivity.
///
/// # Quick start
///
/// ```no_run
/// use ndn_mobile::MobileEngine;
///
/// #[tokio::main]
/// async fn main() -> anyhow::Result<()> {
///     let (engine, handle) = MobileEngine::builder().build().await?;
///
///     let mut consumer = ndn_mobile::Consumer::from_handle(handle);
///     let data = consumer.fetch("/example/hello").await?;
///
///     engine.shutdown().await;
///     Ok(())
/// }
/// ```
pub struct MobileEngine {
    engine: ForwarderEngine,
    shutdown: ShutdownHandle,
    /// Parent cancel token for all network faces (multicast + unicast).
    /// Cancelling this token suspends all network I/O while keeping the
    /// engine, FIB, PIT, CS, and AppFace alive.
    network_cancel: CancellationToken,
    /// Stored multicast interface for [`resume_network_faces`](Self::resume_network_faces).
    multicast_iface: Option<Ipv4Addr>,
    /// Fixed FaceId assigned to the multicast face at build time.
    /// Preserved across suspend/resume so UdpNeighborDiscovery remains valid.
    multicast_face_id: FaceId,
}

/// Builder for [`MobileEngine`].
///
/// Defaults are tuned for mobile: 8 MB content store, single-threaded
/// pipeline, full chain security validation.  Adjust with the fluent
/// methods before calling [`build`](MobileEngineBuilder::build).
pub struct MobileEngineBuilder {
    cs_capacity_mb: usize,
    security_profile: SecurityProfile,
    multicast_iface: Option<Ipv4Addr>,
    unicast_peers: Vec<SocketAddr>,
    node_name: Option<Name>,
    pipeline_threads: usize,
    #[cfg_attr(not(feature = "fjall"), allow(dead_code))]
    persistent_cs_path: Option<PathBuf>,
}

impl Default for MobileEngineBuilder {
    fn default() -> Self {
        Self {
            cs_capacity_mb: 8,
            security_profile: SecurityProfile::Default,
            multicast_iface: None,
            unicast_peers: Vec::new(),
            node_name: None,
            pipeline_threads: 1,
            persistent_cs_path: None,
        }
    }
}

impl MobileEngineBuilder {
    /// Content store capacity (default: 8 MB).
    pub fn cs_capacity_mb(mut self, mb: usize) -> Self {
        self.cs_capacity_mb = mb;
        self
    }

    /// Security profile (default: [`SecurityProfile::Default`] — full chain validation).
    ///
    /// Use [`SecurityProfile::AcceptSigned`] to verify signatures without
    /// cert-chain fetching, or [`SecurityProfile::Disabled`] to turn off
    /// validation entirely (e.g. isolated test networks).
    pub fn security_profile(mut self, p: SecurityProfile) -> Self {
        self.security_profile = p;
        self
    }

    /// Number of forwarder pipeline threads (default: 1).
    ///
    /// The single-threaded default minimises wake-ups and battery drain.
    /// Increase only if the application saturates the pipeline at high
    /// Interest/Data rates (e.g. a video-streaming producer).
    pub fn pipeline_threads(mut self, n: usize) -> Self {
        self.pipeline_threads = n.max(1);
        self
    }

    /// Enable NDN UDP multicast on the given local IPv4 interface.
    ///
    /// Joins the standard NDN multicast group `224.0.23.170:6363` on that
    /// interface.  If [`with_discovery`](Self::with_discovery) is also called,
    /// the multicast face doubles as the discovery transport.
    pub fn with_udp_multicast(mut self, iface: Ipv4Addr) -> Self {
        self.multicast_iface = Some(iface);
        self
    }

    /// Add a unicast UDP peer (e.g. a campus NDN hub at a known address).
    pub fn with_unicast_peer(mut self, addr: SocketAddr) -> Self {
        self.unicast_peers.push(addr);
        self
    }

    /// Enable NDN neighbor discovery (Hello protocol over UDP multicast).
    ///
    /// Uses [`DiscoveryProfile::Mobile`]: conservative hello intervals tuned
    /// for topology changes at human-movement timescales, with fast failure
    /// detection.  Requires [`with_udp_multicast`](Self::with_udp_multicast)
    /// to also be set; calling this without multicast emits a warning at build
    /// time and discovery is silently disabled.
    ///
    /// `node_name` identifies this device on the NDN network (e.g.
    /// `/mobile/device/phone-alice`).  A transient Ed25519 key derived
    /// deterministically from the name is used to sign Hello packets.
    pub fn with_discovery(mut self, node_name: impl Into<Name>) -> Self {
        self.node_name = Some(node_name.into());
        self
    }

    /// Use a persistent on-disk content store at `path`.
    ///
    /// The persistent CS survives app restarts — the device will not
    /// re-fetch cached Data objects it already has on disk.  `path` is the
    /// directory where the store files are kept.
    ///
    /// # iOS App Groups
    ///
    /// To share the content store between your main app and app extensions
    /// (widgets, share extensions, etc.) in the same App Group, pass the App
    /// Group container path obtained from Swift/ObjC:
    ///
    /// ```swift
    /// // Swift — resolve the path and pass to Rust over FFI
    /// let url = FileManager.default
    ///     .containerURL(forSecurityApplicationGroupIdentifier: "group.com.example.app")!
    ///     .appendingPathComponent("ndn-cs")
    /// rust_engine_set_cs_path(url.path)
    /// ```
    ///
    /// # Android
    ///
    /// Use the app's files directory, e.g. obtained from `Context.getFilesDir()` in
    /// Kotlin/Java and passed to Rust via JNI.
    ///
    /// Requires the `fjall` feature flag on this crate.
    #[cfg(feature = "fjall")]
    pub fn with_persistent_cs(mut self, path: impl Into<PathBuf>) -> Self {
        self.persistent_cs_path = Some(path.into());
        self
    }

    /// Build the engine.
    ///
    /// Returns a `(MobileEngine, AppHandle)` pair. The [`AppHandle`] is the
    /// default application face — pass it to [`Consumer::from_handle`] or
    /// create a [`Producer`] via [`MobileEngine::register_producer`].
    pub async fn build(self) -> Result<(MobileEngine, AppHandle), anyhow::Error> {
        let config = EngineConfig {
            cs_capacity_bytes: self.cs_capacity_mb * 1024 * 1024,
            pipeline_threads: self.pipeline_threads,
            pipeline_channel_cap: 1024,
        };

        // Create the builder first so we can allocate face IDs through its
        // FaceTable counter, ensuring no two faces share the same ID.
        let mut builder = EngineBuilder::new(config).security_profile(self.security_profile);

        // Allocate the primary AppFace ID through the builder's counter.
        // Must happen before alloc_face_id() calls for multicast/unicast so
        // that AppFace always holds FaceId(1) and the table stays consistent.
        let app_face_id = builder.alloc_face_id();
        let (app_face, app_handle) = AppFace::new(app_face_id, 256);
        builder = builder.face(app_face);

        // Persistent CS (fjall feature).
        #[cfg(feature = "fjall")]
        if let Some(ref path) = self.persistent_cs_path {
            let cs = ndn_store::FjallCs::open(path, self.cs_capacity_mb * 1024 * 1024)
                .map_err(|e| anyhow::anyhow!("failed to open persistent CS at {}: {e}", path.display()))?;
            builder = builder.content_store(Arc::new(cs));
        }

        // Pre-allocate multicast face ID if we have an interface configured.
        // This must happen before build() so UdpNeighborDiscovery can reference it.
        let multicast_face_id = if self.multicast_iface.is_some() {
            Some(builder.alloc_face_id())
        } else {
            None
        };

        // Wire up discovery if a node name was provided alongside multicast.
        if let Some(face_id) = multicast_face_id {
            if let Some(ref node_name) = self.node_name {
                let discovery = UdpNeighborDiscovery::new_with_config(
                    face_id,
                    node_name.clone(),
                    DiscoveryConfig::for_profile(&DiscoveryProfile::Mobile),
                );
                builder = builder.discovery(discovery);
            }
        } else if self.node_name.is_some() {
            tracing::warn!(
                "with_discovery() has no effect without with_udp_multicast(); \
                 discovery requires a multicast face"
            );
        }

        let (engine, shutdown) = builder.build().await?;

        // Create a parent cancel token for all network faces.
        // Cancelling it suspends all network I/O without touching AppFace.
        let network_cancel = shutdown.cancel_token().child_token();

        // Add multicast face.
        if let Some(face_id) = multicast_face_id {
            let iface = self.multicast_iface.unwrap();
            match MulticastUdpFace::ndn_default(iface, face_id).await {
                Ok(face) => {
                    engine.add_face(face, network_cancel.child_token());
                }
                Err(e) => {
                    tracing::warn!(%iface, error = %e, "UDP multicast face setup failed");
                }
            }
        }

        // Add unicast peers.
        for peer in self.unicast_peers {
            let face_id = engine.faces().alloc_id();
            let local: SocketAddr = "0.0.0.0:0".parse().unwrap();
            match UdpFace::bind(local, peer, face_id).await {
                Ok(face) => {
                    engine.add_face_with_persistency(
                        face,
                        network_cancel.child_token(),
                        FacePersistency::Persistent,
                    );
                }
                Err(e) => {
                    tracing::warn!(%peer, error = %e, "UDP unicast face setup failed");
                }
            }
        }

        Ok((
            MobileEngine {
                engine,
                shutdown,
                network_cancel,
                multicast_iface: self.multicast_iface,
                multicast_face_id: multicast_face_id.unwrap_or(FaceId(0)),
            },
            app_handle,
        ))
    }
}

impl MobileEngine {
    /// Create a builder with mobile-sensible defaults.
    pub fn builder() -> MobileEngineBuilder {
        MobileEngineBuilder::default()
    }

    // ── App faces ─────────────────────────────────────────────────────────────

    /// Create a new application face and return its handle and face ID.
    ///
    /// Use this when multiple independent app components need their own NDN
    /// faces.  The returned [`FaceId`] can be passed to
    /// [`add_route`](Self::add_route) to install FIB entries for that face.
    pub fn new_app_handle(&self) -> (FaceId, AppHandle) {
        let face_id = self.engine.faces().alloc_id();
        let (face, handle) = AppFace::new(face_id, 256);
        let cancel = self.shutdown.cancel_token().child_token();
        self.engine.add_face(face, cancel);
        (face_id, handle)
    }

    /// Register a producer prefix in the FIB and return a ready [`Producer`].
    ///
    /// Allocates a new AppFace for the producer and installs a FIB route so
    /// that Interests arriving on any network face are forwarded to it.
    ///
    /// ```no_run
    /// # async fn example(engine: ndn_mobile::MobileEngine) -> anyhow::Result<()> {
    /// let mut producer = engine.register_producer("/example/app");
    /// producer.serve(|interest| async move {
    ///     let data = ndn_packet::encode::DataBuilder::new((*interest.name).clone(), b"hello").build();
    ///     Some(data)
    /// }).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn register_producer(
        &self,
        prefix: impl Into<Name>,
    ) -> Producer {
        let prefix: Name = prefix.into();
        let (face_id, handle) = self.new_app_handle();
        self.engine.fib().add_nexthop(&prefix, face_id, 0);
        Producer::from_handle(handle, prefix)
    }

    /// Create a [`Consumer`] on the given AppHandle.
    pub fn consumer(&self, handle: AppHandle) -> Consumer {
        Consumer::from_handle(handle)
    }

    // ── FIB ───────────────────────────────────────────────────────────────────

    /// Add a FIB route: forward Interests matching `prefix` to `face_id` at `cost`.
    pub fn add_route(&self, prefix: &Name, face_id: FaceId, cost: u32) {
        self.engine.fib().add_nexthop(prefix, face_id, cost);
    }

    // ── Background mode ───────────────────────────────────────────────────────

    /// Suspend all network faces (UDP multicast, unicast peers, Bluetooth).
    ///
    /// Cancels the shared network cancel token, which stops all recv/send
    /// tasks for non-AppFace faces.  The engine, FIB, PIT, CS, and AppFace
    /// remain fully active — in-process communication continues uninterrupted.
    ///
    /// Call this from the platform lifecycle callback when the app moves to
    /// background:
    /// - **Android**: `onStop()` or `onPause()` in your `Activity`
    /// - **iOS**: `applicationDidEnterBackground(_:)` or
    ///   `sceneDidEnterBackground(_:)`
    ///
    /// After calling this, network NDN traffic will not be processed until
    /// [`resume_network_faces`](Self::resume_network_faces) is called.
    pub fn suspend_network_faces(&mut self) {
        tracing::debug!("suspending network faces");
        self.network_cancel.cancel();
        // Replace with a fresh (not-yet-cancelled) token so resume() can
        // attach new faces to the engine without triggering the old token.
        self.network_cancel = self.shutdown.cancel_token().child_token();
    }

    /// Resume network faces after [`suspend_network_faces`](Self::suspend_network_faces).
    ///
    /// Recreates the UDP multicast face if one was configured at build time,
    /// reusing the **same `FaceId`** as the original face so that the discovery
    /// module's multicast face list remains valid.
    ///
    /// Unicast peers and Bluetooth faces must be re-added manually via
    /// [`engine`](Self::engine) and [`network_cancel_token`](Self::network_cancel_token)
    /// (their addresses / streams are not stored here).
    ///
    /// Call this from the platform lifecycle callback when the app moves to
    /// foreground:
    /// - **Android**: `onStart()` or `onResume()` in your `Activity`
    /// - **iOS**: `applicationWillEnterForeground(_:)` or
    ///   `sceneWillEnterForeground(_:)`
    pub async fn resume_network_faces(&mut self) {
        tracing::debug!("resuming network faces");
        if let Some(iface) = self.multicast_iface {
            // Reuse the stored face ID so UdpNeighborDiscovery (which holds a
            // fixed list of multicast face IDs) can still send Hello packets
            // after resume without needing to know about the new socket.
            match MulticastUdpFace::ndn_default(iface, self.multicast_face_id).await {
                Ok(face) => {
                    self.engine
                        .add_face(face, self.network_cancel.child_token());
                    tracing::debug!(%iface, face_id = %self.multicast_face_id, "multicast face resumed");
                }
                Err(e) => {
                    tracing::warn!(%iface, error = %e, "multicast face resume failed");
                }
            }
        }
    }

    // ── Advanced ──────────────────────────────────────────────────────────────

    /// Access the underlying [`ForwarderEngine`] for advanced configuration.
    ///
    /// Use this to add Bluetooth faces, register custom strategies, add CS
    /// observers, or inspect the neighbor table.
    pub fn engine(&self) -> &ForwarderEngine {
        &self.engine
    }

    /// A child cancel token that is cancelled by [`suspend_network_faces`](Self::suspend_network_faces).
    ///
    /// Pass this (or a child of it) when adding platform-supplied faces
    /// (e.g. Bluetooth) so they are automatically suspended along with the
    /// built-in UDP faces when the app moves to background.
    ///
    /// ```no_run
    /// # async fn example(engine: &ndn_mobile::MobileEngine, reader: impl tokio::io::AsyncRead + Send + Sync + Unpin + 'static, writer: impl tokio::io::AsyncWrite + Send + Sync + Unpin + 'static) {
    /// let face = ndn_mobile::bluetooth_face_from_parts(
    ///     engine.engine().faces().alloc_id(),
    ///     "BT:AA:BB:CC:DD:EE",
    ///     reader,
    ///     writer,
    /// );
    /// engine.engine().add_face(face, engine.network_cancel_token().child_token());
    /// # }
    /// ```
    pub fn network_cancel_token(&self) -> CancellationToken {
        self.network_cancel.child_token()
    }

    /// Gracefully shut down the forwarder and all spawned tasks.
    ///
    /// Waits for in-flight packets to drain before returning.
    pub async fn shutdown(self) {
        self.shutdown.shutdown().await;
    }
}
