//! `LinkMedium` trait — abstraction over link-layer differences for discovery.
//!
//! UDP and Ethernet neighbor discovery share the same SWIM/hello/probe state
//! machine but differ in address types, face creation, and packet signing.
//! Implementing `LinkMedium` provides those customisation points while
//! [`HelloProtocol<T>`](super::hello_protocol::HelloProtocol) supplies the
//! common logic.

use std::collections::{HashMap, VecDeque};
use std::str::FromStr;
use std::sync::Mutex;
use std::sync::atomic::AtomicU32;
use std::time::Instant;

use bytes::Bytes;
use ndn_packet::Name;
use ndn_transport::FaceId;

use crate::config::DiscoveryConfig;
use crate::strategy::{NeighborProbeStrategy, build_strategy};
use crate::{DiffEntry, DiscoveryContext, HelloPayload, InboundMeta, NeighborEntry, ProtocolId};

// ─── Shared constants ────────────────────────────────────────────────────────

pub const HELLO_PREFIX_STR: &str = "/ndn/local/nd/hello";
pub const HELLO_PREFIX_DEPTH: usize = 4;
pub(crate) const MAX_DIFF_ENTRIES: usize = 16;

// ─── HelloState ──────────────────────────────────────────────────────────────

/// Mutable state shared by all `HelloProtocol<T>` instances.
///
/// Contains nonce-keyed maps for outstanding hellos, SWIM probes, relay
/// bookkeeping, and the recent neighbor-diff queue piggybacked onto outgoing
/// hello Data packets.
#[derive(Default)]
pub struct HelloState {
    /// Nonce → send_time for outstanding hello probes.
    pub pending_probes: HashMap<u32, Instant>,
    /// Recent neighbor additions/removals for SWIM gossip piggyback.
    pub recent_diffs: VecDeque<DiffEntry>,
    /// SWIM direct probes: nonce → (sent_at, target_name).
    pub swim_probes: HashMap<u32, (Instant, Name)>,
    /// Relay state: relay_nonce → (origin_face, original_interest_name).
    pub relay_probes: HashMap<u32, (FaceId, Name)>,
}

impl HelloState {
    pub fn new() -> Self {
        Self::default()
    }
}

// ─── HelloCore ───────────────────────────────────────────────────────────────

/// Shared (non-link-specific) fields used by `HelloProtocol<T>`.
///
/// Exposed to `LinkMedium` implementations so they can access the node name,
/// config, strategy, and mutable state when building packets or handling
/// inbound messages.
pub struct HelloCore {
    pub node_name: Name,
    pub hello_prefix: Name,
    pub claimed: Vec<Name>,
    pub nonce_counter: AtomicU32,
    pub config: DiscoveryConfig,
    pub strategy: Mutex<Box<dyn NeighborProbeStrategy>>,
    pub served_prefixes: Mutex<Vec<Name>>,
    pub state: Mutex<HelloState>,
}

impl HelloCore {
    pub fn new(node_name: Name, config: DiscoveryConfig) -> Self {
        let hello_prefix = Name::from_str(HELLO_PREFIX_STR).expect("static prefix is valid");
        let mut claimed = vec![hello_prefix.clone()];
        if config.swim_indirect_fanout > 0 {
            claimed.push(crate::scope::probe_direct().clone());
            claimed.push(crate::scope::probe_via().clone());
        }
        let strategy = build_strategy(&config);
        Self {
            node_name,
            hello_prefix,
            claimed,
            nonce_counter: AtomicU32::new(1),
            strategy: Mutex::new(strategy),
            served_prefixes: Mutex::new(Vec::new()),
            config,
            state: Mutex::new(HelloState::new()),
        }
    }
}

// ─── LinkMedium trait ────────────────────────────────────────────────────────

/// Abstraction over link-layer differences between discovery protocols.
///
/// Implementations provide the link-specific operations (face creation,
/// address extraction, packet signing) while the shared SWIM/hello/probe
/// state machine lives in [`HelloProtocol<T>`].
///
/// [`HelloProtocol<T>`]: super::hello_protocol::HelloProtocol
pub trait LinkMedium: Send + Sync + 'static {
    /// Protocol identifier (e.g. `"udp-nd"`, `"ether-nd"`).
    fn protocol_id(&self) -> ProtocolId;

    /// Build the hello Data reply for the given Interest name.
    ///
    /// UDP signs with Ed25519; Ethernet uses an unsigned placeholder.
    fn build_hello_data(&self, core: &HelloCore, interest_name: &Name) -> Bytes;

    /// Handle a hello Interest (link-specific dispatch).
    ///
    /// Extracts the source address from `meta`, performs any link-specific
    /// actions (e.g. passive detection for new MACs), builds and sends the
    /// reply via `ctx.send_on`.  Returns `true` if the Interest was consumed.
    fn handle_hello_interest(
        &self,
        raw: &Bytes,
        incoming_face: FaceId,
        meta: &InboundMeta,
        core: &HelloCore,
        ctx: &dyn DiscoveryContext,
    ) -> bool;

    /// Verify signature (if applicable), extract source address, and ensure
    /// a unicast face to the peer exists.
    ///
    /// Called by `HelloProtocol::handle_hello_data` after the shared code has
    /// parsed the hello Data, extracted the nonce, and decoded the
    /// `HelloPayload`.
    ///
    /// Returns `(responder_name, optional_face_id)` on success, or `None`
    /// to silently drop the packet.
    fn verify_and_ensure_peer(
        &self,
        raw: &Bytes,
        payload: &HelloPayload,
        meta: &InboundMeta,
        core: &HelloCore,
        ctx: &dyn DiscoveryContext,
    ) -> Option<(Name, Option<FaceId>)>;

    /// Send a packet on all multicast face(s).
    fn send_multicast(&self, ctx: &dyn DiscoveryContext, pkt: Bytes);

    /// Whether `face_id` is one of this medium's multicast faces.
    fn is_multicast_face(&self, face_id: FaceId) -> bool;

    /// Handle face-down event (clean up link-specific state).
    fn on_face_down(&self, face_id: FaceId, state: &mut HelloState, ctx: &dyn DiscoveryContext);

    /// Clean up link-specific state when a peer is being removed
    /// (reached miss_limit in the liveness state machine).
    fn on_peer_removed(&self, entry: &NeighborEntry, state: &mut HelloState);
}
