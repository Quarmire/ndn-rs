//! `LinkMedium` trait — abstraction over link-layer differences for discovery.

use std::collections::{HashMap, VecDeque};
use std::str::FromStr;
use std::sync::atomic::AtomicU32;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use bytes::Bytes;
use ndn_packet::Name;
use ndn_transport::FaceId;

use crate::config::DiscoveryConfig;
use crate::strategy::{NeighborProbeStrategy, build_strategy};
use crate::{DiffEntry, DiscoveryContext, HelloPayload, InboundMeta, NeighborEntry, ProtocolId};


pub const HELLO_PREFIX_STR: &str = "/ndn/local/nd/hello";
pub const HELLO_PREFIX_DEPTH: usize = 4;
pub(crate) const MAX_DIFF_ENTRIES: usize = 16;


#[derive(Default)]
pub struct HelloState {
    pub pending_probes: HashMap<u32, Instant>,
    pub recent_diffs: VecDeque<DiffEntry>,
    pub swim_probes: HashMap<u32, (Instant, Name)>,
    pub relay_probes: HashMap<u32, (FaceId, Name)>,
}

impl HelloState {
    pub fn new() -> Self {
        Self::default()
    }
}


/// Shared (non-link-specific) fields used by `HelloProtocol<T>`.
pub struct HelloCore {
    pub node_name: Name,
    pub hello_prefix: Name,
    pub claimed: Vec<Name>,
    pub nonce_counter: AtomicU32,
    /// Behind `RwLock` so the management handler can update parameters at runtime.
    pub config: Arc<RwLock<DiscoveryConfig>>,
    pub strategy: Mutex<Box<dyn NeighborProbeStrategy>>,
    pub served_prefixes: Mutex<Vec<Name>>,
    pub state: Mutex<HelloState>,
}

impl HelloCore {
    pub fn new(node_name: Name, config: DiscoveryConfig) -> Self {
        Self::new_shared(node_name, Arc::new(RwLock::new(config)))
    }

    pub fn new_shared(node_name: Name, config: Arc<RwLock<DiscoveryConfig>>) -> Self {
        let hello_prefix = Name::from_str(HELLO_PREFIX_STR).expect("static prefix is valid");
        let mut claimed = vec![hello_prefix.clone()];
        let (swim_fanout, strategy) = {
            let cfg = config.read().unwrap();
            let fanout = cfg.swim_indirect_fanout;
            let strategy = build_strategy(&cfg);
            (fanout, strategy)
        };
        if swim_fanout > 0 {
            claimed.push(crate::scope::probe_direct().clone());
            claimed.push(crate::scope::probe_via().clone());
        }
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

    pub fn config_handle(&self) -> Arc<RwLock<DiscoveryConfig>> {
        Arc::clone(&self.config)
    }
}


/// Link-specific operations for [`HelloProtocol<T>`](super::protocol::HelloProtocol).
pub trait LinkMedium: Send + Sync + 'static {
    fn protocol_id(&self) -> ProtocolId;

    fn build_hello_data(&self, core: &HelloCore, interest_name: &Name) -> Bytes;

    /// Returns `true` if the Interest was consumed.
    fn handle_hello_interest(
        &self,
        raw: &Bytes,
        incoming_face: FaceId,
        meta: &InboundMeta,
        core: &HelloCore,
        ctx: &dyn DiscoveryContext,
    ) -> bool;

    /// Verify signature, extract source address, ensure unicast face exists.
    /// Returns `None` to silently drop the packet.
    fn verify_and_ensure_peer(
        &self,
        raw: &Bytes,
        payload: &HelloPayload,
        meta: &InboundMeta,
        core: &HelloCore,
        ctx: &dyn DiscoveryContext,
    ) -> Option<(Name, Option<FaceId>)>;

    fn send_multicast(&self, ctx: &dyn DiscoveryContext, pkt: Bytes);

    fn is_multicast_face(&self, face_id: FaceId) -> bool;

    fn on_face_down(&self, face_id: FaceId, state: &mut HelloState, ctx: &dyn DiscoveryContext);

    fn on_peer_removed(&self, entry: &NeighborEntry, state: &mut HelloState);
}
