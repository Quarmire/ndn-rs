//! `ServiceDiscoveryProtocol` — service record publication/browsing and
//! demand-driven peer list.
//!
//! ## Wire format -- Peers response
//!
//! ```text
//! PeerList ::= (PEER-ENTRY TLV)*
//! PEER-ENTRY  ::= 0xE0 length Name
//! ```

mod browsing;
mod fib_auto;
mod records;

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::Instant;

use bytes::Bytes;
use ndn_packet::Name;
use ndn_transport::FaceId;
use tracing::{debug, info};

use crate::config::ServiceDiscoveryConfig;
use crate::context::DiscoveryContext;
use crate::prefix_announce::ServiceRecord;
use crate::protocol::{DiscoveryProtocol, InboundMeta, ProtocolId};
use crate::scope::{peers_prefix, sd_services};

pub use browsing::decode_peer_list;
use fib_auto::AutoFibEntry;
use records::{ProducerRateLimit, RecordEntry};

const PROTOCOL: ProtocolId = ProtocolId("service-discovery");

/// Service discovery and peer-list protocol.
///
/// Attach alongside [`UdpNeighborDiscovery`] or [`EtherNeighborDiscovery`] in
/// a [`CompositeDiscovery`] to enable service record publication/browsing and
/// demand-driven neighbor queries.
///
/// [`UdpNeighborDiscovery`]: crate::UdpNeighborDiscovery
/// [`CompositeDiscovery`]: crate::CompositeDiscovery
pub struct ServiceDiscoveryProtocol {
    /// This node's NDN name (used when building responses).
    #[expect(dead_code)]
    node_name: Name,
    pub(super) config: ServiceDiscoveryConfig,
    claimed: Vec<Name>,
    pub(super) local_records: Mutex<Vec<RecordEntry>>,
    /// Deduplicated on `(announced_prefix, node_name)`.
    pub(super) peer_records: Mutex<Vec<ServiceRecord>>,
    pub(super) rate_limits: Mutex<HashMap<String, ProducerRateLimit>>,
    pub(super) auto_fib: Mutex<Vec<AutoFibEntry>>,
    /// Tracks which neighbors have received an initial browse Interest.
    /// Uses neighbor table (not face IDs) to avoid browsing management/app faces.
    pub(super) browsed_neighbors: Mutex<HashSet<Name>>,
    pub(super) last_browse: Mutex<Option<Instant>>,
}

impl ServiceDiscoveryProtocol {
    pub fn new(node_name: Name, config: ServiceDiscoveryConfig) -> Self {
        let claimed = vec![sd_services().clone(), peers_prefix().clone()];
        Self {
            node_name,
            config,
            claimed,
            local_records: Mutex::new(Vec::new()),
            peer_records: Mutex::new(Vec::new()),
            rate_limits: Mutex::new(HashMap::new()),
            auto_fib: Mutex::new(Vec::new()),
            browsed_neighbors: Mutex::new(HashSet::new()),
            last_browse: Mutex::new(None),
        }
    }

    pub fn with_defaults(node_name: Name) -> Self {
        Self::new(node_name, ServiceDiscoveryConfig::default())
    }
}


impl DiscoveryProtocol for ServiceDiscoveryProtocol {
    fn protocol_id(&self) -> ProtocolId {
        PROTOCOL
    }

    fn claimed_prefixes(&self) -> &[Name] {
        &self.claimed
    }

    fn on_face_up(&self, _face_id: FaceId, _ctx: &dyn DiscoveryContext) {}

    fn on_face_down(&self, face_id: FaceId, ctx: &dyn DiscoveryContext) {
        {
            let mut local = self.local_records.lock().unwrap();
            let before = local.len();
            local.retain(|e| e.owner_face != Some(face_id));
            let removed = before - local.len();
            if removed > 0 {
                info!(face = ?face_id, count = removed, "ServiceDiscovery: withdrew local records for downed face");
            }
        }

        let affected: Vec<Name> = ctx
            .neighbors()
            .all()
            .into_iter()
            .filter(|e| e.faces.iter().any(|(fid, _, _)| *fid == face_id))
            .map(|e| e.node_name.clone())
            .collect();

        if !affected.is_empty() {
            let mut peer_recs = self.peer_records.lock().unwrap();
            peer_recs.retain(|r| !affected.contains(&r.node_name));
            debug!(
                nodes = ?affected.iter().map(|n| n.to_string()).collect::<Vec<_>>(),
                "ServiceDiscovery: evicted peer records for face-down nodes",
            );
        }

        let mut fib_removals: Vec<(Name, FaceId)> = Vec::new();
        {
            let mut auto_fib = self.auto_fib.lock().unwrap();
            auto_fib.retain(|e| {
                if e.face_id == face_id {
                    fib_removals.push((e.prefix.clone(), e.face_id));
                    false
                } else {
                    true
                }
            });
        }
        for (prefix, fid) in &fib_removals {
            ctx.remove_fib_entry(prefix, *fid, PROTOCOL);
        }
        if !fib_removals.is_empty() {
            debug!(count = fib_removals.len(), face = ?face_id, "ServiceDiscovery: removed auto-FIB entries for downed face");
        }

        if !affected.is_empty() {
            let mut seen = self.browsed_neighbors.lock().unwrap();
            for name in &affected {
                seen.remove(name);
            }
        }
    }

    fn on_inbound(
        &self,
        raw: &Bytes,
        incoming_face: FaceId,
        _meta: &InboundMeta,
        ctx: &dyn DiscoveryContext,
    ) -> bool {
        match raw.first() {
            Some(&0x05) => {
                if self.handle_sd_interest(raw, incoming_face, ctx) {
                    return true;
                }
                self.handle_peers_interest(raw, incoming_face, ctx)
            }
            Some(&0x06) => {
                self.handle_sd_data(raw, incoming_face, ctx)
            }
            _ => false,
        }
    }

    fn on_tick(&self, now: Instant, ctx: &dyn DiscoveryContext) {
        self.expire_auto_fib(now, ctx);
        self.expire_local_records(now);
        let browse_interval = self.compute_browse_interval(now);
        self.browse_neighbors(now, browse_interval, ctx);
    }
}


#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::time::Duration;

    use super::*;
    use crate::wire::write_name_tlv;
    use crate::{MacAddr, NeighborTable};
    use ndn_tlv::TlvWriter;

    fn name(s: &str) -> Name {
        Name::from_str(s).unwrap()
    }

    fn make_sd() -> ServiceDiscoveryProtocol {
        ServiceDiscoveryProtocol::with_defaults(name("/ndn/test/node"))
    }

    #[test]
    fn publish_and_withdraw() {
        let sd = make_sd();
        let rec = ServiceRecord::new(name("/ndn/sensor/temp"), name("/ndn/test/node"));
        sd.publish(rec);
        {
            let records = sd.local_records.lock().unwrap();
            assert_eq!(records.len(), 1);
        }
        sd.withdraw(&name("/ndn/sensor/temp"));
        {
            let records = sd.local_records.lock().unwrap();
            assert!(records.is_empty());
        }
    }

    #[test]
    fn publish_replaces_existing() {
        let sd = make_sd();
        let rec1 = ServiceRecord {
            announced_prefix: name("/ndn/sensor/temp"),
            node_name: name("/ndn/test/node"),
            freshness_ms: 30_000,
            capabilities: 0,
        };
        let mut rec2 = rec1.clone();
        rec2.freshness_ms = 60_000;
        sd.publish(rec1);
        sd.publish(rec2);
        let records = sd.local_records.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].record.freshness_ms, 60_000);
    }

    #[test]
    fn claimed_prefixes_includes_sd_and_peers() {
        let sd = make_sd();
        let claimed = sd.claimed_prefixes();
        assert!(claimed.iter().any(|p| p.has_prefix(sd_services())));
        assert!(claimed.iter().any(|p| p == peers_prefix()));
    }

    #[test]
    fn decode_peer_list_roundtrip() {
        let mut w = TlvWriter::new();
        let n1 = name("/ndn/test/peer1");
        let n2 = name("/ndn/test/peer2");
        w.write_nested(0xE0, |w: &mut TlvWriter| {
            write_name_tlv(w, &n1);
        });
        w.write_nested(0xE0, |w: &mut TlvWriter| {
            write_name_tlv(w, &n2);
        });
        let content = w.finish();
        let decoded = decode_peer_list(&content);
        assert_eq!(decoded.len(), 2);
    }

    #[test]
    fn auto_fib_ttl_expiry_on_tick() {
        use crate::context::DiscoveryContext;
        use crate::{NeighborTableView, NeighborUpdate};
        use std::sync::{Arc, Mutex as StdMutex};

        struct TrackCtx {
            now: Instant,
            removed: StdMutex<Vec<Name>>,
        }
        impl DiscoveryContext for TrackCtx {
            fn alloc_face_id(&self) -> FaceId {
                FaceId(0)
            }
            fn add_face(&self, _: Arc<dyn ndn_transport::ErasedFace>) -> FaceId {
                FaceId(0)
            }
            fn remove_face(&self, _: FaceId) {}
            fn add_fib_entry(&self, _: &Name, _: FaceId, _: u32, _: ProtocolId) {}
            fn remove_fib_entry(&self, prefix: &Name, _: FaceId, _: ProtocolId) {
                self.removed.lock().unwrap().push(prefix.clone());
            }
            fn remove_fib_entries_by_owner(&self, _: ProtocolId) {}
            fn neighbors(&self) -> Arc<dyn NeighborTableView> {
                NeighborTable::new()
            }
            fn update_neighbor(&self, _: NeighborUpdate) {}
            fn send_on(&self, _: FaceId, _: Bytes) {}
            fn now(&self) -> Instant {
                self.now
            }
        }

        let sd = make_sd();
        let now = Instant::now();
        let ctx = TrackCtx {
            now,
            removed: StdMutex::new(Vec::new()),
        };

        // Manually insert an already-expired auto-FIB entry.
        {
            let mut af = sd.auto_fib.lock().unwrap();
            af.push(AutoFibEntry {
                prefix: name("/ndn/sensor/temp"),
                face_id: FaceId(7),
                expires_at: now - Duration::from_millis(1),
                node_name: name("/ndn/test/peer"),
            });
        }

        sd.on_tick(now, &ctx);
        let removed = ctx.removed.lock().unwrap();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0], name("/ndn/sensor/temp"));
        assert!(sd.auto_fib.lock().unwrap().is_empty());
    }

    #[test]
    fn relay_records_sends_to_other_peers() {
        use crate::context::DiscoveryContext;
        use crate::{
            NeighborEntry, NeighborState, NeighborTable, NeighborTableView, NeighborUpdate,
        };
        use std::sync::{Arc, Mutex as StdMutex};

        struct RelayCtx {
            neighbors: Arc<NeighborTable>,
            sent: StdMutex<Vec<(FaceId, Bytes)>>,
        }
        impl DiscoveryContext for RelayCtx {
            fn alloc_face_id(&self) -> FaceId {
                FaceId(99)
            }
            fn add_face(&self, _: Arc<dyn ndn_transport::ErasedFace>) -> FaceId {
                FaceId(99)
            }
            fn remove_face(&self, _: FaceId) {}
            fn add_fib_entry(&self, _: &Name, _: FaceId, _: u32, _: ProtocolId) {}
            fn remove_fib_entry(&self, _: &Name, _: FaceId, _: ProtocolId) {}
            fn remove_fib_entries_by_owner(&self, _: ProtocolId) {}
            fn neighbors(&self) -> Arc<dyn NeighborTableView> {
                Arc::clone(&self.neighbors) as Arc<dyn NeighborTableView>
            }
            fn update_neighbor(&self, u: NeighborUpdate) {
                self.neighbors.apply(u);
            }
            fn send_on(&self, face_id: FaceId, pkt: Bytes) {
                self.sent.lock().unwrap().push((face_id, pkt));
            }
            fn now(&self) -> Instant {
                Instant::now()
            }
        }

        let cfg = ServiceDiscoveryConfig {
            relay_records: true,
            auto_populate_fib: false, // keep test focused on relay only
            ..ServiceDiscoveryConfig::default()
        };
        let sd = ServiceDiscoveryProtocol::new(name("/ndn/test/node"), cfg);

        let neighbors = NeighborTable::new();
        // Add two reachable neighbors with different faces.
        let mut e1 = NeighborEntry::new(name("/ndn/peer/a"));
        e1.state = NeighborState::Established {
            last_seen: Instant::now(),
        };
        e1.faces = vec![(FaceId(10), MacAddr([0u8; 6]), "eth0".into())];
        let mut e2 = NeighborEntry::new(name("/ndn/peer/b"));
        e2.state = NeighborState::Established {
            last_seen: Instant::now(),
        };
        e2.faces = vec![(FaceId(20), MacAddr([0u8; 6]), "eth0".into())];
        neighbors.apply(NeighborUpdate::Upsert(e1));
        neighbors.apply(NeighborUpdate::Upsert(e2));

        let ctx = RelayCtx {
            neighbors,
            sent: StdMutex::new(Vec::new()),
        };

        // Build a valid service record Data packet arriving on face 10.
        let rec = ServiceRecord {
            announced_prefix: name("/ndn/sensor/temp"),
            node_name: name("/ndn/peer/a"),
            freshness_ms: 10_000,
            capabilities: 0,
        };
        let pkt = rec.build_data(1000);

        sd.on_inbound(&pkt, FaceId(10), &crate::InboundMeta::none(), &ctx);

        let sent = ctx.sent.lock().unwrap();
        // Should relay to face 20 (peer/b), not back to face 10 (source).
        assert!(
            sent.iter().any(|(fid, _)| *fid == FaceId(20)),
            "should relay to peer/b"
        );
        assert!(
            !sent.iter().any(|(fid, _)| *fid == FaceId(10)),
            "must not relay back to source face"
        );
    }
}
