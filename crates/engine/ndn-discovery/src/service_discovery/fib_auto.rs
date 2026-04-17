//! FIB auto-population logic: entry creation and TTL-based expiry.

use std::time::{Duration, Instant};

use ndn_packet::Name;
use ndn_transport::FaceId;
use tracing::debug;

use crate::context::DiscoveryContext;
use crate::prefix_announce::ServiceRecord;

use super::{PROTOCOL, ServiceDiscoveryProtocol};

pub(crate) struct AutoFibEntry {
    pub(super) prefix: Name,
    pub(super) face_id: FaceId,
    pub(super) expires_at: Instant,
    pub(super) node_name: Name,
}

impl ServiceDiscoveryProtocol {
    pub(super) fn auto_populate_fib(
        &self,
        record: &ServiceRecord,
        incoming_face: FaceId,
        ctx: &dyn DiscoveryContext,
    ) {
        let fib_face = ctx
            .neighbors()
            .get(&record.node_name)
            .and_then(|e| e.faces.first().map(|(fid, _, _)| *fid))
            .unwrap_or(incoming_face);

        ctx.add_fib_entry(
            &record.announced_prefix,
            fib_face,
            self.config.auto_fib_cost,
            PROTOCOL,
        );
        let ttl_ms =
            (record.freshness_ms as f64 * self.config.auto_fib_ttl_multiplier as f64) as u64;
        let expires_at = ctx.now() + Duration::from_millis(ttl_ms);
        {
            let mut auto_fib = self.auto_fib.lock().unwrap();
            auto_fib.retain(|e| !(e.prefix == record.announced_prefix && e.face_id == fib_face));
            auto_fib.push(AutoFibEntry {
                prefix: record.announced_prefix.clone(),
                face_id: fib_face,
                expires_at,
                node_name: record.node_name.clone(),
            });
        }
        debug!(
            "ServiceDiscovery: auto-FIB {:?} via face {fib_face:?} (cost {}, ttl {}ms)",
            record.announced_prefix, self.config.auto_fib_cost, ttl_ms
        );
    }

    /// Also evicts peer_records and resets browsed_neighbors for the
    /// affected node so re-browse is triggered on the next tick.
    pub(super) fn expire_auto_fib(&self, now: Instant, ctx: &dyn DiscoveryContext) {
        struct Expired {
            prefix: Name,
            face_id: FaceId,
            node_name: Name,
        }
        let mut expired: Vec<Expired> = Vec::new();
        {
            let mut auto_fib = self.auto_fib.lock().unwrap();
            auto_fib.retain(|e| {
                if now >= e.expires_at {
                    expired.push(Expired {
                        prefix: e.prefix.clone(),
                        face_id: e.face_id,
                        node_name: e.node_name.clone(),
                    });
                    false
                } else {
                    true
                }
            });
        }
        if !expired.is_empty() {
            {
                let mut peer_recs = self.peer_records.lock().unwrap();
                for e in &expired {
                    peer_recs.retain(|r| {
                        !(r.announced_prefix == e.prefix && r.node_name == e.node_name)
                    });
                }
            }

            {
                let mut seen = self.browsed_neighbors.lock().unwrap();
                for e in &expired {
                    seen.remove(&e.node_name);
                }
            }

            for e in &expired {
                ctx.remove_fib_entry(&e.prefix, e.face_id, PROTOCOL);
                debug!(
                    prefix = %e.prefix,
                    node   = %e.node_name,
                    face   = ?e.face_id,
                    "ServiceDiscovery: expired auto-FIB entry",
                );
            }
        }
    }

    pub(super) fn expire_local_records(&self, now: Instant) {
        let mut local = self.local_records.lock().unwrap();
        let before = local.len();
        local.retain(|e| e.expires_at.is_none_or(|exp| now < exp));
        if before != local.len() {
            debug!(
                removed = before - local.len(),
                "ServiceDiscovery: expired TTL local record(s)"
            );
        }
    }

    pub(super) fn compute_browse_interval(&self, now: Instant) -> Duration {
        const BROWSE_FLOOR: Duration = Duration::from_secs(10);
        let auto_fib = self.auto_fib.lock().unwrap();
        auto_fib
            .iter()
            .map(|e| e.expires_at.saturating_duration_since(now) / 2)
            .min()
            .unwrap_or(Duration::from_secs(30))
            .max(BROWSE_FLOOR)
    }
}
