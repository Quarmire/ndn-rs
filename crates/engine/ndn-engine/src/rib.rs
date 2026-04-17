use std::collections::HashMap;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use ndn_packet::Name;
use ndn_transport::FaceId;

use crate::fib::{Fib, FibNexthop};

#[derive(Clone, Debug)]
pub struct RibRoute {
    pub face_id: FaceId,
    /// See `ndn_config::control_parameters::origin` for standard values.
    pub origin: u64,
    pub cost: u32,
    /// See `ndn_config::control_parameters::route_flags`.
    pub flags: u64,
    pub expires_at: Option<Instant>,
}

impl RibRoute {
    pub fn remaining(&self) -> Option<Duration> {
        self.expires_at
            .map(|exp| exp.saturating_duration_since(Instant::now()))
    }
}

/// The Routing Information Base.
///
/// # RIB-to-FIB computation
///
/// For each name prefix the RIB collapses all registered routes to a single
/// `FibEntry` by selecting, **per unique face_id**, the route with the lowest
/// cost (ties broken by lowest origin value). The resulting nexthop set is
/// atomically written to the FIB via [`Fib::set_nexthops`].
///
/// Discovery protocols write directly to the FIB via `EngineDiscoveryContext`
/// and are **not** tracked in the RIB.
pub struct Rib {
    routes: DashMap<Name, Vec<RibRoute>>,
}

impl Rib {
    pub fn new() -> Self {
        Self {
            routes: DashMap::new(),
        }
    }

    /// Returns `true` if the FIB should be recomputed for this prefix.
    pub fn add(&self, prefix: &Name, route: RibRoute) -> bool {
        let mut entry = self.routes.entry(prefix.clone()).or_default();
        let routes = entry.value_mut();
        if let Some(existing) = routes
            .iter_mut()
            .find(|r| r.face_id == route.face_id && r.origin == route.origin)
        {
            let changed = existing.cost != route.cost
                || existing.flags != route.flags
                || existing.expires_at != route.expires_at;
            *existing = route;
            changed
        } else {
            routes.push(route);
            true
        }
    }

    pub fn remove(&self, prefix: &Name, face_id: FaceId, origin: u64) -> bool {
        let Some(mut entry) = self.routes.get_mut(prefix) else {
            return false;
        };
        let before = entry.len();
        entry.retain(|r| !(r.face_id == face_id && r.origin == origin));
        let changed = entry.len() != before;
        if entry.is_empty() {
            drop(entry);
            self.routes.remove(prefix);
        }
        changed
    }

    pub fn remove_nexthop(&self, prefix: &Name, face_id: FaceId) -> bool {
        let Some(mut entry) = self.routes.get_mut(prefix) else {
            return false;
        };
        let before = entry.len();
        entry.retain(|r| r.face_id != face_id);
        let changed = entry.len() != before;
        if entry.is_empty() {
            drop(entry);
            self.routes.remove(prefix);
        }
        changed
    }

    pub fn flush_origin(&self, origin: u64) -> Vec<Name> {
        let mut affected = Vec::new();
        self.routes.retain(|name, routes| {
            let before = routes.len();
            routes.retain(|r| r.origin != origin);
            if routes.len() != before {
                affected.push(name.clone());
            }
            !routes.is_empty()
        });
        affected
    }

    pub fn flush_face(&self, face_id: FaceId) -> Vec<Name> {
        let mut affected = Vec::new();
        self.routes.retain(|name, routes| {
            let before = routes.len();
            routes.retain(|r| r.face_id != face_id);
            if routes.len() != before {
                affected.push(name.clone());
            }
            !routes.is_empty()
        });
        affected
    }

    pub fn drain_expired(&self) -> Vec<Name> {
        let now = Instant::now();
        let mut affected = Vec::new();
        self.routes.retain(|name, routes| {
            let before = routes.len();
            routes.retain(|r| r.expires_at.is_none_or(|exp| exp > now));
            if routes.len() != before {
                affected.push(name.clone());
            }
            !routes.is_empty()
        });
        affected
    }

    pub fn apply_to_fib(&self, prefix: &Name, fib: &Fib) {
        let Some(entry) = self.routes.get(prefix) else {
            fib.set_nexthops(prefix, Vec::new());
            return;
        };

        let mut best: HashMap<FaceId, (u32, u64)> = HashMap::new();
        for route in entry.iter() {
            let e = best.entry(route.face_id).or_insert((u32::MAX, u64::MAX));
            if route.cost < e.0 || (route.cost == e.0 && route.origin < e.1) {
                *e = (route.cost, route.origin);
            }
        }

        let nexthops: Vec<FibNexthop> = best
            .into_iter()
            .map(|(face_id, (cost, _))| FibNexthop { face_id, cost })
            .collect();

        fib.set_nexthops(prefix, nexthops);
    }

    /// Flush RIB routes via `face_id` and recompute affected FIB entries.
    ///
    /// Complementary to `Fib::remove_face` which handles discovery-managed
    /// routes not tracked in the RIB.
    pub fn handle_face_down(&self, face_id: FaceId, fib: &Fib) {
        let affected = self.flush_face(face_id);
        for prefix in &affected {
            self.apply_to_fib(prefix, fib);
        }
    }

    pub fn dump(&self) -> Vec<(Name, Vec<RibRoute>)> {
        self.routes
            .iter()
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect()
    }
}

impl Default for Rib {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use ndn_packet::NameComponent;

    fn name(s: &'static str) -> Name {
        Name::from_components([NameComponent::generic(Bytes::from_static(s.as_bytes()))])
    }

    fn route(face_id: u32, origin: u64, cost: u32) -> RibRoute {
        RibRoute {
            face_id: FaceId(face_id),
            origin,
            cost,
            flags: 0,
            expires_at: None,
        }
    }

    #[test]
    fn add_and_dump() {
        let rib = Rib::new();
        rib.add(&name("ndn"), route(1, 128, 5));
        let entries = rib.dump();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1.len(), 1);
    }

    #[test]
    fn add_updates_existing() {
        let rib = Rib::new();
        rib.add(&name("ndn"), route(1, 128, 5));
        rib.add(&name("ndn"), route(1, 128, 10));
        let entries = rib.dump();
        assert_eq!(entries[0].1.len(), 1);
        assert_eq!(entries[0].1[0].cost, 10);
    }

    #[test]
    fn multiple_origins_same_face() {
        let rib = Rib::new();
        rib.add(&name("ndn"), route(1, 128, 5)); // NLSR
        rib.add(&name("ndn"), route(1, 255, 100)); // STATIC
        let entries = rib.dump();
        assert_eq!(entries[0].1.len(), 2);
    }

    #[test]
    fn remove_by_face_and_origin() {
        let rib = Rib::new();
        rib.add(&name("ndn"), route(1, 128, 5));
        rib.add(&name("ndn"), route(1, 255, 100));
        rib.remove(&name("ndn"), FaceId(1), 128);
        let entries = rib.dump();
        // Static route remains
        assert_eq!(entries[0].1.len(), 1);
        assert_eq!(entries[0].1[0].origin, 255);
    }

    #[test]
    fn flush_origin_removes_matching() {
        let rib = Rib::new();
        rib.add(&name("a"), route(1, 128, 5));
        rib.add(&name("b"), route(2, 128, 10));
        rib.add(&name("a"), route(1, 255, 100));

        let affected = rib.flush_origin(128);
        assert_eq!(affected.len(), 2);
        // /a still has static route
        let entries = rib.dump();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1[0].origin, 255);
    }

    #[test]
    fn flush_face_removes_all_for_face() {
        let rib = Rib::new();
        rib.add(&name("a"), route(1, 128, 5));
        rib.add(&name("a"), route(2, 128, 10));
        rib.add(&name("b"), route(1, 128, 3));

        let affected = rib.flush_face(FaceId(1));
        assert_eq!(affected.len(), 2);
        // /a still has face 2
        let entries = rib.dump();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1[0].face_id, FaceId(2));
    }

    #[test]
    fn drain_expired_removes_stale() {
        let rib = Rib::new();
        let past = Instant::now() - Duration::from_secs(1);
        rib.add(
            &name("a"),
            RibRoute {
                face_id: FaceId(1),
                origin: 128,
                cost: 5,
                flags: 0,
                expires_at: Some(past),
            },
        );
        rib.add(&name("b"), route(2, 128, 10)); // permanent

        let affected = rib.drain_expired();
        assert_eq!(affected.len(), 1);
        assert_eq!(rib.dump().len(), 1);
    }
}
