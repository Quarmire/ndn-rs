use std::collections::HashMap;
use std::time::Duration;
use web_time::Instant;

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

    /// Effective FIB nexthops for `prefix`, honouring route flags. A prefix
    /// gets a FIB entry only if it has its own RIB routes; that entry is then
    /// augmented with routes inherited from ancestors carrying
    /// `CHILD_INHERIT` — unless `prefix`, or a nearer ancestor, carries
    /// `CAPTURE`, which blocks inheritance from above it. Per face, an own
    /// route takes precedence over an inherited one. (Pure-inheritance to
    /// unregistered prefixes is handled by FIB longest-prefix match.)
    fn effective_nexthops(&self, prefix: &Name) -> Vec<FibNexthop> {
        // Route-flag bits (ndn_config::control_parameters::route_flags;
        // ndn-cxx nfd-constants.hpp): CHILD_INHERIT=1, CAPTURE=2.
        const CHILD_INHERIT: u64 = 1;
        const CAPTURE: u64 = 2;

        let Some(own_entry) = self.routes.get(prefix) else {
            return Vec::new();
        };
        // Best own cost per face (ties → lowest origin), and whether this
        // prefix captures (blocks inheriting from ancestors).
        let mut best_own: HashMap<FaceId, (u32, u64)> = HashMap::new();
        let mut own_captures = false;
        for r in own_entry.iter() {
            own_captures |= r.flags & CAPTURE != 0;
            let e = best_own.entry(r.face_id).or_insert((u32::MAX, u64::MAX));
            if r.cost < e.0 || (r.cost == e.0 && r.origin < e.1) {
                *e = (r.cost, r.origin);
            }
        }
        drop(own_entry);

        // Inherited: walk strict ancestors nearest→farthest, collecting
        // CHILD_INHERIT routes; stop after a capturing ancestor.
        let mut best_inh: HashMap<FaceId, u32> = HashMap::new();
        if !own_captures {
            for n in (0..prefix.len()).rev() {
                let anc = Name::from_components(prefix.components()[..n].iter().cloned());
                let Some(routes) = self.routes.get(&anc) else {
                    continue;
                };
                let mut anc_captures = false;
                for r in routes.iter() {
                    anc_captures |= r.flags & CAPTURE != 0;
                    if r.flags & CHILD_INHERIT != 0 {
                        let e = best_inh.entry(r.face_id).or_insert(u32::MAX);
                        if r.cost < *e {
                            *e = r.cost;
                        }
                    }
                }
                if anc_captures {
                    break;
                }
            }
        }

        let mut nexthops: Vec<FibNexthop> = best_own
            .iter()
            .map(|(face_id, (cost, _))| FibNexthop {
                face_id: *face_id,
                cost: *cost,
            })
            .collect();
        for (face_id, cost) in best_inh {
            if !best_own.contains_key(&face_id) {
                nexthops.push(FibNexthop { face_id, cost });
            }
        }
        nexthops
    }

    /// Recompute the FIB for `prefix` **and every RIB descendant** — a change
    /// to a `CHILD_INHERIT`/`CAPTURE` route at `prefix` changes what its
    /// more-specific RIB entries inherit.
    pub fn apply_to_fib(&self, prefix: &Name, fib: &Fib) {
        fib.set_nexthops(prefix, self.effective_nexthops(prefix));
        let descendants: Vec<Name> = self
            .routes
            .iter()
            .map(|e| e.key().clone())
            .filter(|k| k != prefix && k.has_prefix(prefix))
            .collect();
        for d in descendants {
            fib.set_nexthops(&d, self.effective_nexthops(&d));
        }
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

    fn route(face_id: u64, origin: u64, cost: u32) -> RibRoute {
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

    fn nn(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn flagged(face_id: u64, cost: u32, flags: u64) -> RibRoute {
        RibRoute {
            face_id: FaceId(face_id),
            origin: 255,
            cost,
            flags,
            expires_at: None,
        }
    }

    fn faces_at(fib: &Fib, name: &str) -> Vec<u64> {
        let mut v: Vec<u64> = fib
            .lpm(&nn(name))
            .map(|e| e.nexthops.iter().map(|h| h.face_id.0).collect())
            .unwrap_or_default();
        v.sort_unstable();
        v
    }

    #[test]
    fn child_inherit_propagates_to_descendant_rib_entry() {
        const CHILD_INHERIT: u64 = 1;
        let rib = Rib::new();
        let fib = Fib::new();
        // /a → face1 (CHILD_INHERIT); /a/b → face2 (plain).
        rib.add(&nn("/a"), flagged(1, 10, CHILD_INHERIT));
        rib.add(&nn("/a/b"), flagged(2, 10, 0));
        rib.apply_to_fib(&nn("/a"), &fib);
        rib.apply_to_fib(&nn("/a/b"), &fib);

        assert_eq!(faces_at(&fib, "/a"), vec![1], "/a → its own face");
        // /a/b inherits /a's CHILD_INHERIT route on top of its own.
        assert_eq!(
            faces_at(&fib, "/a/b"),
            vec![1, 2],
            "/a/b must inherit face1 from /a plus its own face2"
        );
    }

    #[test]
    fn capture_blocks_inheritance() {
        const CHILD_INHERIT: u64 = 1;
        const CAPTURE: u64 = 2;
        let rib = Rib::new();
        let fib = Fib::new();
        // /a → face1 (CHILD_INHERIT); /a/b → face2 (CAPTURE).
        rib.add(&nn("/a"), flagged(1, 10, CHILD_INHERIT));
        rib.add(&nn("/a/b"), flagged(2, 10, CAPTURE));
        rib.apply_to_fib(&nn("/a"), &fib);

        assert_eq!(
            faces_at(&fib, "/a/b"),
            vec![2],
            "CAPTURE at /a/b must block inheriting face1 from /a"
        );
    }

    #[test]
    fn plain_ancestor_route_is_not_inherited() {
        let rib = Rib::new();
        let fib = Fib::new();
        // /a → face1 (no CHILD_INHERIT); /a/b → face2.
        rib.add(&nn("/a"), flagged(1, 10, 0));
        rib.add(&nn("/a/b"), flagged(2, 10, 0));
        rib.apply_to_fib(&nn("/a"), &fib);

        assert_eq!(
            faces_at(&fib, "/a/b"),
            vec![2],
            "without CHILD_INHERIT, /a's route is not pushed into /a/b"
        );
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
