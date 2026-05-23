//! Reflexive-forwarding reverse-route table
//! (`draft-oran-icnrg-reflexive-forwarding`).
//!
//! When an Interest carrying a [`reflexive_name`](ndn_packet::Interest::reflexive_name)
//! `R` arrives on face `F`, the forwarder installs a temporary reverse route
//! `R -> F`. A later Interest the producer issues *under* `R` longest-prefix
//! matches that route and is forwarded back along `F` — the exact inverse of
//! the path the original Interest came in on.
//!
//! Tunables (`enabled`, `max_per_face`, `max_lifetime`) are runtime-mutable so
//! the `/localhost/nfd/reflexive` management module can toggle and re-cap the
//! capability live; counters back its status dataset.
//!
//! Witnessed invariants (`testbed/tests/audit/rf*.sh` / the unit tests below):
//!
//! - **W-RF-1 backward-only.** A route can only point at the face the Interest
//!   arrived on; a different face cannot hijack an existing reflexive name.
//! - **W-RF-3 bounded lifetime.** Routes expire no later than `max_lifetime`;
//!   [`sweep`](ReflexiveTable::sweep) drops expired, [`remove`](ReflexiveTable::remove)
//!   frees on satisfy.
//! - **W-RF-4 per-face cap.** Installs beyond `max_per_face` are refused.
//! - **W-RF-6 monotonic face identity.** Routes store a [`FaceId`], never recycled.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use dashmap::DashMap;
use web_time::{SystemTime, UNIX_EPOCH};

use ndn_packet::Name;
use ndn_store::NameTrie;
use ndn_transport::FaceId;

/// Boot-time defaults for the reflexive-route table. Each field is also
/// runtime-mutable via the management module once the table is live.
#[derive(Clone, Copy, Debug)]
pub struct ReflexiveConfig {
    /// Whether reflexive forwarding is active at start-up.
    pub enabled: bool,
    /// Maximum live reverse routes per incoming face (W-RF-4).
    pub max_per_face: usize,
    /// Upper bound on a route's lifetime regardless of the requesting
    /// Interest's declared lifetime (W-RF-3 ceiling).
    pub max_lifetime: Duration,
}

impl Default for ReflexiveConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_per_face: 256,
            max_lifetime: Duration::from_secs(8),
        }
    }
}

/// Observable state of the reflexive-route table (the `reflexive/info` dataset).
#[derive(Clone, Copy, Debug)]
pub struct ReflexiveStatus {
    pub enabled: bool,
    pub max_per_face: usize,
    pub max_lifetime_ms: u64,
    /// Live (not-yet-expired) reverse routes.
    pub live_routes: usize,
    /// Total routes installed since start.
    pub installs: u64,
    /// Installs refused (disabled, per-face cap, or face collision).
    pub refused: u64,
    /// Routes dropped by expiry sweep.
    pub expired: u64,
    /// Reverse Interests that matched a live route.
    pub lookup_hits: u64,
}

#[derive(Clone, Copy, Debug)]
struct ReflexiveRoute {
    face_id: FaceId,
    expiry_ns: u64,
}

/// Temporary reverse routes keyed by reflexive name, with longest-prefix match.
pub struct ReflexiveTable {
    routes: NameTrie<Arc<ReflexiveRoute>>,
    per_face: DashMap<FaceId, usize>,
    /// Live route count — lets the hot path skip the trie lookup when reflexive
    /// forwarding is unused (the common case).
    live: AtomicUsize,
    enabled: AtomicBool,
    max_per_face: AtomicUsize,
    max_lifetime_ns: AtomicU64,
    installs: AtomicU64,
    refused: AtomicU64,
    expired: AtomicU64,
    lookup_hits: AtomicU64,
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

impl ReflexiveTable {
    pub fn new(config: ReflexiveConfig) -> Self {
        Self {
            routes: NameTrie::new(),
            per_face: DashMap::new(),
            live: AtomicUsize::new(0),
            enabled: AtomicBool::new(config.enabled),
            max_per_face: AtomicUsize::new(config.max_per_face),
            max_lifetime_ns: AtomicU64::new(config.max_lifetime.as_nanos() as u64),
            installs: AtomicU64::new(0),
            refused: AtomicU64::new(0),
            expired: AtomicU64::new(0),
            lookup_hits: AtomicU64::new(0),
        }
    }

    /// Whether any reverse routes are live — a cheap hot-path guard.
    pub fn is_empty(&self) -> bool {
        self.live.load(Ordering::Relaxed) == 0
    }

    /// Whether new reflexive routes are being accepted.
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Enable or disable installing new reverse routes. Disabling is a graceful
    /// drain: existing routes keep being served until they expire (so in-flight
    /// handshakes complete); use [`flush`](Self::flush) for an immediate stop.
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    /// Update the per-face route cap (W-RF-4). Existing routes above the new cap
    /// are left to expire; only new installs are bound by it.
    pub fn set_max_per_face(&self, max: usize) {
        self.max_per_face.store(max, Ordering::Relaxed);
    }

    /// Update the route-lifetime ceiling (W-RF-3). Applies to new installs.
    pub fn set_max_lifetime(&self, max: Duration) {
        self.max_lifetime_ns
            .store(max.as_nanos() as u64, Ordering::Relaxed);
    }

    /// Install (or refresh) a reverse route `reflexive_name -> face_id`, living
    /// for `min(lifetime, max_lifetime)`. Returns `false` if reflexive
    /// forwarding is disabled, the per-face cap is hit (W-RF-4), or a different
    /// face already holds this name (W-RF-1 backward-only). Refreshing an
    /// existing route from the same face never counts against the cap.
    pub fn install(&self, reflexive_name: &Name, face_id: FaceId, lifetime: Duration) -> bool {
        if !self.enabled.load(Ordering::Relaxed) {
            self.refused.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let max_lifetime = Duration::from_nanos(self.max_lifetime_ns.load(Ordering::Relaxed));
        let ttl = lifetime.min(max_lifetime);
        let expiry_ns = now_ns().saturating_add(ttl.as_nanos() as u64);

        if let Some(existing) = self.routes.get(reflexive_name) {
            if existing.face_id != face_id {
                self.refused.fetch_add(1, Ordering::Relaxed);
                return false;
            }
            self.routes
                .insert(reflexive_name, Arc::new(ReflexiveRoute { face_id, expiry_ns }));
            return true;
        }

        let mut count = self.per_face.entry(face_id).or_insert(0);
        if *count >= self.max_per_face.load(Ordering::Relaxed) {
            self.refused.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        *count += 1;
        drop(count);

        self.routes
            .insert(reflexive_name, Arc::new(ReflexiveRoute { face_id, expiry_ns }));
        self.live.fetch_add(1, Ordering::Relaxed);
        self.installs.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Longest-prefix-match `name` against the live reverse routes. Expired
    /// routes are treated as absent. Served even while disabled (graceful
    /// drain).
    pub fn lookup(&self, name: &Name) -> Option<FaceId> {
        let route = self.routes.lpm(name)?;
        if route.expiry_ns <= now_ns() {
            return None;
        }
        self.lookup_hits.fetch_add(1, Ordering::Relaxed);
        Some(route.face_id)
    }

    /// Remove the route for `reflexive_name` (e.g. on satisfy). No-op if absent.
    pub fn remove(&self, reflexive_name: &Name) {
        if let Some(route) = self.routes.get(reflexive_name) {
            self.routes.remove(reflexive_name);
            self.decrement(route.face_id);
            self.live.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Drop every route pointing at `face_id` (face teardown).
    pub fn remove_face(&self, face_id: FaceId) {
        let mut removed = 0;
        for (name, route) in self.routes.dump() {
            if route.face_id == face_id {
                self.routes.remove(&name);
                removed += 1;
            }
        }
        self.per_face.remove(&face_id);
        self.live.fetch_sub(removed, Ordering::Relaxed);
    }

    /// Drop expired routes. Returns the number removed.
    pub fn sweep(&self) -> usize {
        let now = now_ns();
        let mut removed = 0;
        for (name, route) in self.routes.dump() {
            if route.expiry_ns <= now {
                self.routes.remove(&name);
                self.decrement(route.face_id);
                removed += 1;
            }
        }
        self.live.fetch_sub(removed, Ordering::Relaxed);
        self.expired.fetch_add(removed as u64, Ordering::Relaxed);
        removed
    }

    /// Immediately drop *all* reverse routes (the management `flush` verb).
    /// Returns the number removed. Abrupt: breaks any in-flight handshakes.
    pub fn flush(&self) -> usize {
        let all: Vec<Name> = self.routes.dump().into_iter().map(|(n, _)| n).collect();
        let removed = all.len();
        for name in all {
            self.routes.remove(&name);
        }
        self.per_face.clear();
        self.live.store(0, Ordering::Relaxed);
        removed
    }

    /// Snapshot for the management status dataset.
    pub fn status(&self) -> ReflexiveStatus {
        ReflexiveStatus {
            enabled: self.enabled.load(Ordering::Relaxed),
            max_per_face: self.max_per_face.load(Ordering::Relaxed),
            max_lifetime_ms: self.max_lifetime_ns.load(Ordering::Relaxed) / 1_000_000,
            live_routes: self.live.load(Ordering::Relaxed),
            installs: self.installs.load(Ordering::Relaxed),
            refused: self.refused.load(Ordering::Relaxed),
            expired: self.expired.load(Ordering::Relaxed),
            lookup_hits: self.lookup_hits.load(Ordering::Relaxed),
        }
    }

    /// Live route count for `face_id` (test/observability).
    pub fn route_count(&self, face_id: FaceId) -> usize {
        self.per_face.get(&face_id).map(|c| *c).unwrap_or(0)
    }

    fn decrement(&self, face_id: FaceId) {
        if let Some(mut c) = self.per_face.get_mut(&face_id) {
            *c = c.saturating_sub(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(max_per_face: usize, max_lifetime: Duration) -> ReflexiveConfig {
        ReflexiveConfig {
            enabled: true,
            max_per_face,
            max_lifetime,
        }
    }

    fn name(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[test]
    fn install_then_lookup_lpm() {
        let t = ReflexiveTable::new(ReflexiveConfig::default());
        assert!(t.install(&name("/rfx/abc"), FaceId(7), Duration::from_secs(4)));
        assert_eq!(t.lookup(&name("/rfx/abc")), Some(FaceId(7)));
        assert_eq!(t.lookup(&name("/rfx/abc/params")), Some(FaceId(7)));
        assert_eq!(t.lookup(&name("/rfx/other")), None);
    }

    #[test]
    fn collision_from_different_face_refused() {
        let t = ReflexiveTable::new(ReflexiveConfig::default());
        assert!(t.install(&name("/rfx/x"), FaceId(1), Duration::from_secs(4)));
        assert!(!t.install(&name("/rfx/x"), FaceId(2), Duration::from_secs(4)));
        assert_eq!(t.lookup(&name("/rfx/x")), Some(FaceId(1)));
    }

    #[test]
    fn expired_route_not_returned_and_swept() {
        let t = ReflexiveTable::new(ReflexiveConfig::default());
        t.install(&name("/rfx/exp"), FaceId(3), Duration::from_nanos(0));
        assert_eq!(t.lookup(&name("/rfx/exp")), None);
        assert_eq!(t.sweep(), 1);
        assert_eq!(t.route_count(FaceId(3)), 0);
    }

    #[test]
    fn lifetime_capped_by_config() {
        let t = ReflexiveTable::new(cfg(256, Duration::from_nanos(0)));
        t.install(&name("/rfx/y"), FaceId(1), Duration::from_secs(3600));
        assert_eq!(t.lookup(&name("/rfx/y")), None);
    }

    #[test]
    fn per_face_cap_refuses_excess() {
        let t = ReflexiveTable::new(cfg(2, Duration::from_secs(8)));
        assert!(t.install(&name("/rfx/1"), FaceId(9), Duration::from_secs(4)));
        assert!(t.install(&name("/rfx/2"), FaceId(9), Duration::from_secs(4)));
        assert!(!t.install(&name("/rfx/3"), FaceId(9), Duration::from_secs(4)));
        assert_eq!(t.route_count(FaceId(9)), 2);
        assert_eq!(t.lookup(&name("/rfx/3")), None);
    }

    #[test]
    fn remove_frees_cap_slot() {
        let t = ReflexiveTable::new(cfg(1, Duration::from_secs(8)));
        assert!(t.install(&name("/rfx/a"), FaceId(1), Duration::from_secs(4)));
        assert!(!t.install(&name("/rfx/b"), FaceId(1), Duration::from_secs(4)));
        t.remove(&name("/rfx/a"));
        assert_eq!(t.route_count(FaceId(1)), 0);
        assert!(t.install(&name("/rfx/b"), FaceId(1), Duration::from_secs(4)));
    }

    #[test]
    fn remove_face_drops_all_its_routes() {
        let t = ReflexiveTable::new(ReflexiveConfig::default());
        t.install(&name("/rfx/a"), FaceId(1), Duration::from_secs(4));
        t.install(&name("/rfx/b"), FaceId(1), Duration::from_secs(4));
        t.install(&name("/rfx/c"), FaceId(2), Duration::from_secs(4));
        t.remove_face(FaceId(1));
        assert_eq!(t.lookup(&name("/rfx/a")), None);
        assert_eq!(t.lookup(&name("/rfx/b")), None);
        assert_eq!(t.lookup(&name("/rfx/c")), Some(FaceId(2)));
        assert_eq!(t.route_count(FaceId(1)), 0);
    }

    #[test]
    fn is_empty_tracks_live_routes() {
        let t = ReflexiveTable::new(ReflexiveConfig::default());
        assert!(t.is_empty());
        t.install(&name("/rfx/a"), FaceId(1), Duration::from_secs(4));
        t.install(&name("/rfx/b"), FaceId(1), Duration::from_secs(4));
        assert!(!t.is_empty());
        t.install(&name("/rfx/a"), FaceId(1), Duration::from_secs(4));
        t.remove(&name("/rfx/a"));
        assert!(!t.is_empty());
        t.remove(&name("/rfx/b"));
        assert!(t.is_empty());
    }

    #[test]
    fn disabled_refuses_new_but_serves_existing() {
        // Graceful drain: an existing route is still looked up after disable,
        // but new installs are refused.
        let t = ReflexiveTable::new(ReflexiveConfig::default());
        assert!(t.install(&name("/rfx/live"), FaceId(1), Duration::from_secs(4)));
        t.set_enabled(false);
        assert!(!t.is_enabled());
        assert!(!t.install(&name("/rfx/new"), FaceId(1), Duration::from_secs(4)));
        assert_eq!(t.lookup(&name("/rfx/live")), Some(FaceId(1)));
        t.set_enabled(true);
        assert!(t.install(&name("/rfx/new"), FaceId(1), Duration::from_secs(4)));
    }

    #[test]
    fn flush_clears_all_routes_immediately() {
        let t = ReflexiveTable::new(ReflexiveConfig::default());
        t.install(&name("/rfx/a"), FaceId(1), Duration::from_secs(4));
        t.install(&name("/rfx/b"), FaceId(2), Duration::from_secs(4));
        assert_eq!(t.flush(), 2);
        assert!(t.is_empty());
        assert_eq!(t.lookup(&name("/rfx/a")), None);
        assert_eq!(t.route_count(FaceId(1)), 0);
    }

    #[test]
    fn runtime_cap_change_takes_effect() {
        let t = ReflexiveTable::new(cfg(1, Duration::from_secs(8)));
        assert!(t.install(&name("/rfx/1"), FaceId(1), Duration::from_secs(4)));
        assert!(!t.install(&name("/rfx/2"), FaceId(1), Duration::from_secs(4)));
        t.set_max_per_face(2);
        assert!(t.install(&name("/rfx/2"), FaceId(1), Duration::from_secs(4)));
    }

    #[test]
    fn status_reports_counters() {
        let t = ReflexiveTable::new(cfg(1, Duration::from_secs(8)));
        t.install(&name("/rfx/a"), FaceId(1), Duration::from_secs(4));
        t.install(&name("/rfx/b"), FaceId(1), Duration::from_secs(4)); // refused (cap)
        t.lookup(&name("/rfx/a"));
        let s = t.status();
        assert!(s.enabled);
        assert_eq!(s.max_per_face, 1);
        assert_eq!(s.live_routes, 1);
        assert_eq!(s.installs, 1);
        assert_eq!(s.refused, 1);
        assert_eq!(s.lookup_hits, 1);
    }
}
