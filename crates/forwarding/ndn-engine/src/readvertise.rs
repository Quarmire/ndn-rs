//! Readvertise: propagate locally-originated prefix registrations to a
//! routing protocol (or upstream gateway) so a remote node can reach an
//! app's prefix without manual config — NFD `rib/readvertise/`.
//!
//! The RIB calls [`Rib::readvertise_announce`](crate::Rib::readvertise_announce)
//! / [`Rib::readvertise_withdraw`](crate::Rib::readvertise_withdraw) when a
//! route is registered/unregistered through management. A registered
//! [`ReadvertiseDestination`] (e.g. NLSR's [`ReadvertisedPrefixes`]) then
//! announces the prefix into the routing plane. The origin-based
//! [`should_readvertise`] policy readvertises only *locally-originated*
//! registrations (app/client/static), never routes a routing protocol
//! itself installed — which is what keeps an announce from looping back.

use std::collections::BTreeSet;
use std::sync::Mutex;

use ndn_packet::Name;
use tokio::sync::Notify;

/// A sink for locally-originated prefixes to be propagated into the routing
/// plane. Implemented by a routing protocol (NLSR/DV) or a gateway
/// readvertiser.
pub trait ReadvertiseDestination: Send + Sync {
    /// Begin advertising `prefix` (idempotent).
    fn advertise(&self, prefix: &Name);
    /// Stop advertising `prefix` (idempotent).
    fn withdraw(&self, prefix: &Name);
}

/// Whether a RIB registration with this `origin` should be readvertised.
///
/// `true` for locally-originated registrations — `APP` (0), `AUTOREG` (64),
/// `CLIENT` (65), `STATIC` (255) — and `false` for routing-plane-learned
/// routes — `AUTOCONF` (66), `DVR` (127), `NLSR` (128), `PREFIX_ANN` (129).
/// Excluding routing origins is the loop-prevention: a prefix NLSR installed
/// from a peer's LSA must not be re-announced as locally-originated.
/// (Values mirror `ndn_config::control_parameters::origin`.)
pub fn should_readvertise(origin: u64) -> bool {
    const APP: u64 = 0;
    const AUTOREG: u64 = 64;
    const CLIENT: u64 = 65;
    const STATIC: u64 = 255;
    matches!(origin, APP | AUTOREG | CLIENT | STATIC)
}

/// A concrete [`ReadvertiseDestination`] holding the current set of
/// readvertised prefixes, with change notification. A routing protocol
/// registers one with the RIB, then merges [`snapshot`](Self::snapshot) into
/// what it announces, re-originating whenever [`changed`](Self::changed)
/// fires.
#[derive(Default)]
pub struct ReadvertisedPrefixes {
    set: Mutex<BTreeSet<Name>>,
    notify: Notify,
}

impl ReadvertisedPrefixes {
    pub fn new() -> Self {
        Self::default()
    }

    /// The current readvertised prefix set, in canonical name order.
    pub fn snapshot(&self) -> Vec<Name> {
        self.set
            .lock()
            .expect("readvertise set poisoned")
            .iter()
            .cloned()
            .collect()
    }

    /// Resolve once the set changes (a prefix was added or removed). A
    /// consumer awaits this to re-originate promptly.
    pub async fn changed(&self) {
        self.notify.notified().await;
    }

    /// Whether the set is empty (introspection/tests).
    pub fn is_empty(&self) -> bool {
        self.set
            .lock()
            .expect("readvertise set poisoned")
            .is_empty()
    }
}

impl ReadvertiseDestination for ReadvertisedPrefixes {
    fn advertise(&self, prefix: &Name) {
        let inserted = self
            .set
            .lock()
            .expect("readvertise set poisoned")
            .insert(prefix.clone());
        if inserted {
            self.notify.notify_one();
        }
    }

    fn withdraw(&self, prefix: &Name) {
        let removed = self
            .set
            .lock()
            .expect("readvertise set poisoned")
            .remove(prefix);
        if removed {
            self.notify.notify_one();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_readvertises_local_origins_only() {
        // Local registrations propagate.
        assert!(should_readvertise(0)); // APP
        assert!(should_readvertise(64)); // AUTOREG
        assert!(should_readvertise(65)); // CLIENT
        assert!(should_readvertise(255)); // STATIC
        // Routing-plane origins do NOT (loop prevention).
        assert!(!should_readvertise(66)); // AUTOCONF
        assert!(!should_readvertise(127)); // DVR
        assert!(!should_readvertise(128)); // NLSR
        assert!(!should_readvertise(129)); // PREFIX_ANN
    }

    #[test]
    fn prefixes_accumulate_and_dedupe() {
        let r = ReadvertisedPrefixes::new();
        assert!(r.is_empty());
        let a: Name = "/app/a".parse().unwrap();
        let b: Name = "/app/b".parse().unwrap();
        r.advertise(&a);
        r.advertise(&a); // idempotent
        r.advertise(&b);
        assert_eq!(r.snapshot(), vec![a.clone(), b.clone()]);
        r.withdraw(&a);
        assert_eq!(r.snapshot(), vec![b]);
    }

    #[tokio::test]
    async fn changed_fires_on_advertise() {
        let r = ReadvertisedPrefixes::new();
        let p: Name = "/app/x".parse().unwrap();
        // notify_one stores a permit, so an advertise before `changed()` is
        // still observed.
        r.advertise(&p);
        tokio::time::timeout(std::time::Duration::from_secs(1), r.changed())
            .await
            .expect("changed must fire after advertise");
    }
}
