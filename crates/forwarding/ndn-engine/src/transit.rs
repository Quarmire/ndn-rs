//! Namespaces this forwarder carries in **transit**: Data under them is
//! forwarded without validation, and never enters the Content Store.
//!
//! The forwarder validates every Data it forwards against the trust
//! contexts it holds. A relay that serves the devices of a namespace it
//! does not hold (its serving policy lists the namespace's root key, or
//! is open) cannot validate their Data: it holds neither their trust
//! context nor their certificates. Their Data is still signed, and the
//! devices that asked for it validate it; the relay forwards it as any NDN
//! router would, answering only pending Interests (unsolicited Data is
//! dropped as always), and caches none of it. The link layer marks such a
//! namespace while a device it serves for it is linked, and unmarks it when
//! the last one leaves. A namespace this forwarder holds is never in
//! transit: its Data is validated whatever the marks say.

use std::collections::HashMap;
use std::sync::{PoisonError, RwLock};

use ndn_packet::Name;

/// Namespaces in transit, each counted by how many links hold it there.
#[derive(Debug, Default)]
pub struct TransitPrefixes {
    prefixes: RwLock<HashMap<Name, usize>>,
}

impl TransitPrefixes {
    /// One more reason to carry `prefix` in transit.
    pub fn add(&self, prefix: &Name) {
        *self
            .prefixes
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(prefix.clone())
            .or_default() += 1;
    }

    /// One reason less; the last one takes `prefix` out of transit.
    pub fn remove(&self, prefix: &Name) {
        let mut prefixes = self
            .prefixes
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = prefixes.get_mut(prefix) {
            *count -= 1;
            if *count == 0 {
                prefixes.remove(prefix);
            }
        }
    }

    /// Whether `name` is under a namespace in transit.
    pub fn covers(&self, name: &Name) -> bool {
        let prefixes = self.prefixes.read().unwrap_or_else(PoisonError::into_inner);
        !prefixes.is_empty() && prefixes.keys().any(|p| name.has_prefix(p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_prefix_stays_in_transit_while_any_link_holds_it() {
        let transit = TransitPrefixes::default();
        let ns: Name = "/ra".parse().unwrap();
        let data: Name = "/ra/member/m1/x".parse().unwrap();
        transit.add(&ns);
        transit.add(&ns);
        transit.remove(&ns);
        assert!(transit.covers(&data));
        transit.remove(&ns);
        assert!(!transit.covers(&data));
        assert!(!transit.covers(&"/rb/x".parse().unwrap()));
    }
}
