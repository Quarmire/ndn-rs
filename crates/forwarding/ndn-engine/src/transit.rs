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
//! the last one leaves; the first mark and the last unmark run the host's
//! action (it runs the namespace's sync group with the multicast strategy
//! meanwhile). A namespace this forwarder holds is never in transit: its
//! Data is validated whatever the marks say.

use std::collections::HashMap;
use std::sync::{PoisonError, RwLock};

use ndn_packet::Name;

/// Namespaces in transit, each counted by how many links hold it there.
#[derive(Debug, Default)]
pub struct TransitPrefixes {
    prefixes: RwLock<HashMap<Name, usize>>,
}

impl TransitPrefixes {
    /// One more reason to carry `prefix` in transit. The first one also
    /// runs `first`, under the lock: of a first `add` and a last
    /// [`remove`](Self::remove) racing, their actions happen in the order
    /// of their counts.
    pub fn add(&self, prefix: &Name, first: impl FnOnce()) {
        let mut prefixes = self
            .prefixes
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        let count = prefixes.entry(prefix.clone()).or_default();
        *count += 1;
        if *count == 1 {
            first();
        }
    }

    /// One reason less; the last one takes `prefix` out of transit and
    /// runs `last`, under the lock.
    pub fn remove(&self, prefix: &Name, last: impl FnOnce()) {
        let mut prefixes = self
            .prefixes
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = prefixes.get_mut(prefix) {
            *count -= 1;
            if *count == 0 {
                prefixes.remove(prefix);
                last();
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
        let (firsts, lasts) = (std::cell::Cell::new(0), std::cell::Cell::new(0));
        let first = || firsts.set(firsts.get() + 1);
        let last = || lasts.set(lasts.get() + 1);
        transit.add(&ns, first);
        transit.add(&ns, first);
        transit.remove(&ns, last);
        assert!(transit.covers(&data));
        assert_eq!((firsts.get(), lasts.get()), (1, 0));
        transit.remove(&ns, last);
        assert!(!transit.covers(&data));
        transit.remove(&ns, last);
        assert_eq!((firsts.get(), lasts.get()), (1, 1));
        assert!(!transit.covers(&"/rb/x".parse().unwrap()));
    }
}
