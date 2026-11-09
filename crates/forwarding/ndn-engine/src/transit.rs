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
//!
//! Every forwarded Data is looked up here, so the lookup is a few hash
//! probes — one per distinct length of the namespaces held (a person's
//! `/user/<h>` is two components) — never a scan of the namespaces.

use std::collections::{BTreeMap, HashMap};
use std::sync::{PoisonError, RwLock};

use ndn_packet::{Name, NameComponent};

/// Namespaces in transit, each counted by how many links hold it there.
#[derive(Debug, Default)]
pub struct TransitPrefixes {
    held: RwLock<Held>,
}

/// The namespaces, keyed by their components, and how many of them have
/// each length: a Data name is probed at those lengths only.
#[derive(Debug, Default)]
struct Held {
    reasons: HashMap<Box<[NameComponent]>, usize>,
    lengths: BTreeMap<usize, usize>,
}

impl TransitPrefixes {
    /// One more reason to carry `prefix` in transit. The first one also
    /// runs `first`, under the lock: of a first `add` and a last
    /// [`remove`](Self::remove) racing, their actions happen in the order
    /// of their counts.
    pub fn add(&self, prefix: &Name, first: impl FnOnce()) {
        let mut guard = self.held.write().unwrap_or_else(PoisonError::into_inner);
        let held = &mut *guard;
        let count = held.reasons.entry(prefix.components().into()).or_default();
        *count += 1;
        if *count == 1 {
            *held.lengths.entry(prefix.len()).or_default() += 1;
            first();
        }
    }

    /// One reason less; the last one takes `prefix` out of transit and
    /// runs `last`, under the lock.
    pub fn remove(&self, prefix: &Name, last: impl FnOnce()) {
        let mut guard = self.held.write().unwrap_or_else(PoisonError::into_inner);
        let held = &mut *guard;
        let Some(count) = held.reasons.get_mut(prefix.components()) else {
            return;
        };
        *count -= 1;
        if *count == 0 {
            held.reasons.remove(prefix.components());
            if let Some(n) = held.lengths.get_mut(&prefix.len()) {
                *n -= 1;
                if *n == 0 {
                    held.lengths.remove(&prefix.len());
                }
            }
            last();
        }
    }

    /// Whether `name` is under a namespace in transit.
    pub fn covers(&self, name: &Name) -> bool {
        let held = self.held.read().unwrap_or_else(PoisonError::into_inner);
        let components = name.components();
        held.lengths
            .keys()
            .take_while(|&&len| len <= components.len())
            .any(|&len| held.reasons.contains_key(&components[..len]))
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

    /// A Data name is in transit exactly when one of the namespaces held
    /// is a prefix of it, whole components compared, whatever their
    /// lengths: a person's `/user/<h>` and a one-component namespace side
    /// by side, a sibling person's namespace never matching, and a
    /// namespace leaving taking only its own names with it.
    #[test]
    fn covers_matches_whole_components_of_any_held_length() {
        use ndn_security::self_certifying::self_certifying_name;
        let transit = TransitPrefixes::default();
        let carol = self_certifying_name(&[7; 32]);
        let dave = self_certifying_name(&[8; 32]);
        let ra: Name = "/ra".parse().unwrap();
        let under = |ns: &Name, rest: &str| ns.clone().append(rest);
        transit.add(&carol, || {});
        transit.add(&ra, || {});
        assert!(transit.covers(&under(&carol, "dev/32=data/x")));
        assert!(transit.covers(&carol), "the namespace's own name");
        assert!(transit.covers(&under(&ra, "member")));
        assert!(!transit.covers(&under(&dave, "dev")), "a sibling person");
        assert!(
            !transit.covers(&"/rab/x".parse().unwrap()),
            "a longer component"
        );
        assert!(
            !transit.covers(&"/user".parse().unwrap()),
            "shorter than any held"
        );
        assert!(!transit.covers(&Name::root()));
        transit.remove(&ra, || {});
        assert!(!transit.covers(&under(&ra, "member")));
        assert!(transit.covers(&under(&carol, "dev")));
        transit.add(&Name::root(), || {});
        assert!(
            transit.covers(&under(&dave, "dev")),
            "the root covers every name"
        );
    }
}
