//! Policy for **unsolicited Data** — Data that arrives without a matching PIT
//! entry (e.g. overheard on a broadcast/ad-hoc medium, or a producer pushing
//! ahead of demand).
//!
//! NDN drops unsolicited Data by default: it was not requested, so forwarding
//! it would be unsolicited traffic, and admitting arbitrary bytes to the
//! Content Store is a cache-poisoning surface. But on a shared medium,
//! opportunistically caching overheard Data lets a later Interest be served
//! from the local CS instead of traversing the network — the central win of a
//! broadcast bearer.
//!
//! This mirrors NFD's `fw::UnsolicitedDataPolicy`
//! (`daemon/fw/unsolicited-data-policy.hpp`): the same four variants, the same
//! `DropAll` default, and the same scope-keyed decision. Admitted unsolicited
//! Data is **cached only, never forwarded** — there is no pending Interest to
//! satisfy. ndn-rs additionally keeps the fail-secure invariant that only
//! *verified* Data enters the CS, so an admitted packet still passes through
//! validation (see `data_pipeline`).

use ndn_transport::FaceScope;

/// Decision for a piece of unsolicited Data, keyed by the scope of the face it
/// arrived on. `DropAll` is the default and preserves pre-existing behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UnsolicitedDataPolicy {
    /// Never cache unsolicited Data (NFD `DropAllUnsolicitedDataPolicy`).
    #[default]
    DropAll,
    /// Cache only when it arrived on a local face (NFD `AdmitLocal`).
    AdmitLocal,
    /// Cache only when it arrived on a non-local (network) face
    /// (NFD `AdmitNetwork`). The right choice for a broadcast/ad-hoc bearer
    /// where overhearing peers' Data is the point.
    AdmitNetwork,
    /// Cache unconditionally (NFD `AdmitAll`).
    AdmitAll,
}

impl UnsolicitedDataPolicy {
    /// Whether unsolicited Data arriving on a face with `scope` should be
    /// admitted to the Content Store.
    pub fn admits(&self, scope: FaceScope) -> bool {
        match self {
            Self::DropAll => false,
            Self::AdmitLocal => scope == FaceScope::Local,
            Self::AdmitNetwork => scope == FaceScope::NonLocal,
            Self::AdmitAll => true,
        }
    }

    /// Parse the NFD-compatible config token (`drop-all`, `admit-local`,
    /// `admit-network`, `admit-all`). Returns `None` for an unknown token.
    pub fn from_token(s: &str) -> Option<Self> {
        match s {
            "drop-all" => Some(Self::DropAll),
            "admit-local" => Some(Self::AdmitLocal),
            "admit-network" => Some(Self::AdmitNetwork),
            "admit-all" => Some(Self::AdmitAll),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drop_all_admits_nothing() {
        let p = UnsolicitedDataPolicy::DropAll;
        assert!(!p.admits(FaceScope::Local));
        assert!(!p.admits(FaceScope::NonLocal));
    }

    #[test]
    fn admit_network_only_network() {
        let p = UnsolicitedDataPolicy::AdmitNetwork;
        assert!(!p.admits(FaceScope::Local));
        assert!(p.admits(FaceScope::NonLocal));
    }

    #[test]
    fn admit_local_only_local() {
        let p = UnsolicitedDataPolicy::AdmitLocal;
        assert!(p.admits(FaceScope::Local));
        assert!(!p.admits(FaceScope::NonLocal));
    }

    #[test]
    fn admit_all_admits_both() {
        let p = UnsolicitedDataPolicy::AdmitAll;
        assert!(p.admits(FaceScope::Local));
        assert!(p.admits(FaceScope::NonLocal));
    }

    #[test]
    fn from_token_roundtrip() {
        assert_eq!(
            UnsolicitedDataPolicy::from_token("drop-all"),
            Some(UnsolicitedDataPolicy::DropAll)
        );
        assert_eq!(
            UnsolicitedDataPolicy::from_token("admit-network"),
            Some(UnsolicitedDataPolicy::AdmitNetwork)
        );
        assert_eq!(UnsolicitedDataPolicy::from_token("bogus"), None);
        assert_eq!(
            UnsolicitedDataPolicy::default(),
            UnsolicitedDataPolicy::DropAll
        );
    }
}
