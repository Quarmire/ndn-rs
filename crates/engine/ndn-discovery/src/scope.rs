//! Well-known prefix constants and scope enforcement.
//!
//! All discovery traffic lives under `/ndn/local/` (never forwarded beyond
//! the local link, analogous to IPv6 `fe80::/10`).

use std::str::FromStr;
use std::sync::OnceLock;

use ndn_packet::Name;

use crate::config::DiscoveryScope;

/// Build and cache a `Name` from a string literal (parsed once at first use).
macro_rules! cached_name {
    ($vis:vis fn $fn:ident() -> $s:literal) => {
        $vis fn $fn() -> &'static Name {
            static CELL: OnceLock<Name> = OnceLock::new();
            CELL.get_or_init(|| {
                Name::from_str($s).expect(concat!("invalid well-known name: ", $s))
            })
        }
    };
}

cached_name!(pub fn ndn_local() -> "/ndn/local");

cached_name!(pub fn nd_root()        -> "/ndn/local/nd");
cached_name!(pub fn hello_prefix()   -> "/ndn/local/nd/hello");
cached_name!(pub fn probe_direct()   -> "/ndn/local/nd/probe/direct");
cached_name!(pub fn probe_via()      -> "/ndn/local/nd/probe/via");
cached_name!(pub fn peers_prefix()   -> "/ndn/local/nd/peers");
cached_name!(pub fn gossip_prefix()  -> "/ndn/local/nd/gossip");

cached_name!(pub fn sd_root()     -> "/ndn/local/sd");
cached_name!(pub fn sd_services() -> "/ndn/local/sd/services");
cached_name!(pub fn sd_updates()  -> "/ndn/local/sd/updates");

cached_name!(pub fn routing_lsa()    -> "/ndn/local/routing/lsa");
cached_name!(pub fn routing_prefix() -> "/ndn/local/routing/prefix");

cached_name!(pub fn mgmt_prefix() -> "/ndn/local/mgmt");

cached_name!(pub fn site_root()   -> "/ndn/site");
cached_name!(pub fn global_root() -> "/ndn/global");

pub fn scope_root(scope: &DiscoveryScope) -> &'static Name {
    match scope {
        DiscoveryScope::LinkLocal => ndn_local(),
        DiscoveryScope::Site => site_root(),
        DiscoveryScope::Global => global_root(),
    }
}

#[inline]
pub fn is_link_local(name: &Name) -> bool {
    name.has_prefix(ndn_local())
}

#[inline]
pub fn is_nd_packet(name: &Name) -> bool {
    name.has_prefix(nd_root())
}

#[inline]
pub fn is_sd_packet(name: &Name) -> bool {
    name.has_prefix(sd_root())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ndn_packet::Name;

    use super::*;

    fn n(s: &str) -> Name {
        Name::from_str(s).unwrap()
    }

    #[test]
    fn hello_prefix_is_link_local() {
        assert!(is_link_local(hello_prefix()));
    }

    #[test]
    fn nd_root_is_nd_packet() {
        assert!(is_nd_packet(&n("/ndn/local/nd/hello/abc")));
        assert!(!is_nd_packet(&n("/ndn/local/sd/services")));
    }

    #[test]
    fn sd_root_is_sd_packet() {
        assert!(is_sd_packet(&n("/ndn/local/sd/services/foo")));
        assert!(!is_sd_packet(&n("/ndn/local/nd/hello/abc")));
    }

    #[test]
    fn non_local_is_not_link_local() {
        assert!(!is_link_local(&n("/ndn/edu/ucla/cs")));
    }

    #[test]
    fn scope_root_returns_correct_prefix() {
        assert_eq!(scope_root(&DiscoveryScope::LinkLocal), ndn_local());
        assert_eq!(scope_root(&DiscoveryScope::Site), site_root());
        assert_eq!(scope_root(&DiscoveryScope::Global), global_root());
    }

    #[test]
    fn nd_and_sd_are_disjoint() {
        // Neither is a prefix of the other.
        assert!(!nd_root().has_prefix(sd_root()));
        assert!(!sd_root().has_prefix(nd_root()));
    }
}
