//! Well-known prefix constants and scope checks. All discovery traffic
//! lives under `/ndn/local/` and is never forwarded beyond the link.

use std::str::FromStr;
use std::sync::OnceLock;

use ndn_packet::Name;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiscoveryScope {
    LinkLocal,
    Site,
    Global,
}

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

cached_name!(pub fn nd_root()      -> "/ndn/local/nd");
cached_name!(pub fn probe_ping()   -> "/ndn/local/nd/probe/ping");
cached_name!(pub fn peers_prefix()   -> "/ndn/local/nd/peers");
cached_name!(pub fn gossip_prefix()  -> "/ndn/local/nd/gossip");

cached_name!(pub fn localhop_autoconf_hub() -> "/localhop/ndn-autoconf/hub");

cached_name!(pub fn sd_root()     -> "/ndn/local/sd");

/// `<root>/services` — rendezvous namespace.
pub fn sd_services_under(root: &Name) -> Name {
    Name::from_str(&format!("{root}/services")).expect("invalid discovery root")
}

/// `<root>/service-info` — body Data namespace; shares the version
/// component with the rendezvous record.
pub fn sd_service_info_under(root: &Name) -> Name {
    Name::from_str(&format!("{root}/service-info")).expect("invalid discovery root")
}

/// `<root>/updates` — SVS sync namespace.
pub fn sd_updates_under(root: &Name) -> Name {
    Name::from_str(&format!("{root}/updates")).expect("invalid discovery root")
}

#[doc(hidden)]
cached_name!(pub fn sd_services() -> "/ndn/local/sd/services");
#[doc(hidden)]
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
    fn probe_ping_is_link_local() {
        assert!(is_link_local(probe_ping()));
    }

    #[test]
    fn nd_root_is_nd_packet() {
        assert!(is_nd_packet(&n("/ndn/local/nd/probe/ping/abc")));
        assert!(!is_nd_packet(&n("/ndn/local/sd/services")));
    }

    #[test]
    fn sd_root_is_sd_packet() {
        assert!(is_sd_packet(&n("/ndn/local/sd/services/foo")));
        assert!(!is_sd_packet(&n("/ndn/local/nd/probe/ping/abc")));
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
        assert!(!nd_root().has_prefix(sd_root()));
        assert!(!sd_root().has_prefix(nd_root()));
    }

    #[test]
    fn sd_services_under_matches_default() {
        assert_eq!(sd_services_under(sd_root()), *sd_services());
    }

    #[test]
    fn sd_updates_under_matches_default() {
        assert_eq!(sd_updates_under(sd_root()), *sd_updates());
    }

    #[test]
    fn sd_service_info_under_is_sibling_of_services() {
        let root = n("/ndn/local/sd");
        let svc = sd_services_under(&root);
        let info = sd_service_info_under(&root);
        // They share the root but differ at the last component.
        assert!(svc.has_prefix(&root));
        assert!(info.has_prefix(&root));
        assert_ne!(svc, info);
    }

    #[test]
    fn injectable_root_creates_disjoint_namespaces() {
        let root_a = n("/zone/a/sd");
        let root_b = n("/zone/b/sd");
        let svc_a = sd_services_under(&root_a);
        let svc_b = sd_services_under(&root_b);
        assert!(!svc_a.has_prefix(&svc_b));
        assert!(!svc_b.has_prefix(&svc_a));
    }
}
