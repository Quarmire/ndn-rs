//! Namespace sync groups, forwarded with no configuration (data-layer spec
//! §12, `docs/specs/data-layer.md`).
//!
//! Namespace `/<O>` (one component) has one sync group, `/<O>/32=sync`: State
//! Vector Sync Interests that must reach every member of the group. A member
//! registers the group prefix for its own sync face, and as the longest match
//! that entry hides every shorter route; the routes a forwarder has toward the
//! namespace's other devices (ndn-link routes a linked device by its device
//! name, `/<O>/…/<device>`) are not prefixes of the group at all. So the group
//! is not left to longest-prefix match. A forwarder **carries** the group when
//! it has a face registered at or under the group prefix, or a link (a
//! non-local face) routed at or under `/<O>`; it then sends each Interest of
//! the group, with the multicast strategy, to
//!
//! - every face registered at or under the group prefix: the members on this
//!   node, and any link a route of the group itself names;
//! - every link routed at or under `/<O>` (the namespace's devices and
//!   relays), or at a prefix of it (a default route);
//! - every link one of the group's Interests arrived on, while that face is
//!   up: how a member of another namespace is reached, toward which this
//!   forwarder has no route into `/<O>`.
//!
//! A neighbour reached over two datagram faces is sent one copy (the
//! stage's peer-host rule), and the strategy excludes the face the Interest
//! came from.
//! A forwarder that carries the group neither for a member nor toward the
//! namespace — a hub holding default routes only — forwards it like any other
//! name.

use std::sync::Arc;

use dashmap::DashMap;
use ndn_packet::{Name, tlv_type};
use ndn_strategy::{ErasedStrategy, FibEntry, FibNexthop, MulticastStrategy};
use ndn_transport::face::FaceScope;
use ndn_transport::{FaceId, FaceTable};
use smallvec::SmallVec;

use super::strategy::peer_host;
use crate::Fib;

/// The keyword of a namespace's sync group: `/<O>/32=sync`.
const SYNC: &[u8] = b"sync";

/// The sync group `name` lies in: `/<O>/32=sync` when its second component is
/// the keyword `sync`.
pub(crate) fn group_prefix(name: &Name) -> Option<Name> {
    let comps = name.components();
    let kw = comps.get(1)?;
    (kw.typ == tlv_type::KEYWORD && kw.value.as_ref() == SYNC)
        .then(|| Name::from_components(comps[..2].iter().cloned()))
}

/// The links each group's Interests arrived on, and the strategy the groups
/// run.
pub struct SyncGroups {
    heard: DashMap<Name, SmallVec<[FaceId; 4]>>,
    multicast: Arc<dyn ErasedStrategy>,
}

impl Default for SyncGroups {
    fn default() -> Self {
        Self {
            heard: DashMap::new(),
            multicast: Arc::new(MulticastStrategy::new()),
        }
    }
}

impl SyncGroups {
    /// The strategy every group's Interests run.
    pub(crate) fn strategy(&self) -> &Arc<dyn ErasedStrategy> {
        &self.multicast
    }

    /// Where an Interest of `group` that arrived on `in_face` goes at this
    /// node (see the module docs), the face it came from among them; `None`
    /// when this node does not carry the group. A link it arrived on is
    /// remembered for the group while that face is up.
    pub(crate) fn nexthops(
        &self,
        group: &Name,
        in_face: FaceId,
        fib: &Fib,
        faces: &FaceTable,
    ) -> Option<FibEntry> {
        let is_link = |id: FaceId| {
            faces
                .get(id)
                .is_some_and(|f| f.scope() == FaceScope::NonLocal)
        };
        let namespace = Name::from_components(group.components()[..1].iter().cloned());
        let mut hops: Vec<FibNexthop> = Vec::new();
        let mut carries = false;
        fib.visit_around(&namespace, |path, entry| {
            let in_group = path.len() >= group.len() && path[..group.len()] == *group.components();
            let into_namespace = !path.is_empty();
            for hop in &entry.nexthops {
                let member = in_group && faces.get(hop.face_id).is_some();
                if member || is_link(hop.face_id) {
                    carries |= member || into_namespace;
                    hops.push(FibNexthop {
                        face_id: hop.face_id,
                        cost: hop.cost,
                    });
                }
            }
        });
        if !carries {
            return None;
        }
        {
            let mut heard = self.heard.entry(group.clone()).or_default();
            heard.retain(|id| faces.get(*id).is_some());
            if is_link(in_face) && !heard.contains(&in_face) {
                heard.push(in_face);
                tracing::debug!(target: "fwd.strategy", group = %group, face = in_face.0, "sync group: heard a member over this link");
            }
            hops.extend(heard.iter().map(|&face_id| FibNexthop { face_id, cost: 0 }));
        }
        self.heard.remove_if(group, |_, heard| heard.is_empty());

        // One copy per neighbour, chosen the same way on every run.
        hops.sort_by_key(|hop| hop.face_id.0);
        hops.dedup_by_key(|hop| hop.face_id);
        let mut hosts: SmallVec<[String; 4]> = SmallVec::new();
        hops.retain(|hop| match peer_host(faces, hop.face_id) {
            Some(host) if hosts.contains(&host) => false,
            Some(host) => {
                hosts.push(host);
                true
            }
            None => true,
        });
        Some(FibEntry { nexthops: hops })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use ndn_face_local::InProcFace;
    use ndn_packet::NameComponent;
    use ndn_transport::FaceKind;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn group(ns: &str) -> Name {
        n(ns).append_component(NameComponent::keyword(Bytes::from_static(SYNC)))
    }

    /// A face table holding a local face for each of `local` and a link for
    /// each of `links`.
    fn table(local: &[u64], links: &[u64]) -> FaceTable {
        let t = FaceTable::new();
        for &id in local {
            t.insert(InProcFace::new(FaceId(id), 1).0);
        }
        for &id in links {
            t.insert(InProcFace::new_kind(FaceId(id), 1, FaceKind::Udp).0);
        }
        t
    }

    fn faces(entry: Option<FibEntry>) -> Vec<u64> {
        entry
            .expect("the node carries the group")
            .nexthops
            .iter()
            .map(|h| h.face_id.0)
            .collect()
    }

    const SYNC_FACE: u64 = 1;
    const CA_FACE: u64 = 2;
    const PHONE: u64 = 10;
    const DEFAULT: u64 = 11;
    const OTHER: u64 = 12;
    const FOREIGN: u64 = 13;

    /// The member's own registration of the group does not hide the links
    /// toward the namespace: the device-name route under it, the default
    /// route above it. A local face routed in the namespace outside the group
    /// (a producer) and a link routed into another namespace get nothing.
    #[test]
    fn a_members_group_goes_over_every_link_toward_its_namespace() {
        let t = table(&[SYNC_FACE, CA_FACE], &[PHONE, DEFAULT, OTHER]);
        let fib = Fib::new();
        fib.add_nexthop(&group("/nt"), FaceId(SYNC_FACE), 0);
        fib.add_nexthop(&n("/nt"), FaceId(CA_FACE), 0);
        fib.add_nexthop(&n("/nt/member/phone"), FaceId(PHONE), 10);
        fib.add_nexthop(&Name::root(), FaceId(DEFAULT), 10);
        fib.add_nexthop(&n("/bob"), FaceId(OTHER), 10);
        let groups = SyncGroups::default();
        assert_eq!(
            faces(groups.nexthops(&group("/nt"), FaceId(SYNC_FACE), &fib, &t)),
            [SYNC_FACE, PHONE, DEFAULT]
        );
    }

    /// A member of another namespace, which this node routes nothing in
    /// `/nt` toward, is reached over the link its Interest of the group came
    /// on — until that face is gone.
    #[test]
    fn a_link_a_groups_interest_arrived_on_is_a_member_while_it_is_up() {
        let t = table(&[SYNC_FACE], &[PHONE, FOREIGN]);
        let fib = Fib::new();
        fib.add_nexthop(&group("/nt"), FaceId(SYNC_FACE), 0);
        fib.add_nexthop(&n("/nt/member/phone"), FaceId(PHONE), 10);
        let groups = SyncGroups::default();
        let g = group("/nt");
        assert_eq!(
            faces(groups.nexthops(&g, FaceId(FOREIGN), &fib, &t)),
            [SYNC_FACE, PHONE, FOREIGN]
        );
        assert_eq!(
            faces(groups.nexthops(&g, FaceId(SYNC_FACE), &fib, &t)),
            [SYNC_FACE, PHONE, FOREIGN]
        );
        t.remove(FaceId(FOREIGN));
        assert_eq!(
            faces(groups.nexthops(&g, FaceId(SYNC_FACE), &fib, &t)),
            [SYNC_FACE, PHONE]
        );
    }

    /// A node with no member of the group and no link routed into its
    /// namespace leaves the group to longest-prefix match, and remembers no
    /// link for it.
    #[test]
    fn a_node_with_only_default_routes_does_not_carry_the_group() {
        let t = table(&[], &[DEFAULT, PHONE]);
        let fib = Fib::new();
        fib.add_nexthop(&Name::root(), FaceId(DEFAULT), 10);
        fib.add_nexthop(&Name::root(), FaceId(PHONE), 10);
        let groups = SyncGroups::default();
        assert!(
            groups
                .nexthops(&group("/nt"), FaceId(PHONE), &fib, &t)
                .is_none()
        );
        assert!(groups.heard.is_empty());
    }

    #[test]
    fn only_a_keyword_sync_second_component_names_a_group() {
        assert_eq!(
            group_prefix(&group("/nt").append("v=3")),
            Some(group("/nt"))
        );
        assert_eq!(group_prefix(&n("/nt/sync")), None);
        assert_eq!(group_prefix(&group("/nt/32=trust-context")), None);
        assert_eq!(group_prefix(&group("/nt/notes")), None);
        assert_eq!(group_prefix(&n("/nt")), None);
    }
}
