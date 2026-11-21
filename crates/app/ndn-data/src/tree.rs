//! A writer's own nested summary of one namespace: which of its log entries
//! lie in which collection, as a Merkle tree of summary packets.
//!
//! Each node summarises one name (a collection, a folder, or both): the
//! writer's entries directly in it, its members records, and its children by
//! digest. The root is the namespace `O`; its one child is `O/32=data`, the
//! folder every collection `O/32=data/<path>` lies under. A node with more
//! than [`PAGE_FANOUT`] children pages them by hash.
//! A node's name carries its head, and its content is fixed by the writer's
//! log up to that head, so one name has one packet. Inner nodes and pages are
//! DigestSha256 packets a reader checks against the digest its parent lists;
//! only the root is signed, so a put costs one signature for its version and
//! at most one for the next root anyone asks for.
//!
//! Nodes are built lazily, when one is served: a put only marks its path
//! changed. Because a node's content is fixed by the log up to its head, a
//! node a change superseded is rebuilt from the log when a reader descending
//! an older root asks for it: every node and page any root listed stays
//! servable for as long as the log holds the entries it lists, so a descent
//! never has to start over however fast the writer puts. Recently superseded
//! packets are kept ready, so a reader a few roots behind costs no rebuild.
//!
//! A node of a log or one-key collection lists in `Entries` only the
//! versions unexpired at its reference date `E`, the date of the writer's
//! newest version in it (spec §7): `Keep::Until(t)` while `t > E`,
//! `Keep::LastN(n)` while fewer than `n` later versions are listed there.
//! For those it lists kept `Until` a date it states bounds of their keeps,
//! in at most [`EXPIRY_RUNS`] runs, so a reader that never held them sees by
//! its own clock when they expired, however long the writer stays silent.
//! All of it is fixed by the log up to the node's head, so one name still
//! has one packet, and a constant stream's node stays bounded by its keep
//! window.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use bytes::Bytes;
use ndn_foundation_types::{Name, NameComponent};
use ndn_packet::encode::DataBuilder;

use crate::version::{Keep, Timestamp};
use crate::wire::{
    Branches, ChildRef, EXPIRY_RUNS, ExpiryRun, NodeBody, PAGE_FANOUT, PageRef, bucket_of,
    encode_node, implicit_digest, node_name, page_name, ranges_of,
};

/// How many superseded summary packets a tree keeps ready. A cache only:
/// any superseded node or page is rebuilt from the log when asked for.
const RECENT: usize = 4096;

/// How a version is listed by keep: its keep and date, as its record
/// carries them. A merge collection's versions are listed whatever their
/// keep ([`Retain::ALWAYS`]): its state needs every operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Retain {
    pub(crate) keep: Keep,
    pub(crate) dated: Timestamp,
}

impl Retain {
    /// Listed whatever comes later.
    pub(crate) const ALWAYS: Retain = Retain {
        keep: Keep::Forever,
        dated: Timestamp(0),
    };
}

/// What a log entry adds to a node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// A version, listed by its keep.
    Version(Retain),
    /// A record that is not a version: members, hold, lease or prune.
    Record,
}

#[derive(Default)]
struct TNode {
    entries: BTreeMap<u64, Retain>,
    members: BTreeSet<u64>,
    children: BTreeMap<NameComponent, TNode>,
    head: u64,
    built: Option<Built>,
}

/// The versions of `entries` up to `h` that a node at head `h` lists: those
/// unexpired at the date of the newest of them (spec §7).
fn listed_at(entries: &BTreeMap<u64, Retain>, h: u64) -> Vec<u64> {
    let upto = entries.range(..=h);
    let Some((_, newest)) = upto.clone().next_back() else {
        return Vec::new();
    };
    let e = newest.dated;
    let mut out: Vec<u64> = upto
        .rev()
        .enumerate()
        .filter(|(later, (_, r))| match r.keep {
            Keep::Until(t) => t > e,
            Keep::LastN(n) => (*later as u64) < u64::from(n),
            Keep::Forever => true,
        })
        .map(|(_, (s, _))| *s)
        .collect();
    out.reverse();
    out
}

/// The `Expiry` runs of a node listing `listed` of `entries` (spec §7):
/// its listed versions kept `Until` a date, in seq order, one run per group
/// of them with one keep while those are at most [`EXPIRY_RUNS`]; beyond,
/// split into [`EXPIRY_RUNS`] runs of equal count (the last may hold fewer),
/// each stating the latest keep in it. Versions kept forever or for the
/// last n are in none.
fn expiry_of(entries: &BTreeMap<u64, Retain>, listed: &[u64]) -> Vec<ExpiryRun> {
    let until: Vec<(u64, Timestamp)> = listed
        .iter()
        .filter_map(|s| match entries.get(s)?.keep {
            Keep::Until(t) => Some((*s, t)),
            _ => None,
        })
        .collect();
    let groups = until.chunk_by(|(_, a), (_, b)| a == b).collect::<Vec<_>>();
    let runs: Vec<&[(u64, Timestamp)]> = if groups.len() <= EXPIRY_RUNS {
        groups
    } else {
        until.chunks(until.len().div_ceil(EXPIRY_RUNS)).collect()
    };
    runs.into_iter()
        .map(|run| ExpiryRun {
            seqs: ranges_of(run.iter().map(|(s, _)| s)),
            until: run
                .iter()
                .map(|(_, t)| *t)
                .max()
                .expect("a run is not empty"),
        })
        .collect()
}

/// A node's or page's packets, by page path.
type Pages = HashMap<Bytes, (Name, Bytes, [u8; 32])>;

struct Built {
    content: Bytes,
    name: Name,
    wire: Bytes,
    digest: [u8; 32],
    pages: Pages,
}

/// One namespace's summary tree of this device's log.
pub(crate) struct Tree {
    ns: Name,
    root: TNode,
    recent: VecDeque<Name>,
    recent_wire: HashMap<Name, Bytes>,
}

impl Tree {
    pub(crate) fn new(ns: Name) -> Self {
        Self {
            ns,
            root: TNode::default(),
            recent: VecDeque::new(),
            recent_wire: HashMap::new(),
        }
    }

    /// The writer's highest seq in the namespace.
    #[cfg(test)]
    pub(crate) fn head(&self) -> u64 {
        self.root.head
    }

    /// Record log entry `seq` about `subject` (under the tree's namespace).
    pub(crate) fn add(&mut self, subject: &Name, seq: u64, kind: Kind) {
        debug_assert!(subject.has_prefix(&self.ns));
        let rest = &subject.components()[self.ns.len()..];
        let mut node = &mut self.root;
        let mut retired = Vec::new();
        for comp in rest {
            retire(node, &mut retired);
            node.head = node.head.max(seq);
            node = node.children.entry(comp.clone()).or_default();
        }
        retire(node, &mut retired);
        node.head = node.head.max(seq);
        match kind {
            Kind::Version(r) => {
                node.entries.insert(seq, r);
            }
            Kind::Record => {
                node.members.insert(seq);
            }
        };
        for (name, wire) in retired {
            self.remember(name, wire);
        }
    }

    fn remember(&mut self, name: Name, wire: Bytes) {
        if self.recent_wire.insert(name.clone(), wire).is_none() {
            self.recent.push_back(name);
        }
        while self.recent.len() > RECENT {
            if let Some(old) = self.recent.pop_front() {
                self.recent_wire.remove(&old);
            }
        }
    }

    /// Build every changed node; returns the root's content (to sign).
    pub(crate) fn build(&mut self, device: &Name, writer: &Name) -> Bytes {
        let ns = self.ns.clone();
        build(&mut self.root, device, writer, &ns);
        self.root
            .built
            .as_ref()
            .expect("just built")
            .content
            .clone()
    }

    /// The packet named `name`: of `subject`'s node (or of its page `page`)
    /// at `head`, current or superseded. A superseded one is rebuilt from the
    /// log unless it is still kept; a name no root ever listed has none.
    pub(crate) fn packet(
        &mut self,
        device: &Name,
        writer: &Name,
        subject: &Name,
        page: Option<&Bytes>,
        head: u64,
        name: &Name,
    ) -> Option<Bytes> {
        self.build(device, writer);
        let node = self.node(subject)?;
        let b = node.built.as_ref().expect("just built");
        let current = match page {
            None => (node.head == head).then_some(&b.wire),
            Some(path) => b
                .pages
                .get(path)
                .filter(|(page_name, _, _)| page_name == name)
                .map(|(_, wire, _)| wire),
        };
        if let Some(wire) = current.or_else(|| self.recent_wire.get(name)) {
            return Some(wire.clone());
        }
        let rebuilt = match page {
            None => {
                let (b, _) = node_at(node, head, device, writer, subject)?;
                let mut pages = b.pages;
                pages.insert(Bytes::new(), (b.name, b.wire, b.digest));
                pages
            }
            Some(path) => page_at(node, head, device, writer, subject, path)?,
        };
        let mut found = None;
        for (_, (packet_name, wire, _)) in rebuilt {
            if packet_name == *name {
                found = Some(wire.clone());
            }
            self.remember(packet_name, wire);
        }
        found
    }

    /// The root as the log up to `h` fixes it: its head and content (to
    /// sign). The current root when nothing above `h` was added; an empty
    /// root when nothing up to `h` was.
    pub(crate) fn root_at(&mut self, device: &Name, writer: &Name, h: u64) -> (u64, Bytes) {
        let current = self.build(device, writer);
        if self.root.head <= h {
            return (self.root.head, current);
        }
        let ns = self.ns.clone();
        match node_at(&self.root, h, device, writer, &ns) {
            Some((b, head)) => {
                let content = b.content.clone();
                self.remember_built(b);
                (head, content)
            }
            None => {
                let empty = assemble(device, writer, &ns, 0, &BTreeMap::new(), 0, &[], Vec::new());
                (0, empty.content)
            }
        }
    }

    /// Keep a rebuilt node's packets ready: a reader descending the root
    /// that lists it asks for them next.
    fn remember_built(&mut self, b: Built) {
        for (_, (name, wire, _)) in b.pages {
            self.remember(name, wire);
        }
        self.remember(b.name, b.wire);
    }

    /// `subject`'s node as the log up to `h` fixes it: its head and its
    /// packet; `None` if it had no entry by then.
    pub(crate) fn node_at(
        &mut self,
        device: &Name,
        writer: &Name,
        subject: &Name,
        h: u64,
    ) -> Option<(u64, Bytes)> {
        self.build(device, writer);
        let node = self.node(subject)?;
        if node.head <= h {
            return Some((node.head, node.built.as_ref()?.wire.clone()));
        }
        let (b, head) = node_at(node, h, device, writer, subject)?;
        let wire = b.wire.clone();
        self.remember_built(b);
        Some((head, wire))
    }

    fn node(&self, subject: &Name) -> Option<&TNode> {
        if !subject.has_prefix(&self.ns) {
            return None;
        }
        let mut node = &self.root;
        for comp in &subject.components()[self.ns.len()..] {
            node = node.children.get(comp)?;
        }
        Some(node)
    }
}

/// Take a node's packets out of service (they move to the recent set).
fn retire(node: &mut TNode, out: &mut Vec<(Name, Bytes)>) {
    if let Some(b) = node.built.take() {
        out.push((b.name, b.wire));
        for (_, (name, wire, _)) in b.pages {
            out.push((name, wire));
        }
    }
}

fn packet(name: &Name, content: &Bytes) -> (Bytes, [u8; 32]) {
    let wire = DataBuilder::new(name.clone(), content).sign_digest_sha256();
    let digest = implicit_digest(&wire);
    (wire, digest)
}

/// A node's packet from its parts: one name, one packet. It lists the
/// versions of `entries` up to `upto` by keep, with their keep bounds.
#[allow(clippy::too_many_arguments)]
fn assemble<'a>(
    device: &Name,
    writer: &Name,
    subject: &Name,
    head: u64,
    entries: &BTreeMap<u64, Retain>,
    upto: u64,
    members: impl IntoIterator<Item = &'a u64>,
    refs: Vec<ChildRef>,
) -> Built {
    let mut pages = HashMap::new();
    let branches = if refs.len() <= PAGE_FANOUT {
        Branches::Children(refs)
    } else {
        Branches::Pages(paginate(refs, device, writer, subject, &[], &mut pages))
    };
    let listed = listed_at(entries, upto);
    let body = NodeBody {
        subject: subject.clone(),
        writer: writer.clone(),
        head,
        page: None,
        entries: ranges_of(&listed),
        expiry: expiry_of(entries, &listed),
        members: ranges_of(members),
        branches,
    };
    let content = encode_node(&body);
    let name = node_name(device, subject, head);
    let (wire, digest) = packet(&name, &content);
    Built {
        content,
        name,
        wire,
        digest,
        pages,
    }
}

fn build(node: &mut TNode, device: &Name, writer: &Name, subject: &Name) -> ([u8; 32], u64) {
    if let Some(b) = &node.built {
        return (b.digest, node.head);
    }
    let mut refs = Vec::with_capacity(node.children.len());
    for (comp, child) in node.children.iter_mut() {
        let sub = subject.clone().append_component(comp.clone());
        let (digest, head) = build(child, device, writer, &sub);
        refs.push(ChildRef {
            component: comp.clone(),
            head,
            digest,
        });
    }
    let built = assemble(
        device,
        writer,
        subject,
        node.head,
        &node.entries,
        node.head,
        &node.members,
        refs,
    );
    let digest = built.digest;
    node.built = Some(built);
    (digest, node.head)
}

/// `node` as it was when its subtree's head was at most `h` (the log up to
/// `h` fixes it), and that head; `None` if the subtree had no entry yet. A
/// built subtree unchanged since `h` is taken as built.
fn node_at(
    node: &TNode,
    h: u64,
    device: &Name,
    writer: &Name,
    subject: &Name,
) -> Option<(Built, u64)> {
    let refs = refs_at(node, h, device, writer, subject, |_| true);
    let head = node
        .entries
        .range(..=h)
        .next_back()
        .map(|(s, _)| s)
        .into_iter()
        .chain(node.members.range(..=h).next_back())
        .copied()
        .chain(refs.iter().map(|r| r.head))
        .max()?;
    let built = assemble(
        device,
        writer,
        subject,
        head,
        &node.entries,
        h,
        node.members.range(..=h),
        refs,
    );
    Some((built, head))
}

/// `node`'s children for which `keep` holds, as they were when its subtree's
/// head was at most `h`.
fn refs_at(
    node: &TNode,
    h: u64,
    device: &Name,
    writer: &Name,
    subject: &Name,
    keep: impl Fn(&NameComponent) -> bool,
) -> Vec<ChildRef> {
    node.children
        .iter()
        .filter(|(comp, _)| keep(comp))
        .filter_map(|(comp, child)| {
            let (digest, head) = match &child.built {
                Some(b) if child.head <= h => (b.digest, child.head),
                _ => {
                    let sub = subject.clone().append_component(comp.clone());
                    let (b, head) = node_at(child, h, device, writer, &sub)?;
                    (b.digest, head)
                }
            };
            Some(ChildRef {
                component: comp.clone(),
                head,
                digest,
            })
        })
        .collect()
}

/// Page `path` of `node` as it was when the page's head was `head`, with
/// its sub-pages; `None` if no page of that name was ever listed. The page
/// lists the node's children of its buckets, which the log up to `head`
/// fixes: a later child of those buckets has a higher seq.
fn page_at(
    node: &TNode,
    head: u64,
    device: &Name,
    writer: &Name,
    subject: &Name,
    path: &[u8],
) -> Option<Pages> {
    if path.is_empty() || path.len() > 64 {
        return None;
    }
    let refs = refs_at(node, head, device, writer, subject, |comp| {
        path.iter()
            .enumerate()
            .all(|(depth, bucket)| bucket_of(comp, depth) == *bucket)
    });
    if refs.is_empty() {
        return None;
    }
    let mut out = HashMap::new();
    let listed = page(refs, device, writer, subject, path.to_vec(), &mut out);
    (listed.head == head).then_some(out)
}

fn paginate(
    refs: Vec<ChildRef>,
    device: &Name,
    writer: &Name,
    subject: &Name,
    path: &[u8],
    out: &mut Pages,
) -> Vec<PageRef> {
    let depth = path.len();
    let mut buckets: [Vec<ChildRef>; 16] = Default::default();
    for r in refs {
        buckets[usize::from(bucket_of(&r.component, depth))].push(r);
    }
    let mut pages = Vec::new();
    for (bucket, list) in buckets.into_iter().enumerate() {
        if list.is_empty() {
            continue;
        }
        let mut sub = path.to_vec();
        sub.push(bucket as u8);
        pages.push(page(list, device, writer, subject, sub, out));
    }
    pages
}

/// The page at `path` listing `list` (not empty), into `out` with its
/// sub-pages.
fn page(
    list: Vec<ChildRef>,
    device: &Name,
    writer: &Name,
    subject: &Name,
    path: Vec<u8>,
    out: &mut Pages,
) -> PageRef {
    let bucket = *path.last().expect("a page has a path");
    let head = list.iter().map(|r| r.head).max().unwrap_or(0);
    // SHA-256 has 64 nibbles; past them children cannot be told apart.
    let branches = if list.len() <= PAGE_FANOUT || path.len() >= 64 {
        Branches::Children(list)
    } else {
        Branches::Pages(paginate(list, device, writer, subject, &path, out))
    };
    let path = Bytes::from(path);
    let body = NodeBody {
        subject: subject.clone(),
        writer: writer.clone(),
        head,
        page: Some(path.clone()),
        entries: Vec::new(),
        members: Vec::new(),
        expiry: Vec::new(),
        branches,
    };
    let name = page_name(device, subject, &path, head);
    let (wire, digest) = packet(&name, &encode_node(&body));
    out.insert(path, (name, wire, digest));
    PageRef {
        bucket,
        head,
        digest,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{decode_node, parse_summary_name};
    use ndn_packet::Data;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    const V: Kind = Kind::Version(Retain::ALWAYS);

    fn until(dated: u64, until: u64) -> Kind {
        Kind::Version(Retain {
            keep: Keep::Until(Timestamp(until)),
            dated: Timestamp(dated),
        })
    }

    fn entries_of(wire: &Bytes) -> Vec<u64> {
        let body = decode_node(
            Data::decode(wire.clone())
                .unwrap()
                .content()
                .unwrap()
                .clone(),
        );
        crate::wire::seqs_of(&body.unwrap().entries).collect()
    }

    #[test]
    fn a_node_lists_by_keep_at_its_newest_date_one_packet_per_name() {
        let (device, writer) = (n("/alice/sensor"), n("/alice/sensor/KEY/1"));
        let temps = n("/alice/32=data/temps");
        let last = n("/alice/32=data/last");
        let mut tree = Tree::new(n("/alice"));
        tree.add(&temps, 1, until(0, 100));
        tree.add(&temps, 2, until(50, 150));
        let (h2, at2) = tree.node_at(&device, &writer, &temps, u64::MAX).unwrap();
        assert_eq!((h2, entries_of(&at2)), (2, vec![1, 2]));
        // The newest date moves past the first keep: no longer listed.
        tree.add(&temps, 3, until(120, 220));
        let (h3, at3) = tree.node_at(&device, &writer, &temps, u64::MAX).unwrap();
        assert_eq!((h3, entries_of(&at3)), (3, vec![2, 3]));
        for kept in [2u64, 3] {
            let lastn = Kind::Version(Retain {
                keep: Keep::LastN(2),
                dated: Timestamp(kept),
            });
            tree.add(&last, kept + 2, lastn);
        }
        tree.add(
            &last,
            6,
            Kind::Version(Retain {
                keep: Keep::LastN(2),
                dated: Timestamp(6),
            }),
        );
        let (_, l) = tree.node_at(&device, &writer, &last, u64::MAX).unwrap();
        assert_eq!(entries_of(&l), vec![5, 6], "the last 2 by count");
        // Rebuilt from the log alone, the node at head 2 is the packet it was.
        tree.recent.clear();
        tree.recent_wire.clear();
        let name = node_name(&device, &temps, 2);
        assert_eq!(
            tree.packet(&device, &writer, &temps, None, 2, &name),
            Some(at2)
        );
    }

    fn node_of(wire: &Bytes) -> NodeBody {
        let data = Data::decode(wire.clone()).unwrap();
        decode_node(data.content().unwrap().clone()).unwrap()
    }

    /// The keep bound `body` states for `seq`, if a run lists it.
    fn bound_of(body: &NodeBody, seq: u64) -> Option<Timestamp> {
        body.expiry
            .iter()
            .find(|r| crate::wire::seqs_of(&r.seqs).any(|s| s == seq))
            .map(|r| r.until)
    }

    #[test]
    fn a_node_bounds_the_keep_of_each_version_it_lists_kept_until_a_date() {
        let (device, writer) = (n("/alice/sensor"), n("/alice/sensor/KEY/1"));
        let mut tree = Tree::new(n("/alice"));
        // More keeps than a node states runs, then few: versions kept until
        // a date among ones kept forever and for the last n.
        let soil = n("/alice/32=data/soil");
        let air = n("/alice/32=data/air");
        let mut keeps = BTreeMap::new();
        let mut seq = 0;
        for (c, distinct) in [(&soil, 3 * EXPIRY_RUNS as u64), (&air, 4)] {
            for i in 0..3 * EXPIRY_RUNS as u64 {
                seq += 1;
                let keep = match i % 5 {
                    0 => Keep::Forever,
                    1 => Keep::LastN(1000),
                    _ => Keep::Until(Timestamp(
                        10_000 + (i * distinct / (3 * EXPIRY_RUNS as u64)),
                    )),
                };
                let dated = Timestamp(i);
                tree.add(c, seq, Kind::Version(Retain { keep, dated }));
                keeps.insert(seq, keep);
            }
        }
        for (c, exact) in [(&soil, false), (&air, true)] {
            let (head, wire) = tree.node_at(&device, &writer, c, u64::MAX).unwrap();
            let body = node_of(&wire);
            assert!(
                body.expiry.len() <= EXPIRY_RUNS,
                "{c}: {} runs",
                body.expiry.len()
            );
            for s in crate::wire::seqs_of(&body.entries) {
                match keeps[&s] {
                    Keep::Until(t) if exact => {
                        assert_eq!(bound_of(&body, s), Some(t), "{c} seq {s}")
                    }
                    Keep::Until(t) => {
                        assert!(bound_of(&body, s).is_some_and(|b| b >= t), "{c} seq {s}")
                    }
                    _ => assert_eq!(bound_of(&body, s), None, "{c} seq {s}"),
                }
            }
            // One packet per name: superseded, the node rebuilt from the log
            // alone is the packet it was, its bounds included.
            seq += 1;
            tree.add(c, seq, V);
            tree.recent.clear();
            tree.recent_wire.clear();
            let name = node_name(&device, c, head);
            assert_eq!(
                tree.packet(&device, &writer, c, None, head, &name),
                Some(wire)
            );
        }
    }

    #[test]
    fn a_change_moves_only_its_path_and_old_packets_stay_servable() {
        let (device, writer) = (n("/alice/phone"), n("/alice/phone/KEY/1"));
        let mut tree = Tree::new(n("/alice"));
        for i in 0..200u64 {
            tree.add(&n(&format!("/alice/32=data/notes/n{i}")), i + 1, V);
        }
        tree.build(&device, &writer);
        let folder = tree.node(&n("/alice/32=data/notes")).unwrap();
        let before = folder.built.as_ref().unwrap();
        let Branches::Pages(pages) = decode_node(
            Data::decode(before.wire.clone())
                .unwrap()
                .content()
                .unwrap()
                .clone(),
        )
        .unwrap()
        .branches
        else {
            panic!("200 children are paged");
        };
        let old_name = before.name.clone();
        let old_digests: Vec<_> = pages.iter().map(|p| (p.bucket, p.digest)).collect();

        tree.add(&n("/alice/32=data/notes/n7"), 201, V);
        tree.build(&device, &writer);
        let after = tree
            .node(&n("/alice/32=data/notes"))
            .unwrap()
            .built
            .as_ref()
            .unwrap();
        let Branches::Pages(pages) = decode_node(
            Data::decode(after.wire.clone())
                .unwrap()
                .content()
                .unwrap()
                .clone(),
        )
        .unwrap()
        .branches
        else {
            panic!("still paged");
        };
        let changed = pages
            .iter()
            .zip(&old_digests)
            .filter(|(p, (_, d))| p.digest != *d)
            .count();
        assert_eq!(changed, 1, "one changed note changes one page");
        assert!(
            tree.packet(
                &device,
                &writer,
                &n("/alice/32=data/notes"),
                None,
                200,
                &old_name
            )
            .is_some(),
            "the superseded node is still served by its name"
        );
    }

    #[test]
    fn a_root_at_a_head_is_the_root_the_log_up_to_it_made() {
        let (device, writer) = (n("/alice/phone"), n("/alice/phone/KEY/1"));
        let mut tree = Tree::new(n("/alice"));
        assert_eq!(
            tree.root_at(&device, &writer, 0),
            (0, Tree::new(n("/alice")).build(&device, &writer)),
            "nothing written: the empty root"
        );
        for i in 1..=150u64 {
            tree.add(&n(&format!("/alice/32=data/notes/n{}", i % 40)), i, V);
        }
        let then = tree.build(&device, &writer);
        for i in 151..=170u64 {
            tree.add(&n(&format!("/alice/32=data/notes/n{}", i % 7)), i, V);
        }
        tree.add(&n("/alice/32=data/other"), 171, V);
        assert_eq!(
            tree.root_at(&device, &writer, 150),
            (150, then),
            "the root up to a head is the one the log up to it made, whatever came after"
        );
        let now = tree.build(&device, &writer);
        assert_eq!(tree.root_at(&device, &writer, 171), (171, now));
        assert_eq!(
            tree.root_at(&device, &writer, 0),
            (0, Tree::new(n("/alice")).build(&device, &writer))
        );
    }

    /// Every packet the tree's current root lists (below the root), walked
    /// through [`Tree::packet`] and checked against the digests listed.
    fn listed(tree: &mut Tree, device: &Name, writer: &Name) -> Vec<(Name, Bytes)> {
        let mut todo = vec![decode_node(tree.build(device, writer)).unwrap()];
        let mut out = Vec::new();
        while let Some(body) = todo.pop() {
            let below: Vec<(Name, Option<Bytes>, u64, [u8; 32])> = match &body.branches {
                Branches::Children(list) => list
                    .iter()
                    .map(|c| {
                        let sub = body.subject.clone().append_component(c.component.clone());
                        (sub, None, c.head, c.digest)
                    })
                    .collect(),
                Branches::Pages(list) => list
                    .iter()
                    .map(|p| {
                        let mut path = body.page.clone().unwrap_or_default().to_vec();
                        path.push(p.bucket);
                        (
                            body.subject.clone(),
                            Some(Bytes::from(path)),
                            p.head,
                            p.digest,
                        )
                    })
                    .collect(),
            };
            for (subject, page, head, digest) in below {
                let name = match &page {
                    None => node_name(device, &subject, head),
                    Some(path) => page_name(device, &subject, path, head),
                };
                let wire = tree
                    .packet(device, writer, &subject, page.as_ref(), head, &name)
                    .unwrap_or_else(|| panic!("{name} is listed, so served"));
                assert_eq!(
                    implicit_digest(&wire),
                    digest,
                    "{name} has the listed digest"
                );
                let data = Data::decode(wire.clone()).unwrap();
                todo.push(decode_node(data.content().unwrap().clone()).unwrap());
                out.push((name, wire));
            }
        }
        out
    }

    #[test]
    fn every_packet_a_root_listed_is_served_however_many_puts_follow() {
        let (device, writer) = (n("/alice/phone"), n("/alice/phone/KEY/1"));
        let mut tree = Tree::new(n("/alice"));
        tree.add(&n("/alice/32=data/todo"), 1, Kind::Record);
        tree.add(&n("/alice/32=data/todo"), 2, V);
        // 1100 notes: the folder is paged and its fuller buckets sub-paged.
        for i in 0..1100u64 {
            tree.add(&n(&format!("/alice/32=data/notes/n{i}")), i + 3, V);
        }
        let then = listed(&mut tree, &device, &writer);
        assert!(
            then.iter().any(|(name, _)| parse_summary_name(name)
                .unwrap()
                .page
                .is_some_and(|p| p.len() == 2)),
            "the walk reaches sub-pages"
        );

        // Edits of old notes, new notes (filling buckets past a page), and
        // new entries in the old root's other branch, with roots between.
        let mut seq = 1102;
        for i in 0..600u64 {
            seq += 1;
            let note = if i % 2 == 0 { i * 7 % 1100 } else { 1100 + i };
            tree.add(&n(&format!("/alice/32=data/notes/n{note}")), seq, V);
            if i % 50 == 0 {
                seq += 1;
                tree.add(&n("/alice/32=data/todo"), seq, V);
            }
            if i % 100 == 99 {
                tree.build(&device, &writer);
            }
        }
        // Nothing kept ready: every superseded packet is rebuilt from the log.
        tree.recent.clear();
        tree.recent_wire.clear();
        for (name, wire) in &then {
            let s = parse_summary_name(name).unwrap();
            let served = tree.packet(
                &device,
                &writer,
                &s.subject,
                s.page.as_ref(),
                s.head.unwrap(),
                name,
            );
            assert_eq!(
                served.as_ref(),
                Some(wire),
                "{name} is served as the root listed it"
            );
        }
        // What no root listed is not served: note n0's only head is 3.
        let n0 = n("/alice/32=data/notes/n0");
        assert_eq!(
            tree.packet(&device, &writer, &n0, None, 4, &node_name(&device, &n0, 4)),
            None
        );
    }
}
