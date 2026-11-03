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

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use bytes::Bytes;
use ndn_foundation_types::{Name, NameComponent};
use ndn_packet::encode::DataBuilder;

use crate::wire::{
    Branches, ChildRef, NodeBody, PAGE_FANOUT, PageRef, bucket_of, encode_node, implicit_digest,
    node_name, page_name, ranges_of,
};

/// How many superseded summary packets a tree keeps ready. A cache only:
/// any superseded node or page is rebuilt from the log when asked for.
const RECENT: usize = 4096;

/// What a log entry adds to a node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Entry {
    /// A version.
    Version,
    /// A members record.
    Members,
}

#[derive(Default)]
struct TNode {
    entries: BTreeSet<u64>,
    members: BTreeSet<u64>,
    children: BTreeMap<NameComponent, TNode>,
    head: u64,
    built: Option<Built>,
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
    pub(crate) fn head(&self) -> u64 {
        self.root.head
    }

    /// Record log entry `seq` about `subject` (under the tree's namespace).
    pub(crate) fn add(&mut self, subject: &Name, seq: u64, entry: Entry) {
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
        match entry {
            Entry::Version => node.entries.insert(seq),
            Entry::Members => node.members.insert(seq),
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

/// A node's packet from its parts: one name, one packet.
fn assemble<'a>(
    device: &Name,
    writer: &Name,
    subject: &Name,
    head: u64,
    entries: impl IntoIterator<Item = &'a u64>,
    members: impl IntoIterator<Item = &'a u64>,
    refs: Vec<ChildRef>,
) -> Built {
    let mut pages = HashMap::new();
    let branches = if refs.len() <= PAGE_FANOUT {
        Branches::Children(refs)
    } else {
        Branches::Pages(paginate(refs, device, writer, subject, &[], &mut pages))
    };
    let body = NodeBody {
        subject: subject.clone(),
        writer: writer.clone(),
        head,
        page: None,
        entries: ranges_of(entries),
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
        node.entries.range(..=h),
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

    #[test]
    fn a_change_moves_only_its_path_and_old_packets_stay_servable() {
        let (device, writer) = (n("/alice/phone"), n("/alice/phone/KEY/1"));
        let mut tree = Tree::new(n("/alice"));
        for i in 0..200u64 {
            tree.add(
                &n(&format!("/alice/32=data/notes/n{i}")),
                i + 1,
                Entry::Version,
            );
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

        tree.add(&n("/alice/32=data/notes/n7"), 201, Entry::Version);
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
        tree.add(&n("/alice/32=data/todo"), 1, Entry::Members);
        tree.add(&n("/alice/32=data/todo"), 2, Entry::Version);
        // 1100 notes: the folder is paged and its fuller buckets sub-paged.
        for i in 0..1100u64 {
            tree.add(
                &n(&format!("/alice/32=data/notes/n{i}")),
                i + 3,
                Entry::Version,
            );
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
            tree.add(
                &n(&format!("/alice/32=data/notes/n{note}")),
                seq,
                Entry::Version,
            );
            if i % 50 == 0 {
                seq += 1;
                tree.add(&n("/alice/32=data/todo"), seq, Entry::Version);
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
