//! A writer's own nested summary of one namespace: which of its log entries
//! lie in which collection, as a Merkle tree of summary packets.
//!
//! Each node summarises one name (a collection, a folder, or both): the
//! writer's entries directly in it, its members records, and its children by
//! digest. A node with more than [`PAGE_FANOUT`] children pages them by hash.
//! A node's name carries its head, and its content is fixed by the writer's
//! log up to that head, so one name has one packet. Inner nodes and pages are
//! DigestSha256 packets a reader checks against the digest its parent lists;
//! only the root is signed, so a put costs one signature for its version and
//! at most one for the next root anyone asks for.
//!
//! Nodes are built lazily, when one is served: a put only marks its path
//! changed. Packets of nodes a change superseded stay servable for a while,
//! so a reader descending a slightly older root still completes.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use bytes::Bytes;
use ndn_foundation_types::{Name, NameComponent};
use ndn_packet::encode::DataBuilder;

use crate::wire::{
    Branches, ChildRef, NodeBody, PAGE_FANOUT, PageRef, bucket_of, encode_node, implicit_digest,
    node_name, page_name, ranges_of,
};

/// How many superseded summary packets a tree keeps servable.
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

struct Built {
    content: Bytes,
    name: Name,
    wire: Bytes,
    digest: [u8; 32],
    pages: HashMap<Bytes, (Name, Bytes, [u8; 32])>,
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

    /// The packet named `name` — the current one of `subject` (or of its
    /// page `page`) at `head`, or a recently superseded one. The tree must be
    /// built.
    pub(crate) fn packet(
        &self,
        subject: &Name,
        page: Option<&Bytes>,
        head: u64,
        name: &Name,
    ) -> Option<Bytes> {
        if let Some(node) = self.node(subject)
            && let Some(b) = &node.built
        {
            let current = match page {
                None => (node.head == head).then_some(&b.wire),
                Some(path) => b
                    .pages
                    .get(path)
                    .filter(|(page_name, _, _)| page_name == name)
                    .map(|(_, wire, _)| wire),
            };
            if let Some(wire) = current {
                return Some(wire.clone());
            }
        }
        self.recent_wire.get(name).cloned()
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
    let mut pages = HashMap::new();
    let branches = if refs.len() <= PAGE_FANOUT {
        Branches::Children(refs)
    } else {
        Branches::Pages(paginate(refs, device, writer, subject, &[], &mut pages))
    };
    let body = NodeBody {
        subject: subject.clone(),
        writer: writer.clone(),
        head: node.head,
        page: None,
        entries: ranges_of(&node.entries),
        members: ranges_of(&node.members),
        branches,
    };
    let content = encode_node(&body);
    let name = node_name(device, subject, node.head);
    let (wire, digest) = packet(&name, &content);
    node.built = Some(Built {
        content,
        name,
        wire,
        digest,
        pages,
    });
    (digest, node.head)
}

fn paginate(
    refs: Vec<ChildRef>,
    device: &Name,
    writer: &Name,
    subject: &Name,
    path: &[u8],
    out: &mut HashMap<Bytes, (Name, Bytes, [u8; 32])>,
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
        let bucket = bucket as u8;
        let mut sub = path.to_vec();
        sub.push(bucket);
        let head = list.iter().map(|r| r.head).max().unwrap_or(0);
        // SHA-256 has 64 nibbles; past them children cannot be told apart.
        let branches = if list.len() <= PAGE_FANOUT || sub.len() >= 64 {
            Branches::Children(list)
        } else {
            Branches::Pages(paginate(list, device, writer, subject, &sub, out))
        };
        let sub = Bytes::from(sub);
        let body = NodeBody {
            subject: subject.clone(),
            writer: writer.clone(),
            head,
            page: Some(sub.clone()),
            entries: Vec::new(),
            members: Vec::new(),
            branches,
        };
        let name = page_name(device, subject, &sub, head);
        let (wire, digest) = packet(&name, &encode_node(&body));
        out.insert(sub, (name, wire, digest));
        pages.push(PageRef {
            bucket,
            head,
            digest,
        });
    }
    pages
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::decode_node;
    use ndn_packet::Data;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[test]
    fn a_change_moves_only_its_path_and_old_packets_stay_servable() {
        let (device, writer) = (n("/alice/phone"), n("/alice/phone/KEY/1"));
        let mut tree = Tree::new(n("/alice"));
        for i in 0..200u64 {
            tree.add(&n(&format!("/alice/notes/n{i}")), i + 1, Entry::Version);
        }
        tree.build(&device, &writer);
        let folder = tree.node(&n("/alice/notes")).unwrap();
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

        tree.add(&n("/alice/notes/n7"), 201, Entry::Version);
        tree.build(&device, &writer);
        let after = tree
            .node(&n("/alice/notes"))
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
            tree.packet(&n("/alice/notes"), None, 200, &old_name)
                .is_some(),
            "the superseded node is still served by its name"
        );
    }
}
