//! A value too large for an entry travels in pieces under the entry's name
//! (spec §3.5): its octets cut into chunks, listed by a manifest tree of
//! fan-out [`FANOUT`] whose root digest the entry carries. This is the tree's
//! shape and the pieces' names; cutting, assembling and verifying are the
//! `pieces` module.

use ndn_foundation_types::Name;

use super::names::{LogName, MANIFEST, PIECE, is_kw, kw, name_of, parse_log_name};

/// The payload octets one chunk carries (the last may carry fewer).
pub(crate) const CHUNK: usize = 4096;

/// The digests one manifest node lists.
pub(crate) const FANOUT: usize = 128;

/// The most payload octets a value carries at all (64 MiB): a reader
/// assembles a payload whole, so an entry claiming more is refused.
pub(crate) const PAYLOAD_MAX: u64 = 64 << 20;

/// A payload carried in pieces: its octets and the digest of its manifest
/// tree's root node packet (what [`Payload::Blob`](super::Payload::Blob)
/// says).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct ChunksBody {
    /// The payload's octets as carried (sealed: the ciphertext's).
    pub size: u64,
    /// SHA-256 of the root manifest node's whole Data packet.
    pub root: [u8; 32],
}

/// A piece of a large value: a node of its manifest tree, or a chunk of its
/// payload. The order is the order a fetch asks in: nodes (each unlocks more
/// pieces) before chunks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PieceKind {
    /// Manifest node `k`, in heap order from the root (0):
    /// `<E>/32=piece/32=manifest/seg=<k>`.
    Manifest(u64),
    /// Chunk `i` of the payload: `<E>/32=piece/seg=<i>`.
    Chunk(u64),
}

/// A parsed piece name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PieceName {
    /// The entry's name, `E`.
    pub entry: Name,
    /// The entry as parsed.
    pub log: LogName,
    /// Which piece.
    pub kind: PieceKind,
}

/// The name of piece `kind` of the entry named `entry`.
///
/// Public: a sibling crate's cases name a piece as the layer does.
pub fn piece_name(entry: &Name, kind: PieceKind) -> Name {
    let base = entry.clone().append_component(kw(PIECE));
    match kind {
        PieceKind::Chunk(i) => base.append_segment(i),
        PieceKind::Manifest(k) => base.append_component(kw(MANIFEST)).append_segment(k),
    }
}

/// Parse `<E>/32=piece/seg=<i>` or `<E>/32=piece/32=manifest/seg=<k>`, `E` an
/// entry's name.
///
/// Public: a sibling crate that filters names tells a piece of an entry by it.
pub fn parse_piece_name(name: &Name) -> Option<PieceName> {
    let comps = name.components();
    let (last, rest) = comps.split_last()?;
    let n = last.as_segment()?;
    let (rest, kind) = match rest.split_last() {
        Some((m, before)) if is_kw(m, MANIFEST) => (before, PieceKind::Manifest(n)),
        _ => (rest, PieceKind::Chunk(n)),
    };
    let (p, entry) = rest.split_last()?;
    if !is_kw(p, PIECE) {
        return None;
    }
    let entry = name_of(entry);
    let log = parse_log_name(&entry)?;
    Some(PieceName { entry, log, kind })
}

/// The shape of one payload's manifest tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Shape {
    /// The payload's octets.
    pub size: u64,
    /// Chunks.
    pub chunks: u64,
    /// Manifest levels (the root is level 1, the bottom level `depth`).
    pub depth: u32,
}

impl Shape {
    /// The shape of a payload of `size` octets.
    pub(crate) fn of(size: u64) -> Shape {
        let chunks = size.div_ceil(CHUNK as u64).max(1);
        let mut depth = 1;
        let mut reach = FANOUT as u64;
        while reach < chunks {
            reach = reach.saturating_mul(FANOUT as u64);
            depth += 1;
        }
        Shape {
            size,
            chunks,
            depth,
        }
    }

    /// Nodes at `level` (1 = root).
    pub(crate) fn width(&self, level: u32) -> u64 {
        let span = (FANOUT as u64).saturating_pow(self.depth - level + 1);
        self.chunks.div_ceil(span)
    }

    /// Heap number of the first node of `level`.
    pub(crate) fn offset(level: u32) -> u64 {
        // (F^(level-1) - 1) / (F - 1)
        let f = FANOUT as u64;
        (0..level - 1).fold(0, |acc, _| acc * f + 1)
    }

    /// Every manifest node, in heap order.
    #[cfg(test)]
    pub(crate) fn manifests(&self) -> impl Iterator<Item = u64> + '_ {
        (1..=self.depth).flat_map(move |l| {
            let off = Self::offset(l);
            (0..self.width(l)).map(move |j| off + j)
        })
    }

    /// How many pieces: chunks and manifest nodes.
    #[cfg(test)]
    pub(crate) fn pieces(&self) -> u64 {
        self.chunks + (1..=self.depth).map(|l| self.width(l)).sum::<u64>()
    }

    /// The level and index within it of node `k`, if it is a node.
    pub(crate) fn locate(&self, k: u64) -> Option<(u32, u64)> {
        (1..=self.depth).find_map(|l| {
            let off = Self::offset(l);
            (k >= off && k < off + self.width(l)).then_some((l, k - off))
        })
    }

    /// What node `k` lists: its children, as pieces, in order.
    pub(crate) fn children(&self, k: u64) -> Option<Vec<PieceKind>> {
        let (level, j) = self.locate(k)?;
        let f = FANOUT as u64;
        if level == self.depth {
            let lo = j * f;
            let hi = ((j + 1) * f).min(self.chunks);
            return Some((lo..hi).map(PieceKind::Chunk).collect());
        }
        let below = self.width(level + 1);
        let off = Self::offset(level + 1);
        let lo = j * f;
        let hi = ((j + 1) * f).min(below);
        Some((lo..hi).map(|i| PieceKind::Manifest(off + i)).collect())
    }

    /// The octets chunk `i` carries.
    pub(crate) fn chunk_len(&self, i: u64) -> usize {
        let start = i * CHUNK as u64;
        (self.size.saturating_sub(start)).min(CHUNK as u64) as usize
    }
}
