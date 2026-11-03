//! Large payloads in pieces (spec §4.1): a payload longer than
//! [`INLINE_MAX`](crate::wire::INLINE_MAX) travels as chunks of
//! [`CHUNK`](crate::wire::CHUNK) octets under the version's name, listed by a
//! manifest tree of fan-out [`FANOUT`](crate::wire::FANOUT) whose root's
//! digest the signed version record carries. Every piece is a DigestSha256
//! packet its parent lists by implicit digest, so each verifies on its own,
//! fetched from anywhere.
//!
//! The tree's shape follows from the payload's size alone: `n` chunks, depth
//! `d` the least `d ≥ 1` with `FANOUT^d ≥ n`, and nodes numbered in heap
//! order from the root (0), the children of node `k` being
//! `k·FANOUT + 1 …`. A node at the bottom level lists chunks; one above it
//! lists nodes.

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_packet::encode::DataBuilder;

use crate::wire::{
    CHUNK, ChunksBody, FANOUT, PieceKind, decode_manifest, encode_manifest, implicit_digest,
    piece_name,
};

/// The shape of one payload's tree.
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
    fn width(&self, level: u32) -> u64 {
        let span = (FANOUT as u64).saturating_pow(self.depth - level + 1);
        self.chunks.div_ceil(span)
    }

    /// Heap number of the first node of `level`.
    fn offset(level: u32) -> u64 {
        // (F^(level-1) - 1) / (F - 1)
        let f = FANOUT as u64;
        (0..level - 1).fold(0, |acc, _| acc * f + 1)
    }

    /// Every manifest node, in heap order.
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
    fn locate(&self, k: u64) -> Option<(u32, u64)> {
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

/// One piece: its name, its packet, its digest.
pub(crate) struct Piece {
    pub name: Name,
    pub wire: Bytes,
    pub digest: [u8; 32],
}

fn packet(name: Name, content: &[u8]) -> Piece {
    let wire = DataBuilder::new(name.clone(), content).sign_digest_sha256();
    let digest = implicit_digest(&wire);
    Piece { name, wire, digest }
}

/// Cut `payload` into the pieces of the version named `version`; returns
/// them (chunks first, then the manifest nodes bottom-up) and what the
/// record carries.
pub(crate) fn split(version: &Name, payload: &[u8]) -> (Vec<Piece>, ChunksBody) {
    let shape = Shape::of(payload.len() as u64);
    let mut out: Vec<Piece> = payload
        .chunks(CHUNK)
        .enumerate()
        .map(|(i, c)| packet(piece_name(version, PieceKind::Chunk(i as u64)), c))
        .collect();
    // Digests by piece, filled level by level from the bottom.
    let mut below: Vec<[u8; 32]> = out.iter().map(|p| p.digest).collect();
    for level in (1..=shape.depth).rev() {
        let off = Shape::offset(level);
        let mut here = Vec::with_capacity(shape.width(level) as usize);
        for (j, group) in below.chunks(FANOUT).enumerate() {
            let k = off + j as u64;
            let p = packet(
                piece_name(version, PieceKind::Manifest(k)),
                &encode_manifest(group),
            );
            here.push(p.digest);
            out.push(p);
        }
        below = here;
    }
    let root = below[0];
    (
        out,
        ChunksBody {
            size: payload.len() as u64,
            root,
        },
    )
}

/// The digest a manifest node `wire`, checked to be `expected`, lists for
/// its children: `None` when it is not that node, or lists another number of
/// children than its place in `shape` holds.
pub(crate) fn open_node(
    shape: &Shape,
    k: u64,
    wire: &[u8],
    expected: &[u8; 32],
) -> Option<Vec<[u8; 32]>> {
    if implicit_digest(wire) != *expected {
        return None;
    }
    let data = ndn_packet::Data::decode(Bytes::copy_from_slice(wire)).ok()?;
    let digests = decode_manifest(data.content()?.clone()).ok()?;
    (digests.len() == shape.children(k)?.len()).then_some(digests)
}

/// The payload a chunk packet `wire`, checked to be `expected`, carries;
/// `None` when it is not that chunk or carries another length than chunk
/// `i` of `shape`.
pub(crate) fn open_chunk(shape: &Shape, i: u64, wire: &[u8], expected: &[u8; 32]) -> Option<Bytes> {
    if implicit_digest(wire) != *expected {
        return None;
    }
    let data = ndn_packet::Data::decode(Bytes::copy_from_slice(wire)).ok()?;
    let content = data.content()?.clone();
    (content.len() == shape.chunk_len(i)).then_some(content)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[test]
    fn a_payload_splits_into_pieces_its_manifest_lists_and_reassembles() {
        let v = n("/alice/phone/32=log/alice/32=data/photos/seq=3");
        for size in [6145usize, 4096 * 128, 4096 * 128 + 1, 4096 * 300 + 7] {
            let payload: Vec<u8> = (0..size).map(|i| (i * 31 % 251) as u8).collect();
            let (pieces, chunks) = split(&v, &payload);
            let shape = Shape::of(chunks.size);
            assert_eq!(pieces.len() as u64, shape.pieces());
            let by_name: std::collections::HashMap<Name, &Piece> =
                pieces.iter().map(|p| (p.name.clone(), p)).collect();
            // Walk the tree from the root by digest and reassemble.
            let mut out = Vec::new();
            let mut stack = vec![(PieceKind::Manifest(0), chunks.root)];
            while let Some((kind, digest)) = stack.pop() {
                let p = by_name[&piece_name(&v, kind)];
                match kind {
                    PieceKind::Manifest(k) => {
                        let listed = open_node(&shape, k, &p.wire, &digest).expect("verifies");
                        let kids = shape.children(k).unwrap();
                        for (kid, d) in kids.into_iter().zip(listed).rev() {
                            stack.push((kid, d));
                        }
                    }
                    PieceKind::Chunk(i) => {
                        out.extend_from_slice(&open_chunk(&shape, i, &p.wire, &digest).unwrap())
                    }
                }
            }
            assert_eq!(out, payload, "size {size}");
            // A piece whose bytes changed is not the piece its parent lists.
            let mut bad = pieces[0].wire.to_vec();
            let at = bad.len() - 1;
            bad[at] ^= 1;
            assert!(open_chunk(&shape, 0, &bad, &pieces[0].digest).is_none());
        }
    }
}
