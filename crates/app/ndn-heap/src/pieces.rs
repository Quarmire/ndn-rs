//! Payloads over one packet, in pieces (spec §8).
//!
//! A payload too large for an entry is cut into chunks of
//! [`CHUNK`](crate::wire::CHUNK) octets, listed by a manifest tree of fan-out
//! [`FANOUT`](crate::wire::FANOUT) whose root's digest the entry carries
//! (`BLOB { size, root }`). Every piece is a DigestSha256 Data packet under
//! the entry's name that its parent lists by implicit digest, so a piece
//! verifies by its digest alone, from whichever holder it came from; the
//! tree's shape follows from the payload's size alone (`wire::Shape`).
//!
//! A sealed payload is encrypted whole first and cut after: [`split`] cuts
//! whatever bytes it is given and [`join`] returns them, so a holder of the
//! pieces learns the payload's size and nothing else.
//!
//! Nothing here is stored until it is all held. An [`Assembler`] collects the
//! verified pieces of one payload in memory (the payload's size once, no
//! copy of it besides) and hands them over together
//! ([`Assembler::take_ops`]); the caller writes them as one
//! [`DataStore::apply`](ndn_sync::DataStore::apply), so a kill leaves all of
//! a payload's pieces or none. The assembler holds no lock and does no I/O:
//! the fetcher asks for what [`Assembler::next_wanted`] names and offers what
//! arrives, and decides nothing else.

use std::collections::BTreeMap;

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_packet::Data;
use ndn_packet::encode::DataBuilder;
use ndn_sync::{DataStore, StoreOp};

use crate::wire::{
    CHUNK, ChunksBody, FANOUT, PAYLOAD_MAX, PieceKind, Shape, decode_manifest, encode_manifest,
    implicit_digest, parse_piece_name, piece_name,
};

#[cfg(test)]
#[path = "pieces_tests.rs"]
mod tests;

/// Why a payload or a piece was refused, or is not whole yet.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum PieceError {
    /// More octets than a heap carries for one value.
    #[error(
        "a payload of {size} octets is over the 64 MiB a heap carries for one value; split the \
         value into several paths"
    )]
    Oversize {
        /// The payload's octets.
        size: u64,
    },
    /// A piece is not held.
    #[error("{missing} is not held yet; try again later, when its pieces have been fetched")]
    Incomplete {
        /// The first piece lacking.
        missing: Name,
    },
    /// Bytes that are not a Data packet.
    #[error("the bytes are not a Data packet; ask another holder for the piece")]
    NotAPiece,
    /// A packet that is not a piece of this payload.
    #[error("{name} is not a piece of this payload; ask the holder for the piece by its name")]
    Foreign {
        /// The packet's name.
        name: Name,
    },
    /// A packet that is not the one its parent lists: altered, or another's.
    #[error("{name} is not the piece its parent lists; ask another holder for it")]
    Wrong {
        /// The piece's name.
        name: Name,
    },
    /// The piece the entry names, which is not a well-formed piece: its
    /// writer signed an entry naming it.
    #[error("{name} is the piece the entry names and is not well formed; refuse the entry")]
    Malformed {
        /// The piece's name.
        name: Name,
    },
    /// The piece the entry names, which says another shape than the size the
    /// entry declares: its writer signed an entry that contradicts itself.
    #[error("{name} disagrees with the size the entry declares ({why}); refuse the entry")]
    Shape {
        /// The piece's name.
        name: Name,
        /// How it disagrees.
        why: String,
    },
}

/// One piece: its name, its packet, its implicit digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Piece {
    /// `<E>/32=piece/…`.
    pub name: Name,
    /// The DigestSha256 Data packet.
    pub wire: Bytes,
    /// SHA-256 of `wire`: what the parent lists.
    pub digest: [u8; 32],
}

fn packet(name: Name, content: &[u8]) -> Piece {
    let wire = DataBuilder::new(name.clone(), content).sign_digest_sha256();
    let digest = implicit_digest(&wire);
    Piece { name, wire, digest }
}

/// The pieces of one payload, cut.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Pieces {
    /// The entry the pieces are under.
    pub entry: Name,
    /// The chunks in order, then the manifest nodes bottom-up (the root
    /// last).
    pub packets: Vec<Piece>,
    /// The root node's digest: what the entry carries.
    pub root: [u8; 32],
    /// The payload's octets.
    pub size: u64,
}

impl Pieces {
    /// What the entry carries for this payload.
    pub(crate) fn blob(&self) -> ChunksBody {
        ChunksBody {
            size: self.size,
            root: self.root,
        }
    }

    /// The names of the pieces `have` does not say it holds, in packet order.
    pub(crate) fn wanted(&self, have: impl Fn(&Name) -> bool) -> Vec<Name> {
        self.packets
            .iter()
            .filter(|p| !have(&p.name))
            .map(|p| p.name.clone())
            .collect()
    }

    /// Every piece as a write, to be applied in one batch.
    pub(crate) fn ops(&self) -> Vec<StoreOp> {
        self.packets
            .iter()
            .map(|p| StoreOp::Insert(p.name.clone(), p.wire.clone()))
            .collect()
    }
}

/// Cut `payload` (sealed already, when the value is sealed) into the pieces
/// of the entry named `entry`.
pub(crate) fn split(entry: &Name, payload: &[u8]) -> Result<Pieces, PieceError> {
    let size = payload.len() as u64;
    if size > PAYLOAD_MAX {
        return Err(PieceError::Oversize { size });
    }
    let shape = Shape::of(size);
    // An empty payload is one empty chunk, as `Shape` counts it.
    let cuts: Vec<&[u8]> = if payload.is_empty() {
        vec![payload]
    } else {
        payload.chunks(CHUNK).collect()
    };
    let mut packets: Vec<Piece> = cuts
        .into_iter()
        .enumerate()
        .map(|(i, c)| packet(piece_name(entry, PieceKind::Chunk(i as u64)), c))
        .collect();
    // The digests of the level below, filled level by level from the bottom.
    let mut below: Vec<[u8; 32]> = packets.iter().map(|p| p.digest).collect();
    for level in (1..=shape.depth).rev() {
        let offset = Shape::offset(level);
        let mut here = Vec::with_capacity(shape.width(level) as usize);
        for (j, group) in below.chunks(FANOUT).enumerate() {
            let k = offset + j as u64;
            let node = packet(
                piece_name(entry, PieceKind::Manifest(k)),
                &encode_manifest(group),
            );
            here.push(node.digest);
            packets.push(node);
        }
        below = here;
    }
    let root = below[0];
    Ok(Pieces {
        entry: entry.clone(),
        packets,
        root,
        size,
    })
}

/// A piece that disagrees with the size its entry declares.
fn mismatch(name: Name, why: impl Into<String>) -> PieceError {
    PieceError::Shape {
        name,
        why: why.into(),
    }
}

/// Decode `wire` as the piece `kind` of `entry`, checked to be the one
/// `expected` names.
fn decode(
    entry: &Name,
    kind: PieceKind,
    wire: &Bytes,
    expected: &[u8; 32],
) -> Result<Data, PieceError> {
    let name = piece_name(entry, kind);
    if implicit_digest(wire) != *expected {
        return Err(PieceError::Wrong { name });
    }
    let data =
        Data::decode(wire.clone()).map_err(|_| PieceError::Malformed { name: name.clone() })?;
    if *data.name != name {
        return Err(PieceError::Wrong { name });
    }
    Ok(data)
}

/// The digests the manifest node `k` of `entry`, `wire`, lists for its
/// children, checked to be the node `expected` names and to list as many
/// children as its place in `shape` holds.
pub(crate) fn open_node(
    entry: &Name,
    shape: &Shape,
    k: u64,
    wire: &Bytes,
    expected: &[u8; 32],
) -> Result<Vec<[u8; 32]>, PieceError> {
    let kind = PieceKind::Manifest(k);
    let data = decode(entry, kind, wire, expected)?;
    let name = piece_name(entry, kind);
    let digests = data
        .content()
        .cloned()
        .and_then(|content| decode_manifest(content).ok())
        .ok_or_else(|| PieceError::Malformed { name: name.clone() })?;
    let Some(children) = shape.children(k) else {
        return Err(mismatch(
            name,
            format!(
                "a payload of {} octets has no such manifest node",
                shape.size
            ),
        ));
    };
    if digests.len() != children.len() {
        return Err(mismatch(
            name,
            format!(
                "it lists {} digests where a payload of {} octets has {}",
                digests.len(),
                shape.size,
                children.len()
            ),
        ));
    }
    Ok(digests)
}

/// The octets chunk `i` of `entry`, `wire`, carries, checked to be the chunk
/// `expected` names and to carry as many octets as its place in `shape`
/// holds.
pub(crate) fn open_chunk(
    entry: &Name,
    shape: &Shape,
    i: u64,
    wire: &Bytes,
    expected: &[u8; 32],
) -> Result<Bytes, PieceError> {
    let kind = PieceKind::Chunk(i);
    let data = decode(entry, kind, wire, expected)?;
    let content = data.content().cloned().unwrap_or_default();
    if i >= shape.chunks || content.len() != shape.chunk_len(i) {
        return Err(mismatch(
            piece_name(entry, kind),
            format!(
                "it carries {} octets where chunk {i} of a payload of {} octets carries {}",
                content.len(),
                shape.size,
                shape.chunk_len(i)
            ),
        ));
    }
    Ok(content)
}

/// What a verified node says its children are: the digests the fetch still
/// has to prove, by place.
#[derive(Default)]
struct Listed {
    nodes: BTreeMap<u64, [u8; 32]>,
    chunks: BTreeMap<u64, [u8; 32]>,
}

impl Listed {
    /// Record the digests node `k` lists.
    fn list(&mut self, shape: &Shape, k: u64, digests: Vec<[u8; 32]>) {
        for (kid, digest) in shape.children(k).into_iter().flatten().zip(digests) {
            match kid {
                PieceKind::Manifest(m) => self.nodes.insert(m, digest),
                PieceKind::Chunk(i) => self.chunks.insert(i, digest),
            };
        }
    }
}

/// Collects the pieces of one payload, each proven against the digest its
/// parent lists before it is kept, and says which to ask for next.
pub(crate) struct Assembler {
    entry: Name,
    shape: Shape,
    /// Pieces whose digests are known and that are not held.
    wanted: Listed,
    /// Held nodes, by heap number.
    nodes: BTreeMap<u64, Bytes>,
    /// Held chunks, by index: the packet and the octets it carries.
    chunks: BTreeMap<u64, (Bytes, Bytes)>,
}

/// What an offered piece came to, when it was not refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Offered {
    /// Proven and kept.
    Accepted,
    /// Already held.
    Duplicate,
    /// Its parent is not held yet, so no digest is known to prove it by:
    /// offer it again when the plan asks for it.
    NotYet,
}

impl Assembler {
    /// Start collecting the pieces of the payload `blob` of the entry named
    /// `entry`. Refuses a size over `PAYLOAD_MAX`: no entry may make a
    /// reader gather more.
    pub(crate) fn new(entry: Name, blob: ChunksBody) -> Result<Assembler, PieceError> {
        if blob.size > PAYLOAD_MAX {
            return Err(PieceError::Oversize { size: blob.size });
        }
        let mut wanted = Listed::default();
        wanted.nodes.insert(0, blob.root);
        Ok(Assembler {
            entry,
            shape: Shape::of(blob.size),
            wanted,
            nodes: BTreeMap::new(),
            chunks: BTreeMap::new(),
        })
    }

    /// The pieces to ask for now, at most `window`: the manifest nodes
    /// first (each unlocks up to [`FANOUT`] more), then chunks in order.
    /// Only a piece whose digest a held node lists is named, so what the
    /// plan asks for is always provable when it arrives. A piece not
    /// offered yet is named again by the next call: the fetcher keeps track
    /// of what it has in flight.
    pub(crate) fn next_wanted(&self, window: usize) -> Vec<Name> {
        let nodes = self.wanted.nodes.keys().map(|&k| PieceKind::Manifest(k));
        let chunks = self.wanted.chunks.keys().map(|&i| PieceKind::Chunk(i));
        nodes
            .chain(chunks)
            .take(window)
            .map(|kind| piece_name(&self.entry, kind))
            .collect()
    }

    /// Every piece is held and proven.
    pub(crate) fn is_complete(&self) -> bool {
        self.wanted.nodes.is_empty() && self.wanted.chunks.is_empty()
    }

    /// Offer a packet that arrived from anywhere. It is kept only if it is
    /// the piece its name says and the digest its parent lists names exactly
    /// its bytes; a bad copy changes nothing, and the same piece is still
    /// wanted.
    ///
    /// # Errors
    ///
    /// [`PieceError::Wrong`] for a copy that is not the listed piece (ask
    /// another holder); [`PieceError::Shape`] and [`PieceError::Malformed`]
    /// for a listed piece that contradicts the entry (refuse the entry);
    /// [`PieceError::Foreign`] and [`PieceError::NotAPiece`] for a packet
    /// that is not a piece of this payload.
    pub(crate) fn offer(&mut self, wire: Bytes) -> Result<Offered, PieceError> {
        let data = Data::decode(wire.clone()).map_err(|_| PieceError::NotAPiece)?;
        let foreign = || PieceError::Foreign {
            name: (*data.name).clone(),
        };
        let parsed = parse_piece_name(&data.name).ok_or_else(foreign)?;
        if parsed.entry != self.entry {
            return Err(foreign());
        }
        match parsed.kind {
            PieceKind::Manifest(k) => {
                if self.nodes.contains_key(&k) {
                    return Ok(Offered::Duplicate);
                }
                if self.shape.locate(k).is_none() {
                    return Err(foreign());
                }
                let Some(expected) = self.wanted.nodes.get(&k).copied() else {
                    return Ok(Offered::NotYet);
                };
                let digests = open_node(&self.entry, &self.shape, k, &wire, &expected)?;
                self.wanted.nodes.remove(&k);
                self.wanted.list(&self.shape, k, digests);
                self.nodes.insert(k, wire);
            }
            PieceKind::Chunk(i) => {
                if self.chunks.contains_key(&i) {
                    return Ok(Offered::Duplicate);
                }
                if i >= self.shape.chunks {
                    return Err(foreign());
                }
                let Some(expected) = self.wanted.chunks.get(&i).copied() else {
                    return Ok(Offered::NotYet);
                };
                let content = open_chunk(&self.entry, &self.shape, i, &wire, &expected)?;
                self.wanted.chunks.remove(&i);
                self.chunks.insert(i, (wire, content));
            }
        }
        Ok(Offered::Accepted)
    }

    /// The payload, once every piece is held and proven: the octets the
    /// chunks carry, in order, joined from what was proven as it arrived (no
    /// read of the store and no second digest). Asked for before
    /// [`Self::take_ops`], which gives the pieces up.
    pub(crate) fn payload(&self) -> Option<Vec<u8>> {
        if !self.is_complete() || self.nodes.is_empty() {
            return None;
        }
        let mut out = Vec::with_capacity(self.shape.size as usize);
        for (_, content) in self.chunks.values() {
            out.extend_from_slice(content);
        }
        Some(out)
    }

    /// Every piece as a write, once all are held, and only then: the caller
    /// applies them as ONE batch. The assembler gives them up once; it holds
    /// nothing after.
    pub(crate) fn take_ops(&mut self) -> Option<Vec<StoreOp>> {
        if !self.is_complete() || self.nodes.is_empty() {
            return None;
        }
        let entry = &self.entry;
        let chunks = std::mem::take(&mut self.chunks)
            .into_iter()
            .map(|(i, (wire, _))| (piece_name(entry, PieceKind::Chunk(i)), wire));
        let nodes = std::mem::take(&mut self.nodes)
            .into_iter()
            .map(|(k, wire)| (piece_name(entry, PieceKind::Manifest(k)), wire));
        Some(
            chunks
                .chain(nodes)
                .map(|(name, wire)| StoreOp::Insert(name, wire))
                .collect(),
        )
    }
}

/// The payload of the entry named `entry` from its pieces as `get` finds
/// them, every node and chunk checked against the digest its parent lists
/// and the root against `blob.root`. A sealed payload comes back sealed.
///
/// # Errors
///
/// [`PieceError::Incomplete`] names the first piece `get` does not find (the
/// value is not available yet, never short); [`PieceError::Wrong`] a stored
/// piece that is not the listed one (the store is damaged: drop it and
/// fetch it again).
pub(crate) fn join(
    entry: &Name,
    blob: &ChunksBody,
    get: impl Fn(&Name) -> Option<Bytes>,
) -> Result<Vec<u8>, PieceError> {
    if blob.size > PAYLOAD_MAX {
        return Err(PieceError::Oversize { size: blob.size });
    }
    let shape = Shape::of(blob.size);
    let mut wanted = Listed::default();
    wanted.nodes.insert(0, blob.root);
    // Heap order lists a parent before its children.
    while let Some((k, expected)) = wanted.nodes.pop_first() {
        let name = piece_name(entry, PieceKind::Manifest(k));
        let wire = get(&name).ok_or(PieceError::Incomplete { missing: name })?;
        let digests = open_node(entry, &shape, k, &wire, &expected)?;
        wanted.list(&shape, k, digests);
    }
    let mut out = Vec::with_capacity(blob.size as usize);
    for (i, expected) in wanted.chunks {
        let name = piece_name(entry, PieceKind::Chunk(i));
        let wire = get(&name).ok_or(PieceError::Incomplete { missing: name })?;
        out.extend_from_slice(&open_chunk(entry, &shape, i, &wire, &expected)?);
    }
    Ok(out)
}

/// [`join`] over a store.
pub(crate) fn read(
    store: &dyn DataStore,
    entry: &Name,
    blob: &ChunksBody,
) -> Result<Vec<u8>, PieceError> {
    join(entry, blob, |name| store.get(name))
}
