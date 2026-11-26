//! What a receiver keeps when a frame is shown not to be the sender's (docs/specs/channel.md,
//! Checkpoints): [`ChannelEvidence`], the last 64 in memory (and at most 4 MiB of octets between
//! them), readable with [`crate::host::NodeHandle::channel_evidence`] and serializable with
//! [`ChannelEvidence::encode`].
//!
//! Evidence proves that **a holder of the channel key** made a frame the sender's signature
//! contradicts. It does not say which holder (the sender equivocating, a receiver, a member
//! relaying): the ingress face narrows it to the link the frame came over.

use std::collections::VecDeque;

use bytes::{BufMut, Bytes, BytesMut};
use ndn_foundation_types::Name;
use ndn_transport::FaceId;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};

use super::varint;
use crate::error::Timestamp;

/// How many pieces of evidence a node keeps: the newest.
pub const EVIDENCE_KEPT: usize = 64;

/// The most octets of one part of a piece of evidence (the frame, the proof) that are kept: 128
/// KiB. A part over it is kept as its length and its SHA-256 only ([`EvidenceDigest`]): the
/// stream class carries frames of up to 1 MiB, and 64 of them with their proofs would hold tens
/// of MiB of a node's memory for a peer's choosing.
pub const EVIDENCE_PART_KEPT: usize = 128 * 1024;

/// The most octets of frames and proofs the evidence of a node holds in all: 4 MiB. The oldest
/// goes first, whatever the count.
pub const EVIDENCE_OCTETS: usize = 4 * 1024 * 1024;

/// What the evidence shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EvidenceKind {
    /// A frame this device accepted, in the range of a signed checkpoint that does not list it or
    /// lists another hash at its sequence. [`ChannelEvidence::proof`] is the signed checkpoint
    /// frame, [`ChannelEvidence::frame`] the contradicted frame.
    Mismatch,
    /// Two authentic frames at one sequence with different octets (the first accepted won; the
    /// second was an event, not a delivery). [`ChannelEvidence::frame`] is the second,
    /// [`ChannelEvidence::proof`] the first (empty if it was forgotten). It does not say which is
    /// the sender's: the next checkpoint that covers the sequence does, as a `Mismatch` of the
    /// other.
    Conflict,
    /// A checkpoint that opened under the channel key and does not verify under the sender's:
    /// [`ChannelEvidence::frame`] is that checkpoint frame, [`ChannelEvidence::proof`] is empty.
    BadCheckpoint,
}

impl EvidenceKind {
    fn code(self) -> u8 {
        match self {
            EvidenceKind::Mismatch => 1,
            EvidenceKind::Conflict => 2,
            EvidenceKind::BadCheckpoint => 3,
        }
    }

    fn of(code: u8) -> Option<Self> {
        match code {
            1 => Some(EvidenceKind::Mismatch),
            2 => Some(EvidenceKind::Conflict),
            3 => Some(EvidenceKind::BadCheckpoint),
            _ => None,
        }
    }
}

/// One piece of evidence that a holder of a channel's key made a frame the sender did not send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelEvidence {
    /// What it shows.
    pub kind: EvidenceKind,
    /// The channel id.
    pub channel: u64,
    /// The sender's device, whose channel it is.
    pub sender: Name,
    /// The channel's key epoch (all 32 bits).
    pub key_epoch: u32,
    /// The first sequence of the frame.
    pub seq0: u64,
    /// The frame octets this device accepted (header, ciphertext, tag), as they came: what the
    /// evidence is against. Empty when [`Self::frame_digest`] is set: a frame over
    /// [`EVIDENCE_PART_KEPT`] is kept as its length and hash.
    pub frame: Bytes,
    /// The length and SHA-256 of the frame when it was too long to keep, else `None`.
    pub frame_digest: Option<EvidenceDigest>,
    /// The face the frame came over.
    pub ingress: FaceId,
    /// What contradicts it: see [`EvidenceKind`] (the signed checkpoint frame for a `Mismatch`).
    /// With the channel key's holder's help a third party can open both and check the signature
    /// against the sender's key; the layout of the checkpoint is in `docs/specs/channel.md`.
    /// Empty when [`Self::proof_digest`] is set.
    pub proof: Bytes,
    /// The length and SHA-256 of the proof when it was too long to keep, else `None`.
    pub proof_digest: Option<EvidenceDigest>,
    /// This device's wall clock when the evidence was made.
    pub when: Timestamp,
}

/// What a part of evidence was before it was too long to keep: its length and its SHA-256.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvidenceDigest {
    /// The octets there were.
    pub len: u64,
    /// Their SHA-256: a holder of the frame can check it is the one the evidence was made against.
    pub hash: [u8; 32],
}

/// `octets` as kept: whole up to [`EVIDENCE_PART_KEPT`], else nothing and the digest.
fn keep(octets: Bytes) -> (Bytes, Option<EvidenceDigest>) {
    if octets.len() <= EVIDENCE_PART_KEPT {
        return (octets, None);
    }
    let digest = EvidenceDigest {
        len: octets.len() as u64,
        hash: Sha256::digest(&octets).into(),
    };
    (Bytes::new(), Some(digest))
}

/// Why evidence octets do not decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("the octets are no channel evidence (version 2): {0}")]
pub struct EvidenceError(&'static str);

/// The first octet of an encoded piece of evidence: its layout's version.
pub const EVIDENCE_VERSION: u8 = 2;

impl ChannelEvidence {
    /// Evidence of `kind`: `frame` and `proof` are kept whole up to [`EVIDENCE_PART_KEPT`] each,
    /// and as their length and SHA-256 above it.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        kind: EvidenceKind,
        channel: u64,
        sender: Name,
        key_epoch: u32,
        seq0: u64,
        frame: Bytes,
        ingress: FaceId,
        proof: Bytes,
        when: Timestamp,
    ) -> ChannelEvidence {
        let (frame, frame_digest) = keep(frame);
        let (proof, proof_digest) = keep(proof);
        ChannelEvidence {
            kind,
            channel,
            sender,
            key_epoch,
            seq0,
            frame,
            frame_digest,
            ingress,
            proof,
            proof_digest,
            when,
        }
    }

    /// The octets this piece of evidence holds in memory: what a node's total is counted in.
    fn octets(&self) -> usize {
        self.frame.len() + self.proof.len()
    }

    /// The evidence as octets (version 2):
    ///
    /// ```text
    /// version (1, = 2) | kind (1: 1 Mismatch, 2 Conflict, 3 BadCheckpoint)
    /// channel id (8, big-endian) | key epoch (4) | seq0 (8) | ingress face (8) | when, ms (8)
    /// sender: length (varint) | its Name as a complete Name TLV
    /// frame: length (varint, of the frame as it was) | kept (1: 1 octets follow, 0 SHA-256
    ///        follows) | the octets, or the 32-octet SHA-256 of them
    /// proof: the same
    /// ```
    ///
    /// Every integer is big-endian; a varint is the QUIC variable-length integer. A part is kept
    /// whole up to [`EVIDENCE_PART_KEPT`] octets and as its hash above it. Version 1 (every part
    /// whole, no `kept` octet) is no longer written or read.
    pub fn encode(&self) -> Bytes {
        let name = self.sender.encode_to_tlv();
        let mut out = BytesMut::with_capacity(
            48 + name.len() + 2 * (8 + 32) + self.frame.len() + self.proof.len(),
        );
        out.put_u8(EVIDENCE_VERSION);
        out.put_u8(self.kind.code());
        out.put_u64(self.channel);
        out.put_u32(self.key_epoch);
        out.put_u64(self.seq0);
        out.put_u64(self.ingress.0);
        out.put_u64(self.when.0);
        // The parts are at most a name and two frames: far below a varint's limit.
        let _ = varint::write(&mut out, name.len() as u64);
        out.put_slice(&name);
        for (octets, digest) in [
            (&self.frame, &self.frame_digest),
            (&self.proof, &self.proof_digest),
        ] {
            match digest {
                None => {
                    let _ = varint::write(&mut out, octets.len() as u64);
                    out.put_u8(1);
                    out.put_slice(octets);
                }
                Some(digest) => {
                    let _ = varint::write(&mut out, digest.len);
                    out.put_u8(0);
                    out.put_slice(&digest.hash);
                }
            }
        }
        out.freeze()
    }

    /// Reads what [`Self::encode`] wrote.
    ///
    /// # Errors
    ///
    /// [`EvidenceError`] for octets that are not version-2 evidence: a wrong version, an unknown
    /// kind, a part that runs past the end or whose octets are not the length it states, a name
    /// that is not a Name TLV, or octets left over.
    pub fn decode(octets: &[u8]) -> Result<ChannelEvidence, EvidenceError> {
        let fixed = 1 + 1 + 8 + 4 + 8 + 8 + 8;
        let head = octets
            .get(..fixed)
            .ok_or(EvidenceError("it ends inside the header"))?;
        if head[0] != EVIDENCE_VERSION {
            return Err(EvidenceError("another version"));
        }
        let kind = EvidenceKind::of(head[1]).ok_or(EvidenceError("an unknown kind"))?;
        let be = |from: usize, len: usize| -> u64 {
            head[from..from + len]
                .iter()
                .fold(0, |acc, b| (acc << 8) | u64::from(*b))
        };
        let (channel, key_epoch, seq0, ingress, when) =
            (be(2, 8), be(10, 4) as u32, be(14, 8), be(22, 8), be(30, 8));
        let mut cursor = Cursor { octets, at: fixed };
        let name_len = cursor.varint("the sender's name runs past the end")?;
        let name =
            Bytes::copy_from_slice(cursor.take(name_len, "the sender's name runs past the end")?);
        let (frame, frame_digest) = cursor.part("the frame runs past the end")?;
        let (proof, proof_digest) = cursor.part("the proof runs past the end")?;
        if cursor.at != octets.len() {
            return Err(EvidenceError("octets are left over"));
        }
        let sender = Name::decode_from_tlv(name)
            .map_err(|_| EvidenceError("the sender is not a Name TLV"))?;
        Ok(ChannelEvidence {
            kind,
            channel,
            sender,
            key_epoch,
            seq0,
            frame,
            frame_digest,
            ingress: FaceId(ingress),
            proof,
            proof_digest,
            when: Timestamp(when),
        })
    }
}

/// Where [`ChannelEvidence::decode`] is in the octets.
struct Cursor<'a> {
    octets: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    /// The next `len` octets, or `what`.
    fn take(&mut self, len: u64, what: &'static str) -> Result<&'a [u8], EvidenceError> {
        let end = usize::try_from(len)
            .ok()
            .and_then(|len| self.at.checked_add(len))
            .filter(|end| *end <= self.octets.len())
            .ok_or(EvidenceError(what))?;
        let bytes = &self.octets[self.at..end];
        self.at = end;
        Ok(bytes)
    }

    /// The next varint, or `what`.
    fn varint(&mut self, what: &'static str) -> Result<u64, EvidenceError> {
        let (value, n) = varint::read(&self.octets[self.at..]).ok_or(EvidenceError(what))?;
        self.at += n;
        Ok(value)
    }

    /// A frame or a proof: its length, whether it follows whole, and the octets or their hash.
    fn part(
        &mut self,
        what: &'static str,
    ) -> Result<(Bytes, Option<EvidenceDigest>), EvidenceError> {
        let len = self.varint(what)?;
        match self.take(1, what)?[0] {
            1 => Ok((Bytes::copy_from_slice(self.take(len, what)?), None)),
            0 => {
                let hash: [u8; 32] = self
                    .take(32, what)?
                    .try_into()
                    .map_err(|_| EvidenceError(what))?;
                Ok((Bytes::new(), Some(EvidenceDigest { len, hash })))
            }
            _ => Err(EvidenceError("a part is neither whole nor a hash")),
        }
    }
}

/// The last [`EVIDENCE_KEPT`] pieces of evidence a node made, within [`EVIDENCE_OCTETS`].
#[derive(Default)]
pub(crate) struct EvidenceLog {
    kept: Mutex<Pieces>,
}

#[derive(Default)]
struct Pieces {
    pieces: VecDeque<ChannelEvidence>,
    /// The octets of every frame and proof in `pieces`.
    octets: usize,
}

impl EvidenceLog {
    /// Keep `evidence`; the oldest go while 64 are held or the octets held would pass 4 MiB. A
    /// piece holds at most two parts of [`EVIDENCE_PART_KEPT`], so it always fits alone.
    pub(crate) fn push(&self, evidence: ChannelEvidence) {
        let mut kept = self.kept.lock();
        let more = evidence.octets();
        while kept.pieces.len() >= EVIDENCE_KEPT || kept.octets + more > EVIDENCE_OCTETS {
            let Some(old) = kept.pieces.pop_front() else {
                break;
            };
            kept.octets -= old.octets();
        }
        kept.octets += more;
        kept.pieces.push_back(evidence);
    }

    /// What is kept, oldest first.
    pub(crate) fn all(&self) -> Vec<ChannelEvidence> {
        self.kept.lock().pieces.iter().cloned().collect()
    }

    /// The octets of frames and proofs held now.
    #[cfg(test)]
    pub(crate) fn octets(&self) -> usize {
        self.kept.lock().octets
    }
}

impl crate::host::NodeHandle {
    /// The evidence this node holds that a frame of a channel was not its sender's: the last
    /// [`EVIDENCE_KEPT`] (64) and at most [`EVIDENCE_OCTETS`] (4 MiB) of frames and proofs, oldest
    /// first, in memory only (a restart forgets them). A frame or a proof over
    /// [`EVIDENCE_PART_KEPT`] is kept as its length and SHA-256 ([`EvidenceDigest`]). Each is made
    /// the moment a signed checkpoint contradicts an accepted frame, two authentic frames come at
    /// one sequence, or a checkpoint is not the sender's; [`ChannelEvidence::encode`] serializes
    /// one. It proves that a **holder of the channel key** made the frame, and the face it came
    /// over ([`ChannelEvidence::ingress`]) is where to look; it does not say which holder.
    pub fn channel_evidence(&self) -> Vec<ChannelEvidence> {
        self.inner.chan.evidence.all()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_kit::n;

    fn evidence(kind: EvidenceKind, seq0: u64) -> ChannelEvidence {
        ChannelEvidence {
            kind,
            channel: 0x0102_0304_0506_0708,
            sender: n("/bob/phone"),
            key_epoch: 0x0000_0102,
            seq0,
            frame: Bytes::from(vec![0xAB; 300]),
            frame_digest: None,
            ingress: FaceId(9),
            proof: Bytes::from(vec![0xCD; 150]),
            proof_digest: None,
            when: Timestamp(1_700_000_000_123),
        }
    }

    /// Every kind survives `encode` then `decode` with every field, and the layout is the one the
    /// docs state (a fixed 38-octet header, the name, then a frame and a proof each with its length,
    /// a kept octet and the octets).
    #[test]
    fn evidence_encodes_and_decodes_every_field_of_every_kind() {
        for kind in [
            EvidenceKind::Mismatch,
            EvidenceKind::Conflict,
            EvidenceKind::BadCheckpoint,
        ] {
            let one = evidence(kind, 77);
            let octets = one.encode();
            assert_eq!(octets[0], EVIDENCE_VERSION);
            assert_eq!(octets[1], kind.code());
            assert_eq!(&octets[2..10], &0x0102_0304_0506_0708u64.to_be_bytes());
            assert_eq!(&octets[10..14], &[0, 0, 1, 2]);
            assert_eq!(&octets[14..22], &77u64.to_be_bytes());
            assert_eq!(&octets[22..30], &9u64.to_be_bytes());
            assert_eq!(&octets[30..38], &1_700_000_000_123u64.to_be_bytes());
            assert_eq!(ChannelEvidence::decode(&octets), Ok(one));
            // The name is a varint length and a Name TLV; the frame follows: its length (300 is
            // the two-octet varint 0x412C), 1 (whole), its octets; then the proof's 150 (0x4096).
            let at = 38 + 1 + usize::from(octets[38]);
            assert_eq!(&octets[at..at + 3], &[0x41, 0x2C, 1]);
            assert_eq!(&octets[at + 3..at + 303], &[0xAB; 300][..]);
            assert_eq!(&octets[at + 303..at + 306], &[0x40, 0x96, 1]);
            assert_eq!(octets.len(), at + 306 + 150);
        }
        let empty_proof = ChannelEvidence {
            proof: Bytes::new(),
            frame: Bytes::new(),
            ..evidence(EvidenceKind::BadCheckpoint, 0)
        };
        assert_eq!(
            ChannelEvidence::decode(&empty_proof.encode()),
            Ok(empty_proof)
        );
    }

    /// Octets that are not evidence are refused, whatever the damage: another version, an unknown
    /// kind, any cut, a part that claims more than is left, and octets left over. Nothing panics.
    #[test]
    fn damaged_evidence_is_refused_not_misread() {
        let octets = evidence(EvidenceKind::Mismatch, 5).encode().to_vec();
        for len in 0..octets.len() {
            assert!(
                ChannelEvidence::decode(&octets[..len]).is_err(),
                "a cut at {len} of {} octets",
                octets.len()
            );
        }
        let mut other = octets.clone();
        other[0] = 1;
        assert!(
            ChannelEvidence::decode(&other).is_err(),
            "version 1 is no longer read"
        );
        other[0] = 3;
        assert!(ChannelEvidence::decode(&other).is_err(), "version 3");
        for code in [0u8, 4, 255] {
            let mut unknown = octets.clone();
            unknown[1] = code;
            assert!(ChannelEvidence::decode(&unknown).is_err(), "kind {code}");
        }
        let mut longer = octets.clone();
        longer.push(0);
        assert!(
            ChannelEvidence::decode(&longer).is_err(),
            "an octet left over"
        );
        // The name's length claims more than the whole record holds.
        let mut claims = octets.clone();
        claims[38] = 0x3F;
        assert!(ChannelEvidence::decode(&claims).is_err());
        // A part is whole (1) or a hash (0), nothing else.
        let at = 38 + 1 + usize::from(octets[38]) + 2;
        let mut neither = octets.clone();
        neither[at] = 2;
        assert!(
            ChannelEvidence::decode(&neither).is_err(),
            "a kept octet of 2"
        );
    }

    /// A node keeps the last 64 pieces of evidence, oldest first: the 65th pushes out the first.
    #[test]
    fn the_log_keeps_the_last_64_oldest_first() {
        let log = EvidenceLog::default();
        assert!(log.all().is_empty());
        for seq0 in 0..(EVIDENCE_KEPT as u64 + 6) {
            log.push(evidence(EvidenceKind::Mismatch, seq0));
        }
        let kept = log.all();
        assert_eq!(EVIDENCE_KEPT, 64);
        assert_eq!(kept.len(), 64);
        assert_eq!(kept.first().unwrap().seq0, 6, "the six oldest went");
        assert_eq!(kept.last().unwrap().seq0, 69);
        assert!(kept.windows(2).all(|w| w[0].seq0 + 1 == w[1].seq0));
    }

    /// A frame or a proof over 128 KiB is kept as its length and SHA-256, whole at or under it
    /// (security review L4), and the hash survives `encode` and `decode`.
    #[test]
    fn a_part_over_the_limit_is_kept_as_its_hash() {
        let big = Bytes::from(vec![0x5A; EVIDENCE_PART_KEPT + 1]);
        let exact = Bytes::from(vec![0x5B; EVIDENCE_PART_KEPT]);
        let one = ChannelEvidence::new(
            EvidenceKind::Mismatch,
            1,
            n("/bob/phone"),
            2,
            3,
            big.clone(),
            FaceId(4),
            exact.clone(),
            Timestamp(5),
        );
        assert!(one.frame.is_empty(), "a frame over the limit is not kept");
        let digest = one.frame_digest.expect("its length and hash are");
        assert_eq!(digest.len, big.len() as u64);
        assert_eq!(digest.hash, <[u8; 32]>::from(Sha256::digest(&big)));
        assert_eq!(one.proof, exact, "a proof at the limit is kept whole");
        assert!(one.proof_digest.is_none());
        assert_eq!(one.octets(), EVIDENCE_PART_KEPT);
        let octets = one.encode();
        assert!(
            octets.len() < EVIDENCE_PART_KEPT + 300,
            "the frame is not in the octets"
        );
        assert_eq!(ChannelEvidence::decode(&octets), Ok(one));
    }

    /// All the evidence of a node holds at most 4 MiB of frames and proofs, the oldest going
    /// first, whatever the count (security review L4): 64 pieces of 256 KiB were 16 MiB.
    #[test]
    fn the_log_holds_at_most_4_mib_of_octets_oldest_first() {
        let log = EvidenceLog::default();
        for seq0 in 0..(EVIDENCE_KEPT as u64) {
            log.push(ChannelEvidence::new(
                EvidenceKind::Conflict,
                1,
                n("/bob/phone"),
                2,
                seq0,
                Bytes::from(vec![0xAB; EVIDENCE_PART_KEPT]),
                FaceId(9),
                Bytes::from(vec![0xCD; EVIDENCE_PART_KEPT]),
                Timestamp(0),
            ));
            assert!(
                log.octets() <= EVIDENCE_OCTETS,
                "after {seq0}: {}",
                log.octets()
            );
        }
        let kept = log.all();
        assert_eq!(EVIDENCE_OCTETS, 4 * 1024 * 1024);
        assert_eq!(kept.len(), 16, "4 MiB of 256 KiB pieces");
        assert_eq!(kept.last().unwrap().seq0, 63, "the newest is kept");
        assert_eq!(kept.first().unwrap().seq0, 48, "the oldest went");
        // What a peer can make the node hold: a stream frame of 1 MiB is a hash.
        let big = ChannelEvidence::new(
            EvidenceKind::Conflict,
            1,
            n("/bob/phone"),
            2,
            99,
            Bytes::from(vec![1; 1 << 20]),
            FaceId(9),
            Bytes::from(vec![2; 1 << 20]),
            Timestamp(0),
        );
        assert_eq!(big.octets(), 0);
    }
}
