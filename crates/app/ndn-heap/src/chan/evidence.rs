//! What a receiver keeps when a frame is shown not to be the sender's (docs/specs/channel.md,
//! Checkpoints): [`ChannelEvidence`], the last 64 in memory, readable with
//! [`crate::NodeHandle::channel_evidence`] and serializable with [`ChannelEvidence::encode`].
//!
//! Evidence proves that **a holder of the channel key** made a frame the sender's signature
//! contradicts. It does not say which holder (the sender equivocating, a receiver, a member
//! relaying): the ingress face narrows it to the link the frame came over.

use std::collections::VecDeque;

use bytes::{BufMut, Bytes, BytesMut};
use ndn_foundation_types::Name;
use ndn_transport::FaceId;
use parking_lot::Mutex;

use super::varint;
use crate::error::Timestamp;

/// How many pieces of evidence a node keeps: the newest.
pub const EVIDENCE_KEPT: usize = 64;

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
    /// evidence is against.
    pub frame: Bytes,
    /// The face the frame came over.
    pub ingress: FaceId,
    /// What contradicts it: see [`EvidenceKind`] (the signed checkpoint frame for a `Mismatch`).
    /// With the channel key's holder's help a third party can open both and check the signature
    /// against the sender's key; the layout of the checkpoint is in `docs/specs/channel.md`.
    pub proof: Bytes,
    /// This device's wall clock when the evidence was made.
    pub when: Timestamp,
}

/// Why evidence octets do not decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("the octets are no channel evidence (version 1): {0}")]
pub struct EvidenceError(&'static str);

/// The first octet of an encoded piece of evidence: its layout's version.
pub const EVIDENCE_VERSION: u8 = 1;

impl ChannelEvidence {
    /// The evidence as octets (version 1):
    ///
    /// ```text
    /// version (1, = 1) | kind (1: 1 Mismatch, 2 Conflict, 3 BadCheckpoint)
    /// channel id (8, big-endian) | key epoch (4) | seq0 (8) | ingress face (8) | when, ms (8)
    /// sender: length (varint) | its Name as a complete Name TLV
    /// frame: length (varint) | octets
    /// proof: length (varint) | octets
    /// ```
    ///
    /// Every integer is big-endian; a varint is the QUIC variable-length integer.
    pub fn encode(&self) -> Bytes {
        let name = self.sender.encode_to_tlv();
        let mut out =
            BytesMut::with_capacity(48 + name.len() + self.frame.len() + self.proof.len());
        out.put_u8(EVIDENCE_VERSION);
        out.put_u8(self.kind.code());
        out.put_u64(self.channel);
        out.put_u32(self.key_epoch);
        out.put_u64(self.seq0);
        out.put_u64(self.ingress.0);
        out.put_u64(self.when.0);
        for part in [&name, &self.frame, &self.proof] {
            // The parts are at most a name and two frames: far below a varint's limit.
            let _ = varint::write(&mut out, part.len() as u64);
            out.put_slice(part);
        }
        out.freeze()
    }

    /// Reads what [`Self::encode`] wrote.
    ///
    /// # Errors
    ///
    /// [`EvidenceError`] for octets that are not version-1 evidence: a wrong version, an unknown
    /// kind, a part that runs past the end, a name that is not a Name TLV, or octets left over.
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
        let mut at = fixed;
        let mut part = |what: &'static str| -> Result<Bytes, EvidenceError> {
            let (len, n) = varint::read(&octets[at..]).ok_or(EvidenceError(what))?;
            at += n;
            let end = usize::try_from(len)
                .ok()
                .and_then(|len| at.checked_add(len))
                .filter(|end| *end <= octets.len())
                .ok_or(EvidenceError(what))?;
            let bytes = Bytes::copy_from_slice(&octets[at..end]);
            at = end;
            Ok(bytes)
        };
        let name = part("the sender's name runs past the end")?;
        let frame = part("the frame runs past the end")?;
        let proof = part("the proof runs past the end")?;
        if at != octets.len() {
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
            ingress: FaceId(ingress),
            proof,
            when: Timestamp(when),
        })
    }
}

/// The last [`EVIDENCE_KEPT`] pieces of evidence a node made.
#[derive(Default)]
pub(crate) struct EvidenceLog {
    kept: Mutex<VecDeque<ChannelEvidence>>,
}

impl EvidenceLog {
    /// Keep `evidence`; the oldest goes when 64 are held.
    pub(crate) fn push(&self, evidence: ChannelEvidence) {
        let mut kept = self.kept.lock();
        if kept.len() >= EVIDENCE_KEPT {
            kept.pop_front();
        }
        kept.push_back(evidence);
    }

    /// What is kept, oldest first.
    pub(crate) fn all(&self) -> Vec<ChannelEvidence> {
        self.kept.lock().iter().cloned().collect()
    }
}

impl crate::host::NodeHandle {
    /// The evidence this node holds that a frame of a channel was not its sender's: the last
    /// [`EVIDENCE_KEPT`] (64), oldest first, in memory only (a restart forgets them). Each is made
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
            ingress: FaceId(9),
            proof: Bytes::from(vec![0xCD; 150]),
            when: Timestamp(1_700_000_000_123),
        }
    }

    /// Every kind survives `encode` then `decode` with every field, and the layout is the one the
    /// docs state (a fixed 38-octet header, then three length-prefixed parts).
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
        other[0] = 2;
        assert!(ChannelEvidence::decode(&other).is_err(), "version 2");
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
}
