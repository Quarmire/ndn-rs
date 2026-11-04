//! The local file a device's data layer writes for a revocation cut and the
//! root device reads to sign it ([`CutFile`]).
//!
//! A cut is what the producing device holds verified of a key, bounded by
//! the device's own observation: the entries it first verified before a
//! time (`held_before`, by its clock), and optionally up to a sequence
//! number per collection (`upto`). The file carries, beside the
//! RevocationCut TLV (0x0428, the part signed into the trust context), the
//! bound the device used, the entries the bound left out (full names with
//! their implicit digests, to re-admit one by one if they are genuine) and
//! the cut manifest's packets (the root publishes them with the version).
//!
//! The file is local: it never travels as a packet. Its container types are
//! outside the trust-context registry:
//!
//! ```text
//! CutFile        = 0xC5F0 TLV-LENGTH
//!                    RevocationCut           ; 0x0428, verbatim
//!                    [HeldBefore]
//!                    *Upto
//!                    *LeftOut
//!                    *ManifestPacket
//! HeldBefore     = 0xC5F2 TLV-LENGTH NonNegativeInteger   ; ms since the Unix epoch
//! Upto           = 0xC5F4 TLV-LENGTH Name UptoSeq         ; a collection, its last seq in the cut
//! UptoSeq        = 0xC5F6 TLV-LENGTH NonNegativeInteger
//! LeftOut        = 0xC5F8 TLV-LENGTH Name                 ; ends in its implicit digest
//! ManifestPacket = 0xC5FA TLV-LENGTH Data                 ; root packet first
//! ```
//!
//! A file holding only the RevocationCut TLV (as written before cuts were
//! bounded) decodes as a cut without a bound, which a root refuses to sign.

use std::collections::BTreeMap;

use bytes::Bytes;
use ndn_packet::{Data, Name};
use ndn_security::RevocationCut;
use ndn_security::cut_manifest::CutManifests;
use ndn_tlv::{TlvWriter, read_varu64};

use crate::context_update::BumpError;

/// The outer TLV of a cut file.
pub const CUT_FILE: u64 = 0xC5F0;
const HELD_BEFORE: u64 = 0xC5F2;
const UPTO: u64 = 0xC5F4;
const UPTO_SEQ: u64 = 0xC5F6;
const LEFT_OUT: u64 = 0xC5F8;
const MANIFEST_PACKET: u64 = 0xC5FA;
/// RevocationCut (trust-context registry).
const REVOCATION_CUT: u64 = 0x0428;

/// A revocation cut as its producing device wrote it, with the bound it
/// used, the entries the bound left out and the cut manifest's packets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CutFile {
    /// The cut signed into the trust context.
    pub cut: RevocationCut,
    /// Entries the device first verified at or after this time (ms since
    /// the Unix epoch, by the device's clock) are not in the cut.
    pub held_before: Option<u64>,
    /// Per collection, the last sequence number in the cut.
    pub upto: BTreeMap<Name, u64>,
    /// Entries of the key the device holds that the bound left out: full
    /// names ending in their implicit digests.
    pub left_out: Vec<Name>,
    /// The cut manifest's packets (Data wires), its root packet first.
    pub manifest: Vec<Bytes>,
}

/// Why bytes are not a cut file.
#[derive(Debug, thiserror::Error)]
pub enum CutFileError {
    #[error("truncated at {0}")]
    Truncated(&'static str),
    #[error("type {0:#x} where a cut file (0xC5F0) or a revocation cut (0x0428) was expected")]
    NotACutFile(u64),
    #[error("the cut file holds no revocation cut first")]
    NoCut,
    #[error("its revocation cut does not decode: {0}")]
    BadCut(String),
    #[error("a name does not decode: {0}")]
    BadName(String),
    #[error("a number is not a NonNegativeInteger of 1, 2, 4 or 8 octets")]
    BadNumber,
    #[error("a left-out entry {0} does not end in a 32-octet implicit digest")]
    LeftOutNotFullName(String),
    #[error("a manifest packet is not a Data packet: {0}")]
    BadManifestPacket(String),
    #[error("{0} appears more than once")]
    Duplicate(&'static str),
    #[error("{0} bytes follow the cut file")]
    Trailing(usize),
}

impl CutFile {
    /// `cut` alone: no bound, nothing left out, no manifest.
    pub fn new(cut: RevocationCut) -> Self {
        Self {
            cut,
            held_before: None,
            upto: BTreeMap::new(),
            left_out: Vec::new(),
            manifest: Vec::new(),
        }
    }

    /// Whether the device bounded the cut (a time, or a sequence number per
    /// collection).
    pub fn is_bounded(&self) -> bool {
        self.held_before.is_some() || !self.upto.is_empty()
    }

    /// Refuse a cut that may hold entries written after the key was lost
    /// at `lost` (ms since the Unix epoch): one without a time bound, or
    /// whose bound (`held_before`) is later than `lost`. A bound only by
    /// sequence numbers cannot be checked against a time, so it is refused
    /// too.
    pub fn check_bound(&self, lost: u64) -> Result<(), BumpError> {
        let key = self.cut.key().to_string();
        match self.held_before {
            None => Err(BumpError::CutUnbounded { key }),
            Some(held_before) if held_before > lost => Err(BumpError::CutAfterLoss {
                key,
                held_before,
                lost,
            }),
            Some(_) => Ok(()),
        }
    }

    /// Refuse a file whose manifest packets are not the whole manifest the
    /// cut names (every node reachable from its root, each held under its
    /// own digest): the root publishes them with the version, and a reader
    /// missing one cannot accept the entries it lists.
    pub fn check_manifest(&self) -> Result<(), BumpError> {
        let Some(root) = self.cut.manifest() else {
            return Ok(());
        };
        let incomplete = |reason: String| BumpError::CutManifestIncomplete {
            key: self.cut.key().to_string(),
            reason,
        };
        let held = CutManifests::new(self.manifest.len().max(1));
        for wire in &self.manifest {
            let data = Data::decode(wire.clone()).map_err(|e| incomplete(e.to_string()))?;
            held.insert(&data).map_err(|e| incomplete(e.to_string()))?;
        }
        let missing = held.missing(root);
        if !missing.is_empty() {
            let names: Vec<String> = missing.iter().map(Name::to_string).collect();
            return Err(incomplete(format!("missing {}", names.join(", "))));
        }
        Ok(())
    }

    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(CUT_FILE, |w| {
            w.write_raw(&self.cut.encode());
            if let Some(t) = self.held_before {
                w.write_tlv(HELD_BEFORE, &nni(t));
            }
            for (collection, seq) in &self.upto {
                w.write_nested(UPTO, |w| {
                    w.write_raw(&collection.encode_to_tlv());
                    w.write_tlv(UPTO_SEQ, &nni(*seq));
                });
            }
            for name in &self.left_out {
                w.write_tlv(LEFT_OUT, &name.encode_to_tlv());
            }
            for packet in &self.manifest {
                w.write_tlv(MANIFEST_PACKET, packet);
            }
        });
        w.finish()
    }

    /// A cut file, or a bare RevocationCut TLV (no bound).
    pub fn decode(wire: &[u8]) -> Result<Self, CutFileError> {
        let (t, value, rest) = read_tlv(wire)?;
        if !rest.is_empty() {
            return Err(CutFileError::Trailing(rest.len()));
        }
        match t {
            REVOCATION_CUT => Ok(Self::new(decode_cut(wire)?)),
            CUT_FILE => Self::decode_value(value),
            other => Err(CutFileError::NotACutFile(other)),
        }
    }

    fn decode_value(value: &[u8]) -> Result<Self, CutFileError> {
        let (t, _, mut cur) = read_tlv(value)?;
        if t != REVOCATION_CUT {
            return Err(CutFileError::NoCut);
        }
        let mut file = Self::new(decode_cut(&value[..value.len() - cur.len()])?);
        while !cur.is_empty() {
            let (t, v, rest) = read_tlv(cur)?;
            cur = rest;
            match t {
                HELD_BEFORE => {
                    if file.held_before.is_some() {
                        return Err(CutFileError::Duplicate("HeldBefore"));
                    }
                    file.held_before = Some(decode_nni(v)?);
                }
                UPTO => {
                    let (nt, name, rest) = read_tlv(v)?;
                    let (st, seq, rest) = read_tlv(rest)?;
                    if nt != ndn_packet::tlv_type::NAME || st != UPTO_SEQ || !rest.is_empty() {
                        return Err(CutFileError::Truncated("Upto"));
                    }
                    let collection = decode_name(name)?;
                    if file.upto.insert(collection, decode_nni(seq)?).is_some() {
                        return Err(CutFileError::Duplicate("an Upto collection"));
                    }
                }
                LEFT_OUT => {
                    let (nt, name, rest) = read_tlv(v)?;
                    if nt != ndn_packet::tlv_type::NAME || !rest.is_empty() {
                        return Err(CutFileError::Truncated("LeftOut"));
                    }
                    let name = decode_name(name)?;
                    if crate::context_update::split_full_name(&name).is_none() {
                        return Err(CutFileError::LeftOutNotFullName(name.to_string()));
                    }
                    file.left_out.push(name);
                }
                MANIFEST_PACKET => {
                    let packet = Bytes::copy_from_slice(v);
                    Data::decode(packet.clone())
                        .map_err(|e| CutFileError::BadManifestPacket(e.to_string()))?;
                    file.manifest.push(packet);
                }
                // Unknown even types are skipped (non-critical), odd refused.
                other if other % 2 == 0 => {}
                other => return Err(CutFileError::NotACutFile(other)),
            }
        }
        Ok(file)
    }
}

fn decode_cut(wire: &[u8]) -> Result<RevocationCut, CutFileError> {
    RevocationCut::decode(wire).map_err(|e| CutFileError::BadCut(e.to_string()))
}

fn decode_name(value: &[u8]) -> Result<Name, CutFileError> {
    Name::decode(Bytes::copy_from_slice(value)).map_err(|e| CutFileError::BadName(e.to_string()))
}

fn read_tlv(input: &[u8]) -> Result<(u64, &[u8], &[u8]), CutFileError> {
    let (t, tn) = read_varu64(input).map_err(|_| CutFileError::Truncated("TLV type"))?;
    let (l, ln) = read_varu64(&input[tn..]).map_err(|_| CutFileError::Truncated("TLV length"))?;
    let header = tn + ln;
    let total = usize::try_from(l)
        .ok()
        .and_then(|l| header.checked_add(l))
        .ok_or(CutFileError::Truncated("length"))?;
    if total > input.len() {
        return Err(CutFileError::Truncated("value"));
    }
    Ok((t, &input[header..total], &input[total..]))
}

/// NDN NonNegativeInteger: 1, 2, 4 or 8 big-endian octets by magnitude.
fn nni(v: u64) -> Vec<u8> {
    if let Ok(v) = u8::try_from(v) {
        vec![v]
    } else if let Ok(v) = u16::try_from(v) {
        v.to_be_bytes().to_vec()
    } else if let Ok(v) = u32::try_from(v) {
        v.to_be_bytes().to_vec()
    } else {
        v.to_be_bytes().to_vec()
    }
}

fn decode_nni(v: &[u8]) -> Result<u64, CutFileError> {
    match v.len() {
        1 | 2 | 4 | 8 => Ok(v.iter().fold(0u64, |n, b| (n << 8) | u64::from(*b))),
        _ => Err(CutFileError::BadNumber),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_packet::encode::DataBuilder;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[test]
    fn a_cut_file_reads_back_as_written() {
        let key = n("/home/bob/member/phone/KEY/k");
        let mut cut = RevocationCut::new(key.clone());
        let notes = n("/home/bob/member/phone/32=log/notes");
        cut.add_run(&notes, 1, 3);
        let mut file = CutFile::new(cut);
        file.held_before = Some(1_790_000_000_123);
        file.upto.insert(notes.clone(), 3);
        file.left_out
            .push(notes.clone().append_sequence_num(4).append_component(
                ndn_packet::NameComponent::new(
                    ndn_packet::tlv_type::IMPLICIT_SHA256,
                    Bytes::from_static(&[7; 32]),
                ),
            ));
        file.manifest
            .push(DataBuilder::new(n("/home/bob/32=trust-context/32=cut/x/seg=0"), b"m").build());
        let back = CutFile::decode(&file.encode()).unwrap();
        assert_eq!(back, file);
        assert!(back.is_bounded());
    }

    #[test]
    fn a_bare_revocation_cut_is_a_cut_without_a_bound() {
        let cut = RevocationCut::new(n("/home/bob/member/phone/KEY/k"));
        let file = CutFile::decode(&cut.encode()).unwrap();
        assert_eq!(file.cut, cut);
        assert!(!file.is_bounded());
    }

    #[test]
    fn a_left_out_entry_must_be_a_full_name() {
        let mut file = CutFile::new(RevocationCut::new(n("/a/member/p/KEY/k")));
        file.left_out.push(n("/a/member/p/32=log/c/seq=1"));
        assert!(matches!(
            CutFile::decode(&file.encode()),
            Err(CutFileError::LeftOutNotFullName(_))
        ));
    }
}
