use super::decode_be_u64;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

pub struct FragmentHeader {
    pub sequence: u64,
    pub frag_index: u64,
    pub frag_count: u64,
    pub frag_start: usize,
    pub frag_end: usize,
}

/// Hot-path fragment extraction without allocation. Returns `Some` only for
/// multi-fragment LpPackets; unfragmented packets fall through to `LpPacket::decode`.
pub fn extract_fragment(raw: &[u8]) -> Option<FragmentHeader> {
    if raw.first() != Some(&0x64) {
        return None;
    }
    let (_, type_len) = ndn_tlv::read_varu64(raw).ok()?;
    let (outer_len, len_len) = ndn_tlv::read_varu64(raw.get(type_len..)?).ok()?;
    // All offset arithmetic is `checked_*` + slice `.get()` (never `+` / `[..]`)
    // so an attacker-controlled length near `u64::MAX` cannot overflow `usize`
    // and panic the receive path (audit W-2, same class as W-1).
    let header_len = type_len.checked_add(len_len)?;
    let inner_end = header_len.checked_add(usize::try_from(outer_len).ok()?)?;
    let inner = raw.get(header_len..inner_end)?;

    let mut pos = 0usize;
    let mut sequence = None;
    let mut frag_index = None;
    let mut frag_count = None;
    let mut frag_start = 0usize;
    let mut frag_end = 0usize;

    while pos < inner.len() {
        let (t, tn) = ndn_tlv::read_varu64(inner.get(pos..)?).ok()?;
        pos = pos.checked_add(tn)?;
        let (l, ln) = ndn_tlv::read_varu64(inner.get(pos..)?).ok()?;
        pos = pos.checked_add(ln)?;
        let l = usize::try_from(l).ok()?;
        let end = pos.checked_add(l)?;
        let val = inner.get(pos..end)?;
        match t {
            0x51 => sequence = Some(decode_be_u64(val)),
            0x52 => frag_index = Some(decode_be_u64(val)),
            0x53 => {
                let c = decode_be_u64(val);
                if c <= 1 {
                    return None;
                }
                frag_count = Some(c);
            }
            0x50 => {
                frag_start = header_len.checked_add(pos)?;
                frag_end = header_len.checked_add(end)?;
            }
            _ => {}
        }
        pos = end;
    }

    Some(FragmentHeader {
        sequence: sequence?,
        frag_index: frag_index?,
        frag_count: frag_count?,
        frag_start,
        frag_end,
    })
}

/// The NDN packet kind + name peeked from an LP frame — the cheap classification a
/// forwarding-plane feature (QoS / cognition demand) uses to key per-name policy
/// without a full packet decode. Component slices borrow the input wire.
pub struct PeekedName<'a> {
    /// `true` = Interest (`0x05`), `false` = Data (`0x06`).
    pub is_interest: bool,
    /// Name components, in order, borrowed from the wire (root name → empty).
    pub components: Vec<&'a [u8]>,
}

/// Peek the NDN packet kind + name from an LP frame **without a full decode** — the
/// hook a forwarding-plane observer uses to classify per-name QoS/demand on the fast
/// path. Handles an LP packet (`0x64`) carrying an unfragmented packet *or* the first
/// fragment of a fragmented one (the name lives in fragment 0), and a bare NDN wire
/// (`0x05`/`0x06`). Returns `None` for a continuation fragment (index > 0, no name),
/// an LP frame with no Fragment (control-only), an unrecognised head, or any
/// malformed length. Panic-free (all offsets checked) and allocation-light.
pub fn peek_lp_name(lp_wire: &[u8]) -> Option<PeekedName<'_>> {
    let pkt = ndn_packet_bytes(lp_wire)?;
    let (ptype, tn) = ndn_tlv::read_varu64(pkt).ok()?;
    let is_interest = match ptype {
        0x05 => true,
        0x06 => false,
        _ => return None,
    };
    let (_plen, ln) = ndn_tlv::read_varu64(pkt.get(tn..)?).ok()?;
    let body = pkt.get(tn.checked_add(ln)?..)?;
    // The first inner TLV of an Interest/Data is always the Name (0x07).
    let (ntype, ntn) = ndn_tlv::read_varu64(body).ok()?;
    if ntype != 0x07 {
        return None;
    }
    let (nlen, nln) = ndn_tlv::read_varu64(body.get(ntn..)?).ok()?;
    let name_start = ntn.checked_add(nln)?;
    let name_val =
        body.get(name_start..name_start.checked_add(usize::try_from(nlen).ok()?)?)?;
    let mut components = Vec::new();
    let mut pos = 0usize;
    while pos < name_val.len() {
        let (_ct, ctn) = ndn_tlv::read_varu64(name_val.get(pos..)?).ok()?;
        pos = pos.checked_add(ctn)?;
        let (cl, cln) = ndn_tlv::read_varu64(name_val.get(pos..)?).ok()?;
        pos = pos.checked_add(cln)?;
        let end = pos.checked_add(usize::try_from(cl).ok()?)?;
        components.push(name_val.get(pos..end)?);
        pos = end;
    }
    Some(PeekedName {
        is_interest,
        components,
    })
}

/// The NDN-packet byte slice within an LP frame: the Fragment (`0x50`) payload of an
/// LP packet (fragment 0 only — else `None`), or the whole wire if it is already a
/// bare NDN packet (`0x05`/`0x06`). `None` for anything else.
///
/// Public so integrations that peeked the name with [`peek_lp_name`] and matched a
/// self-contained (single-fragment) control Data — e.g. a reception report on
/// `/localhop/radio/report/*` — can pull its NDN wire and `Data::decode` the Content
/// without reassembling through the forwarder.
pub fn lp_ndn_packet_bytes(lp_wire: &[u8]) -> Option<&[u8]> {
    ndn_packet_bytes(lp_wire)
}

fn ndn_packet_bytes(lp_wire: &[u8]) -> Option<&[u8]> {
    match lp_wire.first() {
        Some(0x05 | 0x06) => Some(lp_wire),
        Some(0x64) => {
            let (_t, tn) = ndn_tlv::read_varu64(lp_wire).ok()?;
            let (olen, ln) = ndn_tlv::read_varu64(lp_wire.get(tn..)?).ok()?;
            let hstart = tn.checked_add(ln)?;
            let inner = lp_wire.get(hstart..hstart.checked_add(usize::try_from(olen).ok()?)?)?;
            let mut pos = 0usize;
            let mut frag = None;
            while pos < inner.len() {
                let (t, tn) = ndn_tlv::read_varu64(inner.get(pos..)?).ok()?;
                pos = pos.checked_add(tn)?;
                let (l, ln) = ndn_tlv::read_varu64(inner.get(pos..)?).ok()?;
                pos = pos.checked_add(ln)?;
                let end = pos.checked_add(usize::try_from(l).ok()?)?;
                let val = inner.get(pos..end)?;
                match t {
                    0x52 if decode_be_u64(val) != 0 => return None, // continuation fragment
                    0x50 => frag = Some(val),
                    _ => {}
                }
                pos = end;
            }
            frag
        }
        _ => None,
    }
}

pub fn extract_acks(raw: &[u8]) -> (Option<u64>, smallvec::SmallVec<[u64; 8]>) {
    let mut tx_seq = None;
    let mut acks = smallvec::SmallVec::new();

    if raw.first() != Some(&0x64) {
        return (tx_seq, acks);
    }
    let Some((_, type_len)) = ndn_tlv::read_varu64(raw).ok() else {
        return (tx_seq, acks);
    };
    let Some(after_type) = raw.get(type_len..) else {
        return (tx_seq, acks);
    };
    let Some((outer_len, len_len)) = ndn_tlv::read_varu64(after_type).ok() else {
        return (tx_seq, acks);
    };
    // Checked arithmetic + `.get()` throughout (audit W-2).
    let Some(header_len) = type_len.checked_add(len_len) else {
        return (tx_seq, acks);
    };
    let Some(inner_end) = usize::try_from(outer_len)
        .ok()
        .and_then(|o| header_len.checked_add(o))
    else {
        return (tx_seq, acks);
    };
    let Some(inner) = raw.get(header_len..inner_end) else {
        return (tx_seq, acks);
    };

    let mut pos = 0usize;
    while pos < inner.len() {
        let Some((t, tn)) = inner.get(pos..).and_then(|s| ndn_tlv::read_varu64(s).ok()) else {
            break;
        };
        let Some(np) = pos.checked_add(tn) else { break };
        pos = np;
        let Some((l, ln)) = inner.get(pos..).and_then(|s| ndn_tlv::read_varu64(s).ok()) else {
            break;
        };
        let Some(np) = pos.checked_add(ln) else { break };
        pos = np;
        let Some(l) = usize::try_from(l).ok() else {
            break;
        };
        let Some(end) = pos.checked_add(l) else { break };
        let Some(val) = inner.get(pos..end) else {
            break;
        };
        match t {
            0x0348 => tx_seq = Some(decode_be_u64(val)),
            0x0344 => acks.push(decode_be_u64(val)),
            _ => {}
        }
        pos = end;
    }
    (tx_seq, acks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::encode_interest;
    use crate::lp::{LpPacket, encode_lp_acks, encode_lp_packet, encode_lp_reliable};
    use crate::{Name, NameComponent};
    use bytes::Bytes;
    use ndn_tlv::TlvWriter;

    fn name(comps: &[&[u8]]) -> Name {
        Name::from_components(
            comps
                .iter()
                .map(|c| NameComponent::generic(Bytes::copy_from_slice(c))),
        )
    }

    #[test]
    fn extract_fragment_returns_correct_fields() {
        let n = name(&[b"test"]);
        let interest_wire = encode_interest(&n, None);

        let mut w = TlvWriter::new();
        w.write_nested(crate::tlv_type::LP_PACKET, |w| {
            w.write_tlv(crate::tlv_type::LP_SEQUENCE, &42u64.to_be_bytes());
            w.write_tlv(crate::tlv_type::LP_FRAG_INDEX, &[1]);
            w.write_tlv(crate::tlv_type::LP_FRAG_COUNT, &[3]);
            w.write_tlv(crate::tlv_type::LP_FRAGMENT, &interest_wire);
        });
        let raw = w.finish();

        let hdr = extract_fragment(&raw).unwrap();
        assert_eq!(hdr.sequence, 42);
        assert_eq!(hdr.frag_index, 1);
        assert_eq!(hdr.frag_count, 3);
        assert_eq!(&raw[hdr.frag_start..hdr.frag_end], &interest_wire[..]);
    }

    #[test]
    fn extract_fragment_returns_none_for_unfragmented() {
        let n = name(&[b"test"]);
        let interest_wire = encode_interest(&n, None);
        let lp_wire = encode_lp_packet(&interest_wire);
        assert!(extract_fragment(&lp_wire).is_none());
    }

    #[test]
    fn peek_lp_name_reads_kind_and_components() {
        let n = name(&[b"radio-demo", b"ping", b"42"]);
        let interest_wire = encode_interest(&n, None);
        // Unfragmented LP-wrapped Interest.
        let lp = encode_lp_packet(&interest_wire);
        let p = peek_lp_name(&lp).expect("peek LP");
        assert!(p.is_interest);
        assert_eq!(p.components, vec![&b"radio-demo"[..], b"ping", b"42"]);
        // Bare NDN wire (no LP wrapper) also works.
        let p2 = peek_lp_name(&interest_wire).expect("peek bare");
        assert!(p2.is_interest);
        assert_eq!(p2.components, vec![&b"radio-demo"[..], b"ping", b"42"]);
    }

    #[test]
    fn peek_lp_name_first_fragment_has_name_continuation_does_not() {
        let n = name(&[b"obj", b"v1"]);
        let interest_wire = encode_interest(&n, None);
        let mk = |idx: u8| {
            let mut w = TlvWriter::new();
            w.write_nested(crate::tlv_type::LP_PACKET, |w| {
                w.write_tlv(crate::tlv_type::LP_SEQUENCE, &7u64.to_be_bytes());
                w.write_tlv(crate::tlv_type::LP_FRAG_INDEX, &[idx]);
                w.write_tlv(crate::tlv_type::LP_FRAG_COUNT, &[2]);
                w.write_tlv(crate::tlv_type::LP_FRAGMENT, &interest_wire);
            });
            w.finish()
        };
        // Fragment 0 carries the name.
        let f0 = mk(0);
        let p = peek_lp_name(&f0).expect("frag 0 peek");
        assert_eq!(p.components, vec![&b"obj"[..], b"v1"]);
        // A continuation fragment (index > 0) has no name at the head → None.
        let f1 = mk(1);
        assert!(peek_lp_name(&f1).is_none());
    }

    #[test]
    fn peek_lp_name_none_for_control_only_and_garbage() {
        // Control-only LP frame (pure ACKs, no Fragment).
        assert!(peek_lp_name(&encode_lp_acks(&[1, 2, 3])).is_none());
        // Garbage / non-NDN head.
        assert!(peek_lp_name(&[0xff, 0x00, 0x01]).is_none());
        assert!(peek_lp_name(&[]).is_none());
    }

    #[test]
    fn extract_fragment_returns_none_for_single_fragment() {
        let mut w = TlvWriter::new();
        w.write_nested(crate::tlv_type::LP_PACKET, |w| {
            w.write_tlv(crate::tlv_type::LP_SEQUENCE, &[0]);
            w.write_tlv(crate::tlv_type::LP_FRAG_INDEX, &[0]);
            w.write_tlv(crate::tlv_type::LP_FRAG_COUNT, &[1]);
            w.write_tlv(crate::tlv_type::LP_FRAGMENT, &[0x05, 0x00]);
        });
        assert!(extract_fragment(&w.finish()).is_none());
    }

    #[test]
    fn extract_fragment_matches_full_decode() {
        use crate::fragment::fragment_packet;
        let data: Vec<u8> = (0..3000).map(|i| (i % 256) as u8).collect();
        let frags = fragment_packet(&data, 500, 99);
        for frag_bytes in &frags {
            let hdr = extract_fragment(frag_bytes).unwrap();
            let lp = LpPacket::decode(Bytes::copy_from_slice(frag_bytes)).unwrap();
            assert_eq!(hdr.sequence, lp.sequence.unwrap());
            assert_eq!(hdr.frag_index, lp.frag_index.unwrap());
            assert_eq!(hdr.frag_count, lp.frag_count.unwrap());
            assert_eq!(
                &frag_bytes[hdr.frag_start..hdr.frag_end],
                &lp.fragment.unwrap()[..]
            );
        }
    }

    #[test]
    fn extract_acks_from_reliable_packet() {
        let wire = encode_lp_reliable(&[0x05, 0x00], 42, None, &[10, 20, 30]);
        let (seq, acks) = extract_acks(&wire);
        assert_eq!(seq, Some(42));
        assert_eq!(&acks[..], &[10, 20, 30]);
    }

    #[test]
    fn extract_acks_from_ack_only() {
        let wire = encode_lp_acks(&[7, 8]);
        let (seq, acks) = extract_acks(&wire);
        assert_eq!(seq, None);
        assert_eq!(&acks[..], &[7, 8]);
    }

    // --- W-2 regression: malformed LP lengths must not panic ----------------

    #[test]
    fn extract_fragment_huge_outer_length_no_panic() {
        // 0x64 (LpPacket) then a 9-byte u64::MAX outer length.
        let raw = vec![0x64, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        assert!(extract_fragment(&raw).is_none());
    }

    #[test]
    fn extract_fragment_huge_subtlv_length_no_panic() {
        // Valid-ish outer, but an inner sub-TLV (0x51 Sequence) with a 9-byte
        // u64::MAX length → the inner walk must reject, not panic.
        let inner = vec![0x51, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let mut raw = vec![0x64, inner.len() as u8];
        raw.extend_from_slice(&inner);
        assert!(extract_fragment(&raw).is_none());
    }

    #[test]
    fn extract_acks_huge_length_no_panic() {
        let raw = vec![0x64, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let (seq, acks) = extract_acks(&raw);
        assert!(seq.is_none() && acks.is_empty());
    }

    #[test]
    fn extract_acks_from_plain_lp() {
        let n = name(&[b"test"]);
        let interest_wire = encode_interest(&n, None);
        let wire = encode_lp_packet(&interest_wire);
        let (seq, acks) = extract_acks(&wire);
        assert_eq!(seq, None);
        assert!(acks.is_empty());
    }
}
