use super::decode_be_u64;

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
