use super::decode_be_u64;

pub struct FragmentHeader {
    pub sequence: u64,
    pub frag_index: u64,
    pub frag_count: u64,
    pub frag_start: usize,
    pub frag_end: usize,
}

/// Hot-path fragment extraction: scans for Sequence, FragIndex, FragCount, and
/// Fragment without allocating. Returns `Some` only for multi-fragment LpPackets.
/// Unfragmented packets fall through to `LpPacket::decode`.
pub fn extract_fragment(raw: &[u8]) -> Option<FragmentHeader> {
    if raw.first() != Some(&0x64) {
        return None;
    }
    let (_, type_len) = ndn_tlv::read_varu64(raw).ok()?;
    let (outer_len, len_len) = ndn_tlv::read_varu64(&raw[type_len..]).ok()?;
    let header_len = type_len + len_len;
    let inner = raw.get(header_len..header_len + outer_len as usize)?;

    let mut pos = 0;
    let mut sequence = None;
    let mut frag_index = None;
    let mut frag_count = None;
    let mut frag_start = 0;
    let mut frag_end = 0;

    while pos < inner.len() {
        let (t, tn) = ndn_tlv::read_varu64(&inner[pos..]).ok()?;
        pos += tn;
        let (l, ln) = ndn_tlv::read_varu64(&inner[pos..]).ok()?;
        pos += ln;
        let l = l as usize;
        if pos + l > inner.len() {
            return None;
        }
        match t {
            0x51 => sequence = Some(decode_be_u64(&inner[pos..pos + l])),
            0x52 => frag_index = Some(decode_be_u64(&inner[pos..pos + l])),
            0x53 => {
                let c = decode_be_u64(&inner[pos..pos + l]);
                if c <= 1 {
                    return None;
                }
                frag_count = Some(c);
            }
            0x50 => {
                frag_start = header_len + pos;
                frag_end = frag_start + l;
            }
            _ => {}
        }
        pos += l;
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
    let Some((outer_len, len_len)) = ndn_tlv::read_varu64(&raw[type_len..]).ok() else {
        return (tx_seq, acks);
    };
    let header_len = type_len + len_len;
    let Some(inner) = raw.get(header_len..header_len + outer_len as usize) else {
        return (tx_seq, acks);
    };

    let mut pos = 0;
    while pos < inner.len() {
        let Some((t, tn)) = ndn_tlv::read_varu64(&inner[pos..]).ok() else {
            break;
        };
        pos += tn;
        let Some((l, ln)) = ndn_tlv::read_varu64(&inner[pos..]).ok() else {
            break;
        };
        pos += ln;
        let l = l as usize;
        if pos + l > inner.len() {
            break;
        }
        match t {
            0x51 => tx_seq = Some(decode_be_u64(&inner[pos..pos + l])),
            0x0344 => acks.push(decode_be_u64(&inner[pos..pos + l])),
            _ => {}
        }
        pos += l;
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
            w.write_tlv(crate::tlv_type::LP_FRAG_COUNT, &[1]); // count=1, not fragmented
            w.write_tlv(crate::tlv_type::LP_FRAGMENT, &[0x05, 0x00]);
        });
        assert!(extract_fragment(&w.finish()).is_none());
    }

    #[test]
    fn extract_fragment_matches_full_decode() {
        // Ensure extract_fragment and LpPacket::decode agree on fragment content.
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
