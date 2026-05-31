//! NDNLPv2 **A-LAL** (Ad-hoc Link Adaptation Layer) LP TLVs for CCLF.
//!
//! Three headers ride forwarded packets as a near-free, airtime-efficient
//! substitute for dedicated beacons (CCLF, Chowdhury/Khan/Wang ICN '20 §A-LAL):
//!
//! - **Presence** (`0x0360`) — the forwarding node's NDN Name (its encoded Name
//!   wire). This is the **network-layer neighbor identity** counted for CCLF's
//!   density suppression — deliberately *not* a MAC/host address, which is
//!   unstable under mobility and monitor-mode.
//! - **Previous-hop location** (`0x0362`) and **Data (destination) location**
//!   (`0x0364`) — 12-byte geographic fixes feeding the optional Location Score.
//!
//! All three TLV-TYPEs are in the NDNLPv2 experimental range and **non-critical**
//! (even, `> 31`, per [`crate::is_critical_tlv_type`]), so a peer without A-LAL
//! ignores them rather than rejecting the packet. These codes are
//! **ndn-rs-experimental**, not NDN-standard.

#[cfg(feature = "std")]
use bytes::Bytes;

/// Presence/announcement: the forwarding node's NDN Name (encoded Name wire),
/// the network-layer identity counted for density. Non-critical.
pub const TLV_AL_PRESENCE: u64 = 0x0360;
/// Previous-hop geographic fix (12-byte [`GeoFix`]). Non-critical.
pub const TLV_AL_PREV_HOP_LOC: u64 = 0x0362;
/// Destination/data geographic fix (12-byte [`GeoFix`]). Non-critical.
pub const TLV_AL_DATA_LOC: u64 = 0x0364;

const GEO_LEN: usize = 12;

/// A fixed-point geographic fix carried in PL/DL: latitude and longitude in
/// degrees × 1e7 and altitude in centimetres, each a big-endian `i32`. Mirrors
/// `ndn_signals_core::GeoPos` without coupling this low-level crate to it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GeoFix {
    pub lat_e7: i32,
    pub lon_e7: i32,
    pub alt_cm: i32,
}

impl GeoFix {
    /// Encode the 12-byte value (no outer TYPE/LENGTH).
    pub fn encode_value(&self) -> [u8; GEO_LEN] {
        let mut buf = [0u8; GEO_LEN];
        buf[0..4].copy_from_slice(&self.lat_e7.to_be_bytes());
        buf[4..8].copy_from_slice(&self.lon_e7.to_be_bytes());
        buf[8..12].copy_from_slice(&self.alt_cm.to_be_bytes());
        buf
    }

    /// Decode from the 12-byte value, `None` on wrong length.
    pub fn decode_value(value: &[u8]) -> Option<Self> {
        if value.len() != GEO_LEN {
            return None;
        }
        let i32_at =
            |o: usize| i32::from_be_bytes([value[o], value[o + 1], value[o + 2], value[o + 3]]);
        Some(Self {
            lat_e7: i32_at(0),
            lon_e7: i32_at(4),
            alt_cm: i32_at(8),
        })
    }
}

/// Splice an LP header `typ` carrying `value` into an existing LP-wrapped wire,
/// in ascending TLV-TYPE order (NDNLPv2 element-order rule), replacing any
/// existing header of the same type. Cost: one LP re-encode. Non-LP wires pass
/// through unchanged. This is the egress-piggyback primitive shared by all
/// three A-LAL headers.
#[cfg(feature = "std")]
pub fn splice_lp_header(lp_wire: Bytes, typ: u64, value: &[u8]) -> Bytes {
    use ndn_tlv::{TlvReader, TlvWriter};

    if !super::is_lp_packet(&lp_wire) {
        return lp_wire;
    }
    let mut outer = TlvReader::new(lp_wire.clone());
    let (t0, body) = match outer.read_tlv() {
        Ok(t) => t,
        Err(_) => return lp_wire,
    };
    if t0 != crate::tlv_type::LP_PACKET {
        return lp_wire;
    }

    let mut inner = TlvReader::new(body);
    let mut headers: Vec<(u64, Bytes)> = Vec::new();
    let mut fragment_tlv: Option<(u64, Bytes)> = None;
    while !inner.is_empty() {
        let Ok((t, v)) = inner.read_tlv() else {
            return lp_wire;
        };
        if t == crate::tlv_type::LP_FRAGMENT {
            fragment_tlv = Some((t, v));
            continue;
        }
        if t == typ {
            continue; // replace, don't duplicate
        }
        headers.push((t, v));
    }

    let mut w = TlvWriter::new();
    w.write_nested(crate::tlv_type::LP_PACKET, |w| {
        let mut inserted = false;
        for (t, v) in &headers {
            if !inserted && *t > typ {
                w.write_tlv(typ, value);
                inserted = true;
            }
            w.write_tlv(*t, v);
        }
        if !inserted {
            w.write_tlv(typ, value);
        }
        if let Some((t, v)) = fragment_tlv {
            w.write_tlv(t, &v);
        }
    });
    w.finish()
}

/// Extract the value of LP header `typ` from an LP-wrapped wire, or `None` if
/// the wire is not LP-wrapped, malformed, or carries no such header.
#[cfg(feature = "std")]
pub fn extract_lp_header(lp_wire: &Bytes, typ: u64) -> Option<Bytes> {
    use ndn_tlv::TlvReader;

    if !super::is_lp_packet(lp_wire) {
        return None;
    }
    let mut outer = TlvReader::new(lp_wire.clone());
    let (t0, body) = outer.read_tlv().ok()?;
    if t0 != crate::tlv_type::LP_PACKET {
        return None;
    }
    let mut inner = TlvReader::new(body);
    while !inner.is_empty() {
        let (t, v) = inner.read_tlv().ok()?;
        if t == typ {
            return Some(v);
        }
        if t == crate::tlv_type::LP_FRAGMENT {
            return None;
        }
    }
    None
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use ndn_tlv::TlvWriter;

    fn lp_around(interest: &[u8]) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(crate::tlv_type::LP_PACKET, |w| {
            w.write_tlv(crate::tlv_type::LP_FRAGMENT, interest);
        });
        w.finish()
    }

    fn minimal_interest() -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(crate::tlv_type::INTEREST, |w| {
            w.write_nested(crate::tlv_type::NAME, |w| {
                w.write_tlv(crate::tlv_type::NAME_COMPONENT, b"test");
            });
            w.write_tlv(crate::tlv_type::NONCE, &[1, 2, 3, 4]);
        });
        w.finish()
    }

    #[test]
    fn geofix_value_roundtrip() {
        let g = GeoFix {
            lat_e7: 351_234_567,
            lon_e7: -901_234_567,
            alt_cm: 12_345,
        };
        assert_eq!(GeoFix::decode_value(&g.encode_value()), Some(g));
        assert_eq!(GeoFix::decode_value(&[0u8; 11]), None);
    }

    #[test]
    fn presence_splice_extract_roundtrip() {
        let lp = lp_around(&minimal_interest());
        let name_wire: &[u8] = b"\x07\x06\x08\x04node";
        let spliced = splice_lp_header(lp, TLV_AL_PRESENCE, name_wire);
        assert_eq!(
            extract_lp_header(&spliced, TLV_AL_PRESENCE).as_deref(),
            Some(name_wire)
        );
        // The packet still decodes as a valid LpPacket (non-critical TLV).
        let pkt = crate::lp::LpPacket::decode(spliced).expect("LpPacket must accept presence");
        assert!(pkt.al_presence.is_some());
        assert!(pkt.fragment.is_some());
    }

    #[test]
    fn second_splice_replaces() {
        let lp = lp_around(&minimal_interest());
        let once = splice_lp_header(lp, TLV_AL_PRESENCE, b"aaaa");
        let twice = splice_lp_header(once, TLV_AL_PRESENCE, b"bbbb");
        assert_eq!(
            extract_lp_header(&twice, TLV_AL_PRESENCE).as_deref(),
            Some(&b"bbbb"[..])
        );
    }

    #[test]
    fn location_headers_coexist_in_order() {
        let lp = lp_around(&minimal_interest());
        let pl = GeoFix {
            lat_e7: 1,
            lon_e7: 2,
            alt_cm: 3,
        };
        let dl = GeoFix {
            lat_e7: 4,
            lon_e7: 5,
            alt_cm: 6,
        };
        let w1 = splice_lp_header(lp, TLV_AL_PRESENCE, b"n");
        let w2 = splice_lp_header(w1, TLV_AL_PREV_HOP_LOC, &pl.encode_value());
        let w3 = splice_lp_header(w2, TLV_AL_DATA_LOC, &dl.encode_value());
        // All three present and the packet still decodes.
        let pkt = crate::lp::LpPacket::decode(w3.clone()).expect("decodes");
        assert!(
            pkt.al_presence.is_some() && pkt.al_prev_hop_loc.is_some() && pkt.al_data_loc.is_some()
        );
        assert_eq!(
            GeoFix::decode_value(&extract_lp_header(&w3, TLV_AL_PREV_HOP_LOC).unwrap()),
            Some(pl)
        );
        assert_eq!(
            GeoFix::decode_value(&extract_lp_header(&w3, TLV_AL_DATA_LOC).unwrap()),
            Some(dl)
        );
    }
}
