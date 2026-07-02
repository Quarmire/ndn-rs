//! Platform-neutral on-air (de)framing: wrap an NDN-LP payload into the
//! `radiotap ++ 802.11 ++ <format body>` bytes the driver injects, and recover
//! it on capture. The socket I/O lives in the Linux [`af_packet`](crate)
//! backend; keeping the byte layout here makes every [`FrameFormat`] unit-
//! testable on any host.

use bytes::Bytes;
use ndn_transport::FaceError;

use crate::{CapturedFrame, FrameFormat, InjectFrame, radiotap};

/// 802.11 non-QoS data frame header (FC + Duration + 3×addr + SeqCtrl).
const DOT11_HDR_LEN: usize = 24;
/// QoS data frames carry an extra 2-byte QoS Control field.
const DOT11_QOS_HDR_LEN: usize = 26;
/// LLC/SNAP header preceding an EtherType-tagged payload in an 802.11 frame.
const LLC_SNAP_LEN: usize = 8;
pub const LLC_SNAP_PREFIX: [u8; 6] = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00];

// ── ESP-NOW vendor-action-frame constants ────────────────────────────────────
// ESP-NOW is a vendor-specific 802.11 *Action* frame: a subset of raw
// injection. The layout (after the 24-byte MAC header) is the IDF/esp-wifi
// wire format: Category(0x7f) + OUI + 4-byte random + a vendor element
// (0xdd, len, OUI, Type=0x04, Version=0x01, Body). Matching it byte-for-byte
// is what lets a $5 ESP32 running stock `esp-wifi` ESP-NOW hear our frames.
const ESPNOW_CATEGORY: u8 = 0x7f; // vendor-specific action
const ESPNOW_ELEMENT_ID: u8 = 0xdd; // vendor-specific element
const ESPNOW_TYPE: u8 = 0x04; // ESP-NOW
/// ESP-NOW protocol version. esp-idf v5+/`esp-radio` emit **2**; older stacks
/// used 1. We transmit 2 and accept either on receive (see [`parse`]).
const ESPNOW_VERSION: u8 = 0x02;
const ESPNOW_RANDOM_LEN: usize = 4;
/// ESP-NOW body cap (the element `Length` is a single byte: OUI+Type+Ver = 5,
/// so body ≤ 250). A face speaking ESP-NOW must fragment to this via its MTU.
pub const ESPNOW_MAX_BODY: usize = 250;
/// Espressif's OUI — the default for [`FrameFormat::EspNow`].
pub const ESPNOW_OUI: [u8; 3] = [0x18, 0xfe, 0x34];

/// The broadcast/default-source addresses now live in `ndn-radio-hal`; re-exported
/// through the crate root so `frame::BROADCAST` / `frame::DEFAULT_SRC` still resolve.
pub use crate::{BROADCAST, DEFAULT_SRC};

/// FNV-1a (64-bit) — a fast, dependency-free, non-cryptographic hash. The group
/// MAC is only a Bloom-style pre-filter hint; the full name + signature are
/// authoritative after decode, so collision resistance is not required.
fn fnv1a(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// A **multicast** MAC derived from a name prefix — *"the prefix is the group
/// address."* A receiver interested in `prefix` can program its NIC's
/// multicast filter (or a software pre-filter) to this address and hardware-
/// drop everything else, making the medium's broadcast nature selective by
/// name. The first octet sets the I/G (group) and U/L (locally-administered)
/// bits; the low 46 bits carry `fnv1a(prefix)`.
pub fn name_group_mac(prefix: &[u8]) -> [u8; 6] {
    let h = fnv1a(prefix).to_be_bytes();
    let mut m = [h[0], h[1], h[2], h[3], h[4], h[5]];
    m[0] = (m[0] & 0xFC) | 0x03; // I/G = 1 (group), U/L = 1 (local)
    m
}

/// A **unicast** locally-administered MAC derived from a name prefix, used as
/// the source/transmitter address so the 802.11 `addr2` is name-derived rather
/// than a host id. Because every fragment of a prefix's traffic shares it, the
/// reassembly stream key the face reports upward is name-keyed, not host-keyed.
pub fn name_group_uni(prefix: &[u8]) -> [u8; 6] {
    let h = fnv1a(prefix).to_be_bytes();
    let mut m = [h[0], h[1], h[2], h[3], h[4], h[5]];
    m[0] = (m[0] & 0xFC) | 0x02; // I/G = 0 (unicast), U/L = 1 (local)
    m
}

/// Build `radiotap ++ 802.11 ++ <format body>` for one injected frame. The
/// 802.11 address fields are filled from `frame.dst`/`frame.src` — for a
/// name-grouped face these are name-derived (`name_group_mac`/`name_group_uni`),
/// so no host identity appears on the wire.
///
/// The radiotap TX header carries the rate: a per-frame MCS for `RawNdn`, or a
/// robust legacy rate for `EspNow` (1 Mbps on 2.4 GHz). The 802.11 frame itself
/// is built by [`build_dot11`] — backends that supply their own rate header
/// (e.g. the RTL88xx USB driver's TX descriptor) call that directly instead.
pub fn build(format: FrameFormat, frame: &InjectFrame) -> Result<Vec<u8>, FaceError> {
    // Build the 802.11 frame first; this also runs the per-format validation
    // (e.g. the ESP-NOW body cap), so a bad frame errors before the radiotap.
    let dot11 = build_dot11(format, frame)?;
    let mut out = Vec::with_capacity(16 + dot11.len());
    match format {
        // ESP-NOW rides a robust legacy rate (1 Mbps), not an MCS.
        FrameFormat::EspNow { .. } => out.extend_from_slice(&radiotap::build_tx_legacy(2)),
        // RawNdn (and anything else `build_dot11` accepts) carries a per-frame
        // rate: resolve the intent to an 802.11 MCS for the radiotap header. The
        // kernel driver on the AF_PACKET path honours this; a resolution over a
        // conservative default capability is right for a header-only hint.
        _ => {
            let mcs = crate::McsDescriptor::for_intent(&frame.tx, crate::MAX_RELIABLE_MCS, false);
            out.extend_from_slice(&radiotap::build_tx_header(mcs.index, mcs.short_gi))
        }
    }
    out.extend_from_slice(&dot11);
    Ok(out)
}

/// Build just the **802.11 frame** for `frame` under `format` — the bytes that
/// follow the radiotap header (or, for a hardware backend, its own TX
/// descriptor). Factored out of [`build`] so the RTL88xx USB driver — which
/// prepends a chip TX descriptor and sets the rate there, not via radiotap —
/// shares the exact same on-air byte layout (notably the ESP-NOW vendor-action
/// frame a stock `esp-wifi` peer keys on).
pub fn build_dot11(format: FrameFormat, frame: &InjectFrame) -> Result<Vec<u8>, FaceError> {
    let mut out = Vec::with_capacity(64 + frame.payload.len());
    match format {
        FrameFormat::RawNdn { ethertype } => {
            // 802.11 non-QoS data frame. addr1/addr3 = destination group (or
            // broadcast); addr2 = name-derived source. The NDN name is the
            // addressing — these fields are a name-keyed index, not host ids.
            out.extend_from_slice(&[0x08, 0x00]); // FC: type=Data, subtype=0
            out.extend_from_slice(&[0x00, 0x00]); // Duration
            out.extend_from_slice(&frame.dst); // addr1 (RA/DA) = group/broadcast
            out.extend_from_slice(&frame.src); // addr2 (TA/SA) = name-derived
            out.extend_from_slice(&frame.dst); // addr3 (BSSID) = group/broadcast
            out.extend_from_slice(&[0x00, 0x00]); // SeqCtrl
            out.extend_from_slice(&LLC_SNAP_PREFIX);
            out.extend_from_slice(&ethertype.to_be_bytes());
            out.extend_from_slice(&frame.payload);
        }
        FrameFormat::EspNow { oui } => {
            if frame.payload.len() > ESPNOW_MAX_BODY {
                return Err(FaceError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "ESP-NOW body > 250 B — set a smaller face MTU",
                )));
            }
            // 802.11 vendor-specific Action frame (management subtype 13).
            // ESP-NOW requires addr1 = broadcast (its receivers key on it).
            out.extend_from_slice(&[0xd0, 0x00]); // FC: type=Mgmt, subtype=Action
            out.extend_from_slice(&[0x00, 0x00]); // Duration
            out.extend_from_slice(&[0xff; 6]); // addr1 = broadcast
            out.extend_from_slice(&frame.src); // addr2 = src
            out.extend_from_slice(&[0xff; 6]); // addr3 (BSSID) = broadcast
            out.extend_from_slice(&[0x00, 0x00]); // SeqCtrl
            // Action body.
            out.push(ESPNOW_CATEGORY);
            out.extend_from_slice(&oui);
            out.extend_from_slice(&[0u8; ESPNOW_RANDOM_LEN]); // random value
            // Vendor-specific element carrying the ESP-NOW payload.
            out.push(ESPNOW_ELEMENT_ID);
            out.push((5 + frame.payload.len()) as u8); // OUI(3)+Type(1)+Ver(1)+body
            out.extend_from_slice(&oui);
            out.push(ESPNOW_TYPE);
            out.push(ESPNOW_VERSION);
            out.extend_from_slice(&frame.payload);
        }
        FrameFormat::Raw80211 => {
            // The payload IS the complete 802.11 frame; inject it verbatim.
            out.extend_from_slice(&frame.payload);
        }
        other => {
            return Err(FaceError::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!("frame format {other:?} not yet implemented"),
            )));
        }
    }
    Ok(out)
}

/// Recover the NDN payload + transmitter address from a captured buffer
/// (`radiotap ++ 802.11 ++ …`). `None` if the frame isn't ours.
pub fn parse(
    format: FrameFormat,
    buf: &[u8],
    rssi: Option<i8>,
    mcs: Option<u8>,
) -> Option<CapturedFrame> {
    let info = radiotap::parse(buf)?;
    let body = buf.get(info.header_len..)?;
    // radiotap RSSI/rate are the fallback when the caller has no out-of-band read.
    parse_dot11(format, body, rssi.or(info.rssi_dbm), mcs.or(info.mcs_index))
}

/// Recover the NDN payload + transmitter address from a bare **802.11 frame**
/// `body` (no radiotap) under `format`. `rssi`/`mcs` are passed through to the
/// returned [`CapturedFrame`] as-is. The counterpart to [`build_dot11`]: a
/// hardware backend that strips its own RX descriptor (and reads RSSI/rate from
/// it) recovers the payload through this, sharing the format byte layout with
/// the radiotap-based [`parse`].
pub fn parse_dot11(
    format: FrameFormat,
    body: &[u8],
    rssi: Option<i8>,
    mcs: Option<u8>,
) -> Option<CapturedFrame> {
    if body.len() < 2 {
        return None;
    }
    let fc0 = body[0];

    match format {
        FrameFormat::RawNdn { ethertype } => {
            if (fc0 >> 2) & 0x03 != 0x02 {
                return None; // not a data frame
            }
            let hdr_len = if (fc0 >> 4) & 0x08 != 0 {
                DOT11_QOS_HDR_LEN
            } else {
                DOT11_HDR_LEN
            };
            if body.len() < hdr_len + LLC_SNAP_LEN {
                return None;
            }
            let llc = &body[hdr_len..hdr_len + LLC_SNAP_LEN];
            if llc[..6] != LLC_SNAP_PREFIX || llc[6..8] != ethertype.to_be_bytes() {
                return None;
            }
            let mut ta = [0u8; 6];
            ta.copy_from_slice(&body[10..16]);
            let mut group = [0u8; 6];
            group.copy_from_slice(&body[4..10]); // addr1 (RA/DA)
            Some(CapturedFrame {
                payload: Bytes::copy_from_slice(&body[hdr_len + LLC_SNAP_LEN..]),
                addr: Some(ta),
                group: Some(group),
                rssi_dbm: rssi,
                mcs_index: mcs,
            })
        }
        FrameFormat::EspNow { oui } => {
            // Must be a vendor-specific Action frame (FC first octet 0xd0).
            if fc0 != 0xd0 {
                return None;
            }
            let action = body.get(DOT11_HDR_LEN..)?;
            // Category + OUI + random, then the vendor element.
            let elem_off = 1 + 3 + ESPNOW_RANDOM_LEN;
            if action.first() != Some(&ESPNOW_CATEGORY) || action.get(1..4)? != oui {
                return None;
            }
            let elem = action.get(elem_off..)?;
            if elem.first() != Some(&ESPNOW_ELEMENT_ID) {
                return None;
            }
            let len = *elem.get(1)? as usize;
            // Tolerate ESP-NOW version 1 or 2 (we transmit 2).
            if elem.get(2..5)? != oui
                || elem.get(5) != Some(&ESPNOW_TYPE)
                || !matches!(elem.get(6), Some(1 | 2))
            {
                return None;
            }
            let body_len = len.checked_sub(5)?; // minus OUI(3)+Type(1)+Ver(1)
            let payload = elem.get(7..7 + body_len)?;
            let mut ta = [0u8; 6];
            ta.copy_from_slice(&body[10..16]);
            let mut group = [0u8; 6];
            group.copy_from_slice(&body[4..10]); // addr1 (broadcast for ESP-NOW)
            Some(CapturedFrame {
                payload: Bytes::copy_from_slice(payload),
                addr: Some(ta),
                group: Some(group),
                rssi_dbm: rssi,
                mcs_index: mcs,
            })
        }
        FrameFormat::Raw80211 => {
            // The whole 802.11 frame is the payload (the caller parses it). Still
            // surface addr2 (TA) and addr1 (RA) from the fixed header offsets —
            // management and data frames share the first 16 bytes — so signal
            // plumbing and dedup work uniformly.
            if body.len() < DOT11_HDR_LEN {
                return None;
            }
            let mut ta = [0u8; 6];
            ta.copy_from_slice(&body[10..16]);
            let mut group = [0u8; 6];
            group.copy_from_slice(&body[4..10]);
            Some(CapturedFrame {
                payload: Bytes::copy_from_slice(body),
                addr: Some(ta),
                group: Some(group),
                rssi_dbm: rssi,
                mcs_index: mcs,
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TxIntent;

    const SRC: [u8; 6] = [0x02, 0x4e, 0x44, 0x4e, 0x00, 0x01];

    fn frame(payload: &[u8]) -> InjectFrame {
        InjectFrame {
            payload: Bytes::copy_from_slice(payload),
            tx: TxIntent::CONSERVATIVE,
            dst: BROADCAST,
            src: SRC,
        }
    }

    #[test]
    fn raw_ndn_round_trips() {
        let fmt = FrameFormat::RawNdn { ethertype: 0x8624 };
        let wire = build(fmt, &frame(b"\x05\x03interest")).unwrap();
        let got = parse(fmt, &wire, Some(-50), Some(3)).unwrap();
        assert_eq!(got.payload.as_ref(), b"\x05\x03interest");
        assert_eq!(got.addr, Some(SRC));
        assert_eq!(got.group, Some(BROADCAST));
        assert_eq!(got.rssi_dbm, Some(-50));
    }

    #[test]
    fn espnow_round_trips() {
        let fmt = FrameFormat::EspNow { oui: ESPNOW_OUI };
        let payload = b"\x64\x0fNDN-LP-over-ESPNOW";
        let wire = build(fmt, &frame(payload)).unwrap();
        let got = parse(fmt, &wire, Some(-40), None).unwrap();
        assert_eq!(got.payload.as_ref(), payload.as_slice());
        assert_eq!(got.addr, Some(SRC));
    }

    /// Group MAC: name-derived multicast (I/G+U/L set), unicast source variant,
    /// distinct prefixes → distinct addresses, deterministic.
    #[test]
    fn name_group_mac_is_local_multicast_and_distinct() {
        let a = name_group_mac(b"/sensors/temp");
        let b = name_group_mac(b"/sensors/humidity");
        assert_eq!(a[0] & 0x03, 0x03, "I/G (group) + U/L (local) bits set");
        assert_ne!(a, b, "distinct prefixes → distinct group MACs");
        assert_eq!(a, name_group_mac(b"/sensors/temp"), "deterministic");
        let u = name_group_uni(b"/sensors/temp");
        assert_eq!(u[0] & 0x03, 0x02, "unicast + local");
        assert_eq!(u[1..], a[1..], "same hash body, differ only in I/G bit");
    }

    /// A name-grouped frame round-trips with the group MAC in addr1 and the
    /// name-derived unicast source in addr2.
    #[test]
    fn name_group_addressing_round_trips() {
        let fmt = FrameFormat::RawNdn { ethertype: 0x8624 };
        let g = name_group_mac(b"/p");
        let u = name_group_uni(b"/p");
        let f = InjectFrame {
            payload: Bytes::from_static(b"\x05\x01z"),
            tx: TxIntent::CONSERVATIVE,
            dst: g,
            src: u,
        };
        let got = parse(fmt, &build(fmt, &f).unwrap(), None, None).unwrap();
        assert_eq!(got.group, Some(g), "addr1 carries the name-group MAC");
        assert_eq!(got.addr, Some(u), "addr2 is the name-derived source");
    }

    /// The injected bytes after radiotap must be a well-formed ESP-NOW vendor
    /// action frame (what a stock esp-wifi ESP-NOW receiver keys on).
    #[test]
    fn espnow_wire_layout_is_canonical() {
        let fmt = FrameFormat::EspNow { oui: ESPNOW_OUI };
        let wire = build(fmt, &frame(b"hi")).unwrap();
        let rt = radiotap::TX_LEGACY_HEADER_LEN;
        let b = &wire[rt..];
        assert_eq!(&b[0..2], &[0xd0, 0x00], "Action frame control");
        assert_eq!(&b[24], &ESPNOW_CATEGORY, "vendor-specific category");
        assert_eq!(&b[25..28], &ESPNOW_OUI, "action OUI");
        assert_eq!(b[32], ESPNOW_ELEMENT_ID, "vendor element id");
        assert_eq!(b[33] as usize, 5 + 2, "element length = OUI+Type+Ver+body");
        assert_eq!(&b[34..37], &ESPNOW_OUI, "element OUI");
        assert_eq!(b[37], ESPNOW_TYPE);
        assert_eq!(b[38], ESPNOW_VERSION);
        assert_eq!(&b[39..41], b"hi", "ESP-NOW body");
    }

    /// The radiotap-free `build_dot11`/`parse_dot11` helpers (used by hardware
    /// backends that carry the rate in their own TX/RX descriptor) round-trip,
    /// and `build` is exactly `radiotap ++ build_dot11`.
    #[test]
    fn dot11_helpers_round_trip_and_compose_build() {
        let fmt = FrameFormat::EspNow { oui: ESPNOW_OUI };
        let f = frame(b"\x05\x05hello");
        let dot11 = build_dot11(fmt, &f).unwrap();
        // No radiotap prefix — starts at the 802.11 Action frame control.
        assert_eq!(&dot11[0..2], &[0xd0, 0x00]);
        let got = parse_dot11(fmt, &dot11, Some(-33), Some(7)).unwrap();
        assert_eq!(got.payload.as_ref(), b"\x05\x05hello");
        assert_eq!(got.addr, Some(SRC));
        assert_eq!(got.rssi_dbm, Some(-33), "descriptor RSSI passes through");
        assert_eq!(got.mcs_index, Some(7), "descriptor rate passes through");
        // `build` == radiotap header ++ the same 802.11 frame.
        assert!(build(fmt, &f).unwrap().ends_with(&dot11));
    }

    /// Raw80211 injects the payload verbatim (after radiotap) and recovers the
    /// whole 802.11 frame on parse, with addr2/addr1 surfaced from the fixed
    /// header — the path the userspace NAN stack uses for management frames.
    #[test]
    fn raw80211_passes_the_whole_frame_through() {
        let fmt = FrameFormat::Raw80211;
        // A fabricated NAN-beacon-shaped 802.11 frame: FC=80 00, dur, addr1..3, seq.
        let mut frame_bytes = vec![0x80, 0x00, 0x00, 0x00];
        frame_bytes.extend_from_slice(&BROADCAST); // addr1
        frame_bytes.extend_from_slice(&SRC); // addr2
        frame_bytes.extend_from_slice(&[0x50, 0x6F, 0x9A, 0x01, 0x00, 0x00]); // addr3
        frame_bytes.extend_from_slice(&[0x00, 0x00]); // seq
        frame_bytes.extend_from_slice(b"nan-attributes-here");

        let inj = InjectFrame {
            payload: Bytes::from(frame_bytes.clone()),
            tx: TxIntent::CONSERVATIVE,
            dst: BROADCAST,
            src: SRC,
        };
        // build_dot11 is the identity on the payload (no extra framing).
        assert_eq!(build_dot11(fmt, &inj).unwrap(), frame_bytes);

        let got = parse(fmt, &build(fmt, &inj).unwrap(), Some(-60), Some(0)).unwrap();
        assert_eq!(
            got.payload.as_ref(),
            &frame_bytes[..],
            "whole frame preserved"
        );
        assert_eq!(got.addr, Some(SRC), "addr2 surfaced");
        assert_eq!(got.group, Some(BROADCAST), "addr1 surfaced");
        assert_eq!(got.rssi_dbm, Some(-60));
    }

    #[test]
    fn espnow_rejects_oversize_body() {
        let fmt = FrameFormat::EspNow { oui: ESPNOW_OUI };
        assert!(build(fmt, &frame(&[0u8; 251])).is_err());
    }

    #[test]
    fn formats_do_not_cross_parse() {
        let raw = FrameFormat::RawNdn { ethertype: 0x8624 };
        let esp = FrameFormat::EspNow { oui: ESPNOW_OUI };
        let raw_wire = build(raw, &frame(b"x")).unwrap();
        assert!(parse(esp, &raw_wire, None, None).is_none());
        let esp_wire = build(esp, &frame(b"x")).unwrap();
        assert!(parse(raw, &esp_wire, None, None).is_none());
    }
}
