//! Platform-neutral on-air (de)framing: wrap an NDN-LP payload into the
//! `radiotap ++ 802.11 ++ <format body>` bytes the driver injects, and recover
//! it on capture. The socket I/O lives in the Linux [`af_packet`](crate)
//! backend; keeping the byte layout here makes every [`FrameFormat`] unit-
//! testable on any host.

use bytes::Bytes;
use ndn_transport::FaceError;

use crate::{
    CapturedFrame, ClockDomainId, FrameFormat, InjectFrame, LatchPoint, LinkStamp, radiotap,
};

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

/// **SipHash-2-4** (Aumasson & Bernstein) — a fast *keyed* PRF, vendored (no dep)
/// and shared with the FHSS rendezvous (`HopSchedule`). Keyed because the
/// name-group hash is the compiled form of a **public** name: an unkeyed hash lets
/// any outsider compute (or cheaply collide) a victim's group hash and flood its
/// receive filter. Under a private trust domain's secret key the group hash is
/// unforgeable and unlinkable to outsiders; under the well-known [`OPEN_GROUP_KEY`]
/// it is a strong public hash giving an open receiver set. (This is not the last
/// line of DoS defence — that is PIT-gated verification + rate-limiting; keying just
/// raises the bar for *outsiders* targeting a private group's pre-parse filter.)
pub fn siphash24(key: &[u8; 16], data: &[u8]) -> u64 {
    let k0 = u64::from_le_bytes(key[0..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(key[8..16].try_into().unwrap());
    let mut v0 = 0x736f_6d65_7073_6575 ^ k0;
    let mut v1 = 0x646f_7261_6e64_6f6d ^ k1;
    let mut v2 = 0x6c79_6765_6e65_7261 ^ k0;
    let mut v3 = 0x7465_6462_7974_6573 ^ k1;
    macro_rules! round {
        () => {{
            v0 = v0.wrapping_add(v1);
            v1 = v1.rotate_left(13);
            v1 ^= v0;
            v0 = v0.rotate_left(32);
            v2 = v2.wrapping_add(v3);
            v3 = v3.rotate_left(16);
            v3 ^= v2;
            v0 = v0.wrapping_add(v3);
            v3 = v3.rotate_left(21);
            v3 ^= v0;
            v2 = v2.wrapping_add(v1);
            v1 = v1.rotate_left(17);
            v1 ^= v2;
            v2 = v2.rotate_left(32);
        }};
    }
    let mut chunks = data.chunks_exact(8);
    for c in &mut chunks {
        let m = u64::from_le_bytes(c.try_into().unwrap());
        v3 ^= m;
        round!();
        round!();
        v0 ^= m;
    }
    let mut last = (data.len() as u64 & 0xff) << 56;
    for (i, &b) in chunks.remainder().iter().enumerate() {
        last |= (b as u64) << (8 * i);
    }
    v3 ^= last;
    round!();
    round!();
    v0 ^= last;
    v2 ^= 0xff;
    round!();
    round!();
    round!();
    round!();
    v0 ^ v1 ^ v2 ^ v3
}

/// A trust-context key for name-group hashing (see [`siphash24`]). The well-known
/// [`OPEN_GROUP_KEY`] gives an open receiver set (anyone computes the hash and
/// filters/joins); a shared secret scopes a group to a trust domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupKey(pub [u8; 16]);

/// The well-known key for open/public namespaces — an open receiver set.
pub const OPEN_GROUP_KEY: GroupKey = GroupKey(*b"ndn/open-group!!");

/// Set the I/G + U/L bits of a locally-administered address body: `group=true`
/// → multicast (`0x03`), `false` → unicast (`0x02`).
fn tag_local(mut m: [u8; 6], group: bool) -> [u8; 6] {
    m[0] = (m[0] & 0xFC) | if group { 0x03 } else { 0x02 };
    m
}

/// A **multicast** MAC derived from a name — *"the name is the group address."* A
/// receiver interested in it programs its NIC's address filter (or a software
/// pre-filter) to this and the hardware drops everything else (measured: chip-level
/// filtering gives the MAC-filter CPU profile, see the mac-addressing-doctrine). The
/// first octet sets I/G (group) + U/L (local); the low 46 bits carry the keyed hash.
///
/// This is the **flat** full-name form (no prefix aggregation) — right for a leaf
/// consumer or a producer's own group. When a *relay* must match a whole family of
/// names under a routable prefix, use [`name_group`] + [`prefix_key`] instead.
///
/// The group MAC is a Bloom-style pre-filter; the full name + signature are
/// authoritative after decode, so a hash collision only wastes a wake, never
/// mis-delivers.
pub fn name_group_mac(name: &[u8]) -> [u8; 6] {
    let h = siphash24(&OPEN_GROUP_KEY.0, name).to_be_bytes();
    tag_local([h[0], h[1], h[2], h[3], h[4], h[5]], true)
}

/// The **unicast** locally-administered form of [`name_group_mac`] (same hash body,
/// I/G clear) — used where a unicast addr1 is wanted (e.g. the exact-match chip
/// filter, or a name-derived source when an ephemeral nonce is not in use).
pub fn name_group_uni(name: &[u8]) -> [u8; 6] {
    let h = siphash24(&OPEN_GROUP_KEY.0, name).to_be_bytes();
    tag_local([h[0], h[1], h[2], h[3], h[4], h[5]], false)
}

/// **Prefix-aggregating** name-group address: the 46-bit hash split
/// `H(routable_prefix)` (high 24 bits, structural bits aside) ‖ `H(full_name)` (low
/// 24 bits), both keyed by the trust context. A **FIB relay** filters coarsely on the
/// high bits ([`prefix_key`]) — matching *every* name under the prefix, so one filter
/// entry aggregates a family (the IP-prefix-match trick). A **consumer/PIT** compares
/// the full width for the exact name. Generation/block IDs are *not* here — they live
/// in the coding metadata, scoped by the already-identified name (`FecMetadata`), so
/// they need no global collision resistance.
///
/// `routable_prefix` is the prefix a FIB routes on (a naming convention fixes its
/// boundary); `full_name` is the whole name. Collision cost is a wasted wake caught by
/// the name check above the hash — the hash accelerates, the name authorises.
///
/// **Entropy tradeoff (be aware):** within one routable prefix, names are
/// discriminated only by the low 24 bits (the suffix hash) — a 24-bit birthday bound,
/// ~4096 names/prefix before a likely collision. That is fine for a *filter* (a
/// collision wastes a wake, never mis-delivers) but a producer of a huge *flat*
/// namespace that needs full 46-bit discrimination and no aggregation should use
/// [`name_group_mac`] instead.
pub fn name_group(key: &GroupKey, routable_prefix: &[u8], full_name: &[u8], group: bool) -> [u8; 6] {
    let ph = siphash24(&key.0, routable_prefix);
    let nh = siphash24(&key.0, full_name);
    tag_local(
        [(ph >> 16) as u8, (ph >> 8) as u8, ph as u8, (nh >> 16) as u8, (nh >> 8) as u8, nh as u8],
        group,
    )
}

/// The coarse **prefix-match key** of a [`name_group`] address: zero the low 3 bytes
/// (the full-name hash), keeping only the routable-prefix hash. A FIB relay registers
/// `prefix_key(name_group(key, P, P, g))` and matches any frame whose `prefix_key`
/// equals it — one entry covers the whole prefix family.
pub fn prefix_key(mut addr: [u8; 6]) -> [u8; 6] {
    addr[3] = 0;
    addr[4] = 0;
    addr[5] = 0;
    addr
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
    // Resolve the frame's intent to an 802.11 rate for the radiotap header (a
    // conservative default capability is right for a header-only hint), then
    // build. The exact-rate path ([`build_at`]) is used when a caller has already
    // resolved a rate (the cognitive face, fixed-rate benches).
    let mcs = crate::McsDescriptor::for_intent(&frame.tx, crate::MAX_RELIABLE_MCS, false);
    build_at(format, frame, mcs)
}

/// Like [`build`], but at an explicit `mcs` — the radiotap TX header carries this
/// exact rate instead of resolving `frame.tx`. The counterpart of
/// [`WifiRadio::inject_at`](crate::WifiRadio::inject_at) for the AF_PACKET path.
pub fn build_at(
    format: FrameFormat,
    frame: &InjectFrame,
    mcs: crate::McsDescriptor,
) -> Result<Vec<u8>, FaceError> {
    // Build the 802.11 frame first; this also runs the per-format validation
    // (e.g. the ESP-NOW body cap), so a bad frame errors before the radiotap.
    let dot11 = build_dot11(format, frame)?;
    let mut out = Vec::with_capacity(16 + dot11.len());
    match format {
        // ESP-NOW rides a robust legacy rate (1 Mbps), not an MCS.
        FrameFormat::EspNow { .. } => out.extend_from_slice(&radiotap::build_tx_legacy(2)),
        // S1G/HaLow: no 11n/ac MCS — the on-chip MAC picks the sub-GHz rate.
        FrameFormat::RawNdnS1g { .. } => out.extend_from_slice(&radiotap::build_tx_s1g()),
        _ => out.extend_from_slice(&radiotap::build_tx_header(mcs.index, mcs.short_gi)),
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
        // RawNdn and RawNdnS1g share the exact data-frame body; they differ only
        // in the radiotap TX rate header chosen in `build_at`.
        FrameFormat::RawNdn { ethertype } | FrameFormat::RawNdnS1g { ethertype } => {
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
    domain: ClockDomainId,
) -> Option<CapturedFrame> {
    let info = radiotap::parse(buf)?;
    let body = buf.get(info.header_len..)?;
    // If radiotap carried a TSFT, build a hardware receive stamp for it. The
    // caller supplies the clock `domain` (a TSF counter is per-NIC); the latch
    // is `MacDone` (~1 µs) and precision is clamped to that latch's floor.
    let stamp = info.tsft.map(|raw| {
        LinkStamp::new(
            raw,
            domain,
            LatchPoint::MacDone.precision_floor_ns(),
            LatchPoint::MacDone,
        )
    });
    // radiotap RSSI/rate are the fallback when the caller has no out-of-band read.
    parse_dot11(
        format,
        body,
        rssi.or(info.rssi_dbm),
        mcs.or(info.mcs_index),
        stamp,
    )
}

/// Recover the NDN payload + transmitter address from a bare **802.11 frame**
/// `body` (no radiotap) under `format`. `rssi`/`mcs`/`stamp` are passed through
/// to the returned [`CapturedFrame`] as-is. The counterpart to [`build_dot11`]:
/// a hardware backend that strips its own RX descriptor (reading RSSI/rate and
/// latching a receive timestamp from it) recovers the payload through this,
/// sharing the format byte layout with the radiotap-based [`parse`], which
/// instead builds the `stamp` from radiotap TSFT.
pub fn parse_dot11(
    format: FrameFormat,
    body: &[u8],
    rssi: Option<i8>,
    mcs: Option<u8>,
    stamp: Option<LinkStamp>,
) -> Option<CapturedFrame> {
    if body.len() < 2 {
        return None;
    }
    let fc0 = body[0];

    match format {
        FrameFormat::RawNdn { ethertype } | FrameFormat::RawNdnS1g { ethertype } => {
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
                stamp,
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
                stamp,
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
                stamp,
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
        let got = parse(fmt, &wire, Some(-50), Some(3), crate::ClockDomainId(0)).unwrap();
        assert_eq!(got.payload.as_ref(), b"\x05\x03interest");
        assert_eq!(got.addr, Some(SRC));
        assert_eq!(got.group, Some(BROADCAST));
        assert_eq!(got.rssi_dbm, Some(-50));
    }

    #[test]
    fn parse_populates_stamp_from_radiotap_tsft() {
        let fmt = FrameFormat::RawNdn { ethertype: 0x8624 };
        let dot11 = build_dot11(fmt, &frame(b"\x05\x03abc")).unwrap();
        // Hand-build a radiotap header carrying only a TSFT (bit 0), then the
        // 802.11 frame — the shape a monitor NIC delivers.
        let tsft: u64 = 0xdead_beef_0000_0001;
        let mut wire = vec![0u8, 0]; // version, pad
        let present: u32 = 1 << 0;
        let it_len = (8 + 8) as u16; // header + one 8-byte TSFT field
        wire.extend_from_slice(&it_len.to_le_bytes());
        wire.extend_from_slice(&present.to_le_bytes());
        wire.extend_from_slice(&tsft.to_le_bytes());
        wire.extend_from_slice(&dot11);

        let domain = crate::ClockDomainId(42);
        let stamp = parse(fmt, &wire, None, None, domain)
            .unwrap()
            .stamp
            .expect("a TSFT header must yield a hardware stamp");
        assert_eq!(stamp.raw, tsft, "raw counter preserved");
        assert_eq!(stamp.domain, domain, "the NIC's clock domain is carried");
        assert_eq!(stamp.latch, LatchPoint::MacDone);
        assert_eq!(
            stamp.precision_ns, 1_000,
            "clamped to the MacDone ~1µs floor"
        );

        // A frame built with an ordinary TX radiotap header (no TSFT) is
        // honestly unstamped.
        let plain = build(fmt, &frame(b"\x05\x03abc")).unwrap();
        assert!(
            parse(fmt, &plain, None, None, domain)
                .unwrap()
                .stamp
                .is_none(),
            "no TSFT => no stamp"
        );
    }

    #[test]
    fn espnow_round_trips() {
        let fmt = FrameFormat::EspNow { oui: ESPNOW_OUI };
        let payload = b"\x64\x0fNDN-LP-over-ESPNOW";
        let wire = build(fmt, &frame(payload)).unwrap();
        let got = parse(fmt, &wire, Some(-40), None, crate::ClockDomainId(0)).unwrap();
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

    /// SipHash-2-4 correctness against the reference vector (Aumasson & Bernstein):
    /// key = 00..0f, data = 00..0e (15 bytes) → 0xa129ca6149be45e5. Verifies the
    /// vendored primitive rather than trusting it.
    #[test]
    fn siphash24_reference_vector() {
        let key: [u8; 16] = core::array::from_fn(|i| i as u8);
        let data: [u8; 15] = core::array::from_fn(|i| i as u8);
        assert_eq!(siphash24(&key, &data), 0xa129_ca61_49be_45e5);
    }

    /// Keying: the SAME name under different trust-context keys yields different
    /// group hashes — an outsider without the key cannot compute (nor cheaply target)
    /// a private group's pre-parse filter.
    #[test]
    fn keying_hides_a_private_group_from_outsiders() {
        let secret = GroupKey(*b"trust-domain-42!");
        let open = name_group(&OPEN_GROUP_KEY, b"/x", b"/x/y", true);
        let priv_ = name_group(&secret, b"/x", b"/x/y", true);
        assert_ne!(open, priv_, "same name, different key → different group hash");
        assert_eq!(priv_, name_group(&secret, b"/x", b"/x/y", true), "deterministic under a key");
    }

    /// Prefix aggregation: every name under one routable prefix shares the coarse
    /// prefix-match key (a FIB relay matches the family with one entry), yet the full
    /// addresses are distinct (a consumer/PIT distinguishes the exact names).
    #[test]
    fn prefix_key_aggregates_a_family_but_full_addr_is_distinct() {
        let k = &OPEN_GROUP_KEY;
        let a = name_group(k, b"/x", b"/x/a", true);
        let b = name_group(k, b"/x", b"/x/b", true);
        let other = name_group(k, b"/z", b"/z/a", true);
        assert_eq!(prefix_key(a), prefix_key(b), "same routable prefix → same coarse key");
        assert_ne!(prefix_key(a), prefix_key(other), "different prefix → different coarse key");
        assert_ne!(a, b, "distinct full names → distinct full addresses (fine PIT match)");
    }

    /// Collision behaviour, stated honestly. The **flat** full-name hash
    /// ([`name_group_mac`]) uses all 46 bits, so 20k distinct names collide
    /// essentially never (birthday ~ n²/2⁴⁷ ≈ 3e-6). The **split** [`name_group`]
    /// trades entropy for aggregation: names under *one* routable prefix are
    /// discriminated only by the low 24 bits (the suffix hash), a 24-bit birthday
    /// bound (~4096 names/prefix before a likely collision). Both are fine for a
    /// *filter* — a collision only wastes a wake, since the full name + signature
    /// above the hash are authoritative — but a producer of a huge flat namespace
    /// should use `name_group_mac` (46-bit), and only relays that need family-match
    /// use the split.
    #[test]
    fn collision_behaviour_flat_46bit_vs_split_24bit_within_prefix() {
        use std::collections::HashSet;
        let n = 20_000;

        // Flat full-name hash: 46 bits → no collisions among 20k distinct names.
        let flat: HashSet<_> = (0..n).map(|i| name_group_mac(format!("/app/{i}/data").as_bytes())).collect();
        assert_eq!(flat.len(), n, "flat 46-bit hash: no collisions among {n} names");

        // Split under DIFFERENT prefixes: the full 46 bits vary → no collisions.
        let k = &OPEN_GROUP_KEY;
        let across: HashSet<_> =
            (0..n).map(|i| name_group(k, format!("/p{i}").as_bytes(), format!("/p{i}/d").as_bytes(), true)).collect();
        assert_eq!(across.len(), n, "split across distinct prefixes: no collisions");

        // Split WITHIN one prefix: only the low 24 bits discriminate, so 20k names DO
        // collide at the 24-bit birthday rate — the documented aggregation tradeoff.
        let within: HashSet<_> =
            (0..n).map(|i| name_group(k, b"/app", format!("/app/{i}").as_bytes(), true)).collect();
        assert!(within.len() < n, "split within one prefix: 24-bit discrimination collides (expected)");
        assert!(within.len() > n * 99 / 100, "…but only a handful ({}/{n} unique)", within.len());
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
        let got = parse(
            fmt,
            &build(fmt, &f).unwrap(),
            None,
            None,
            crate::ClockDomainId(0),
        )
        .unwrap();
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
        let got = parse_dot11(fmt, &dot11, Some(-33), Some(7), None).unwrap();
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

        let got = parse(
            fmt,
            &build(fmt, &inj).unwrap(),
            Some(-60),
            Some(0),
            crate::ClockDomainId(0),
        )
        .unwrap();
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
        assert!(parse(esp, &raw_wire, None, None, crate::ClockDomainId(0)).is_none());
        let esp_wire = build(esp, &frame(b"x")).unwrap();
        assert!(parse(raw, &esp_wire, None, None, crate::ClockDomainId(0)).is_none());
    }
}
