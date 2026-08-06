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

/// An **ephemeral, per-boot, rotating source tag** — the source-field value the named-radio doctrine
/// (mac-addressing-doctrine §2) calls for. It is a locally-administered, *individual* 6-byte address
/// with **no routing meaning**: randomized once per boot (from a caller-supplied `boot_seed`) and
/// rotated on a schedule to bound linkability. It is **not** a host identity — the doctrine forbids
/// keying any routing/forwarding state on it. Its only jobs are per-frame RSSI attribution (a
/// per-neighbour `SignalStore` key), per-source DoS rate-limiting, and disambiguating two producers
/// emitting under one prefix at once.
///
/// The nonce for a given instant is `SipHash(boot_seed, rotation_epoch)` truncated to the low 46
/// bits, with the first octet forced to U/L=local, I/G=individual — so it stays inert to real
/// networks and can never be mistaken for a manufacturer-assigned host MAC.
#[derive(Clone, Copy, Debug)]
pub struct EphemeralSource {
    boot_seed: u64,
    rotation_period_ms: u64,
}

impl EphemeralSource {
    /// `boot_seed` should be drawn from a per-boot entropy source by the caller (time ⊕ pid ⊕ face,
    /// or an RNG). `rotation_period_ms` is how long one nonce stays stable; `0` disables rotation
    /// (one fixed nonce for the whole boot — still per-boot random, just not rotating).
    pub const fn new(boot_seed: u64, rotation_period_ms: u64) -> Self {
        Self { boot_seed, rotation_period_ms }
    }

    /// The source address in effect at `now_ms`. Frames within one rotation period share it (so a
    /// receiver can attribute their RSSI to one neighbour); it changes across periods and boots.
    pub fn current(&self, now_ms: u64) -> [u8; 6] {
        let epoch =
            if self.rotation_period_ms == 0 { 0 } else { now_ms / self.rotation_period_ms };
        let mut key = [0u8; 16];
        key[..8].copy_from_slice(&self.boot_seed.to_le_bytes());
        let h = siphash24(&key, &epoch.to_le_bytes()).to_le_bytes();
        // Low 46 bits into the address body; force U/L=local (0x02) + I/G=individual (clear 0x01).
        let mut m = [h[0], h[1], h[2], h[3], h[4], h[5]];
        m[0] = (m[0] & 0xFC) | 0x02;
        m
    }
}

/// Build `radiotap ++ 802.11 ++ <format body>` for one injected frame. The
/// 802.11 address fields are filled from `frame.dst`/`frame.src`/`frame.addr3` — under the
/// Tier-0 layout `addr1 ‖ addr2` are the name's prefix-set filter and `addr3` the ephemeral
/// nonce, so no host identity appears on the wire.
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

/// Build one **A-MSDU** frame for the AF_PACKET monitor path: radiotap (per
/// `format`/`mcs`) ++ a single QoS-Data MPDU carrying `msdus` as A-MSDU
/// subframes under one PHY preamble and one FCS. The link-layer bundling
/// actuator — one preamble amortized over many NDN packets, the bigger win at
/// S1G where preambles are long and rates low. All subframes ride one MPDU
/// (addr1/RA = addr3 = `ra`, addr2/TA = `ta`); each subframe carries its own
/// DA/SA, so a broadcast face collapses to one A-MSDU. The caller bounds the
/// aggregate size (S1G caps the max MPDU per bandwidth). Byte layout matches the
/// RTL/MT USB backends' `build_amsdu_body` (they prepend a chip TX descriptor
/// instead of radiotap); the RX side de-aggregates via [`parse_dot11`], which
/// already handles QoS-Data for RawNdn/RawNdnS1g. Only RawNdn/RawNdnS1g support
/// A-MSDU.
pub fn build_amsdu(
    format: FrameFormat,
    ra: [u8; 6],
    ta: [u8; 6],
    msdus: &[([u8; 6], [u8; 6], Bytes)],
    seq: u16,
    mcs: crate::McsDescriptor,
) -> Result<Vec<u8>, FaceError> {
    let ethertype = match format {
        FrameFormat::RawNdn { ethertype } | FrameFormat::RawNdnS1g { ethertype } => ethertype,
        other => {
            return Err(FaceError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("A-MSDU unsupported for frame format {other:?}"),
            )));
        }
    };
    if msdus.is_empty() {
        return Err(FaceError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "A-MSDU needs at least one MSDU",
        )));
    }
    let mut out = Vec::with_capacity(
        16 + DOT11_QOS_HDR_LEN + msdus.iter().map(|(_, _, p)| 32 + p.len()).sum::<usize>(),
    );
    // Radiotap TX header — identical rate choice to `build_at`.
    match format {
        FrameFormat::RawNdnS1g { .. } => out.extend_from_slice(&radiotap::build_tx_s1g()),
        _ => out.extend_from_slice(&radiotap::build_tx_header(mcs.index, mcs.short_gi)),
    }
    // QoS-Data MPDU header (26 B): FC subtype 8 (QoS Data); A-MSDU-present in QoS Ctrl.
    out.extend_from_slice(&[0x88, 0x00]); // FC: type=Data, subtype=QoS Data
    out.extend_from_slice(&[0x00, 0x00]); // Duration
    out.extend_from_slice(&ra); // addr1 (RA)
    out.extend_from_slice(&ta); // addr2 (TA)
    out.extend_from_slice(&ra); // addr3 (BSSID)
    out.extend_from_slice(&((seq & 0x0fff) << 4).to_le_bytes()); // SeqCtrl
    out.extend_from_slice(&[0x80, 0x00]); // QoS Ctrl: A-MSDU Present (bit 7), TID 0
    let last = msdus.len() - 1;
    for (i, (da, sa, payload)) in msdus.iter().enumerate() {
        let msdu_len = LLC_SNAP_LEN + payload.len(); // LLC/SNAP + payload
        out.extend_from_slice(da); // subframe DA
        out.extend_from_slice(sa); // subframe SA
        out.extend_from_slice(&(msdu_len as u16).to_be_bytes()); // Length (big-endian)
        out.extend_from_slice(&LLC_SNAP_PREFIX);
        out.extend_from_slice(&ethertype.to_be_bytes());
        out.extend_from_slice(payload);
        if i != last {
            // Pad every subframe but the last to a 4-byte boundary.
            let sub_len = 14 + msdu_len; // DA+SA+Len + MSDU
            let pad = (4 - (sub_len % 4)) % 4;
            out.extend(std::iter::repeat_n(0u8, pad));
        }
    }
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
            out.extend_from_slice(&frame.dst); // addr1 (RA/DA) = group / Tier-0 filter hi
            out.extend_from_slice(&frame.src); // addr2 (TA/SA) = name-derived / filter lo
            // addr3: the ephemeral source nonce when addr1‖addr2 is a Tier-0 filter, else
            // the legacy BSSID slot (a copy of dst). Nothing on the RX path reads addr3 for
            // the legacy layout, so the fallback is byte-compatible with prior deployments.
            out.extend_from_slice(&frame.addr3.unwrap_or(frame.dst)); // addr3 (BSSID / nonce)
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
            // addr3 (BSSID slot): the sender's ephemeral nonce under the Tier-0 layout, where
            // addr1‖addr2 is the prefix-set filter and so cannot also carry the source.
            let addr3 = body.get(16..22).map(|s| {
                let mut a = [0u8; 6];
                a.copy_from_slice(s);
                a
            });
            Some(CapturedFrame {
                payload: Bytes::copy_from_slice(&body[hdr_len + LLC_SNAP_LEN..]),
                addr: Some(ta),
                group: Some(group),
                addr3,
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
                addr3: None, // ESP-NOW addr3 is broadcast, not a nonce
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
            let addr3 = body.get(16..22).map(|s| {
                let mut a = [0u8; 6];
                a.copy_from_slice(s);
                a
            });
            Some(CapturedFrame {
                payload: Bytes::copy_from_slice(body),
                addr: Some(ta),
                group: Some(group),
                addr3,
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
            addr3: None,
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

    /// §2 doctrine: the ephemeral source nonce is a locally-administered *individual* tag (U/L=local,
    /// I/G=individual), never a host MAC; it is stable within a rotation period, rotates across
    /// periods, and differs across boots — so it can attribute per-frame RSSI without being an identity.
    #[test]
    fn ephemeral_source_is_local_individual_and_rotates() {
        let src = EphemeralSource::new(0xDEAD_BEEF, 1000); // 1 s rotation
        let a = src.current(0);
        // Locally administered (not a vendor MAC) + individual (a source, not multicast).
        assert_eq!(a[0] & 0x02, 0x02, "U/L local bit set — not a globally-unique host MAC");
        assert_eq!(a[0] & 0x01, 0x00, "I/G individual bit clear — a source address");
        // Stable within a period; rotates across periods.
        assert_eq!(a, src.current(999), "stable within one rotation period");
        assert_ne!(a, src.current(1000), "rotates into the next period");
        // Different boot seed → different nonce (per-boot randomness, no persistent identity).
        assert_ne!(a, EphemeralSource::new(0x1234_5678, 1000).current(0), "differs across boots");
        // No rotation when the period is 0 (still per-boot random, just fixed for the boot).
        let fixed = EphemeralSource::new(7, 0);
        assert_eq!(fixed.current(0), fixed.current(1_000_000), "period 0 → one nonce for the boot");
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
            addr3: None,
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
