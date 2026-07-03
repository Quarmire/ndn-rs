//! Minimal radiotap codec for monitor-mode injection and capture.
//!
//! Radiotap is the de-facto header that drivers prepend to captured 802.11
//! frames and honour on injected ones (<https://www.radiotap.org>). This face
//! needs exactly two operations from it:
//!
//! * **TX** — build a header that tells the driver *which rate/MCS* to transmit
//!   at. This is the lever that defeats the legacy-rate wall: an injected frame
//!   carries its own MCS in the radiotap `MCS` field, so there is no AP basic-
//!   rate floor (see the crate-level docs). wfb-ng / OpenIPC inject this exact
//!   shape to push 10–50 Mbps of "broadcast" video.
//! * **RX** — parse the header the driver prepends to a captured frame to pull
//!   the per-frame **RSSI** (and the MCS it arrived at), feeding the cross-layer
//!   signal store and the adaptive-MCS picker.
//!
//! Layout: an 8-byte fixed header (`u8 version`, `u8 pad`, `le16 len`,
//! `le32 present`) optionally followed by more `le32` present words (when the
//! extension bit is set), then the present fields in ascending bit order, each
//! aligned to its natural size **relative to the start of the header**. We
//! implement the field table up to the fields we read; if an unknown present
//! bit appears we stop walking and return what was gathered so far — RSSI
//! (bit 5) is low enough that it is always reached before vendor/extension
//! fields. The 802.11 frame always begins at byte `it_len`, so payload
//! extraction never depends on understanding every field.

/// Present-bitmap bit indices (subset we care about).
const BIT_TSFT: u32 = 0;
const BIT_RATE: u32 = 2;
const BIT_DBM_ANTSIGNAL: u32 = 5;
const BIT_TX_FLAGS: u32 = 15;
const BIT_MCS: u32 = 19;
/// Bit 31 of a present word: another present word follows.
const BIT_EXT: u32 = 31;

/// `IEEE80211_RADIOTAP_F_TX_NOACK` — inject as broadcast, do not wait for an
/// ACK that will never come (there is no associated peer).
const TX_FLAG_NOACK: u16 = 0x0008;

// MCS "known" mask: which of the MCS sub-fields we are actually specifying.
const MCS_HAVE_MCS: u8 = 0x01;
const MCS_HAVE_BW: u8 = 0x02;
const MCS_HAVE_GI: u8 = 0x04;
// MCS flags: bandwidth in bits 0-1 (0 = 20 MHz), short-GI in bit 2.
const MCS_FLAG_BW_20: u8 = 0x00;
const MCS_FLAG_SGI: u8 = 0x04;

/// Total length of the TX header produced by [`build_tx_header`].
pub const TX_HEADER_LEN: usize = 13;

/// Build a radiotap **TX** header selecting an 802.11n MCS rate.
///
/// The frame the driver transmits is `build_tx_header(..) ++ <802.11 frame>`.
/// `mcs_index` is the 11n modulation-and-coding index (0–7 for a single
/// spatial stream, 20 MHz). `short_gi` requests the 400 ns guard interval.
///
/// Field layout (no padding needed — TX_FLAGS is 2-byte aligned at offset 8,
/// MCS is 1-byte aligned right after):
/// ```text
/// off 0  : version = 0
/// off 1  : pad     = 0
/// off 2  : le16 len = 13
/// off 4  : le32 present = (1<<TX_FLAGS) | (1<<MCS)
/// off 8  : le16 TX_FLAGS = NOACK
/// off 10 : u8 MCS.known = HAVE_MCS|HAVE_BW|HAVE_GI
/// off 11 : u8 MCS.flags = BW_20 | (SGI if short_gi)
/// off 12 : u8 MCS.index = mcs_index
/// ```
pub fn build_tx_header(mcs_index: u8, short_gi: bool) -> [u8; TX_HEADER_LEN] {
    let present: u32 = (1 << BIT_TX_FLAGS) | (1 << BIT_MCS);
    let mut h = [0u8; TX_HEADER_LEN];
    // fixed header
    h[0] = 0; // version
    h[1] = 0; // pad
    h[2..4].copy_from_slice(&(TX_HEADER_LEN as u16).to_le_bytes());
    h[4..8].copy_from_slice(&present.to_le_bytes());
    // TX_FLAGS (bit 15)
    h[8..10].copy_from_slice(&TX_FLAG_NOACK.to_le_bytes());
    // MCS (bit 19)
    h[10] = MCS_HAVE_MCS | MCS_HAVE_BW | MCS_HAVE_GI;
    h[11] = MCS_FLAG_BW_20 | if short_gi { MCS_FLAG_SGI } else { 0 };
    h[12] = mcs_index;
    h
}

/// Total length of the legacy-rate TX header produced by [`build_tx_legacy`].
pub const TX_LEGACY_HEADER_LEN: usize = 12;

/// Build a radiotap **TX** header selecting a **legacy (non-HT) rate** instead
/// of an MCS. `rate_500kbps` is in 500 kbps units (`2` = 1 Mbps DSSS). This is
/// the robust, ESP-NOW-native path: 1 Mbps has a far better link budget than
/// the lowest MCS (≈9 dB), and it is the rate an ESP32 expects for ESP-NOW.
///
/// Layout: RATE (bit 2, 1 byte) then TX_FLAGS (bit 15, 2-byte aligned → one
/// pad byte at offset 9).
pub fn build_tx_legacy(rate_500kbps: u8) -> [u8; TX_LEGACY_HEADER_LEN] {
    const BIT_RATE: u32 = 2;
    let present: u32 = (1 << BIT_RATE) | (1 << BIT_TX_FLAGS);
    let mut h = [0u8; TX_LEGACY_HEADER_LEN];
    h[2..4].copy_from_slice(&(TX_LEGACY_HEADER_LEN as u16).to_le_bytes());
    h[4..8].copy_from_slice(&present.to_le_bytes());
    h[8] = rate_500kbps; // RATE @ offset 8
    // offset 9 is a pad byte for the u16 TX_FLAGS alignment
    h[10..12].copy_from_slice(&TX_FLAG_NOACK.to_le_bytes());
    h
}

/// What we extract from a captured frame's radiotap header.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RadiotapInfo {
    /// Received signal strength in dBm (`IEEE80211_RADIOTAP_DBM_ANTSIGNAL`).
    pub rssi_dbm: Option<i8>,
    /// 11n MCS index the frame was received at, if the `MCS` field was present.
    pub mcs_index: Option<u8>,
    /// Legacy rate in 500 kbps units, if the `RATE` field was present.
    pub rate_500kbps: Option<u8>,
    /// The 64-bit TSFT (MAC Timing Synchronization Function) counter latched by
    /// the NIC at reception, if the header carried it. This is the hardware
    /// receive timestamp named-time builds a [`LinkStamp`](ndn_radio_hal::LinkStamp)
    /// from — ~1 µs resolution, latched before host software touches the frame.
    pub tsft: Option<u64>,
    /// Offset where the 802.11 frame begins (== `it_len`).
    pub header_len: usize,
}

/// `(alignment, size)` for each radiotap field we know how to skip, indexed by
/// present-bit. `None` = a field whose size we don't model; hitting a set bit
/// with `None` stops the walk (we return what was gathered, payload offset is
/// still known from `it_len`).
const FIELD_DEFS: [Option<(usize, usize)>; 22] = [
    Some((8, 8)),  // 0  TSFT
    Some((1, 1)),  // 1  FLAGS
    Some((1, 1)),  // 2  RATE
    Some((2, 4)),  // 3  CHANNEL
    Some((2, 2)),  // 4  FHSS
    Some((1, 1)),  // 5  DBM_ANTSIGNAL
    Some((1, 1)),  // 6  DBM_ANTNOISE
    Some((2, 2)),  // 7  LOCK_QUALITY
    Some((2, 2)),  // 8  TX_ATTENUATION
    Some((2, 2)),  // 9  DB_TX_ATTENUATION
    Some((1, 1)),  // 10 DBM_TX_POWER
    Some((1, 1)),  // 11 ANTENNA
    Some((1, 1)),  // 12 DB_ANTSIGNAL
    Some((1, 1)),  // 13 DB_ANTNOISE
    Some((2, 2)),  // 14 RX_FLAGS
    Some((2, 2)),  // 15 TX_FLAGS
    Some((1, 1)),  // 16 RTS_RETRIES
    Some((1, 1)),  // 17 DATA_RETRIES
    None,          // 18 (XChannel / reserved — ambiguous, stop here)
    Some((1, 3)),  // 19 MCS
    Some((4, 8)),  // 20 AMPDU_STATUS
    Some((2, 12)), // 21 VHT
];

fn align_up(off: usize, align: usize) -> usize {
    (off + align - 1) & !(align - 1)
}

/// Parse a captured frame's radiotap header. Returns `None` only when the
/// buffer is too short or the version/length are malformed; a header that
/// simply lacks RSSI yields `RadiotapInfo { rssi_dbm: None, .. }` with a valid
/// `header_len`.
pub fn parse(buf: &[u8]) -> Option<RadiotapInfo> {
    if buf.len() < 8 || buf[0] != 0 {
        return None;
    }
    let it_len = u16::from_le_bytes([buf[2], buf[3]]) as usize;
    if it_len < 8 || it_len > buf.len() {
        return None;
    }

    // Read the first present word; skip any extension words (bit 31 set).
    let present0 = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let mut off = 8;
    let mut word = present0;
    while word & (1 << BIT_EXT) != 0 {
        if off + 4 > it_len {
            return None;
        }
        word = u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
        off += 4;
    }

    let mut info = RadiotapInfo {
        header_len: it_len,
        ..RadiotapInfo::default()
    };

    // Walk only the standard fields advertised by the first present word.
    for (bit, def) in FIELD_DEFS.iter().enumerate() {
        if present0 & (1 << bit) == 0 {
            continue;
        }
        let (align, size) = match def {
            Some(d) => *d,
            None => break, // unknown field; payload offset already known
        };
        off = align_up(off, align);
        if off + size > it_len {
            break;
        }
        match bit as u32 {
            BIT_TSFT => {
                info.tsft = Some(u64::from_le_bytes([
                    buf[off],
                    buf[off + 1],
                    buf[off + 2],
                    buf[off + 3],
                    buf[off + 4],
                    buf[off + 5],
                    buf[off + 6],
                    buf[off + 7],
                ]));
            }
            BIT_RATE => info.rate_500kbps = Some(buf[off]),
            BIT_DBM_ANTSIGNAL => info.rssi_dbm = Some(buf[off] as i8),
            BIT_MCS => info.mcs_index = Some(buf[off + 2]), // known, flags, index
            _ => {}
        }
        off += size;
    }

    Some(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_header_carries_mcs_and_noack() {
        let h = build_tx_header(3, true);
        assert_eq!(h.len(), TX_HEADER_LEN);
        assert_eq!(h[0], 0, "version");
        assert_eq!(u16::from_le_bytes([h[2], h[3]]) as usize, TX_HEADER_LEN);
        let present = u32::from_le_bytes([h[4], h[5], h[6], h[7]]);
        assert_eq!(present, (1 << BIT_TX_FLAGS) | (1 << BIT_MCS));
        assert_eq!(u16::from_le_bytes([h[8], h[9]]), TX_FLAG_NOACK);
        assert_eq!(h[10], MCS_HAVE_MCS | MCS_HAVE_BW | MCS_HAVE_GI);
        assert_eq!(h[11] & MCS_FLAG_SGI, MCS_FLAG_SGI, "short GI requested");
        assert_eq!(h[12], 3, "mcs index");
    }

    /// A TX header is itself valid radiotap, so parsing it back must recover the
    /// MCS index and find the payload at `it_len`.
    #[test]
    fn tx_header_round_trips_through_parse() {
        let h = build_tx_header(5, false);
        let info = parse(&h).expect("tx header is valid radiotap");
        assert_eq!(info.mcs_index, Some(5));
        assert_eq!(info.header_len, TX_HEADER_LEN);
        assert_eq!(info.rssi_dbm, None, "TX header carries no RSSI");
    }

    /// Synthesise a realistic capture header (FLAGS + RATE + CHANNEL +
    /// DBM_ANTSIGNAL + ANTENNA, the ath9k-ish set) and confirm RSSI extraction
    /// with correct field alignment.
    #[test]
    fn parse_extracts_rssi_from_capture_header() {
        let present: u32 = (1 << 1) | (1 << 2) | (1 << 3) | (1 << 5) | (1 << 11);
        let mut h = vec![0u8, 0]; // version, pad
        let mut body = Vec::new();
        // bit 1 FLAGS (1,1) @ off 8
        body.push(0x10);
        // bit 2 RATE (1,1) @ off 9
        body.push(0x02); // 1 Mbps in 500kbps units
        // bit 3 CHANNEL (2,4): off 10 -> align 2 -> 10, write 4 bytes
        body.extend_from_slice(&2412u16.to_le_bytes());
        body.extend_from_slice(&0x00a0u16.to_le_bytes());
        // bit 5 DBM_ANTSIGNAL (1,1) @ off 14
        body.push((-67i8) as u8);
        // bit 11 ANTENNA (1,1) @ off 15
        body.push(0);
        let it_len = (8 + body.len()) as u16;
        h.extend_from_slice(&it_len.to_le_bytes());
        h.extend_from_slice(&present.to_le_bytes());
        h.extend_from_slice(&body);

        let info = parse(&h).expect("valid header");
        assert_eq!(info.rssi_dbm, Some(-67));
        assert_eq!(info.rate_500kbps, Some(0x02));
        assert_eq!(info.header_len, it_len as usize);
    }

    #[test]
    fn parse_extracts_tsft() {
        // A header carrying only TSFT (bit 0), an 8-byte counter aligned to 8.
        let present: u32 = 1 << 0;
        let tsft: u64 = 0x0123_4567_89ab_cdef;
        let mut h = vec![0u8, 0]; // version, pad
        let body = tsft.to_le_bytes(); // TSFT @ off 8 (already aligned)
        let it_len = (8 + body.len()) as u16;
        h.extend_from_slice(&it_len.to_le_bytes());
        h.extend_from_slice(&present.to_le_bytes());
        h.extend_from_slice(&body);

        let info = parse(&h).expect("valid header");
        assert_eq!(info.tsft, Some(tsft));
        // A header without TSFT leaves it None.
        let mut h2 = vec![0u8, 0];
        let present2: u32 = 1 << 5; // DBM_ANTSIGNAL only
        let it_len2 = 8u16 + 1;
        h2.extend_from_slice(&it_len2.to_le_bytes());
        h2.extend_from_slice(&present2.to_le_bytes());
        h2.push((-50i8) as u8);
        assert_eq!(parse(&h2).unwrap().tsft, None);
    }

    #[test]
    fn parse_rejects_garbage() {
        assert_eq!(parse(&[]), None);
        assert_eq!(parse(&[1, 0, 8, 0, 0, 0, 0, 0]), None, "bad version");
        assert_eq!(parse(&[0, 0, 0xff, 0xff, 0, 0, 0, 0]), None, "len > buf");
    }
}
