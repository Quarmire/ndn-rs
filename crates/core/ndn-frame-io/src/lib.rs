//! Layer: spec — backend-agnostic link-layer frame I/O.
//!
//! The substrate the connectionless radio faces are built on. A [`FrameIo`]
//! backend injects [`InjectFrame`]s at a chosen [`McsDescriptor`] rate and
//! yields [`CapturedFrame`]s; the [`frame`] module wraps/unwraps the NDN
//! payload per [`FrameFormat`], and [`radiotap`] parses the RX header. Reusable
//! backends live here: `AfPacketBackend` (Linux monitor mode) and the
//! format-agnostic [`LoopbackMonitorBus`] for tests. Device-specific drivers
//! (e.g. the RTL8812 USB backend) live with their face crate and implement
//! [`FrameIo`] against this surface.

pub mod frame;
pub mod radiotap;

/// The data-plane radio-HAL contract now lives in `ndn-radio-hal`; re-exported
/// here so every existing `ndn_frame_io::X` path and internal `crate::X`
/// reference still resolves unchanged.
pub use ndn_radio_hal::{
    BROADCAST, CapturedFrame, ClockDomainId, DEFAULT_SRC, FaceError, FaceId, FrameIo, InjectFrame,
    LatchPoint, LinkStamp, MAX_RELIABLE_MCS, McsDescriptor, McsPolicy, RadioCapability,
    RadioClockKind, RadioProfile, RadioTime, RadioTimeSource, Reach, Reliability, TxIntent,
    WifiRadio, mcs_for_rssi, mcs_phy_rate_bps,
};

pub use frame::{ESPNOW_MAX_BODY, ESPNOW_OUI, name_group_mac, name_group_uni};

mod loopback;
pub use loopback::{LoopbackEndpoint, LoopbackMonitorBus};

#[cfg(target_os = "linux")]
mod af_packet;
#[cfg(target_os = "linux")]
pub use af_packet::AfPacketBackend;

/// Usable injected-frame payload budget, sized to the **single 802.11 MSDU
/// ceiling**: an 802.11 MSDU is at most 2304 octets, and the backend spends 8
/// of those on the LLC/SNAP header that precedes our payload, leaving 2296.
/// One injected frame therefore carries one ~2296-byte LP frame without any
/// aggregation — the cheapest way to cut fragments-per-object (and thus the
/// multi-fragment loss an unACKed broadcast suffers) before reaching for
/// A-MSDU. Tunable per face via `MonitorWifiFace::with_mtu`; bigger frames
/// also raise per-frame loss at a given MCS, so the sweet spot is empirical
/// (see the `monitor_roundtrip` goodput bench).
pub const MONITOR_MTU: usize = 2296;

/// The legacy ~1500-byte-Ethernet-ish MTU used before the single-MSDU bump,
/// kept as a named baseline for the goodput A/B (`with_mtu(LEGACY_ETHER_MTU)`).
pub const LEGACY_ETHER_MTU: usize = 1450;

/// How an outbound NDN payload is wrapped into an on-air frame body (after the
/// radiotap TX header). Selected per `AfPacketBackend`; the loopback bus is
/// format-agnostic (it carries the payload directly).
///
/// On-air, a monitor-mode receiver hears *all* of these — radiotap is a
/// host-side capture artifact, not on the air — so different formats coexist on
/// one medium. Only [`RawNdn`](FrameFormat::RawNdn) is wired today; the rest are
/// the Phase-3 frame-format multiplexing seam (ESP-NOW interop with ESP32s,
/// HaLow sub-GHz, wfb-ng FPV-chipset interop).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameFormat {
    /// 802.11 data frame + LLC/SNAP carrying `ethertype`, then the NDN payload.
    /// Our peers' native format.
    RawNdn { ethertype: u16 },
    /// wfb-ng frame layout — interop with OpenIPC / FPV chipsets. (Phase 3.)
    Wfb,
    /// ESP-NOW vendor action frame (`oui` = vendor OUI) — interop with ESP32s
    /// running stock `esp_now_*`. ESP-NOW *is* a raw 802.11 vendor-action
    /// format, so it is a subset of this machinery. (Phase 3.)
    EspNow { oui: [u8; 3] },
    /// 802.11ah (HaLow) vendor action frame — sub-GHz, km-range. (Phase 3.)
    HaLowVendorAction,
    /// **Raw 802.11 passthrough**: `InjectFrame.payload` is already a complete
    /// 802.11 frame (from the management/data header onward), injected verbatim
    /// after the radiotap TX header; on capture, the whole 802.11 frame is
    /// returned as the payload. Unlike the other formats, this builds/parses *no*
    /// body framing — the caller owns the entire frame. It is how the userspace
    /// Wi-Fi Aware (NAN) stack injects management frames (beacons / Service
    /// Discovery action frames), which are not data frames and so don't fit
    /// [`RawNdn`](FrameFormat::RawNdn)'s LLC/SNAP data-frame shape.
    Raw80211,
}

impl Default for FrameFormat {
    fn default() -> Self {
        // 0x8624 is the NDN-over-Ethernet ethertype used across the stack.
        FrameFormat::RawNdn { ethertype: 0x8624 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use proptest::prelude::*;

    /// Build an `InjectFrame` from arbitrary parts (the MCS descriptor content is
    /// irrelevant to (de)framing here — only `index` is surfaced by the radiotap
    /// TX header, and the round-trip tests supply the RX MCS explicitly).
    fn inject(payload: Vec<u8>, dst: [u8; 6], src: [u8; 6]) -> InjectFrame {
        InjectFrame {
            payload: Bytes::from(payload),
            tx: TxIntent::CONSERVATIVE,
            dst,
            src,
        }
    }

    proptest! {
        /// `RawNdn`: any payload + any ethertype/addresses builds, and
        /// `parse(build(..))` recovers the payload, `src → addr`, `dst → group`,
        /// and passes the RX RSSI/MCS through verbatim.
        #[test]
        fn raw_ndn_round_trips_arbitrary(
            payload in prop::collection::vec(any::<u8>(), 0..2048),
            ethertype in any::<u16>(),
            dst in any::<[u8; 6]>(),
            src in any::<[u8; 6]>(),
            rssi in any::<i8>(),
            mcs in any::<u8>(),
        ) {
            let fmt = FrameFormat::RawNdn { ethertype };
            let f = inject(payload.clone(), dst, src);
            let wire = frame::build(fmt, &f).expect("RawNdn always builds");
            let got = frame::parse(fmt, &wire, Some(rssi), Some(mcs), crate::ClockDomainId(0))
                .expect("a freshly built RawNdn frame must parse");
            prop_assert_eq!(got.payload.as_ref(), &payload[..]);
            prop_assert_eq!(got.addr, Some(src));
            prop_assert_eq!(got.group, Some(dst));
            prop_assert_eq!(got.rssi_dbm, Some(rssi));
            prop_assert_eq!(got.mcs_index, Some(mcs));
        }

        /// `EspNow`: any body ≤ 250 B + any OUI round-trips. ESP-NOW pins
        /// `addr1` to broadcast (its receivers key on it), so the recovered group
        /// is always broadcast, independent of the injected `dst`.
        #[test]
        fn espnow_round_trips_arbitrary(
            payload in prop::collection::vec(any::<u8>(), 0..=ESPNOW_MAX_BODY),
            oui in any::<[u8; 3]>(),
            dst in any::<[u8; 6]>(),
            src in any::<[u8; 6]>(),
            rssi in any::<i8>(),
            mcs in any::<u8>(),
        ) {
            let fmt = FrameFormat::EspNow { oui };
            let f = inject(payload.clone(), dst, src);
            let wire = frame::build(fmt, &f).expect("body ≤ 250 always builds");
            let got = frame::parse(fmt, &wire, Some(rssi), Some(mcs), crate::ClockDomainId(0))
                .expect("a freshly built ESP-NOW frame must parse");
            prop_assert_eq!(got.payload.as_ref(), &payload[..]);
            prop_assert_eq!(got.addr, Some(src));
            prop_assert_eq!(got.group, Some(BROADCAST), "ESP-NOW addr1 is broadcast");
            prop_assert_eq!(got.rssi_dbm, Some(rssi));
            prop_assert_eq!(got.mcs_index, Some(mcs));
        }

        /// `EspNow` rejects a body over the single-byte element-length ceiling.
        #[test]
        fn espnow_rejects_oversize_body(
            payload in prop::collection::vec(any::<u8>(), (ESPNOW_MAX_BODY + 1)..(ESPNOW_MAX_BODY + 64)),
        ) {
            let fmt = FrameFormat::EspNow { oui: ESPNOW_OUI };
            let f = inject(payload, BROADCAST, DEFAULT_SRC);
            prop_assert!(frame::build(fmt, &f).is_err());
        }

        /// `Raw80211`: the payload IS the whole 802.11 frame — it survives byte
        /// for byte, and `addr2`/`addr1` are surfaced from the fixed header
        /// offsets (bytes 10..16 / 4..10) rather than from the InjectFrame.
        #[test]
        fn raw80211_round_trips_arbitrary(
            frame_bytes in prop::collection::vec(any::<u8>(), 24..2048),
            rssi in any::<i8>(),
            mcs in any::<u8>(),
        ) {
            let fmt = FrameFormat::Raw80211;
            // dst/src on the InjectFrame are ignored by Raw80211 (verbatim copy).
            let f = inject(frame_bytes.clone(), BROADCAST, DEFAULT_SRC);
            let wire = frame::build(fmt, &f).expect("Raw80211 always builds");
            let got = frame::parse(fmt, &wire, Some(rssi), Some(mcs), crate::ClockDomainId(0))
                .expect("a ≥24-byte Raw80211 frame must parse");
            prop_assert_eq!(got.payload.as_ref(), &frame_bytes[..], "verbatim");
            let mut ta = [0u8; 6];
            ta.copy_from_slice(&frame_bytes[10..16]);
            let mut ra = [0u8; 6];
            ra.copy_from_slice(&frame_bytes[4..10]);
            prop_assert_eq!(got.addr, Some(ta), "addr2 from the frame body");
            prop_assert_eq!(got.group, Some(ra), "addr1 from the frame body");
            prop_assert_eq!(got.rssi_dbm, Some(rssi));
            prop_assert_eq!(got.mcs_index, Some(mcs));
        }

        /// `mcs_for_rssi` is monotone non-decreasing in RSSI and never exceeds the
        /// verified reliable ceiling.
        #[test]
        fn mcs_for_rssi_is_monotone_and_capped(a in any::<i8>(), b in any::<i8>()) {
            let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
            prop_assert!(mcs_for_rssi(lo) <= mcs_for_rssi(hi), "stronger RSSI ⇒ ≥ MCS");
            prop_assert!(mcs_for_rssi(a) <= MAX_RELIABLE_MCS);
        }

        /// `mcs_phy_rate_bps` is monotone non-decreasing across the modelled MCS
        /// range and clamps everything above MCS7 to the top rate.
        #[test]
        fn mcs_phy_rate_is_monotone_and_clamps(a in 0u8..=7, b in 0u8..=7, high in 8u8..=255) {
            let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
            prop_assert!(mcs_phy_rate_bps(lo) <= mcs_phy_rate_bps(hi));
            prop_assert_eq!(mcs_phy_rate_bps(high), mcs_phy_rate_bps(7), "clamped above MCS7");
        }
    }

    /// The buildable formats do not cross-parse each other's wire bytes.
    #[test]
    fn distinct_formats_do_not_cross_parse() {
        let f = inject(b"payload".to_vec(), BROADCAST, DEFAULT_SRC);
        let raw = FrameFormat::RawNdn { ethertype: 0x8624 };
        let esp = FrameFormat::EspNow { oui: ESPNOW_OUI };
        let raw_wire = frame::build(raw, &f).unwrap();
        let esp_wire = frame::build(esp, &f).unwrap();
        assert!(frame::parse(esp, &raw_wire, None, None, crate::ClockDomainId(0)).is_none());
        assert!(frame::parse(raw, &esp_wire, None, None, crate::ClockDomainId(0)).is_none());
    }

    /// The unimplemented formats error at build time (never a panic).
    #[test]
    fn unimplemented_formats_error_not_panic() {
        let f = inject(b"x".to_vec(), BROADCAST, DEFAULT_SRC);
        assert!(frame::build(FrameFormat::Wfb, &f).is_err());
        assert!(frame::build(FrameFormat::HaLowVendorAction, &f).is_err());
    }

    /// The `McsDescriptor` builder helpers set exactly the fields they name.
    #[test]
    fn mcs_descriptor_builders() {
        assert_eq!(McsDescriptor::default(), McsDescriptor::CONSERVATIVE);
        let ht = McsDescriptor::ht(5);
        assert_eq!(ht.index, 5);
        assert!(!ht.vht && ht.nss == 1 && !ht.stbc && !ht.ldpc);
        let vht = McsDescriptor::vht(7);
        assert!(vht.vht && vht.nss == 1);
        let vht2 = McsDescriptor::vht_2ss(4);
        assert!(vht2.vht && vht2.nss == 2);
        let both = McsDescriptor::ht(3).with_stbc().with_ldpc();
        assert!(both.stbc && both.ldpc);
    }
}
