//! Layer: spec — the data-plane radio HAL contract.
//!
//! The bearer-agnostic transmit/receive seam the connectionless radio faces are
//! built on: [`TxIntent`] states *what* a transmit should achieve, a backend
//! resolves it to its PHY (802.11 maps it to an [`McsDescriptor`] via
//! [`McsDescriptor::for_intent`]); [`InjectFrame`]/[`CapturedFrame`] are the
//! inject/capture units; [`FrameIo`] is the radio trait, and [`WifiRadio`] the
//! WiFi-only escape hatch for injecting at an exact 802.11 rate. Pure types +
//! traits — no I/O, no framing. The on-air framing, radiotap codec, and the
//! reusable AF_PACKET/loopback backends live in `ndn-frame-io`, which re-exports
//! this contract so its public surface is unchanged.

use async_trait::async_trait;
use bytes::Bytes;

/// Re-exported so backend/face authors can name the id type without depending
/// on `ndn-transport` directly.
pub use ndn_transport::{FaceError, FaceId};

/// The 802.11 broadcast address — the default destination when no name-group is
/// configured (every monitor receiver keeps the frame).
pub const BROADCAST: [u8; 6] = [0xff; 6];
/// A locally-administered unicast default source. Monitor injection places no
/// meaning on the source MAC (the NDN name is the addressing), but a well-formed
/// 802.11 header needs one; this is `02:'N':'D':'N':00:01`, never a host MAC.
pub const DEFAULT_SRC: [u8; 6] = [0x02, 0x4e, 0x44, 0x4e, 0x00, 0x01];

/// The 802.11n/ac rate to inject a frame at — what defeats the legacy-rate wall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct McsDescriptor {
    /// Modulation-and-coding index. HT: 0–7 (1 stream) / 8–15 (2 streams).
    /// VHT 1SS at 20 MHz: 0–8 (MCS9 needs ≥40 MHz).
    pub index: u8,
    /// Request the 400 ns short guard interval (≈11% faster, needs good SNR).
    pub short_gi: bool,
    /// Inject as 802.11ac (VHT) instead of 802.11n (HT). VHT adds 256-QAM
    /// (MCS8/9) and a more efficient PHY header.
    pub vht: bool,
    /// Spatial streams. **VHT only** (1 or 2) — selects the VHT-1SS vs VHT-2SS
    /// rate code. For HT the stream count is carried by `index` (0–7 = 1 stream,
    /// 8–15 = 2 streams), so this is ignored. Requires the 2-stream TX path
    /// (`0x820=0x31`, set in `set_channel_bw20`).
    pub nss: u8,
    /// Space-Time Block Coding: Alamouti-encode **one** spatial stream across
    /// both TX antennas (A+B, always enabled here via `0x820=0x31`). Pure TX
    /// diversity — it doubles the air time per bit but turns a 2-antenna chip
    /// into a far more robust single-stream transmitter, with **no receiver
    /// feedback**. That makes it ideal for broadcast NDN, where there are no
    /// ACKs to drive retransmission. Only valid for a 1-stream rate (HT MCS0–7
    /// or VHT `nss == 1`); the descriptor bit is suppressed for 2-stream rates
    /// (STBC + 2 spatial streams is not an 802.11 mode this chip transmits).
    pub stbc: bool,
    /// Low-Density Parity-Check coding: use the LDPC FEC encoder instead of the
    /// mandatory binary convolutional code (BCC). Stronger error correction
    /// (~1.5–2 dB coding gain) for the same rate — directly useful on the lossy,
    /// un-retransmitted broadcast channel. Both endpoints advertise/honour it in
    /// the HT-SIG / VHT-SIG; the receiver must support LDPC RX (the kernel
    /// rtl8812eu does). Independent of `stbc` — they compose.
    pub ldpc: bool,
}

impl McsDescriptor {
    /// A conservative, widely-decodable default (HT MCS1, long GI).
    pub const CONSERVATIVE: McsDescriptor = McsDescriptor {
        index: 1,
        short_gi: false,
        vht: false,
        nss: 1,
        stbc: false,
        ldpc: false,
    };

    /// An 802.11n (HT) rate at `index`, long GI (index 8–15 = 2 streams).
    pub const fn ht(index: u8) -> Self {
        McsDescriptor {
            index,
            short_gi: false,
            vht: false,
            nss: 1,
            stbc: false,
            ldpc: false,
        }
    }

    /// An 802.11ac (VHT) single-stream rate at `index`, long GI.
    pub const fn vht(index: u8) -> Self {
        McsDescriptor {
            index,
            short_gi: false,
            vht: true,
            nss: 1,
            stbc: false,
            ldpc: false,
        }
    }

    /// An 802.11ac (VHT) **2-stream** rate at `index`, long GI.
    pub const fn vht_2ss(index: u8) -> Self {
        McsDescriptor {
            index,
            short_gi: false,
            vht: true,
            nss: 2,
            stbc: false,
            ldpc: false,
        }
    }

    /// Enable [`stbc`](Self::stbc) (space-time diversity over both antennas).
    /// Chainable: `McsDescriptor::ht(5).with_stbc()`.
    pub const fn with_stbc(mut self) -> Self {
        self.stbc = true;
        self
    }

    /// Enable [`ldpc`](Self::ldpc) (LDPC FEC instead of BCC). Chainable:
    /// `McsDescriptor::vht(7).with_ldpc()`.
    pub const fn with_ldpc(mut self) -> Self {
        self.ldpc = true;
        self
    }
}

impl Default for McsDescriptor {
    fn default() -> Self {
        Self::CONSERVATIVE
    }
}

/// What a transmit should *achieve*, independent of how a given PHY achieves it
/// — the bearer-agnostic transmit contract carried on every [`InjectFrame`].
/// 802.11 maps it to an MCS + coding ([`McsDescriptor::for_intent`]); a LoRa
/// bearer would map it to a spreading factor, an SDR to its own waveform. On a
/// broadcast, un-ACKed medium *reliability* is the primary axis — there is no
/// per-receiver feedback to rate-adapt against, so the caller states intent and
/// the backend (or the cognitive plane) resolves it for the hardware.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxIntent {
    /// The robustness objective — the axis that dominates on a no-ARQ broadcast.
    pub reliability: Reliability,
    /// Who the frame is for — every receiver in range, or a name-group.
    pub reach: Reach,
    /// An 802.11 rate the caller has already resolved for a WiFi bearer (fixed-
    /// rate benches, and the adaptive / cognitive `MonitorWifiFace`). Abstract
    /// callers and non-WiFi bearers leave this `None`; a WiFi backend then
    /// resolves `reliability` via [`McsDescriptor::for_intent`]. Non-WiFi backends
    /// ignore it — it is an opt-in WiFi pre-resolution, not the shape of the seam.
    pub wifi: Option<McsDescriptor>,
}

/// The robustness objective of a [`TxIntent`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Reliability {
    /// Maximum robustness — lowest-order modulation + strongest FEC + diversity
    /// coding where the PHY offers it. Discovery, beacons, control: anything the
    /// farthest / worst receiver must still decode. (802.11: base MCS + STBC + LDPC.)
    MostRobust,
    /// A widely-decodable balance — the default when there is no measured link.
    #[default]
    Balanced,
    /// Favour throughput on a link known to be good (measured RSSI headroom).
    Throughput,
}

/// Who a [`TxIntent`] is addressed to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Reach {
    /// Every receiver in range; no per-receiver adaptation is possible.
    #[default]
    Broadcast,
    /// A name-group; adaptation may target the group's worst member.
    Group,
}

impl TxIntent {
    /// Maximum-robustness broadcast — the discovery / beacon / control default,
    /// and what a NAN or unmeasured face should use.
    pub const ROBUST: TxIntent = TxIntent {
        reliability: Reliability::MostRobust,
        reach: Reach::Broadcast,
        wifi: None,
    };
    /// A widely-decodable balance broadcast.
    pub const CONSERVATIVE: TxIntent = TxIntent {
        reliability: Reliability::Balanced,
        reach: Reach::Broadcast,
        wifi: None,
    };
    /// Broadcast at a stated reliability.
    pub const fn broadcast(reliability: Reliability) -> Self {
        TxIntent { reliability, reach: Reach::Broadcast, wifi: None }
    }
    /// Pin an exact 802.11 rate (WiFi benches / the resolved `MonitorWifiFace`
    /// rate). A WiFi-only escape hatch; other bearers ignore `wifi`.
    pub const fn wifi(mcs: McsDescriptor) -> Self {
        TxIntent { reliability: Reliability::Balanced, reach: Reach::Broadcast, wifi: Some(mcs) }
    }
}

impl Default for TxIntent {
    fn default() -> Self {
        TxIntent::CONSERVATIVE
    }
}

impl McsDescriptor {
    /// Resolve a bearer-agnostic [`TxIntent`] to a concrete 802.11 rate for a
    /// radio that supports up to `max_index` (single-stream HT) and, if
    /// `vht_cap`, 802.11ac. Honours an explicit `intent.wifi` pre-resolution;
    /// otherwise maps the reliability axis: `MostRobust` → base rate with STBC +
    /// LDPC diversity (ideal for un-ACKed broadcast), `Balanced` → a conservative
    /// mid rate, `Throughput` → the top validated rate + short GI. This is the
    /// 802.11 mapping of the transmit intent; another bearer maps it differently.
    pub fn for_intent(intent: &TxIntent, max_index: u8, vht_cap: bool) -> McsDescriptor {
        if let Some(m) = intent.wifi {
            return m;
        }
        match intent.reliability {
            Reliability::MostRobust => McsDescriptor::ht(0).with_stbc().with_ldpc(),
            Reliability::Balanced => McsDescriptor::CONSERVATIVE,
            Reliability::Throughput => {
                let idx = max_index.min(MAX_RELIABLE_MCS);
                let base = if vht_cap { McsDescriptor::vht(idx) } else { McsDescriptor::ht(idx) };
                McsDescriptor { short_gi: true, ..base }
            }
        }
    }
}

/// How the face picks the injection MCS for each frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum McsPolicy {
    /// Always inject at this rate.
    Fixed(McsDescriptor),
    /// Pick the MCS from the most recently observed RSSI ([`mcs_for_rssi`]).
    /// This is the content-centric replacement for MAC rate-adaptation
    /// feedback: the feedback is the RSSI of frames we hear, not link-layer
    /// ACKs. (Phase 2.)
    Adaptive,
}

impl Default for McsPolicy {
    fn default() -> Self {
        McsPolicy::Fixed(McsDescriptor::CONSERVATIVE)
    }
}

/// Highest MCS the userspace RTL8812EU driver is *validated* to deliver today.
///
/// The PA is non-linear at the BPSK/QPSK operating power, so 16-QAM and up
/// (MCS3+) smear (bad EVM) unless backed off. `calibrate_tx_power` now writes a
/// per-rate **backoff** into the `0x3a00` TXAGC diff table (MCS3 −6, MCS4/5
/// −11, MCS6/7 −14) so each rate transmits in its linear region while MCS0–2
/// keep full power — the mechanism the stock driver gets from DPK. With backoff
/// in place this ceiling is the highest rate *confirmed on-air*. Once the
/// on-air TX-power gate was found — the BB NCTL TX-power push
/// (`set_txagc_to_hw`, NCTL reg 0x38 via the 0x1700/0x1704 port), which the
/// abbreviated init skipped and which had left TX ~50 dB low — the link reaches
/// full power (−22 dBm, kernel-level). A full-power MCS sweep vs the OPi
/// receiver then decodes the **entire 11n single-stream range**: MCS2 95%,
/// MCS4–6 ~95–97%, **MCS7 (64-QAM 5/6) 66%**. So the ceiling is the 11n max, 7.
/// (Higher needs 2-stream / VHT / wider bandwidth — separate work.)
///
/// `set_txagc_to_hw`: crate::LibUsbRtl88xxBackend::set_txagc_to_hw
pub const MAX_RELIABLE_MCS: u8 = 7;

/// Map an observed RSSI (dBm) to an 802.11n single-stream 20 MHz MCS index,
/// capped at [`MAX_RELIABLE_MCS`].
///
/// A monotone heuristic over typical 11n receiver-sensitivity thresholds: the
/// stronger the signal we hear from the neighbourhood, the more aggressive the
/// rate we inject at. This is the kernel of [`McsPolicy::Adaptive`]; the
/// "MCS climbs as nodes approach" behaviour is validated on hardware, but the
/// mapping itself is unit-tested here. The ceiling reflects the *verified*
/// reliable rate, not the 11n maximum — see [`MAX_RELIABLE_MCS`].
pub fn mcs_for_rssi(rssi_dbm: i8) -> u8 {
    let raw = match rssi_dbm {
        r if r >= -55 => 7,
        r if r >= -62 => 6,
        r if r >= -68 => 5,
        r if r >= -72 => 4,
        r if r >= -76 => 3,
        r if r >= -80 => 2,
        r if r >= -84 => 1,
        _ => 0,
    };
    raw.min(MAX_RELIABLE_MCS)
}

/// PHY data rate (bits/s) of an 802.11n single-stream 20 MHz MCS, long guard
/// interval — the per-MCS modulation/coding rate table. Used to surface the
/// link's achievable rate as a cross-layer signal (`LinkSignals.observed_tput_bps`)
/// so measured strategies can prefer faster neighbours. This is the PHY rate,
/// an upper bound on goodput, not a measured throughput.
pub fn mcs_phy_rate_bps(mcs_index: u8) -> u32 {
    match mcs_index {
        0 => 6_500_000,
        1 => 13_000_000,
        2 => 19_500_000,
        3 => 26_000_000,
        4 => 39_000_000,
        5 => 52_000_000,
        6 => 58_500_000,
        _ => 65_000_000, // MCS7 (and any out-of-range, clamped to the top rate)
    }
}

/// One frame as injected: the (LP-framed) NDN payload, the PHY rate, and the
/// 802.11 destination/source addresses. For a name-grouped face `dst`/`src` are
/// name-derived (`ndn_frame_io::frame::name_group_mac`/`name_group_uni`); otherwise
/// broadcast + the default source. Never a host MAC.
#[derive(Clone, Debug)]
pub struct InjectFrame {
    pub payload: Bytes,
    /// What this transmit should achieve — a bearer-agnostic [`TxIntent`]. The
    /// backend resolves it to its own PHY rate ([`McsDescriptor::for_intent`] for
    /// 802.11); the seam itself no longer names an MCS.
    pub tx: TxIntent,
    /// 802.11 destination (`addr1`/`addr3`): a name-group MAC or broadcast.
    pub dst: [u8; 6],
    /// 802.11 source (`addr2`): name-derived, or [`DEFAULT_SRC`].
    pub src: [u8; 6],
}

impl InjectFrame {
    /// A broadcast frame from the default source — the addressing-agnostic case
    /// (every monitor receiver keeps it). Grouped faces fill `dst`/`src` instead.
    pub fn broadcast(payload: Bytes, tx: TxIntent) -> Self {
        Self {
            payload,
            tx,
            dst: BROADCAST,
            src: DEFAULT_SRC,
        }
    }
}

/// One frame as captured: the NDN payload recovered from the on-air frame, plus
/// what the headers told us. The NDN layer forwards on the *name* inside
/// `payload`; the rest are link-layer hints, never the addressing.
#[derive(Clone, Debug)]
pub struct CapturedFrame {
    pub payload: Bytes,
    /// Source address (`addr2`) — name-derived or the default source, never a
    /// host MAC. Reported upward as the (host-free) reassembly stream key.
    pub addr: Option<[u8; 6]>,
    /// Destination group (`addr1`) — the name-group MAC or broadcast. Used for
    /// the receive-side name pre-filter.
    pub group: Option<[u8; 6]>,
    /// Per-frame RSSI in dBm from radiotap, if measured.
    pub rssi_dbm: Option<i8>,
    /// MCS index the frame was received at, if radiotap reported it.
    pub mcs_index: Option<u8>,
}

/// The radio behind a `MonitorWifiFace`: inject a frame at a chosen rate, and
/// yield captured frames. `recv_frame` has a single consumer (the face's reader
/// task); `inject` may be called concurrently and must synchronise internally.
#[async_trait]
pub trait FrameIo: Send + Sync + 'static {
    /// Transmit `frame.payload` on the medium for `frame.tx`. Fire-and-forget,
    /// unacknowledged — like all broadcast injection.
    async fn inject(&self, frame: InjectFrame) -> Result<(), FaceError>;

    /// Transmit a batch of frames, bundling runs that share dst/src/tx into one
    /// **A-MSDU** (link-layer bundling — one PHY preamble for many NDN packets,
    /// no Block-Ack needed) where the backend supports it. The default sends each
    /// individually; the RTL8812EU backend overrides this with A-MSDU. Used by
    /// the face-level batcher (`MonitorWifiFace::with_amsdu_batching`).
    async fn inject_batch(&self, frames: Vec<InjectFrame>) -> Result<(), FaceError> {
        for f in frames {
            self.inject(f).await?;
        }
        Ok(())
    }

    /// Await the next frame captured on the medium. A node never hears its own
    /// transmissions (half-duplex radio); the backend filters those.
    async fn recv_frame(&self) -> Result<CapturedFrame, FaceError>;
}

/// A WiFi radio: inject at an EXACT 802.11 rate, overriding intent
/// resolution. For fixed-rate benches and the adaptive/cognitive
/// MonitorWifiFace, which have already resolved a concrete McsDescriptor.
/// Non-WiFi backends implement only FrameIo.
#[async_trait]
pub trait WifiRadio: FrameIo {
    async fn inject_at(&self, frame: InjectFrame, mcs: McsDescriptor) -> Result<(), FaceError>;
}
