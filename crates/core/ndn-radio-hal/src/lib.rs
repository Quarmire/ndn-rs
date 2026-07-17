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

/// Re-exported link-timestamp vocabulary (from the named-time core). A backend
/// stamps a [`CapturedFrame`] with a [`LinkStamp`] carrying its clock domain and
/// honest precision; the generic time layer consumes it. See ADR 0007.
pub use ndn_time::{ClockDomainId, LatchPoint, LinkStamp, RadioClockKind, RadioTimeSource};

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
    };
    /// A widely-decodable balance broadcast.
    pub const CONSERVATIVE: TxIntent = TxIntent {
        reliability: Reliability::Balanced,
        reach: Reach::Broadcast,
    };
    /// Broadcast at a stated reliability.
    pub const fn broadcast(reliability: Reliability) -> Self {
        TxIntent {
            reliability,
            reach: Reach::Broadcast,
        }
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
    /// `vht_cap`, 802.11ac. Maps the reliability axis: `MostRobust` → base rate
    /// with STBC + LDPC diversity (ideal for un-ACKed broadcast), `Balanced` → a
    /// conservative mid rate, `Throughput` → the top validated rate + short GI.
    /// This is the 802.11 mapping of the transmit intent; another bearer maps it
    /// differently. An exact WiFi rate (fixed-rate benches, the cognitive face)
    /// travels the [`WifiRadio::inject_at`] path instead — not on the seam.
    pub fn for_intent(intent: &TxIntent, max_index: u8, vht_cap: bool) -> McsDescriptor {
        match intent.reliability {
            Reliability::MostRobust => McsDescriptor::ht(0).with_stbc().with_ldpc(),
            Reliability::Balanced => McsDescriptor::CONSERVATIVE,
            Reliability::Throughput => {
                let idx = max_index.min(MAX_RELIABLE_MCS);
                let base = if vht_cap {
                    McsDescriptor::vht(idx)
                } else {
                    McsDescriptor::ht(idx)
                };
                McsDescriptor {
                    short_gi: true,
                    ..base
                }
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
    /// Hardware receive timestamp, if the backend latched one (radiotap TSFT on
    /// a monitor NIC, a NIC PHC, an on-chip counter). Carries its clock domain
    /// and honest precision; `None` when the backend has no hardware stamp (a
    /// software-timestamped or loopback frame). This is the named-time "Cut 1"
    /// seam — the input to time-transfer measurement.
    pub stamp: Option<LinkStamp>,
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
    /// Inject one frame at an exact 802.11 rate.
    async fn inject_at(&self, frame: InjectFrame, mcs: McsDescriptor) -> Result<(), FaceError>;

    /// Inject a batch, each frame with its own exact rate — the WiFi counterpart
    /// of [`FrameIo::inject_batch`]. Backends that A-MSDU-bundle (the RTL8812EU)
    /// override this to group runs that share dst/src/rate into one aggregate;
    /// the default sends each via [`inject_at`](WifiRadio::inject_at).
    async fn inject_batch_at(
        &self,
        frames: Vec<(InjectFrame, McsDescriptor)>,
    ) -> Result<(), FaceError> {
        for (f, mcs) in frames {
            self.inject_at(f, mcs).await?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Radio control plane: the stateful-knob seam + the capability descriptor.
// ---------------------------------------------------------------------------

/// Channel bandwidth, uniform across backends. The numeric `code()` matches the
/// cognition plane's `TxParams.bw` / `RadioCapability.max_bw` encoding and the
/// RTL `ChannelBw` discriminants: `0=20, 1=40, 2=80, 3=10MHz, 4=5MHz`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Bandwidth {
    /// 20 MHz (standard).
    #[default]
    Bw20,
    /// 40 MHz.
    Bw40,
    /// 80 MHz (VHT).
    Bw80,
    /// 10 MHz narrowband (non-standard; longer range / lower rate).
    Nb10,
    /// 5 MHz narrowband.
    Nb5,
}

impl Bandwidth {
    /// Numeric code shared with `TxParams.bw` / `RadioCapability.max_bw`.
    pub fn code(self) -> u8 {
        match self {
            Bandwidth::Bw20 => 0,
            Bandwidth::Bw40 => 1,
            Bandwidth::Bw80 => 2,
            Bandwidth::Nb10 => 3,
            Bandwidth::Nb5 => 4,
        }
    }

    /// Inverse of [`code`](Self::code); unknown codes fall back to 20 MHz.
    pub fn from_code(c: u8) -> Self {
        match c {
            1 => Bandwidth::Bw40,
            2 => Bandwidth::Bw80,
            3 => Bandwidth::Nb10,
            4 => Bandwidth::Nb5,
            _ => Bandwidth::Bw20,
        }
    }
}

/// The uniform stateful-knob surface every userspace radio backend exposes to
/// the named-radio control plane. Implementors are wrapped behind a
/// `RadioActuators` adapter (see `control.rs`) so a single generic actuator can
/// drive any radio.
///
/// Only [`set_channel`](Self::set_channel) is required — a radio that cannot at
/// least tune is not useful. The remaining knobs default to no-ops so a port can
/// land RX/TX first and grow contention/power control later. Per-frame
/// rate/STBC/LDPC/short-GI/NSS is NOT here; that travels with each
/// [`InjectFrame`]`.mcs` on the data plane.
pub trait RadioKnobs: Send + Sync {
    /// Tune to `channel` at bandwidth `bw`. Returns an error if the radio cannot
    /// reach that channel/width (e.g. a port that has only captured one channel).
    fn set_channel(&self, channel: u8, bw: Bandwidth) -> Result<(), FaceError>;

    /// Set the TXAGC reference index (a back-off below the regulatory ceiling;
    /// never used to exceed it). Default: no-op (radio runs at its init power).
    fn set_tx_power(&self, _idx: u32) -> Result<(), FaceError> {
        Ok(())
    }

    /// Enable cyclic-shift diversity on the second chain (1-stream robustness via
    /// antenna diversity). Default: no-op (not supported / single-chain).
    fn set_tx_csd(&self, _on: bool) -> Result<(), FaceError> {
        Ok(())
    }

    /// Ignore EDCCA / listen-before-talk so TX proceeds under channel contention. Default: no-op.
    /// (A LoRa radio maps this to its LBT toggle.)
    fn set_edcca_ignore(&self, _on: bool) -> Result<(), FaceError> {
        Ok(())
    }

    /// Set the LoRa **spreading factor** (7–12) — the sub-GHz reach/rate dial, the direct analogue
    /// of Wi-Fi MCS: each step up trades throughput for link budget (≈ doubling airtime, ≈ +2.5 dB
    /// sensitivity). No-op default; only a [`RadioKind::Lora`] radio acts on it. Cognition drives
    /// this the way it drives MCS — down for close/bulk, up for far/urgent.
    fn set_spreading_factor(&self, _sf: u8) -> Result<(), FaceError> {
        Ok(())
    }

    /// Set the LoRa **coding rate** (`1`=4/5 … `4`=4/8) — a robustness/FEC dial (more coding = more
    /// resilience to interference, at the cost of airtime). No-op default.
    fn set_coding_rate(&self, _cr: u8) -> Result<(), FaceError> {
        Ok(())
    }

    /// Set the LoRa channel **bandwidth in kHz** (125 / 250 / 500) — a rate/range axis orthogonal to
    /// spreading factor (wider = faster but noisier / shorter). No-op default.
    fn set_bandwidth_khz(&self, _khz: u32) -> Result<(), FaceError> {
        Ok(())
    }

    /// The transmit-timing discipline this radio can *promise* (named-time Cut 2) — the capability
    /// beacon slots / the URLLC lane / TSCH-by-name read to know how tightly airtime is bounded.
    /// Default [`TxDiscipline::BestEffort`]; a radio that can suppress CSMA backoff on owned
    /// spectrum (EDCCA-ignore + single-frame injection) reports [`TxDiscipline::PromptBounded`].
    fn tx_discipline(&self) -> TxDiscipline {
        TxDiscipline::BestEffort
    }
}

/// What the transmit path can *promise* about when a frame leaves the antenna — a named-time
/// Cut-2 capability the protocol reads, never a chipset register. A beacon slot or the URLLC lane
/// asks for a discipline and reads its bound; *how* a backend delivers it (EDCCA-ignore on owned
/// spectrum, a hardware scheduled-TX engine) stays below this seam, exactly as an MCS stays below
/// [`TxIntent`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxDiscipline {
    /// No timing promise — kernel Wi-Fi, or any congested medium where CSMA backoff is unbounded.
    BestEffort,
    /// The frame leaves within `max_delay_ns` of the request — what EDCCA-ignore + single-MPDU
    /// injection deliver on owned spectrum (bounded contention).
    PromptBounded {
        /// Upper bound, ns, from request to on-air.
        max_delay_ns: u64,
    },
    /// The frame leaves at a *scheduled instant*, accurate to `granularity_ns` — a PIO/optical face
    /// or a future scheduled-TX radio (the `LatchPoint::ScheduledTx` class).
    ScheduledAt {
        /// Scheduling granularity, ns.
        granularity_ns: u64,
    },
}

/// A radio's named-time surface: which link clocks it exposes and how to read the readable
/// ones. Implemented per backend so `ndn-time` can, uniformly across heterogeneous radios,
/// learn the domain RX [`LinkStamp`]s live in, that clock's honest quality, and compute a
/// frame's age via a read-now clock — without special-casing any backend.
///
/// Grounded in hardware reality: a radio may expose several link clocks of different quality
/// (an always-on free-run per-frame RX stamp, a gated/beacon-resynced port TSF, a host
/// software stamp). A backend enumerates them via [`RadioTimeSource`] rather than pretending
/// to have one canonical TSF. Default impl reports nothing — a port that has not wired up its
/// timekeeping yet is honest about having none.
pub trait RadioTime: Send + Sync {
    /// The link clocks this radio exposes, best-first (the per-frame RX-stamp clock first).
    fn time_sources(&self) -> Vec<RadioTimeSource> {
        Vec::new()
    }

    /// Read the current value of a `read_now` clock, selected by `domain`, if this radio has
    /// one. Returns `Ok(None)` when the domain is unknown or the radio has only per-frame
    /// stamps (no readable clock). The value is in that domain's raw ticks.
    fn read_clock(&self, _domain: ClockDomainId) -> Result<Option<u64>, FaceError> {
        Ok(None)
    }
}

/// A face's named-time service profile (design §15) — **trait-derived, not a static table**.
///
/// Rather than a per-driver lookup of "what can this radio do for time," the profile is
/// *computed* from the capability traits a backend already implements: its [`RadioTime`] link
/// clocks and its [`RadioTime`]/[`RadioKnobs::tx_discipline`] transmit discipline. A new radio
/// gains a correct time profile the moment it reports its clocks and discipline — nothing here
/// needs editing. The timekeeper reads this to decide what a face may contribute: whether it can
/// source common-view (needs a shared-counter RX stamp), how tightly it stamps arrivals, and how
/// bounded its transmit timing is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FaceTimeProfile {
    /// The best (tightest, best-first) link clock the face exposes, or `None` if it stamps
    /// nothing. A per-frame [`RadioClockKind::FreeRunRxStamp`] beats a gated [`RadioClockKind::PortTsf`]
    /// beats a [`RadioClockKind::HostRecv`] software stamp.
    pub best_clock: Option<RadioClockKind>,
    /// The precision (ns) of that best clock's stamps, or `None` if the face stamps nothing. This
    /// is the floor on any offset uncertainty the face can produce (design §9 self-consistency).
    pub stamp_precision_ns: Option<u32>,
    /// The transmit-timing discipline the face can promise (Cut 2).
    pub tx_discipline: TxDiscipline,
    /// Whether the face can contribute common-view observations: it needs a per-frame RX stamp on a
    /// stable shared counter (a [`RadioClockKind::FreeRunRxStamp`]), so two receivers' stamps of one
    /// event are differenced meaningfully. A host-recv-only face cannot (its stamp jitter swamps the
    /// inter-receiver offset).
    pub can_common_view: bool,
}

impl FaceTimeProfile {
    /// Derive the profile from a radio's time surface and transmit discipline (design §15). Pass
    /// the backend's own [`RadioTime`] and the [`TxDiscipline`] it promises. `time_sources()` is
    /// best-first, so the head is the best clock.
    pub fn derive(time: &dyn RadioTime, tx_discipline: TxDiscipline) -> Self {
        let sources = time.time_sources();
        let best = sources.first();
        let best_clock = best.map(|s| s.kind);
        let stamp_precision_ns = best.map(|s| s.precision_ns);
        // Common-view needs a per-frame RX stamp on a shared free-running counter; a gated TSF or a
        // host stamp does not qualify (design §M3 / measure::common_view).
        let can_common_view = sources
            .iter()
            .any(|s| s.kind == RadioClockKind::FreeRunRxStamp);
        Self {
            best_clock,
            stamp_precision_ns,
            tx_discipline,
            can_common_view,
        }
    }
}

/// A radio's static capability profile — band, rates, channels, duty cycle, etc. Implemented
/// per backend so the heterogeneous-radio selection layer reasons about every radio uniformly
/// (which one to pick for a given reach/rate/airtime) instead of hard-coding per-driver
/// knowledge. The companion to [`RadioTime`] (dynamic clocks) on the static-capability axis.
pub trait RadioProfile: Send + Sync {
    /// This radio's capability. Every radio declares one — there is no sensible default.
    fn capability(&self) -> RadioCapability;
}

/// RF band — the coarse range/penetration axis used for heterogeneous radio
/// selection (sub-GHz reaches far / penetrates; 5/6 GHz is bulk; 60 GHz is dense).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Band {
    Sub1GHz,
    Band2_4GHz,
    Band5GHz,
    Band6GHz,
    Band60GHz,
}

impl Band {
    /// Relative range/penetration rank (higher = reaches further / penetrates more).
    pub fn range_rank(self) -> u8 {
        match self {
            Band::Sub1GHz => 4,
            Band::Band2_4GHz => 3,
            Band::Band5GHz => 2,
            Band::Band6GHz => 1,
            Band::Band60GHz => 0,
        }
    }
}

/// What kind of radio this is — selects the regime and whether it can transmit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RadioKind {
    /// Commodity Wi-Fi in monitor/injection mode (the load-bearing data radio).
    WifiMonitor,
    /// Sub-GHz long-range / low-rate (LoRa-class) — heterogeneous coordination/ambient.
    Lora,
    /// 802.11ah HaLow sub-GHz.
    WifiHaLow,
    /// Bluetooth LE broadcast face.
    Ble,
    /// Software-defined radio used **RX-only as a spectrum instrument** (the richest
    /// `SenseSource`: real PSD/occupancy, interference ID, DFS radar detection,
    /// a calibrated witness for our own TX). Not a data transmitter here — the
    /// SDR-as-modem arc stays the frontier.
    Sdr,
    Other,
}

/// Whether a radio can afford to listen continuously — the axis that selects the
/// rendezvous mode. A mains-powered monitor radio listens always; a battery
/// sub-GHz node duty-cycles. This is *not* an 802.11 concept: it is the
/// bearer-agnostic reason Discovery Windows exist (see `ndn-nan-core::rendezvous`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum TimingModel {
    /// Continuous RX — no wake schedule needed; the rendezvous mode can be null
    /// (always-on). Commodity Wi-Fi monitor radios, SDRs, mains-powered relays.
    #[default]
    AlwaysOn,
    /// Duty-cycled RX to save power — needs a windowed rendezvous (a NAN-style
    /// Discovery Window, a TSCH slotframe). Battery sub-GHz / IoT nodes.
    DutyCycled,
}

/// Whether a radio exports channel-state information to the host, and at what granularity — the
/// axis the named-time / sensing plane needs to know per port. Assessed on real hardware:
/// commodity Realtek Wi-Fi is [`None`](Self::None) — its only on-chip CSI is compressed 802.11
/// beamforming feedback (angles for TxBF on >=2-antenna parts, N/A on the 1x1 8733b), never a
/// host-visible H-matrix. Full per-subcarrier CSI needs a CSI-tool NIC (Atheros/Intel) or an SDR.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum CsiSupport {
    /// No host-visible channel state beyond the per-frame RSSI/MCS already on `CapturedFrame`.
    #[default]
    None,
    /// Coarse per-path channel quality recoverable from the RX phystatus (RSSI, CFO, EVM) — a
    /// sensing hint, not a full channel estimate.
    Coarse,
    /// Full per-subcarrier CSI (the H-matrix) — an SDR or a CSI-tool NIC.
    PerSubcarrier,
}

/// Per-radio capability descriptor — the single switch between homogeneous
/// (NDNPIPES: identical capabilities → channel assignment + spatial reuse) and
/// heterogeneous (NDN-CRAHNs: divergent capabilities → object→radio mapping by
/// fit) regimes. Generalizes the `LinkProfile` cost prior.
///
/// A radio's peak-rate ceiling, keyed by bearer — the static-capability peer of the actuator-side
/// `RateParams`. A consumer reads the rate/reach tradeoff through [`RadioCapability::rate_rank`]
/// (bearer-agnostic) and the Wi-Fi ceilings through the typed accessors; no bearer's rate model is
/// baked into the capability's fields (LoRa has no `max_mcs`, Wi-Fi no spreading factor).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RateCapability {
    /// No transmit-rate ceiling — an RX-only sensor, or a single-fixed-rate bearer.
    None,
    /// Wi-Fi 802.11: max MCS index, spatial streams, and channel-bandwidth code (0=20…4=5).
    Wifi { max_mcs: u8, max_nss: u8, max_bw: u8 },
    /// LoRa sub-GHz: the spreading-factor span (the reach↔rate range; lower SF = faster).
    Lora { min_sf: u8, max_sf: u8 },
}

/// Carries the bearer-specific rate ceiling ([`RateCapability`], read via [`rate_rank`] and the
/// typed accessors) **and** the bearer-agnostic operational axes a cognitive plane needs to place
/// work on a heterogeneous radio: its timing model, duty-cycle ceiling, on-air payload cap, and
/// duplex. Those are what let LoRa, an SDR, or a future PHY be *described* rather than special-cased.
///
/// [`rate_rank`]: RadioCapability::rate_rank
#[derive(Clone, Debug)]
pub struct RadioCapability {
    pub kind: RadioKind,
    /// The RF band(s) this radio can operate on — several parts are dual-band (2.4 + 5 GHz),
    /// so this is a set, not one band. Best-first for range is [`range_rank`](Self::range_rank).
    pub bands: Vec<Band>,
    /// Bearer-specific peak-rate ceiling. Read the rate/reach tradeoff via
    /// [`rate_rank`](Self::rate_rank); the Wi-Fi ceilings via [`max_mcs`](Self::max_mcs) /
    /// [`max_nss`](Self::max_nss) / [`max_bw`](Self::max_bw); the LoRa span via
    /// [`sf_range`](Self::sf_range).
    pub rate: RateCapability,
    /// Channels this radio may use.
    pub channels: Vec<u8>,
    /// Max TX-power index (chip TXAGC scale) = the *calibrated/regulatory ceiling*.
    /// The power knob backs off below this; it is never exceeded. This is also a
    /// capability item peers can learn (reach class).
    pub max_tx_power: u8,
    /// Can retune quickly (fast FHSS-capable).
    pub agile: bool,
    /// RX-only — participates in sensing/reception, never selected for TX (e.g. SDR
    /// sensor). Such radios still contribute to macrodiversity reception pooling.
    pub rx_only: bool,
    /// Whether the radio listens continuously or duty-cycles — selects the
    /// rendezvous mode (always-on vs a windowed schedule).
    pub timing: TimingModel,
    /// Regulatory / policy ceiling on the fraction of airtime this radio may use
    /// (`1.0` = unrestricted; LoRa sub-GHz is ~`0.01`). A broadcast rate planner
    /// must respect it.
    pub duty_cycle_max: f32,
    /// Largest on-air payload one frame carries (bytes) — the fragmentation MTU
    /// the link service targets (WiFi ~1500+, ESP-NOW 250, LoRa ~256).
    pub max_payload: usize,
    /// Half-duplex: cannot receive while transmitting (a node never hears its own
    /// TX). True for essentially every single-antenna packet radio.
    pub half_duplex: bool,
    /// Whether this radio exports channel-state information to the host (assessed per port).
    pub csi: CsiSupport,
}

impl RadioCapability {
    /// The best (furthest-reaching / most-penetrating) band-rank this radio can use — the max
    /// of [`Band::range_rank`] over its [`bands`](Self::bands). Used by the heterogeneous-radio
    /// selection layer to rank a dual-band radio by its most capable band. 0 if bandless.
    pub fn range_rank(&self) -> u8 {
        self.bands.iter().map(|b| b.range_rank()).max().unwrap_or(0)
    }

    /// Bearer-agnostic peak-throughput rank in `[0, 1]` — the *rate* axis of the reach/rate
    /// heterogeneous-selection tradeoff, comparable across Wi-Fi, LoRa, and future PHYs. Wi-Fi
    /// scales with MCS + spatial streams; LoRa is orders of magnitude slower so it lands near zero
    /// (a lower min SF nudges it up); a rate-less radio (SDR sensor) is zero.
    pub fn rate_rank(&self) -> f32 {
        match self.rate {
            RateCapability::Wifi {
                max_mcs, max_nss, ..
            } => (max_mcs as f32 / 9.0 + (max_nss.saturating_sub(1)) as f32 / 3.0) / 2.0,
            RateCapability::Lora { min_sf, .. } => (12u8.saturating_sub(min_sf)) as f32 / 100.0,
            RateCapability::None => 0.0,
        }
    }

    /// Wi-Fi max MCS index (0 for a non-Wi-Fi radio).
    pub fn max_mcs(&self) -> u8 {
        match self.rate {
            RateCapability::Wifi { max_mcs, .. } => max_mcs,
            _ => 0,
        }
    }

    /// Wi-Fi max spatial streams (1 for a non-Wi-Fi radio).
    pub fn max_nss(&self) -> u8 {
        match self.rate {
            RateCapability::Wifi { max_nss, .. } => max_nss,
            _ => 1,
        }
    }

    /// Wi-Fi max channel-bandwidth code (0 = 20 MHz, for a non-Wi-Fi radio too).
    pub fn max_bw(&self) -> u8 {
        match self.rate {
            RateCapability::Wifi { max_bw, .. } => max_bw,
            _ => 0,
        }
    }

    /// LoRa spreading-factor span `(min, max)`, or `None` for a non-LoRa radio.
    pub fn sf_range(&self) -> Option<(u8, u8)> {
        match self.rate {
            RateCapability::Lora { min_sf, max_sf } => Some((min_sf, max_sf)),
            _ => None,
        }
    }

    /// A commodity 5 GHz Wi-Fi monitor radio (our RTL8812EU/8822E data radio).
    pub fn wifi_monitor_5ghz(channels: Vec<u8>) -> Self {
        Self {
            kind: RadioKind::WifiMonitor,
            bands: vec![Band::Band5GHz],
            rate: RateCapability::Wifi {
                max_mcs: 9,
                max_nss: 2,
                max_bw: 2,
            },
            channels,
            max_tx_power: 63,
            agile: true,
            rx_only: false,
            timing: TimingModel::AlwaysOn,
            duty_cycle_max: 1.0,
            max_payload: 1500,
            half_duplex: true,
            csi: CsiSupport::None,
        }
    }

    /// A 2.4 GHz Wi-Fi monitor radio — our MT7612U (mt76x2u, 2x2 11n on 2.4 GHz).
    /// TX-capable in principle; today only channel 6 / 20 MHz is captured (the
    /// `RadioKnobs` impl errors on other channels), so callers usually pass
    /// `channels = vec![6]` and `max_bw` stays 0 until wider widths are ported.
    pub fn wifi_monitor_2ghz(channels: Vec<u8>) -> Self {
        Self {
            kind: RadioKind::WifiMonitor,
            bands: vec![Band::Band2_4GHz],
            rate: RateCapability::Wifi {
                max_mcs: 7,
                max_nss: 2,
                max_bw: 0,
            },
            channels,
            max_tx_power: 63,
            agile: true,
            rx_only: false,
            timing: TimingModel::AlwaysOn,
            duty_cycle_max: 1.0,
            max_payload: 1500,
            half_duplex: true,
            csi: CsiSupport::None,
        }
    }

    /// A single-chain (1x1) 5 GHz Wi-Fi monitor radio — the RTL8731BU (halmac_87xx, 1x1 11ac).
    /// One spatial stream, so `max_nss = 1`; at 20 MHz the top reliable VHT-1SS rate is MCS8
    /// (MCS9 needs >=40 MHz). (This part is dual-band; the single `band` field reports its
    /// primary 5 GHz use — a known limitation of the one-band capability model.)
    pub fn wifi_monitor_5ghz_1ss(channels: Vec<u8>) -> Self {
        Self {
            rate: RateCapability::Wifi {
                max_mcs: 8,
                max_nss: 1,
                max_bw: 2,
            },
            ..Self::wifi_monitor_5ghz(channels)
        }
    }

    /// A single-chain (1x1) 2.4 GHz Wi-Fi monitor radio — e.g. the RTL8720DN (BW16) serial
    /// board: 1 stream, 11n MCS0-7, 20 MHz.
    pub fn wifi_monitor_2ghz_1ss(channels: Vec<u8>) -> Self {
        Self {
            rate: RateCapability::Wifi {
                max_mcs: 7,
                max_nss: 1,
                max_bw: 0,
            },
            ..Self::wifi_monitor_2ghz(channels)
        }
    }

    /// A Wi-Fi HaLow (802.11ah / S1G) monitor radio — our Newracom NRC7292 on
    /// the sub-GHz band. Same 802.11-family framing and monitor-injection model
    /// as the 2.4/5 GHz backends (so it pools uniformly), but on the ~900 MHz S1G
    /// PHY: narrow channels, single stream, and a longer link budget for range.
    /// `channels` are the driver's US alias numbers (e.g. 161 = 925 MHz). The
    /// NRC7292 supports S1G MCS 0–10; rate is set by the on-chip MAC, so the
    /// injection radiotap names no MCS ([`FrameFormat::RawNdnS1g`]).
    pub fn wifi_halow_s1g(channels: Vec<u8>) -> Self {
        Self {
            kind: RadioKind::WifiMonitor,
            bands: vec![Band::Sub1GHz],
            rate: RateCapability::Wifi {
                max_mcs: 10, // S1G MCS0–10 (MCS10 = 1 MHz-only rep-coded BPSK)
                max_nss: 1,
                max_bw: 0, // 1/2/4 MHz S1G widths; we run the base 1 MHz-equiv slot
            },
            channels,
            max_tx_power: 63,
            agile: true,
            rx_only: false,
            // S1G is a licence-exempt sub-GHz band but, unlike the LoRa ISM path,
            // 802.11ah uses CSMA/CA (listen-before-talk), not a hard duty cycle.
            timing: TimingModel::AlwaysOn,
            duty_cycle_max: 1.0,
            max_payload: 1500,
            half_duplex: true,
            csi: CsiSupport::None,
        }
    }

    /// A sub-GHz LoRa-class radio (long range, low rate).
    pub fn lora(channels: Vec<u8>) -> Self {
        Self {
            kind: RadioKind::Lora,
            bands: vec![Band::Sub1GHz],
            // SX126x spreading-factor span 7–12 (the reach↔rate range).
            rate: RateCapability::Lora {
                min_sf: 7,
                max_sf: 12,
            },
            channels,
            max_tx_power: 63,
            agile: false,
            rx_only: false,
            // Sub-GHz is duty-cycle-limited (~1%) and needs a windowed rendezvous;
            // tiny frames, half-duplex.
            timing: TimingModel::DutyCycled,
            duty_cycle_max: 0.01,
            max_payload: 256,
            half_duplex: true,
            csi: CsiSupport::None,
        }
    }

    /// An RX-only SDR spectrum sensor.
    pub fn sdr_sensor(channels: Vec<u8>) -> Self {
        Self {
            kind: RadioKind::Sdr,
            bands: vec![Band::Band5GHz],
            rate: RateCapability::None, // RX-only instrument — no transmit rate
            channels,
            max_tx_power: 0,
            agile: true,
            rx_only: true,
            // A spectrum instrument: always listening, never transmits.
            timing: TimingModel::AlwaysOn,
            duty_cycle_max: 1.0,
            max_payload: 0,
            half_duplex: false,
            csi: CsiSupport::PerSubcarrier,
        }
    }
}
