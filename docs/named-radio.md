# Named-data radio (monitor-mode WiFi) — *extension*

> **Non-standard extension.** Nothing here is an NDN community spec. It is a
> pragmatic bearer that carries spec NDN (Packet Format v0.3 + NDNLPv2) over a
> raw radio. `ndn-face-monitor-wifi` is `[package.metadata.scope] = "extension"`.

`ndn-face-monitor-wifi` (`crates/ndn-face-monitor-wifi`) is a **connectionless
802.11 monitor-mode injection face** — the data-centric reframing of wfb-ng,
with association, MAC addressing, and ARQ discarded. There is no destination
address: the **NDN name is the addressing**. Every monitor-mode receiver in
range hears every injected frame and evaluates it against its own PIT/FIB/CS.

It is **one bearer** in a much larger named-data-radio vision (see
[Status](#scope--status) below); it is the slice that runs on ~$60 of commodity
hardware today by riding the existing 802.11 OFDM PHY rather than a custom one.

## The two walls, and why monitor mode clears them

* **Legacy-rate wall.** Managed-mode multicast falls back to a basic rate
  (1/6/24 Mbps) because group-addressed frames get no ACKs, so the AP can't
  rate-adapt. That is a property of the *managed-mode MAC*, not the radio. A
  monitor-mode **injected** frame carries its own rate/MCS in the radiotap TX
  header — we pick the MCS per frame, near link rate, no AP floor.
* **No ARQ / no rate feedback.** What injection gives up, the architecture
  already replaces: loss → FEC/RLNC (`ndn-coding`) instead of retransmits;
  rate feedback → per-frame RSSI in the cross-layer signal store
  (`ndn-signals-core`) driving adaptive MCS, instead of a MAC back-channel.

## Layers

| Layer | Entry point | Use |
|-------|-------------|-----|
| transport | `MonitorWifiFace` | a `Face` (`FaceKind::Wfb`, `AdHoc`); rides `LpLinkService` for NDNLPv2 fragmentation |
| backend | `RawFrameIo` | inject/recv raw frames — `AfPacketBackend` (Linux `SOCK_RAW`) or `LoopbackMonitorBus` (CI) |
| framing | `frame::build` / `frame::parse` | platform-neutral `radiotap ++ 802.11 ++ body` per `FrameFormat` |
| rate | `radiotap::build_tx_header` / `build_tx_legacy` | per-frame MCS (defeats the legacy wall) or legacy rate |
| adapt | `McsPolicy` / `mcs_for_rssi` | RSSI-driven MCS selection from observed signal |

`FrameFormat` multiplexes wire formats on one monitor interface:
`RawNdn { ethertype }` (our peers), `EspNow { oui }` (ESP32 interop), and the
reserved `Wfb` / `HaLowVendorAction` variants. All on-air (de)framing lives in
the platform-neutral `frame.rs`, so every format is unit-tested off-target;
only the socket I/O is Linux.

```rust
use ndn_face_monitor_wifi::{AfPacketBackend, FrameFormat, MonitorWifiFace};
use ndn_transport::FaceId;
use std::sync::Arc;

// Linux, CAP_NET_RAW, interface already in monitor mode.
let backend = Arc::new(AfPacketBackend::new("wlan0", FrameFormat::default())?);
let face = MonitorWifiFace::new(FaceId(1), backend)
    .with_adaptive_mcs()       // pick MCS from observed RSSI
    .into_face();              // pairs LpLinkService for fragmentation
```

## ESP-NOW interop

`FrameFormat::EspNow` builds/parses the ESP-NOW vendor-action frame (802.11
Action, category `0x7f`, OUI `18:fe:34`, element type `0x04`, version `0x02`),
so a $5 ESP32 running stock `esp-wifi` ESP-NOW is a named-data peer. The
companion firmware is the `ndn-espnow` project (no_std esp-hal + esp-radio).
ESP-NOW bodies are ≤250 B, so an ESP-NOW face sets a small MTU.

## Hardware validation

Proven over the air on two Orange Pi 5 Pro + RTL8812EU (svpcom `8812eu`) and an
ESP32-S3:

* **Rate wall (Phase 0):** injected MCS0/3/7 captured at exactly the requested
  index — the wall is a managed-mode artifact (`testbed/bench/wifi_inject_rate.sh`).
* **Round-trip (Phase 1):** real Interest/Data over the air with NDNLPv2
  fragment reassembly (`examples/monitor_roundtrip.rs`).
* **FEC (Phase 4):** K-of-N recovery (`ndn-coding` engine-free codec) hit **100%**
  delivery at object sizes where uncoded multi-fragment dropped to 37–60%.
* **ESP-NOW (Phase 3):** ESP32-S3 → dongle, NDN Interest over ESP-NOW, received
  and parsed. The reverse (dongle → ESP32) is gated on a 2.4 GHz-injection
  adapter — the RTL8812EU's svpcom driver injects on 5 GHz only.

## Scope & status

This face is the **monitor-mode-WiFi slice** of the named-data-radio vision in
`.claude/notes/named-radio/` and `.claude/notes/speculative-2026-05-20/`. The
vision is radio-agnostic: names should seed not just *which frame* but *which
spectrum, hop sequence, and modulation*. We built the part that rides 802.11's
existing PHY; the software-defined-PHY part is largely future work.

| Theme | Status |
|-------|--------|
| WiFi monitor-mode injection face | **built** (this crate) |
| Per-frame MCS / rate selection (defeats legacy wall) | **built** |
| RLNC/FEC over broadcast | **built** (`ndn-coding` core) |
| NDNLPv2 fragmentation/reassembly | **built** |
| RSSI cross-layer signals + adaptive MCS | **built** |
| ESP-NOW bearer + ESP32 peer | **built** (RX into dongle proven) |
| BLE advertising face | built (`ndn-face-ble-adv`) |
| WiFi Aware (NAN) face | built (`ndn-face-wifi-aware`) |
| CCLF forwarder election | built (`ndn-strategy-cclf`) |
| No-host-addressing / verify-on-decode doctrine | built (doctrine) |
| **Distributed diversity reception** (macrodiversity, swarm aggregator) | designed, **not built** (note 2026-05-24) |
| **Friend-forwarder** for sleepy/low-power nodes | designed, not built |
| Fragment-stream-key reassembly (bearer-keyed) | not built |
| **Name-seeded FHSS** + narrow-channel spectrum + demand widening | designed, **not built** — needs SDR |
| **Custom modulation** (GFSK/GMSK/CSS/DSSS) on SDR | designed, not built — needs SDR (AD9363/Zynq) |
| Time-sync + coordination-announcement (FHSS prerequisites) | designed, not built |
| HaLow (802.11ah) bearer | future — needs Morse Micro hardware |
| LoRa / SX1262 bearer | future — needs hardware |
| Userspace libusb backend (devourer) — non-Linux portability | future |
| Linux-VM intermediary for non-Linux hosts | future |
| ESP32 Tier B (raw NDN-ethertype 802.11, not ESP-NOW) | future |

The largest **software-buildable** gaps (no exotic hardware) are distributed
diversity reception (rides the FEC we already have), the friend-forwarder, and
the userspace driver backend. The largest **vision** gap is the software-defined
PHY (FHSS + modulation by name), which gates on SDR hardware and a DSP effort —
that is the part where a *name* tunes the actual radio, not just the frame.
