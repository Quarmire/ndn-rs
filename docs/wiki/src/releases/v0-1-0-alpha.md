# Release: 0.1.0-alpha

**Tagged:** 2026-04-06 · **Branch:** `main` · **[GitHub Release](https://github.com/Quarmire/ndn-rs/releases/tag/v0.1.0-alpha)**

---

This is the first tagged release of ndn-rs: a Named Data Networking forwarder stack written in Rust, built from scratch to prove that NDN's architecture maps cleanly onto Rust's ownership model and async runtime.

What started as "can Rust model NDN's pipeline better than C++ can?" turned into a complete forwarder stack, wire-format library, embedded forwarder, browser simulation, management layer, and discovery stack. This release tags all of that as a coherent baseline.

Everything in this release should be considered unstable. APIs will break. The `0.1.0` designation means "the stack works and interoperates with NFD," not "the API is stable for downstream crates."

---

## What This Release Contains

### The Forwarding Pipeline

The core insight driving ndn-rs is that NDN's forwarding pipeline is a data processing pipeline, not a class hierarchy. `PacketContext` is a value type passed through a fixed sequence of `PipelineStage` trait objects. Each stage returns an `Action` (`Continue`, `Send`, `Satisfy`, `Drop`, `Nack`) that drives dispatch. Returning `Continue` hands ownership of the context to the next stage — use-after-hand-off is a compile error, not a runtime bug.

The Interest pipeline: `TlvDecodeStage → CsLookupStage → PitCheckStage → StrategyStage → PacketDispatcher`

The Data pipeline: `TlvDecodeStage → PitMatchStage → ValidationStage → CsInsertStage → PacketDispatcher`

Dispatch is non-blocking throughout: each face has a bounded 512-slot send queue, so the pipeline runner is never stalled waiting for a slow TCP connection to drain. The fragment sieve runs single-threaded; per-packet tokio tasks run the full pipeline in parallel across cores.

### Wire-Format Fidelity

One of the non-negotiable constraints was bit-exact interoperability with ndnd and ndn-cxx. This required a detailed compliance audit against RFC 8569, NDN Packet Format v0.3, and NDNLPv2. The audit found 25 gaps — mostly in encoding widths, framing conventions, and obscure packet types — all of which are resolved in this release. Some highlights:

- `NonNegativeInteger` now uses minimal lengths (1/2/4/8 bytes per spec, not always 8).
- `DataBuilder::build()` omits MetaInfo when no freshness period is set. An absent MetaInfo means "no freshness constraint"; `FreshnessPeriod=0` means "immediately stale." These are not the same, and NFD treats them differently.
- Nack packets are NDNLPv2-framed (wrapped in `LpPacket`) rather than bare 0x0320 TLV, which NFD silently dropped.
- `ParametersSha256DigestComponent` is computed and validated, not just carried along.

The `InterestBuilder` and `DataBuilder` APIs expose this correctly without requiring callers to know the wire format. Signed Interests (NDN v0.3 §5.4) are fully supported, including auto-generated anti-replay nonce and timestamp fields.

### The Security Stack

NDN's security model is content-centric: data is secured at the object level, not the channel level. Every Data packet carries a signature; verification walks a certificate chain from the signing key to a trust anchor. This release implements the full chain:

`ValidationStage` sits between PitMatch and CsInsert in the Data pipeline. When a validator is configured, it checks the packet's signature against the trust schema, then walks the certificate chain via `Validator::validate_chain()`. If a certificate is missing from the cache, `CertFetcher` issues a side-channel Interest to fetch it — with deduplication, so ten simultaneous Data packets all needing the same certificate share one Interest.

The `SecurityProfile` enum (`Default`, `AcceptSigned`, `Disabled`, `Custom`) lets operators choose how strict validation is per deployment. `SecurityManager::auto_init()` generates an Ed25519 identity on first startup so nodes are always signed — "security by default" without per-node configuration ceremony.

Two interesting performance wins in the signing path: `Signer::sign_sync()` and `DataBuilder::sign_sync()` eliminate the `Box::pin` heap allocation that the async path required, saving ~1.2M allocations/sec at line rate on a signing benchmark. For deployments where asymmetric key distribution isn't needed, `HmacSha256Signer` is approximately 10× faster than Ed25519.

### Network Faces: Every Medium

The face layer abstracts the network medium behind a two-method trait:

```rust
trait Face: Send + Sync {
    async fn recv(&self) -> Result<Bytes>;
    async fn send(&self, pkt: Bytes) -> Result<()>;
}
```

This release implements that trait for more media than expected:

**UDP and TCP** — including an auto-created per-peer UDP face on listener sockets. A subtle bug: listener-created UDP faces were replying from an ephemeral port, not from port 6363. Peers expecting replies from the well-known port were silently dropping them. Fixed by having all listener-created UDP faces share the listener's socket via `Arc<UdpSocket>`.

**Raw Ethernet** — three platform implementations: Linux (`AF_PACKET` + TPACKET_V2 mmap rings for zero-copy I/O), macOS (`PF_NDRV` sockets with `NDRV_SETDMXSPEC` for EtherType filtering), and Windows (Npcap bridged via background threads). All use the IANA NDN Ethernet multicast group `01:00:5e:00:17:aa` and EtherType `0x8624`.

**WebSocket** — binary-frame WebSocket, compatible with NFD's WebSocket transport. Useful for browser clients.

**Serial / COBS** — UART, LoRa, RS-485 support via COBS framing. COBS encodes packets so `0x00` never appears in the payload, making it a reliable frame delimiter for resync after line noise.

**NDNLPv2 per-hop reliability** — unicast UDP faces now implement the NDNLPv2 reliability protocol (retransmit, Ack, adaptive RTO), eliminating the throughput instability that unrecovered UDP loss causes.

### SHM Local Faces

The zero-copy local face — `SpscFace` / `SpscHandle` — is the data plane between applications and the forwarder. Applications write to a shared-memory ring; the forwarder reads from it without copying. The ring is 256 slots; the wakeup mechanism uses a named FIFO wrapped in `AsyncFd`, which integrates directly into Tokio's epoll/kqueue loop with no blocking thread transitions.

This was more work than expected. The initial Linux implementation used futex syscalls, which looked correct but had a cross-process problem: `FUTEX_PRIVATE_FLAG` keys on virtual addresses and only works within a single process. SHM spans processes via physical pages, so the futex must use plain `FUTEX_WAIT` without the private flag. After that fix, Linux and macOS were converged on the same FIFO-based path for simplicity.

### Discovery

The discovery layer implements SWIM (Scalable Weakly-consistent Infection-style Membership) for link-layer peer discovery. Each node sends periodic hello Interests; missed hellos trigger direct probes; missed direct probes trigger K indirect probes via randomly chosen established neighbors. The result is a failure detector that converges quickly without flooding the network.

Hello packets use a spec-compliant TLV format (`HelloPayload` with `NODE-NAME`, `SERVED-PREFIX`, `CAPABILITIES`, `NEIGHBOR-DIFF` fields). The `NEIGHBOR-DIFF` field carries SWIM gossip piggybacked on every hello, so membership information disseminates for free.

Two higher-level discovery protocols layer on top: `EpidemicGossip` for pull-gossip over `/ndn/local/nd/gossip/`, and `SvsServiceDiscovery` for push notifications using the SVS sync protocol.

### Sync Protocols

`ndn-sync` provides two sync primitives:

**SVS (State Vector Sync)** — each node maintains a `(node-key → sequence-number)` state vector. When vectors differ, the holder of the higher sequence number knows the other side is behind and sends the missing data. Used by service discovery and the `Subscriber` API.

**PSync (Partial Sync via IBF)** — nodes exchange Invertible Bloom Filters representing their local data sets. Subtracting two IBFs yields the symmetric difference: what each side has that the other lacks. Useful for larger data sets where exchanging full state vectors would be expensive.

### Mobile Support (Android / iOS)

`ndn-mobile` packages the forwarder for Android and iOS. It runs in-process inside the app binary — no system daemon — using `InProcFace` channels (zero IPC overhead) for app traffic and standard UDP faces for LAN/WAN connectivity.

Key features: `MobileEngine::builder()` with mobile-tuned defaults (8 MB CS, single pipeline thread, full security validation); `with_udp_multicast` + `with_discovery` for LAN neighbor discovery; `suspend_network_faces` / `resume_network_faces` for battery-efficient app lifecycle; `bluetooth_face_from_parts` for wrapping a platform-supplied async stream with COBS framing; optional persistent CS via the `fjall` feature.

See the [Mobile Apps guide](../guides/mobile-apps.md).

### The Embedded Forwarder

`ndn-embedded` is a `#![no_std]` NDN forwarder for ARM Cortex-M, RISC-V, and ESP32. It shares only the TLV codec with the full stack; everything else is const-generic and stack-allocated. `Pit<N>` and `Fib<N>` size is fixed at compile time. The `Forwarder` is single-threaded; `run_one_tick()` purges expired PIT entries. No heap allocator required for the core.

This crate exists because several NDN use cases are inherently embedded: mesh radio nodes, IoT sensors, environmental monitoring. A full Tokio runtime is inappropriate for a device with 256 KB of RAM.

### WASM Browser Simulation

`ndn-wasm` brings the NDN forwarding pipeline to the browser. It's a standalone Rust reimplementation (not a port of `ndn-engine`) that compiles to `wasm32-unknown-unknown` with `wasm-pack`. The explorer uses it to drive animated pipeline traces, a multi-hop topology sandbox, and a TLV inspector.

See the [ndn-wasm deep-dive](../deep-dive/wasm-browser-simulation.md) for a detailed analysis of what it replicates faithfully (FIB trie, PIT, CS, all pipeline stages) and where it simplifies (signature validation is a flag, not cryptography).

### NFD Management Compatibility

The router speaks NFD's TLV management protocol: `ControlParameters` (TLV 0x68), `ControlResponse` (TLV 0x65), standard name conventions (`/localhost/nfd/<module>/<verb>`). The `ndn-ctl` CLI sends NFD-format commands; any tool that can talk to NFD can talk to ndn-rs.

---

## Design Decisions That Didn't Make the Cut

A few approaches were tried and reverted:

**Multiple pipeline runners** — the pipeline channel can be read by multiple tasks in parallel using `Arc<Mutex<Receiver>>`. This was prototyped and benchmarked. Result: 2–4× *slower* than a single runner, because the bottleneck isn't draining the channel — it's the per-packet decode/PIT/strategy work, which already runs in parallel via `tokio::spawn`. Multiple runners just add contention.

**iceoryx2 shared-memory transport** — referenced in early config documentation. Never implemented; removed from all source files.

**SHM futex-based wakeup on Linux** — the `atomic-wait` crate initially provided futex wait/wake. Discovered that `FUTEX_PRIVATE_FLAG` doesn't work cross-process over SHM. Replaced with `libc::SYS_futex` without the private flag, then later replaced entirely with the same FIFO+AsyncFd approach used on macOS, eliminating the platform divergence.

---

## What's Next

The major gaps between this release and a stable 1.0:

- **ASF (Adaptive Smoothed RTT-based Forwarding) strategy** — the production-grade adaptive forwarding strategy is not yet implemented. BestRoute and Multicast are stable; ASF requires the measurements table, which exists, but the adaptation logic is not wired.
- **PSync network layer** — the IBF data structure is implemented; the Interest/Data exchange protocol that runs it over NDN faces is not.
- **Real engine in the browser** — `ndn-wasm` is a standalone simulation. Compiling the real `ndn-engine` to WASM requires replacing `DashMap` (thread-local state), removing `rt-multi-thread` from Tokio, and substituting `wasm_bindgen_futures::spawn_local` for `tokio::spawn`. None of these are fundamental; they're a few days of careful refactoring.
- **Bluetooth RFCOMM crate** — `BluetoothFace` (`ndn-mobile`) accepts any `AsyncRead + AsyncWrite` pair and works correctly with a platform-supplied stream. What's missing is a pure-Rust async crate for opening RFCOMM connections natively (without going through Android/iOS native APIs). Once such a crate exists, `ndn-mobile` can open Bluetooth connections directly from Rust rather than requiring a native bridge.
- **API stabilization** — essentially every public API has at least one rough edge. The 0.2.0 cycle will focus on stabilizing `ndn-app`, `ndn-packet`, and `ndn-transport` as the crates most likely to be used by downstream code.
