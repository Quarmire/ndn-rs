# TODO — Unimplemented Features

Tracked stubs, placeholders, and deferred work across the codebase.

---

## Face implementations (all stub — recv/send return `FaceError::Closed`)

- [x] **NamedEtherFace** — `ndn-faces/src/l2/ether.rs` (Linux), `ether_macos.rs` (macOS), `ether_windows.rs` (Windows)
      Linux: AF_PACKET + SOCK_DGRAM with TPACKET_V2 mmap ring buffers (RX + TX).
      macOS: PF_NDRV raw Ethernet via `NdrvSocket`; source-MAC filtering in software.
      Windows: Npcap via `PcapSocket`; background recv/send threads bridge to Tokio.
- [ ] **WfbFace** — `ndn-faces/src/l2/wfb.rs`
      Unidirectional 802.11 monitor-mode injection via wfb-ng.
      Tx recv parks with `pending()`; Rx recv/send stub. **(v0.2.0)**
- [ ] **BleFace** — `ndn-faces/src/l2/bluetooth.rs`
      Full GATT server implementation (NDNts `@ndn/web-bluetooth-transport` protocol).
      Protocol spec and UUIDs are documented in the stub; requires a stable async
      BLE GATT crate (candidates: `bluer`, `btleplug`). **(v0.2.0)**
- [x] **SerialFace** — `ndn-faces/src/serial/serial.rs`
      UART/LoRa/RS-485 with COBS framing via `tokio-serial`. Functional.

## Engine pipeline

- [x] **NACK handling** — `ndn-engine/src/dispatcher.rs`
      Inbound nack pipeline (PIT out-record lookup → strategy `on_nack` → retry
      or propagate). Outbound nack encoding via `encode_nack` and dispatch to
      incoming face. `Action::Nack` now carries `PacketContext`.
- [x] **ForwardAfter delay scheduling** — `ndn-engine/src/stages/strategy.rs`
      Spawns a Tokio timer; re-checks PIT before delayed send to avoid
      forwarding satisfied/expired Interests.

## Compute face

- [ ] **ComputeFace::send dispatch** — `ndn-compute/src/compute_face.rs:37`
      `// TODO: decode Interest, dispatch to registry, inject Data`
- [ ] **Pipeline sender wiring** — `ndn-compute/src/compute_face.rs:16`
      `// TODO: wire to pipeline mpsc channel`

## Security

- [x] **TLV cert encoding** — `ndn-security/src/manager.rs`
      `certify()` encodes a full NDN certificate Data packet (Name + MetaInfo
      + Content with public key & validity period + SignatureInfo with
      KeyLocator + SignatureValue) and signs it with the issuer's key.
- [x] **SecurityPolicy engine wiring** — `ndn-router/src/main.rs`
      `SecurityManager` passed into `EngineBuilder::security()` and stored in
      `EngineInner`. Accessible via `ForwarderEngine::security()`.

## CLI tools

- [x] **ndn-peek** — `crates/ndn-tools-core/src/peek.rs`
      Single and segmented fetch via `ForwarderClient`, ndn-cxx compatible naming.
- [x] **ndn-ping** — `crates/ndn-tools-core/src/ping.rs`
      Server and client modes; measures RTT, emits per-packet and summary events.
- [x] **ndn-put** — `crates/ndn-tools-core/src/put.rs`
      Publishes chunked objects with `ChunkedProducer`; ndn-cxx compatible segments.

## WebSocket TLS / ACME

- [ ] **WebSocket ACME certificate distribution** — targeted for v0.2.0.
      Automated certificate renewal via ACME (Let's Encrypt) with SVS-based
      fleet distribution. `websocket-tls` feature (v0.1.0) supports self-signed
      and user-supplied certs; ACME integration is deferred.

## Research

- [ ] **ChannelManager::switch** — `ndn-research/src/channel_manager.rs:27`
      Always returns `Err(NotImplemented)`. Needs nl80211 netlink.
