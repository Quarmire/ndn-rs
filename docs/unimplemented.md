# TODO — Unimplemented Features

Tracked stubs, placeholders, and deferred work across the codebase.

---

## Face implementations (all stub — recv/send return `FaceError::Closed`)

- [x] **NamedEtherFace** — `ndn-face-l2/src/ether.rs` (Linux), `ether_macos.rs` (macOS), `ether_windows.rs` (Windows)
      Linux: AF_PACKET + SOCK_DGRAM with TPACKET_V2 mmap ring buffers (RX + TX).
      macOS: PF_NDRV raw Ethernet via `NdrvSocket`; source-MAC filtering in software.
      Windows: Npcap via `PcapSocket`; background recv/send threads bridge to Tokio.
- [ ] **WfbFace** — `ndn-face-l2/src/wfb.rs`
      Unidirectional 802.11 monitor-mode injection via wfb-ng.
      Tx recv parks with `pending()`; Rx recv/send stub.
- [ ] **BluetoothFace** — `ndn-face-l2/src/bluetooth.rs`
      RFCOMM stream with COBS framing (reuse SerialFace model).
- [ ] **SerialFace** — `ndn-face-serial/src/serial.rs`
      UART/LoRa/RS-485 with COBS framing via `tokio-serial`.

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

## CLI tools (none connected to a live forwarder)

- [ ] **ndn-peek** — `ndn-tools/src/peek.rs:49`
      `// TODO: connect to local forwarder via AppFace`
- [ ] **ndn-ping** — `ndn-tools/src/ping.rs:60`
      Simulates RTT with `sleep(1ms)` instead of real Interest/Data.
- [ ] **ndn-put** — `ndn-tools/src/put.rs:70`
      Segments file but doesn't publish.

## Research

- [ ] **ChannelManager::switch** — `ndn-research/src/channel_manager.rs:27`
      Always returns `Err(NotImplemented)`. Needs nl80211 netlink.
