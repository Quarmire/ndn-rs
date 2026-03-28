# TODO — Unimplemented Features

Tracked stubs, placeholders, and deferred work across the codebase.

---

## Face implementations (all stub — recv/send return `FaceError::Closed`)

- [ ] **NamedEtherFace** — `ndn-face-wireless/src/ether.rs`
      AF_PACKET raw socket with NDN Ethertype 0x8624.
      Design calls for PACKET_RX_RING / TX_RING mmap ring buffers.
- [ ] **WfbFace** — `ndn-face-wireless/src/wfb.rs`
      Unidirectional 802.11 monitor-mode injection via wfb-ng.
      Tx recv parks with `pending()`; Rx recv/send stub.
- [ ] **BluetoothFace** — `ndn-face-wireless/src/bluetooth.rs`
      RFCOMM stream with COBS framing (reuse SerialFace model).
- [ ] **SerialFace** — `ndn-face-serial/src/serial.rs`
      UART/LoRa/RS-485 with COBS framing via `tokio-serial`.

## Engine pipeline

- [ ] **NACK handling** — `ndn-engine/src/dispatcher.rs:109,162`
      Inbound and outbound NACKs log "not yet implemented" and drop.
- [ ] **ForwardAfter delay scheduling** — `ndn-engine/src/stages/strategy.rs:79`
      Ignores `delay` parameter, forwards immediately.

## Compute face

- [ ] **ComputeFace::send dispatch** — `ndn-compute/src/compute_face.rs:37`
      `// TODO: decode Interest, dispatch to registry, inject Data`
- [ ] **Pipeline sender wiring** — `ndn-compute/src/compute_face.rs:16`
      `// TODO: wire to pipeline mpsc channel`

## Security

- [ ] **TLV cert encoding** — `ndn-security/src/manager.rs:112`
      `certify()` defers full TLV certificate encoding.
- [ ] **SecurityPolicy engine wiring** — `ndn-router/src/main.rs:340`
      SecurityManager loaded but discarded (`_mgr` not passed to engine).

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
