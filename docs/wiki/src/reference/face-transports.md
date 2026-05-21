# Face transports

Catalogue of face transports shipped in ndn-rs. Each row points at
the implementation crate, the `[[face]] kind` value, and the
typical use case.

For the `Face = Transport + LinkService` shape see
[Extend tier → Face](../api/extend.md#face). For writing a new
transport see [Implementing a face](../guides/implementing-a-face.md).

## Catalogue

| Kind | Crate | `[[face]] kind` | Typical use |
|---|---|---|---|
| UDP | `crates/spec/ndn-faces/src/net/udp.rs` | `udp` | NDN-over-UDP across hosts. |
| TCP | `crates/spec/ndn-faces/src/net/tcp.rs` | `tcp` | NDN-over-TCP across hosts (firewall-friendlier). |
| Multicast UDP | `crates/spec/ndn-faces/src/net/multicast.rs` | `multicast` | Link-local neighbour discovery (group `224.0.23.170`). |
| Unix socket | `crates/spec/ndn-faces/src/local/unix.rs` | `unix` | App-to-forwarder IPC. |
| In-process | `crates/spec/ndn-faces/src/local/in_proc.rs` | (programmatic) | Embedded engine, tests. |
| Shared memory | `crates/spec/ndn-faces/src/local/shm.rs` | `shm` | High-throughput per-host IPC (feature `spsc-shm`). |
| Raw Ethernet | `crates/spec/ndn-faces/src/l2/ether.rs` | `ether` | EtherType `0x8624`. Requires `CAP_NET_RAW`/root. |
| WiFi Direct/AP | `crates/spec/ndn-faces/src/l2/wfb.rs` | `wfb` | WiFi direct broadcast. |
| Bluetooth (BLE) | `crates/spec/ndn-faces/src/l2/bluetooth/mod.rs` | `bluetooth` | BLE L2CAP. |
| Serial (UART) | `crates/spec/ndn-faces/src/serial/mod.rs` | `serial` | Embedded / microcontroller. |
| WebSocket | `crates/spec/ndn-faces/` (`ws`) | `ws` | Browser-to-forwarder over WebSocket. |
| WebTransport | `crates/spec/ndn-face-webtransport/`; wasm: `crates/extension/ndn-face-webtransport-wasm/` | `webtransport` | Browser-to-forwarder over QUIC datagrams. |
| WebRTC datachannel | `crates/extension/ndn-face-webrtc/` | `webrtc` | Browser ↔ browser, browser ↔ relay. |
| SharedWorker | `crates/extension/ndn-face-shared-worker/` | (programmatic) | Per-origin engine sharing across tabs. |
| Callback / Tap | `crates/spec/ndn-faces/src/callback.rs` | (Instrument tier) | Researcher: virtual face whose send-path is a closure. |
| BoltFFI | `crates/extension/ndn-boltffi/` | (programmatic) | FFI bridge for non-Rust hosts. |

## Configuration shape

UDP unicast face listener:

```toml
[[face]]
kind = "udp"
bind = "0.0.0.0:6363"
# remote = "10.0.0.1:6363"  # optional: point-to-point only
```

WebTransport face listener:

```toml
[[face]]
kind = "webtransport"
listen = "0.0.0.0:4443"
cert = "/etc/ndn-fwd/wt.pem"
key  = "/etc/ndn-fwd/wt.key"
```

Shared-memory face (per-host IPC):

```toml
[[face]]
kind = "shm"
path = "/tmp/ndn-fwd.shm"
capacity_mb = 16
```

The full per-kind option set is in `examples/ndn-fwd.example.toml`.

## Programmatic faces (not in `ndn-fwd.toml`)

Some faces are constructed by application code rather than by
listener config:

- `InProcFace` — created in the same process, paired between two
  engines. The pattern is in
  [Develop tier → embedded engine](../api/develop.md#embedded-engine).
- `CallbackFace` / `TapFace` — Instrument tier. See
  [Instrument tier](../api/instrument.md).
- SharedWorker face — `crates/extension/ndn-face-shared-worker/`.
  Mounted via the dashboard's browser-engine profile.

## Link service per face

The default `LinkService` is `LpLinkService` (NDNLPv2 framing). The
high-throughput exceptions:

- `InProcFace` uses `PassthroughLinkService` — bytes go in, bytes
  come out, no framing overhead.
- `ShmFace` uses `PassthroughLinkService` by default;
  switch to `LpLinkService` for cross-host wire compatibility.

See `crates/spec/ndn-transport/src/link_service.rs` for the trait.

## Compile-time gates

| Feature | Carrier crate | Effect |
|---|---|---|
| `spsc-shm` | `ndn-faces` | Enable the shared-memory transport. |
| `ether-linux` | `ndn-faces` | Linux raw-Ethernet face. |
| `ether-macos` | `ndn-faces` | macOS BPF face. |
| `ether-windows` | `ndn-faces` | Windows packet-driver face. |
| `bluetooth` | `ndn-faces` | BLE L2CAP face. |
| `serial` | `ndn-faces` | Serial face. |
| `wasm32` | `ndn-faces` (auto) | WebTransport-wasm + WebRTC + SharedWorker. |

## See also

- [Implementing a face](../guides/implementing-a-face.md) — author
  guide.
- [Config reference](../operations/config-reference.md) — every
  `[[face]]` listener key.
- `crates/spec/ndn-transport/` — the trait surface.
