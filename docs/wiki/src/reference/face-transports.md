# Face transports

Catalogue of face transports shipped in ndn-rs, each row pointing at the
implementation crate, the `[[face]] kind` value, and the typical use. For the
`Face = Transport + LinkService` shape see [Extend tier → Face](../api/extend.md#face);
for writing a new transport see [Implementing a face](../guides/implementing-a-face.md).

## Catalogue

| Kind | Crate | `[[face]] kind` | Typical use |
|---|---|---|---|
| UDP | `crates/ndn-face-native/src/net/udp.rs` | `udp` | NDN-over-UDP across hosts. |
| TCP | `crates/ndn-face-native/src/net/tcp.rs` | `tcp` | NDN-over-TCP across hosts (firewall-friendlier). |
| Multicast UDP | `crates/ndn-face-native/src/net/multicast.rs` | `multicast` | Link-local neighbour discovery (group `224.0.23.170`). |
| Unix socket | `crates/ndn-face-native/src/local/unix.rs` | `unix` | App-to-forwarder IPC. |
| In-process | `crates/ndn-face-native/src/local/in_proc.rs` | (programmatic) | Embedded engine, tests. |
| Shared memory | `crates/ndn-face-native/src/local/shm.rs` | `shm` | High-throughput per-host IPC (feature `spsc-shm`). |
| Raw Ethernet | `crates/ndn-face-native/src/l2/ether.rs` | `ether` | EtherType `0x8624`. Requires `CAP_NET_RAW`/root. |
| WiFi Direct/AP | `crates/ndn-face-native/src/l2/wfb.rs` | `wfb` | WiFi direct broadcast. |
| Bluetooth LE — central | `crates/ndn-face-native/src/l2/bluetooth/central/` | `ble://<name-or-addr>` (via `faces/create`) | Dial a peripheral as GATT client (Linux/macOS/Windows). |
| Bluetooth LE — peripheral | `crates/ndn-face-native/src/l2/bluetooth/mod.rs` | `[listeners.ble]` | GATT server; advertises the NDN service (Linux/macOS). |
| Serial (UART) | `crates/ndn-face-native/src/serial/mod.rs` | `serial` | Embedded / microcontroller. |
| WebSocket | `crates/ndn-face-native/` (`ws`) | `ws` | Browser-to-forwarder over WebSocket. |
| WebTransport | `crates/ndn-face-webtransport/`; wasm: `crates/ndn-face-webtransport-wasm/` | `[listeners.webtransport]`; dial via `[[face]] kind = "web-transport"` or `faces/create wts://…` | Browser↔forwarder and forwarder↔forwarder (NAT-traversing) over QUIC datagrams; oversized packets are NDNLPv2-fragmented to `maxDatagramSize` (interoperates with NDNts `H3Transport`). |
| QUIC | `crates/ndn-face-quic/` | `[listeners.quic]`; dial via `[[face]] kind = "quic"` or `faces/create quic://…` | Forwarder-to-forwarder backbone over raw QUIC (TLS 1.3, **connection migration**, 0-RTT); one reliable bidi stream of NDN TLV. No HTTP/3 layer (does not reach browsers). |
| WebRTC datachannel | `crates/ndn-face-webrtc/` | `webrtc` | Browser ↔ browser, browser ↔ relay. |
| SharedWorker | `crates/ndn-face-shared-worker/` | (programmatic) | Per-origin engine sharing across tabs. |
| Callback / Tap | `crates/ndn-face-native/src/callback.rs` | (Instrument tier) | Researcher: virtual face whose send-path is a closure. |
| BoltFFI | `crates/ndn-boltffi/` | (programmatic) | FFI bridge for non-Rust hosts. |

## Configuration shape

UDP unicast face listener:

```toml
[[face]]
kind = "udp"
bind = "0.0.0.0:6363"
# remote = "10.0.0.1:6363"  # optional: point-to-point only
```

TLS faces — **WebTransport** (browser↔forwarder and NAT-traversing
forwarder↔forwarder over QUIC datagrams) and **QUIC** (native router-to-router
backbone, TLS 1.3 with connection migration) — share one listener `cert_source`
shape (`self_signed_dev` / `pem` / `acme`, resolved by `ndn-acme`) and one
dialer trust policy (`cert_sha256` leaf-pin or `webpki`):

```toml
[listeners.webtransport]    # or [listeners.quic]
enabled = true
listen = "0.0.0.0:4443"
cert_source = { type = "self_signed_dev", hostnames = ["localhost"] }

[[face]]                     # outbound dial
kind = "web-transport"       # or "quic"
remote = "wts://peer.example:4443"
cert_sha256 = "ab12…64hex"   # pin the peer's logged leaf hash; or webpki = true
```

A self-signed WebTransport cert is capped at 13 days (Chrome's
`serverCertificateHashes` limit); a self-signed QUIC cert is long-lived (a
pinned dialer trusts the leaf hash, not the expiry). Listener cert status
(notAfter, renewal state) is readable via
`/localhost/nfd/webtransport/cert-status`. The WebTransport face interoperates
with **ndnd**'s HTTP/3 face (witness `testbed/tests/audit/wt02_ndnd_interop.sh`);
QUIC does not reach browsers — that is WebTransport's role.

A shared-memory face (`kind = "shm"`, `path`, `capacity_mb`) gives per-host IPC.
The full per-kind option set is in `examples/ndn-fwd.example.toml`.

## Bluetooth LE

BLE has two roles, modelled as distinct faces (central and peripheral are
distinct GATT roles, not a flag): a **central** dials a peripheral as GATT
client, a **peripheral** runs the GATT server. Both use the NDNts
`web-bluetooth-transport` GATT profile, so they interoperate with browser Web
Bluetooth and `esp8266ndn`. Requires `ndn-fwd --features bluetooth`. The wire
rules — UUIDs, the NDNLPv2-vs-NDNts framing split, and its automatic
disambiguation — are normative in
[NDN over BLE — GATT profile](./ndn-ble-gatt-profile.md).

A central is an outgoing face created at runtime via `faces/create` with a
`ble://` URI (`ble://ndn-rs-esp32c3`, `ble://AA:BB:CC:DD:EE:FF`); `?framing=`
and `?adapter=` ride the query string, other per-face knobs go through the
`faces` module. A peripheral is a listener (`[listeners.ble]` → `enabled =
true`) whose accept loop yields one face per connected central. Because the
peripheral carries controller state it gets a small management module
`/localhost/nfd/ble/<verb>`: `list` (status: advertising, adapter, central
count), `start` and `stop` (toggle advertising at runtime). The module returns
`404` without `--features bluetooth`.

## Programmatic faces (not in `ndn-fwd.toml`)

Some faces are constructed by application code rather than by listener config:

- `InProcFace` — created in the same process, paired between two
  engines. The pattern is in
  [Develop tier → embedded engine](../api/develop.md#embedded-engine).
- `CallbackFace` / `TapFace` — Instrument tier. See
  [Instrument tier](../api/instrument.md).
- SharedWorker face — `crates/ndn-face-shared-worker/`.
  Mounted via the dashboard's browser-engine profile.

## Link service per face

The default `LinkService` is `LpLinkService` (NDNLPv2 framing); the
high-throughput exceptions use `PassthroughLinkService` — `InProcFace` always,
and `ShmFace` by default (switch it to `LpLinkService` for cross-host wire
compatibility). See `crates/ndn-transport/src/link_service.rs` for the trait.

## Per-face NDNLPv2 local fields

`IncomingFaceId` and `NextHopFaceId` are NDNLPv2 local fields, gated per-face by
the `LocalFields` flag (off by default). If `IncomingFaceId` always reads
`0`/absent, the face hasn't enabled LocalFields — enable it first via
`faces/update` (`Flags`+`Mask` bit 0 = LocalFields, 1 = LpReliability, 2 =
CongestionMarking):

```sh
ndn-ctl faces update face-id 263 flags 0x1 mask 0x1   # LocalFields on
```

With it enabled: `IncomingFaceId` (0x032C) is attached to packets sent out that
face — the face the packet arrived on (or the reserved Content-Store id `254` on
a cache hit), readable from `LpInfo` (`Consumer::fetch_with_meta`); and
`NextHopFaceId` (0x0330) is honoured on Interests arriving on it, pinning an
Interest to an egress face past the FIB (`Consumer::fetch_on`). A face without
LocalFields ignores `NextHopFaceId`, so an untrusted peer cannot steer
forwarding. Local-scope only; the bundled routing protocol enables it on its
own faces.

## Compile-time gates

| Feature | Carrier crate | Effect |
|---|---|---|
| `spsc-shm` | `ndn-face-native` | Enable the shared-memory transport. |
| `ether-linux` | `ndn-face-native` | Linux raw-Ethernet face. |
| `ether-macos` | `ndn-face-native` | macOS BPF face. |
| `ether-windows` | `ndn-face-native` | Windows packet-driver face. |
| `bluetooth` | `ndn-face-native` | BLE GATT central (`ble://`) + peripheral (`[listeners.ble]`). |
| `serial` | `ndn-face-native` | Serial face. |
| `wasm32` | `ndn-face-native` (auto) | WebTransport-wasm + WebRTC + SharedWorker. |

## See also

- [Implementing a face](../guides/implementing-a-face.md) — author
  guide.
- [Config reference](../operations/config-reference.md) — every
  `[[face]]` listener key.
- `crates/ndn-transport/` — the trait surface.
