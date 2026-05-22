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
| Bluetooth LE — central | `crates/spec/ndn-faces/src/l2/bluetooth/central/` | `ble://<name-or-addr>` (via `faces/create`) | Dial a peripheral as GATT client (Linux/macOS/Windows). |
| Bluetooth LE — peripheral | `crates/spec/ndn-faces/src/l2/bluetooth/mod.rs` | `[listeners.ble]` | GATT server; advertises the NDN service (Linux/macOS). |
| Serial (UART) | `crates/spec/ndn-faces/src/serial/mod.rs` | `serial` | Embedded / microcontroller. |
| WebSocket | `crates/spec/ndn-faces/` (`ws`) | `ws` | Browser-to-forwarder over WebSocket. |
| WebTransport | `crates/spec/ndn-face-webtransport/`; wasm: `crates/extension/ndn-face-webtransport-wasm/` | `[listeners.webtransport]`; dial via `[[face]] kind = "web-transport"` or `faces/create wts://…` | Browser↔forwarder and forwarder↔forwarder (NAT-traversing) over QUIC datagrams; oversized packets are NDNLPv2-fragmented to `maxDatagramSize` (interoperates with NDNts `H3Transport`). |
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

WebTransport listener (inbound; browsers and peer forwarders connect here):

```toml
[listeners.webtransport]
enabled = true
listen = "0.0.0.0:4443"
# Self-signed dev cert (browser pins it via serverCertificateHashes):
cert_source = { type = "self_signed_dev", hostnames = ["localhost"] }
# Or PEM:  { type = "pem", cert_pem = "/etc/ndn-fwd/wt.pem", key_pem = "/etc/ndn-fwd/wt.key" }
# Or ACME: { type = "acme", directory_url = "…", email = "…", domain = "…",
#            dns_provider = "cloudflare", cache_dir = "/var/lib/ndn-fwd/acme" }
```

WebTransport outbound dial (forwarder-to-forwarder over NAT):

```toml
[[face]]
kind = "web-transport"
remote = "wts://peer.example:4443"
# Pin a self-signed peer's leaf cert by SHA-256 (hex); omit for WebPKI:
cert_sha256 = "ab12…64hex"
# webpki = true   # validate against the OS trust store instead
```

The listener's TLS cert status (notAfter, days remaining, renewal state) is
readable per listener via the `/localhost/nfd/webtransport/cert-status`
management dataset.

Shared-memory face (per-host IPC):

```toml
[[face]]
kind = "shm"
path = "/tmp/ndn-fwd.shm"
capacity_mb = 16
```

The full per-kind option set is in `examples/ndn-fwd.example.toml`.

## Bluetooth LE

BLE has two roles, modelled differently because central and peripheral are
distinct GATT roles — not a flag on one face. Both use the NDNts
`web-bluetooth-transport` GATT *profile* (service `099577e3-…`), so device
discovery/connect interoperate with browser Web Bluetooth and `esp8266ndn`.
Requires `ndn-fwd --features bluetooth`.

> **Profile is shared; framing is not — but it's auto-negotiated.** ndn-rs
> prefers **NDNLPv2** (one `LpPacket` per ATT write, same path as UDP/Ethernet);
> stock NDNts and `esp8266ndn` use a **1-byte fragmentation header** on the same
> UUIDs. ndn-rs faces speak both and disambiguate automatically (see below), so
> they interoperate with each other *and* with stock NDNts/ESP32 peers.

### Framing disambiguation

The two framings share every UUID, so discovery alone can't tell them apart.
ndn-rs resolves it without manual selection:

- **Responder (peripheral):** sniffs the first inbound write — `0x64` is the
  `LpPacket` TLV (NDNLPv2), anything else is NDNts — latches it per central, and
  **mirrors** it on reply. Zero config.
- **Initiator (central):** reads an optional read-only **capability
  characteristic** (`099577e3-…-…d97392`) after connecting. Present ⇒ the
  peer's advertised framing (NDNLPv2 for ndn-rs peers); **absent ⇒ NDNts** (a
  stock NDNts/esp8266ndn peer never exposes it). No probing or write
  amplification — absence is itself the signal.
- **Override:** `ble://<addr>?framing=ndnts` (or `framing=ndnlpv2`) forces a
  framing and skips the capability read.

NDNts framing is reassembled inside the face (the pipeline only understands
NDNLPv2); NDNLPv2 passes through to the pipeline's `ReassemblyBuffer` as before.

The wire-level rules (UUIDs, framing octets, negotiation, conformance) are
specified normatively in
[NDN over BLE — GATT profile](./ndn-ble-gatt-profile.md).

**Central** — dial a specific peripheral. Created at runtime via `faces/create`
(it is an outgoing face to a remote, exactly like `udp4://host:port`):

```text
ble://<device-name-or-address>
ble://ndn-rs-esp32c3
ble://AA:BB:CC:DD:EE:FF
```

The `?query` carries transport-specific knobs: `?framing=ndnts|ndnlpv2` forces
a wire framing (see disambiguation below), and `?adapter=hci0` is reserved for
adapter selection. Per-face options that aren't BLE-specific — persistency,
MTU, lp-reliability — flow through the standard `faces` management module like
every other face, not through the URI.

**Peripheral** — run the GATT server. It advertises and accepts inbound
centrals, so (per NFD's channel/listener model) it is configured as a listener,
**not** created via `faces/create`:

```toml
[listeners.ble]
enabled = true
```

Each connected central becomes its **own** NDN face: the listener's accept loop
yields one `BleFace` per central, keyed by the BlueZ device address (Linux) or
`CBCentral.identifier` (macOS), so a peripheral serving several centrals shows
several faces. Adapter selection and a custom advertised name are planned
`[listeners.ble]` knobs (today the default adapter and `ndn-rs` name are used).

### `ble` management module

Because the peripheral has controller-level state (advertising on/off,
connected centrals), it gets a small management module —
`/localhost/nfd/ble/<verb>`:

| Verb | Effect |
|---|---|
| `list` | Status line: `supported`, `advertising`, `adapter`, `centrals` (count). |
| `start` | Begin advertising the NDN service (idempotent). |
| `stop` | Stop advertising and tear down the listener. |

`start`/`stop` share one lifecycle with the `[listeners.ble]` auto-start, so the
operator can toggle the peripheral at runtime. The backend is `BleControl` in
`ndn-fwd`; the module returns `404` when the forwarder is built without
`--features bluetooth`.

Per-face knobs that aren't BLE-specific (persistency, MTU, lp-reliability) still
go through the `faces` module, and central-creation knobs ride the `ble://`
FaceUri query string — the `ble` module is only for peripheral/controller state
(a future home for pairing/bonding).

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
| `bluetooth` | `ndn-faces` | BLE GATT central (`ble://`) + peripheral (`[listeners.ble]`). |
| `serial` | `ndn-faces` | Serial face. |
| `wasm32` | `ndn-faces` (auto) | WebTransport-wasm + WebRTC + SharedWorker. |

## See also

- [Implementing a face](../guides/implementing-a-face.md) — author
  guide.
- [Config reference](../operations/config-reference.md) — every
  `[[face]]` listener key.
- `crates/spec/ndn-transport/` — the trait surface.
