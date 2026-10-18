# Face transports

Catalogue of face transports shipped in ndn-rs, each row pointing at the
implementation crate, the `[[face]] kind` value, and the typical use. For the
`Face = Transport + LinkService` shape see [Extend tier → Face](../api/extend.md#face);
for writing a new transport see [Implementing a face](../guides/implementing-a-face.md).

## Catalogue

| Kind | Crate | `[[face]] kind` | Typical use |
|---|---|---|---|
| UDP | `crates/faces/ndn-face/src/net/udp.rs` | `udp` | NDN-over-UDP across hosts. |
| TCP | `crates/faces/ndn-face/src/net/tcp.rs` | `tcp` | NDN-over-TCP across hosts (firewall-friendlier). |
| Multicast UDP | `crates/faces/ndn-face/src/net/multicast.rs` | `multicast` | Link-local neighbour discovery (group `224.0.23.170`); auto-created per interface via `[face_system.udp] auto_multicast`. |
| Unix socket | `crates/faces/ndn-face/src/local/unix.rs` | `unix` | App-to-forwarder IPC. |
| In-process | `crates/faces/ndn-face-local/src/lib.rs` | (programmatic) | Embedded engine, tests. |
| Shared memory | `ndn-ext/crates/faces/ndn-face-shm/src/spsc.rs` | `shm` | High-throughput per-host IPC (feature `spsc-shm`). |
| Ethernet unicast | `crates/faces/ndn-face/src/l2/ether.rs` | `ether` (TOML) or `faces/create ether://[<mac>]/<iface>` | Point-to-point link to a known peer MAC. EtherType `0x8624`; requires `CAP_NET_RAW`/root. |
| Ethernet multicast | `crates/faces/ndn-face/src/l2/multicast_ether.rs` | `ether-multicast` | Group `01:00:5e:00:17:aa`; auto-created per interface via `[face_system.ether] auto_multicast` (Linux). |
| 802.11 monitor-mode | `ndn-ext/crates/faces/ndn-face-monitor-wifi/` | `wfb` | Connectionless raw 802.11 injection (named-radio): `MonitorWifiFace` over a `FrameIo` backend (`ndn-frame-io`). |
| Bluetooth LE — central | `ndn-ext/crates/faces/ndn-face-bluetooth/src/central/` | `ble://<name-or-addr>` (via `faces/create`) | Dial a peripheral as GATT client (Linux/macOS/Windows). |
| Bluetooth LE — peripheral | `ndn-ext/crates/faces/ndn-face-bluetooth/src/lib.rs` | `[listeners.ble]` | GATT server; advertises the NDN service (Linux/macOS). |
| Serial (UART) | `ndn-ext/crates/faces/ndn-face-serial/src/lib.rs` | `serial` | Embedded / microcontroller. |
| WebSocket | `ndn-ext/crates/faces/ndn-face-websocket/` | `ws` | Browser-to-forwarder over WebSocket. |
| WebTransport | `ndn-ext/crates/faces/ndn-face-webtransport/`; wasm: `ndn-ext/crates/faces/ndn-face-webtransport-wasm/` | `[listeners.webtransport]`; dial via `[[face]] kind = "web-transport"` or `faces/create wts://…` | Browser↔forwarder and forwarder↔forwarder (NAT-traversing) over QUIC datagrams; oversized packets are NDNLPv2-fragmented to `maxDatagramSize` (interoperates with NDNts `H3Transport`). |
| QUIC links | `ndn-ext/crates/faces/ndn-face-quic/` | `quic` (listens for links: `bind`); links are dialled from `[[peer]]` | Device-to-device and device-to-relay links across networks. Each end is identified by its NDN device key (TLS 1.3 with raw public keys); NDN packets ride QUIC datagrams, NDNLPv2-fragmented; a link survives an address change (connection migration). No HTTP/3 layer (does not reach browsers). See [QUIC links](#quic-links). |
| WebRTC datachannel | `ndn-ext/crates/faces/ndn-face-webrtc/` | `webrtc` | Browser ↔ browser, browser ↔ relay. |
| SharedWorker | `ndn-ext/crates/faces/ndn-face-shared-worker/` | (programmatic) | Per-origin engine sharing across tabs. |
| Callback / Tap | `crates/faces/ndn-face/src/callback.rs` | (Instrument tier) | Researcher: virtual face whose send-path is a closure. |
| BoltFFI | `ndn-mobile/crates/ndn-boltffi/` | (programmatic) | FFI bridge for non-Rust hosts. |

## Configuration shape

UDP unicast face listener:

```toml
[[face]]
kind = "udp"
bind = "0.0.0.0:6363"
# remote = "10.0.0.1:6363"  # optional: point-to-point only
```

A face with `remote` is connected to that peer. Its local port is the `bind`
port when given; otherwise the port of this forwarder's own UDP listener when
it has one (datagrams then leave from the port the peer knows, so the peer
keeps one face for us); otherwise an ephemeral port. Only a listener's port is
shared; any other port is bound exclusively, so two forwarders on one host each
dialing the same hub get separate source addresses and their own replies.
Its local IP is the `bind` IP when that is a specific address; with
`0.0.0.0`/`[::]` or no `bind`, the address the host routes to the peer. A
`bind` IP of the other family than `remote`, or one the host does not hold,
is refused with the reason in the log (`failed to create UDP face`).

**WebTransport** (browser↔forwarder and NAT-traversing forwarder↔forwarder
over QUIC datagrams) takes a listener `cert_source` (`self_signed_dev` /
`pem` / `acme`, resolved by `ndn-acme`) and a dialer trust policy
(`cert_sha256` leaf-pin or `webpki`):

```toml
[listeners.webtransport]
enabled = true
listen = "0.0.0.0:4443"
cert_source = { type = "self_signed_dev", hostnames = ["localhost"] }

[[face]]                     # outbound dial
kind = "web-transport"
remote = "wts://peer.example:4443"
cert_sha256 = "ab12…64hex"   # pin the peer's logged leaf hash; or webpki = true
```

A self-signed WebTransport cert is capped at 13 days (Chrome's
`serverCertificateHashes` limit). The self-signed key and cert are persisted
(files `0600`) under `cache_dir` — default `$XDG_STATE_HOME/ndn-fwd/tls`,
else `~/.local/state/ndn-fwd/tls` — keyed by `hostnames`, so the pinned hash
survives restarts: the cert is re-issued from the same key when within a day
of expiry. Changing `hostnames` mints a new key and cert; give co-hosted
nodes distinct `cache_dir`s to keep their pins distinct. Listener cert status
(notAfter, renewal state) is readable via
`/localhost/nfd/webtransport/cert-status`. The WebTransport face interoperates
with **ndnd**'s HTTP/3 face (witness `testbed/tests/audit/wt02_ndnd_interop.sh`).
WebTransport is the way to reach browsers; QUIC links (below) do not, and
they use no certificate files at all.

A shared-memory face (`kind = "shm"`, `path`, `capacity_mb`) gives per-host IPC.
The full per-kind option set is in `examples/ndn-fwd.example.toml`.

Ethernet faces (EtherType `0x8624`, `CAP_NET_RAW`/root) come in three forms — a
unicast link to a known peer MAC, a multicast group face, and per-interface
auto-creation:

```toml
[[face]]                       # unicast point-to-point
kind = "ether"
interface = "eth0"
peer-mac = "aa:bb:cc:dd:ee:ff"

[[face]]                       # multicast group face (Linux)
kind = "ether-multicast"
interface = "eth0"

[face_system.ether]            # auto-create a multicast face per matching NIC
auto_multicast = true          # + add/remove on hotplug with watch_interfaces
```

A unicast Ethernet face can also be created at runtime:
`nfdc face create ether://[aa:bb:cc:dd:ee:ff]/eth0`. The peer MAC is explicit —
neighbour discovery is a separate path. As with every wire face, NDNLPv2
framing and fragmentation are owned by the paired `LpLinkService`: the face is
payload-only and reports a 1500-byte send-MTU, so the link service fragments
once at the Ethernet boundary (it does **not** re-frame at the transport).

## QUIC links

A QUIC link joins two devices — two `ndn-fwd` daemons — across networks: a
laptop to a home server, a phone to a relay on a VPS. For the person using
them this is "link my devices" or "use my relay"; the steps are on
[Linking devices](./links.md). This section is the reference. The transport
is `ndn-face-quic`; the admission rules below, the routes, redial and the
one-link-per-pair rule are the `ndn-link` library (`ndn-ext/crates/faces/ndn-link/`),
which `ndn-fwd` and any other host link through.

**Identity is the device's NDN key.** Both ends run TLS 1.3 with raw public
keys (RFC 7250): the key each side presents *is* its NDN device key (Ed25519
or P-256), and the handshake signature is made with it. There is no CA, no
host name, no certificate file and no session resumption; ALPN is
`ndn-link/1`. A device is named in config by its key's **fingerprint**: the
SHA-256 of the public key as an NDN certificate carries it (Ed25519: the raw
32 bytes; P-256: the SubjectPublicKeyInfo DER), 64 lowercase hex digits —
the same function as a trust-anchor fingerprint. The daemon logs its own at
startup (`this device's link key`, `fingerprint=…`, target `face.quic`). A
daemon whose key signs only asynchronously (a hardware token, a custodian)
cannot link and refuses to start links with that reason; so does a daemon
running without a signing key.

**Admission.** After the handshake each side sends its device certificate
and the issuer certificates it keeps; each side then decides. A link is
admitted when either

- the certificate validates in a namespace this device holds — with the
  certificates the peer sent and the ones this device already serves or
  caches, nothing fetched — certifies the key the handshake proved, is a
  device certificate `/<ns>/<role>/<device>/KEY/…` within its validity, is
  not revoked (nor its key or an issuer) by the held trust-context version,
  the namespace's link policy lets that role link, and, when a `[[peer]]`
  names `device = …`, it is that device; or
- the key matches a `[[peer]] key` (an expected fingerprint) — for a device
  of another namespace, or one not enrolled or adopted yet. A certificate
  that validates and names another device than the `[[peer]]` says, or a
  revoked one, is still refused.

Otherwise the link is closed with a reason code and a sentence saying why
and what to do — unless it can be an **enrollment link** (below); the face
exists only once both sides admitted the link, and the verdict each side
sends says whether it admitted a full link or an enrollment link.
The **link policy** is data in the trust context (field `LINK_POLICY`,
`0x0412`): which roles may link, which may act as relays, and whether a relay
of the namespace admits an unknown device on an enrollment link that carries
only its enrollment (the CA endpoints, the trust context and certificates),
and whether devices linked through a relay may try a direct path between
them. When the
context carries none, any device role may link, a relay must be a `node`
device, enrollment links are on when the namespace has a CA, and direct
paths are on. `ndn-fwd
init -c <config>` writes it from `[ca] link_roles` / `relay_roles` /
`enrollment_links` / `direct_paths` (else the default), and `ndn-fwd schema update -c
<config>` changes it — a narrowing only with `--accept-narrowing` (see
[Context updates](context-updates.md)). A revocation, once this device adopts it, closes every live link
whose certificate or issuer it revokes. Renewal keeps the key, so links
survive renewals. When both devices dial each other, both keep the link
dialled by the device with the smaller fingerprint; otherwise a newer link
to the same device replaces the older one.

**Enrollment links.** A device not enrolled yet can enroll over QUIC. A
relay — this device holds a certificate of a role the namespace's link
policy lets relay — admits a device whose key it does not know on an
enrollment link when that policy allows them and the trust context names a
CA endpoint. The device, holding no certificate in the namespace of the
relay its `[[peer]]` names, cannot confirm the relay yet and links to it on
the same terms. An enrollment link carries only Interests whose names are
under a CA endpoint of the namespace, under `/<ns>/32=trust-context`, or
name a certificate or key in it (a `KEY` component), and the Data and Nacks
answering them: the relay takes such Interests and sends their answers, the
device the other way round; nothing else crosses in either direction.
The face drops what the scope does not carry — judging each NDNLPv2 frame
by its packet's name, a fragment by its first fragment's — and answers a
dropped Interest with a Nack (NoRoute). On the relay no route points over
the link (answers return the way their Interests came); the device routes
`/<ns>` over it. Per relay: at most 32 enrollment links, 4 from one source
address, 32 Interests at once refilled at 4 per second on each, and a link
that carried nothing for 120 s (twice the longest a CA holds a STATUS
request) is closed with code `0x02`; the device dials again. A key revoked
by the held version gets no enrollment link (`0x12`). When the device
switches to its enrolled key, it closes its enrollment links for that
namespace (code `0x03`) and dials again, now presenting the certificate.

| Close code | Reason |
|---|---|
| `0x00` | The device is shutting down; it links again when it is back. |
| `0x01` | A newer link to the same device took this one's place. |
| `0x02` | An enrollment link carried nothing for its idle lifetime (120 s). |
| `0x03` | The device enrolled; it links again as an enrolled device. |
| `0x10` | The key has no valid certificate in a namespace this device holds, no `[[peer]]` expects it, and this device admits no enrollment link (the sentence says why). |
| `0x11` | The certificate sent is for another key than the one the handshake proved. |
| `0x12` | The key, or a certificate on its chain, is revoked. |
| `0x13` | The namespace's link policy does not let the peer's role link (or relay) here. |
| `0x14` | A valid device, but not the one a `[[peer]]` expects there. |
| `0x15` | Malformed link messages. |
| `0x16` | Too many link attempts at once from that address, or in total; or too many enrollment links. |
| `0x17` | The device has no usable link key. |

**Datagrams and fragmentation.** NDN packets ride QUIC DATAGRAM frames, one
NDNLPv2 frame per datagram. The face's `LpLinkService` fragments packets
larger than the connection's current maximum datagram size, which grows with
path MTU discovery from the QUIC minimum (~1200-byte packets). No data
travels on streams, so a lost packet holds up nothing behind it. `[[peer]]
reliability = true` turns on NDNLPv2 reliability for that link. The face
has kind `quic`, remote URI `quic4://ip:port` or `quic6://…`, persistency
persistent, and is removed when the link ends.

**Keep-alive and idle.** Keep-alive every 10 s, idle timeout 30 s — sized
for NAT bindings. A link keeps going across an address change (connection
migration). After a crash and restart, a peer's next packet gets a QUIC
stateless reset (its key is derived from the device key), so the peer
redials at once instead of waiting out the idle timeout.

**Rate limits.** An unauthenticated attempt costs one handshake, so
attempts are bounded: at most 64 not yet admitted at once (handshake, hello
and verdict), 4 per source address, and a source refused 8 times is refused
outright for 60 s. Once half of those 64 are in use, a source whose address
is not yet validated gets a QUIC Retry first. Attempts over these limits are
refused before the handshake (QUIC `CONNECTION_REFUSED`; the dialer reports
code `0x16`). The hello and the verdict each have 10 s.

**Config.** One link socket per daemon, and one `[[peer]]` per device to
link with (full field list in the [config reference](../operations/config-reference.md#peer--quic-links)):

```toml
[[face]]
kind = "quic"
bind = "0.0.0.0:6367"        # "[::]:6367" for both families
# listen = false             # dial only, from bind (e.g. "192.0.2.7:0")
# advertise = ["203.0.113.7:6367"]  # port forwards offered as direct-path candidates

[[peer]]
device = "/home/node/relay"  # or key = "<64 hex>" (expected fingerprint)
endpoint = "relay.example.net:6367"
```

Routes come with the link: a relay (a `node` device this one has a
`[[peer]]` for) gets its namespace prefix `/<ns>`, any other device its
device name, and a peer reached through a relay (`relay = …`) is routed over
the relay's link at cost 10 (a direct link costs 0). A `[[route]]` cannot
name the QUIC link socket; set `[[peer]] routes` instead. Dialing uses the
link socket when the address family matches, so the other side sees one
address for this device — the one `bind` names. A device that only dials
picks its source address with `listen = false` (no links accepted; port `0`
lets the system pick the port); without a quic `[[face]]` it dials from an
address and port the system picks. On SIGTERM every link is closed with
code `0x00` and persistent peers redial. `ndn-ctl face create quic://…` is
refused with the `[[peer]]` config to write instead.

Not done yet: hole punching and endpoint discovery. Two devices behind NATs
link **relay-first** — each links to a relay, which forwards between the two
links. A link is the pair of keys, not an address, so a later direct path
needs no change of identity.

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
- SharedWorker face — `ndn-ext/crates/faces/ndn-face-shared-worker/`.
  Mounted via the dashboard's browser-engine profile.

## Connectionless named-radio faces — *extension*

> These are ndn-rs extensions with no NDN community-spec basis; the wire is
> ordinary NDNLPv2 over the radio's native broadcast primitive.

A node — especially a phone — can carry NDN over **connectionless broadcast
radios** with no AP, no pairing, and no host addresses (the NDN name is the
only addressing). Each is `link_type() == AdHoc` with a small MTU, so the
`LpLinkService` fragments NDN across the radio's frames automatically.

| Face | Crate | Radio primitive | Notes |
| --- | --- | --- | --- |
| Wi-Fi Aware (NAN) | `ndn-ext/crates/faces/ndn-face-wifi-aware/` | NAN follow-up messages (255 B) | AP-less peer Wi-Fi; service pub/sub discovery; bulk over NDP (`request_ndp` → `UdpFace`). |
| BLE advertising | `ndn-ext/crates/faces/ndn-face-ble-adv/` | BLE 5 extended advertisement (~245 B) | Near-universal; pairless broadcast; presence + small Interest/Data (bulk wants a connection face). |
| 802.11 monitor | `ndn-ext/crates/faces/ndn-face-monitor-wifi/` | raw-injected 802.11 frames | Per-frame MCS, no association/ARQ. |

The physical radio sits behind a **backend trait** (`NanBackend`, `AdvBackend`)
with a hardware-free `Loopback*Bus` for tests, so the face is exercised without
hardware; a platform supplies the radio by implementing the trait (Android JNI,
BlueZ, an MCU). These faces are **not mutually exclusive** — a node holds a set
of them at once and a mesh strategy fans Interests over all (see the
*Face system* section of `ARCHITECTURE.md` in the repo root). On mobile they're
attached at runtime via `ndn-mobile` (`attach_wifi_aware` / `attach_ble`) or the
`ndn-boltffi` FFI seam (`NdnNanBackend` / `NdnBleBackend` + the engine's
`*_deliver_*` methods); nearby peers surface at the localhost dataset
`/localhost/discovery/peers`.

**Tap-to-share over these faces (extension).** To send a file to a tapped peer,
an app serves an *offer board* (`NdnEngine`/`NdnClient::start_offer_board`): a
certificate at `/ndn/node/<id>/cert` (the TOFU pin target) and a signed manifest
at `/ndn/node/<id>/offers`, both reached over the per-peer route with no hint.
Each offered file (`add_offer`) is a signed RDR object under the offerer's own
identity, fetched by a peer with `fetch_object_verified_hinted(name,
"/ndn/node/<peerId>")` — the `ForwardingHint` steers it to the peer, whose node
strips the hint via its `NetworkRegionTable` (declared at discovery start) and
serves it by name. See the *Connectionless named-radio faces* section of
`ARCHITECTURE.md` for the full flow.

## Wi-Fi Direct bulk upgrade — *extension*

The connectionless radios above are great for discovery and small control but
are duty-cycled or small-MTU, so bulk transfer wants a real Wi-Fi link. The
pattern (the same one Quick Share / AirDrop use) is **discover over Wi-Fi Aware
/ BLE, then upgrade to Wi-Fi Direct for bulk**. Crucially this stays
data-centric: once a Wi-Fi P2P group forms it is just a multi-access IP subnet
(the group owner runs DHCP on `192.168.49.0/24`), so the host-centric
group-owner election and DHCP live entirely *below* the Face. Above it there is
no host — only `FaceKind::WifiDirect` faces carrying names:

| Use | Face | Notes |
| --- | --- | --- |
| 1:1 bulk | `UdpFace::with_kind(WifiDirect)` (unicast) | Full Wi-Fi MCS rate (5 GHz); `LinkProfile` cost 8 so cost-aware forwarding prefers it over NDP/LAN UDP (10), Wi-Fi Aware (20), BLE (50). |
| One-to-many | `MulticastUdpFace::with_kind(WifiDirect)` | Join `224.0.23.170:56363` on the group interface; `MulticastStrategy` + PIT aggregation give one-Interest-to-many, one-Data-to-many — the "seed a file to the room" path. Wi-Fi multicast is basic-rate/un-ACKed, so it is for coordination + Interests (and FEC-coded bulk), not raw 1:1 throughput. |

No new crate or Cargo feature — these are the existing UDP faces re-tagged to
the real radio. On mobile they attach via `ndn-mobile`
(`attach_wifi_direct_face` / `attach_wifi_direct_multicast_face`) or the
`ndn-boltffi` FFI (`attachWifiDirectFace` / `attachWifiDirectMulticastFace`),
mirroring the Wi-Fi Aware NDP bulk path (`attach_ndp_face`). The same shape maps
to a Wi-Fi **SoftAP** "portable router" (one node provides the medium; peers
join and multicast by name) and to Apple's Wi-Fi Aware framework on iOS (the
same NAN standard behind `NanBackend`).

## Link service per face

The default `LinkService` is `LpLinkService` (NDNLPv2 framing); the
high-throughput exceptions use `PassthroughLinkService` — `InProcFace` always,
and `ShmFace` by default (switch it to `LpLinkService` for cross-host wire
compatibility). See `crates/core/ndn-transport/src/link_service/` for the trait.

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
| `spsc-shm` | `ndn-face-shm` | Enable the shared-memory transport. |
| `ether-linux` | `ndn-face` | Linux raw-Ethernet face. |
| `ether-macos` | `ndn-face` | macOS BPF face. |
| `ether-windows` | `ndn-face` | Windows packet-driver face. |
| `bluetooth` | `ndn-face-bluetooth` | BLE GATT central (`ble://`) + peripheral (`[listeners.ble]`). |
| `serial` | `ndn-face-serial` | Serial face. |
| `wasm32` | `ndn-face` (auto) | WebTransport-wasm + WebRTC + SharedWorker. |

## See also

- [Implementing a face](../guides/implementing-a-face.md) — author
  guide.
- [Config reference](../operations/config-reference.md) — every
  `[[face]]` listener key and `[[peer]]`.
- [Linking devices](./links.md) — linking devices over QUIC, step by step.
- `crates/core/ndn-transport/` — the trait surface.
