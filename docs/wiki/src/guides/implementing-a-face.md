# Implementing a face

A face is the NDN-layer link to a peer. It owns a `Transport` (raw
byte send/recv) and a `LinkService` (NDNLPv2 framing). This guide
walks through writing a new face transport and wiring it into the
engine.

The trait surface is [Extend tier → Face](../api/extend.md#face);
the catalog of shipped transports is in
[Face transports](../reference/face-transports.md).

## When to add a new face

- Your transport (a new wireless link, a new IPC channel, a new
  overlay) isn't already covered by the in-tree faces.
- You need a face with non-standard framing (e.g. wrapping NDN in a
  different envelope).

For most NDN-over-Internet work, UDP or TCP already exists. For
browser deployments WebTransport and WebRTC ship; for in-process
work the `InProc` face ships.

## The two halves

```mermaid
graph LR
    subgraph Face
        T[Transport: bytes in/out]
        L[LinkService: NDNLPv2]
    end
    E[Engine] <--> L <--> T
    T <--> P[Peer]
```

- `Transport` moves byte slices to/from a peer. It knows nothing of
  NDN packets — only `Bytes`.
- `LinkService` frames byte sequences into NDN-layer packets:
  applies/strips NDNLPv2 headers, handles fragmentation, sets
  IncomingFaceId, marks congestion.
- `Face = Transport + LinkService` is the composition the engine
  sees.

## Writing the transport

`Transport` is defined in `crates/core/ndn-transport/src/transport.rs`.
Send and receive return `impl Future` (write them as `async fn`);
the trait is **not** `#[async_trait]`. Both `send_bytes` and
`recv_bytes` take `&self` — `send_bytes` may be called concurrently
and must synchronise internally, while `recv_bytes` has a single
consumer (the face's own reader task).

```rust,ignore
use ndn_transport::{Transport, FaceId, FaceKind, FaceError};
use bytes::Bytes;

pub struct MyTransport {
    id: FaceId,
    // ... your socket / handle / whatever
}

impl Transport for MyTransport {
    fn id(&self) -> FaceId { self.id }
    fn kind(&self) -> FaceKind { FaceKind::Udp /* the closest classification */ }

    // Optional; default `None`. Used for management-protocol display.
    fn remote_uri(&self) -> Option<String> { Some("my4://peer".into()) }
    fn local_uri(&self) -> Option<String> { None }

    async fn send_bytes(&self, wire: Bytes) -> Result<(), FaceError> {
        // hand `wire` to your link
        Ok(())
    }

    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        // pull the next frame; `Err(FaceError::Closed)` when the link ends
        todo!()
    }
}
```

To tear a transport down, drop it (and cancel the face's tasks via
the `CancellationToken` you pass at wiring time) — there is no
shutdown method on the trait. `FaceError` has three variants:
`Closed`, `Io`, and `Full`.

`send_bytes`/`recv_bytes` are the only required I/O methods. The trait
also provides defaulted hooks you may override: `send_batch` (a
`sendmmsg`-style burst), `recv_bytes_with_addr` (multicast sender
address), `send_mtu` / `set_send_mtu` (link MTU and LP fragmentation
threshold), and `set_persistency`.

### Side frames: `send_side`, `forward_side`, `side_frame_max`

A frame whose **first octet is `0x00`** (`ndn_transport::SIDE_MARKER`) is not
an NDN packet: TLV-TYPE 0 is unassigned, so no Interest, Data, Nack or
NDNLPv2 packet starts with it, and every NDN decoder rejects it. It is a
*side frame*, for a protocol that rides on a face next to NDN (the channel
of the heap crate is the first). `Face::send_side(frame, class)` hands one to
the transport **without the link service**: no LP header, no fragmentation, no
reliability, no scope judge. `SideClass` says `Datagram` or `Stream`.

A transport carries side frames only if it **opts in**: `side_frame_max()` is 0
by default, and then `send_side` refuses every frame (`SideRefused::NotCarried`),
so a face that frames, codes or decodes what it sends (a TLV byte stream such as
`StreamFace`, whose codec would read the marker as a TLV header and lose its place;
COPE and recoder faces; NDNts-framed BLE) cannot take one by forgetting to say so.
A face that sends a frame as one unit (a datagram, an Ethernet payload, a ring
slot, an in-process channel) opts in by overriding `side_frame_max()` with its
limit, usually `send_mtu()`; the default `send_side` then refuses a frame that does
not start with the marker (`SideRefused::Malformed`; an NDN packet never takes the
side path) and one longer than `side_frame_max()` (`SideRefused::TooLarge`; nothing
is fragmented), sends the rest through `send_bytes` as is, and ignores the class.
`forward_side` (a synchronous send that never waits) is `Unsupported`. Override
`send_side` only for a transport with a second carrier (QUIC's stream) or one
whose limit varies by phy (the smallest phy of a multi-phy radio); an override
must make the same two refusals (marker, length) itself.

On receipt `LpLinkService::recv` returns a marked frame unchanged, before any
reliability bookkeeping, and the engine's face reader peels it right after
`recv_bytes_with_addr()`, before LP detection and the bounded pipeline
channel: it never reaches the PIT, a spawned task, `in_drops` or the
malformed-packet count. The reader counts it per face (`FaceCounters::in_side_frames`,
`in_side_bytes`), stamps the face's activity and hands it to the engine's side table,
which routes it from the one face a route came from and copies it to the faces that
asked for it with `forward_side_from` (which must never wait; docs/specs/channel.md §14).
Ethernet pads a payload under 46 octets and a receiver sees the padding, so a
side frame on an Ethernet face must be self-delimiting or at least 46 octets
(the channel codec is bound by this).

### `FaceKind` vs `FacePersistency`

`FaceKind` classifies the **link**; the engine uses it to pick a
default `LinkService` and resolve face scope. Variants include `Udp`,
`Tcp`, `Unix`, `App`, `Shm`, `Ethernet`, `Serial`, `Bluetooth`, and
the browser kinds. `FacePersistency` is a separate axis —
`OnDemand`, `Persistent`, or `Permanent` — supplied when you wire the
face into the engine, not returned from the transport.

An `App` face lives as long as its app sends. When its reader stops — the
app dropped its end, closed its socket, or its cancel token fired — the
face's routes go at once, so Interests under its prefixes reach the next app
that registers them. The face itself is removed with its socket and tasks:
at once when it was cancelled, or after `ndn_engine::APP_FACE_DRAIN` when the
app closed its end, so the Data of Interests still in the pipeline can reach
an app that only half-closed. An app that waits for Data keeps its sending end
open until the Data arrives; it does not rely on the drain.

## Picking a LinkService

| LinkService | When to use |
|---|---|
| `LpLinkService` | Anything reachable over a lossy or fragmented link. Handles NDNLPv2 framing, fragmentation, IncomingFaceId. Default for wire kinds. |
| `PassthroughLinkService` | Reliable, ordered, MTU-large links where you want bytes-in/bytes-out (e.g. shared memory, in-process). Default for local kinds. |

`default_link_service_for_kind` returns the right one for your
`FaceKind`. The convenience constructor `Face::from_transport` uses
it; `Face::new` lets you choose explicitly.

## Assembling the face

`Face::new(transport: Arc<dyn ErasedTransport>, link_service: Arc<dyn
LinkService>)` (`crates/core/ndn-transport/src/face.rs:367`) composes the
two halves. `ErasedTransport` is the object-safe view of `Transport`,
auto-implemented for every `Transport`, so any concrete transport
becomes `Arc<dyn ErasedTransport>` just by wrapping it in `Arc`:

```rust,ignore
use std::sync::Arc;
use ndn_transport::{Face, LpLinkService};

let face = Face::new(
    Arc::new(MyTransport { /* ... */ }),
    Arc::new(LpLinkService::default()),
);

// Or let the kind pick the LinkService for you:
let face = Face::from_transport(MyTransport { /* ... */ });
```

## Wiring a face into the engine

There is no general `FaceListener` trait. Each transport owns its own
accept/dial loop and hands the resulting transport to the engine. The
engine accepts a bare `Transport` and composes the `Face` for you:

- `EngineBuilder::face(transport)` — add a face at build time.
- `engine.add_face(transport, cancel)` — add one at runtime
  (`cancel` is a `tokio_util::sync::CancellationToken` that stops the
  face's tasks). `add_face_with_persistency` sets the
  `FacePersistency` explicitly.

For a listening transport, run an accept loop and call `add_face` per
connection. `IpcListener` in
`crates/faces/ndn-face/src/local/ipc.rs` is the in-tree pattern: its
`accept(face_id)` returns one face per connection, which the owning
task then wires in.

```rust,ignore
use ndn_engine::EngineBuilder;
use tokio_util::sync::CancellationToken;

# async fn run(transport: MyTransport) -> anyhow::Result<()> {
let (engine, _shutdown) = EngineBuilder::new(Default::default())
    .face(transport)            // one initial face
    .build()
    .await?;

// Later, accept loops add more faces at runtime:
// engine.add_face(next_transport, CancellationToken::new());
# Ok(()) }
```

## Wasm-compatibility check

The dashboard's browser engine builds for `wasm32-unknown-unknown`.
If your face is intended to run in-browser, vet every dependency for
wasm support (no `mio`, no raw sockets, no `tokio::net`). The
`ndn-face-webtransport-wasm` and `ndn-face-webrtc` crates are the
in-tree reference for browser faces. Browser engines are assembled
with `WasmEngineBuilder::add_face(Arc<Face>)` — mirror your builder
method there if the face is meant to run in-browser.

## Built-in references

| Face | Crate | Transport shape |
|---|---|---|
| UDP | `crates/faces/ndn-face/src/net/udp.rs` | UDP socket per peer. |
| TCP | `crates/faces/ndn-face/src/net/tcp.rs` | TCP connection. |
| IPC | `crates/faces/ndn-face/src/local/ipc.rs` | Unix socket / named pipe. |
| InProc | `crates/faces/ndn-face-local/src/lib.rs` | In-process channel. |
| Shm | `ndn-ext/crates/faces/ndn-face-shm/src/spsc.rs` | Shared-memory ring (spsc-shm). |
| Ether | `crates/faces/ndn-face/src/l2/ether.rs` | Raw Ethernet. |
| Bluetooth | `ndn-ext/crates/faces/ndn-face-bluetooth/src/lib.rs` | BLE L2CAP. |
| Serial | `ndn-ext/crates/faces/ndn-face-serial/src/lib.rs` | UART. |
| WebTransport | `ndn-ext/crates/faces/ndn-face-webtransport*` | QUIC datagrams. |
| WebRTC | `ndn-ext/crates/faces/ndn-face-webrtc/` | Datachannel. |
| SharedWorker | `ndn-ext/crates/faces/ndn-face-shared-worker/` | Per-origin engine sharing. |
| BoltFFI | `ndn-mobile/crates/ndn-boltffi/` | FFI bridge. |

## See also

- [Extend tier → Face](../api/extend.md#face) — trait inventory.
- [Face transports](../reference/face-transports.md) — catalog with
  feature flags and use cases.
- `crates/core/ndn-transport/` — `Transport`, `LinkService`, and
  `Face` definitions.
