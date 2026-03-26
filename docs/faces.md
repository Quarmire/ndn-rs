# Face Abstraction and Face Types

## `Face` Trait

```rust
pub trait Face: Send + Sync + 'static {
    fn id(&self) -> FaceId;
    fn kind(&self) -> FaceKind;
    async fn recv(&self) -> Result<Bytes, FaceError>;
    async fn send(&self, pkt: Bytes) -> Result<(), FaceError>;
}

pub struct FaceId(u32);

pub enum FaceKind {
    App,       // in-process or IPC
    Udp,
    Tcp,
    Unix,
    Ether,
    Serial,
    Bluetooth,
    Wfb,
}
```

**`recv` vs `send` asymmetry**: `recv` is called from exactly one task (the face's own task). `send` can be called concurrently from many pipeline tasks. `send` must be `&self` and internally synchronized. For UDP this is trivial — `UdpSocket::send_to` takes `&self`. For TCP/Unix, `Arc<Mutex<WriteHalf>>` serializes concurrent sends on the same stream.

## Task Topology

Each face owns a Tokio task whose only job is calling `face.recv().await` in a loop and pushing `RawPacket` onto a shared `mpsc` channel:

```rust
struct RawPacket {
    bytes:   Bytes,
    face_id: FaceId,
    arrival: u64,    // ns timestamp taken at recv, before channel enqueue
}
```

**Backpressure**: `tx.send().await` yields the face task if the pipeline channel is full — a slow pipeline slows all face tasks naturally.

**Timestamp at recv**: Interest lifetime accounting starts when the packet arrives at the face, not when the pipeline processes it.

## `FaceTable`

```rust
pub struct FaceTable(DashMap<FaceId, Arc<dyn ErasedFace>>);
```

`DashMap` for sharded concurrent reads from many pipeline tasks with occasional writes on face add/remove.

Pipeline stages clone the `Arc` out of the table, release the table reference, then call `face.send().await`. The `Arc` keeps the face alive across the `await` point without holding the table lock during I/O — holding the lock during I/O would deadlock.

**Face removal**: When a remote peer disconnects, the face task's `recv()` returns an error. The task removes itself from the `FaceTable` and sends a `FaceEvent::Closed(face_id)` to the face manager task, which cleans up PIT `OutRecord` entries.

## TCP and Unix Stream Framing

NDN uses TLV length-prefix framing over byte streams. Use `tokio_util::codec` with a `TlvCodec` implementing `Decoder`:

```rust
impl Face for TcpFace {
    async fn recv(&self) -> Result<Bytes> {
        self.framed.next().await.ok_or(FaceError::Closed)?
    }
    async fn send(&self, pkt: Bytes) -> Result<()> {
        self.framed.send(pkt).await
    }
}
```

## UDP — NDNLPv2 Fragmentation

NDN Data can reach 8800 bytes; UDP MTU is typically 1500 bytes. NDNLPv2 handles fragmentation and reassembly inside the UDP face, below the pipeline. The pipeline sees only complete reassembled packets. This is invisible to all stages.

## `EtherFace` / `NamedEtherFace` — AF_PACKET

NDN has IANA-assigned Ethertype `0x8624` for carrying NDN packets directly over Ethernet frames with no IP or UDP. An `AF_PACKET` raw socket in Linux sends and receives these frames identified only by MAC address.

```rust
pub struct NamedEtherFace {
    node_name:  Name,            // this neighbor's NDN node name (stable across channels)
    peer_mac:   MacAddr,         // resolved once at hello exchange, stored here
    iface:      String,
    radio_meta: RadioFaceMetadata,
    socket:     Arc<PacketRing>, // PACKET_RX_RING / PACKET_TX_RING
}

impl Face for NamedEtherFace {
    async fn send(&self, pkt: Bytes) -> Result<()> {
        let frame = EtherFrame {
            dst:       self.peer_mac,   // ONLY place MAC address appears
            src:       self.local_mac,
            ethertype: NDN_ETHERTYPE,
            payload:   pkt,
        };
        self.ring.send(frame).await
    }
}
```

**MAC as implementation detail**: The MAC address never surfaces to the FIB, PIT, strategy, or any pipeline stage. The FIB contains `(/node/B/prefix, face_id=7)` — not a MAC address. `EtherFace.send()` is the only place MAC appears.

**`PACKET_RX_RING`**: Memory-mapped ring buffer that the kernel fills directly. Userspace polls without syscalls, largely closing the throughput gap with UDP. Combined with `PACKET_TX_RING` for transmit batching, well-tuned `EtherFace` approaches UDP throughput.

## MAC Address Resolution

NDN's resolution problem is simpler than ARP in three ways:
1. Strictly one-hop — only need MAC of directly adjacent neighbors
2. Established once at first contact as a side effect of the hello exchange
3. Binding keyed on stable node name — mobility does not invalidate it

The hello exchange: one broadcast Interest `/local/hello/nonce=XYZ` at legacy rate. Responding neighbors' Data carries the source MAC and their node name. `NamedEtherFace` structs are created per `(peer_mac, iface)` pair. From that point, all traffic is unicast at full rate adaptation.

**Multi-radio**: A node reachable on both wlan0 and wlan1 gets two `NamedEtherFace` entries — `(mac=A, iface=wlan0, radio=0, ch=6)` and `(mac=A, iface=wlan1, radio=1, ch=36)`. The FIB can have nexthop entries for both with different costs.

## wfb-ng (`WfbFace`) — Asymmetric Links

wfb-ng uses 802.11 monitor mode with raw frame injection — no association, no ACK, no CSMA/CA. Purely unidirectional broadcast link with FEC. NDN's Interest-Data model requires bidirectional paths.

**`FacePairTable`**: Maps rx face_id → tx face_id for asymmetric links. Normal faces return `None` and behave identically to today.

```rust
// in dispatch stage, before sending Data
let send_face_id = self.face_pairs
    .get_tx_for_rx(ctx.pit_token.in_face)
    .unwrap_or(ctx.pit_token.in_face);
face_table.get(send_face_id)?.send(data).await;
```

**Natural fit**: Use wfb-ng as a named data broadcast layer where the producer continuously pushes named segments and the CS does the work. The drone broadcasts `/drone/video/seg=N` continuously on the downlink; ground stations receive what they can; the CS buffers it; missed segments are re-requested on the uplink. FEC (wfb-ng) and NDN retransmission are complementary.

## `SerialFace`

`tokio-serial` wraps platform serial ports as async `AsyncRead + AsyncWrite` streams. Same `tokio_util::codec` framing pattern as TCP. COBS framing for frame resynchronisation after line noise.

**Use cases**: UART sensor nodes, RS-485 multi-drop industrial bus (Modbus replacement with NDN caching), LoRa radio modems (kilometre-range, ~5.5 kbps at SF7). Bluetooth Classic RFCOMM presents as `/dev/rfcommN` — `SerialFace` works without modification.

**RS-485**: NDN's broadcast-and-respond model maps naturally onto the multi-drop bus. An Interest broadcast reaches all nodes; the node with the named data responds. CS caching reduces bus traffic in dense polling scenarios.

## `BluetoothFace` (BLE)

Use **L2CAP Connection-Oriented Channels (CoC)** rather than GATT NUS. L2CAP CoC provides bidirectional stream channels with negotiated MTU up to 65535 bytes, avoiding the 20-byte GATT limit. Negotiated MTU lands ~247 bytes in practice — fits NDN Interests comfortably, NDNLPv2 fragmentation handles Data.

**BLE + CS interaction**: When a peripheral sleeps between connection intervals, consumers with CS hits get data without the peripheral waking. Battery-powered sensors only need to push data once per freshness period.

## XDP Limitation on Wireless

XDP requires `ndo_xdp_xmit` in the network driver. Virtually no 802.11 drivers implement this — the 802.11 MAC sublayer (ACK, RTS/CTS, rate adaptation, power save buffering) does not map onto XDP's model.

**tc eBPF** (`cls_bpf`) is the realistic kernel fast path for wireless. Runs after the driver processes the frame (post-mac80211). `bpf_redirect()` can forward between wireless interfaces without reaching userspace. Use the `aya` crate for loading tc eBPF programs and managing BPF maps.

**Honest assessment**: A single 802.11 hop has ~300–500 µs minimum latency (DIFS backoff + transmission + ACK). Engine overhead of 10–50 µs is 3–15% of that. The userspace forwarding cache (described in the engine docs) reduces hot-path overhead to ~1–2 µs without any kernel changes.

## AppFace (In-Process)

For same-process applications, `AppFace` uses `tokio::sync::mpsc` channels. An `Arc<DecodedPacket>` clone costs one atomic increment (~10–20 ns). No TLV encoding/decoding — the decoded packet passes directly. This is the default for embedded research nodes where everything runs in one process.

For cross-process, use iceoryx2 for the Data delivery path (zero-copy, ~150 ns) and `mpsc` for the Interest path. See `docs/ipc.md`.
