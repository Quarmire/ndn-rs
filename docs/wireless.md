# Wireless NDN: Discovery, Multi-Radio, and Channel Management

## NDN Data MUST Follow the Reverse Interest Path

NDN's Interest-Data model requires Data to travel the **exact reverse path** of the Interest. This is fundamental to how the PIT works — the PIT `InRecord` is the only authorization for Data to flow in a direction. Unsolicited Data has no PIT entry and is dropped.

**Consequence for multicast**: You cannot send an Interest as a broadcast and return Data as a unicast to the requester's IP address. The Interest must arrive on a specific face; Data returns on that same face.

**Solution**: Create per-neighbor unicast `NamedEtherFace` instances. Interest and Data travel on the same unicast face at full rate adaptation. The initial broadcast is only for neighbor discovery.

## Wireless Discovery Options

### 802.11 Infrastructure Mode — IPv6 Link-Local Multicast

IPv6 link-local multicast (`ff02::1`) reaches every node on the same network segment without going through an AP router, even in infrastructure mode — most APs pass link-local multicast between clients because it is required for neighbor discovery.

Create a `MulticastUdpFace` sending NDN packets as UDP payloads to `ff02::1:6363`. Every NDN node on the segment receives them. This is deployable today without any kernel changes.

**Limitation**: Multicast and broadcast are sent at legacy rates (1–6 Mbps) because the 802.11 MAC has no per-receiver rate knowledge for non-unicast frames. However, **Interests are small** (~100–300 bytes). At 1 Mbps that is under 3 µs of airtime. The real problem would be multicasting Data — never do this.

**Strategy**: Use multicast only for Interest flooding (small, infrequent, interest suppression in strategy reduces duplicates). Deliver Data via **per-neighbor unicast `NamedEtherFace`** at full rate adaptation.

### mDNS for Unicast Peer Discovery

Add an `MdnsDiscovery` task at startup: advertise `_ndn._udp.local` with the node's NDN face endpoint, listen for peer advertisements, create `NamedEtherFace` or `UdpFace` per discovered peer, add default FIB entries pointing to them.

IPv6 link-local multicast for flooding + mDNS for unicast peer discovery = complete wireless NDN discovery without AP dependency, without link layer changes.

### 802.11 Ad-Hoc (IBSS) / Wi-Fi Direct / 802.11s Mesh

In ad-hoc or mesh mode, broadcast frames reach all nodes within radio range — exactly what NDN Interest flooding needs. Linux supports 802.11s natively via `iw` since kernel 3.0.

For true multi-hop mesh without any AP: add a `MeshFace` that sets the interface to mesh mode and uses the 802.11s path selection protocol to forward NDN Interests beyond one-hop range.

## Multi-Radio, Multi-Channel Architecture

### Why Unify Channel/Radio Management with NDN

In a multi-radio multi-hop wireless network, the routing decision (which next hop) and the radio decision (which channel and radio) are the **same decision at different timescales**. OLSR and similar protocols try to bridge them but the bridge is always incomplete.

NDN unifies them because the name namespace is the coordination medium. Channel state, neighbor tables, link quality, and radio configuration are all named data. A node wanting the channel load on a neighbor's wlan1 expresses an Interest for `/radio/node=neighbor/wlan1/survey` — the same mechanism for any other data.

### Multi-Hop Degradation — Root Causes and Solution

**Hidden node problem**: Nodes on different hops cannot hear each other. Multiple radios on different non-overlapping channels solve this — the relay receives on channel A and transmits on channel B simultaneously without self-interference.

**Halved throughput problem**: A relay must receive and then retransmit every packet. With dedicated channels per direction, receive and transmit happen concurrently.

NDN handles this by assigning `RadioFace` instances to specific roles:
- Access radio: client-facing Interests and Data
- Backhaul radio: inter-node forwarding

The FIB contains separate nexthop entries per radio for the same name prefix. The strategy selects based on `RadioTable` metrics.

### `ChannelManager` Task

Runs alongside the engine. Does three things:

1. Reads nl80211 survey data and station info continuously via Netlink (channel utilization, per-station RSSI, MCS index, retransmission counts)
2. Publishes this as named NDN content under `/radio/local/<iface>/state` with short freshness
3. Subscribes to neighbor radio state via standing Interests on `/radio/+/state` — keeps local `RadioTable` current

**Remote channel coordination**: Express an Interest to `/radio/node=neighbor/wlan1/switch/ch=36`. The neighbor's engine receives it, `ChannelManager` validates credentials (prefix authorization), executes the switch, returns an Ack Data with actual switch latency. Cleaner than any IP-based radio management — authenticated, named, cached, uses the same forwarding infrastructure as data traffic.

**Channel switch and PIT**: Channel switching causes brief interface unavailability during which PIT entries may time out. The strategy suppresses retransmissions during the switch window. Before issuing the nl80211 channel switch, call `xdp_map.flush_interface(ifindex)` if using tc eBPF fast path.

### `RadioTable`

```rust
pub struct RadioTable(DashMap<FaceId, RadioFaceMetrics>);

pub struct RadioFaceMetrics {
    pub interface:    String,
    pub channel:      u8,
    pub band:         WifiBand,
    pub rssi_dbm:     i16,
    pub tx_mcs:       u8,
    pub retx_rate:    f32,
    pub channel_util: f32,
}
```

The `MultiRadioStrategy` holds `Arc<RadioTable>` and reads it on every `after_receive_interest` call to rank faces by current link quality.

### `FlowTable`

Maps name prefixes to preferred radio faces based on observed flow characteristics:

```rust
pub struct FlowEntry {
    prefix:         Name,
    preferred_face: FaceId,
    observed_tput:  f32,    // EWMA bytes/sec
    observed_rtt:   f32,    // EWMA ms
    last_updated:   u64,
}
```

Strategy populates on every Data arrival. Established flows (e.g. `/video/stream` consistently faster via 5 GHz radio) are sent directly to the preferred face without consulting the FIB. FIB is the fallback for new flows.

### `FacePairTable` (wfb-ng Asymmetric Links)

For wfb-ng's inherently unidirectional broadcast links, map rx face_id → tx face_id:

```rust
// in dispatch stage, before sending Data
let send_face_id = self.face_pairs
    .get_tx_for_rx(ctx.pit_token.in_face)
    .unwrap_or(ctx.pit_token.in_face);
```

Normal faces return `None` and are unaffected. A small, well-contained engine change (~50 lines).

## tc eBPF Fast Path (Wireless)

XDP is **not supported on wireless interfaces** — no 802.11 driver implements `ndo_xdp_xmit`. This reflects a genuine mismatch between XDP's assumptions and 802.11's per-station queuing and power save buffering.

**tc eBPF (`cls_bpf`)** runs after the driver processes the frame (post-mac80211) and works on wireless interfaces. `bpf_redirect()` can forward between wireless interfaces without reaching userspace. Use the `aya` crate.

**Honest performance context**: A single 802.11 hop has ~300–500 µs minimum latency (DIFS backoff + transmission + ACK). Engine overhead of 10–50 µs is 3–15% of total. The userspace forwarding cache (first packet takes full pipeline; subsequent packets for known `(in_face, name_hash)` skip all stages) gets to ~1–2 µs in userspace without kernel changes.

**The right question**: Not "how do I match kernel bridge performance" but "what is the forwarding overhead relative to what I gain from NDN-aware forwarding decisions." A kernel bridge cannot make multi-radio selection decisions at all.

## NamedEtherFace vs UdpFace Throughput

Historical reasons EtherFace had worse throughput than UdpFace:

1. **Per-syscall cost**: Standard `AF_PACKET recvfrom` delivers one frame per syscall. At 830k fps that is 830k syscalls/sec. UDP uses GRO (Generic Receive Offload) to coalesce packets and `recvmmsg` to batch receives.
   - Fix: `PACKET_RX_RING` + `PACKET_TX_RING` memory-mapped ring buffers. No syscall overhead per frame, approaches UDP throughput.

2. **MTU difference**: Manageable — NDNLPv2 fragmentation handles it identically for both face types.

3. **Software offloads**: Some TCP/UDP offloads (checksum, GSO) are not available for `AF_PACKET`. Less relevant for NDN's bounded packet sizes.

## Named MAC Layer

The current `NamedEtherFace` architecture provides named-face semantics at the NDN layer while using MAC addresses as internal implementation details only visible inside `send()`:

```rust
impl Face for NamedEtherFace {
    async fn send(&self, pkt: Bytes) -> Result<()> {
        let frame = EtherFrame {
            dst: self.peer_mac,   // only place MAC appears
            src: self.local_mac,
            ethertype: NDN_ETHERTYPE,
            payload: pkt,
        };
        self.ring.send(frame).await
    }
}
```

Above this call everything is pure NDN names. The FIB, PIT, strategy, and pipeline stages never see a MAC address.

**Benefits over IP-based networking for wireless research**:
- **No ARP/NDP**: MAC resolved once at hello exchange; no per-destination resolution
- **Mobility**: Mobile node's name `/node/device123` is stable. Only the internal MAC resolution updates when it moves. FIB entries, PIT entries, and strategy state remain valid.
- **Channel switch stability**: Face identity is the node name, not MAC+channel. Channel switches update face metadata in-place without changing `FaceId`.

A fully named MAC layer (names in 802.11 management frames) requires custom 802.11 firmware — beyond userspace today, but a coherent research direction.
