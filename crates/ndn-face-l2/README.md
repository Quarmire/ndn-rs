# ndn-face-l2

Link-layer (Layer 2) face implementations for NDN over raw Ethernet (Ethertype
`0x8624`), Wifibroadcast NG (802.11 monitor-mode injection), and Bluetooth RFCOMM.
Also provides `EtherNeighborDiscovery` for link-local peer detection and `RadioTable`
for tracking metadata about radio-based faces.

## Key types

| Type | Description |
|------|-------------|
| `NamedEtherFace` | Unicast raw Ethernet face (Linux: `AF_PACKET`, macOS: `PF_NDRV`, Windows: Npcap) |
| `MulticastEtherFace` | Multicast raw Ethernet face for link-local broadcast |
| `WfbFace` | Wifibroadcast NG face using 802.11 monitor-mode injection (Linux only) |
| `BluetoothFace` | BlueZ RFCOMM serial face (Linux only) |
| `EtherNeighborDiscovery` | Link-layer neighbor discovery over raw Ethernet (Linux only) |
| `RadioTable` | Cross-platform metadata registry for radio-based faces |
| `NDN_ETHERTYPE` | IANA-assigned Ethertype `0x8624` for NDN over Ethernet |

## Platform support

| Platform | Ethernet | WfbFace | BluetoothFace | Neighbor Discovery |
|----------|----------|---------|---------------|--------------------|
| Linux | `AF_PACKET` | yes | yes (BlueZ) | yes |
| macOS | `PF_NDRV` | no | no | no |
| Windows | Npcap/WinPcap | no | no | no |
| Android / iOS | no | no | no | no |

On Android and iOS only `RadioTable` and `NDN_ETHERTYPE` are exported; use
`ndn-face-net` and `ndn-face-local` for mobile deployments instead.

## Usage

```toml
[dependencies]
ndn-face-l2 = { version = "*" }
```

```rust
// Linux only — requires CAP_NET_RAW or root
use ndn_face_l2::NamedEtherFace;
let face = NamedEtherFace::open("eth0", peer_mac).await?;
```
