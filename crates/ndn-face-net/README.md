# ndn-face-net

IP-based face implementations for NDN over UDP, TCP, multicast UDP, and WebSocket.
Each face implements the `Face` trait from `ndn-transport` and runs as an independent
Tokio task. The NDNLPv2 reliability layer adds optional ARQ retransmission on top of
any underlying transport.

## Key types

| Type | Description |
|------|-------------|
| `UdpFace` | Unicast UDP face |
| `MulticastUdpFace` | Link-local multicast UDP face (e.g. `224.0.23.170:6363`) |
| `TcpFace` | Stream-oriented TCP face with length-prefix framing |
| `WebSocketFace` | WebSocket face for browser and proxy connectivity |
| `LpReliability` | NDNLPv2 reliability layer with configurable RTO strategy |

## Feature flags

| Feature | Default | Description |
|---------|---------|-------------|
| `websocket` | yes | Enable `WebSocketFace` via `tokio-tungstenite` |

## Usage

```toml
[dependencies]
ndn-face-net = { version = "*" }                      # all features
ndn-face-net = { version = "*", default-features = false }  # UDP/TCP only
```

```rust
use ndn_face_net::{UdpFace, TcpFace, MulticastUdpFace};
use std::net::SocketAddr;

let addr: SocketAddr = "127.0.0.1:6363".parse().unwrap();
let face = UdpFace::bind(addr).await?;
```
