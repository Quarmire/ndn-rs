# ndn-transport

Async face abstraction and transport layer for ndn-rs. Provides the `Face` trait implemented by all link types (UDP, TCP, Unix, Ethernet, Bluetooth, etc.), a runtime face registry, TLV stream framing, and per-face congestion control.

## Key Types

| Type | Role |
|------|------|
| `Face` | Async `send`/`recv` trait implemented by every transport |
| `FaceId` / `FaceKind` | Opaque face identity and classification (UDP, TCP, AppFace, etc.) |
| `FaceAddr` / `FaceScope` / `FacePersistency` | Face metadata |
| `FaceTable` / `ErasedFace` / `FaceInfo` | Runtime registry of type-erased faces |
| `FacePairTable` | Bidirectional face-pair map for in-process channels |
| `RawPacket` | Raw `Bytes` payload paired with its source `FaceId` |
| `StreamFace` | Generic `AsyncRead`+`AsyncWrite` face (TCP, Unix sockets) |
| `TlvCodec` | `tokio_util::codec` framing for TLV byte streams |
| `CongestionController` | Per-face AIMD congestion window management |
| `AnyMap` | Type-erased extension map for per-packet metadata |
| `FaceEvent` | Face lifecycle events (up/down/created/destroyed) |

## Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `serde` | off | Derives `Serialize`/`Deserialize` on `FaceId`, `FaceKind`, and related types |

## Usage

```rust
use ndn_transport::{Face, FaceId, RawPacket};

// Implement Face for a custom transport
struct MyFace { /* ... */ }

#[async_trait::async_trait]
impl Face for MyFace {
    async fn send(&self, pkt: bytes::Bytes) -> Result<(), ndn_transport::FaceError> { todo!() }
    async fn recv(&self) -> Result<bytes::Bytes, ndn_transport::FaceError> { todo!() }
}
```

Part of the [ndn-rs](../../README.md) workspace.
