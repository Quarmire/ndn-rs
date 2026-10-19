# ndn-ipc

Connects application processes to the NDN forwarder over Unix sockets, with an optional shared-memory SPSC ring buffer for high-throughput data paths. Provides chunked transfer for objects larger than a single NDN packet, and a local service registry for prefix advertisement and lookup.

## Key Types

| Type / Trait | Role |
|---|---|
| `IpcClient` | Unix-socket client endpoint for app-to-forwarder communication |
| `IpcServer` | Unix-socket server endpoint (used by the forwarder) |
| `RouterClient` | Ergonomic wrapper around `IpcClient` for common app operations |
| `MgmtClient` | Control-plane client — sends NFD management commands to the forwarder |
| `events::EventSubscription` | Follows the daemon's trust or links change notifications in order, on a connection of its own (resync on a gap; see `docs/specs/mgmt-trust.md` § Notifications) |
| `ChunkedProducer` | Segments a large object and serves it over NDN |
| `ChunkedConsumer` | Reassembles a segmented object from multiple Data packets |
| `ServiceRegistry` | Local service advertisement and prefix lookup |

## Feature Flags

| Flag | Default | Description |
|---|---|---|
| `spsc-shm` | yes | Enables SPSC shared-memory ring-buffer transport via `ndn-face-local` |

## Usage

```rust
use ndn_ipc::RouterClient;

let client = RouterClient::connect("/run/nfd/nfd.sock").await?;
client.register_prefix(&"/myapp/data".parse()?).await?;
```

Part of the [ndn-rs](../../README.md) workspace.
