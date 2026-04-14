# ndn-app

High-level Consumer, Producer, and Subscriber APIs for NDN applications. Supports two connection modes: connecting to a running `ndn-fwd` forwarder over a Unix socket, or running an embedded forwarder entirely in-process (useful for mobile/embedded targets). `KeyChain` handles identity and packet signing.

## Key Types

| Type / Trait | Role |
|---|---|
| `Consumer` | Fetch named data; retries, timeout, and optional signing |
| `Producer` | Serve named data under a registered prefix |
| `Subscriber` | Pub/sub stream of `Sample` values over SVS sync |
| `Queryable` / `Query` | RPC-style request/reply pattern |
| `KeyChain` | Identity store — sign Interests/Data and manage keys |
| `AppFace` | In-process channel pair connecting an app to the embedded engine |
| `NdnConnection` | Low-level Unix-socket connection to an external router |
| `AppError` | Unified error type for the application layer |

## Feature Flags

| Flag | Default | Description |
|---|---|---|
| `blocking` | no | Adds synchronous (blocking) wrappers via `tokio::runtime` |

## Usage

```rust
// Connect to a running ndn-fwd forwarder
use ndn_app::Consumer;
let mut consumer = Consumer::connect("/run/nfd/nfd.sock").await?;
let data = consumer.fetch("/example/data").await?;

// Or run embedded
use ndn_app::{Consumer, Producer, EngineBuilder};
use ndn_engine::EngineConfig;
use ndn_face_local::AppFace;
use ndn_transport::FaceId;

let (consumer_face, consumer_handle) = AppFace::new(FaceId(1), 64);
let (engine, _shutdown) = EngineBuilder::new(EngineConfig::default())
    .face(consumer_face)
    .build().await?;
let mut consumer = Consumer::from_handle(consumer_handle);
```

Part of the [ndn-rs](../../README.md) workspace.
