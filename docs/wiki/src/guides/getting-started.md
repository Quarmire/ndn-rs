# Getting Started — Publish and Subscribe

This guide shows the two main ways to use ndn-rs:

1. **Embedded** — forwarder runs inside your process (no IPC, ~20 ns round-trip)
2. **External** — connect to a running `ndn-fwd` via Unix socket

Both modes share the same `Consumer`, `Producer`, and `Subscriber` API from `ndn-app`.

---

## Prerequisites

```toml
# Cargo.toml
[dependencies]
ndn-app = "0.1"
tokio   = { version = "1", features = ["full"] }
```

---

## Mode 1: Embedded (in-process forwarder)

No external router needed — ideal for testing, mobile apps, and embedded targets.
The engine runs inside your process; `InProcFace` pairs replace IPC.

```rust
use ndn_app::{Consumer, EngineBuilder, Producer};
use ndn_engine::EngineConfig;
use ndn_faces::local::InProcFace;
use ndn_packet::{Name, encode::DataBuilder};
use ndn_transport::FaceId;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Create in-process face pairs: one for the consumer, one for the producer.
    let (consumer_face, consumer_handle) = InProcFace::new(FaceId(1), 64);
    let (producer_face, producer_handle) = InProcFace::new(FaceId(2), 64);

    // 2. Build the forwarding engine with both faces.
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(consumer_face)
        .face(producer_face)
        .build()
        .await?;

    // 3. Route Interests for /hello → the producer face.
    let prefix: Name = "/hello".parse()?;
    engine.fib().add_nexthop(&prefix, FaceId(2), 0);

    // 4. Producer: serve Data on request.
    let producer = Producer::from_handle(producer_handle, prefix.clone());
    tokio::spawn(async move {
        producer.serve(|interest, responder| {
            let name = (*interest.name).clone();
            async move {
                let wire = DataBuilder::new(name, b"Hello, NDN!").build();
                responder.respond_bytes(wire).await.ok();
            }
        }).await
    });

    // 5. Consumer: fetch /hello/world.
    let mut consumer = Consumer::from_handle(consumer_handle);
    let data = consumer.fetch("/hello/world").await?;
    println!("Received: {:?}", data.content());

    shutdown.shutdown().await;
    Ok(())
}
```

---

## Mode 2: External (connect to ndn-fwd)

Start the forwarder first:

```bash
ndn-fwd --config /etc/ndn-fwd/config.toml
# or: ndn-fwd  # uses /tmp/ndn.sock by default
```

Then connect from your app:

```rust
use ndn_app::{Consumer, Producer, AppError};
use ndn_packet::Name;

const SOCKET: &str = "/tmp/ndn.sock";

#[tokio::main]
async fn main() -> Result<(), AppError> {
    // Producer side.
    let mut producer = Producer::connect(SOCKET, "/hello").await?;
    tokio::spawn(async move {
        producer.serve(|_interest, responder| async move {
            responder.respond_bytes(b"Hello from ndn-fwd!".to_vec().into()).await.ok();
        }).await;
    });

    // Consumer side (separate connection).
    let consumer = Consumer::connect(SOCKET).await?;
    let name: Name = "/hello/world".parse().unwrap();
    let data = consumer.fetch(&name).await?;
    println!("Received: {:?}", data.content());

    Ok(())
}
```

---

## Publish/Subscribe (SVS sync)

`Subscriber` uses State Vector Sync to discover new publications without polling.

```rust
use ndn_app::Subscriber;

let mut sub = Subscriber::connect("/tmp/ndn.sock", "/chat/room1").await?;

while let Some(sample) = sub.recv().await {
    println!("[{}] seq={}: {:?}", sample.publisher, sample.seq, sample.payload);
}
```

To use PSync instead of SVS:

```rust
let mut sub = Subscriber::connect_psync("/tmp/ndn.sock", "/chat/room1").await?;
```

---

## Next Steps

- [Building NDN Apps](building-ndn-apps.md) — in-depth guide with error handling, signing, chunked transfer
- [CLI Tools](cli-tools.md) — `ndn-peek`, `ndn-put`, `ndn-ping` usage
- [Implementing a Face](implementing-face.md) — add a new transport
- [Performance Tuning](performance-tuning.md) — SHM transport, CS sizing, pipeline threads
