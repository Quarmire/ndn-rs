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

```rust
use ndn_app::{EmbeddedRouter, Consumer, Producer, AppError};
use ndn_packet::Name;

#[tokio::main]
async fn main() -> Result<(), AppError> {
    // Spin up an in-process forwarder.
    let router = EmbeddedRouter::start().await?;

    // Producer: register /hello and serve Data on request.
    let mut producer = router.producer("/hello").await?;
    tokio::spawn(async move {
        producer.serve(|_interest, responder| async move {
            responder.respond_bytes(b"Hello, NDN!".to_vec().into()).await.ok();
        }).await;
    });

    // Consumer: fetch /hello/world.
    let consumer = router.consumer().await?;
    let data = consumer.fetch(&"/hello/world".parse::<Name>().unwrap()).await?;
    println!("Received: {:?}", data.content());

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
