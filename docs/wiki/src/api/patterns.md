# Application Patterns

This page maps common application design patterns to the ndn-rs APIs that implement them. Each pattern includes the recommended crate/type, and a short code snippet showing the key call.

---

## Fetch Content Once

Fetch a named piece of content by name and wait for a response.

**API:** `ndn_app::Consumer::get` or `Consumer::fetch`

```rust
let mut consumer = Consumer::connect("/tmp/ndn.sock").await?;
let bytes = consumer.get("/example/data").await?;
```

To set a **hop limit**, **forwarding hint**, or **application parameters**, use `Consumer::fetch_with` with an `InterestBuilder`:

```rust
use ndn_packet::encode::InterestBuilder;

// Limit to 4 forwarding hops
let data = consumer.fetch_with(
    InterestBuilder::new("/ndn/remote/data").hop_limit(4)
).await?;

// Reach a producer via a delegation prefix (forwarding hint)
let data = consumer.fetch_with(
    InterestBuilder::new("/alice/files/photo.jpg")
        .forwarding_hint(vec!["/campus/ndn-hub".parse()?])
).await?;

// Parameterised fetch — ApplicationParameters triggers
// ParametersSha256DigestComponent auto-appended to the name
let data = consumer.fetch_with(
    InterestBuilder::new("/service/query")
        .app_parameters(b"filter=recent&limit=10")
).await?;
```

The local receive timeout is derived automatically from the Interest lifetime (+ 500 ms buffer). Call `fetch_wire` directly if you need a non-standard timeout.

---

## Serve Content on Demand

Register a prefix and respond to Interests with dynamically generated Data.

**API:** `ndn_app::Producer::connect` + `serve`

```rust
let mut producer = Producer::connect("/tmp/ndn.sock", "/sensor").await?;
producer.serve(|interest| async move {
    Some(DataBuilder::new((*interest.name).clone(), b"42").build())
}).await
```

---

## Subscribe to a Live Data Stream

Receive all new data published to a shared group prefix (SVS-based sync).

**API:** `ndn_app::Subscriber`

```rust
let mut sub = Subscriber::connect(
    "/tmp/ndn.sock",
    "/chat/room1",
    SubscriberConfig::default(),
).await?;
while let Some(sample) = sub.recv().await {
    println!(
        "[{}] {}",
        sample.publisher,
        String::from_utf8_lossy(&sample.payload.unwrap_or_default()),
    );
}
```

---

## Request/Response (RPC-style)

Handle request-response pairs where each reply goes only to the querying consumer.

**API:** `ndn_app::Queryable`

```rust
let mut queryable = Queryable::connect("/tmp/ndn.sock", "/compute").await?;
while let Some(query) = queryable.recv().await {
    let result = do_work(query.interest());
    query.reply(
        DataBuilder::new(query.interest().name().clone())
            .content(result.as_bytes())
            .build_unsigned(),
    ).await?;
}
```

---

## Transfer Large Content (Segmented)

Transfer content larger than a single packet, with automatic segmentation and reassembly.

**API:** `ndn_app::ChunkedProducer` + `ChunkedConsumer`

```rust
// Producer side
ChunkedProducer::connect(socket, "/files/report.pdf", &file_bytes).await?;

// Consumer side
let bytes = ChunkedConsumer::connect(socket).fetch("/files/report.pdf").await?;
```

---

## Verify Content Before Use

Fetch Data and cryptographically verify it against a trust schema before use. The `SafeData` type ensures only verified data reaches sensitive code paths.

**API:** `Consumer::fetch_verified` + `KeyChain`

```rust
let keychain = KeyChain::load_or_init("/etc/ndn/keys").await?;
let safe_data = consumer
    .fetch_verified("/example/data", &keychain.validator().await?)
    .await?;
// safe_data: SafeData — compiler-enforced proof of verification
```

---

## Embedded / Mobile (No External Router)

Run the full NDN forwarding engine inside your binary. No system daemon required.

**For Android / iOS:** use `ndn_mobile::MobileEngine` — a pre-configured wrapper with mobile-tuned defaults, lifecycle suspend/resume, and Bluetooth face support. See the [Mobile Apps guide](../guides/mobile-apps.md).

```rust
// ndn-mobile: one-liner setup, mobile-tuned defaults
use ndn_mobile::{Consumer, MobileEngine};

let (engine, handle) = MobileEngine::builder().build().await?;
let mut consumer = Consumer::from_handle(handle);
let mut producer = engine.register_producer("/my/prefix");
```

**For desktop / testing:** use `ndn_app::EngineBuilder` directly. See the [Embedded Engine section](../guides/building-ndn-apps.md#mode-2-embedded-engine).

```rust
use ndn_app::EngineBuilder;
use ndn_engine::EngineConfig;
use ndn_faces::local::InProcFace;
use ndn_transport::FaceId;

let mut builder = EngineBuilder::new(EngineConfig::default());
let app_face_id = builder.alloc_face_id();
let (face, handle) = InProcFace::new(app_face_id, 64);
let (engine, _shutdown) = builder.face(face).build().await?;
let mut consumer = ndn_app::Consumer::from_handle(handle);
```

---

## Publish State to a Sync Group

Publish local state updates to a distributed sync group; all members receive updates.

**API:** `ndn_sync::join_svs_group` + `SyncHandle`

```rust
let sync = join_svs_group(&engine, "/chat/room1", "/ndn/mynode").await?;
sync.publish(b"hello everyone".to_vec()).await?;
while let Some(update) = sync.recv().await {
    println!("from {}: {:?}", update.name, update.data);
}
```

---

## Custom Forwarding Strategy

Override the default forwarding decision for a name prefix.

**API:** `ndn_strategy::Strategy` trait + `EngineBuilder::strategy`

```rust
struct MyStrategy;
impl Strategy for MyStrategy {
    fn on_interest(&self, ctx: &StrategyContext, interest: &Interest) -> ForwardingAction {
        // Custom forwarding logic
        ForwardingAction::Forward(ctx.fib_lookup(interest.name()))
    }
    // on_nack and on_data_in omitted for brevity
}
let engine = EngineBuilder::new(config)
    .strategy("/my/prefix", MyStrategy)
    .build()
    .await?;
```

---

## Peer Discovery and Auto-FIB

Discover NDN neighbors on the local network and automatically populate the FIB.

**API:** `ndn_discovery::UdpNeighborDiscovery` + `EngineBuilder::discovery`

```rust
let discovery = UdpNeighborDiscovery::new(config)?;
let engine = EngineBuilder::new(config)
    .discovery(discovery)
    .build()
    .await?;
// FIB entries for discovered neighbors are installed automatically
```

---

## Integration Testing with Simulated Topology

Spin up a full forwarding engine in tests without any external processes or network.

**API:** `ndn_sim::Simulation`

```rust
let mut sim = Simulation::new();
let router = sim.add_router("r1");
let producer = sim.add_producer("p1", "/test");
sim.add_link(router, producer, LinkConfig::default());
let result = sim.send_interest(consumer, "/test/data").await?;
assert!(result.is_ok());
```

---

## Synchronous / Non-Async Applications

Use NDN in blocking code (Python extensions, CLI tools, non-async Rust).

**API:** `ndn_app::blocking::{BlockingConsumer, BlockingProducer}`

```rust
let mut consumer = BlockingConsumer::connect("/tmp/ndn.sock")?;
let bytes = consumer.get("/example/hello")?;
```

---

## Embedded / Constrained Devices (no_std)

Run a minimal forwarder on ARM Cortex-M or RISC-V with no heap allocator.

**API:** `ndn_embedded::Forwarder` (const-generic, no_std)

Refer to the [Embedded Targets guide](../guides/embedded-targets.md).

---

For a deeper walkthrough of the most common patterns, see [Building NDN Applications](../guides/building-ndn-apps.md).
