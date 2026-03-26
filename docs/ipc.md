# NDN as IPC

## Why NDN for IPC

NDN's name-based decoupling solves real IPC problems:
- **Late binding**: producers don't need to know consumers, consumers don't need to know locations
- **Data outlives producers**: CS means a producer that ran and exited can still satisfy consumers — no traditional IPC mechanism provides this
- **PIT aggregation**: ten processes expressing the same Interest generate one lookup
- **Multicast-by-default**: the same data consumed by N processes without the producer scaling

NDN IPC is strongest when you need at least one of: discovery without prior producer knowledge, data that outlives the producer, data consumed by multiple processes without producer scaling, or seamless transparency between local and remote data sources.

For processes that know at compile time they will communicate and do not need NDN properties, a direct `tokio::sync::mpsc` channel is simpler and faster.

## IPC Transport Tiers

| Scenario | Transport | Latency |
|----------|-----------|---------|
| Same process | `tokio mpsc` + `Arc<DecodedPacket>` | ~20 ns |
| Cross-process | iceoryx2 Data + mpsc Interest | ~150 ns |
| Cross-process high-perf | hand-rolled SPSC ring buffer | ~80 ns |

A hand-rolled SPSC ring buffer with service discovery, crash detection, and flow control is essentially iceoryx2. Draw the line: use iceoryx2 for cross-process and mpsc for in-process.

## iceoryx2 — Cross-Process Zero-Copy

iceoryx2 is a zero-copy IPC middleware from automotive (AUTOSAR). The Rust rewrite is a first-class citizen. Its pub-sub model maps well to the Data delivery direction (engine → application) but is awkward for Interests (request-response correlation needed).

**Two services for variable NDN packet sizes**:

```rust
let interest_service = node
    .service_builder(&ServiceName::new("ndn/interests")?)
    .publish_subscribe::<[u8]>()
    .max_slice_len(512)   // covers all realistic Interests
    .create()?;

let data_service = node
    .service_builder(&ServiceName::new("ndn/data")?)
    .publish_subscribe::<[u8]>()
    .max_slice_len(9000)  // NDN MTU + headroom
    .create()?;
```

**Zero-copy delivery**:

```rust
async fn deliver_to_app(&self, data: &Data, publisher: &Publisher<[u8]>) -> Result<()> {
    let wire = data.raw.as_ref();
    let mut sample = publisher.loan_slice_uninit(wire.len())?;
    sample.payload_mut().copy_from_slice(wire); // write directly into shared memory
    let sample = unsafe { sample.assume_init() };
    sample.send()?;
    Ok(())
}
```

The application receives a `SampleMut` — a direct reference into the shared memory segment. No copy from engine to application. For an 8800-byte video segment, iceoryx2 saves ~8–10 µs vs Unix socket copy cost.

## Chunked Transfer (Large Payloads)

NDN's 8800-byte MTU is a networking constraint, not an IPC constraint. For megabyte payloads, implement chunked transfer as a library layer above the engine.

The IPC API presents `send(name, bytes)` / `recv(name) -> Bytes` — handles segmentation and reassembly internally. The CS handles the rest: a second consumer fetching the same named payload gets all segments from cache without the producer being involved. This is fundamentally better than pipes or sockets — the producer can be a batch job that ran once, and consumers can retrieve the result later.

## Push Notifications (Standing Interests)

NDN is pull-only at the wire level. Push patterns are implemented with standing Interests:

```rust
// consumer — registers standing subscription
app_face.subscribe("/ipc/sensor/temperature", |data| {
    println!("temp update: {:?}", data);
}).await?;

// producer — satisfies the standing Interest whenever it has new data
loop {
    let reading = sensor.read().await;
    app_face.notify("/ipc/sensor/temperature", reading.encode()).await?;
}
```

Internally `subscribe` expresses a renewable Interest held in the PIT indefinitely. When `notify` is called, the engine finds the standing PIT entry and satisfies it immediately — PIT lookup and a channel send, no network round-trip. The callback fires within microseconds.

After the satisfied Interest is consumed, `subscribe` automatically re-expresses it so the next notification is ready.

This is entirely implemented in the application library layer on top of the existing `AppFace` — almost no engine changes required.

## Push Approaches for Long-Running Computations

**Approach A — Standing Interests**: Good for low-frequency events. Limitation: PIT entry occupies memory for its full lifetime; producer crash leaves consumer hanging until timeout.

**Approach B — Versioned namespace**: Producer publishes `/compute/job=abc/status/v=1`, then `/v=2`, etc. Consumer always expresses Interest for the next version with `MustBeFresh=true`. Clean, robust to producer crashes — consumer detects staleness when new versions stop appearing. CS caches each status update.

**Approach C — `Nack(NotYet, retry_after)`**: Producer's forwarder sends a Nack with a `retry_after` hint in milliseconds. Consumer respects the hint before re-expressing — eliminates wasted re-expressions during a long computation phase. Requires a `retry_after` field in the Nack TLV and a timer in the consumer's pending Interest table.

**Approach D — Notification Interest** (push inversion): When the producer has something to say, it expresses an Interest to the consumer's prefix: `/consumer/abc/notify/job=abc/status=complete`. The consumer registered that prefix and receives the Interest as a notification, then fetches the result via a normal Interest. Stays entirely within NDN semantics. Maps cleanly onto long-running compute: when training completes, the compute node sends `/client/xyz/ready/job=abc`, the client receives it, and expresses `/compute/train/job=abc/result`.

## Service Registry

Services register presence by producing Data:
- `/local/services/<servicename>/info` — `ServiceDescriptor` (capabilities, version)
- `/local/services/<servicename>/alive` — heartbeat, short freshness period

Discovery: express `/local/services` with `CanBePrefix=true` — CS returns all registered service descriptors.

When a service exits its face is closed by the engine, removing its FIB entries. Its heartbeat stops being refreshed and expires from the CS naturally. No separate daemon, no registration protocol, no SPOF.

## Local Trust for IPC

For local faces, replace crypto signature verification with **process identity**. Capture credentials at `AppFace` connection time via `SO_PEERCRED`:

```rust
pub struct FaceCredentials {
    pub pid:              u32,
    pub uid:              u32,
    pub gid:              u32,
    pub allowed_prefixes: Vec<Name>,
}
```

A `LocalTrustStage` enforces prefix authorization: a process connecting as uid 1000 cannot produce Data under `/system/`. Data from local faces is **not forwarded to remote faces** — prevents local IPC processes from injecting data into the network-facing forwarding plane.

## `ndn-ipc` Crate

Sits above `ndn-app` and provides ergonomic IPC API:
- `IpcServer` — expose a named service
- `IpcClient` — consume a named service
- `ChunkedProducer` / `ChunkedConsumer` — large payload transfer
- `ServiceRegistry` — maps service names to name prefixes
- `subscribe()` / `notify()` — push notification patterns

The engine itself is unchanged — this is entirely application-layer.
