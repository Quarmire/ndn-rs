# The `Node` cookbook

`Node` is the one entry point an application reaches for. It owns a single
forwarder handle and exposes every NDN application pattern over it with one
NDN-native vocabulary — `fetch`, `serve`, `object`, `publish`, `subscribe`,
`query`. Each recipe below is one pattern; they all run on the same `Node`.

The per-pattern types (`Consumer`, `Producer`, `Publisher`, `Subscriber`,
`Queryable`) remain available as lower-level building blocks via
[`Node::connection`](#escape-hatch); `Node` is the surface most apps want.

## Connect

```rust,ignore
use ndn::prelude::*;
use ndn::Node;

# async fn run() -> Result<(), ndn::AppError> {
let node = Node::connect("/run/nfd/nfd.sock").await?;
# Ok(()) }
```

`Node::connect` is the full node: because it can re-dial, every pattern is
available. A `Node::from_connection(conn)` built from a single pre-made
connection serves `fetch` / `object` / `serve`, but the patterns that need their
own stream (`publish` / `subscribe` / `query` / `serve_object`) return
`AppError::Unsupported` — use [`connection()`](#escape-hatch) for those. (One
connection multiplexes `fetch` and `serve` with no cross-talk; the sync and
query patterns each get a dedicated connection to the same forwarder.)

## Fetch one Data

```rust,ignore
# async fn run(node: ndn::Node) -> Result<(), ndn::AppError> {
let data = node.fetch("/peer/greeting").await?;        // unverified
println!("{} bytes", data.content().map(|c| c.len()).unwrap_or(0));
# Ok(()) }
```

## Fetch, verified

Decide trust once with `verifying`; then `fetch` returns `SafeData` — proof the
signature checked out.

```rust,ignore
# async fn run(node: ndn::Node, validator: ndn::Validator) -> Result<(), ndn::AppError> {
let safe = node.verifying(validator).fetch("/peer/greeting").await?;
# let _ = safe; Ok(()) }
```

## Fetch an object (RDR)

`object(name)` is a fluent builder for a (possibly segmented) RDR object. Chain
the modifiers, then a terminal verb. This replaces the old `fetch_object_*`
method family.

```rust,ignore
# async fn run(node: ndn::Node, validator: ndn::Validator) -> Result<(), ndn::AppError> {
// simple — whole object in memory
let bytes = node.object("/alice/photo").fetch().await?;

// verified + forwarding hint + a progress bar
let bytes = node.object("/alice/photo")
    .verify(validator)
    .hint(["/gateway"])
    .progress(|done, total| eprintln!("{done}/{total}"))
    .fetch().await?;
# let _ = bytes; Ok(()) }
```

Terminal verbs pick the delivery shape:

| Verb | Returns | Memory | Notes |
|---|---|---|---|
| `.fetch()` | `Bytes` | whole object | reassembled in order |
| `.stream(have, on_segment)` | `u64` (size) | flat | per-segment; `have(seg)` skips for resume |
| `.to_file(&file)` | `u64` (bytes) | flat | positioned writes; unix; requires `.verify()` |

## Serve dynamic content

`serve` registers a prefix and runs the handler for each matching Interest,
concurrently with any fetches on the same `Node`. Serving stops when the
returned guard is dropped. The handler gets the `Interest` and a `Responder`.

```rust,ignore
# async fn run(node: ndn::Node) -> Result<(), ndn::AppError> {
let _guard = node.serve("/alice/notes", |interest, reply| async move {
    let body = format!("note for {}", &*interest.name);
    let _ = reply.respond((*interest.name).clone(), body).await;
}).await?;
// ... keep _guard alive while serving ...
# Ok(()) }
```

## Serve a static object or file

```rust,ignore
# async fn run(node: ndn::Node) -> Result<(), ndn::AppError> {
let _g = node.serve_object("/alice/notes/today", "buy milk").await?;
# #[cfg(unix)]
let _g = node.serve_file("/alice/share/big.bin", "/path/to/big.bin").await?;
# Ok(()) }
```

Segments are `DigestSha256` (unsigned). For **signed** serving, build a
`Producer` with a signer from [`connection()`](#escape-hatch).

## Publish / subscribe (dataset sync)

```rust,ignore
# async fn run(node: ndn::Node) -> Result<(), ndn::AppError> {
let publisher = node.publish("/svs/chatroom", "/alice").await?;
publisher.put(b"hello room").await?;

let subscriber = node.subscribe("/svs/chatroom", "/alice").await?;
// while let Some(sample) = subscriber.recv().await { ... }
# Ok(()) }
```

## Query responder

```rust,ignore
# async fn run(node: ndn::Node) -> Result<(), ndn::AppError> {
let queryable = node.query("/alice/svc").await?;
// while let Some(q) = queryable.recv().await { q.reply(answer).await?; }
# Ok(()) }
```

## Typed objects (feature `serde`)

With `ndn-app`'s `serde` feature, objects (de)serialize as JSON Content:

```rust,ignore
# async fn run(node: ndn::Node, validator: ndn::Validator) -> Result<(), ndn::AppError> {
# #[derive(serde::Serialize, serde::Deserialize)] struct Profile { name: String }
let me = Profile { name: "alice".into() };
let _g = node.serve_object_typed("/alice/profile", &me).await?;

let them: Profile = node.object("/bob/profile").verify(validator).fetch_as().await?;
# let _ = them; Ok(()) }
```

## In-process — no sockets (tests, mobile, browser)

Two `Node`s on one embedded engine talk to each other with no forwarder process.
Ideal for tests.

```rust,ignore
use ndn::{EngineAppExt, EngineBuilder};
use ndn_engine::EngineConfig;
use tokio_util::sync::CancellationToken;

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let (engine, _shutdown) = EngineBuilder::new(EngineConfig::default()).build().await?;
let cancel = CancellationToken::new();
let alice = engine.app_node(cancel.child_token());
let bob   = engine.app_node(cancel.child_token());

let _g = alice.serve("/alice", |i, r| async move {
    let _ = r.respond((*i.name).clone(), "hi").await;
}).await?;
let data = bob.fetch("/alice/greeting").await?;   // routes engine → FIB → alice
# let _ = data; Ok(()) }
```

In-process nodes are `from_connection`-style, so the dedicated-stream patterns
(`publish` / `subscribe` / `query` / `serve_object`) report `Unsupported`;
`fetch` / `object` / `serve` cover the harness.

## Escape hatch {#escape-hatch}

`node.connection()` returns the underlying multiplexed `Connection`, so you can
drop to the lower-level `Consumer` / `Producer` / `Publisher` / … building
blocks — for a signer, a custom congestion strategy, or anything `Node` doesn't
surface.

```rust,ignore
# async fn run(node: ndn::Node, keychain: ndn::KeyChain) -> Result<(), Box<dyn std::error::Error>> {
use ndn::Producer;
let signed = Producer::new(node.connection(), "/alice/notes".parse()?)
    .with_signer(keychain.signer()?);
# let _ = signed; Ok(()) }
```

## See also

- [Develop tier](./develop.md) — the full type inventory behind `Node`.
- [Building an application](../guides/building-an-app.md) — end-to-end guide.
