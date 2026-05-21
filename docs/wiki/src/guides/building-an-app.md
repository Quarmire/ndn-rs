# Building an application

This guide walks through a small but complete NDN application: a
note-taking service that publishes signed notes and answers
Interests for them. By the end you'll have used `KeyChain`,
`Producer`, `Consumer`, `Responder`, and a `TrustPolicy`.

For the 20-line warmup, see [Five-minute app](../quickstart/5-minute-app.md).

## Setup

```sh
cargo new --bin notes
cd notes
cargo add ndn-rs-prelude tokio --features tokio/full
cargo add anyhow
```

Run a forwarder in another terminal (see
[Running the forwarder](../quickstart/running-the-forwarder.md)).

## Step 1 — Create an identity

```rust,ignore
use ndn::prelude::*;
use ndn::KeyChain;

# async fn run() -> anyhow::Result<()> {
let mut keychain = KeyChain::open_default().await?;
if keychain.identity("/alice").await.is_none() {
    let id = keychain.create_identity("/alice").await?;
    println!("created identity {}", id.name());
}
# Ok(()) }
```

Idempotent: rerunning the program reuses the existing identity from
the PIB.

## Step 2 — Publish a static note

```rust,ignore
use ndn::prelude::*;
use ndn::{KeyChain, Producer};

# async fn publish(keychain: KeyChain) -> anyhow::Result<()> {
let mut producer = Producer::connect("/tmp/ndn-fwd.sock", keychain).await?;
producer.publish_object(
    "/alice/notes/2026-05-20/v=1",
    b"buy milk".to_vec(),
).await?;
# Ok(()) }
```

`publish_object` signs the note with `/alice`'s default key,
registers the prefix `/alice/notes` (the first two name components,
the application name) with the forwarder, and serves the object on
demand.

## Step 3 — Serve dynamic notes with `Responder`

A `Responder` answers each Interest with a freshly-built `Data`.
Useful when the content depends on the current time or on the
Interest's selectors.

```rust,ignore
use ndn::prelude::*;
use ndn::{KeyChain, Responder};

# async fn serve(keychain: KeyChain) -> anyhow::Result<()> {
let mut responder = Responder::connect("/tmp/ndn-fwd.sock", keychain).await?;
responder.serve("/alice/clock", |_interest| async {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    Ok::<_, anyhow::Error>(format!("{now}").into_bytes())
}).await?;
tokio::signal::ctrl_c().await?;
# Ok(()) }
```

## Step 4 — Fetch with validation

A consumer that trusts `/alice`'s key and rejects anything else:

```rust,ignore
use ndn::prelude::*;
use ndn::{Consumer, ValidationPolicy, HierarchicalPolicy};

# async fn fetch() -> anyhow::Result<()> {
let policy = HierarchicalPolicy::anchor("/alice");
let mut consumer = Consumer::connect("/tmp/ndn-fwd.sock").await?
    .with_validation(policy);

let bytes = consumer.fetch_object("/alice/notes/2026-05-20/v=1").await?;
println!("{}", String::from_utf8_lossy(&bytes));
# Ok(()) }
```

`HierarchicalPolicy::anchor("/alice")` says: accept `Data` under
`/alice/...` if its signature chains up to a key under `/alice`.

## Step 5 — Subscribe to a stream

If `/alice` is one publisher in a multi-publisher feed, use
`Subscriber`:

```rust,ignore
use ndn::prelude::*;
use ndn::{Subscriber, SubscriberConfig};

# async fn sub() -> anyhow::Result<()> {
let mut sub = Subscriber::connect(
    "/tmp/ndn-fwd.sock",
    SubscriberConfig::new("/team/notes"),
).await?;
while let Some(sample) = sub.next().await {
    println!("{}: {} bytes", sample.publisher(), sample.content().len());
}
# Ok(()) }
```

In v0.1.0 `Subscriber` is read-only — see
`docs/notes/api-completeness-check-2026-05-20.md` GAP-5 for the
write-path follow-up.

## Step 6 — Run the engine in-process

For tests or "talk to yourself" scenarios:

```rust,ignore
use ndn::prelude::*;
use ndn::{Consumer, InProcConnection};
use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_faces::local::InProcFace;
use ndn_transport::FaceId;

# async fn embed() -> anyhow::Result<()> {
let (face, handle) = InProcFace::new(FaceId(1), 64);
let (_engine, _shutdown) = EngineBuilder::new(EngineConfig::default())
    .face(face)
    .build()
    .await?;
let mut consumer = Consumer::new(InProcConnection::from_handle(handle));
let _ = consumer.fetch("/alice/clock").await?;
# Ok(()) }
```

The Develop tier deliberately keeps `EngineBuilder` outside the
umbrella — see [Develop tier → embedded engine](../api/develop.md#embedded-engine).

## Where each piece lives

| Concern | Type | Crate |
|---|---|---|
| Identity, keys, signing | `KeyChain`, `SigningInfo` | `ndn-security` |
| Publishing | `Producer`, `Responder` | `ndn-app` |
| Fetching | `Consumer` | `ndn-app` |
| Subscribing | `Subscriber` | `ndn-app` |
| Validation | `ValidationPolicy`, `HierarchicalPolicy`, `LvsTrust` | `ndn-security` |
| Connection | `IpcConnection`, `InProcConnection` | `ndn-app` |

## What to read next

- [NDNCERT setup](./ndncert-setup.md) — automate cert issuance for
  apps instead of self-signed identities.
- [Trust policies](../reference/trust-policies.md) — write a custom
  policy.
- [Develop tier](../api/develop.md) — full API surface.
- [Logging](../operations/logging.md) — observe what your app is
  doing inside the forwarder.
