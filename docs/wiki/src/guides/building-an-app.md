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

# fn run() -> anyhow::Result<()> {
// Generates the key + self-signed cert for `/alice` on first run; reloads it
// from the file-backed PIB on every run after.
let keychain = KeyChain::open_or_create("/var/lib/ndn/pib".as_ref(), "/alice")?;
println!("identity {}", keychain.name());
# Ok(()) }
```

Idempotent: a `KeyChain` *is* one identity, and `open_or_create` reuses the
existing key from the PIB on reruns. (For a throwaway in-memory identity, use
`KeyChain::ephemeral("/alice")`.)

## Step 2 — Publish a static note

```rust,ignore
use ndn::prelude::*;

# async fn publish(keychain: KeyChain) -> anyhow::Result<()> {
let producer = Producer::connect("/tmp/ndn-fwd.sock", "/alice/notes")
    .await?
    .with_signer(keychain.signer()?);
producer
    .publish_object("/alice/notes/2026-05-20/v=1".parse()?, b"buy milk".to_vec().into(), 0)
    .await?;
# Ok(()) }
```

`connect` registers the prefix `/alice/notes`; `with_signer` makes
`publish_object` **sign** each segment with `/alice`'s key (without it,
the object would be `DigestSha256` only). The object is served on
demand.

## Step 3 — Serve dynamic notes with `Responder`

`Producer::serve` answers each Interest with a freshly-built `Data` via
a `Responder`. Useful when the content depends on the current time or
the Interest's selectors. With a signer configured, `respond` signs.

```rust,ignore
use ndn::prelude::*;

# async fn serve(keychain: KeyChain) -> anyhow::Result<()> {
let producer = Producer::connect("/tmp/ndn-fwd.sock", "/alice/clock")
    .await?
    .with_signer(keychain.signer()?);
producer.serve(|interest, responder| async move {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // `respond` signs the reply with the configured signer.
    responder.respond((*interest.name).clone(), format!("{now}").into_bytes()).await.ok();
}).await?;
tokio::signal::ctrl_c().await?;
# Ok(()) }
```

## Step 4 — Fetch with validation

A consumer that trusts `/alice`'s key and rejects anything else:

```rust,ignore
use ndn::Consumer;
use ndn_security::{Certificate, TrustSchema, Validator};

# async fn fetch(alice_cert: Certificate) -> anyhow::Result<()> {
// Pin /alice's certificate as a trust anchor; accept only what chains to it.
let validator = Validator::new(TrustSchema::hierarchical());
validator.add_trust_anchor(alice_cert);

let mut consumer = Consumer::connect("/tmp/ndn-fwd.sock").await?;

// `fetch_verified` returns `SafeData` only if the signature verifies and the
// schema accepts it. Prefer it over the bare `fetch`, which returns unverified
// `Data`. (Need to decide per call? `fetch_unverified` returns `Unverified<Data>`,
// which forces an explicit `.verify(&validator)` or a loud `.trust_unchecked()`.)
let safe = consumer.fetch_verified("/alice/notes/today", &validator).await?;
println!("{}", String::from_utf8_lossy(safe.data().content().unwrap_or_default()));
# Ok(()) }
```

A hierarchical schema says: accept `Data` under `/alice/...` if its
signature chains up to a key under `/alice`.

## Step 5 — Subscribe to a stream

If `/alice` is one publisher in a multi-publisher feed, use
`Subscriber`:

```rust,ignore
use ndn::prelude::*;
use ndn::Subscriber;

# async fn sub() -> anyhow::Result<()> {
let mut sub = Subscriber::connect("/tmp/ndn-fwd.sock", "/team/notes").await?;
while let Some(sample) = sub.recv().await {
    println!("{}: {:?}", sample.publisher, sample.payload);
}
# Ok(()) }
```

In v0.1.0 `Subscriber` is read-only; sync-group publishing is
filed for v0.1.x.

## Step 6 — Run the engine in-process

For tests or "talk to yourself" scenarios:

```rust,ignore
use ndn::prelude::*;
use ndn::{Consumer, InProcConnection};
use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face::local::InProcFace;
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
