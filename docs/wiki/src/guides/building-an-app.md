# Building an application

This guide walks through a small but complete NDN application: a
note-taking service that publishes signed notes and answers Interests for
them. By the end you'll have used one `Node`, a `KeyChain`, a `Validator`,
and the signed-producer escape hatch.

For the 30-second warmup, see [Five-minute app](../quickstart/5-minute-app.md).

## Setup

ndn-rs is not on crates.io; the front door is one git dependency on the
`ndn-rs-prelude` package (library name `ndn`):

```sh
cargo new --bin notes
cd notes
```

`Cargo.toml`:

```toml
[dependencies]
ndn = { package = "ndn-rs-prelude", git = "https://github.com/Quarmire/ndn-rs", tag = "v0.1.0-alpha.3" }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
anyhow = "1"
```

Working inside the ndn-workspace checkout? Use a path dependency instead:

```toml
ndn = { package = "ndn-rs-prelude", path = "../ndn-rs/crates/app/ndn-rs-prelude" }
```

Run a forwarder in another terminal (see
[Running the forwarder](../quickstart/running-the-forwarder.md) — it lives
in the sibling repo ndn-fwd). For tests, or to skip the external process
entirely, you can instead embed the engine in-process — see
[Step 6](#step-6--run-the-engine-in-process).

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

## Step 2 — Connect a Node

`Node` is the one handle the rest of this guide uses — every pattern
(`fetch` / `serve` / `object` / `publish` / `subscribe` / `query`) runs over
it. Point it at the forwarder's management/face socket (the path configured
under `[management] face_socket`; `/run/ndn-fwd/ndn-fwd.sock` with the
shipped default config):

```rust,ignore
use ndn::prelude::*;
use ndn::Node;

# async fn run() -> anyhow::Result<()> {
let node = Node::connect("/run/ndn-fwd/ndn-fwd.sock").await?;
# Ok(()) }
```

## Step 3 — Serve dynamic notes

`serve` registers the prefix and runs your handler for each matching
Interest. Serving stops when the returned guard drops.

```rust,ignore
# async fn serve(node: ndn::Node) -> anyhow::Result<()> {
let _guard = node.serve("/alice/clock", |interest, reply| async move {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let _ = reply.respond((*interest.name).clone(), format!("{now}")).await;
}).await?;
tokio::signal::ctrl_c().await?;
# Ok(()) }
```

## Step 4 — Publish a signed note

`node.serve_object(name, content)` serves static content, but its segments
are `DigestSha256` — integrity, not authorship. To **sign** what you
publish, drop one level to the `Producer` building block via the escape
hatch and give it the identity's signer:

```rust,ignore
use ndn::Producer;

# async fn publish(node: ndn::Node, keychain: ndn::KeyChain) -> anyhow::Result<()> {
let producer = Producer::new(node.connection(), "/alice/notes".parse()?)
    .with_signer(keychain.signer()?);
producer
    .publish_object("/alice/notes/2026-05-20/v=1".parse()?, b"buy milk".to_vec().into(), 0)
    .await?;
# Ok(()) }
```

`with_signer` makes `publish_object` sign each segment with `/alice`'s key;
the object is then served on demand, and consumers can verify authorship.

## Step 5 — Fetch with validation

A consumer that trusts `/alice`'s key and rejects anything else. Decide
trust once with `verifying`; the short verb then returns
[`SafeData`](../concepts/identity-and-keys.md) — proof the signature
checked out.

```rust,ignore
use ndn::{Node, Validator};
use ndn::security::{Certificate, TrustSchema};

# async fn fetch(node: ndn::Node, alice_cert: Certificate) -> anyhow::Result<()> {
// Pin /alice's certificate as a trust anchor; accept only what chains to it.
let validator = Validator::new(TrustSchema::hierarchical());
validator.add_trust_anchor(alice_cert);

let safe = node.verifying(validator).fetch("/alice/notes/today").await?;
println!("{}", String::from_utf8_lossy(safe.data().content().unwrap_or_default()));
# Ok(()) }
```

A hierarchical schema says: accept `Data` under `/alice/...` if its
signature chains up to a key under `/alice`. The bare `node.fetch(name)`
returns raw, **unverified** `Data`; prefer the verifying path. See
[Security pitfalls](./security-pitfalls.md).

## Step 6 — Publish into / subscribe to a shared feed

If `/alice` is one publisher in a multi-publisher feed, use the sync
patterns — both run on the same `Node`:

```rust,ignore
# async fn sub(node: ndn::Node) -> anyhow::Result<()> {
let publisher = node.publish("/team/notes", "/alice").await?;
publisher.put(b"buy milk").await?;

let mut sub = node.subscribe("/team/notes", "/alice").await?;
while let Some(sample) = sub.recv().await {
    println!("{}: {:?}", sample.publisher, sample.payload);
}
# Ok(()) }
```

## Step 6b — Run the engine in-process {#step-6--run-the-engine-in-process}

For tests or "talk to yourself" scenarios there is no forwarder process at
all — build the engine in-process and mint full `Node`s from it (this is
exactly what `examples/hello-node` does):

```rust,ignore
use ndn::{EngineAppExt, EngineBuilder, EngineConfig, Node};
use tokio_util::sync::CancellationToken;

# async fn embed() -> anyhow::Result<()> {
let (engine, shutdown) = EngineBuilder::new(EngineConfig::default()).build().await?;
let cancel = CancellationToken::new();
let alice: Node = engine.app_node(cancel.child_token());
let bob: Node = engine.app_node(cancel.child_token());
// alice.serve(...) / bob.fetch(...) exactly as above
# Ok(()) }
```

## Where each piece lives

Everything below arrives through the one `ndn` dependency (package
`ndn-rs-prelude`); the source crates are listed for orientation.

| Concern | Type | Source crate |
|---|---|---|
| The app surface | `Node` (+ `Consumer`, `Producer`, `Subscriber`, …) | `ndn-app` (`crates/app/ndn-app`) |
| Identity, keys, signing | `KeyChain`, `SigningInfo` | `ndn-security` (`crates/security/ndn-security`) |
| Validation | `Validator`, `TrustSchema`, `SafeData` | `ndn-security` |
| Embedded engine | `EngineBuilder`, `EngineAppExt` | `ndn-engine` / `ndn-app` |
| Packets | `Name`, `Interest`, `Data`, builders | `ndn-packet` (`crates/core/ndn-packet`) |

## What to read next

- [The Node cookbook](../api/node-cookbook.md) — every `Node` pattern,
  including objects (RDR), typed objects, and query.
- [NDNCERT setup](./ndncert-setup.md) — automate cert issuance for apps
  instead of self-signed identities.
- [Trust policies](../reference/trust-policies.md) — write a custom policy.
- [Develop tier](../api/develop.md) — full API surface.
- [Logging](../operations/logging.md) — observe what your app is doing
  inside the forwarder.
