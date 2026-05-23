# Ten-minute producer

This page extends the [Five-minute app](./5-minute-app.md) into a
producer/consumer pair: one process serves a `Data`, another fetches
it.

## Prerequisites

A running forwarder at `/tmp/ndn-fwd.sock`. See
[Running the forwarder](./running-the-forwarder.md).

## The producer

```rust,ignore
use ndn::prelude::*;
use ndn::{KeyChain, Producer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let keychain = KeyChain::open_default().await?;
    let mut producer = Producer::connect("/tmp/ndn-fwd.sock", keychain).await?;

    producer.publish_object(
        "/example/hello",
        b"hello, ndn".to_vec(),
    ).await?;

    // Keep the process alive while the forwarder serves requests.
    tokio::signal::ctrl_c().await?;
    Ok(())
}
```

`publish_object` is the RDR-shaped publish verb in
`crates/ndn-app/src/producer.rs`. It signs the `Data` with the
default identity from the `KeyChain`, registers the name prefix with
the forwarder, and serves the segmented object on demand.

## The consumer

```rust,ignore
use ndn::prelude::*;
use ndn::Consumer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut consumer = Consumer::connect("/tmp/ndn-fwd.sock").await?;
    let bytes = consumer.fetch_object("/example/hello").await?;
    println!("{}", String::from_utf8_lossy(&bytes));
    Ok(())
}
```

`fetch_object` reassembles segmented `Data` from RDR metadata. For a
single packet, `fetch` is sufficient (see
[Five-minute app](./5-minute-app.md)).

## What happens on the wire

1. Producer signs the `Data` and announces `/example/hello` to the
   forwarder.
2. Consumer expresses an Interest for `/example/hello`.
3. Forwarder consults its FIB, finds the producer's face, forwards
   the Interest.
4. Producer hands back the `Data`. Forwarder caches it in the
   Content Store and returns it to the consumer.
5. Repeat consumer calls within the cache lifetime never reach the
   producer.

The cache + PIT/FIB story is in
[Interest and Data lifecycle](../concepts/interest-data-lifecycle.md).

## Signing identities

The `KeyChain::open_default` call uses the operating-system PIB
(`~/.ndn/pib.db` by default). For first-run setup or temporary keys,
see [Identity and keys](../concepts/identity-and-keys.md). The
producer signs with the default identity unless overridden via
`SigningInfo`.

## Next steps

- **Trust on the consumer side** — verify the producer's signature
  by configuring a `TrustPolicy`:
  [Trust policies](../reference/trust-policies.md).
- **Serve dynamic responses** instead of static bytes — use
  `Responder` for closure-style producers:
  [Develop tier → Responder](../api/develop.md#responder).
- **Subscribe to a multi-publisher stream** with `Subscriber`
  (SVS-style): [Develop tier → Subscriber](../api/develop.md#subscriber).
