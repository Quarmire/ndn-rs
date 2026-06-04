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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keychain = KeyChain::ephemeral("/example")?;
    // connect registers the prefix; with_signer signs what we publish.
    let producer = Producer::connect("/tmp/ndn-fwd.sock", "/example")
        .await?
        .with_signer(keychain.signer()?);

    producer
        .publish_object("/example/hello".parse()?, b"hello, ndn".to_vec().into(), 0)
        .await?;

    // Keep the process alive while the forwarder serves requests.
    tokio::signal::ctrl_c().await?;
    Ok(())
}
```

`publish_object(name, content, chunk_size)` segments the object and
serves it on demand, **signing** each segment with the configured
signer (without `with_signer` it emits `DigestSha256` — integrity, not
authorship). `chunk_size == 0` uses the default segment size.

## The consumer — verify what you fetch

The producer signed its `Data`; the consumer's job is to **check that signature**
against a trust anchor it has decided to pin. Verifying is not an optional extra
step — it is how the consumer decides the data is authentic.

```rust,ignore
use ndn::prelude::*;
use ndn::{Consumer, KeyChain};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut consumer = Consumer::connect("/tmp/ndn-fwd.sock").await?;

    // Build a validator that pins the producer's certificate as a trust anchor.
    // Across processes the anchor is distributed out-of-band — a cert file, a
    // `did:ndn`, or NDNCERT enrollment; see "Identity and keys" below.
    let keychain = KeyChain::ephemeral("/consumer")?;
    keychain.add_trust_anchor(producer_cert); // the /example producer's anchor
    let validator = keychain.validator();

    // fetch_verified returns SafeData only if the signature checks out.
    let safe = consumer.fetch_verified("/example/hello", &validator).await?;
    println!("{}", String::from_utf8_lossy(safe.data().content().unwrap_or_default()));
    Ok(())
}
```

`fetch_verified` returns [`SafeData`](../concepts/identity-and-keys.md) — proof
the signature verified. The unauthenticated siblings `fetch` /  `fetch_object`
return raw `Data`/bytes and **do not check the signature**; use them only when
you are handling trust yourself (see
[Security pitfalls](../guides/security-pitfalls.md)). For a complete, runnable
signed-and-verified exchange in one file, see
[`example-secure-fetch`](./5-minute-app.md).

## What happens on the wire

The producer signs the `Data` and announces `/example/hello`. The consumer's
Interest is routed by the forwarder's FIB to the producer's face; the returned
`Data` is cached in the Content Store, so repeat calls within the cache lifetime
never reach the producer. The full PIT/FIB/CS story is in
[Interest and Data lifecycle](../concepts/interest-data-lifecycle.md).

## Signing identities

`KeyChain::ephemeral` keeps the key in memory (regenerated each run) — fine for a
demo. For a persistent identity backed by a key file, use
`KeyChain::open_or_create(path, name)`; for enrollment under a CA, see
[Identity and keys](../concepts/identity-and-keys.md). The producer signs with the
keychain's default identity unless overridden via `SigningInfo`.

## Next steps

- **Understand the trust decision** you made by pinning that anchor:
  [Trust, first](../start/trust-first.md) and
  [Trust policies](../reference/trust-policies.md).
- **Distribute anchors and enroll identities** instead of hard-coding a cert:
  [Identity and keys](../concepts/identity-and-keys.md).
- **Serve dynamic responses**, or **subscribe to a multi-publisher stream**:
  [Develop tier → Responder / Subscriber](../api/develop.md#responder).
