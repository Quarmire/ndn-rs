# Five-minute app

> **Security is step one, not a hardening pass.** In NDN the signature check is
> the precondition for accepting data at all — so this first app *signs and
> verifies*, rather than leaving it for later. The one-paragraph "why" is
> [Trust, first](../start/trust-first.md); the mistakes to avoid are in
> [Security pitfalls](../guides/security-pitfalls.md).

This page gets you from `cargo new` to a complete, **verified** exchange: a
producer signs one `Data` with its identity, a consumer fetches it and accepts it
only after the signature checks out against a pinned trust anchor.

## Run it

The whole exchange is one runnable file — no external forwarder, engine in-process:

```sh
cargo run -p example-secure-fetch
```

```text
verified: 21 bytes under /demo/alice/thing — signature checked against /demo/alice
explicit path: same Data verifies too
```

The source is `examples/secure-fetch/src/main.rs` in the repository.

## The three lines that are the point

```rust,ignore
// Producer: sign each Data with the identity key — not an unsigned build().
let wire = DataBuilder::new(name, b"authenticated payload")
    .sign_with_sync(&*signer)?;

// Consumer: decide trust once, then the short verb is safe.
let mut consumer = consumer.verifying(producer_kc.validator());
let safe = consumer.fetch("/demo/alice/thing").await?;   // -> SafeData
```

- **`sign_with_sync`** signs with the producer's identity key. (The bare
  `DataBuilder::build()` carries only a digest — integrity, *not* authorship.)
- **`verifying(validator)`** pins the trust anchor once; after it,
  `consumer.fetch(name)` returns [`SafeData`](../concepts/identity-and-keys.md) —
  the obvious call is the verified one. You can *only* obtain a `SafeData` by
  verifying, so "did I check this packet?" is answered by the compiler, not by
  convention. (`fetch_verified(name, &validator)` is the one-shot equivalent when
  you don't want to hold the validator.)

## Why there is no quiet way to skip it

The consumer never has to remember to verify, because the type system asks for
the decision. `fetch_verified` gives you `SafeData`. The lower-level
`fetch_unverified` gives you `Unverified<Data>`, which you cannot use until you
either `.verify(&validator)` it (getting `SafeData`) or call the loud, greppable
`.trust_unchecked()`:

```rust,ignore
let unverified = consumer.fetch_unverified("/demo/alice/thing").await?;
let safe = unverified.verify(&validator).await?;   // → SafeData
// or, only where no trust schema applies (tests, local IPC):
// let raw = unverified.trust_unchecked();          // loud and searchable
```

There is also a bare `consumer.fetch(name)` that returns raw, **unverified**
`Data` — a low-level primitive the safe methods build on. Reach for it only when
you are deliberately handling verification yourself; otherwise prefer
`fetch_verified`. See [Security pitfalls](../guides/security-pitfalls.md).

## Talking to a standalone forwarder

To split producer and consumer into separate processes against a running
`ndn-fwd`, the consumer pins the producer's certificate as a trust anchor and
calls `fetch_verified` exactly as above — the only difference is where the anchor
comes from. That full flow (publishing, anchor distribution) is the
[Ten-minute producer](./10-minute-producer.md).

## Next steps

- **Serve and verify across two processes**: [Ten-minute producer](./10-minute-producer.md).
- **Understand the trust decision** you just made: [Trust, first](../start/trust-first.md)
  and [Identity and keys](../concepts/identity-and-keys.md).
- **Avoid the common footguns**: [Security pitfalls](../guides/security-pitfalls.md).
- **Fetch a multi-segment object**: [Develop tier → `fetch_object`](../api/develop.md#fetch_object).
