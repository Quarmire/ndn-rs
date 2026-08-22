# Five-minute app

This page gets you from a fresh clone to a running NDN exchange: one
in-process forwarding engine, two [`Node`](../api/node-cookbook.md)s on it —
one serves a Data under `/hello`, the other fetches it back and prints it.
No external forwarder, no sockets, no configuration.

## Run it

The whole exchange is the repository's front-door example,
`examples/hello-node`:

```sh
git clone https://github.com/Quarmire/ndn-rs
cd ndn-rs
cargo run -p example-hello-node
```

```text
/hello/world => hello from ndn-rs
```

## The code

`examples/hello-node/src/main.rs`, in full:

```rust,ignore
use ndn::{EngineAppExt, EngineBuilder, EngineConfig, Node};
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default()).build().await?;
    let cancel = CancellationToken::new();
    let alice: Node = engine.app_node(cancel.child_token());
    let bob: Node = engine.app_node(cancel.child_token());

    let _guard = alice
        .serve("/hello", |interest, reply| async move {
            let _ = reply.respond((*interest.name).clone(), "hello from ndn-rs").await;
        })
        .await?;

    let data = bob.fetch("/hello/world").await?;
    let payload = data.content().map(|c| c.as_ref()).unwrap_or_default();
    println!("{} => {}", data.name, String::from_utf8_lossy(payload));

    cancel.cancel();
    shutdown.shutdown().await;
    Ok(())
}
```

`Node` is the one type to learn: a single handle exposing every application
pattern — `fetch` / `serve` / `object` / `publish` / `subscribe` / `query` —
over one forwarder connection. Here the "forwarder" is an engine embedded in
the same process (`EngineBuilder` + `app_node`); against a standalone
forwarder the same code starts from `Node::connect(socket)` instead. See
[The Node cookbook](../api/node-cookbook.md).

## Using ndn-rs from your own crate

ndn-rs is **not published on crates.io** (the `ndn` name there is an
unrelated placeholder). The front door is one git dependency on the
`ndn-rs-prelude` package, whose library is deliberately named `ndn`:

```toml
[dependencies]
ndn = { package = "ndn-rs-prelude", git = "https://github.com/Quarmire/ndn-rs", tag = "v0.1.0-alpha.3" }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
tokio-util = "0.7"   # CancellationToken, if you embed the engine
```

Developing inside the ndn-workspace checkout? Use a path dependency
instead of git:

```toml
ndn = { package = "ndn-rs-prelude", path = "../ndn-rs/crates/app/ndn-rs-prelude" }
```

Either way your imports read `use ndn::Node;` — the umbrella re-exports the
flagship types at the top level and the application-facing sub-crates as
modules (`ndn::packet`, `ndn::security`, `ndn::engine`, …), so one
dependency covers the front door and the reach-in surface.

## Where the signature check comes in

`node.fetch` above is the **unverified** surface: the reply is a
`DigestSha256` Data — integrity, not authorship. In NDN the signature check
is the precondition for accepting data at all, and the verified path is one
call away:

```rust,ignore
// Decide trust once; then the short verb returns SafeData —
// proof the signature checked out against your trust anchor.
let safe = node.verifying(validator).fetch("/demo/alice/thing").await?;
```

You can *only* obtain a [`SafeData`](../concepts/identity-and-keys.md) by
verifying, so "did I check this packet?" is answered by the compiler, not by
convention. The signing-and-verifying version of this app — producer signs
with its identity key, consumer pins a trust anchor — is
`examples/secure-fetch`:

```sh
cargo run -p example-secure-fetch
```

The one-paragraph "why" is [Trust, first](../start/trust-first.md); the
mistakes to avoid are in [Security pitfalls](../guides/security-pitfalls.md).

## Next steps

- **Serve and verify across two processes**: [Ten-minute producer](./10-minute-producer.md).
- **Every `Node` pattern** (objects, pub/sub, query): [The Node cookbook](../api/node-cookbook.md).
- **Run a standalone forwarder** to connect real apps to:
  [Running the forwarder](./running-the-forwarder.md).
- **Understand the trust decision**: [Trust, first](../start/trust-first.md)
  and [Identity and keys](../concepts/identity-and-keys.md).
