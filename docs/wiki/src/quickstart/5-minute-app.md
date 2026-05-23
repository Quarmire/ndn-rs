# Five-minute app

This page gets you from `cargo new` to fetching one `Data` packet.
You write ~20 lines; nothing else.

## Prerequisites

- Rust toolchain (`rustup default stable`).
- A running forwarder at a known Unix socket. If you have none, run
  the bundled `ndn-fwd` in one terminal:

  ```sh
  cargo run -p ndn-fwd
  ```

  Default socket path: `/tmp/ndn-fwd.sock`. See
  [Running the forwarder](./running-the-forwarder.md) for the
  10-minute version.

## The program

```sh
cargo new --bin hello-ndn
cd hello-ndn
cargo add ndn-rs-prelude tokio --features tokio/macros,tokio/rt-multi-thread
```

`src/main.rs`:

```rust,ignore
use ndn::prelude::*;
use ndn::Consumer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut consumer = Consumer::connect("/tmp/ndn-fwd.sock").await?;
    let data = consumer.fetch("/example/hello").await?;
    println!("got {} bytes under {}", data.content().len(), data.name());
    Ok(())
}
```

That's the 5-minute path. The crate `ndn-rs-prelude` exposes itself
as the library `ndn`, so `use ndn::...` reads cleanly even though
Cargo.toml names the dependency by its longer form. See
`crates/ndn-rs-prelude/Cargo.toml` for the package/library
split.

## What just happened

- `Consumer::connect` opens an IPC connection to the forwarder over
  the Unix socket.
- `consumer.fetch(name)` expresses an Interest, awaits the reply,
  and returns the decoded `Data`. The name is parsed from the URI
  form (`/example/hello`).
- The forwarder routes the Interest, gets a `Data`, and returns it
  through the same connection. PIT/FIB/CS work is invisible to the
  application — that's the Develop tier's promise.

## Next steps

- **Fetch a multi-segment object** with `fetch_object` (RDR-shaped
  segmented fetch): [Develop tier → `fetch_object`](../api/develop.md#fetch_object).
- **Serve a `Data` instead of fetching one**:
  [Ten-minute producer](./10-minute-producer.md).
- **Run the engine in-process** (mobile, tests, browser):
  [Develop tier → embedded engine](../api/develop.md#embedded-engine).

