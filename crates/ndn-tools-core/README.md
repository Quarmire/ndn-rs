# ndn-tools-core

Embeddable NDN tool logic shared by the `ndn-tools` binary, `ndn-dashboard`, and
any application that wants to embed NDN diagnostic tools. Each tool is gated behind
a Cargo feature; enable only what you need. All tools share a streaming event API:
typed `*Params` structs in, `ToolEvent` stream out, clean cancellation via dropped
sender.

## Key types

| Type / Module | Feature | Description |
|---------------|---------|-------------|
| `ToolEvent` / `ToolData` / `EventLevel` | always | Shared event envelope and severity |
| `ConnectConfig` | always | Connection parameters (face address, router socket path) |
| `ping` | `ping` | NDN ping: send Interests, receive Data/Nack, report RTT |
| `iperf` | `iperf` | NDN throughput test: measure Interest/Data rate and goodput |
| `peek` | `peek` | Fetch a single named Data object and print its content |
| `put` | `put` | Inject a Data packet into the forwarder |
| `send` / `recv` | `send`, `recv` | Multi-segment file transfer over NDN |

## Feature flags

| Feature | Description |
|---------|-------------|
| `ping` | NDN ping tool |
| `iperf` | Throughput benchmark tool |
| `peek` | Single-object fetch |
| `put` | Data injection |
| `send` | Multi-segment file send (enables `ndn-filestore`) |
| `recv` | Multi-segment file receive (enables `ndn-filestore`) |

## Usage

```toml
[dependencies]
ndn-tools-core = { version = "*", features = ["ping", "iperf"] }
```

```rust
use ndn_tools_core::ping::{PingParams, run_ping};
use tokio::sync::mpsc;

let (tx, mut rx) = mpsc::channel(64);
tokio::spawn(run_ping(PingParams { name: "/ndn/edu/example".parse()?, count: 5 }, tx));
while let Some(event) = rx.recv().await {
    println!("{event:?}");
}
```
