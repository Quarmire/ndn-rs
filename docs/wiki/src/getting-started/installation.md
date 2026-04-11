# Installation

This page covers how to build ndn-rs from source and install its binaries.

## Prerequisites

- **Rust 2024 edition** -- install via [rustup](https://rustup.rs/). The workspace uses `edition = "2024"`, so you need a nightly or recent stable toolchain that supports it.
- **cargo** -- ships with rustup.
- **Linux or macOS** -- some face types (raw Ethernet, SHM) are Unix-only. The core library compiles on Windows but network tooling is limited.

## Clone and build

```bash
git clone https://github.com/user/ndn-rs.git   # replace with actual URL
cd ndn-rs

# Build the entire workspace
cargo build

# Run all tests
cargo test

# Lint (treat warnings as errors)
cargo clippy -- -D warnings

# Format check
cargo fmt -- --check
```

## Building the router binary

The standalone forwarder lives in `binaries/ndn-fwd`:

```bash
cargo build -p ndn-fwd
```

The compiled binary is at `target/debug/ndn-fwd` (or `target/release/ndn-fwd` with `--release`).

To build the CLI tools (ping, peek, put, ctl, traffic, iperf):

```bash
cargo build -p ndn-tools
```

This produces several binaries: `ndn-ping`, `ndn-peek`, `ndn-put`, `ndn-ctl`, `ndn-traffic`, and `ndn-iperf`.

## Optional features

### ndn-fwd features

The router binary has three optional feature flags, all enabled by default:

| Feature     | Description                                                  | Gate            |
|-------------|--------------------------------------------------------------|-----------------|
| `spsc-shm`  | Shared-memory data plane between apps and router (Unix only) | `ndn-faces/spsc-shm` |
| `websocket` | WebSocket face for browser and remote clients                | `ndn-faces/websocket`  |
| `serial`    | Serial port face (RS-232 / USB-serial)                       | `ndn-faces/serial`  |

To build without WebSocket support, for example:

```bash
cargo build -p ndn-fwd --no-default-features --features spsc-shm,serial
```

### ndn-store features

The content store crate has an optional persistent backend:

| Feature | Description                              |
|---------|------------------------------------------|
| `fjall`  | Persistent content store backed by fjall |

Enable it from a dependent crate or when running benchmarks:

```bash
cargo test -p ndn-store --features fjall
```

## Running the router

Copy the example configuration and adjust it for your environment:

```bash
cp ndn-fwd.example.toml ndn-fwd.toml

# Start the router (needs sudo for raw sockets / privileged ports)
sudo ./target/debug/ndn-fwd --config ndn-fwd.toml
```

The config file can also be specified via the `NDN_CONFIG` environment variable:

```bash
sudo NDN_CONFIG=ndn-fwd.toml ./target/release/ndn-fwd
```

The log level defaults to `info` and can be overridden at runtime:

```bash
sudo ./target/release/ndn-fwd --config ndn-fwd.toml --log-level debug
```

Or via the standard `RUST_LOG` environment variable:

```bash
sudo RUST_LOG=ndn_engine=debug ./target/release/ndn-fwd --config ndn-fwd.toml
```

See [Running the Router](./running-router.md) for a detailed configuration walkthrough.

## Verifying the installation

After the router starts, you should see log output indicating that faces are created and the pipeline is running. Use `ndn-ctl` to confirm the router is alive:

```bash
ndn-ctl status
```

This connects to the router's management socket (default `/tmp/ndn.sock`) and prints forwarding engine state.
