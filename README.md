<p align="center">
  <img src="docs/logo.svg" alt="ndn-rs" width="180">
</p>

<h1 align="center">ndn-rs</h1>

<p align="center">
  A Named Data Networking forwarder stack in Rust.
</p>

> **Notice: primarily AI-authored, not yet proven correct.**
>
> This codebase is primarily authored by an AI coding assistant. An
> evidence-based audit against the NDN specifications found numerous
> spec-compliance errors, including BLOCKER-tier wire-format bugs that
> any conforming NDN peer would reject. Remediation is in progress in
> the open; see [`testbed/EXPECTED_FAILURES.md`](testbed/EXPECTED_FAILURES.md)
> for current known-bad behaviours and the
> [spec-compliance summary](docs/wiki/src/reference/spec-compliance.md)
> for what has been verified against the spec.
>
> **Do not use `ndn-rs` as a reference implementation of NDN or cite
> it as one.** Use [NFD](https://github.com/named-data/NFD),
> [ndn-cxx](https://github.com/named-data/ndn-cxx),
> [NDNts](https://github.com/yoursunny/NDNts),
> [ndnd](https://github.com/named-data/ndnd), or
> [python-ndn](https://github.com/named-data/python-ndn).

[Named Data Networking](https://named-data.net/) routes packets by
name rather than address: consumers express **Interests**; the network
routes them toward producers and returns **Data** along the reverse
path, caching at every hop. ndn-rs is a Rust implementation of that
substrate — a forwarder engine plus the tools and libraries around it.

---

## Features

- Async pipeline with and pluggable forwarding strategies.
- Multiple face transports: UDP, TCP, Unix socket, in-process channel,
  shared-memory, serial, BLE, Ethernet, WebSocket, WebTransport.
- Identity and trust: KeyChain, signing-info composition, validation
  policies, NDNCERT enrollment.
- NFD-compatible management surface (`/localhost/nfd/...`) for
  cross-stack tooling.
- Browser-ready: the engine builds for `wasm32-unknown-unknown` and
  runs in a browser tab.

---

## Implementations and applications

| Binary | What it does |
|---|---|
| [`ndn-fwd`](binaries/spec/ndn-fwd) | The forwarder daemon. |
| [`ndn-ctl`](binaries/tooling/ndn-tools) | Management CLI (NFD-compatible). |
| [`ndn-peek`, `ndn-put`, `ndn-ping`](binaries/tooling/ndn-tools) | Operator utilities. |
| [`ndn-sec`](binaries/tooling/ndn-tools) | Identity / key / cert management. |
| [`ndn-traffic`, `ndn-iperf`](binaries/tooling/ndn-tools) | Synthetic load + throughput measurement. |
| [`ndn-otel-bridge`](binaries/tooling/ndn-otel-bridge) | OpenTelemetry export for engine traces. |

### Other ndn-rs projects

*Repositories not yet published. Linked once they land.*

- **ndn-dashboard** — desktop / browser UI for managing one or more
  forwarders.

---

## Build from source

### Forwarder

```bash
cargo build --release -p ndn-fwd
./target/release/ndn-fwd -c examples/ndn-fwd.example.toml
```

### Tools

```bash
cargo build --release -p ndn-tools
# Builds: ndn-peek, ndn-put, ndn-ping, ndn-sec, ndn-ctl, ndn-traffic, ndn-iperf
```

Run any binary with `--help` for its full option set.

---

## Self-host

Two ways to deploy:

### Nix (recommended)

The flake exposes every shipped binary as a `nix run`/`nix profile
install` target, plus a NixOS module for running the forwarder as a
hardened systemd service.

```bash
# Run the forwarder ad-hoc
nix run github:Quarmire/ndn-rs

# Install operator CLIs
nix profile install github:Quarmire/ndn-rs#ndn-tools

# Run a specific tool
nix run github:Quarmire/ndn-rs#ndn-fwd-tokens -- --help
```

To run the forwarder as a NixOS system service:

```nix
{
  inputs.ndn-rs.url = "github:Quarmire/ndn-rs";

  outputs = { self, nixpkgs, ndn-rs }: {
    nixosConfigurations.router = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        ndn-rs.nixosModules.default
        {
          services.ndn-fwd.enable = true;
          services.ndn-fwd.openFirewall = true;
          services.ndn-fwd.identity = "/ndn/mysite/router1";
          services.ndn-fwd.configFile = ./ndn-fwd.toml;
        }
      ];
    };
  };
}
```

The NixOS module:

- Creates a `ndn-fwd` system user + state directory at `/var/lib/ndn-fwd`.
- Optionally auto-generates the router's Ed25519 identity on first boot.
- Hardens the service (`ProtectSystem=strict`, `NoNewPrivileges`,
  capability bounding, etc.) and grants only `CAP_NET_RAW` +
  `CAP_NET_BIND_SERVICE` for raw faces and privileged ports.
- Optionally opens UDP/TCP 6363 in the firewall.

### Docker Compose

A turnkey docker-compose stack is at [`deploy/`](deploy/), including a
forwarder, an NDNCERT CA, and a WebRTC signaling relay. Start with
[`deploy/install.sh`](deploy/install.sh).

---

## Develop

```bash
# Native (Tokio)
cargo build --workspace
cargo test  --workspace -- --skip ignored
cargo clippy --workspace -- -D warnings

# Browser target (wasm32)
cargo build --target wasm32-unknown-unknown -p ndn

# Wiki
mdbook build docs/wiki
```

With Nix, `nix develop` enters a shell with the rust toolchain,
rust-analyzer, clippy, mdbook + mdbook-mermaid, and the workflow
tools. `nix develop .#wasm` adds wasm-pack and wasm-bindgen-cli for
the in-browser builds.

---

## Documentation

| | |
|--|--|
| [**Wiki**](https://quarmire.github.io/ndn-rs/wiki/) | Quickstart, concepts, API reference, guides, operations. |
| [**Releases**](https://github.com/Quarmire/ndn-rs/releases) | Tagged versions and release notes. |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Crate map and dependency-layer overview. |
| [`docs/specs/`](docs/specs) | ndn-rs-proprietary specs. |

---

## Acknowledgements

ndn-rs builds on the Named Data Networking architecture developed by
the NDN research team led by Lixia Zhang at UCLA, with contributions
from NIST, the University of Memphis, the University of Arizona, and
others. Protocol specifications, packet format, and forwarding
semantics are defined by the NDN team's technical reports and
specifications. ndn-rs's surfaces borrow shape from the long-standing
reference implementations the wider community maintains.

## License

Licensed under either [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE) at your option.
