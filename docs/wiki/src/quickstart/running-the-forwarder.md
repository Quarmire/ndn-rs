# Running the forwarder

The production forwarder daemon `ndn-fwd` does **not** live in this
repository: it lives in the sibling repo
[ndn-fwd](https://github.com/Quarmire/ndn-fwd), which depends on ndn-rs by
path. Clone the two side by side, then build and run the forwarder from its
own repo. For production deployments see
[Self-hosting](../guides/self-hosting.md).

## Build and run

```sh
git clone https://github.com/Quarmire/ndn-rs
git clone https://github.com/Quarmire/ndn-fwd
cd ndn-fwd
cargo run -p ndn-fwd -- -c binaries/ndn-fwd/ndn-fwd.default.toml
```

`ndn-fwd` takes its config from `-c/--config <path>`; with no flag it runs
on built-in defaults. The annotated starting-point config is
`binaries/ndn-fwd/ndn-fwd.default.toml` in the ndn-fwd repo — its inline
comments are the current documentation of every section (faces, management,
security, routing, observability, fec, rate limits, radio).

With the default config the forwarder:

- Listens on UDP/6363 and TCP/6363 for cross-host NDN traffic, and
  WebSocket/9696 for browser peers.
- Listens on `/run/ndn-fwd/ndn-fwd.sock` for application IPC (the
  management/face socket; built-in default when no config is given:
  `/run/nfd/nfd.sock`).
- Auto-generates its identity on first startup (`[security] auto_init`).
- Logs to stderr at `info` (override with `RUST_LOG` or the config's
  logging section).

## Verify

In another terminal (still in the ndn-fwd repo):

```sh
cargo run -p ndn-tools --bin ndn-ctl -- status
```

`ndn-ctl` lives in `binaries/tooling/ndn-tools/` in the ndn-fwd repo. It
speaks the TLV management protocol over the forwarder's Unix socket and
prints face / route / strategy state.

## Minimal config

A minimal `my-fwd.toml` (pass with `-c my-fwd.toml`):

```toml
[management]
face_socket = "/tmp/ndn-fwd.sock"

[[face]]
kind = "udp"
bind = "0.0.0.0:6363"

[logging]
level = "info,ndn_engine=debug"
```

For everything else start from `binaries/ndn-fwd/ndn-fwd.default.toml` and
its comments — that file ships with the forwarder and is the current truth.
This wiki's [Config reference](../operations/config-reference.md) predates
the newer subsystems (fec, rate limits, radio) and carries a stale banner.

## Stopping

`Ctrl-C` shuts down cleanly: the forwarder closes faces and exits.

## Next steps

- **Connect an application** to this forwarder:
  [Five-minute app](./5-minute-app.md) — swap the in-process engine for
  `Node::connect("/run/ndn-fwd/ndn-fwd.sock")`.
- **Run as a system service** with `docker-compose`:
  [Self-hosting](../guides/self-hosting.md).
- **Configure faces** (UDP, TCP, Unix, WebTransport, WebRTC, BLE,
  Ethernet, shared memory): [Face transports](../reference/face-transports.md).
- **Tune for throughput**: [Performance](../operations/performance.md).
