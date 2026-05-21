# Running the forwarder

This page gets a local `ndn-fwd` process listening on a Unix socket
in under five minutes. For production deployments see
[Self-hosting](../guides/self-hosting.md).

## Build and run

From the workspace root:

```sh
cargo run -p ndn-fwd
```

`ndn-fwd` reads `ndn-fwd.toml` from the current directory; if absent
it uses defaults. The example config is at
`ndn-fwd.example.toml` in the repository root.

By default the forwarder:

- Listens on `/tmp/ndn-fwd.sock` for application IPC.
- Listens on UDP/6363 for cross-host NDN traffic.
- Stores PIB and KeyChain at `~/.ndn/`.
- Logs to stderr at `info` level (override with `RUST_LOG`).

## Verify

In another terminal:

```sh
ndn-ctl status
```

`ndn-ctl` ships in `binaries/tooling/ndn-tools/`. It speaks the
TLV management protocol over the same Unix socket and prints
face / route / strategy state.

## Minimal config

`ndn-fwd.toml`:

```toml
[mgmt]
socket = "/tmp/ndn-fwd.sock"

[face.udp]
listen = "0.0.0.0:6363"

[log]
filter = "info,ndn_engine=debug"
```

Every knob is documented in [Config reference](../operations/config-reference.md).

## Stopping

`Ctrl-C` shuts down cleanly. The forwarder closes faces, persists
strategy choices, and exits. State that survives a restart lives in
`~/.ndn/` and the on-disk config.

## Next steps

- **Connect an application** to this forwarder:
  [Five-minute app](./5-minute-app.md).
- **Run as a system service** with `systemd` or `docker-compose`:
  [Self-hosting](../guides/self-hosting.md).
- **Configure faces** (UDP, TCP, Unix, WebTransport, WebRTC, BLE,
  Ethernet, shared memory): [Face transports](../reference/face-transports.md).
- **Tune for throughput**: [Performance](../operations/performance.md).
