# ndn-fwd

Standalone NDN forwarder binary.

## Usage

```bash
# Default config:
cargo run --bin ndn-fwd

# With a TOML config file:
cargo run --bin ndn-fwd -- -c ndn-fwd.toml

# Override log level:
RUST_LOG=ndn_engine=debug cargo run --bin ndn-fwd -- -c ndn-fwd.toml
```

## Features

- Loads face and route configuration from a TOML file (`-c`)
- Supports UDP, TCP, multicast, WebSocket, Unix socket, and serial faces
- Static FIB routes from config, plus runtime route management via `ndn-ctl`
- NDN-native management via `/localhost/nfd/` Interest/Data exchange
- Optional trust-anchor and key directory for signed-Data verification
- Structured tracing via `RUST_LOG` (e.g. `RUST_LOG=ndn_engine=trace`)

## Configuration

See the [running-router wiki page](../../docs/wiki/src/getting-started/running-router.md) for the full TOML schema and examples.

## Docker

Pre-built images are published to `ghcr.io/quarmire/ndn-fwd`:

```bash
# Latest stable release
docker pull ghcr.io/quarmire/ndn-fwd:latest

# Bleeding-edge main branch
docker pull ghcr.io/quarmire/ndn-fwd:edge
```

### Run with default config

```bash
docker run --rm \
  -p 6363:6363/udp \
  -p 6363:6363/tcp \
  ghcr.io/quarmire/ndn-fwd:latest
```

### Supply a custom configuration file

Mount your `ndn-fwd.toml` over the default `/etc/ndn-fwd/config.toml`:

```bash
docker run --rm \
  -p 6363:6363/udp \
  -p 6363:6363/tcp \
  -v /path/to/ndn-fwd.toml:/etc/ndn-fwd/config.toml:ro \
  ghcr.io/quarmire/ndn-fwd:latest
```

### Supply TLS certificates (WebSocket TLS)

Mount the certificate and key files, then reference them in the config:

```bash
docker run --rm \
  -p 6363:6363/udp \
  -p 6363:6363/tcp \
  -p 9696:9696/tcp \
  -v /path/to/ndn-fwd.toml:/etc/ndn-fwd/config.toml:ro \
  -v /path/to/cert.pem:/etc/ndn-fwd/certs/cert.pem:ro \
  -v /path/to/key.pem:/etc/ndn-fwd/certs/key.pem:ro \
  ghcr.io/quarmire/ndn-fwd:latest
```

In your `ndn-fwd.toml`, reference the mounted paths:

```toml
[[face]]
kind = "web-socket"
bind = "0.0.0.0:9696"
tls_cert = "/etc/ndn-fwd/certs/cert.pem"
tls_key  = "/etc/ndn-fwd/certs/key.pem"
```

### Access the management socket

The router's Unix management socket is at `/run/ndn-fwd/mgmt.sock` inside the container. Expose it to the host with a bind mount:

```bash
docker run --rm \
  -p 6363:6363/udp \
  -v /path/to/ndn-fwd.toml:/etc/ndn-fwd/config.toml:ro \
  -v /run/ndn-fwd:/run/ndn-fwd \
  ghcr.io/quarmire/ndn-fwd:latest

# Then use ndn-ctl from the host (pointing at the exposed socket):
ndn-ctl --socket /run/ndn-fwd/mgmt.sock status
```

### Build the image locally

From the repository root:

```bash
docker build -f binaries/ndn-fwd/Dockerfile -t ndn-fwd .
```
