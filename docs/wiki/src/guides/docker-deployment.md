# Docker Deployment

`ndn-fwd` is published as a minimal Docker image to the GitHub Container Registry.  This page explains how to pull, configure, and run it.

## Image tags

| Tag | Description |
|-----|-------------|
| `latest` | Latest stable release (tracks `vX.Y.Z` git tags) |
| `X.Y.Z` | Specific release, e.g. `0.1.0` |
| `edge` | Latest commit on `main` (may be unstable) |

```bash
docker pull ghcr.io/quarmire/ndn-fwd:latest
```

## Quick start

```bash
docker run --rm \
  -p 6363:6363/udp \
  -p 6363:6363/tcp \
  ghcr.io/quarmire/ndn-fwd:latest
```

This starts the forwarder with the built-in default configuration (UDP + TCP listeners on port 6363, no static routes).

## Supplying a configuration file

The container reads its config from `/etc/ndn-fwd/config.toml`.  Mount your own file over it:

```bash
docker run --rm \
  -p 6363:6363/udp \
  -p 6363:6363/tcp \
  -v /path/to/ndn-fwd.toml:/etc/ndn-fwd/config.toml:ro \
  ghcr.io/quarmire/ndn-fwd:latest
```

A minimal `ndn-fwd.toml` for a router with UDP and multicast faces:

```toml
[engine]
cs_capacity_mb = 64

[[face]]
kind = "udp"
bind = "0.0.0.0:6363"

[[face]]
kind = "multicast"
group = "224.0.23.170"
port  = 56363

[[route]]
prefix = "/ndn"
face   = 0
cost   = 10
```

See [Running the Router](../getting-started/running-router.md) for the full configuration reference.

## Supplying TLS certificates

When the WebSocket face is configured with TLS, mount the certificate and key files into `/etc/ndn-fwd/certs/` (the directory is pre-created in the image):

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

Reference the mounted paths in `ndn-fwd.toml`:

```toml
[[face]]
kind     = "web-socket"
bind     = "0.0.0.0:9696"
tls_cert = "/etc/ndn-fwd/certs/cert.pem"
tls_key  = "/etc/ndn-fwd/certs/key.pem"
```

### Obtaining a certificate

With [Let's Encrypt / Certbot](https://certbot.eff.org/):

```bash
certbot certonly --standalone -d router.example.com
# Certificates written to /etc/letsencrypt/live/router.example.com/
```

Then mount the live directory:

```bash
-v /etc/letsencrypt/live/router.example.com/fullchain.pem:/etc/ndn-fwd/certs/cert.pem:ro
-v /etc/letsencrypt/live/router.example.com/privkey.pem:/etc/ndn-fwd/certs/key.pem:ro
```

## Accessing the management socket

The router's Unix management socket is created inside the container at `/run/ndn-fwd/mgmt.sock`.  Bind-mount the directory to reach it from the host:

```bash
mkdir -p /run/ndn-fwd

docker run --rm \
  -p 6363:6363/udp \
  -p 6363:6363/tcp \
  -v /path/to/ndn-fwd.toml:/etc/ndn-fwd/config.toml:ro \
  -v /run/ndn-fwd:/run/ndn-fwd \
  ghcr.io/quarmire/ndn-fwd:latest
```

Then use `ndn-ctl` from the host:

```bash
ndn-ctl --socket /run/ndn-fwd/mgmt.sock status
ndn-ctl --socket /run/ndn-fwd/mgmt.sock face list
ndn-ctl --socket /run/ndn-fwd/mgmt.sock route add /ndn --face 1 --cost 10
```

## Docker Compose

A complete `docker-compose.yml` for a single-node testbed:

```yaml
services:
  ndn-fwd:
    image: ghcr.io/quarmire/ndn-fwd:latest
    restart: unless-stopped
    ports:
      - "6363:6363/udp"
      - "6363:6363/tcp"
      - "9696:9696/tcp"
    volumes:
      - ./ndn-fwd.toml:/etc/ndn-fwd/config.toml:ro
      - ./certs/cert.pem:/etc/ndn-fwd/certs/cert.pem:ro
      - ./certs/key.pem:/etc/ndn-fwd/certs/key.pem:ro
      - ndn-mgmt:/run/ndn-fwd

volumes:
  ndn-mgmt:
```

## Building the image locally

From the repository root:

```bash
docker build -f binaries/ndn-fwd/Dockerfile -t ndn-fwd .
docker run --rm -p 6363:6363/udp ndn-fwd
```

## Image details

| Property | Value |
|----------|-------|
| Base image | `debian:trixie-slim` |
| Runtime dependencies | `ca-certificates` |
| Default config path | `/etc/ndn-fwd/config.toml` |
| Certificate directory | `/etc/ndn-fwd/certs/` |
| Management socket | `/run/ndn-fwd/mgmt.sock` |
| Exposed ports | `6363/udp`, `6363/tcp`, `9696/tcp` |

The image uses a two-stage build: the builder stage compiles `ndn-fwd` from source using the official `rust:1.85-slim` image; the runtime stage copies only the compiled binary into a minimal `debian:trixie-slim` base with no Rust toolchain.
