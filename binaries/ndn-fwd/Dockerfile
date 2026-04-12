# Multi-stage Docker image for the ndn-fwd NDN forwarder.
#
# Build:
#   docker build -f binaries/ndn-fwd/Dockerfile -t ndn-fwd .
#
# Run with default config:
#   docker run --rm -p 6363:6363/udp -p 6363:6363/tcp ndn-fwd
#
# Run with a custom config file:
#   docker run --rm -p 6363:6363/udp -p 6363:6363/tcp \
#     -v /path/to/ndn-fwd.toml:/etc/ndn-fwd/config.toml:ro \
#     ndn-fwd
#
# Run with TLS certificates (for websocket-tls):
#   docker run --rm -p 6363:6363/udp -p 6363:6363/tcp -p 9696:9696/tcp \
#     -v /path/to/ndn-fwd.toml:/etc/ndn-fwd/config.toml:ro \
#     -v /path/to/cert.pem:/etc/ndn-fwd/cert.pem:ro \
#     -v /path/to/key.pem:/etc/ndn-fwd/key.pem:ro \
#     ndn-fwd
#
# Exposes:
#   6363/udp  — NDN UDP face
#   6363/tcp  — NDN TCP face
#   9696/tcp  — WebSocket face (wss:// when websocket-tls feature is enabled)

# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM rust:slim AS builder

WORKDIR /build

# Copy only workspace manifests first (cache-friendly: only re-compiles deps
# when Cargo.toml / Cargo.lock changes, not when source changes).
COPY Cargo.toml Cargo.lock ./

# Copy every crate manifest (needed for workspace member resolution).
COPY binaries/ binaries/
COPY crates/ crates/
COPY tools/ tools/
COPY bindings/ bindings/
COPY examples/ examples/

# Build only the ndn-fwd binary in release mode.
RUN cargo build --release --bin ndn-fwd

# ── Stage 2: runtime image ────────────────────────────────────────────────────
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the compiled binary.
COPY --from=builder /build/target/release/ndn-fwd /usr/local/bin/ndn-fwd

# Copy the default configuration.
COPY binaries/ndn-fwd/ndn-fwd.default.toml /etc/ndn-fwd/config.toml

# Certificate directory — mount TLS certs here at runtime.
RUN mkdir -p /etc/ndn-fwd/certs

# Runtime socket directory.
RUN mkdir -p /run/ndn-fwd

EXPOSE 6363/udp 6363/tcp 9696/tcp

ENTRYPOINT ["ndn-fwd", "--config", "/etc/ndn-fwd/config.toml"]
