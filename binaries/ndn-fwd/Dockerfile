# Multi-stage Docker image for the ndn-fwd NDN forwarder.
#
# Build: docker build -f binaries/ndn-fwd/Dockerfile -t ndn-fwd .
# Run:   docker run --rm -v /tmp:/tmp ndn-fwd
#
# Exposes:
#   6363/udp  — NDN UDP face
#   6363/tcp  — NDN TCP face
#   9696/tcp  — WebSocket face (wss:// when websocket-tls feature is enabled)

# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM rust:1.82-slim AS builder

# Install system libraries required for native-tls / OpenSSL.
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy only workspace manifests first (cache-friendly: only re-compiles deps
# when Cargo.toml / Cargo.lock changes, not when source changes).
COPY Cargo.toml Cargo.lock ./

# Copy every crate manifest (needed for workspace member resolution).
COPY binaries/ binaries/
COPY crates/ crates/
COPY tools/ tools/
COPY bindings/ bindings/

# Build only the ndn-fwd binary in release mode.
RUN cargo build --release --bin ndn-fwd

# ── Stage 2: runtime image ────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the compiled binary.
COPY --from=builder /build/target/release/ndn-fwd /usr/local/bin/ndn-fwd

# Copy the default configuration.
COPY binaries/ndn-fwd/ndn-fwd.default.toml /etc/ndn-fwd/config.toml

# Runtime socket directory.
RUN mkdir -p /run/ndn-fwd

EXPOSE 6363/udp 6363/tcp 9696/tcp

ENTRYPOINT ["ndn-fwd", "--config", "/etc/ndn-fwd/config.toml"]
