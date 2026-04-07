# Build stage
FROM rust:1.82-slim AS builder
WORKDIR /build

# Copy workspace files needed for the build
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY binaries/did-ndn-driver/ binaries/did-ndn-driver/

# Build only the driver (avoids building unrelated crates)
RUN cargo build --release -p did-ndn-driver

# Runtime stage
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/did-ndn-driver /usr/local/bin/did-ndn-driver

ENV PORT=8080
EXPOSE 8080

ENTRYPOINT ["did-ndn-driver"]
