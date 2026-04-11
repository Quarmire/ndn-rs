# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
cargo build                    # build
cargo test                     # run all tests
cargo test <test_name>         # run a single test
cargo clippy -- -D warnings    # lint
cargo fmt                      # format
```

## Testing policy

**Do not run `cargo test` automatically** after making changes. The workspace is large (~50K lines) and a full test run takes 2–3 minutes. Instead:

- Use `cargo build` or `cargo clippy` to verify changes compile and are lint-clean.
- Only run tests when explicitly asked, or when fixing a bug where a specific test is needed to confirm the fix.
- When tests are needed, run them scoped to the affected crate: `cargo test -p <crate-name>` rather than `cargo test --workspace`.

## Project Overview

**ndn-rs** is a Named Data Networking (NDN) forwarder stack written in Rust (edition 2024). NDN is a content-centric networking architecture where packets are named data objects rather than addressed to endpoints.

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the crate map, key abstractions, pipeline flow, and links to detailed design docs in `docs/`.

## Architecture in brief

The key design insight: Rust's ownership model and trait system model NDN as **composable data pipelines with trait-based polymorphism**, not class hierarchies.

- **`PacketContext` by value** through `PipelineStage` objects → compiler-enforced short-circuits
- **`DashMap` PIT** — no global lock on the hot path
- **`bytes::Bytes`** — zero-copy slicing for TLV parsing and Content Store
- **`SafeData` vs `Data`** — compiler enforces that only verified data is forwarded
- **Engine as library** — no daemon/client split; embed in any process or run standalone

The `Face` trait, `Strategy` trait, `ContentStore` trait, `DiscoveryProtocol` trait, and `RoutingProtocol` trait are the main extension points.

## Conventions

- Tracing via the `tracing` crate (not `log`). Binaries own subscriber init; libraries never initialize it.
- Management protocol: NFD-compatible TLV Interest/Data on `/localhost/nfd/<module>/<verb>`.
- Config parsing via `ndn-config` (TOML). Runtime-mutable fields use `Arc<RwLock<T>>`.
- New face types implement `Face` in `ndn-transport` and live in `ndn-face-*` crates.
- New routing algorithms implement `RoutingProtocol` in `ndn-routing`.
- New forwarding strategies implement `Strategy` in `ndn-strategy`.

## Documentation maintenance

- Always update `docs/wiki/src/` and `ARCHITECTURE.md` alongside code changes.
- Add crate-level `//!` docs to every `lib.rs` or `main.rs`.
- Commit code, wiki/docs, and CI config as separate commits.
