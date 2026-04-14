# Forwarder Comparison Benchmarks

This page is automatically updated by the
[testbed CI workflow](https://github.com/Quarmire/ndn-rs/actions/workflows/testbed.yml)
on every push to `main` and weekly on Mondays.

> **Transport note:** `unix` socket numbers are shown for all forwarders.
> ndn-fwd also supports an in-process SHM face (not tested here).
> Numbers using different transports are **not** directly comparable.

<!-- The section below is machine-generated. Do not edit manually. -->

*Last run: `2026-04-14` (ubuntu-latest, stable ndn-rs)*

| Metric | ndn-fwd | ndn-fwd-internal | nfd | yanfd |
|--------|--------|--------|--------|--------|
| internal-throughput (unix) | n/a | 3.26 Gbps / 51480 Int/s | n/a | n/a |
| latency p50/p99 (unix) | 206µs / 838µs | n/a | 239µs / 323µs | 289µs / 796µs |
| throughput (unix) | 3.24 Gbps / 51342 Int/s | n/a | 749.85 Mbps / 11822 Int/s | 1.42 Gbps / 26922 Int/s |

