# Forwarder Comparison Benchmarks

This page is automatically updated by the
[testbed CI workflow](https://github.com/Quarmire/ndn-rs/actions/workflows/testbed.yml)
on every push to `main` and weekly on Mondays.

> **Transport note:** `unix` socket numbers are shown for all forwarders.
> ndn-fwd also supports an in-process SHM face (not tested here).
> Numbers using different transports are **not** directly comparable.

<!-- The section below is machine-generated. Do not edit manually. -->

*Last run: `2026-04-13` (ubuntu-latest, stable ndn-rs)*

| Metric | ndn-fwd | ndn-fwd-internal | nfd | yanfd |
|--------|--------|--------|--------|--------|
| internal-throughput (unix) | n/a | 3.30 Gbps / 52790 Int/s | n/a | n/a |
| latency p50/p99 (unix) | 199µs / 291µs | n/a | 233µs / 305µs | 270µs / 441µs |
| throughput (unix) | 3.43 Gbps / 53367 Int/s | n/a | 813.83 Mbps / 12960 Int/s | 1.54 Gbps / 28568 Int/s |

