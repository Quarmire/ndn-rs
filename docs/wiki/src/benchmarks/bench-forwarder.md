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
| internal-throughput (unix) | n/a | 3.29 Gbps / 52480 Int/s | n/a | n/a |
| latency p50/p99 (unix) | 213µs / 328µs | n/a | n/a / n/a | 285µs / 386µs |
| throughput (unix) | 3.28 Gbps / 52261 Int/s | n/a | 710.94 Mbps / 11215 Int/s | 1.42 Gbps / 26742 Int/s |

