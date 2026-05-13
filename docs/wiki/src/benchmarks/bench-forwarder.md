# Forwarder Comparison Benchmarks

This page is automatically updated by the
[testbed CI workflow](https://github.com/Quarmire/ndn-rs/actions/workflows/testbed.yml)
on every push to `main` and weekly on Mondays.

> **Transport note:** `unix` socket numbers are shown for all forwarders.
> ndn-fwd also supports an in-process SHM face (not tested here).
> Numbers using different transports are **not** directly comparable.

<!-- The section below is machine-generated. Do not edit manually. -->

*Last run: `2026-05-13` (ubuntu-latest, stable ndn-rs)*

| Metric | ndn-fwd | ndn-fwd-internal | nfd | yanfd |
|--------|--------|--------|--------|--------|
| internal-throughput (unix) | n/a | 9.51 Mbps / 5008 Int/s | n/a | n/a |
| latency p50/p99 (unix) | 451µs / 951µs | n/a | 307µs / 991µs | 348µs / 491µs |
| throughput (unix) | 9.12 Mbps / 4980 Int/s | n/a | 1.11 Gbps / 17566 Int/s | 1.39 Gbps / 25758 Int/s |

