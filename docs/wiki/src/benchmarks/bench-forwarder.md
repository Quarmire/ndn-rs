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
| internal-throughput (unix) | n/a | 3.13 Gbps / 49879 Int/s | n/a | n/a |
| latency p50/p99 (unix) | 209µs / 372µs | n/a | 250µs / 350µs | 289µs / 456µs |
| throughput (unix) | 3.20 Gbps / 49996 Int/s | n/a | 695.47 Mbps / 10942 Int/s | 1.43 Gbps / 25965 Int/s |

