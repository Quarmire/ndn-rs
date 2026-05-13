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
| internal-throughput (unix) | n/a | 2.36 Gbps / 37951 Int/s | n/a | n/a |
| latency p50/p99 (unix) | 235µs / 354µs | n/a | 225µs / 309µs | n/a / n/a |
| throughput (unix) | 2.28 Gbps / 37741 Int/s | n/a | 765.78 Mbps / 11989 Int/s | 1.50 Gbps / 25860 Int/s |

