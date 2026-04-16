# Forwarder Comparison Benchmarks

This page is automatically updated by the
[testbed CI workflow](https://github.com/Quarmire/ndn-rs/actions/workflows/testbed.yml)
on every push to `main` and weekly on Mondays.

> **Transport note:** `unix` socket numbers are shown for all forwarders.
> ndn-fwd also supports an in-process SHM face (not tested here).
> Numbers using different transports are **not** directly comparable.

<!-- The section below is machine-generated. Do not edit manually. -->

*Last run: `2026-04-16` (ubuntu-latest, stable ndn-rs)*

| Metric | ndn-fwd | ndn-fwd-internal | nfd | yanfd |
|--------|--------|--------|--------|--------|
| internal-throughput (unix) | n/a | 3.22 Gbps / 50918 Int/s | n/a | n/a |
| latency p50/p99 (unix) | 212µs / 407µs | n/a | 245µs / 758µs | 285µs / 489µs |
| throughput (unix) | 3.35 Gbps / 52175 Int/s | n/a | 723.63 Mbps / 11266 Int/s | 1.45 Gbps / 26698 Int/s |

