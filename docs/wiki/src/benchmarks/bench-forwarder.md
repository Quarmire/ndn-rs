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
| internal-throughput (unix) | n/a | 3.34 Gbps / 52896 Int/s | n/a | n/a |
| latency p50/p99 (unix) | 205µs / 284µs | n/a | 224µs / 320µs | 273µs / 466µs |
| throughput (unix) | 3.36 Gbps / 52779 Int/s | n/a | 788.88 Mbps / 12453 Int/s | 1.45 Gbps / 26822 Int/s |

