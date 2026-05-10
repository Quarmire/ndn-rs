# Forwarder Comparison Benchmarks

This page is automatically updated by the
[testbed CI workflow](https://github.com/Quarmire/ndn-rs/actions/workflows/testbed.yml)
on every push to `main` and weekly on Mondays.

> **Transport note:** `unix` socket numbers are shown for all forwarders.
> ndn-fwd also supports an in-process SHM face (not tested here).
> Numbers using different transports are **not** directly comparable.

<!-- The section below is machine-generated. Do not edit manually. -->

*Last run: `2026-05-10` (ubuntu-latest, stable ndn-rs)*

| Metric | ndn-fwd | ndn-fwd-internal | nfd | yanfd |
|--------|--------|--------|--------|--------|
| internal-throughput (unix) | n/a | 2.44 Gbps / 40838 Int/s | n/a | n/a |
| latency p50/p99 (unix) | 245µs / 340µs | n/a | 233µs / 297µs | 276µs / 368µs |
| throughput (unix) | 2.51 Gbps / 40148 Int/s | n/a | 712.08 Mbps / 11353 Int/s | 1.42 Gbps / 25556 Int/s |

