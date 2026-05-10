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
| internal-throughput (unix) | n/a | 2.35 Gbps / 39278 Int/s | n/a | n/a |
| latency p50/p99 (unix) | 242µs / 368µs | n/a | 238µs / 690µs | 288µs / 444µs |
| throughput (unix) | 2.47 Gbps / 39244 Int/s | n/a | 700.86 Mbps / 11167 Int/s | 1.46 Gbps / 25641 Int/s |

