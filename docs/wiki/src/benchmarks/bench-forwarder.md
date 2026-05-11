# Forwarder Comparison Benchmarks

This page is automatically updated by the
[testbed CI workflow](https://github.com/Quarmire/ndn-rs/actions/workflows/testbed.yml)
on every push to `main` and weekly on Mondays.

> **Transport note:** `unix` socket numbers are shown for all forwarders.
> ndn-fwd also supports an in-process SHM face (not tested here).
> Numbers using different transports are **not** directly comparable.

<!-- The section below is machine-generated. Do not edit manually. -->

*Last run: `2026-05-11` (ubuntu-latest, stable ndn-rs)*

| Metric | ndn-fwd | ndn-fwd-internal | nfd | yanfd |
|--------|--------|--------|--------|--------|
| internal-throughput (unix) | n/a | 2.94 Gbps / 46351 Int/s | n/a | n/a |
| latency p50/p99 (unix) | 257µs / 664µs | n/a | 261µs / 493µs | 300µs / 432µs |
| throughput (unix) | 2.96 Gbps / 46389 Int/s | n/a | 1.10 Gbps / 17500 Int/s | 1.35 Gbps / 28701 Int/s |

