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
| internal-throughput (unix) | n/a | 3.04 Gbps / 48901 Int/s | n/a | n/a |
| latency p50/p99 (unix) | 254µs / 761µs | n/a | 232µs / 788µs | 281µs / 938µs |
| throughput (unix) | 2.98 Gbps / 47957 Int/s | n/a | 1.13 Gbps / 17639 Int/s | 1.51 Gbps / 29768 Int/s |

