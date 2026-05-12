# Forwarder Comparison Benchmarks

This page is automatically updated by the
[testbed CI workflow](https://github.com/Quarmire/ndn-rs/actions/workflows/testbed.yml)
on every push to `main` and weekly on Mondays.

> **Transport note:** `unix` socket numbers are shown for all forwarders.
> ndn-fwd also supports an in-process SHM face (not tested here).
> Numbers using different transports are **not** directly comparable.

<!-- The section below is machine-generated. Do not edit manually. -->

*Last run: `2026-05-12` (ubuntu-latest, stable ndn-rs)*

| Metric | ndn-fwd | ndn-fwd-internal | nfd | yanfd |
|--------|--------|--------|--------|--------|
| internal-throughput (unix) | n/a | 2.26 Gbps / 37084 Int/s | n/a | n/a |
| latency p50/p99 (unix) | 267µs / 986µs | n/a | 249µs / 356µs | 310µs / 1.21ms |
| throughput (unix) | 2.21 Gbps / 35262 Int/s | n/a | 708.62 Mbps / 11066 Int/s | 1.33 Gbps / 25727 Int/s |

