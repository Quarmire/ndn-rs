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
| internal-throughput (unix) | n/a | 2.57 Gbps / 41626 Int/s | n/a | n/a |
| latency p50/p99 (unix) | 229µs / 319µs | n/a | 237µs / 451µs | 280µs / 351µs |
| throughput (unix) | 2.52 Gbps / 41297 Int/s | n/a | 849.32 Mbps / 13697 Int/s | 1.40 Gbps / 26426 Int/s |

