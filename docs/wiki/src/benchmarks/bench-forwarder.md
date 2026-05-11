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
| internal-throughput (unix) | n/a | 2.27 Gbps / 39072 Int/s | n/a | n/a |
| latency p50/p99 (unix) | 247µs / 365µs | n/a | 238µs / 325µs | n/a / n/a |
| throughput (unix) | 2.40 Gbps / 38170 Int/s | n/a | 699.26 Mbps / 10995 Int/s | 1.47 Gbps / 25459 Int/s |

