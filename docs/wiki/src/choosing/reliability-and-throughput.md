# Reliability & throughput

Two separate worries that newcomers often merge: *reliability* is getting
the data despite loss; *throughput* is moving it fast. NDN already gives
you a floor on both — start there and add levers only when you have
measured a need.

## Reliability — surviving loss

| You face… | Reach for | What it costs |
|---|---|---|
| Occasional loss, normal links | **The default** — a consumer re-expresses the Interest; the PIT and caches absorb the rest | Nothing; it is how NDN works. |
| A persistently lossy link | **ReliabilityFeature** on that face (sequence numbers, acks, retransmit) | Per-face state and ack traffic; enable it only on the link that needs it. |
| Loss you can't retransmit through — multicast, broadcast, one-way radio | **Network coding / FEC** <span class="scope extension">extension</span> (`ndn-coding`: K-of-N recode) | Parity overhead on the wire and encode/decode compute; pays off when retransmission is impossible or expensive. |

## Throughput — going faster

| You need… | Reach for | What it costs |
|---|---|---|
| Ordinary speed | **A plain UDP face** | Nothing; fine for most deployments. |
| More packets/sec on Linux | **Batched syscalls** — `recvmmsg` / `sendmmsg` (opt-in feature) | Linux-only; a build feature, off by default. |
| Several cores on one listener | **`SO_REUSEPORT`** with the `rx_sockets` knob | No gain on loopback/macOS — needs a real multi-queue NIC. |
| Line rate, kernel-bypass | **AF_XDP** <span class="scope extension">extension</span> (`af-xdp` feature) | Linux-only, raw NIC, extra setup; the last lever, not the first. |

## How to decide

1. **Is loss actually hurting you?** Measure before adding anything — the
   default re-expression covers a lot.
2. **One bad link?** Turn on `ReliabilityFeature` for that face only.
3. **Can't retransmit (broadcast/one-way)?** That is the case FEC is for —
   see [Network coding (FEC)](../guides/network-coding.md).
4. **Throughput-bound?** Walk the levers in order — batched I/O, then
   `SO_REUSEPORT`, then AF_XDP — and re-measure at each step.
   [Performance](../operations/performance.md) has the benchmarking story.

Every throughput lever past the plain face is Linux-specific and opt-in,
so none of them change behaviour until you ask for it.
