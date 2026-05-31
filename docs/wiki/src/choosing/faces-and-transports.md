# Faces & transports

A face is an NDN-layer link; the *transport* underneath it is a separate
choice. The same Interest and Data ride any of them unchanged, so picking
a transport is about your deployment, not your protocol. Start from where
the two ends are.

| The two ends are… | Reach for | What it costs |
|---|---|---|
| Two processes on one host | Unix socket, or **shared memory** <span class="scope extension">extension</span> (`spsc-shm`) | shm is the fastest path but same-host only; Unix sockets are simpler and still local. |
| Across a network, general purpose | **UDP** (default) or TCP | UDP is the common, cross-implementation choice; TCP adds head-of-line blocking but traverses some middleboxes better. |
| A browser tab and a forwarder | WebSocket or **WebTransport** <span class="scope extension">extension</span> | Needs a listener and (for WebTransport) a cert; browser-side only. |
| Two browsers / NAT-bound peers | **WebRTC** <span class="scope extension">extension</span> | Requires signaling/relay infrastructure to establish the channel. |
| Constrained radio, no IP | **BLE** or **Wi-Fi Aware** <span class="scope extension">extension</span> | Small MTUs force NDNLPv2 fragmentation; throughput and range are limited. |
| Max throughput on a Linux NIC | Ethernet, or **AF_XDP** <span class="scope extension">extension</span> (`af-xdp` feature) | AF_XDP is Linux-only kernel-bypass — fastest, but ties you to that platform and a raw NIC. |

## How to decide

1. **Same host?** Use Unix sockets; reach for shared memory only when you
   have measured the local path as a bottleneck.
2. **Interoperating with other NDN forwarders?** Stay on UDP/TCP — they
   are the lingua franca.
3. **In a browser?** WebSocket is the low-friction start; WebTransport
   when you need datagrams and have the cert plumbing.
4. **On a radio without IP?** BLE or Wi-Fi Aware, and budget for
   fragmentation overhead at small MTUs.
5. **Chasing line rate on Linux?** Ethernet, then AF_XDP — but only after
   the ordinary path is proven too slow ([Reliability & throughput](./reliability-and-throughput.md)).

The full per-transport catalogue — URIs, MTUs, scopes — is in
[Face transports](../reference/face-transports.md). To add a bearer of
your own, see [Implementing a face](../guides/implementing-a-face.md).
