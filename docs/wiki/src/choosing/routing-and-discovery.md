# Routing & discovery

Routing fills the FIB with the next hops that lead toward a name; a
[strategy](../guides/writing-a-strategy.md) then chooses among them per
packet. How the FIB gets filled is the decision here, and it ranges from
"you type the routes" to "the network works them out."

| Your network is… | Reach for | What it costs |
|---|---|---|
| Small and fixed | **Static routes** (`StaticProtocol`) | Zero protocol overhead, but you maintain every route by hand; no adaptation to failures. |
| Multi-router, needs link-state convergence | **NLSR** (`NlsrProtocol`) | Routing traffic and per-router state; converges after topology changes. |
| Multi-router, distance-vector style | **DV** (`DvProtocol`) | Lighter state than link-state; follows the published distance-vector routing spec. |
| Mobile / ad-hoc, peers come and go | **Self-learning** strategy | No routing protocol — learns next hops by broadcasting and validating prefix announcements; flooding cost on first reach. |
| Multiple producers sharing a *dataset* | **SVS** state-vector sync (`ndn-sync`) | Not reachability routing — a sync layer for who-has-what; adds per-dataset state vectors. |

## Routing vs. sync — don't confuse them

The first four rows answer "which way do I forward an Interest for this
name." SVS answers a different question: "which data items exist in a
shared collection, and which am I missing." A pub/sub or multi-writer
dataset usually wants SVS *on top of* one of the routing options, not
instead of it.

## How to decide

1. **Handful of nodes, stable links?** Static routes. Don't run a routing
   protocol you don't need.
2. **A real multi-router topology that changes?** NLSR for link-state, or
   DV if you prefer distance-vector and want the lighter state.
3. **No stable topology at all (mobile, mesh)?** Lean on the self-learning
   strategy rather than a routing protocol.
4. **Synchronising a dataset across producers?** Add SVS — and still pick
   one of the above for reachability.

The protocol types and their state codes are in the
[NDN overview](../concepts/ndn-overview.md#forwarding-strategy) and the
strategy seam in [Writing a strategy](../guides/writing-a-strategy.md).
