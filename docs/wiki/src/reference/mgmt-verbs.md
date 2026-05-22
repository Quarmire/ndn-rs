# Management verbs

ndn-rs's management plane is a set of `MgmtModule` impls, each
owning the verbs under one module name. Commands and datasets ride
TLV Interests under `/localhost/<forwarder>/<module>/<verb>`.

For the module-author surface see [Extend tier → MgmtModule](../api/extend.md#mgmtmodule).
For runtime use see `ndn-ctl` in [ndn-fwd](../operations/ndn-fwd.md).

## Module catalogue

One module per row; one file per module under
`crates/spec/ndn-mgmt/src/modules/`.

| Module | File | What it owns |
|---|---|---|
| `forwarder-status` | `modules/status.rs` | Forwarder-wide info dataset (uptime, version, counters). |
| `faces` | `modules/faces.rs` | Face create/destroy/list and per-face counters. |
| `fib` | `modules/fib.rs` | FIB list, add-nexthop, remove-nexthop. |
| `rib` | `modules/rib.rs` | RIB register, unregister, list. |
| `strategy-choice` | `modules/strategy.rs` | Strategy set, unset, list. |
| `cs` | `modules/cs.rs` | Content store info, config, erase. |
| `routing` | `modules/routing.rs` | Routing-protocol typed status (per `RoutingProtocolStatus`). |
| `discovery` | `modules/discovery.rs` | Discovery-protocol neighbours. |
| `measurements` | `modules/measurements.rs` | Strategy measurement state (Instrument-leaning). |
| `coding` | `modules/coding.rs` | Per-prefix coding adapters. |
| `rate-limit` | `modules/rate_limit.rs` | Token-bucket rate-limit state. |
| `security` | `modules/security.rs` | KeyChain operations. |
| `log` | `modules/log.rs` | Runtime log-filter set/get. |
| `neighbors` | `modules/neighbors.rs` | Neighbour table (joins discovery info with face state). |
| `service` | `modules/service.rs` | Service lifecycle (drain, shutdown). |

The catalogue tracks `crates/spec/ndn-mgmt/src/modules/mod.rs` —
add a module there, it appears here.

## Verb shape

Every command verb takes the same shape:

```text
/localhost/<forwarder>/<module>/<verb>/<params-tlv>/<signed-Interest-fields>
```

Reply: signed `Data` carrying a `ControlResponse` (status code +
text + optional dataset).

Datasets (read-only) use:

```text
/localhost/<forwarder>/<module>/list
```

reassembled segmented `Data`.

## Selected verbs

`faces`:

| Verb | Effect |
|---|---|
| `create` | Create a face with given URI. Returns `face-id`. |
| `destroy` | Destroy a face by `face-id`. |
| `update` | Adjust persistency / congestion-policy on an existing face. |
| `list` | Stream `FaceStatus` dataset. |
| `events` | Notification stream of `FaceEvent` (open / close / counters). |

`fib`:

| Verb | Effect |
|---|---|
| `add-nexthop` | Add a face as a nexthop for a prefix; with cost. |
| `remove-nexthop` | Drop a nexthop. |
| `list` | Stream `FibEntry` dataset. |

`rib`:

| Verb | Effect |
|---|---|
| `register` | Register a prefix (with origin, cost, expiry). |
| `unregister` | Drop a registration. |
| `list` | Stream `RibEntry` dataset. |
| `events` | Notification stream of `RouteEvent`. |

`strategy-choice`:

| Verb | Effect |
|---|---|
| `set` | Pin a strategy under a prefix. |
| `unset` | Revert to inherited strategy. |
| `list` | Stream `StrategyChoice` dataset. |
| `events` | Notification stream of `StrategyEvent`. |

`cs`:

| Verb | Effect |
|---|---|
| `info` | Return capacity / hit / miss / size. |
| `config` | Adjust admission policy at runtime. |
| `erase` | Erase entries matching a prefix. |

`reflexive` (ndn-rs extension; reflexive-forwarding control):

| Verb | Effect |
|---|---|
| `enable` / `disable` | Toggle installing new reverse routes (`disable` drains gracefully). |
| `config` | Set the per-face cap and route-lifetime ceiling. |
| `flush` | Drop all reverse routes immediately. |
| `info` | Settings, live route count, and counters. |

The full per-module verb list is in each module file's
docstring.

## Authentication

The forwarder's `[mgmt.auth]` section decides whether commands need
a signed Interest. Local Unix-socket commands are unauthenticated
by default (filesystem permissions are the security boundary).
Network-face mgmt commands are signed; the signer identity is
configured via `[mgmt.auth] signer = "/your/operator"`.

## Notifications

Notification verbs (`events`) return an SVS-style stream of typed
events. The Develop-tier consumer is `Subscriber`:

```rust,ignore
use ndn::{Subscriber, SubscriberConfig};
# async fn run() -> anyhow::Result<()> {
let mut sub = Subscriber::connect(
    "/tmp/ndn-fwd.sock",
    SubscriberConfig::new("/localhost/ndn-fwd/faces/events"),
).await?;
while let Some(sample) = sub.next().await {
    println!("face event: {:?}", sample.content());
}
# Ok(()) }
```

## See also

- [Extend tier → MgmtModule](../api/extend.md#mgmtmodule).
- [ndn-fwd](../operations/ndn-fwd.md) — `ndn-ctl` operator CLI.
- [Running the dashboard](../guides/running-the-dashboard.md) —
  graphical mgmt consumer.
- `crates/spec/ndn-mgmt/src/modules/` — implementation.
