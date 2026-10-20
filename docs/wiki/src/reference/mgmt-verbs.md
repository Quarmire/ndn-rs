# Management verbs

ndn-rs's management plane is a set of `MgmtModule` impls, each
owning the verbs under one module name. Commands and datasets ride
TLV Interests under `/localhost/<forwarder>/<module>/<verb>`.

For the module-author surface see [Extend tier → MgmtModule](../api/extend.md#mgmtmodule).
For runtime use see `ndn-ctl` in [ndn-fwd](../operations/ndn-fwd.md).

## Module catalogue

One module per row; one file per module under
`crates/forwarding/ndn-mgmt/src/modules/`.

| Module | File | What it owns |
|---|---|---|
| `forwarder-status` | `modules/status.rs` | Forwarder-wide info dataset (uptime, version, counters). |
| `faces` | `modules/faces.rs` | Face create/destroy/list and per-face counters. |
| `fib` | `modules/fib.rs` | FIB list, add-nexthop, remove-nexthop. |
| `rib` | `modules/rib.rs` | RIB register, unregister, list. |
| `strategy-choice` | `modules/strategy.rs` | Strategy set, unset, list. |
| `cs` | `modules/cs.rs` | Content store info, config, erase, list. |
| `routing` | `modules/routing.rs` | Routing-protocol typed status (per `RoutingProtocolStatus`). |
| `discovery` | `modules/discovery.rs` | Discovery-protocol neighbours. |
| `measurements` | `modules/measurements.rs` | Strategy measurement state (Instrument-leaning). |
| `coding` | `modules/coding.rs` | Per-prefix coding adapters. |
| `rate-limit` | `modules/rate_limit.rs` | Token-bucket rate-limit state. |
| `security` | `modules/security.rs` | KeyChain operations. |
| `log` | `modules/log.rs` | Runtime log-filter set/get. |
| `neighbors` | `modules/neighbors.rs` | Neighbour table (joins discovery info with face state). |
| `service` | `modules/service.rs` | Service lifecycle (drain, shutdown). |

The catalogue tracks `crates/forwarding/ndn-mgmt/src/modules/mod.rs` —
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

The Interest (CanBePrefix, MustBeFresh) is answered with segment 0 of a
new version, `<Interest name>/v=<n>/seg=0`, at most 8000 bytes of content
each. The last segment carries `FinalBlockId`. A reader fetches the rest by
exact name, `…/v=<n>/seg=1` up to the `FinalBlockId`, and joins the
contents in order. The daemon holds every segment of a multi-segment
dataset for 10 s after answering, so each segment comes from one snapshot.
A segment of a version no longer held is answered at once with a Data of
ContentType Nack carrying a 404 `ControlResponse`: read the dataset again.
`MgmtClient` reads every dataset this way.

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
| `list` | One page of the names held under a prefix, with the total and whether more follow (ndn-rs extension; see below). |

`cs/list` takes ControlParameters in the name like a command, but is a
public read like `cs/info` and `*/list`: served unsigned under
`/localhost`. `Name` is the prefix (absent: the whole store), `Uri` the
cursor — an NDN URI; the page starts after that name (absent: from the
first) — and `Count` the page size (absent: 100). A `Uri` that is not a
name is refused with 400. The answer is a dataset,
`ndn_mgmt_wire::CsListing` (`MgmtClient::cs_list` decodes it):

```text
CsListing   = CsListTotal [CsListMore] *CsListEntry
CsListTotal = 0x0500 NonNegativeInteger  ; entries held under the prefix
CsListMore  = 0x0508 NonNegativeInteger  ; 1: entries follow this page
CsListEntry = 0x0502 (Name               ; the cached Data's name (0x07)
                      CsEntryBytes       ; 0x0504 NonNegativeInteger: wire size
                      CsEntryFresh)      ; 0x0506 NonNegativeInteger: 1 fresh, 0 stale
```

Entries are the first `Count` under the prefix after the cursor, in
canonical name order. Fresh means the entry still satisfies `MustBeFresh`
at the forwarder's clock. The total counts every entry under the prefix,
on any page. `CsListMore` is present only when entries follow the page.
The page always holds `Count` entries when that many follow the cursor. It
spans as many dataset segments as it needs, so `Count` = 2^64−1 lists
everything in one read.

To page through, ask the first page without a cursor. Then ask each next
page with the last listed name as the cursor
(`CsListing::next_after`), until a page has no `CsListMore`. While the
store is unchanged, every entry comes exactly once, in order. An entry
added or evicted between pages shows up or drops out without shifting the
others. Listing touches neither LRU order nor hit/miss counters. A store
that cannot enumerate (`NullCs`) answers an empty listing with total 0.
Unknown TLVs inside the dataset are skipped.

`reflexive` (ndn-rs extension; reflexive-forwarding control):

| Verb | Effect |
|---|---|
| `enable` / `disable` | Toggle installing new reverse routes (`disable` drains gracefully). |
| `config` | Set the per-face cap and route-lifetime ceiling. |
| `flush` | Drop all reverse routes immediately. |
| `info` | Settings, live route count, and counters. |

`security` (selected; the trust verbs and their answers are specified in
`docs/specs/mgmt-trust.md`):

| Verb | Effect |
|---|---|
| `data-inspect` | Fetch the Data under `Name` (CanBePrefix: content store, else the network), validate it, answer `ndn_cert::report::DataInspection` as JSON: signature, metadata, the trusted prefix covering it, verdict with a coded detail, chain walked. `ExpirationPeriod` bounds the wait (ms). Command gate; answered deferred (`MgmtClient::security_data_inspect`). |

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
use ndn::Subscriber;
# async fn run() -> anyhow::Result<()> {
let mut sub = Subscriber::connect(
    "/tmp/ndn-fwd.sock",
    "/localhost/ndn-fwd/faces/events",
).await?;
while let Some(sample) = sub.recv().await {
    println!("face event: {:?}", sample.payload);
}
# Ok(()) }
```

## See also

- [Extend tier → MgmtModule](../api/extend.md#mgmtmodule).
- [ndn-fwd](../operations/ndn-fwd.md) — `ndn-ctl` operator CLI.
- [Running the dashboard](../guides/running-the-dashboard.md) —
  graphical mgmt consumer.
- `crates/forwarding/ndn-mgmt/src/modules/` — implementation.
