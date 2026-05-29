# Dashboard next

`ndn-dashboard-next` is the browser-first rewrite scaffold for the
operator dashboard. It lives beside the legacy dashboard so the new
architecture can prove itself without breaking existing workflows.

The first milestone is a working vertical scaffold:

- **Observe** — NDN-native traces, span timeline, PIT fan-out, CS and
  strategy attributes, and correlated logs.
- **Trust** — TrustContext posture, identity/context selection,
  anchors, schema summaries, and approvals.
- **Engine** — read-only faces, routes, strategy, CS/PIT, traffic,
  and capability profile views.
- **Tools** — ping, peek, put, iperf, trace lookup, and route/face
  diagnostics as structured workflows.
- **Settings** — attach targets, platform services, density, and
  deployment status.

## Run

Desktop target:

```sh
cargo run -p ndn-dashboard-next
```

Browser target is a first-class deployment path. Build it with the
`web` feature and serve the generated static assets through the normal
Dioxus web workflow:

```sh
dx serve --package ndn-dashboard-next --platform web --features web --no-default-features
```

The milestone-one UI still uses fixtures for browser-safe transports that are
not yet implemented, but desktop local attach now shares live seams for Engine
management and Observe span Data. Attach controls switch between
browser-engine, ndn-rs-native, NFD, and YaNFD profiles so the layout,
capability degradation, and responsive behavior remain visible while each live
transport lands.

Settings now treats attach as an operator workflow instead of a collection
of loose mock buttons. Saved and recent targets are modeled per platform,
selected targets can be probed, and the capability matrix shows the source
probe behind each feature state. This keeps browser, desktop, relay, NFD,
YaNFD, and ndn-rs-native paths on the same UI contract while live transport
adapters are added.

## Architecture

The crate is shaped for a future standalone repository:

| Module | Role |
|---|---|
| `app` | Dioxus shell, responsive layout, routing, platform bootstrap. |
| `core` | Pure models, capability sets, posture derivation, fixtures. |
| `client` | Attach targets and capability probing seams. |
| `engine` | Read-only forwarder datasets and Engine view models. |
| `observe` | OTLP Span decode, `<prefix>/recent` parsing, live span fetch, trace grouping, observability view models. |
| `identity` | Dashboard-facing adapters over reusable trust/identity APIs. |
| `tools` | Structured network-test run state, workflow adapters, result normalization, Observe pivot refs. |
| `platform` | Browser vs desktop services and deployment affordances. |

The dashboard does not own trust semantics or private key storage.
Those remain in `ndn-security`, `ndn-identity`, `ndn-cert`, and the
custodian APIs. The dashboard is the operator UX layer.

The Trust workspace mirrors that boundary in its view models. It renders
TrustContext rows, identity/custodian state, anchors, schema summaries,
approval requests, SafeBag import preview warnings, key/cert inventory,
validation evidence, and schema-review posture without creating dashboard-owned
private key state. Browser profiles surface explicit custodian/storage warnings
so browser deployment remains a first-class target without quietly becoming a
key owner. Desktop builds can feed the same view models from
`ndn-security::Keyring` / `ndn-security::TrustContext` snapshots and
`ndn-identity::TrustContext` identity/custodian snapshots; browser builds keep
the boundary as static dashboard models until browser-safe attach transports
provide those snapshots. The workspace separates **adopt-to-verify** execution
(bootstrap ticket parsing, required out-of-band confirmation, and
`adopt_with_tofu` against the reusable keyring) from
**enroll-to-be-verified** execution (a connected `NdncertClient`, custodian
signer, NDNCERT challenge parameters, and issued-certificate result framing).
Validation evidence is framed from `Validator::trace`, and DID evidence is
derived from reusable certificate-to-DID conversion instead of a dashboard-only
DID preview. The Trust screen is organized as a security cockpit rather than an
inventory of crate concepts. It leads with four operator checks: whether fetched
Data can be verified, whether this node can sign, whether management is
protected by the selected trust context, and whether approvals or adoption work
needs attention. Compact Verify, Sign, Trace, and Maintenance panels expose the
supporting status at a glance. Context, anchor, schema, certificate,
validation-path, DID, SafeBag, approval, adoption, and enrollment details move
into focused dialogs so the first view stays readable while still allowing deep
operator workflows.

Mutation workflows are preflighted before execution. The dashboard models each
write as a typed operation, then checks target write capability, ndn-rs-native
support, TrustContext availability, signed-command posture, platform path, and
whether destructive actions need explicit confirmation. Trust dialogs already
show these gates. The first live execution adapters cover face create/destroy,
route add/remove, strategy set/unset, CS capacity, CS erase, and graceful
shutdown for desktop local attach through `ndn_ipc::MgmtClient`; browser and
relay targets show that the browser-safe mutation transport is not wired yet.
Reconnect remains a dashboard session action. Following the old dashboard's
useful session recorder, dashboard-next records replayable writes as typed
operations instead of stringly `DashCmd` entries, exposes retryable transport
failures separately from hard failures, and can replay the typed mutation
session after a restart. Trust-specific writes are separate follow-up slices.

The Tools workbench consumes reusable tool crates rather than reimplementing
packet workflows in UI code. Desktop local attach runs `ndn-tools-core` ping,
iperf, peek, and put workflows where the selected forwarder supports compatible
tool transport, converts structured events into `ToolRun` samples and summaries,
and carries names/prefixes as Observe pivot references. Tool forms expose the
same operational knobs the workflows need: ping count/interval/lifetime, iperf
duration/window/congestion/auth/reverse tuning, peek pipeline/output/fetch
flags, and put payload/chunk/freshness/signing controls. The workbench uses a
focused tabbed editor rather than a wall of tool cards, keeps a session result
table for concurrent runs, supports filtering and selected-result download, and
opens samples in collapsible detail cards. The detail rail can collapse to
compact two-letter tool icons that retain full labels through accessible names
and tooltips. Failed runs are promoted into error rows, a workbench alert, and
detail-card error messages rather than being hidden in clipped result text.
Iperf detail cards show a compact throughput sparkline, and
congestion-control-specific fields are hidden unless they apply to the selected
algorithm. Trace lookup, route diagnostic, and face diagnostic run directly
against the dashboard's Observe and Engine view models. Browser builds keep the
same UI state model but return explicit browser-safe transport guidance until
the browser tool transport is wired. Long-running server controls are
represented as capability-gated rows; durable lifecycle management remains a
follow-up session-manager task.

## Compatibility

NFD and YaNFD start as read-only compatibility profiles. Missing
ndn-rs-native features are represented as unavailable capabilities
rather than broken controls. ndn-rs-native profiles enable richer
TrustContext and observability surfaces when probes confirm support.

Attach probing is ordered deliberately:

1. Probe NFD-compatible management datasets such as
   `/localhost/nfd/status/general` and `/localhost/nfd/faces/list`.
2. If the target speaks the common management surface, probe ndn-rs native
   extensions for capabilities, observability, TrustContext, and tools.
3. Normalize the result into a `CapabilitySet` so non-ndn-rs forwarders
   stay useful as read-only targets while unavailable native features remain
   explicit.

Browser engine, browser remote, desktop local, and relay attach paths all
use the same dashboard-facing probe transcript. Browser targets must use a
browser-safe NDN transport, in-page engine, or documented relay; the next
dashboard does not make a dashboard-only HTTP proxy the primary attach
architecture.

Preference persistence is platform-scoped through
`ndn-dashboard-next:{browser|desktop}:preferences:v1`. Browser builds store
preferences in `localStorage`; desktop builds store a JSON file under the
local config directory. The saved payload covers density, saved targets,
recent targets, and selected target state. Tests keep an in-memory store for
fast model coverage.

## Witnesses

Focused attach witnesses live with the rest of the testbed:

```sh
testbed/tests/audit/dashboard_next_desktop_attach_ndn_fwd.sh
```

That script builds and boots a temporary local `ndn-fwd`, verifies
`status/general` and `faces/list` over its Unix management socket, and
then applies the dashboard-next desktop attach normalization.

Browser attach is covered by an opt-in Playwright witness:

```sh
dx serve --package ndn-dashboard-next --platform web \
  --features web --no-default-features --port 8124
DASHBOARD_NEXT_URL=http://127.0.0.1:8124 \
  npx playwright test dashboard_next_attach_witness.spec.ts
```

The browser witness selects the in-page engine target, probes it, and checks
that Settings renders browser-safe attach evidence without relying on a
dashboard-only HTTP proxy.

Engine compatibility has a dedicated browser witness:

```sh
DASHBOARD_NEXT_URL=http://127.0.0.1:8124 \
  npx playwright test dashboard_next_engine_compat.spec.ts
```

The Engine view consumes normalized read-only dataset snapshots: forwarder
status, faces, FIB/RIB routes, strategy-choice, CS/PIT, traffic counters,
dataset freshness, and selected detail state. NFD and YaNFD profiles render as
read-only compatible targets with native-only controls hidden or degraded.
Desktop local attach polls live NFD-compatible management through
`ndn-ipc::MgmtClient`; browser-safe targets use the same Engine model seam so
remote web transports and in-page engines can land without changing the UI.

The Observe view consumes the ndn-rs native observability wire shape:
`<prefix>/recent` returns newline-separated `trace-id/span-id` references, and
each span is fetched from `<prefix>/traces/<trace-id>/spans/<span-id>` as raw
OTLP Span protobuf Data. Desktop local attach fetches those Data packets through
`ndn-app::Consumer`, decodes them into `TraceView`, and renders the trace feed,
stage strip, parent/child span tree, PIT fan-out rows, CS attribution, strategy
field, trace-correlated log evidence, and bridge/export status. Desktop local
attach also polls `log/get-recent`; log lines are matched under the selected
trace by trace ID, span ID, span name, Interest name, face ID, target, and
strategy rather than becoming a primary Observe navigation surface. Bridge
status is explicit: the dashboard reports unavailable/unknown/not-attached
states until `ndn-otel-bridge` exposes a real heartbeat, and it can surface
bridge activity or errors when recent logs mention the bridge. Disabled,
degraded, unsupported, and fetch-error states are first-class operator guidance
rather than blank panels.
The trace feed search filters the current trace set by trace ID, span name,
Interest name, face ID, target, strategy, and status.

Observe has two live local `ndn-fwd` witnesses:

```sh
testbed/tests/audit/dashboard_next_observe_disabled_ndn_fwd.sh
testbed/tests/audit/dashboard_next_observe_enabled_ndn_fwd.sh
```

The disabled witness verifies the dashboard guidance state when the publisher is
off. The enabled witness boots `ndn-fwd` with `publish_to_ndn = true`, drives
management traffic, fetches `/recent`, fetches span Data, and verifies the
dashboard decodes at least one live OTLP span into the Observe trace list.

## Responsive density

The default density is compact operational:

- Desktop uses a persistent but collapsible side nav, sticky attach bar,
  multi-pane workbench, and dense tables. Collapsed navigation uses an
  icon-only control, keeps compact workspace icons, and preserves full labels
  through accessible names and hover titles.
- Tablet collapses navigation and keeps two-pane/detail-drawer style
  workflows.
- Phone uses bottom navigation, sticky posture chips, single-pane task
  flow, stacked result rows with readable status chips, and full-width detail
  panels.

Mobile aims for parity. If a workflow becomes too complex for a phone,
the fallback is an operator companion version: status, trace lookup,
tool summaries, trust approvals, and quick diagnostics.
