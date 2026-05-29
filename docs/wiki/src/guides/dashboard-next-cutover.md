# Dashboard Next Cutover

Dashboard-next remains a preview until browser and desktop both satisfy the
agreed parity bar. Legacy `ndn-dashboard` stays runnable during that period.

Migration map:

| Legacy area | Dashboard-next destination |
| --- | --- |
| Overview, faces, routes, CS, strategy | Engine |
| Tools | Tools workbench |
| Security, onboarding, SafeBag, audit | Trust |
| Logs and trace evidence | Observe plus Trust audit |
| Config and dashboard settings | Settings |
| Fleet, radio, coding, rate limit | Engine extension panels |

Coverage matrix:

| Surface | Desktop ndn-rs | Browser ndn-rs | NFD | YaNFD |
| --- | --- | --- | --- | --- |
| Attach/read-only Engine | live | mock/browser-safe pending | read-only | read-only |
| Mutations | local IPC | blocked until safe write transport | read-only | read-only |
| TrustContext | reusable crates | custodian-bound | unsupported | unsupported |
| Observe | live spans | browser-safe transport pending | degraded | degraded |
| Tools | live adapters | explicit guidance | compatible subset | compatible subset |

Repo split decision: split after Attach, Trust, Observe, Tools, Engine live data,
browser deployment, and desktop mutation workflows are stable enough that the
dashboard can evolve independently without hiding ndn-rs crate API changes.

Preview release notes:

- Browser-first shell with responsive density.
- Capability-normalized attach, Engine, Observe, Trust, Tools, Settings.
- Typed mutation workflow with replayable operation history.
- Config, fleet/routing/radio, extension, logs, deployment, and cutover
  scaffolds ready for live transport expansion.
