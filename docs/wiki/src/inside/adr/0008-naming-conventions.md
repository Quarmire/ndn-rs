# 0008 · Crate naming and grouping conventions

**Status:** Accepted

## Context

The 2026 multi-repo split left the workspace with ~90 crates across
thirteen repos, and the names accreted conventions nobody wrote down: three
different things called `-core`, a `faces/` directory holding non-face
crates, one crate with a `-rs` suffix, and a package whose library has a
different name. Each was decided deliberately at the time; this ADR records
the conventions so new crates follow them, and records the known debt so
nobody "fixes" it casually — or mistakes it for a convention to imitate.

## Decision

**1. Crates live in role directories, never bare under `crates/`.** In
ndn-rs the roles are fixed: `crates/{core,forwarding,faces,security,app,
platform,protocols}/`; ndn-ext uses the same pattern with its own roles
(`faces/`, `routing/`, `service/`, `strategies/`, …). A new crate joins the
existing directory matching its role. A crate earns a **new** group
directory only when its role genuinely fits no existing group — not by
crate count: single-crate groups are normal (ndn-ext's `coding/`,
`discovery/`), because the directory names the *role*, and roles outlive
individual crates. Scope (`[package.metadata.scope]`) is orthogonal:
grouping is by what a crate *is for*, not its stability bucket.

**2. `-core` means one of three things — say which when you name one.**

- *Lower-half protocol split*: `ndn-X-core` is the pure, sans-IO/no_std
  lower half of protocol X — wire codec + state machine, no async, no
  sockets — and a driver crate runs it against real I/O.
  `ndn-svs-core` (SVS state-vector logic + codec; `ndn-sync` drives it),
  `ndn-nan-core` / `ndn-nan` (ndn-ext), `ndn-signals-core` (taxonomy +
  traits; signal sources feed it), `ndn-discovery-core` (wasm-safe trait
  shapes; ndn-ext's `ndn-discovery` adds the native protocols). This is
  the ADR 0003 seed-crate pattern applied to one protocol.
- *Repo-split seam*: `<repo>-core` is the library half that stays on this
  side of a repo boundary, and the sibling repo of that name builds on it.
  `ndn-fwd-core` (ndn-rs: the runtime-agnostic forwarding rules the
  ndn-fwd daemon repo ultimately builds on), `ndn-dashboard-core`
  (ndn-ext: the headless, Dioxus-free layer the ndn-dashboard repo's UIs
  build on), `ndn-service-core` (the Service/Carrier contract under
  ndn-ext's service stack).
- *Plain module*: the suffix just marks shared inner code with **no upper
  half of the same name anywhere** — `ndn-crypto-core` (the no_std
  Ed25519/SHA-256 signed-region core; there is no `ndn-crypto`).

New crates should prefer the first two senses; the third is grandfathered,
not a pattern to extend. When a name would be ambiguous between senses
(as `ndn-fwd-core` is — it is *also* an ADR 0003 sans-IO seed), the crate's
`description` must disambiguate.

**3. `faces/` directories hold faces.** A crate in a `faces/` group
implements (or is the platform backend of) a `Face`/`Transport`. Recorded
debt: ndn-ext's `crates/faces/` currently also holds non-face crates that
grew up alongside the faces — `ndn-ipc-shm` (IPC data plane), `ndn-nan` +
`ndn-nan-core` (NAN protocol driver/core), `ndn-radio-cognition` (radio
control plane), `ndn-rtc-signaling-relay` (an HTTP rendezvous server).
They stay put until a deliberate reshuffle (moves are `[patch]`-visible
churn for every path-dep consumer), but the rule is prescriptive for new
crates: if it isn't a face, it doesn't go in `faces/`.

**4. No `-rs` suffix on crates — with one recorded exception.** The repo is
ndn-rs; its crates don't repeat that. `ndnsf-rs` (ndn-ext, the NDN Service
Framework compat crate) is the lone exception, named when it tracked an
external framework's identity. Renaming a published-by-path crate breaks
every consumer at once, so the rename is **deferred to the next breaking
tag**; do not add a second `-rs` crate in the meantime.

**5. The prelude package is `ndn-rs-prelude`; its library is `ndn` —
deliberately.** App code reads `use ndn::Node;` (the name the ecosystem
should see), while the package name stays unambiguous and greppable across
thirteen repos — and the bare `ndn` name on crates.io is held by an
unrelated 2018 placeholder, so the package could not claim it anyway.
Consumers write the rename in one place:
`ndn = { package = "ndn-rs-prelude", git = …, tag = … }`. Do not "fix" the
package/library mismatch: it is the design.

## Consequences

- **Positive:** a new crate has a deterministic home and name: pick the
  role directory, pick the `-core` sense (and say it in the description),
  no `-rs`, and the app-facing surface stays behind the one `ndn` umbrella.
- **Positive:** the debt is fenced: the non-face crates in ndn-ext's
  `faces/` and the `ndnsf-rs` suffix are known, bounded, and scheduled
  (reshuffle / next breaking tag) rather than silently normative.
- **Cost:** three live senses of `-core` remain until a future breaking
  pass; readers must consult the crate description, not the suffix alone.
- **Cost:** `[package] name` ≠ `[lib] name` for the prelude surprises
  first-time contributors; the front-door docs carry the explanation.

## Alternatives considered

- **Flat `crates/` (the pre-split layout).** Rejected: at ~30 crates per
  repo the flat listing hid the architecture; the role directories *are*
  the layer map's top level.
- **One blessed meaning for `-core` and rename the rest now.** Rejected
  for now: every rename is a breaking change for path-dep siblings and the
  pinned `ndn-course`; batching renames into the next breaking tag costs
  less than three separate migrations.
- **Rename the package to `ndn` on a private registry.** Rejected: a
  registry adds infrastructure for one cosmetic win; the `package =`
  rename line gives consumers the same ergonomics today.
