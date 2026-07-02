# The cross-repo contract

ndn-rs is the foundation of a workspace of sibling repositories — `ndn-ext`,
`ndn-fwd`, `ndn-repo`, `ndn-sim`, `ndn-embedded`, `ndn-mobile`, `ndn-dashboard` —
each a standalone cargo workspace that depends on ndn-rs crates by path. The
**contract** is the public API those siblings consume. Breaking it does not break
one crate; it breaks the workspace. This page names that surface so you know what
to treat with the most care.

The load-bearing edges are also drawn in [the crate graph](./architecture/crate-graph.md)
as the "consumed by sibling repos" satellites. This page makes the item-level
detail explicit.

## What "the contract" is

A change is contract-breaking if it alters a **public item a sibling imports** in
a way that stops the sibling compiling or changes its runtime behaviour: renaming
or removing a `pub` type/trait/fn, changing a signature, tightening a bound,
reordering enum variants a sibling matches on, or changing wire behaviour behind
a stable API. Adding items is safe; changing or removing existing ones is not.

Two mechanisms keep this honest:

- **`build_all.sh`** (at the `ndn-workspace` root, one level above ndn-rs)
  compiles every sibling in order against your working tree:
  ```sh
  # from the ndn-workspace root
  ./build_all.sh                 # cargo build across all siblings
  ./build_all.sh --all-features  # extra cargo flags are forwarded
  ```
  It loops `ndn-rs ndn-ext ndn-fwd ndn-mobile ndn-embedded ndn-repo ndn-sim` and
  `cargo build`s each. A red `build_all.sh` after an ndn-rs change is a
  contract break — even when ndn-rs itself is green.
- **`cargo-semver-checks`** runs in CI (the `semver` job in `ci.yml`, on pull
  requests) to catch the break *mechanically* — it diffs the public API of the
  load-bearing crates against the PR's merge-base and fails on a
  major-incompatible change, so a breaking edit is caught in the PR rather than
  in a sibling's build. `build_all.sh` is the complementary end-to-end backstop;
  run it whenever you touch a top-5 crate.

## The top five: treat with most care

These are the crates the siblings reach into deepest. Change a `pub` item here
only deliberately, and run `build_all.sh` when you do.

| Crate | Key exported items | Consumed by |
|---|---|---|
| **`ndn-packet`** | `Name`, `NameComponent`, `Data`, `Interest`, `Selector`, `MetaInfo`, `Nack`, `NackReason`, `SignatureInfo`, `encode::InterestBuilder` / `encode::DataBuilder`, `tlv_type` | **All siblings** — the universal core |
| **`ndn-transport`** | `FaceId`, `FaceError`, `FaceKind`, `FacePersistency`, `Face`, `Transport`, `LinkService`, `ForwardingAction`, `NackReason` | `ndn-ext`, `ndn-fwd`, `ndn-mobile`, `ndn-sim` |
| **`ndn-app`** | `Node`, `Consumer`, `Producer`, `EngineAppExt`, `Subscription`, `Publisher`, `prelude` | `ndn-ext`, `ndn-mobile`, `ndn-sim`, `ndn-repo`, `ndn-dashboard` |
| **`ndn-engine`** | `ForwarderEngine`, `EngineBuilder`, `EngineConfig`, `ShutdownHandle`, `pipeline::{ForwardingAction, PacketContext, DecodedPacket, …}` | `ndn-fwd`, `ndn-ext`, `ndn-sim` |
| **`ndn-security`** | `Signer`, `Validator`, `KeyChain`, `SafeData`, `Verifier`, `TrustPolicy`, `SecurityManager`, `safebag::SafeBag`, `custodian` (feature) | `ndn-ext`, `ndn-mobile`, `ndn-dashboard`, `ndn-fwd` |

Names in the table are verified against each crate's `src/lib.rs`. Two nuances
worth remembering when you edit signatures:

- `InterestBuilder` / `DataBuilder` are under `ndn_packet::encode`, which is
  `#[cfg(feature = "std")]`-gated (also reachable via `ndn_app::prelude`).
- `EngineBuilder` / `EngineConfig` are **non-wasm only**; the browser build uses
  `WasmEngineBuilder` / `WasmEngineConfig`. A change to the native builder should
  be mirrored there — the dashboard's wasm engine depends on it.
- `custodian` in `ndn-security` is `#[cfg(feature = "custodian")]` and not
  re-exported at the crate root; the `SafeBag` type lives in
  `ndn_security::safebag`.

## Dependency intensity

How deeply each sibling reaches into the top five (approximate `use` counts) —
a rough guide to who feels a break the hardest:

| Sibling | `ndn-packet` | `ndn-transport` | `ndn-app` | `ndn-engine` | `ndn-security` |
|---|---:|---:|---:|---:|---:|
| `ndn-ext` | heavy | heavy | heavy | heavy | heavy |
| `ndn-sim` | moderate | light | moderate | heavy | — |
| `ndn-mobile` | moderate | light | heavy | light | moderate |
| `ndn-fwd` | moderate | moderate | light | light | moderate |
| `ndn-repo` | moderate | light | light | light | light |
| `ndn-dashboard` | light | light | light | light | moderate |
| `ndn-embedded` | light | — | — | — | — |

Reading the table:

- **`ndn-ext`** is the heaviest consumer of every crate — it is where most
  extensions live, so a contract change is felt there first and worst. If you
  break something, `ndn-ext` usually tells you.
- **`ndn-sim`** leans on `ndn-engine` and `ndn-app` (it drives simulated
  forwarders) but pulls **no** `ndn-security` — a security-only change cannot
  break it.
- **`ndn-embedded`** depends on `ndn-packet` alone, consistent with a `no_std`
  target: it pulls none of engine/transport/app/security. Anything you keep
  `no_std`-clean in the foundation crates keeps it building.

## How to change the contract safely

1. **Prefer additive changes.** New methods, new optional fields, new variants at
   the end — none of these break a sibling.
2. **When you must break it, do it deliberately** and update the siblings in the
   same logical change (they are separate repos, but the workspace builds as a
   whole). Run `build_all.sh` from the workspace root before you consider it
   done.
3. **Bump versions honestly.** ndn-rs is pre-1.0; a breaking change to a top-five
   crate is a minor bump, and the CI `semver` job will hold you to it.
4. **Load-bearing decisions get an ADR.** If a contract change encodes a design
   decision the workspace now depends on, record it — see
   [about ADRs](./adr/README.md) and [the contribution workflow](./contributing.md).

## See also

- [The crate graph](./architecture/crate-graph.md) — the same edges, drawn.
- [The contribution workflow](./contributing.md) — the dependency-direction rule and the PR checklist.
