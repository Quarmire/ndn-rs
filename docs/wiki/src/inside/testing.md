# The testing guide

ndn-rs tests **behaviour, by exercising behaviour** — not by grepping source
text. That is a deliberate choice with a history: an earlier ~290-script
"audit-witness" suite asserted things about the *spelling* of the code and
rotted silently. It was retired in favour of `cargo nextest` as the single
source of truth for in-repo behaviour. Read
[ADR 0005](./adr/0005-retire-audit-witness-suite.md) for the full story; the
short version is that a test should survive a refactor that moves code around,
and a green run should *mean* something.

This page is the map: the layers, what each guards, and how to run them.

## The layers at a glance

| Layer | Location | What it guards | How to run |
|---|---|---|---|
| **Unit** | inline `#[cfg(test)] mod tests` in `src/*.rs` (~229 files) | Per-function logic, decode/encode edge cases, decision kernels | `cargo nextest run -p <crate>` |
| **Integration** | each crate's `tests/*.rs` (~66 files) | Cross-module behaviour, end-to-end packet flow in-process | `cargo nextest run --workspace` |
| **Property** | `tests/props.rs` in `ndn-tlv`, `ndn-packet`, `ndn-mgmt-wire`, `ndn-sync` (`proptest`) | Wire invariants over random input (round-trips, "never panics") | `cargo nextest run --workspace` |
| **Doctests** | ` ```rust ` blocks in `///` docs | Documented API examples still compile and run | `cargo test --workspace --doc` |
| **Fuzz** | `crates/core/ndn-packet/fuzz/` (libFuzzer) | Decoder robustness on adversarial bytes | `cargo +nightly fuzz run <target>` |
| **Bench** | `benches/*.rs` (`criterion`, 6 crates) | Performance, and that benches still compile | `cargo bench --workspace` |
| **Interop** | `testbed/interop/*.sh` (opt-in) | Behaviour against real external peers / sibling binaries | `./testbed/interop/run_all.sh` |

## The fast suite (the PR gate)

The default run is the whole in-repo behaviour suite:

```sh
cargo nextest run --workspace   # ~1800 tests in ~25s
cargo test --workspace --doc    # doctests (nextest does not run these)
```

`cargo nextest` runs each test in its own process, in parallel, isolated — so a
green run is a real signal. The suite finishes in **~25 seconds for ~1800
tests**, which is only possible because timeout-dependent behaviour is tested
under a **virtual clock** rather than by sleeping — see
[ADR 0004](./adr/0004-virtualize-the-clock.md). This is the same work the CI
`test` job runs on every PR.

Two nextest profiles live in `.config/nextest.toml`:

| Profile | `fail-fast` | Retries | Slow-timeout | Extra |
|---|---|---|---|---|
| `default` (local) | `true` — stop early so the break is at the bottom of your terminal | none | warn at 60s, kill at 3× | — |
| `ci` (the gate) | `false` — report the full failure set | `1` — absorbs scheduler jitter in convergence/suppression-window tests; a pass-only-on-retry test is flagged **FLAKY** | warn at 120s, kill at 2× | JUnit → `junit.xml` |

Select the gate profile with `cargo nextest run --workspace --profile ci`.

### What "integration" covers here

The in-process engine is the workhorse fixture: an integration test wires faces
(often `InProcFace` pairs), installs FIB routes, and asserts a Data comes back
for an Interest — no sockets, no sleeps. Representative files:
`ndn-engine/tests/forwarding_conformance.rs`, `.../self_learning.rs`,
`.../congestion_feedback.rs`; `ndn-app/tests/node.rs`,
`.../rdr_round_trip.rs`, `.../secure_fetch.rs`;
`ndn-sync/tests/convergence.rs`; `ndn-mgmt/tests/notifications.rs`.

### Property tests

`proptest` generates random inputs to check invariants the old GREP-PROOFs only
gestured at. The wire crates carry a `tests/props.rs` each — e.g.
`ndn-tlv/tests/props.rs` (`varu64_roundtrip_with_minimal_width`,
`read_tlv_never_panics`), `ndn-packet/tests/props.rs` (`interest_roundtrip`,
`data_roundtrip`, `name_uri_roundtrip`), and `ndn-sync/tests/props.rs`
(`psync_iblt_decode_never_panics`).

## Fuzzing the wire surface

The decoders are the untrusted-input boundary, so they are fuzzed with libFuzzer
under `crates/core/ndn-packet/fuzz/` (a self-contained sub-workspace). Four
targets, each with a committed seed corpus under `fuzz/seeds/<target>/`:

| Target | Guards |
|---|---|
| `decode` | Full Interest/Data packet decode |
| `name` | Name / URI parsing |
| `tlv` | The TLV varint / type-length codec |
| `mgmt_wire` | NFD `ControlParameters` / `ControlResponse` decode |

Run one locally (nightly toolchain + `cargo-fuzz`):

```sh
cargo +nightly fuzz run decode crates/core/ndn-packet/fuzz/seeds/decode
```

The grown corpus (`fuzz/corpus/`) is git-ignored; only the seeds are committed.
Nightly CI runs each target for 5 minutes from its seeds.

## Interop (external peers)

Some behaviour cannot be covered by an in-process test: talking to a real
Dockerized **NFD / ndnd / NDNCERT CA / C++ PSync**, or spawning **sibling-repo
binaries** (`ndn-fwd`, `ndn-dashboard`) across process/socket boundaries. Those
survived the witness-suite retirement as the explicitly **opt-in**
`testbed/interop/` suite — deliberately *not* part of the PR gate:

```sh
./testbed/interop/run_all.sh                # everything
./testbed/interop/run_all.sh psync ndncert  # name-filtered subset
```

Each script exits `0` PASS / `1` FAIL / `2` SKIP (a missing prerequisite such as
Docker or a sibling checkout). Recorded evidence — including live interop pcaps
(`c13_ndncert_live_interop_after.pcap`, `g04_nlsr_interop_after.pcap`) — is kept
under `testbed/transcripts/`, and the frozen audit ledger is
`testbed/EXPECTED_FAILURES.md`. Some scripts still carry pre-split path rot and
must be revalidated before their class is wired into a scheduled job; this is
called out in `testbed/interop/README.md`.

## The nightly deep lane

The PR gate stays fast by pushing everything slow or broad into
`.github/workflows/nightly.yml` (daily, plus manual `workflow_dispatch`):

| Job | What it does |
|---|---|
| `coverage` | `cargo llvm-cov nextest --workspace`, emits `lcov.info` + a step summary |
| `feature-matrix` | `cargo hack check --each-feature --no-dev-deps` over the wire/API crates — catches a feature combination that doesn't compile |
| `macos` | `cargo nextest run --workspace` on `macos-latest` (the ndrv face + kqueue paths) |
| `bench-smoke` | `cargo bench --workspace -- --test` — runs each bench once to catch bench rot without trusting timing |
| `fuzz` | `cargo +nightly fuzz run <t>` for all four targets, 5 min each from the seed corpora |

## The PR gate itself (`ci.yml`)

For completeness, every job the `ci.yml` lane runs (all required, parallel,
cache-backed): `lint` (fmt + clippy, `-D warnings`), `test` (nextest `ci`
profile + doctests), `docs` (rustdoc, broken links are errors), `msrv`
(`cargo check` on 1.90), `wasm32` (the forwarding chain up to `ndn-engine`),
`no_std` (the `riscv32imc` seed chain), `deny` (cargo-deny), `dep-direction`
(the spec-set-closed guard), and `book` (this wiki builds, internal links
resolve, `{{#include}}` snippets still compile). The lint and dependency policy
those jobs enforce is documented in
[the contribution workflow](./contributing.md).

## What to add when you touch code

- **New behaviour** → an integration or unit test that exercises it.
- **New decode path / wire field** → extend the round-trip and property tests,
  and update [the conformance matrix](./conformance-matrix.md).
- **New timeout-sensitive logic** → test it under the virtual clock, not
  `sleep`.
- **A new external-peer surface** → an opt-in `testbed/interop/` script, not a
  gate test.

Do not add a test that asserts *how the source is written*. If you find yourself
grepping the codebase in a test, you are re-creating the mistake ADR 0005
retired.
