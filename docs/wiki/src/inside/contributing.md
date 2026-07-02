# Contribution workflow

This page is the checklist for landing a change in ndn-rs: the lint policy and
why it is shaped the way it is, the toolchain and MSRV discipline, the
dependency-direction rule, and a copy-pasteable command block that mirrors the CI
gate. Everything here is enforced by `.github/workflows/ci.yml`, so a change that
passes locally passes the gate.

## The lint policy

Lints are set once, workspace-wide, in `Cargo.toml` under `[workspace.lints]`;
every crate inherits them. CI escalates warnings to errors with
`RUSTFLAGS: -Dwarnings`, so "warn" here means **"advisory while you hack, error
at the gate."**

```toml
[workspace.lints.rust]
unsafe_code = "deny"

[workspace.lints.clippy]
dbg_macro   = "warn"
todo        = "warn"
unimplemented = "warn"
```

**`unsafe_code = "deny"`** is the load-bearing one. The protocol and forwarding
core is unsafe-free *by policy* — a memory-safety bug in a packet decoder or the
pipeline is a security bug, and denying `unsafe` there means the reviewer never
has to audit for it. Only the two OS-I/O leaf crates that genuinely need it —
**`ndn-face`** (raw sockets, `sendmmsg`/`recvmmsg`, AF_PACKET/ndrv/pcap FFI) and
**`ndn-frame-io`** — opt back in, each with an `#![allow(unsafe_code)]` scoped to
the module or function that owns the raw boundary. `unsafe` is *walled off* in
the crates whose whole job is to touch the OS, and forbidden everywhere else. The
one other exception is the `linkme` `link_section` in the strategy registry,
carried inside the `register_strategy!` expansion with a scoped `#[allow]` so
registrant crates stay clean.

`dbg_macro`, `todo`, and `unimplemented` are warned so a `dbg!` print or a
`todo!()` placeholder cannot reach `main` — they fail the gate.

## Toolchain and MSRV

Two distinct versions, do not conflate them:

- **Pinned toolchain** (`rust-toolchain.toml`): **1.96.0**, with `rustfmt` and
  `clippy` and the `wasm32-unknown-unknown` + `riscv32imc-unknown-none-elf`
  targets. This is what every contributor and CI job *builds with* — it defines
  what rustfmt and clippy enforce. rustup auto-installs it on first `cargo`
  invocation.
- **MSRV** (`rust-version = "1.90"` in `Cargo.toml`): the oldest compiler a
  *consumer* may use. The floor is edition 2024 (1.85); the binding constraint is
  fjall's declared `rust-version` (1.90). The `msrv` CI job runs `cargo check
  --workspace` on exactly this version.

MSRV discipline: do not reach for a `std`/language feature newer than 1.90 in a
crate a sibling consumes, or the `msrv` job goes red. Bump either version only
deliberately, and only with a matching CI run — the pin changes what the whole
project's lints enforce.

## The dependency-direction rule

The crate graph is a DAG, and it is enforced, not merely observed. The
**`spec`-classified crates are closed under dependency**: a spec crate may only
depend on other spec crates, so the wire/protocol layer can never accidentally
pull in an extension or app-layer crate. The `dep-direction` CI job runs
`python3 testbed/dep-direction-guard.py`; a new `Cargo.toml` edge that would
break the layering fails the build. If you need functionality from a higher
layer inside a lower one, invert the dependency with a trait (as `ndn-mgmt` does
with `MgmtConfig`) rather than adding the edge. See
[the crate graph](./architecture/crate-graph.md) for the layers.

## The pre-PR checklist

Before opening a PR, run the gate locally. This block mirrors the CI jobs in
order:

```sh
# format + lint (CI escalates warnings to errors)
cargo fmt --all
RUSTFLAGS="-Dwarnings" cargo clippy --workspace --all-targets

# tests: the fast suite + doctests
cargo nextest run --workspace --profile ci
cargo test --workspace --doc

# docs: broken intra-doc links are errors
RUSTDOCFLAGS="-Dwarnings" cargo doc --workspace --no-deps

# the wiki builds and its {{#include}} snippets still compile
mdbook build docs/wiki
```

For a change that touches the cross-target or dependency surface, also run the
jobs the gate runs for those:

```sh
cargo +1.90 check --workspace                                   # MSRV
cargo check --target wasm32-unknown-unknown -p ndn-engine       # wasm surface
cargo deny check                                                # advisories + licenses
python3 testbed/dep-direction-guard.py                          # spec set closed
```

Then, the content checklist:

- [ ] **fmt / clippy / nextest / doctests / rustdoc are green.**
- [ ] **New behaviour has a test** that exercises it — behaviour, not source
      text (see [the testing guide](./testing.md) and
      [ADR 0005](./adr/0005-retire-audit-witness-suite.md)).
- [ ] **If you touched a wire path**, the round-trip/property/fuzz tests are
      updated *and* you added a row or test name to
      [the conformance matrix](./conformance-matrix.md).
- [ ] **If you changed a top-five public API**, you ran `build_all.sh` from the
      workspace root — see [the cross-repo contract](./cross-repo-contract.md).
- [ ] **If the change encodes a load-bearing decision**, you wrote an ADR.

## When to write an ADR

An Architecture Decision Record captures a decision the rest of the project now
depends on — a wire-format choice, a layering constraint, a security posture, a
determinism seam. If someone six months from now would ask "why is it built this
way, and can I change it?", the answer belongs in an ADR, not a commit message.
The existing records (real NDN wire format, type-enforced verification, the
sans-IO seed crates, the virtualized clock, retiring the witness suite) are the
model. See [about ADRs](./adr/README.md) for the format and index.

## Cross-repo care

ndn-rs is consumed by sibling repositories, and its public API is a contract:
breaking it breaks the workspace, not just one crate. Before changing a `pub`
item in `ndn-packet`, `ndn-transport`, `ndn-app`, `ndn-engine`, or
`ndn-security`, read [the cross-repo contract](./cross-repo-contract.md) — it
names the surface to treat with the most care and explains how to change it
safely.

## See also

- [The testing guide](./testing.md) — layers, how to run, the philosophy.
- [The cross-repo contract](./cross-repo-contract.md) — the public API the siblings consume.
- [About ADRs](./adr/README.md) — when and how to record a decision.
