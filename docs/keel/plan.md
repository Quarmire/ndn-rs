# The Keel — build plan (M0)

Substrate crates, siblings of ndn-time; the Waterline suite consumes, never the reverse.

## Placement
- `crates/core/ndn-manifest`      — [scope]=spec · no_std+alloc · zero deps (not even sha2: SHA-256 in-crate, see DECISIONS D-K2)
- `crates/core/ndn-render-contract` — [scope]=spec · no_std+alloc · depends only on ndn-manifest
- `crates/tools/ndn-bench`        — [scope]=tool · std binary (scripts→canon, L-01…L-15, `doc`, `vectors`, `freeze`)
- `examples/waterline-keel`       — Dogfood #1; emits its report *as a manifest* (§10)
- `conformance/`                  — strata/ (.ndfs), fixtures/, vectors/ (.ndfv), FREEZE.md
- `docs/keel/`                    — this plan, DECISIONS.md, FRICTION.md

## Order of work (each gate = a runnable command)
- M1  model + canon (R1–R13). Gate: `cargo test -p ndn-manifest` — proptest round-trip + W-03/07/11/22 rejects.
- M2  dag + lock + fixed point. Gate: `cargo run -p ndn-bench -- freeze --pin` pins H(V₀.2)/H(T₀)/H(IM₀)
      into conformance/FREEZE.md + the baked constant; W-19 → Unresolved.
- M3  matcher (4 verdicts, frontier, budget, floor). Gate: C9-07/08, C10-divergence, bomb tests in
      `cargo test -p ndn-render-contract`.
- M4  bench: .ndfs/.ndfm/.ndfc grammars + sugars w/ exact expansions, L-rules, `bench doc`.
      Gate: apiary publishes 0 err / 2 info; `bench doc loss` shows ordinal-coarsening.
- M5  corpus materialized under conformance/vectors/. Gate: `bench vectors conformance/vectors`
      reports per family; shortfalls logged in the ledger, zero padding.
- M6  dogfood + CI: waterline-keel prints all four verdicts for pylon-7 + hold-1 vs T₀ + a card
      contract; `check-independence` job asserts zero ndf-* and --no-default-features builds.

## Session constraints (honesty up front — FRICTION F36–F38)
- No Rust toolchain reachable from this session: every gate ships as a test/command; none is
  demonstrated green here. First `cargo test` on this machine is the real M-gate run.
- Round-2 page (ndf-the-gauntlet.html) not provided; C-family targets taken from the Atelier ledger.
- No Riverwatch fixture exists on disk; pylon-7 + hold-1 are authored per corpus description.

## Non-goals (do not drift)
Sextant/Capstan views; Observatory authorize/instantiate; wasm sandboxing; ceremony countersigning
(slot left explicit in FREEZE.md); the register's other 39 gaps.
