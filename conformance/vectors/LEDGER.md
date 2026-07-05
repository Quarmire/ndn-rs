# The vector ledger — honest counts against the 252 target

The atelier's conformance table targets 252 vectors across the families
below. **Rule: log shortfalls, never pad.** This ledger is the shortfall log.

Updated after the closure pass following the 2026-07-04 freeze (the pins
unblocked the kernel and C3 families; the harness gained `kernel: trio`,
`@kernel-t0`, `kernel-pinned`/`kernel-hash`, and the L-07 two-run check).

| family | target | shipped as `.ndfv` | hosted as Rust tests | shortfall / note |
|---|---:|---:|---:|---|
| C1 fixed point | 6 | 5 (`kernel/`: pinned + three trio-hash goldens recorded at the freeze; C2-01 doubles) | 6 (`ndn-manifest` kernel tests) | boot-refusal-on-mismatch vector needs a fault-injection harness |
| C2 reflection | 18 | 1 (`C2-01-kernel-in-kernel`) | 2 (kernel-describes-kernel) | the meta-tower beyond level one remains unauthored — and level one is all the calculus promises |
| C3 total floor | 9 | 4 (`C3-01/02` T₀ Express under EMPTY frontier — **graduated from Rust per F50**, `C3-03` default-refuse-by-absence, `REFUSE-declared-clause` identity witness) | 2 | opaque-frame media-type variants |
| C4 escape hatch | 12 | 2 (`C4-01` payloads stratum, `C4-02` opaque identity Express) | 1 | silent-escape rejection variants |
| C5 acyclicity | 31 | 0 | 3 (DAG insert ordering, import closure) | cycle-attempt vectors want a multi-file lock harness beyond L-02's self-import |
| C6/C6′ verdicts | 38 | 7 (`verdict/` core four + divergence + severed chain) | 11 (incl. the bomb ×3 budgets) | budget-exhaustion as .ndfv needs a budget: key — deliberate omission, budgets are API not wire |
| C7 independence | 4 | 0 | CI job (`check-independence`) | the property is a build fact, not a byte vector |
| C8 matcher inertia | 26 | 3 (`C8-19` authoring reject, `C8-01` **selection matched without evaluation** — the gauntlet vector, apiary's inert `@range`) | 1 (instance edges ignored) | via-inertness vectors (wasm hash carried, never invoked) |
| C9 fidelity | 17 | 4 (sword, launder, `C9-01` **vendorA→B→C two-loss chain**, `C9-02` severed-without-B) | 2 | loss-ORDER assertion needs a loss-path key in the format |
| C10 frontiers | 21 | 4 (divergence a/b, unresolved, C9-02 doubles) | 2 | 17 short |
| patterns P1–P5 | 32 | 2 (`P2-04`, `L15`) | 0 | pattern catalogue vectors largely unauthored |
| lints | — | 2 extra (`L07` **two-run mutation caught**, `L07b` supersedes-is-the-fix — formerly "harness doesn't exist") | 4 (bench regressions) | counted under their C-families above where they overlap |
| wire (W-map) | 38 | 33 (`wire/` — incl. `W-V1/V2` multi-byte-varint boundaries and `W-11h` exponent-rejects, which vectors CURRENT law without closing knob #6) | 14 (`wire_rejects.rs`, overlapping) | 5 short: deep-nesting depth probes, name-grammar edge cases (name grammar itself is unruled — maintainer question) |
| **total** | **252** | **67** | **~48** | **~137 net short** |

Still not shipped, with reasons:

- **Strata**: `ember`, `acme` demo strata — their term inventories appear on
  NO provided page (F48); authoring them would be invention, not
  transcription. `locales` and `payloads` ARE now shipped (this pass).
  `hydro.*` remains a test article for a register entry that self-describes
  as **"corpus-shaped, not corpus-ratified"** (riverwatch §XI).
- **Loss-path ORDER as .ndfv**: the format would need a `loss:` assertion
  key; hosted in Rust (`c9_07` asserts the exact loss vector) until the
  format grows one deliberately.
- **Budget exhaustion as .ndfv**: budgets are API surface, not wire surface;
  hosted in Rust (the bomb ×3) by design, not by shortfall.

Every skip prints as `skip` in `ndn-bench vectors` output; nothing here is
counted as passed.
