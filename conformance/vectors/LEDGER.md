# The vector ledger — honest counts against the 252 target

The atelier's conformance table targets 252 vectors across the families
below. **Rule: log shortfalls, never pad.** This ledger is the shortfall log.

| family | target | shipped as `.ndfv` | hosted as Rust tests | shortfall / note |
|---|---:|---:|---:|---|
| C1 fixed point | 6 | 0 | 6 (`ndn-manifest` kernel tests: 32 terms, kernel-in-kernel, stability) | vectors want pinned hashes; ship after the first `freeze --pin` |
| C2 reflection | 18 | 0 | 2 (kernel-describes-kernel) | meta-tower targets not yet authored |
| C3 total floor | 9 | 1 (`REFUSE-declared-clause` witnesses identity-Express) | 2 (`t0_expresses_over_every_im0_manifest`) | T₀ vectors need IM₀ hashes → post-freeze |
| C4 escape hatch | 12 | 0 | 1 (opaque in proptests) | opaque+media-type family not yet authored |
| C5 acyclicity | 31 | 0 | 3 (DAG insert ordering, import closure) | cycle-attempt vectors want a multi-file lock harness |
| C6/C6′ verdicts | 38 | 6 (`verdict/`) | 11 (`matcher_vectors.rs`, incl. the bomb ×3 budgets) | 21 short; the four verdicts + divergence + budget are each covered at least once |
| C7 independence | 4 | 0 | CI job (`check-independence`) | the property is a build fact, not a byte vector |
| C8 matcher inertia | 26 | 2 (`C8-19`, apiary's inert `@range`) | 1 (instance edges ignored) | 23 short; selections-matched-without-evaluation vector wants a `.ndfm` selection fixture |
| C9 fidelity | 17 | 2 (sword, launder) | 2 (same, in Rust) | vendorA→B→C 3-hop chain not yet authored |
| C10 frontiers | 21 | 3 (divergence a/b, unresolved) | 2 | 18 short |
| patterns P1–P5 | 32 | 2 (`P2-04`, `L15`) | 0 | pattern catalogue vectors largely unauthored |
| wire (W-map) | 38 | 30 (`wire/`) | 14 (`wire_rejects.rs`, overlapping) | 8 short: multi-byte-varint boundary goldens, deep-nesting depth probes, decimal exponent forms (knob #6 is deliberately open — the campaign dodged decimal semantics and it wants its own vector page) |
| **total** | **252** | **48** (first live run: 48 pass · 0 fail · 0 skip) | **~45** | **~159 net short** |

Also not shipped this round, deliberately:

- **Strata**: `locales`, `payloads`, and the demo strata `ember`, `acme`,
  `bridge` (a verdict-family `bridge.ndfs` exists but is a fixture, not the
  Ring-1 stratum). `hydro.*` is authored from riverwatch-manifest-contract,
  which self-describes as **"corpus-shaped, not corpus-ratified"** — the
  fixtures are test articles for that register entry, not ratifications of it.
- **L-07 vectors**: mutation detection needs a pinned-then-edited two-run
  harness; the lint exists, the vector harness for it doesn't yet.
- **T₀-identity as `.ndfv`**: hosted in Rust
  (`t0_expresses_over_every_im0_manifest`) because IM₀'s hash is unpinned
  until the first freeze (D-K8) — see D-K9's note on vector hosting.

Every skip prints as `skip` in `ndn-bench vectors` output; nothing here is
counted as passed.
