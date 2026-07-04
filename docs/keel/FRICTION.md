# The Keel — friction log (implementation campaign, F36+)

Continues the corpus's numbering. Format: finding · [found: where] · [ruled/blocked: what].

---

**F36 · No toolchain reachable from the authoring session.**
[found: build environment — the session has filesystem access but no rustc/cargo and no network]
[ruled: every milestone gate ships as a runnable command (`cargo test -p …`, `bench …`); none is
demonstrated green in-session. The pin/golden machinery (D-K8) is designed so first-run on a real
toolchain completes M2's freeze without hand-entered hashes. The M-gates below are therefore
*claims about tests that exist*, not test results.]

**F37 · Round-2 page (ndf-the-gauntlet.html) referenced by the brief but not provided.**
[found: prompt §1 reference map vs the uploaded set]
[ruled: C-family targets and counts taken from the Atelier's vector ledger and the landing's
evidence tables, which restate them. Nothing in the missing page appears load-bearing for code;
if it contradicts a count, the corpus-wins rule applies on sight.]

**F38 · No Riverwatch fixture exists on disk.**
[found: searched ndn-workspace and ndf-rs (incl. ndf-vault) for riverwatch/pylon/hydro — zero hits,
despite §6 "hydro from the Riverwatch wire" and §8 M6 naming pylon-7 + hold-1]
[ruled: authored `conformance/fixtures/pylon-7.ndfm` (raw LoRa frame block: the C3 vector —
"renders as hex+mime with zero vocabulary present") and `hold-1.ndfm` (repo-instrument manifest)
from the corpus descriptions. They are seeds, not the real wire; marked as such in-file.]

**F39 · term-of's parameter is ambiguous between vocabulary and parent term.**
[found: cruxes kernel listing says term-of(vocab); r5 answers #2 says term-of queen-status (a term)]
[ruled: D-K4 — one hash, membership = in-vocabulary OR narrower-than-reachable. Both corpus
usages stay legal; decidability untouched.]

**F40 · maps-to's required @loss cannot be enforced as an attribute at the kernel layer.**
[found: kernel freeze vs L-09 — the kernel cannot pin the hash of a stratum's loss term]
[ruled: D-K5 — loss becomes the form's third structural element; surface syntax unchanged.]

**F41 · IM₀'s entries name three non-kernel terms (name, size, kind).**
[found: cruxes C3/IM₀ derivation rule vs the frozen 32]
[ruled: D-K6 — IM₀ is a pinned stratum beside V₀.2; explains R14 pinning H(IM₀) at all.]

**F42 · The .ndfv format is under-specified.**
[found: landing Act III gives only `input bytes · expected {canonical-hash | typed-reject | match-verdict}`]
[ruled: a line-oriented text format (see conformance/vectors/FORMAT.md): `family`, `id`, `input`
(hex bytes | inline script | file ref), `expect` (roundtrip[+golden] | reject <Code> |
verdict <intent> <Verdict> | accept-distinct | compile-error <L-rule>). Golden hashes recorded by
`bench vectors --record` per D-K8.]

**F43 · Corpus count shortfall — targets are 252; this campaign materializes fewer, honestly.**
[found: §6 honesty rule]
[ruled: every named must-have vector exists (W-03/07/11/14/19/22, C9-07/08, C8-19, P2-04, C6-31);
each family has real representatives; the per-family shortfall ledger lives at
conformance/vectors/LEDGER.md and `bench vectors` prints target-vs-present. Zero padding.]

**F44 · The contract/express target shape is nowhere written down.**
[found: landing Act IV freezes the matcher signature and verdicts, but no page states what an
`express` clause structurally binds to]
[ruled: express/approximate carry `intent · target(term-ref) · via? · attrs` (D-K1 form bodies);
a manifest matches a clause when its type term (or any entry's field term) reaches the target
through frontier-admitted narrower-than/equivalent-to (Express) or ≥1 maps-to (Approximate,
loss path accumulated, C9 min-fidelity). This is the minimal shape that makes T₀ ("matches every
IM₀") expressible. Wants maintainer confirmation — top-5 question #1.]

**F45 · `binds` semantics are unstated beyond "optional".**
[found: kernel render-side listing; no corpus page elaborates]
[ruled: implemented as an optional subject filter — hash exact-match or name-prefix match against
the manifest's `describes`; absent ⇒ contract is offered for all subjects. Prefix matching is the
same never-dereference regime as describes (C5/F3).]

**F46 · Selection floor's "specified tie-break" is not specified anywhere provided.**
[found: C6′ / landing Act IV say deterministic, stable-ordered, top-k with specified tie-break —
the specification itself is absent from the pages]
[ruled: total order = (verdict rank Express < Approximate < Refuse < Unresolved, loss-path length
ascending, contract hash lexicographic, intent name lexicographic). Deterministic, input-order
independent. Top-5 question #2.]

**F47 · Stratum script grammar is defined only by worked examples.**
[found: §5 says grammars are defined *by the worked examples*; the Atelier page (rendered text)
preserves fragments, not complete files]
[ruled: grammar reconstructed to cover every construct the corpus quotes (use…as, class/enum,
field rows with `:` types and cardinalities, @attributes, edge/maps-to lines with @loss, intents
with @sensitivity, contract express/refuse, measured-literal `41.2 ±0.3 kg`, fused
`some hash as e:justified-by`, describes lines, map/list/term-of/of type syntax). Anything the
examples don't exercise is a compile error, not a guess. EBNF at docs/keel/GRAMMAR.md.]

**F48 · Atelier's 19 strata are named but their term inventories are not on any provided page.**
[found: atelier roster vs the rendered fragments]
[ruled: Ring-1 strata authored with the terms the corpus actually names (units:kilogram, hertz,
millilitre, per-hundred; loss:visual-only, ordinal-coarsening; edge-kinds:justified-by;
measured incl. instant alias; ui-intents incl. alarm.attention + sensitivity tags; etc.) plus the
minimal fields their consumers need. Ring-2 limited to selections, locales, the ember/acme/bridge
trio, and apiary-as-regression. Inventory gaps are logged per-file, not invented silently.]

**F37 · CLOSED — ndf-the-gauntlet uploaded and read.**
[was: gauntlet round-2 page missing; C6-bomb spec and C8/C9 vectors reconstructed]
[closure: page confirms the reconstruction — bomb = "10-deep µ-groups × nested arity-1
instantiation × a 50k-term subsumption DAG; reachability memoizes; the perf note is an index
requirement, not a semantics change" (matcher: memoized Dijkstra + predecessor-pointer paths);
map-of keys = text·integer·hash·name·term-hash (matches `map_key_legal`); C8 vector = predicate
smuggle rejected at authoring (C8-19); C9 vector = vendorA→B→C approximate-with-declared-loss +
crafted-express-at-hop-3 fails (sword/launder). No code changes were needed — the reconstruction
held.]

**F38 · PARTIALLY CLOSED — riverwatch-manifest-contract uploaded and read.**
[was: pylon-7 fixture material missing; hydro.* invented]
[closure: fixtures re-authored from the page (station datum NAVD88 / gauge-zero 121.44, stages
2.9/3.4/4.1/4.9, hydro.observation/alert/health fields, contract.panel/1's
express·approximate·refuse split, the intent family). REMAINS OPEN by the page's own honesty
ledger: "everything named hydro.* and contract.* on this page is a worked proposal —
corpus-shaped, not corpus-ratified" (§XI). conformance/strata/hydro.ndfs is therefore a test
article for that register entry, not a ratification; the LEDGER says so too.]

**F49 · Where may unknown extension TLVs legally appear?**
[found: R12/W-19 say critical vs benign; no page says at what structural depth]
[ruled: extensions (ty ≥ 0x80) are legal ONLY as trailing TLVs at DOCUMENT level, retained
byte-exactly (they hash — R13 re-encodes them verbatim). An unknown tag nested inside any form
body is a hard reject (UnknownReservedType), because a length-skippable-anywhere rule would let
two canonical spellings of the same nested structure exist. Vector W-19/W-19b (trailing decodes)
vs W-R1b (nested rejects).]

**F50 · Verdict vectors that need pinned kernel hashes cannot ship pre-freeze.**
[found: T₀-over-IM₀ as a .ndfv wants H(IM₀) in its `admit:`/target lines; the pins do not exist
until the first `freeze --pin` on a real toolchain (D-K8/F36)]
[ruled: such vectors are hosted as Rust tests this round (matcher_vectors.rs::t0_expresses…) and
the LEDGER records the hosting; after the first freeze they graduate to .ndfv with recorded
goldens. Also under this entry: `->` requires surrounding spaces (labels contain `-`) — a
grammar decision the corpus never had to make, GRAMMAR.md §choices.]

**F51 · Identity matches bypass frontier admission — observed live, flagged for the maintainer.**
[found: first waterline-keel run — a contract targeting the manifest's exact type-term hash
rendered Express even though the term's defining vocabulary was unadmitted]
[ruled: kept, deliberately. `source == target` consults no edge and no vocabulary semantics: the
term IS the term, and C3 REQUIRES this (T₀ must Express over every IM₀ manifest under an EMPTY
frontier — the total floor works with zero trust). Consequence stated plainly: admission gates
SEMANTIC REACHABILITY (whose edges you believe), not hash equality; a consumer who wants to
suppress offers over unadmitted-vocabulary manifests entirely does so at selection, not in the
matcher. Top-5 question material alongside #3 (D-K4).]

