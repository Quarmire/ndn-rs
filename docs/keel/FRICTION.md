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

**F50 · CLOSED — T₀ vectors graduated to .ndfv after the 2026-07-04 freeze.**
[was: verdict vectors needing pinned kernel hashes could not ship pre-freeze; hosted in Rust]
[closure: the pins exist (H(V₀.2)=568b9581…, H(IM₀)=39cfe0fb…, H(T₀)=a7ac0461…, recorded by
`freeze --pin` on the first live run). The runner gained `kernel: trio` (seeds the trio from the
LIVE encoder — no kernel bytes are ever baked into vector files, preserving D-K8) and
`contract: @kernel-t0`; C3-01/02/03 now ship as .ndfv. Grammar rider from the original entry
(`->` requires surrounding spaces) stands, GRAMMAR.md §choices.]

**F51 · Identity matches bypass frontier admission — observed live, flagged for the maintainer.**
[found: first waterline-keel run — a contract targeting the manifest's exact type-term hash
rendered Express even though the term's defining vocabulary was unadmitted]
[ruled: kept, deliberately. `source == target` consults no edge and no vocabulary semantics: the
term IS the term, and C3 REQUIRES this (T₀ must Express over every IM₀ manifest under an EMPTY
frontier — the total floor works with zero trust). Consequence stated plainly: admission gates
SEMANTIC REACHABILITY (whose edges you believe), not hash equality; a consumer who wants to
suppress offers over unadmitted-vocabulary manifests entirely does so at selection, not in the
matcher. Top-5 question material alongside #3 (D-K4).]

**F52 · The vector format grew four keys in the post-freeze closure pass — recorded, bounded.**
[found: closing the C1/C3/L-07 shortfalls needed harness capabilities the F42 format lacked]
[ruled: added `kernel: trio` (live-encoder trio seeding; petnames v0/im0/t0), `contract:
@kernel-t0`, `expect: kernel-pinned`, `expect: kernel-hash <artifact>` (goldens recorded by the
bench, D-K8 — the C1-02..04 goldens are the freeze's own output transcribed under that rule), and
the L-07 two-run mutation check in the compile families. Deliberately NOT added, with reasons in
the LEDGER: a `loss:` order-assertion key, a `budget:` key (budgets are API, not wire), and any
key requiring baked kernel bytes inside vector files. Format keys are append-only from here;
removing one would orphan shipped vectors.]

**F53 · First-user review (ndn-lab session) — four findings, four dispositions.**
[found: the first real consumer reviewed both crates + demo and hit four walls]
[dispositions:
(1) **Seam undersold** — CORRECT and fixed: both crate docs now open with "Where the built thing
ends": the pipeline ends at verdict + inert Via; the render host (WASM sandbox, ViewBlock,
capability grants, Surface Authority) is design-only; the Riverwatch surfaces are the design
target, not a runnable path; the honest interim is matcher-driven selection + the consumer's own
Via::Native registry.
(2) **Authoring ergonomics are spec-grade, not producer-grade** — CORRECT, accepted as roadmap: a
`ndn-manifest-derive` / typed-builder companion belongs in the TOOL tier (like ndn-bench: leans
on the spec crates, never becomes their dependency — C7 unbroken). Not built this pass; a native
Rust producer today either hand-builds (waterline-keel shows how, ~255 lines) or scripts through
ndn-bench.
(3) **Hash-soup DX / no match-explain** — CORRECT and fixed: `ndn_bench::explain` renders a Match
against the DAG (labels, hop path, named losses, Missing prose). Presentation stays in the tool
tier on purpose: a matcher that needed labels would be a matcher that could be lied to by labels.
(4) **Versioning cookbook missing** — CORRECT, open debt: supersedes/L-07 are mechanical law, but
the operational choreography (who re-issues manifests, live-stream subject migration, stale
frontiers) is underived. Needs a docs/keel/VERSIONING.md written against a real consumer's
migration — ndn-lab's vocabulary evolution is the natural forcing case; write it then, from
evidence, not now, from imagination.]

**F54 · First-slice findings (ndn-lab vertical slice: one metric, two lenses, C10 live) — five
findings, five dispositions.**
[found: the slice shipped — FabricGauges as manifest, sparkline + OTLP contracts,
resolve-once/Sparks, bridge-as-stratum making Phase-B lossiness the named term
otel-attribute-flattening — and produced five findings]
[dispositions:
(1) **Derive shape, from evidence** — accepted as the spec for `ndn-manifest-derive`: emit
Handles (const term hashes) + a Vocabulary contribution + `to_manifest()`; declaration order is
identity (R11) so the macro NEVER reorders; the derive stops at "describe the struct" — intents
are contract-side knowledge and guessing them would cross the producer/lens tattoo. ONE
CORRECTION to the finding: proc macros DO see `///` comments (they arrive as `#[doc = "…"]`
attributes), so L-05 docs ride ordinary doc comments; `#[field(doc=…)]` is unnecessary. Derive
deferred until a SECOND, structurally different struct exists (see ordering ruling below).
(2) **explain's crate home** — CORRECT that a sim depending on the bench reads wrong; OVERRULED
on the destination: not a feature on ndn-render-contract. The law: spec crates carry LAW, tool
crates carry CONVENIENCE — law changes by ratification, display strings by taste, and
feature-gating presentation into a spec crate puts wording under ratification discipline.
Extracted to `crates/tools/ndn-explain` (micro-crate, zero transitive deps); ndn-bench re-exports
it so existing paths keep working.
(3) **contract_via** — CORRECT and adopted INTO the spec crate: it is lawful navigation over spec
types (no strings, no policy), and the intent/target disambiguation (clause target == final path
hop; author-order fallback when pathless) is exactly the fiddly-but-lawful logic one correct
implementation should own. `Via` re-exported from ndn-render-contract.
(4) **The three silences are invisible at the call site** — CORRECT and fixed: `r#match` docs now
carry a "Reading the result" section distinguishing mismatch-silence (no Match; `.is_none()`)
from Refuse (a Match saying no) from Unresolved (a Match naming what's missing).
(5) **C7 as consumability** — adopted verbatim into the crate docs: zero transitive deps = zero
version-collision surface = painless cross-workspace path deps; adding a dependency to a spec
crate is a breaking change to consumers.
Ordering ruling on next steps: topology slice BY HAND first (a nested/structured second type —
scene snapshots exercise list-of/map-of/record where FabricGauges was flat u64s), derive second,
designed against both real structs. A macro designed from one flat struct would overfit.]

**F55 · Second-slice findings (topology, nested) — the two derive policies, ruled; one bug named.**
[found: SceneSnapshot by hand surfaced five ⭑ points; two needed calculus rulings before any
macro could hard-code them]
[rulings, full spec in docs/keel/DERIVE.md:
(A) **Option/Vec** — cardinality declares, list-ness encodes, One is bare: `Option<T>` is the
kernel's `optional T` (hydro's turbidity field was already the precedent) with value `[]`/`[v]`;
`Vec<T>` is `many T`. Presence flags rejected (a flag beside a slot = two sources of truth, R10);
P2 reification rejected (P2 is for structure in ATTRIBUTE position — cardinality already solved
optionality).
(B) **Floats** — f64→Decimal is a LOSSY TRANSLATION, so the annotation is a loss declaration,
not a knob: bare f64 = derive-time error; `#[field(decimal(places = N))]` mandatory; half-even
then normalize; **NaN/inf → Err by default** (`nonfinite = absent` opt-in for optional fields
only). The slice's "0 on refusal" is flagged as a BUG, not a pain point: encoding not-a-number
as a number is a guess wearing a value's clothes — the one ⭑ to go fix.
Also ruled into DERIVE.md: reordering = unintended supersession (an L-07 sin performed by a
macro), countered by `const SCHEMA: Hash` + a pin test — the freeze pattern miniaturized; nested
emit order is a topological walk but identity bookkeeping is FREE (content addressing dedups);
Vec<u8> special-cases to Bytes before the Vec<T> rule. Left open on purpose: data-carrying enums,
map fields — no real producer has needed them yet.]




