# `#[derive(Manifest)]` — the evidence-based spec

**Status: corpus-shaped, not corpus-ratified.** Designed against two real,
structurally different producers (ndn-lab's flat `FabricGauges` and nested
`SceneSnapshot` — F53/F54/F55), not from imagination. Target: a tool-tier
companion crate `ndn-manifest-derive` (proc-macro) — leans on the spec
crates, never becomes their dependency (C7); consumers who don't want it
never see it.

## The three laws (already ruled)

1. **The derive stops at "describe the struct."** It emits terms, a
   vocabulary contribution, and `to_manifest()`. It never names an intent,
   a renderer, or an app — intents are contract-side knowledge, and a
   derive that guessed them would cross the producer/lens tattoo (F54).
2. **Declaration order is identity (R11).** The macro emits fields in
   declaration order and never reorders. See "Reordering" below for what a
   reorder actually *is*.
3. **Docs ride ordinary `///` comments** — proc macros receive them as
   `#[doc = "…"]` attributes (F54 correction). Undocumented public fields
   should fail the derive the way L-05 fails the bench: self-description
   includes humans.

## What the derive emits

- **Handles**: `const` term hashes for the type term and every field term.
- **A Vocabulary contribution**: the record term (fields in declaration
  order, docs attached) plus any nested record terms, ready to insert into
  a DAG or merge into a stratum.
- **`fn to_manifest(&self) -> Result<Manifest, DescribeError>`** —
  fallible, see the float ruling.
- **`const SCHEMA: Hash`** — the record term's hash, so the producer can
  pin it in a golden test (the freeze pattern, miniaturized — see
  "Reordering").

## Ruling F55-A · Option / Vec: cardinality declares, list-ness encodes

The kernel already answered this — record fields carry
`Cardinality::{One, Optional, Some, Many}`, and `Optional` exists precisely
for this case (precedent in the shipped corpus:
`turbidity-ntu : optional m:measured` in `conformance/strata/hydro.ndfs`).
The mapping:

| Rust            | field declaration        | value encoding            |
|-----------------|--------------------------|---------------------------|
| `T`             | `T` (cardinality One)    | the bare value            |
| `Option<T>`     | `optional T`             | 0-or-1 **list** ([] / [v])|
| `Vec<T>`        | `many T`                 | list                      |
| `#[field(some)] Vec<T>` | `some T` (≥1)   | list, len ≥ 1             |

The uniform law: **cardinality One gets the bare (unwrapped) spelling;
every other cardinality encodes as a list whose length the cardinality
bounds.** This is R10's shape at the value layer — the default gets the
short spelling, and there is exactly one spelling per state (None = `[]`,
never an absent position, never a presence flag: a flag beside a slot is
two sources of truth that can disagree).

Rejected alternatives, for the record: **presence flag** (R10 violation as
above); **P2 reification** (P2 is the escape hatch for structure in
*attribute* position — using it for optionality would spend a heavyweight
mechanism on a problem the kernel already solved with cardinality).

## Ruling F55-B · Floats: a lossy translation, so declare the loss

`f64 → canonical Decimal` is not a conversion, it is a **lossy
translation**, and the house law for lossy translation is C9's: the loss is
declared, never silent. Therefore:

- **A bare `f64`/`f32` field is a derive-time error.** The annotation is
  mandatory: `#[field(decimal(places = 4))]`. It is not a config knob — it
  is the loss declaration.
- **Rounding**: fixed-places, round-half-even, then `Decimal::normalize`
  (which strips trailing zeros — `1.5000` → `1.5`). Deterministic; two
  floats differing below the declared precision map to one decimal, and
  that collapse *is* the declared loss.
- **Non-finite values (NaN/±inf) have no canonical decimal, and mapping
  them to any number is a guess wearing a value's clothes.** Default:
  `to_manifest()` returns `Err(DescribeError::NonFinite { field })`.
  Opt-in for `Option`-al fields only: `#[field(nonfinite = absent)]` maps
  NaN/inf to `[]` — absence is honest; zero is not.
- Schema note (outside the derive's scope but worth one line in its docs):
  if the quantity has real uncertainty, `measured { estimate, plus-minus }`
  is the richer target than a bare decimal — that's a schema decision the
  producer makes in the struct, not a policy the macro infers.

## Nested types: the walk is topological; identity is free

Nested struct fields type as `term-of(<nested record term>)` (list/map
variants accordingly), so the macro emits terms leaf-first and threads
hashes upward (C5 manifesting inside the macro — you cannot reference what
does not exist yet). Two simplifications the evidence run confirmed:

- **No identity bookkeeping needed.** Content addressing does the
  deduplication: two fields of the same nested type produce the same term
  bytes, the same hash, and the DAG dedups on insert. The walk needs
  *ordering*, not a registry.
- **Cross-struct composition**: a nested struct that itself derives
  Manifest contributes its terms through its own Handles; identical
  definitions collide into identical hashes by construction.

## Reordering is not "semver-breaking" — it is unintended supersession

Because order is identity, reordering fields does not *break* the old
schema; it silently **mints a new term** while the old one (and every
manifest written against it) continues to exist, unreferenced by the new
code. The failure mode is not incompatibility — it is an accidental version
fork with no `supersedes` edge (the L-07 sin, performed by a macro). Hence
`const SCHEMA: Hash` + the pin test: reorder a field and the golden test
goes red, at which point the producer either reverts or *deliberately*
versions (new stratum + supersedes). The derive turns an invisible fork
into a visible decision.

## Primitive mapping (mechanical tier)

`u8..u64`/`usize` → Integer · `String`/`&str` → Text (annotate
`#[field(name)]` for Name-typed subjects/paths — Text vs Name is semantic,
not inferable) · `bool` → Boolean · `Hash`/`[u8;32]` → Hash ·
`Vec<u8>` → Bytes (NOT a `many integer` — bytes are a primitive; the derive
must special-case it before the `Vec<T>` rule fires).

## Ruling F56 · skip and projection: three needs, three different answers

The retirement of the hand-built vocabularies surfaced it concretely: a
derived `SceneSnapshot` manifest describes ALL five fields, where the old
hand-built slice described the two its lens wanted. "Derive the producer"
and "describe what a lens needs" are not the same thing — and they must
never become the same thing. The three cases:

1. **Non-data fields** (caches, runtime handles, derived scratch) —
   `#[field(skip)]`, ruled legitimate. Skip means "this is not part of what
   I am," a statement about the producer's own identity. Skipped fields
   contribute no term and no entry; the SCHEMA hash doesn't see them.
2. **A lens wants a subset** — **nothing.** Extra fields are inert to the
   matcher and free to the lens; Express does not mean "consumes every
   field." The manifest describes the fact; each lens renders its facet.
   Shaping a producer's description around a renderer's appetite is the
   generalized form of the sin the tattoos forbid ("no manifest names a
   renderer" extends to "no manifest is SHAPED by one"). A skip used for
   this purpose is a design smell the derive cannot detect but reviewers
   should.
3. **The producer wants to publish a genuine subset-facet** (size,
   audience) — **projection is an edge, not an attribute.** Publish a
   projection record term (`scene-topology { nodes, links }`) in the
   vocabulary and declare `narrower-than scene-snapshot scene-topology`:
   every full snapshot Expresses wherever the projection is targeted,
   because a full snapshot structurally IS a topology-plus. One manifest,
   two reachable terms, zero copies — the calculus-native answer. (A
   possible future sugar — `#[manifest(projection(…))]` emitting the term +
   edge — waits for a lens that actually targets a subset term, per the
   evidence rule.)

## Open, deliberately (not ruled — needs evidence)

- **Rust enums.** Unit-variant enums map naturally to the kernel enum
  pattern (members + parent + narrower-than, F30) consumed as
  `term-of(parent)` — but data-carrying variants have no obvious kernel
  shape. Do not design this until a real producer needs one.
- **`describes` policy.** The subject is runtime data
  (`#[manifest(describes = …)]` as a template is a convenience, not a law);
  producers with per-instance subjects pass them to `to_manifest`.
- **Map fields** (`BTreeMap<K,V>` → `map-of`): key-type legality mirrors
  the kernel's map-key rule; unexercised by either real producer so far.
