# The Keel — DECISIONS.md

Rulings made during the implementation campaign. Corpus-page citations use the short names
(landing = ndf-the-landing, atelier = ndf-the-atelier, r5 = ndf-round-5-verdict, cruxes = ndf-two-cruxes).

---

## D-K1 · W-map — concrete TLV type assignments (landing Act III, R1)

R1 gives the kernel forms the space 0x20–0x3F and reserves 0x00–0x1F; it deliberately leaves the
concrete numbers to the implementation. Assignments below; the 32 kernel terms exactly fill their
32-slot space, in the kernel's own listing order (meta → types → links → escape → render), so the
map is memorizable and the "kernel is full" property is visible in the numbering itself.

### Kernel forms (0x20–0x3F)
| form | type | | form | type |
|---|---|---|---|---|
| vocabulary | 0x20 | | manifest | 0x30 |
| term | 0x21 | | describes | 0x31 |
| imports | 0x22 | | edge | 0x32 |
| supersedes | 0x23 | | narrower-than | 0x33 |
| label | 0x24 | | equivalent-to | 0x34 |
| doc | 0x25 | | maps-to | 0x35 |
| attribute | 0x26 | | opaque | 0x36 |
| field | 0x27 | | media-type | 0x37 |
| primitive | 0x28 | | external-ref | 0x38 |
| list-of | 0x29 | | contract | 0x39 |
| map-of | 0x2A | | intent | 0x3A |
| term-of | 0x2B | | express | 0x3B |
| record | 0x2C | | approximate | 0x3C |
| of | 0x2D | | refuse | 0x3D |
| rec-group | 0x2E | | binds | 0x3E |
| cardinality | 0x2F | | via | 0x3F |

### Value / structural space (0x40–0x4F) — not kernel *forms*, so outside 0x20–0x3F; not
reserved by R1. These carry primitive values and the two structural helpers the forms need.
| value | type | | value | type |
|---|---|---|---|---|
| bytes | 0x40 | | boolean | 0x45 |
| text | 0x41 | | hash | 0x46 |
| integer (varint; zigzag iff schema says signed, R3) | 0x42 | | name | 0x47 |
| — (0x43 unassigned, held back) | | | list value | 0x48 |
| decimal (canonical string, R4) | 0x44 | | map value | 0x49 |
| record value | 0x4A | | term-ref (32B hash) | 0x4B |
| group-ref (varint index; legal only inside rec-group) | 0x4C | | manifest-entry (field-hash + value) | 0x4D |

### Varints, lengths, and the critical bit (R2/R3/R12)
- Type and Length are both minimal unsigned LEB128 varints. Minimal = shortest possible encoding;
  a redundant continuation byte is a reject (R2, W-03). Varints wider than u64 reject (R3, W-22).
- Types 0x00–0x1F: reserved (envelope/future) — reject if seen in a document body.
- Types 0x20–0x4D: assigned above. Unassigned numbers < 0x80 (0x43, 0x4E–0x7F): reject
  (`UnknownReservedType`) — this space is spec-owned, an unknown here is malformed, not an extension.
- Types ≥ 0x80: the extension space R12 exists for. **Critical bit = bit 0 of the decoded type
  number**: odd ⇒ critical (document's matches become Unresolved), even ⇒ skip. A parity bit on
  the decoded number survives varint re-encoding untouched, which byte-position flag bits do not.

### Form bodies (R11: fields in definition order — these listings ARE the definitions)
- vocabulary: label · doc? · imports? · term* · (narrower-than|equivalent-to|maps-to|edge)* · supersedes?
- term: label · doc? · type-expr? · attribute*   (term identity = SHA-256 of the whole term TLV)
- imports: hash* · supersedes: hash · label/doc: text bytes
- attribute: key(term-ref) · value(primitive TLV | term-ref)  — flatness is structural (knob #4)
- field: label · doc? · type-expr · cardinality? (absent ⇒ one, R10) · attribute*
- primitive: 1 code byte — 0 bytes · 1 text · 2 integer · 3 decimal · 4 boolean · 5 hash · 6 name
- list-of: type-expr · map-of: key-type-expr, value-type-expr (K ∈ text|integer|hash|name|term-ref)
- term-of: hash (see D-K4) · record: field* · of: term-ref, type-expr (arity 1, knob #2)
- rec-group: term* (members may use group-ref) · cardinality: 1 byte — 0 one · 1 optional · 2 some · 3 many
- manifest: term-ref(type) · label? · describes · manifest-entry* · edge*
- describes: hash | name (never dereferenced by the matcher — C5/F3)
- edge: subject(hash|name) · kind(term-ref) · object(hash|name) · attribute*
- narrower-than / equivalent-to: hash · hash
- maps-to: from(hash) · to(hash) · loss(term-ref) · attribute*  (see D-K5)
- opaque (as type-expr): empty body · media-type: text · external-ref: text
- contract: label · doc? · imports? · binds? · (express|approximate|refuse)*
- intent: name(text) · attribute* · express/approximate: intent · target(term-ref) · via? · attribute*
- refuse: intent · binds: (hash|name)* · via: 1 kind byte (0 wasm · 1 native) + (hash | text)

Defense in one line: kernel-order numbering makes the map auditable against D-49's own term
listing; parity-critical-bit is the only flag scheme that is varint-stable; the 0x40 value space
keeps R1's reservation intact while giving primitives first-class tags so a schema-less decoder
can still walk any document (which C3/IM₀ requires).

---

## D-K2 · SHA-256 implemented in-crate, not via the sha2 workspace dep

ndn-manifest must be no_std + buildable with --no-default-features + zero ndf-* (C7), and its
document hash is constitutionally SHA-256 (landing Act III preamble; atlas: D-3/D-10 killed
agility). Baking ~120 lines of FIPS 180-4 into `ndn-manifest::hash` (with FIPS known-answer
tests) makes the spec crate literally dependency-free, immune to the rustcrypto 0.10/0.11 wave
split noted in the workspace Cargo.toml, and trivially portable. Swap to a shared impl later if
the workspace consolidates; the type (`Hash = [u8; 32]`) won't move.

## D-K3 · Naming — `ndn-bench` supersedes the working name `ndf-bench` (prompt §10 ruling, recorded)

The bench touches only spec crates, so it lives beside them under the ndn- prefix at
`crates/tools/ndn-bench`. "The Keel" is the suite-facing layer name only; no crate carries it.

## D-K4 · term-of takes a definitional hash that may be a vocabulary OR a parent term

cruxes lists `term-of(vocab)`; r5's canonical answer #2 says `term-of queen-status` where
queen-status is the enum's parent *term*. Ruled: the body is one hash; a value satisfies the type
if it is a term defined in that vocabulary, or a term narrower-than-reachable from that parent
term (within the consumer's frontier). Both corpus usages compile; membership stays a finite
reachability check, so C6 is untouched. Flagged as FRICTION F39.

## D-K5 · maps-to's @loss is structural, not attributive

"maps-to (directional; requires @loss)" (prompt §2; atelier L-09). A required attribute keyed by
a stratum term the kernel cannot hash-pin is unenforceable at the wire; making loss the third
element of the form makes the requirement a parse-level guarantee. The .ndfs surface syntax keeps
the `@loss =` spelling; it compiles into the structural slot. FRICTION F40.

## D-K6 · IM₀ is a pinned stratum, not kernel growth

IM₀'s five entries {opaque, media-type, name, size, kind}: opaque/media-type are kernel terms;
name/size/kind are not, and the kernel is frozen (D-49). Ruled: IM₀ ships as a distinguished
stratum authored in V₀.2, published and hash-pinned beside it — which is exactly why R14 pins
H(IM₀) separately. T₀'s express targets are the kernel `opaque` term plus IM₀'s entry terms.
FRICTION F41.

## D-K7 · Budget exhaustion is a typed result, not a fifth verdict

`match(…) -> Result<Vec<Match>, BudgetExceeded>` with the exceeded kind (nodes/edges/depth)
inside. C6′ demands a *typed* budget-exceeded outcome; verdicts stay the ratified four
(landing Act IV). Partial answers under a blown budget would be silent nondeterminism — the
exact disagreement the selection floor exists to kill.

## D-K8 · Golden hashes are recorded by the bench, never hand-computed

No toolchain is reachable from the authoring session (FRICTION F36), so any hand-computed
H(V₀.2) would be an unverifiable assertion. `ndn-bench freeze --pin` computes the trio with the
real encoder and rewrites conformance/FREEZE.md plus ndn-manifest's baked constant
(`src/kernel_hash.rs`); until first run the constant is explicitly `UNPINNED` and
`verify_fixed_point()` reports it — honest, self-healing, and the re-emission check (R13/L-12)
still runs unconditionally. Positive wire vectors likewise assert round-trip identity + recorded
goldens (`bench vectors --record` fills them once, then they guard).

## D-K9 · Mismatch is a silence with a name in the vector runner — not a verdict

The matcher emits NO Match for an unreachable-but-resolvable target (C6′: mismatch ≠ refusal ≠
unresolved). The `.ndfv` verdict family still needs to ASSERT that silence, so the runner accepts
`expect: verdict <intent> Mismatch`, meaning "no Match with this intent exists in the result" —
the keyword lives in the test format only; the API surface stays four verdicts + typed budget
error. Wire-adjacent detail ruled with it: byte-literal reject vectors carry no goldens (there is
nothing canonical to hash), and byte-literal ROUNDTRIP vectors may carry SHA-256-of-given-bytes
goldens computed anywhere — hashing given bytes is toolchain-independent, unlike D-K8's
encoder-derived pins. C10 divergence ships as two vector files over one DAG (admit lists differ),
keeping each .ndfv single-expectation.

