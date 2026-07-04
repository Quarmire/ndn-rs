# The three script grammars — `.ndfs` / `.ndfm` / `.ndfc` (F47)

Reconstructed from the corpus's worked examples: round 5's graded exam
(ndf-round-5-verdict — the stranger's `.ndfm`/`.ndfc` layouts, "adopted as
seeds", F29), the atelier's stratum scripts, and the gauntlet's rulings.
Where the corpus showed no example, the choice is recorded in FRICTION and
flagged for the maintainer. The **artifact** is the canonical TLV bytes;
these grammars are authoring sugar — petnames live here and in the lock,
never in the artifact (F21).

Conventions shared by all three:

- Line-oriented. `#` and `//` start comments. `·` reads as whitespace.
- Strings are `"double-quoted"` with `\n` and `\"` escapes.
- A trailing string on a definition line is its doc string (L-05 data).
- References: `label` (this document), `pet:label` (through the lock, L-01),
  or a bare 64-hex hash.
- `->` requires surrounding spaces (`a -> b`, never `a->b`) — labels may
  contain `-`.
- Attributes: `@key = value`, flat values only (L-04). A bare `@word` key
  resolves against a term named `word` in this document or any import.
- A leading `_` on a label marks a stratum-internal term: undocumented
  internal terms **warn**; undocumented public terms **fail** (L-05).

## `.ndfs` — stratum

```ebnf
stratum   = "stratum" name docstring? item* ;
item      = use | enum | term | record | edge-decl | supersedes ;
use       = "use" name "as" petname ;            (* position-free *)
enum      = "enum" name docstring? "{" name+ "}" ;
            (* L-06/F30: expands to N member terms + 1 parent term
               + N narrower-than edges — the expansion is printed *)
term      = "term"? name (":" type)? attr* docstring? ;
record    = "record" name docstring? attr* "{" field* "}" ;
field     = name ":" cardinality? type attr* docstring? ;
cardinality = "optional" | "some" | "many" | "one" ;   (* fields ONLY *)
type      = primitive | "opaque"
          | "list-of" "(" type ")"
          | "map-of" "(" type "," type ")"     (* keys: text·integer·hash·name·term ref *)
          | "term-of" ref
          | ref "(" type ")"                   (* user parametric, arity-1: L-03 *)
          | ref ;                              (* bare ref = term-of; L-15 fires on enum parents *)
primitive = "bytes"|"text"|"integer"|"decimal"|"boolean"|"hash"|"name" ;
edge-decl = "narrower-than" ref ref
          | "equivalent-to" ref ref
          | "maps-to" ref "->" ref attr*       (* @loss required: L-09/C9 *)
          | "edge" ref ref ref attr* ;         (* subject kind object: F31 idiom *)
supersedes = "supersedes" hash ;               (* L-07: version, don't mutate *)
attr      = "@" (word | ref) "=" literal ;
```

Cardinality at term level is a **parse error** with a record fix-it (round 5,
answer #5: "the field enforces"). Two type parameters on a user parametric is
a parse error naming L-03.

## `.ndfm` — manifest (the stranger's layout, adopted — F29)

```ebnf
manifest  = "manifest" name ":" ref
            use* ("describes" (name-path | hash))
            ("label" docstring)?
            (entry | edge-decl)* ;
entry     = ref "=" literal ;
literal   = string | integer | decimal | boolean | hash | name-path
          | ref | measured | "[" literal ("," literal)* "]" ;
measured  = decimal "±" decimal word ;
```

`describes` is required; name subjects are prefixes and are **never
dereferenced** (F3/C5). The measured literal `41.2 ±0.3 kg` compiles to the
exact F24 expansion — `record { estimate, plus-minus }` — with the unit word
cross-checked against the field's `@unit`; the expansion is printed.

## `.ndfc` — contract (adopted nearly verbatim — F29)

```ebnf
contract  = "contract" name docstring? use* bind* clause* ;
bind      = "binds" (name-prefix | hash) ;      (* subject filter, F45 *)
clause    = "intent" name attr*                 (* declaration; L-11 tags ride here *)
          | "express" name "->" ref via? attr*
          | "approximate" name "->" ref via? attr*
          | "refuse" name ;                     (* documentation: L-14 *)
via       = "via" ("wasm:" hash | "native:" word) ;
```

Unlisted intents are refused by default — **by absence, never inferred**.
Explicit refuses are legal, redundant, and kept (L-14 info).

## Choices the corpus did not rule (flagged for the maintainer)

1. `->` with mandatory surrounding spaces (labels contain `-`).
2. `_`-prefix as the internal-term marker for L-05's warn/fail split.
3. `use` lines are position-free (imports resolve in a pre-pass).
4. Contract clause shape `express <intent> -> <term>` (one target term per
   clause) — the F44 question; riverwatch's `expresses: &[…]` list is the
   same information, clause-per-intent.
