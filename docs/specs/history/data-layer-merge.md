> Superseded by heap.md and invite.md at ndn-rs 2b344e09. Kept for history; nothing here is normative.

# The merge-rule engine, snapshots and state names text cut from `data-layer.md`

The merge-rule engine (slice 6: merge functions by exact versioned name and the rule interface, operations the application builds, versions held but not counted, checkpoints covering by frontier, covered versions as a basis, pieces in merge collections, merge state built lazily across restarts, and the Yjs rule `/merge/yrs`) and snapshots with state names (§11) were removed from the data layer. The one merge function is now the built-in newest register `/ndf/merge/newest/v=1`. The number 0x0550 (`SnapshotRecord`) is freed and quarantined, not reused. `MergeOp` 0x0544, `Rule` 0x0548 and `RuleKind` 0x054A stay on the wire, carrying the register's bytes and its name. Section numbers and wording are those of `data-layer.md` just before the cut.

## Header: Status and Scope (the lines that changed)

### Status: the slice-6 list

  and C: merge rules by exact versioned name and the rule interface,
  operations the application builds, versions held but not counted,
  checkpoints covering by frontier, pieces in merge collections, folder
  members records narrowing every
  collection under a folder with one seal epoch per folder epoch, and
  joining a folder by a code (introductions, §19), §5.1,
  §5.2, §6.1, §6.2, §9, §13, §15, §16, §19); slice 5: a revoked key's versions kept

### Status: slices 1 and 2

  namespace, the merge rule and its function `/merge/yrs`, the log rule,
  removal cuts and the re-check when a cut arrives, seals (epoch keys and
  grants), types, signed nested summaries, snapshots, the sync notice and
  its reach across namespaces, the verbs `get`, `put`, `watch`, `snapshot`

### Scope

  exchanges — versions, collections, members, summaries, cuts, snapshots,
  seals and types — and the five verbs over it. The Rust

## §3 Names, devices, namespaces (the lines that changed)

### Verbs take collection names

- `put`, `get`, `share` and `snapshot` take collection names; `watch` takes

### get also takes log entry names

  (`NextStep::FixName`). `get` also takes log entry and state names
  (§11).

## §4 Version and log (the lines that changed)

### One log per key

  entry it signs about any collection — versions, members records (§6),
  snapshots (§11) — takes the next sequence number of that log. `seq` MUST

### Parents are the frontier

  the writer had applied when it wrote (§5.2), each **tip** `(y, t)` bound

### A merge version names the rule

- A merge version names the rule its operation was made for (`Rule`,
  §16.2); a reader applies it only under that rule (§5.1).

### The payload of a version

- The payload of a version is the fields the writer set (§10) and the
  merge function's operation (§5.1), empty under the log rule.

### A refused version does not hold up later versions

writer do not wait for a version so refused (§5.2).

## §5 Collection and rule (the lines that changed)

### The section title

## 5. Collection and rule — slices 1, 2, 6 (rules by name)

### The default record

`/merge/yrs`, the namespace writing and reading, sealed to it). A collection

### Only once nothing held elsewhere governs it

  only, its rule `/merge/yrs`), even under a folder whose record this

### The rule table: the merge row

| merge | Member logs plus a named merge function every reader runs alike. `get` returns the merged state at a frontier. |

### The log rule: delivery order

delivered in the order of §5.2. The newest of a log collection is, of the

## §5.1 Merge functions (cut whole)

### 5.1 Merge functions

A merge function — a merge **rule** — turns a writer's edit into an
**operation** carried in the version (`MergeOp`) and folds operations into
a state. Every reader that applies the same versions MUST obtain the same
state. A reader that does not know a collection's function MUST NOT claim a
state for it and says so.

**Rules by name — slice 6.**

- A merge collection's members record names exactly one rule by its full
  name (`Rule`, §16.2). A reader MUST match it by exact equality of names:
  never by prefix, by a part of the name or by the nearest version. By
  convention the last component is a version (`v=<n>`, as in
  `/ndf/merge/element/v=1`), and a change of meaning is a new name: every
  program that runs a rule under one name MUST compute what every other
  does. `/merge/yrs` keeps its name.
- A device that does not know the rule holds every version of the
  collection as it holds any version — verifies, stores and serves it, and
  lists it to `watch` with nothing applied — and answers `get(C)`, `get` of
  a state name of `C` (§11), and `put` and `put_op` into `C`,
  with `RuleUnknown`, naming the collection and the rule (next step
  `UpdateProgram`: run a program that knows the rule). It MUST NOT compute a
  state of `C` under any other rule, `/merge/yrs` included.

**The rule interface — slice 6.** A rule makes, per merge collection, a
state for the local writer (ndn-data: `MergeRule::start(collection,
local)`, `MergeState`); the layer passes the collection's name, so the
state knows whose collection it is. The layer hands the state each
operation as an `Op`: the version's id
`(w, s)` — its writer, one key, and its seq —, the implicit digest of its
packet (SHA-256 of the whole Data packet: the version's content address),
its parents, its **past**, the `MergeOp` octets and — round 3 — its
**signed date** (`Dated`, §4: its writer's clock when it signed). The past
is exactly `down(P(v))` (§5.2): the rule asks it whether a version id lies
inside it, and which version of `C` inside it, held here, has a given
implicit digest. The date is the very value the version's signature
covers, so every reader sees the same one: a rule that orders by time
(ndf's "latest wins") reads it rather than a time its operation carries
beside it. It is a writer's claim, as everywhere in the layer (display
only, §4): a rule MAY order by it only where its order is bounded by the
past (a version never loses to one made over it), never let it decide a
check, and MUST treat it as any other field of the operation — the same
on every reader.

- **Owners** (ndn-data: `wire::owns(collection, writer)`). A writer `w`
  (key `<D>/KEY/<k>`) is an **owner device** of `C` exactly when `D` lies
  under `C`'s namespace, the components before its marker (§3). It depends
  on the two names alone, so every member answers alike in any order; the
  layer's owner rule (§3) asks this same test, together with the trust
  context governing the record. A device of a longer held namespace (§3:
  a `/home/bob` device for `/home/32=data/x`) is not distinguishable from
  names alone: `owns` answers the name half — what a reader holding `C`'s
  namespace and none longer under it concludes. A revoked owner device,
  or one outside a cut, needs no handling by a rule: its versions refused
  by their key never reach apply (§5.2, §8).
- **Edit** (`put` with fields) makes the local writer's edit into an
  operation; the layer then checks and applies that operation as any other.
  A rule whose edit already changed its state MUST make that apply
  idempotent (`/merge/yrs`: applying an update already integrated changes
  nothing). A write refused after the edit — too large (`TooLarge`),
  refused by the check, or failing to apply to the writer's own state —
  leaves no trace: nothing is signed, and
  the layer reads the collection again from its versions (§8), so the edit
  is not in the writer's state either. A rule that takes only operations
  the application builds refuses edits, saying so, and `put` answers
  `BadRequest` (next step `FixRequest`: build the operation and use
  `put_op`).
- **Check** says whether the operation is one its writer may have made:
  nothing in it outside its writer's identity, and nothing it is made over
  outside its past. It answers the operation's kind — an **edit** or a
  **checkpoint** (§5.2) — or refuses it for good with a reason. Its answer
  MUST depend on the `Op` alone — never on versions concurrent to it, on
  the device or on a clock — so every reader decides alike.
- **Apply** folds a checked operation into the state and answers
  **counted** (it is in the value) or **not counted** with a reason (it is
  held, applied to the frontier and shown, and not in the value, §5.2).
  Every reason in the operation itself is the check's; apply meets the
  state, which other writers' versions make, so an exclusion that depends
  on it is not counted — never a refusal, which would let one writer
  withdraw another's version. An apply that fails MUST leave
  the state as it was before it; the layer keeps the version applied and
  not counted, with the reason (an own operation that fails is not
  written).
- **Basis** (ndn-data: `MergeState::basis`, round 3) hands the state a
  version a checkpoint applied here covers, which a version not covered
  was made over (§5.2, covered versions as a basis): it is what that
  version is merged against, never applied, counted, told or shown. A rule
  that keeps no history of its own needs none, and ignores it.
- **Made for one rule.** A merge version names the rule its operation was
  made for. A reader refuses one that names another rule than the one in
  force, or none — unless it lies inside the record's `since` (history) —
  for good (`Refusal::OtherRule`, next step `None`: its writer, once it has
  the record naming the new rule, writes the change again under it). A
  stale writer's operation is never read under a rule it was not made for.
- **Counting is a function of the applied set.** Whether a version
  counts MUST be a pure function of the set of versions of `C` that passed
  check and were applied (each with its past), never of their arrival
  order: two devices holding the same applied set count the same versions,
  with the same reasons. As the set grows a version's counting may start
  or stop (a lock arriving after a write made apart from it). **Counting
  changed** (ndn-data: `counting_changed`) lists, since it was last asked,
  every applied version other than the one just applied whose counting
  changed, with how it counts now; the layer asks after every apply and
  tells each change (`Change::Counted`, `Change::NotCounted` with the
  rule's reason unchanged), and the state's `not_counted` follows.
- **Value** is the merged value, typed by the rule: named fields (what
  `/merge/yrs` merges into), or the rule's own encoding, which the program
  defining the rule decodes. The layer passes the applied versions it holds
  back (versions covered only by checkpoints the rule does not count,
  §5.2); the value
  leaves them out, while the rule's counting of every version still sees
  them (the layer's holding back never feeds back into the rule).
- **Determinism.** The layer applies parents first (§5.2), and versions
  concurrent to each other arrive in different orders on different
  devices. A rule MUST answer the same value, the same versions not counted
  and the same refusals for one set of applied versions in every such
  order. A rule may promise more: any order at all.

`/merge/yrs` is a Yjs document. Its root map `fields` holds one entry per
field, each value a binary (`Uint8Array`). The operation of a version is the
Yjs update (lib0 v1 encoding) of its edit: set every field the version sets,
delete every field it sets to an empty value. Concurrent sets of one field
resolve as Yjs resolves them; different fields never conflict. A writer's
Yjs client id is the low 53 bits of SHA-256 over the TLV encoding of its key
name, and a reader MUST refuse an operation that carries content (items or
garbage-collected ranges) under any other client id, or that places an
item against (left or right origin, parent item) or deletes an id of
another client at or past the clock that client's writer had reached in
the operation's past (its parents, and its writer's previous version):
that is its check — an update reaches only content its writer held — and
every operation is an edit, which its apply counts. A Yjs peer may
therefore apply the same updates (it sees
the fields as binaries). A reader ignores root-map entries of other Yjs
shapes; they stay in the document.

## §5.2 Applying versions (cut whole)

### 5.2 Applying versions

A reader applies an admitted version `v = (w, s)` of collection `C` only
when

1. every entry of `w` in `C` below `s` — as `w`'s summary (§7) lists them —
   is applied, unless it never applies: the record in force refuses it by
   its key (a cut that does not list it, §8), or the trust context does (a
   revocation whose cut neither accepts it nor re-admits it, §8.1, §8.2), or
   it was held and refused for
   what it carries (`Unsealed`, §9; an operation the rule refuses), and
2. for every `(y, t)` in `v`'s parents, the reader has applied `y`'s entries
   in `C` up to `t`.

Until then `v` waits. The state's frontier `at` is, per writer, the highest
seq applied; by these rules every entry at or below it that applies at all
is applied, so `at` names exactly the versions the value is computed from.
A parent `(y, t)` that never applies is needed only up to the highest
version of `y` below it that does (for a cut, removal or revocation, the
highest it accepts or re-admits): a
version written on top of refused work is not held back by it (what of the
refused work its operation depended on, the merge function decides).

**Checking and counting — slice 6.** In a merge collection a version that
is ready (above) is checked, then applied:

- `P(v)` is `v`'s parents joined with `(w, s − 1)`, and `down(P)` is every
  version of `C` at or below `P`, writer by writer, that applies at all.
  The rule checks `v` when it is ready to apply, never at admission, with
  the past `down(P(v))`: what `v` was made over, whatever arrived since. An
  operation whose basis lies outside that past is refused.
- A version the rule's check refuses is refused for good for what it
  carries: kept against its name with the reason (`Refused`,
  `Refusal::Rule`), never applied, and never waited for (1. above). Only
  the check refuses: an apply that fails leaves the state unchanged, and
  the version is applied and not counted, with the reason (§5.1) — what
  the state makes impossible is no refusal.
- A version the rule does not count is applied: it lies inside `at`, later
  versions do not wait for it, and it is held, served, delivered to
  watchers as a version and as not counted with the reason
  (`Change::NotCounted`), and listed in the state's `not_counted`; it is
  not in the value. When the rule later counts it, watchers are told
  (`Change::Counted`) and it leaves `not_counted`. A version not counted is
  never dropped. So in a merge collection `at` names exactly the versions
  applied; the value is computed from those of them the rule counts.

**Checkpoints — slice 6.** A checkpoint is an operation the rule's check
says is one; the layer gives it no other mark, and nothing on the wire
tells it from an edit. It **covers** exactly `down(P(CP))`, by frontier.

- Check depends on the `Op` alone, so a reader may check an admitted
  version as soon as it is held whole (§13.1) and every version of
  `down(P(v))` that applies at all is held as a signed record, whole or
  not. A checkpoint is ready then, in place of conditions 1 and 2 above: it
  waits neither for those versions' pieces nor for their application.
- **Parents bound to packets.** Before a merge version applies — an edit
  ready, or a checkpoint whose past is held — each parent `(y, t)` that
  applies at all is checked against the packet held at `(y, t)`: it waits
  while none is held, and is refused for good (`Refusal::Parent`, next step
  `None`) when the parent carries no digest or the packet held there has
  another digest. A mismatch means the version was not made over what this
  reader holds: its writer named a packet that does not exist, or `y`
  signed two packets at `t` (an equivocation; readers holding different
  packets at `(y, t)` differ there already). Every reader holding the same
  packets decides alike, in any arrival order and with no clock. A
  checkpoint whose parent never applies here (a cut, a revocation, a
  refusal for what it carries) is refused likewise: it cannot stand for
  what lies below a version that does not apply.
- Applying it, the layer applies it to the rule, then raises `at` to
  `P(CP)` writer by writer (`at[w] = max(at[w], P(CP)[w])`) — each parent
  held as the packet it names, so a checkpoint covers only what its writer
  applied. Every waiting version now inside `at` is **covered**: held,
  stored, delivered as a version, and never applied to the rule nor
  checked (it reaches the rule only as a basis, below). A version arriving
  later inside `at` is covered likewise. A
  checkpoint planted in a log a removal cut later accepts gains nothing:
  the same check applies to it.
- The rule MUST make applying `CP` yield the state of `down(P(CP))` with
  `CP`, plus the versions concurrent to it already applied, whichever
  subset of `down(P(CP))` it applied before.
- **A checkpoint stands alone for what it covers — round 3.** A rule's
  state after applying a checkpoint MUST NOT depend on whether the versions
  it covers were applied before it: its value, which versions it counts
  and why, and whatever it keeps (locks, alternatives, heads) are the same
  on a device that applied `V1..Vn` before `CP` and on one that applied
  `CP` first and never fetched them, for `CP` and for every version
  applied after it, given the same bases (below). Applying `CP`, the rule
  drops every version `CP` covers from its applied set: a covered version
  counts for nothing on its own — it writes nothing into the value, takes
  and lifts no lock, is no head and no alternative of a conflict — and no
  version is judged against it, except as what a version written apart
  from the checkpoint was made over (below). A version written apart from
  `CP` over some of `V1..Vn` is then counted alike, for the same reason,
  on both devices (conformance `b8`).
- **Covered versions as a basis — round 3.** A version `W` that no
  checkpoint applied here covers may be made over versions one covers:
  its writer worked apart from the checkpoint. A rule merges `W` exactly
  only against what it was made over, so before `W` applies the reader
  hands the rule `W`'s **basis** (`MergeState::basis`, §5.1): every
  version inside the cover of a checkpoint applied here that lies in
  `down(P(W))` and in no `down(P(K))` of a checkpoint `K` applied here
  inside `down(P(W))` — and, of each of those, its own basis by the same
  rule — that the rule does not hold yet. A version the rule applied before
  a checkpoint covered it serves as a basis as it is; nothing is handed
  twice. Each is taken from what the reader holds:
  - held whole — its operation inline in its record, which a reader holds
    before it applies the checkpoint (above), or its pieces held — it is
    opened, checked (one the check refuses is not handed: the check
    answers from the `Op` alone, alike on every reader) and handed as an
    `Op` with its own past;
  - in pieces not held, its pieces are fetched from any holder (§13.1:
    its writer, each device whose version
    held here is made over it — `W`'s writer among them, which applied it
    whole before it wrote `W` — and any device holding it), and `W` waits
    for them as for a parent's pieces — but for its whole basis set at
    most one budget of missed asks: once 16 asks for the bases `W` waits
    for missed, counted over all of them together (each with the
    missed-fetch backoff of §17.1), `W` applies without the ones still
    missing — one lost packet is no evidence they are gone — and they are
    still fetched, and handed whenever they arrive; a basis whose last 16
    asks in a row missed already is not waited for (round 3, review L5:
    counted per basis, a `W` over a wide covered past waited 16 asks for
    each batch of 16 bases, the next fetched only as one ended);
  - held sealed in an epoch whose key the reader does not hold, it is
    handed once the key arrives, and `W` does not wait for it.

  The rule takes a basis only as what the versions made over it were made
  over: it MUST NOT count it, list it in `counting_changed` or show it,
  and handing it changes nothing else. Its state is a function of the
  versions applied that no checkpoint covers (each with its past) and of
  the basis held for them: a basis handed after the versions made over it
  MUST give the state handing it before gives — what was made over it
  merges again, and the counting that moves is told (`counting_changed`).
  When a basis handed after the versions made over it changes the value
  (`MergeState::value`), the collection's watchers are told
  `Change::Remerged` with the collection and the bases handed (§15),
  whatever their frontier: no version arrives with the change, so without
  it a host showing the value would not know to read it again. A basis
  that leaves the value as it was is not told.
  So `W` merges exactly on every device that holds its basis or can fetch
  it: the reference rule replaces with `W`'s edit what the checkpoint
  restated of what `W` was made over, and keeps what the checkpoint
  changed beside (conformance `b9`).
- **When a basis is gone.** Given no basis for a version `W` was made
  over, a rule merges `W` against the checkpoint's state alone: its
  conflict handling (the reference rule keeps `W`'s edit as an alternative
  beside the checkpoint's statement; ndf's turns an edit that no longer
  fits into a conflict carrying its words). This happens only while no
  reachable device has the basis: nothing drops a version's record — an inline operation with it —
  or a large version's chunks, `W`'s writer applied `W`'s basis whole and
  serves it, as does every device that merged `W` exactly (§13.1). A basis
  is therefore gone only while every device that holds it whole is away, and
  a reader knows it as it knows a missing piece: every device it asks
  answers without it, ask after ask (16 in a row, above). Every reader
  then merges `W` without it alike; one
  that finds it again (a device returning) hands it, and its state moves
  to the exact merge, with every other reader's as they find it too; its
  watchers are told `Change::Remerged` when the value moved.
- **Bound — round 3.** `W`'s writer chooses `P(W)`, so it chooses what
  readers fetch as a basis: at most the versions inside the cover in
  `down(P(W))` — signed versions of `C` that exist, each bound to its
  packet by the parents' digests above and carrying at most `PAYLOAD_MAX`
  (§13.1) — each fetched once per device and held after; at most 16 basis
  versions of one collection are fetched at once (ndn-data:
  `BASIS_FETCHES`), the next as one ends; and only for a version admitted
  (signed by a key the record in force names a writer, §8). However many
  bases `W` names, it waits for them at most 16 missed asks in all
  (above): what it names delays its own exact merge, never its applying.

  **Threat note.** A member who writes over a frontier deep in the
  history a checkpoint covers makes every reader that applied the
  checkpoint first fetch and hold that history again — what a reader that
  joined before the checkpoint fetched anyway, and no more: nothing outside
  `C`, nothing its writer did not sign, nothing a reader does not verify
  through the manifest. It cannot make a reader count a covered version,
  nor change how any version counts beyond what an exact merge against its
  own past gives. A holder withholding a basis delays the exact merge on
  readers that can ask only it, as a withheld piece delays any version; it
  cannot make readers differ once the basis reaches them.
- **Newest first; what it covers counts as it counts.** In each pass a
  reader first applies, if one is pending and its past is held, the newest
  checkpoint (by its writer's seq), then what became ready; so a
  collection read anew from its versions applies its newest checkpoint and
  what came after it, whatever order they were held in. A version inside
  the cover of a checkpoint applied here (its `P(CP)`) counts exactly when
  a checkpoint covering it counts: one no other checkpoint applied covers
  counts as its rule counts it, one covered by others as this same test
  says (a covered checkpoint is never applied by a collection read anew
  from its newest checkpoint, so only uncovered ones decide). Covered by a
  checkpoint that counts, a version leaves `not_counted`
  (`Change::Counted` if it was told not counted); covered only by
  checkpoints the rule does not count, it is not counted — listed in
  `not_counted` with the reason ("covered by the checkpoint `<key>` seq
  `<s>`, which its rule does not count: `<the rule's reason>`"), told
  `Change::NotCounted`, and left out of the value (the layer passes it
  back to the rule's value as held back, §5.1), whether the rule applied it
  before or never. It follows its checkpoints' counting as
  `counting_changed` moves it, told each time it changes; what the rule
  says of the covered version itself is not told. The state, value and
  `not_counted` are then the same whether a covered version was applied
  before its checkpoint or never, and after a restart. A rule that would
  not count a checkpoint should rather refuse it in its check: a
  checkpoint not counted takes everything it covers out of the value.
- A reader MUST NOT fetch the pieces (§13.1) of a version covered by a
  checkpoint it holds whole and checked, unless it is the basis of a
  version that no checkpoint applied here covers (above).
- **The past every reader sees.** `down(P)` holds the versions at or
  below `P` not refused by their key (a cut that does not list them, a key
  no writer, a revocation, an issuer no longer trusted): `Past::contains`
  and `Past::by_digest` answer from those held — admitted, held sealed, or
  held and refused for what they carry or for their group, which every
  reader holds before it judges a version over them. A version refused by
  its key is in no past, held here or not (a late reader never fetches
  it): a rule finds no basis there and judges the operation as one whose
  basis is outside its past (it refuses it, or counts it without that
  basis, as it defines).

**Merge state across restarts: built lazily — slice 6.** A merge
collection's state is a function of the signed versions held (above), so
a device need not build it at start; it builds it on first need, and the
state it builds is the one it had before the restart.

- **What start restores.** What the device needs to publish and judge:
  its log and summaries, heads, records (members, cuts, introductions),
  refusals, equivocation evidence, and per
  merge collection the index of the versions its store holds (ndn-data:
  `Coll::dormant`, each writer's seqs and the writers their parents name).
  No merge state is built then.
- **What builds a state.** A `get` of the collection, of a state name,
  version or entry of it; a `watch` of it; a `watch` of a folder over it,
  only when the collection holds a version past the watch's `since` (one
  to list — a collection wholly inside `since` stays unbuilt, and what
  arrives later builds it); `put` or `put_op` into it; a version
  arriving for it; a new members record
  over it; a revocation of a key
  that wrote in it.
- **The build.** It loads the collection's versions from the store and
  applies them by the rules above — its newest checkpoint first, then the
  versions after it — so its state, frontier, value, `not_counted` and
  every verdict are those it had before the restart: each a function of
  the signed versions held, never of timing.
- **Nothing more persisted.** The store holds, of other writers, only
  versions applied here (stored as they apply), and of this device every
  version it wrote; a check's verdict is a function of the operation
  alone, so refused versions, not stored, are fetched and refused again
  alike.
- **Until built,** the collection serves what its store holds of it as
  applied (§13.1). A collection nobody touches costs its index entries
  only.

## §6 Members (the lines that changed)

### Changing the rule

  applied as history only: they order later versions (§5.2) and never
  enter the new rule's state. A state of `C` after the change is named by
  a frontier covering `Since`.

## §6.2 Threat notes (the paragraphs and lines that changed)

### A member writing a bogus checkpoint

**A member writing a bogus checkpoint.** A checkpoint is its writer's
claim of the state of what it covers (§5.2), and nothing else checks its
content beyond the rule's check against its past (a rule may admit
checkpoints from fewer writers than edits, and verify what it can by
digest). What it covers it cannot overstate: each parent carries the
digest of the packet it names (§4), so a writer can name only tips it
held. A checkpoint naming another writer's seq that does not exist yet —
to cover, once it does, edits it never saw — matches no packet there and
is refused (`Refusal::Parent`) on every reader, the other writer's own
device included; one naming a parent that never applies (outside a cut,
refused) is refused likewise, as it would stand for what lies below. Every
reader applies a checkpoint alike, so it cannot make two readers disagree;
covered versions are never applied, and their pieces never fetched, so a
reader does not find a lie about content by itself. The remedy is the
owner's: a removal cut that does not list the checkpoint withdraws it
(§8), and the versions it covered then apply, their pieces fetched. A cut
that does list a checkpoint planted before the removal grants it nothing
the digest check would not.

### A rule refusing or withholding

**A rule refusing or withholding.** A rule is code every reader runs under
one name (§5.1). A version it does not count is held, applied to the
frontier, served, shown with the reason to every watcher and listed in the
state: never dropped, never hidden. Only its check refuses, from the
operation and its past alone; what its apply answers, meeting the state
other writers made, never refuses a version (it is
not counted, with the reason), so no writer can arrange a state that gets
another writer's version withdrawn. A version it refuses is kept against its
name with the reason, and nothing waits for it. A program whose rule
behaves otherwise than another's under the same name breaks determinism;
the defence is the versioned name — a change of meaning is a new name.

### A basis held by some readers only

**A basis held by some readers only.** Which refused records a device
holds depends on when it started: a late reader never fetches an entry a
revocation or a cut refuses. Such a version is in no operation's past
(§5.2), held here or not, so a rule's check finds no basis there on any
reader; versions refused for what they carry or for their group stay in
the past, as every reader holds them before judging what was made over
them. An honest writer whose basis is later cut out loses the operations
that need it, alike everywhere.

### A Yjs update reaching outside its past

**A Yjs update reaching outside its past.** Yjs ids are predictable, and
yrs keeps an update whose references it lacks pending until they arrive,
so an update could delete, or place items against, another writer's
concurrent or future content. `/merge/yrs` refuses any update whose
origins or deletes reach, for any other writer, past the clock that
writer had reached in the update's past (§5.1).

### Pieces served to some devices only

**Pieces served to some devices only.** A writer could serve a version's
pieces to one device, which builds on it, and to no one else, so everyone
else's copy of what that device writes would stall. A device serves the
pieces of every merge version it applied, and readers ask the devices
whose versions are made over it (§13.1), so the version is available
wherever something built on it is.

### Pieces lost and permanent blocking

**Pieces lost and permanent blocking.** In a merge collection
every later version waits for an earlier one's pieces (§13.1), so pieces
lost for good would block the collection for every reader lacking them.
A device never drops its own merge pieces, and serves them to any device
that asks (§13.5): readers lacking them wait — stale — until a device
that holds them answers.

### Unknown-rule downgrade

`RuleUnknown` with nothing computed (§5.1). The name is in the owner-signed

## §6.3 Members' namespaces, adopted for the folder (the line that changed)

  subject no record lists it for, not a summary or a snapshot

## §8 Cut (the lines that changed)

### Kept versions across restarts

    restarts, a state built lazily (§5.2) and every new record — so the

### What it lists

  in `C` it keeps — versions and members records — and one with
  prefix `<D>/32=log` for `K`'s snapshots

### What it refuses: snapshots under 32=log, the summary nodes

  answer either. Snapshots under `<D>/32=log` are fetched only when asked
  for by name. Nodes of `K`'s summary verified before the reader held the
  cut stay verified (they still say which seqs exist, §5.2), but none is

### An entry the cut neither accepts nor re-admits

  versions naming it as a parent do not wait for it (§5.2).

### The bound upto

    collections and snapshots are left out). At least one MUST be

## §9 Seal (a line that changed)

### The grant-answer paragraph

  (round 3, faulty cases f2 and r7: a lossy path to the asker made every

## §10 Type (the lines that changed)

### The fields and type bullets

- A version sets fields: each field it carries is set to its value, a field
  carried with an empty value is removed, and every field it does not carry
  keeps its value. So a writer that knows only revision 1 keeps revision-2
  fields by construction (invariant 8); there is no "replace all" write.
- The type is recorded in the version for readers and lenses; it never
  changes how the merge function folds fields. A type MAY later declare
  richer field kinds (text merged by character); slice 1 has none.

## §11 Snapshot and state names (cut whole)

## 11. Snapshot and state names — slice 1

A **state name** `<C>/32=state/<F>` names the merged value of merge
collection `C` at frontier `F` (the last component is a
GenericNameComponent whose value is a `Frontier` TLV). It is computed, never
fetched: a reader answers it by applying exactly the versions of `C` inside
`F` (§5.2) and MUST answer the same value on every device and however `C`
grows. A reader that does not hold every version inside `F` (as the
writers' summaries list them; a version a checkpoint inside `F` covers, as
its signed record, §5.2) MUST NOT answer a partial value. Of a collection
whose rule the device does not know, it answers `RuleUnknown` (§5.1).

A **snapshot** is an entry of its signer's log, `<D>/32=log/seq=<n>` (no
collection), Content `SnapshotRecord`: the names it pins, each an exact log
entry name or a state name. Publishing it makes a set of versions and
merged states citable together: a link carries the snapshot's name. It
does not hold the versions it pins back — a reader may count them before
the snapshot arrives.

## §13.1 Large payloads (the lines that changed)

### The opening paragraph

travels in pieces, in a collection of any rule: from slice 6 a merge
collection's operations and checkpoints too (slices 3 to 5 carried every
merge operation inline, answering `TooLarge` and `NotInline` for larger
ones).

### The size bound

A payload carries at most 64 MiB (`PAYLOAD_MAX`, 67,108,864 octets) — per
version, so per operation or checkpoint —, as a reader assembles it whole:

### Fetching pieces: the last sentence

  assembles (at most `PAYLOAD_MAX`). A merge version's pieces walk the same way.

### In a merge collection

- **In a merge collection — slice 6.** A version in pieces is admitted,
  and its pieces fetched as above unless a checkpoint the reader holds
  whole and checked covers it (§5.2) and no version that checkpoint does
  not cover is made over it (a basis, §5.2: fetched then, at most 16 of a
  collection at once). Until it is whole it waits as a
  missing parent does: later versions of its writer and versions naming it
  wait. Whole, it is opened (when sealed), checked and applied (§5.2).
  A later version in pieces — maybe a checkpoint covering it, which only
  its opened payload tells — holds back the fetch of the pieces in its
  past (its parents and its writer's earlier entries) until it is found
  whole or `REFRESH_TRIES` of its fetches missed (§17.1): one lost packet
  is no evidence that it is not to be had.

### Besides its writer, other sources for pieces

- Besides its writer, a reader asks for those pieces the
  devices whose versions held here are made over the version (their
  parents include it), each under its own name `<D>/32=held/<Name TLV>`:
  a device serves the entry and pieces of every version it holds (§13.5).
  A writer that serves its pieces to some devices only does not stall what
  others build over them.

### A reader does not keep an applied operation in pieces

- A reader does not keep an applied operation in pieces in memory: it is
  opened again from the pieces when the state is computed anew. A version
  found not whole is not looked for again until its pieces arrive.

## §13.5 What a device serves (the lines that changed)

### What a device served before

log. Before, a device served only its own log and the merge versions it
applied: a person whose phone writes and goes away had their work reach

### What it lists: records

  every record (members, folder, snapshot); stored, or

### What it never serves

`OutsideCut`), a revocation cut or an untrusted chain (§8) or its rule's
check (§5.2) — another reader would refuse it too, and serving it would

### Asking for a writer who does not answer

order, for pieces, the devices whose versions are made over the version (§13.1),
then the other devices it hears for the namespace (§12: heard in its

## §15 Verbs (the lines that changed)

### The verbs table: put_op, watch and snapshot rows

| `put_op` | `put_op(collection, operation, {type, keep}) → (writer, seq)` | 6 |
| `watch` | `watch(collection, since F) → summary, new versions…` | 1 |
| `snapshot` | `snapshot(names \| collections) → snapshot` | 1 |

### The verbs stay five

verbs stay five. Code mostly uses `get`, `put` and `watch`.

### get(C)

- **`get(C)`** of a merge collection answers its state now — `State` with a
  state name, `at`, the value (typed by the rule, §5.1) and `not_counted`:
  the versions held that are not in the value, sorted by id, each with why
  as a `NotCounted` (`Excluded`: the rule's not counted inside `at`;
  `Waits`: a basis or pieces still arriving, §5.2; see
  the `NotCounted` bullet below); of a log collection, its newest version

### get: rule unknown, state name, log entry name

  step `UpdateProgram`), §5.1.
- **`get(state name)`** answers that exact state (`Age::Exact`), §11; under
  a rule the device does not know, `RuleUnknown`.
- **`get(log entry name)`** answers the version or snapshot (`Age::Exact`),

### Every Version a host receives

- **Every `Version` a host receives** — answered by `get`, delivered or
  listed by `watch`, carried whole in an equivocation — MUST carry
  `digest`, the implicit digest of its packet (SHA-256 of the whole Data
  wire: the name a merge operation's basis and a parent's `Digest` use,
  §4, §5.1), and `op`: the `MergeOp` octets of a merge version, exactly
  as its rule's check and apply received them, or nothing under the log
  rule. A merge version's `op` is absent too while its
  operation is not open here — sealed in an epoch whose key the device
  does not hold, or carried in pieces and not read whole (`Payload::Large`,
  listed by its size); a `get` of its name reads it whole and carries it.
  A host keeping versions for history so names them as operations do,
  and reads their edits, with no index of its own.

### put

  device's log with parents = the state's `at` — in a merge collection, the
  operation its rule's edit makes (§5.1) —, applies it, and publishes it
  (§12).

### put refusal and put_op

  in the state (§5.1).
  In a merge collection whose rule the device does not know it answers
  `RuleUnknown` (§5.1); under a rule that takes only operations the
  application builds, `BadRequest` (next step `FixRequest`: use `put_op`).
- **`put_op(C, operation, {type, keep})`** is `put` with the operation the
  application built (`MergeOp`), in a merge collection whose rule the
  device knows: parents = the state's `at`, past = `down(at)`; the device
  signs the version and has the rule check and apply it (§5.1, §5.2), then
  stores and publishes it. An operation the rule refuses answers
  `BadRequest` with the rule's reason (next step `FixRequest`), and nothing
  is stored or published and the log head does not move — nor, for a new
  collection, is its default record signed (§5). Of another rule,
  `BadRequest` (next step `FixRequest`: `put_op` is for merge collections);
  under a rule the device does not know, `RuleUnknown`. It answers as `put`
  does otherwise.

### NotCounted

- **`NotCounted`** is the type of every reason a held version is not in
  the value (`State::not_counted`, `Change::NotCounted::why`), two kinds
  that differ in whether they end by waiting, so a program shows a spinner
  for one and a mark for the other: **`Waits(why)`** is the layer's own
  wait — a basis or pieces of the version are still arriving; it ends
  when what it waits for arrives, and the version then counts
  (`Change::Counted`). **`Excluded(why)`** is a rule's own exclusion (the
  rule's `Counting::NotCounted`, an apply that failed): it does not end by
  waiting for what the layer waits for
  (a later version the rule counts differently may still end it, as §5.2
  says, and `Change::Counted` follows then too). `Display` is the bare
  reason. A version whose reason moves from `Waits` to `Excluded`, or
  back, is told again with `Change::NotCounted`; the same reason of the
  same kind is told once. The rule's own `Counting::NotCounted(String)` is
  unchanged: the layer wraps it as `Excluded`.

### watch: held-but-not-counted reports

  every equivocation (§4), and every version withdrawn (§8); from slice 6
  also every version held but not
  counted, with why (`Change::NotCounted`, §5.2), and every such
  version once it counts (`Change::Counted`); it starts a refresh of every

### Every change names its collection

  it is about (`Change::collection`): a version, withdrawal,
  not-counted or counted report its version's collection; a

### The watch listing

  reports what is applied, and, right after a version, `NotCounted` with
  why when the rule does not count it; a version held but not applied yet
  (it waits for an earlier one, its key or its pieces) is not listed and

### Remerged

  A watch of a merge collection is told `Change::Remerged` (the
  collection and the bases handed) when bases that versions applied here
  were made over arrive after those versions applied without them and
  change the value (§5.2, covered versions as a basis): no version comes
  with that change, so a host showing the value reads it again. It is told
  to every watcher of the collection, whatever its frontier, and never for
  a basis that leaves the value as it was.

### The snapshot verb

- **`snapshot(names)`** pins, for each name, the current state name of a
  merge collection or the exact name of a version, snapshot or entry, and
  signs the `SnapshotRecord`.

## §16.1 Names (the lines that changed)

### Rows: snapshot, state

| snapshot | `<D>/32=log/seq=<n>` | device key |
| state (never fetched) | `<C>/32=state/<Frontier TLV>` | — |

### Log entry bullet

- **Log entry.** `D` is the components before the first `32=log` (`D` has
  no keyword); the last component is `seq=<n>`; what lies between is empty
  (a snapshot) or a collection name.

### State bullet

- **State.** `32=state` is the next-to-last component and the collection
  name precedes it.

## §16.2 TLV-TYPE numbers (the lines that changed)

### The quarantine paragraph

is kept in [history/data-layer-groups.md](history/data-layer-groups.md)). The numbers 0x0525, 0x0527, 0x0529, 0x052B, 0x052D, 0x052F, 0x0533, 0x0535, 0x0537, 0x0539, 0x053D, 0x0541, 0x0543 and 0x0551, which carried custody (the hold, lease and prune records, the hold and audit asks, the audit answer and its fields), are freed and quarantined too, not reused (the old spec is kept in [history/data-layer-custody.md](history/data-layer-custody.md)). The numbers 0x0530, 0x0545, 0x0547, 0x0549, 0x054B, 0x054D, 0x054F and 0x0553, which carried streams (the keep for the last `n`, a block and its entries and offsets, a one-key head and its freshness, the time range of a range name, and a summary node's expiry runs), are freed and quarantined too, not reused (the old spec is kept in [history/data-layer-streams.md](history/data-layer-streams.md)). A number is even unless the notes

### VersionRecord row

| 0x0520 | VersionRecord | Name (collection), Frontier (parents, each entry with its tip's Digest), TypeId, Seal, Keep, Dated, [Rule] (merge: the rule the operation was made for, §5.1), then Fields, MergeOp — or Chunks (§13.1; in a collection of any rule from slice 6) — or, sealed, Sealed |

### Rows: MergeOp, Rule, SnapshotRecord

| 0x0544 | MergeOp | octets: the merge function's operation |
| 0x0548 | Rule | RuleKind [Name (merge rule: its full, versioned name, matched exactly, §5.1)]; in a merge `VersionRecord`, kind 2 and the rule its operation was made for (§4) |
| 0x0550 | SnapshotRecord | Name* (pins) |

### The checkpoints sentence

Checkpoints, versions not counted and effective records are not on the
wire.

### Round 3 adds no TLV: the basis clause

`MembersRecord`; a basis (§5.2) is a version already on the wire; a

## §16.3 Why these encodings (the bullets that changed)

### New records

  a version's parents/type/seal/keep/fields/operation, a members record, a
  snapshot's pins, and a Merkle summary node. SVS-PS mapping data was not

### Rules by exact, versioned name

- **Rules by exact, versioned name** (§5.1), not a rule kind with
  parameters or a name matched by prefix: the name in the owner-signed
  record is the whole policy, a device either runs exactly it or computes
  nothing, and a change of meaning gets a new name, so no two programs
  compute different states under one name and no reader falls back to
  another rule. `/merge/yrs` keeps its name, so slice-2 records still mean
  what they meant.

### Checkpoints are rule-defined and cover by frontier

- **Checkpoints are rule-defined and cover by frontier** (§5.2): only the
  rule knows which operation summarizes a state, so the rule's check says
  so, and no wire mark could be trusted beyond what that check says. What a
  checkpoint covers is `down(P(CP))`, read from the frontier its writer
  signed: every reader computes it alike, it needs no new field, and a
  checkpoint cannot claim to cover a version its writer had not applied:
  each parent carries the digest of the packet it names, which a writer
  can know only of a packet it held (§4).

### Pieces in the version, not references to log versions

- **Pieces in the version, not references to log versions** (§13.1), as
  agreed with ndf-rs (`handoff-ndf-rs/REPLY-3.md`): a reference to a
  version of another collection would leave open whether its readers and
  epoch match the merge collection's, who may write there, and what happens
  when the referenced version is dropped while the operation still needs
  it. Pieces in the version itself raise none of these: they verify through
  the version's own signature and stay sealed in its epoch. The one rule
  they bring is that a merge version's pieces hold back every later
  version of the collection until they are had (§13.1).

## §17 Failure model (the table rows that changed)

### Rows: parent seq, stale writer, apply fails, basis refused, Yjs

| A writer names a parent seq that does not exist yet (a checkpoint over another's future) | Its parent's digest matches no packet at that seq: refused `Refusal::Parent` once the genuine one is held; it covers nothing, and the other writer's versions apply. A checkpoint over a parent that never applies is refused too. | §4, §5.2 |
| A stale writer's operation made for an earlier rule | Refused `Refusal::OtherRule`; never read under the rule in force. | §5.1 |
| A rule's apply fails on the state others made | Applied, not counted, with the reason; no version is refused for it. | §5.1 |
| A basis refused by its key | In no past on any reader, held or not: judged alike everywhere. | §5.2 |
| A Yjs update deleting or placing against content outside its past | Refused by `/merge/yrs`'s check. | §5.1 |

### Row: pieces served to one device only

| Pieces served to one device only | Readers ask the devices whose versions are made over the version. | §13.1 |

### Row: writer behind on a seal

| Writer behind on a seal | Its unsealed version is refused `Unsealed`; its later sealed versions do not wait for it. | §5.2, §9 |

### Row: lossy link

| Lossy link (packets dropped, delayed past the lifetime) | Every fetch that missed is asked again while the device's durable state still owes what it was for — a walk of a summary and what it lists, an epoch key, a merge version's pieces, a removal cut's manifest packet — with a pause doubling from 250 ms to 4 s, never waiting for a new sync notice and never one try per granter; within one ask, an Interest nothing answered is expressed again under a fresh nonce after a retransmission timeout from the round trips the device measured (at least 250 ms, doubling, at most 3 times within the lifetime), so a lost packet costs about that timeout rather than the lifetime; at 20 % loss a sealed folder's first version reaches a reader's watch in seconds. Bounded: at most `FETCH_TRIES` asks of at most 1 + `REEXPRESS_MAX` Interests each per owed packet and source per lifetime plus pause. | §17.1 |

### Rows: device lacks the rule, operation over a basis, rule does not count

| Device lacks a collection's merge rule | It holds, verifies, serves and lists every version, applies none, and answers `RuleUnknown` (`UpdateProgram`); it never computes a state under another rule. | §5.1 |
| Operation made over a basis outside its past | Refused for good by the rule's check against `down(P(v))`, the same at every reader; later versions do not wait for it. | §5.1, §5.2 |
| Rule does not count a version | It is applied to the frontier, held, served and shown with why (`NotCounted`, `not_counted`), never dropped; when the rule counts it, watchers are told (`Counted`). | §5.2 |

### Row: merge version's pieces missing

| Merge version's pieces missing | It waits as a missing parent, with what depends on it, while its pieces are fetched from the writer and the holders; covered by a checkpoint held whole and checked, its pieces are never fetched. | §5.2, §13.1 |

### Rows: bogus checkpoint, checkpoint not counted, stored version gone, power loss while building

| Member writes a bogus checkpoint | Applied alike everywhere as its writer's claim; the owner's removal cut withdraws it, and the versions it covered then apply. | §5.2, §6.2, §8 |
| Checkpoint the rule does not count | What only such checkpoints cover is not counted, saying which checkpoint and why, and is out of the value, alike whether it was applied before the checkpoint or never and after a restart; a member's write the rule never counts stays not counted under her own checkpoint. It counts, and watchers are told, once a checkpoint covering it counts. | §5.2 |
| A stored version gone or no longer decoding when a merge state is first built after a restart | It is no longer held: the state is built from the versions that read, and the lost one is fetched again where a summary lists it; versions after it wait for it — stale, never wrong: every verdict is the one the signed versions held give, as before the restart. | §5.2, §7 |
| Device stops or loses power while a merge state is being built | Nothing is lost or changed: the build computes from the versions its store holds, each verdict a function of them; the next start indexes the collection again and its next need builds the same state. | §4.2, §5.2 |

### Row: write refused after the edit

| Write refused after the edit (too large, rule refuses) | Nothing signed or stored, no default record, the log head unmoved; the collection is read again, so the refused edit is not in the state. | §5, §5.1, §15 |

### Row: version listed by a watch while it waits

| Version listed by a watch while it waits (for an earlier version, its key, its pieces) | Not listed: it comes once it applies, so no watch is handed a version twice. | §15 |

## §17.1 Asking again under loss (the lines that changed)

### A merge version's pieces

- **A merge version's pieces** (§5.2, §13.1) — while the version waits for
  them: not covered by a checkpoint held whole, not cut or let go.

### Inside a walk of a version's pieces

- **Inside a walk of a version's pieces** (§13.1) — a read or a merge
  version's pieces — each piece is an owed fetch, asked in
  place up to `FETCH_TRIES` asks per source, at most `Config::window` of
  one walk's pieces at once; a piece that missed at every source leaves
  the others to be fetched and kept, and the walk ends without the
  payload. A read asks again as its caller does; the loops above ask
  again for merge pieces.

## §18 Conformance (the lines that changed)

### The slice-1 cases: c7 and c11

`/home/bob`), c7 (an older lens keeps a newer field),
c8 (a laptop back after four months: 10,000 notes, 37 changed), c11
(citing a merged state) and o4 (a reader keeps up with a writer that never

### The checkpoint unit test

`ndn-data`'s unit test `a_version_a_checkpoint_covers_counts_as_that_checkpoint_counts`
checks that what only a checkpoint the rule does not count covers is not
counted and out of the value, the same after a restart's lazy build, and
counts once the rule counts the checkpoint (§5.2).

### The slice-6 cases

The slice-6 cases are b1 (a custom rule on two devices: both compute the
same rule-typed value; a third device without the rule holds every version
and reports the collection unreadable, `RuleUnknown`, computing nothing),
b2 (an operation whose basis lies outside its causal past is refused at
every reader, and later versions do not wait for it), b3 (a non-owner's
edit of a setting the owner locked, made with the lock in view, is kept
and shown with why and never counts, even once unlocked), b6 (two owner
devices: a lock set from one holds for the other, whose own later write
counts; a non-owner's edit made with the lock in view is not counted on
every member; one made apart from the lock waits and counts once an owner
writes over it), b7 (a write and a lock concurrent to it, received in
either order, give the same counting on every member: counting stops when
the lock arrives after the write, and starts on unlock),
b4 (a 20 KiB operation and a 100 KiB checkpoint in one merge collection,
in pieces, read and applied at another device; versions the checkpoint
covers are not fetched), b8 (a
device that applied a checkpoint first, never fetching what it covers, and
one that applied the covered versions before it count a version written
apart from the checkpoint alike, for the same reason, and show the same
value, also after an owner writes over it), b9 (a checkpoint written while
another member works offline and comes back, the member's edit
merges exactly on every device, the device that applied the checkpoint
first fetching the covered version it was made over, with no conflict),
h10 (a device serves the versions it holds that another device wrote:
Alice's phone locks a paragraph of a sealed folder and goes away for good,
no cache keeping what it served; her laptop answers for the phone's root,
summary nodes and sealed entry, exactly as the phone signed them, and Bob
counts the lock),
f1 (a folder of 1,000
collections: a reader asks one grant per folder epoch, not one per
collection), f2 (narrowing a collection under a folder works; widening
it is refused, and a widening record signed anyway has no effect), f3
(a collection taking its first own record under a folder: a writer it
drops keeps its earlier versions, cut at what the owner held, and a seal
keeps what was written unsealed before readable, at every reader) and f4
(Carol and Bob join a note by codes; the owner's `members` and folder
watch show both with no gesture of hers; she lets Carol go with a change
naming Carol alone, and Bob stays a member, writing and reading, his
device holding the same record, while Carol no longer reads what follows).
Their features are `RuleByName`, `AppOps`, `MergePieces`,
`FolderMembers` and, for f4, `Introduction`.

### The lazy-state case

The lazy-state case is l1 (a note collection with edits, a checkpoint and
edits after it, beside collections nobody touches after a restart; the
device stops and starts again from its store: no merge state is built at
start, the first `get` builds the note's state from its newest checkpoint
— the checkpoint and the versions after it applied, none before — and its
frontier, value and `not_counted` equal those before the restart; the
untouched collections stay unbuilt, costing index entries only). ndn-data
carries l1 as a unit test, its rule counting starts and applies
(`device/lazy_tests.rs`), with a folder watch that builds only the
collections holding versions past its `since`.

### The folder-watch case

The folder-watch case is w1 (a note of 1,000 paragraphs, one element
collection each, under one folder shared by `share_folder` with a second
person as writer and reader; both watch the folder once. The other person
adds a paragraph — a collection created after the watch began — and the
watcher's stream reports its version tagged with the new collection; the
same the other way round, and for the watcher's own add; a version the
rule does not count, in another paragraph, is reported `NotCounted` and
then `Counted` on the same stream, tagged with that paragraph; no watch is

## README.md rows 26 and 56 (the lines that changed)

| [data-layer.md](data-layer.md) | Data layer: versions, collections, members, summaries, cuts, snapshots, seals and types and the five verbs; slices 1–3, 5 and 6 normative (versions, members, merge rule `/merge/yrs`, nested summaries, snapshots, sync notice, seals, large payloads; revocation cuts; merge rules by versioned name, operations the application builds, checkpoints, merge pieces, folder members records, introductions (joining a folder by a code); TLV 0x0520–0x057F), later slices skeleton |
| 0x0520–0x057F | [data-layer.md](data-layer.md) (even numbers; odd ones for critical additions: slice 3's chunks and size, 0x0521 and 0x0523, and the nonce, asker's proof and proof that the introductions use, 0x0531, 0x053B and 0x053F (0x0525, 0x0527, 0x0529, 0x052B, 0x052D, 0x052F, 0x0533, 0x0535, 0x0537, 0x0539, 0x053D, 0x0541, 0x0543 and 0x0551, which carried the hold, lease and prune records, the hold and audit asks, the audit answer and its fields, are freed and quarantined, not reused: the old spec is kept in [history/data-layer-custody.md](history/data-layer-custody.md)); 0x0530, 0x0545, 0x0547, 0x0549, 0x054B, 0x054D, 0x054F and 0x0553, which carried the keep for the last `n`, a block and its entries and offsets, a one-key head and its freshness, the time range of a range name and a summary node's expiry runs, are freed and quarantined, not reused (the old spec is kept in [history/data-layer-streams.md](history/data-layer-streams.md); `KeepUntil` 0x052E stays, the expiry of an introduction's offer, and `SeqRange` 0x0558, the ranges of `Entries`); slice 6's folder flag of a members record, 0x0555 (0x0557 and 0x0559, which carried a version's group and its count, are freed and quarantined, not reused: the old spec is kept in [history/data-layer-groups.md](history/data-layer-groups.md)), a removal cut's binding of what it keeps to its bytes (CutBytes, the full name of its cut manifest), 0x055B, and a folder cut's list per collection (CutIn), 0x055F; slice 6 reuses, in a version record, FrontierEntry 0x0524 with Digest 0x055E — each parent bound to its tip's packet — and Rule 0x0548, the merge rule an operation was made for; the introduction's offer and use-mark records, ask, answer, role, tries, refusal and credentials, 0x0561–0x056F, §19) |

## ndn-link.md §8.7 Grants, rule 10 (the line that changed)

    Nothing else this device serves by name crosses: an **unsealed collection outside the folder** (the layer answers those by name to whoever asks: "a record with no readers leaves the collection unsealed") is not answered over a grant link, nor a snapshot. A device with no data layer (no `Introductions` given) carries the first three kinds, and no folder. **What stays public by the data layer's model:** the summary nodes on the path to the folder (`<O>`, `<O>/32=data`, … ) list the next component, head and digest of the collections *beside* the folder — names and counts, never a payload — and the sync group carries "device D moved" and nothing else; a person given the folder reads those. Unsealed data of the folder itself is the folder's, and readable by whoever the link carries it to. The person can also no longer use this device's forwarder to reach other peers' names: an Interest outside the names above is Nacked at the link.
