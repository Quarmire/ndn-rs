> Superseded by heap.md and invite.md at ndn-rs 2b344e09. Kept for history; nothing here is normative.

# Streams text cut from `data-layer.md`

Blocks, the one-key rule and its signed head, range reads, retention by expiry and keep bounds. Section numbers and wording are those of `data-layer.md` just before the cut.

## Header: Status and Scope (the lines that changed)

- **Status:** Slices 1–6 normative, with the durability barrier (§4.2:

  re-checked, renewal, rotation and recovery, §8.1–§8.6); slice 4: signed blocks of small
  entries carried inline, the one-key rule with its signed head, rollback
  check and freshness bound, retention by expiry and listing by keep, range
  reads by seq and by time, `put`'s batch, §4.1, §5.3, §5.4, §7, §14.1,
  §14.2); slice 3: large payloads in

## §2 Invariants and the clock paragraph after them (the lines that changed)

7. **Retention is chosen at write.** Nothing extends keep; every device
   drops what has passed its keep, by its own clock (§14.1).

revocation cut is held (§8.5). Dates are display, indexing (range reads,
§5.4) and retention (§14.1) only. The root device's own clock also bounds

## §3 Names, devices, namespaces (the line that changed)

  (§11), and entry and range names (§4.1, §5.4).

## §4 Version and log (the lines that changed)

## 4. Version and log — slices 1, 2, 4 (blocks)

  collection every parent carries one; under the log and one-key rules a
  writer names it when it holds the tip (an expired tip goes without).

- The payload of a version is one entry — the fields the writer set
  (§10), and the merge function's operation (§5.1), empty under the log
  rule — or, in a log or one-key collection, a **block**: many small
  entries under the version's one signature (§4.1).

  stays readable. Keep is recorded at write; every device drops what has
  expired by it (§14.1).

## §4.1 Blocks (cut whole)

### 4.1 Blocks — slice 4

A **block** is one version whose payload is a list of small entries
carried inline, in the version's own packet, under its one signature (model
change M6).

- **Format.** The `VersionRecord` of a block carries `Block` (§16.2) in
  place of `Fields` and `MergeOp`: one or more `BlockEntry`, each an
  `Offset` and that entry's `Fields`. A sealed block (§9) is sealed like any
  payload: the `Block` TLV is the plaintext `Sealed` carries. A block is
  always one packet: its `Block` encoding is at most 6,144 octets
  (`INLINE_MAX`), so it is never in pieces (§13.1). Blocks are for log and
  one-key collections; a merge collection carries one operation per version,
  and a reader refuses a block in one (`NotInline`).
- **Entry dates.** An entry's date is the version's `Dated` plus its
  `Offset`, in milliseconds. The first offset MUST be 0 — the version's
  `Dated` is its first entry's date — and offsets MUST NOT decrease along
  the block; a reader MUST refuse a block that breaks either. A writer dates
  the entries it puts into one collection under one key non-decreasing:
  each entry gets the later of its clock reading and the last date it gave
  in that collection. Dates stay display, indexing and retention: a reader
  refuses nothing for the order of dates across versions (§4).
- **Entry names.** Entry `i` (0-based) of block `V` is named
  `<V>/32=entry/seg=<i>`. Like a state name it is local and never fetched:
  `get` of it uses or fetches the block `V`, verifies it as any log entry
  (§4) and answers that one entry (§15). An entry exists only inside the
  signed packet, so no entry travels apart from the signature that covers
  it: an entry altered, or spliced in from another block, breaks the block's
  signature, and the block is refused — dropped and fetched elsewhere, as
  from a poisoned cache (§17). So each entry is verifiable on its own,
  through its block's signature.
- **Batching.** `put` with `batch = d` (§15) puts the entry into the
  device's open block for the collection, the entry's type and the
  collection's seal epoch, and returns once the block carrying it is signed,
  with that block's id. A block closes — is signed, applied and published
  (§12) — at the earliest `arrival + d` of its entries; before an entry that
  would make its `Block` encoding exceed `INLINE_MAX`; and before an entry
  whose type, keep kind or seal epoch differs; and when the record naming
  the seal epoch moves before the block is signed — every `put` waiting on
  a block that cannot then be signed answers that error. So no entry waits
  longer than the delay its producer accepted, and every block is one
  packet. A `put` without `batch`, and an entry whose own payload exceeds
  `INLINE_MAX`, first close the open block; the entry is then put alone,
  the large one in pieces (§13.1), so seqs follow the order of `put`s.
- **Keep of a block.** Entries kept `Until` a date make a block kept until
  the latest of their dates: no entry is dropped before its own keep, and
  none is kept more than the batch delay past it. Entries kept `Forever`,
  or for the last `n`, share a block only with entries of the same keep.
- `batch` on a merge collection answers `BadRequest` (next step
  `FixRequest`: a merge collection carries one operation per version; put
  without batch).
- `batch` is at most a day (`BATCH_MAX`): an entry waits unsigned no
  longer, and a one-key head states the delay as the `Freshness` every
  reader adds to an answer's age (§5.3). A longer one answers `BadRequest`
  (next step `FixRequest`: put with a batch of at most a day, or without
  batch), before anything is written.
- A single-entry version reads, wherever entries are listed (§5.4), as one
  entry: index 0, dated its `Dated`.


## §4.2 Durability before publication (the lines that changed)

  - serve a summary root, node or page, or a one-key head, listing
    anything above it: what it serves of its summary and heads is what the
    log up to its durable head fixes (§5.3, §7);

  published. A one-key head states the batch delay of the newest version it
  lists, stored with that version, so one head name is one packet across a
  restart (§5.3); a summary's content is fixed by the log up to its head

prefix that a device makes while a batch is open (dropping an expired
version scans the store for its pieces) MUST answer as the store would

## §5 Collection and rule and §5.2 Applying versions (the lines that changed)

## 5. Collection and rule — slices 1, 2, 4 (one key), 6 (rules by name)

| one key | One key writes; the newest is what its signed head names, with a freshness bound (§5.3). `get` returns that version; range reads read the stream by seq or by time (§5.4). |

**signed date** (`Dated`, §4.1: its writer's clock when it signed). The past

only, §4.1): a rule MAY order by it only where its order is bounded by the

   what it carries (`Unsealed`, §9; an operation the rule refuses), or it
   is expired here (§14.1), or — in a log or one-key
   collection, and not held here — shown by the newest node of `w` for `C`
   the reader verified to have expired (§7): at or below that node's `Head`
   and not listed by it, or listed in an `Expiry` run whose date this
   device's clock has reached, and

refused work its operation depended on, the merge function decides). This
holds for seqs the reader never learned as well: a seq of `y` at or below
the `Head` of `y`'s newest node it verified that the node does not list,
and that the reader does not hold, never applies, so a reader that started
after older versions expired is not held back by a parent naming them.
When the reader's clock reaches an `Expiry` date of that node, it reads
again what waits and applies what became ready.

  reachable device has the basis: a merge collection is never expired
  (§14.1), nothing drops a version's record — an inline operation with it —

## §5.3 One key and §5.4 Range reads (cut whole)

### 5.3 One key — slice 4

A one-key collection is written by exactly one key.

- **Members.** Its members record has the rule one key (`RuleKind` 0) and
  `Writers` of exactly one name, a key name `<D>/KEY/<id>`; admission (§6)
  then admits exactly that key. `share(C, {rule: one key, writers: [w]})`
  takes `w` as it is when it is a key name, and as this device's key when
  it is this device's name; any other name, or not exactly one, answers
  `BadRequest` (next step `FixRequest`: name the one key that writes,
  `<D>/KEY/<id>`, or this device). A one-key record whose `Writers` is not
  exactly one key name (signed elsewhere) admits by prefix as usual and
  has no head: `get(C)` answers by the log rule, and a range read answers
  `BadRequest` (`FixRequest`: the record names no single key).
- **Log-like.** Otherwise a one-key collection is a log collection whose
  one member is that key: sync, watch, summaries, pieces,
  seals, blocks and expiry apply to it as to a log collection. Its newest
  is the version of that key's highest seq in `C`.
- **Head.** The writer's head of `C` is the Data packet
  `<D>/32=summary/<C>/32=head/seq=<s>`, `D` the one key's device, signed by
  that key, Content `HeadRecord` (§16.2): `Name` `C`; `Seq` `s`, the `Head`
  of the writer's summary node of `C`; `Digest`, SHA-256 of that node's
  whole packet `<D>/32=summary/<C>/seq=<s>`; and `Freshness`, in
  milliseconds: the batch delay of the entries of the writer's newest
  version in `C`, 0 when it was put without one — the writer holds an
  entry unsigned that long anyway. The packet's FreshnessPeriod is
  `Freshness`. A reader discovers it with `<D>/32=summary/<C>/32=head`
  (CanBePrefix, MustBeFresh), which no node, page, root or other head
  extends. A writer SHOULD sign a head only when one is asked for and its
  node of `C` changed since its last head (as for the root, §7), keeps its
  last head with what it holds, so a restart serves the same packet, and
  MUST serve the node every head it signed names, as it serves the nodes
  its roots list (§7).
- **Reader checks.** A reader MUST verify a head as a log entry (§4) signed
  by the one key of the record in force — a head signed by any other key is
  refused, whatever device it names — whose subject is `C` and whose name's
  seq is its `Seq`. It MUST refuse a head whose `Seq` is lower than one of
  the same key it verified for `C`, or than the highest seq of that key it
  knows in `C` — held, listed by a node of that key it verified, or kept by
  a tombstone (§14.1) — (rollback, invariant 3); a head of the same `Seq`
  is taken again, and renews its receipt once its node checks out. The
  floor is the key's: each key's device numbers its own log, so once the
  owner names another one key
  (a replaced sensor), that key's heads are not compared with the previous
  key's seqs, and a range read without a head uses only what a head of the
  current key listed. The highest `Seq` verified per collection and key is
  durable, kept with what the reader holds, so a restarted reader refuses
  the same rollback. It then fetches the node by name and refuses it unless
  its digest is the head's `Digest`; the node is checked as §7 says.
- **`get(C)`.** A reader answers `get(C)` from the head: head, node, the
  version of the highest seq the node's `Entries` list, and that version —
  from its store, else by name, else from the devices that serve it
  (`32=held`, §13.5). It answers `Got::Version` with
  `Age::Newest { unconfirmed_for }`, `unconfirmed_for` being the time on
  the reader's monotonic clock since it received that head, plus the head's
  `Freshness`. A head's receipt counts only once the node it names checked
  out; a head whose node is withheld or does not match proves only that the
  key's log reached its seq. When the newest version the node lists, or the
  head, or its node, is not to be had, the reader answers the newest version
  of the one key it holds (by seq), aged by how long ago that version was
  last known the newest: `unconfirmed_for` measured from the receipt of the
  last head, received since it started, that named that very version the
  newest and delivered it, plus that head's `Freshness`. It never gives an
  older version the receipt of a head that names a newer one. When no head
  since it started named that version the newest, but a head of the key it
  verified since it started has a higher seq — a newer version may exist,
  and nothing bounds how long ago the held one was the newest — it answers
  `Unavailable` (next step `RetryLater`) rather than an age it cannot bound
  (§14.2: older verified data is answered only with its own age). A receipt
  time does not survive a restart — a monotonic clock does not — so a
  reader that verified no head of `C` above the version it holds since it
  started answers with the age of a log collection (§15). Stale, never
  wrong (invariant 5).

**The freshness bound.** No clock is trusted and none is compared across
devices: the bound is a duration measured on the reader's monotonic clock
plus the duration the writer stated. What it promises, and no more:

- A head the reader received fresh was the writer's newest head — the node
  it names the writer's newest node of `C`, its newest version the
  collection's newest — at a moment no longer than `Freshness` before
  receipt, *if* the one cache that answered honoured FreshnessPeriod. The
  writer's own answer adds nothing; each further caching hop that honoured
  it may add up to `Freshness` more. So `unconfirmed_for` bounds how long
  ago the answer was last known to be the newest, under that proviso.
- It never promises that nothing newer exists now: a partition, a cache
  withholding newer heads and a writer that wrote nothing look alike to a
  reader. Nor does it cover entries the writer holds unsigned in an open
  block, which are at most the delay it accepted old (§4.1).
- A cache or replayer that ignores FreshnessPeriod can serve as fresh any
  old head it saw. The age then understates; the answer is still never
  wrong: the head is never forged (it is signed by the one key) and never
  older than one the reader verified (rollback is refused, also after a
  restart). A reader that must know the writer is alive needs an answer
  from the writer itself, which no name of this layer can force through a
  cache that lies about freshness.

### 5.4 Range reads — slice 4

- **Names.** `get(<C>/32=range/<R>)`, `R` one GenericNameComponent whose
  value is one TLV: `SeqRange` (low, high, inclusive) reads the versions of
  the one key in `C` with those seqs, so by name; `TimeRange` (from, to,
  `from < to`) reads the entries dated `from ≤ date < to` (§4.1). A range
  name is local and never fetched. Range reads read one key's stream: of a
  collection of another rule `get` answers `BadRequest` (next step
  `FixRequest`); a range name that is malformed answers `BadName`
  (`FixName`).
- **Mapping to Interests.** There is no index and no new packet: the reader
  reads the stream through the names it already has — the head (§5.3), the
  node it names, and the versions, `<D>/32=log/<C>/seq=<n>`. The node's
  `Entries` list every version of the stream still listed (§7), the
  seq → name mapping. By seq, the reader fetches exactly the listed seqs in
  the range. By time, it uses that each block states its own first and last
  entry dates (its `Dated`, and `Dated` plus its last `Offset`): it searches
  the listed seqs for the first version whose last date is at least `from`
  and the last whose first date is below `to` — probing the first and the
  last listed first, then, each round, interpolating on the dates of the
  versions probed so far and bisecting in turn — fetching each probed
  version, each immutable and cacheable anywhere, from its store first.
  Each round probes the seq it guessed. A probe not answered — every ask
  of it missed, lost on the way or refused as not verifying (§17.1) — is
  asked again in place, after the pause of §17.1, up to `SEARCH_TRIES`
  probes of the seq, before the round looks anywhere else: loss costs a
  search time, never other versions. Only a guess none of those probes
  reached widens the round: it probes at once the nearest two others of
  the interval not yet probed (`SEARCH_WIDEN`), each asked again in place
  alike, then twice as many each time none of them answers, up to the
  reader's fetch window, and goes on from the nearest that answers; when a
  window of them answers none, the rest of the interval is not probed: it
  is taken into the range and its versions are reported `missing`. When
  the search's bound ended the round instead, that is no evidence that
  they are withheld: a window of versions or fewer left in the interval are
  not judged by the search and are fetched with the versions between, in
  the fetch's own bound; more than a window are reported `missing`. A
  search's cost is counted in distinct versions probed, not Interests:
  asking a version again adds Interests and time, never a version. A
  version it knows expired is placed by the dates its tombstone keeps
  (§14.1); a version in pieces, by its `Dated`. It then fetches the
  versions between, a window at once, each one not answered asked again
  in place after the pause of §17.1 until the bound below, and keeps the
  entries in range. A range read probes its versions within a bound the
  reader sets,
  counted from when it holds the node listing them — the records and the
  head have bounds of their own (§15, §17.1), so a slow path to them does
  not eat the probes' time. In this implementation the bound is eight
  looks (`RANGE_LOOKS`), each the first-look time or four of the device's
  retransmission timeouts (`RANGE_RTOS` · `RTO`, §17.1, once a round trip
  was measured; the first-look time alone before), whichever is
  longer: a search probes one version a round, so the bound covers as many
  rounds on a path whose round trips near the lifetime as on a fast one.
  As `RTO` never exceeds the lifetime, the bound is at most
  `RANGE_LOOKS` · max(first look, `RANGE_RTOS` · lifetime) — 64 s with the
  defaults — however slow or hostile the path. The search and the fetch of
  the versions between each have the bound, the second counted from when
  the search is done: a search whose probes were lost spends its own
  bound, and the versions in range, none of which it asked for, are not
  answered `missing` for that (a path that loses a probe costs it a
  lifetime per ask, however short `RTO` measured the round trips that
  answered). Versions a bound has not reached
  are reported `missing`, so withheld or unreachable blocks cost it time,
  never more than the bound of each phase. The cost is the head, the node, `O(log n)`
  probes (two or three for a steady stream, where interpolation lands near
  the answer) when probes answer — a lost probe is asked again at no cost
  in versions; a guess no ask reaches adds probes in steps of two, four, …
  up to a window, each step run at once — and the versions in the range.
- **Why not a prefix or an index.** Selecting by a prefix of dated names
  would need range selectors NDN no longer has, and would put the writer's
  clock into names readers must guess. A range index as named data would be
  either signed by the producer — more signatures and state on the
  constrained device, and a second structure to keep consistent with the
  log — or built by a holder, which is untrusted: it could only omit or
  misdirect, and every block must be verified anyway. The node already
  lists every version; the blocks' own signed dates are the index.
- **Answer.** `Got::Entries(Entries)`: the collection, the writer (the one
  key), and
  - `entries`, in (seq, index) order, each with its entry name
    `<V>/32=entry/seg=<i>`, its version's id, its index, its date and its
    content, every one from a version verified as a log entry of the one
    key (§4); a single-entry version is one entry (§4.1);
  - `missing`: versions listed within the bounds that no path answered;
  - `expired`: versions within the bounds this device knows expired
    (§14.1);
  - `large`: versions in pieces within the bounds, read whole by name
    (§13.1).

  The age is that of `get(C)` (§5.3). The answer is complete exactly when
  `missing` is empty, and complete relative to the head's node (invariant
  4): what the writer signed after that node, it does not cover.
- **Honest and date-disordered writers.** For a writer whose dates do not
  decrease (§4.1), a time range returns exactly the entries dated in it of
  the versions the node lists. A writer whose dates go back is held to its
  own order: the search may miss entries it dated out of order, and never
  returns an entry the writer did not sign or one dated outside the range.
  No date decides validity.


## §6.1 Folder records and §6.3 Adopting a namespace (the lines that changed)

  folders above, another meaning), leaves a sealed folder no reader (it
  would unseal it), or changes the one writer of a one-key record. With no

  log entries of `S` and of every collection under it, with their pieces
  and block entries; one-key heads of those collections; the signal run

  subject no record lists it for, not a head, a summary or a snapshot

## §7 Summary (the lines that changed; "Listing by keep" and "Keep bounds" cut whole)

## 7. Summary — slice 1 (listing by keep: slice 4)

- `Entries`: the seqs of the writer's versions directly in `X`, as ranges —
  the seq → name mapping, since an entry's name is `<D>/32=log/<X>/seq=<n>`;
  of a log or one-key collection, only those unexpired at the node's
  reference date (listing by keep, below); of a merge collection, all;
- `Expiry` (slice 4): of a log or one-key collection, bounds of the keeps of
  the listed versions kept `Until` a date, in at most 64 runs, each a list
  of seq ranges and a date no earlier than the keep of any version in it
  (listing by keep, below);

SHOULD sign a new root only when one is asked for and the tree changed. A
one-key collection's node is also named by the collection's signed head
(§5.3), one hop from the reader.

**Listing by keep (slice 4).** A writer's node of a log or one-key
collection `X` lists in `Entries` only its versions unexpired (§14.1) at
the node's **reference date** `E`: the `Dated` of the writer's newest
version in `X` up to the node's head. A version kept `Until(t)` is listed
when `t > E`; one kept for the last `n` while fewer than `n` of the writer's
later versions in `X` lie at or below the head; one kept `Forever`, always.
`E` and those counts are fixed by the log up to the head, so one node name
still has one packet, and a constant stream's node stays bounded by its
keep window: 30 days at one block a minute is 43,200 seqs, within the
65,536 a node may list. The writer's own clock moves only its own listing:
it decides the dates, hence `E`, and nothing else of any reader.

**Keep bounds (slice 4).** A writer that stops writing leaves `E` where it
was, so its newest node keeps listing versions kept `Until` a date that has
since passed by every holder's clock: the holders dropped them, and a reader
that never held them could fetch them from no one and could not tell from
the node that they expired. So the node also states, in `Expiry`, a bound
of each such version's keep. The writer takes the listed versions kept
`Until` a date in seq order; while the groups of consecutive ones with one
keep number at most 64, each group is a run stating that keep, exact;
beyond, they split in seq order into 64 runs of equal count (the last may
hold fewer), each stating the latest keep in it. A version kept `Forever`
or for the last `n` is in no run: the last-`n` listing already matches what
holders keep, since a stopped writer writes no newer versions to end them.
The runs are fixed by the log up to the head (the writer's tombstones keep
each dropped version's keep, §14.1), so one node name still has one packet.

A reader keeps, per collection and writer, the newest node it verified —
its `Head`, `Entries` and `Expiry` — and does not wait (§5.2) for a seq of
that writer at or below the `Head` that it does not hold and that either
the node does not list (whether or not the reader ever learned the seq) or
the node lists in a run whose date its own clock has reached. It does not
fetch such versions. It reads again what waits when its clock reaches the
earliest such date still ahead, with the expiry sweep of §14.1, and applies
what became ready. A run's date is an upper bound: the reader stops waiting
at most one run's span (its latest keep minus its earliest) after a
version's own keep, and never before it, so nothing it applied or skipped
depends on a date it was not given.


A writer MUST serve every node and page that any root or head it signed
lists, for as long as it holds the log entries that node lists — in slice 1
a writer never drops its own entries, so always, across its own restarts
too (expiry, slice 4, drops entries, not nodes: the
writer's tombstones keep each node's content, §14.1). Keeping them

for a summary name that none of its roots or heads listed with a Nack.

- MUST refuse a node (or page) with more than 64 `Expiry` runs, a run with
  no seqs or not exactly one date, runs whose seqs are not ascending and
  disjoint across all of them, or a run naming a seq the node does not
  list in `Entries`: a bound covers only what the node lists;

- fetches the entries the visited nodes list that it does not hold, except
  those its newest node of their writer shows expired (keep bounds, above).

## §8.1 Revocation cut and §8.5 Time (the lines that changed)

  in `C` it keeps — versions, blocks and members records — and one with

  date or seq, and every other packet `K` signed — summary roots, one-key
  heads, seal keys, grants, an asker's proofs — since no cut

- **The cut is the listing.** `K`'s summary roots and heads are refused

- In this layer: a version's date (display, time ranges, §5.4), expiry
  (each device's own retention, §14.1, and the summary's keep bounds,
  §7), the one-key head's freshness and the age `get` reports (§5.3) and the
  batch delay (§4.1). None decides
  whether a version is valid; a wrong clock moves only its own device's
  retention, listing and waiting. The root's clock bounds the cuts it makes

- *The signer's* moves only the dates it writes: where a version sorts in
  a time range (§5.4) and, for keep dates, its retention (§14.1). It

- *The reader's* moves only its own retention, waiting and reported ages
  (§5.3, §14.1), its live exchanges (a context whose anchor it thinks

## §13.1 Large payloads and §13.5 What a device serves (the lines that changed)

ones). A block is never in pieces (§4.1), and a reader refuses a block in
a merge collection (`NotInline`).

  whole on `get` of its name (or of a log or one-key collection's newest):

**What it never serves.** What expired by its own clock (§14.1): retention
is the writer's, and a device answering for expired bytes would undo it.
Nothing refused or withdrawn here: by the record in force (`NotMember`,

  collections; expiry bounds how long anything is served.

- *Expiry.* Expiry is checked as a packet is asked for, by the device's
  clock (§14.1).

## §14 Expiry (cut whole: §14, §14.1 and §14.2)

## 14. Expiry — slice 4

### 14.1 Retention by expiry — slice 4

Keep is chosen at write (invariant 7) and, from slice 4, enforced: every
device drops what has expired, by its own clock. Expiry is local
housekeeping; it never decides whether anything verifies.

- **Scope.** Log and one-key collections. A merge collection's state needs
  every operation: it is edited instead,
  and its versions' keep is not enforced by expiry.
- **When.** A version **expires at a device** when it is kept `Until(t)`
  and `t` is at or before the device's own clock, or kept for the last `n`
  and the device knows `n` newer versions of the same writer in `C` — held,
  or listed by a summary node of that writer it verified. A version kept
  `Forever` never expires. Keep was set at write; nothing extends it.
- **What every device does.** Every device — writer or reader —
  MUST drop an expired version, record and pieces; MUST serve none of it,
  by its own name or under `32=held`; MUST NOT store one
  it fetches after it expired; keeps a durable tombstone (the version's
  id, writer and keep, and its first and last entry dates, so the writer's
  nodes stay rebuildable and a range read places it — of a sealed block
  dropped before it was opened, the last date is unknown and kept as such,
  and a range read takes the block as reaching any date from its first on,
  so lists it under `expired` wherever it may overlap); reports it to its
  watchers as `Change::Expired` (the version and its keep); and answers
  `get` of its name, or of an entry name in it,
  `Expired` (the name and the keep; next step `None`: nothing to do, and
  asking again does not help). A range read lists it under `expired`
  (§5.4). A device checks expiry on every access and sweeps at the earliest
  keep it holds, or keep bound its writers' newest nodes state (§7),
  reading its clock again when it wakes; a version that waited for its
  collection's members record counts from the moment the record admits it
  — the sweep reads every collection's earliest keep again whenever a
  members record is taken — so a device that took versions before their
  record (over a lossy path) drops them on time, unasked. A restart drops
  what the store
  still keeps that has expired. Later versions do not wait for an expired
  one (§5.2), and the writer's node stops listing it once the node's
  reference date passes its keep (§7).
- **A stopped writer.** When a writer stops writing into `X`, its newest
  node's reference date stops moving, so that node keeps listing versions
  whose keep has since passed by the holders' clocks; every honest holder
  dropped them, and a reader that never held them cannot fetch them. The
  node states a bound of each listed `Until` keep (`Expiry`, §7), so the
  reader sees by its own clock that they expired: it does not fetch them,
  and a watch of `X` stops waiting on them (§5.2) and applies what the
  writer wrote after them, without the writer writing again. Precision: a
  run's date is the latest keep in it, so the reader stops waiting at most
  one run's span after a version's own keep (none while the node's groups
  of one keep fit its 64 runs), never before it. When the writer does write
  again, a seq its new node no longer lists is not waited for either, even
  one the reader never learned. Versions kept for the last `n` need no
  bound: a stopped writer writes nothing newer that would end them, so
  holders keep them. Nothing wrong is delivered: the reader skips only
  what its own clock, against the bound in the writer's node (verified
  through its signed root or head), says expired.
- **Clocks.** A slow — or lying — clock makes a device hold and serve
  longer; readers with right clocks still answer `Expired` and store
  nothing past keep. A fast clock makes a device drop early its own copy
  only, and nothing of any other device
  changes. A writer's clock moves only its own dates and its own listing
  (§7). A reader's clock moves only what it waits for: a slow one waits
  longer on a stopped writer's expired versions, a fast one stops waiting
  earlier for versions it would itself drop as expired anyway.
- **Forward-only.** Expiry deletes at the devices that keep this
  specification; it recalls no copy (invariant 9). A cache, a device whose
  clock is slow, or a reader that copied the data out of the layer keeps
  what it has.

### 14.2 What a producer, holder or reader can and cannot do — slice 4

With blocks, heads and expiry:

- **A producer** — the one key, or a writer of a log collection:
  - can lie about its dates. That moves only its own order and indexing —
    where its entries fall in time ranges (§5.4) and its own listing by keep
    (§7) — never validity: a reader refuses nothing for a date;
  - can equivocate: two different blocks at one `(writer, seq)` are, like
    any two versions, evidence against its key, kept and reported
    (invariant 2), entries and all;
  - can set any keep, from a moment to forever, and change it only for
    later writes; nothing it signs later extends what it wrote;
  - can delay its entries up to the batch delay it states, and go silent:
    readers' age grows, and the bound promises no more (§5.3); a stream it
    stops keeps its last node listing what has since expired, with the keep
    bounds that let a watch stop waiting on it (§7, §14.1);
  - can state keep bounds other than its versions' keeps: too early, and
    readers that never held those versions skip them sooner; too late, and
    they wait longer. That moves only what readers wait for of its own
    stream, as choosing the keep itself does; nothing is delivered wrong;
  - cannot make an entry outside a block's signature, nor a head of a key
    the members record does not name.
- **A holder**, cache or relay:
  - can withhold blocks, nodes and heads: a range read lists what it lacks
    under `missing`; `get` answers older verified data with its own age —
    how long ago that version was last known the newest, never the age of
    a newer head whose node or version was withheld — or `Unavailable` when
    a newer head was verified and the held version was never confirmed the
    newest since the reader started (§5.3); and the reader fetches
    elsewhere;
  - can replay old heads it saw, as fresh: they are never forged and never
    older than one the reader verified (rollback, durable); the age then
    understates (§5.3);
  - can serve past keep: readers drop by their own clocks and store
    nothing expired (§14.1);
  - cannot forge an entry or splice one from another block: the block's
    signature covers every entry (§4.1). It cannot alter which versions a
    range read considers: the reader takes them from the node the signed
    head names by digest, so a holder can only omit them.
- **A reader** can cache and replay heads to others, as a cache can, and
  keep copies past keep: nothing recalls copies already made (invariant 9).
  It sees, of a sealed block, what §9 lists of any version — its date, keep
  and size, not its entries, their number or their offsets — and of a head
  its seq, digest and freshness, so the writer's batch delay.


## §15 Verbs (the lines that changed)

## 15. Verbs — slices 1–4, 6, host surface slice 7

| `get` | `get(name) → version, state or entries + age` | 1 (entries, ranges: 4) |
| `put` | `put(collection, content, {type, keep, batch}) → (writer, seq)` | 1 (`batch`: 4) |

| `share` | `share(collection, {rule, readers, writers})` | 1 (adding), 2 (removing, the rule), 4 (one key) |

  confirm nothing. Of a
  one-key collection it answers the newest version the writer's head names,
  aged by the head's receipt and freshness (§5.3); the head and the node it
  names are asked in place as a walk's packets are (§17.1). The

  version sealed to an audience the device is not in, `Sealed`; an expired
  one, `Expired` (§14.1).

  as its rule's check and apply received them, or nothing under the log
  and one-key rules. A merge version's `op` is absent too while its

- **`get(entry name)`** answers `Entries` with that one entry of its block
  (`Age::Exact`), fetching the block when not held, as `get` of the block's
  name would (§4.1); an index past the block's last entry, `NotFound`.
- **`get(range name)`** of a one-key collection answers `Entries` (§5.4),
  aged as `get(C)`; of another rule, `BadRequest` (next step `FixRequest`).
- **`put(C, content, {type, keep, batch})`** signs the next entry of the

  With `batch = d` in a log or one-key collection it puts the entry into
  the open block and returns once that block is signed, at most `d` later,
  with the block's id (§4.1); in a merge collection, or with `d` longer
  than a day, `BadRequest` (next step `FixRequest`: put without batch, or
  with a batch of at most a day).

  under a rule the device does not know, `RuleUnknown`; with `batch`, as
  `put` in a merge collection. It answers as `put` does otherwise.

- **A put never waits on other devices** (round 4). `put`, `put_op`
  and the batch forms return once the version is applied

  every equivocation (§4), and every version withdrawn (§8) or expired
  (§14.1); from slice 6 also every version held but not

  expiry, not-counted or counted report its version's collection; a

  merge collection or the exact name of a version, snapshot or entry, and
  signs the `SnapshotRecord`; a range name, which names no fixed set,
  answers `BadRequest` (next step `FixRequest`).

## §15 `share` and §17.1 Asking again under loss (further lines that changed)

  collection's own namespace (§6), whoever owns the group. With the rule
  one key, `writers` names exactly the one key, or this device (§5.3): else
  `BadRequest` (next step `FixRequest`).

- **A group heard from no one (normative).** A first look (§15, a peek
  of §5.3 among them) that finds no device heard that writes into the

## §16 Wire format (the heading that changed)

## 16. Wire format — slices 1–4, 6 (slice 5 adds none)

## §16.1 Names (the rows and bullets that changed)

| version, members record (a folder's too, `<D>/32=log/<F>/seq=<n>`, §6.1) | `<D>/32=log/<C>/seq=<n>` (a block too, §4.1) | device key |
| snapshot | `<D>/32=log/seq=<n>` | device key |
| summary root of `O` | `<D>/32=summary/<O>/32=root/seq=<head>`, FreshnessPeriod 0; discovered by `<D>/32=summary/<O>/32=root` (CanBePrefix, MustBeFresh), which no node, page or head name extends, so only a root answers it | device key |
| head of one-key collection `C` | `<D>/32=summary/<C>/32=head/seq=<s>`, Content `HeadRecord`, FreshnessPeriod = its `Freshness`; discovered by `<D>/32=summary/<C>/32=head` (CanBePrefix, MustBeFresh), which no node, page, root or other head extends (§5.3) | the one key |

| entry `i` of block `V` (never fetched) | `<V>/32=entry/seg=<i>` | — (the block's) |
| range of `C` (never fetched) | `<C>/32=range/<SeqRange or TimeRange TLV>` | — |

- **Summary.** `D` is the components before the first `32=summary`; a last
  `seq=` component is the head; a `32=page` then the next-to-last
  component is the page, and a `32=head` just before the last `seq=` makes
  the name a one-key collection's head packet (§5.3). What remains is the
  subject: a namespace (the root) or a folder or collection name (a head's
  subject is a collection). A root's subject is followed by `32=root`, and
  only the discovery names `<D>/32=summary/<O>/32=root` and
  `<D>/32=summary/<C>/32=head` lack the head — a namespace never ends in
  `seq=` — so a node or page name always carries it, and the subject's own
  last component is never read as the head. A subject without a marker is a
  namespace, never a node under one.

- **Entry.** The last component is `seg=<i>` (a SegmentNameComponent), the
  next-to-last `32=entry`, and what precedes them is a log entry name with a
  collection: the block.

- **Range.** `32=range` is the next-to-last component and the collection
  name precedes it; the last is one GenericNameComponent whose value is one
  `SeqRange` (low ≤ high) or one `TimeRange` (from < to) TLV, nothing else.

## §16.2 TLV-TYPE numbers (the lines and rows that changed)

is kept in [history/data-layer-groups.md](history/data-layer-groups.md)). The numbers 0x0525, 0x0527, 0x0529, 0x052B, 0x052D, 0x052F, 0x0533, 0x0535, 0x0537, 0x0539, 0x053D, 0x0541, 0x0543 and 0x0551, which carried custody (the hold, lease and prune records, the hold and audit asks, the audit answer and its fields), are freed and quarantined too, not reused (the old spec is kept in [history/data-layer-custody.md](history/data-layer-custody.md)). A number is even unless the notes

| 0x0520 | VersionRecord | Name (collection), Frontier (parents, each entry with its tip's Digest), TypeId, Seal, Keep, Dated, [Rule] (merge: the rule the operation was made for, §5.1), then Fields, MergeOp — or Block (§4.1), or Chunks (§13.1; in a collection of any rule from slice 6) — or, sealed, Sealed |

| 0x052C | Keep | one of KeepUntil, KeepLastN, KeepForever |
| 0x052E | KeepUntil | NonNegativeInteger, ms since the Unix epoch |
| 0x0530 | KeepLastN | NonNegativeInteger |

| 0x054A | RuleKind | NonNegativeInteger: 0 one key, 1 log, 2 merge |

| 0x0552 | SummaryNode | Name (subject), Writer, Seq (head), [PagePath], [Entries], [MembersEntries], [Expiry*], [Children \| Pages] |

| 0x0545 | Block | BlockEntry+, in a VersionRecord in place of Fields and MergeOp (sealed: the plaintext of Sealed), its encoding at most 6,144 octets (§4.1) |
| 0x0547 | BlockEntry | Offset, Fields |
| 0x0549 | Offset | NonNegativeInteger: ms after the version's Dated; the first 0, non-decreasing along the block |
| 0x054B | HeadRecord | Name (collection), Seq (the Head of the writer's node of it), Digest (SHA-256 of that node's whole packet), Freshness (§5.3) |
| 0x054D | Freshness | NonNegativeInteger: ms, the batch delay of the writer's newest version; the head's FreshnessPeriod |
| 0x054F | TimeRange | Dated (from), Dated (to), from < to; in range names only (§5.4) |
| 0x0553 | Expiry | SeqRange+ (seqs the node lists in Entries), KeepUntil (a date at or after each one's keep); in a SummaryNode, at most 64, their seqs ascending and disjoint across all of them (§7) |

Slice 4's numbers are odd for the same reasons. A reader passing over
`Block` would read a version with no payload, and one passing over
`Offset` would date every entry at its block's date; a reader passing over
a `HeadRecord` would take a head for nothing, and one passing over
`Freshness` would take a cached head as just confirmed — an age that says
fresher than it is. A range name with an unknown `TimeRange` read as some
other range would answer the wrong entries. A reader passing
over `Expiry` would wait without end on a stopped writer's expired versions
and could not say why; refusing the node says that its format is newer
than the reader.


## §16.3 Why these encodings (the bullets and the line that changed)

- **Blocks carry their entries inline** — a deviation from the model's
  first text, "a block with a digest per entry". Per-entry packets named
  by digest in the signed block cost one Interest and about 160 octets of
  packet (name, signature info, digest) per reading, for every reader, about
  five times the bytes; inline entries cost about 35 octets per reading
  and one Interest per block (1/60 of one per reading at a block a minute),
  and leave nothing apart from the signature to splice or substitute. The
  one signature per block is what model change M6 asked for; each entry
  stays verifiable on its own through its block's signature, so the digest
  per entry is not needed for it. `Block` reuses `Fields` for each entry, so
  an entry reads like any version's payload, and `Offset` rather than a
  `Dated` per entry keeps an entry's date to an octet or two.
- **A head separate from the root.** The root has FreshnessPeriod 0 so
  that discovery always reaches the writer (§7); a battery producer cannot
  answer every reader. The head's FreshnessPeriod is the writer's batch
  delay, so caches absorb readers for as long as the writer would have held
  an entry unsigned anyway, and the head names the collection's node by
  digest — one hop, where the root reaches it through every node from `O`
  down. A `HeadRecord` rather than a second signed node keeps the node
  DigestSha256 and fixed by the log, so heads and roots name the same
  packets.
- **Range reads use the log's own names** (§5.4): the head, the node's
  `Entries` and the blocks' dates, with no index a producer would sign or a
  holder could falsify. `SeqRange` is reused for ranges by seq; `TimeRange`
  reuses `Dated`.
- **Keep bounds in runs** (§7), not a keep per listed version: a node
  stays bounded however many versions it lists — at most 64 dates, and no
  more seq ranges than seqs it lists — and needs no new number for seqs or
  dates (the runs reuse `SeqRange` and `KeepUntil`). Versions sharing a
  keep, as a stream kept to one date does, take one exact run. Past 64
  groups — a stream whose every block is kept a fixed time after its date
  — equal-count runs in seq order keep each run's span (its latest keep
  minus its earliest) to about a 64th of the listed keeps' spread: 30 days
  of keep, about 11 hours, the most later than a version's own keep that a
  reader may stop waiting for it, and only once the writer has stopped. A
  bound rather than the keep itself is enough: a reader needs only to know
  that a version expired, never before it did.

  when the referenced version expires while the operation still needs

## §17 Failure model (the table rows, cut whole)

| Holder withholds a range's blocks | A time search probes a window at once and stops a round none of whose probes answers; the read answers within its bound, listing what it did not reach `missing`. | invariant 4, §5.4 |

| Replayed head | A cache or holder serving an old head as fresh: never forged; refused when older than one of the same key verified or than what the reader knows of that key, also after a restart; otherwise the reader answers the verified version that head names, with an age that understates — stale, never wrong data. | invariant 3, §5.3 |
| Head served, node or newest version withheld | The head raises its key's rollback floor, but its receipt does not count; `get` answers the held version aged from the last head that named it the newest, or `Unavailable` (`RetryLater`) when a newer head was verified and none named it the newest since the reader started. | invariant 5, §5.3 |
| Forged or spliced entry | The block's signature fails; the block is dropped and fetched elsewhere; the entry is never returned. | invariant 1, §4.1 |
| Holder serves past keep | Readers drop by their own clocks, answer `Expired` and store nothing expired. | §14.1 |
| Writer's dates go back | Its entries dated out of order may be missed by a time range; nothing it did not sign is returned. | §5.4 |
| Battery producer, many readers | Caches answer its head for its batch delay; readers' age includes it. | §5.3 |
| Writer stops, keep passes | Its newest node keeps listing what has since expired, with a bound of each `Until` keep (`Expiry`); a reader that never held such a version does not fetch it, and once its own clock passes the bound its watch stops waiting on it and applies what the writer wrote after it, without the writer writing again — at most one run's span after the keep. A seq the writer's newer node no longer lists is not waited for even if the reader never learned it. Nothing wrong is delivered. | §5.2, §7, §14.1 |

## §17.1 Asking again under loss (the lines that changed)

  shown expired by its writer's newest node (§14.1), not cut or otherwise
- **A one-key read** (§5.3, §5.4) — the head of the one key and the node
  it names, within the `get` that reads them, never past it: each asked
  in place as a walk's packets are, a miss or a packet refused as not the
  head or not its node (one that does not verify or match, a forgery on
  the way) asked again after the pause below, up to `FETCH_TRIES` asks of
  each; a head refused as a rollback is a decision, not asked again. A
  version or entry a `get` fetches by name is asked as a walk's versions
  are, up to `FETCH_TRIES` asks of its writer's device; so is each probe
  of a block a range read makes, and a probe none of those asks answered
  (a miss, or a reply refused as not verifying) is probed again in place
  after the pause below (§5.4): a search's guess up to `SEARCH_TRIES`
  probes before its search widens, a block in the range until the range
  read's bound. A refusal kept against the name is not asked again.

cut, expired past its keep, its collection or folder no

A verb's own asks are bounded per call: a one-key read makes at most
`FETCH_TRIES` asks for the head and as many for the node it names; a verb
waiting for an epoch key waits for at most `FETCH_TRIES` rounds of its
ask, one ask per granter each; a range read probes for at most
`RANGE_LOOKS` · max(first look, `RANGE_RTOS` · `RTO`) (§5.4) in its search
and again in the fetch of the versions in range, never more
than `RANGE_LOOKS` · max(first look, `RANGE_RTOS` · lifetime) in each, each probe
an owed fetch as above, probed again in place up to `SEARCH_TRIES` times
in a search and until that bound in the range; a search probes at most a
window more versions for a guess no probe reached, never more for loss.

## §18 Conformance (the slice-4 cases, cut whole)

The slice-4 cases are c6 (a soil sensor puts a reading a second, batched
by a minute, into a one-key collection whose one writer is the sensor's
key: signatures grow with blocks, not readings, no reading waits longer
than the delay accepted, every reading reaches the repo; signatures,
Interests, bytes and energy per reading are recorded, batched and
unbatched), s1 (a range read by time and by seq returns exactly the entries
in the range, with far fewer Interests than the stream has blocks) and s5
(a replayed old head, the sensor offline, does not make `get(C)` answer a
version older than one already verified).

