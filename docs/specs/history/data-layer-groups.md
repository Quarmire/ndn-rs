> Superseded by heap.md and invite.md at ndn-rs 2b344e09. Kept for history; nothing here is normative.

# Groups of versions text cut from `data-layer.md`

Groups of versions (slice 6: versions one writer signs to be counted all or none, `put_group`, TLV `Group` 0x0557 and `GroupCount` 0x0559) were removed from the data layer. The numbers 0x0557 and 0x0559 are freed and quarantined, not reused. `Audience::Group` (a seal audience over people, devices and groups, §6) is not this family and stays in `data-layer.md`, as does the equivocation evidence of §4. What follows is the text as it stood, in the order of `data-layer.md`.

## Header: Status (before §1)

  release of merge pieces only on an audited covering checkpoint, groups
  of versions counted all or none, folder members records narrowing every
  §5.2, §5.5, §6.1, §6.2, §9, §13, §15, §16, §19); slice 5: a revoked key's versions kept

## §4 Version and log (the lines that changed)

`(writer, seq)`, parents, type, seal, keep, a date and a payload, and, when
it is one of a group of versions counted all or none, its group (§5.5).
  before it is reported; a group of the key
  over that seq is malformed (§5.5). A cut accepts a seq only in the

## §4.2 Durability before publication (the lines that changed)

- **Local application is immediate.** `put`, `put_op` and `put_group` return
atomic store, so the same holds of every put and group; on one that is not,
itself; for `put_group`, every record the group's fresh collections need
and every member with its markers, as one batch; a commit round's
Measured, not guaranteed (ext4 on NVMe, release build, medians; one put at
a time, before and after batching): redb `put` 1.74 ms and 0.71 ms,
`put_group` of 10 21.3 ms and 3.2–4.2 ms, of 100 210 ms and 14.2–14.5 ms;
fjall `put` 146 µs and 155–168 µs (59.7 and 55–60 µs back to back),
`put_group` of 100 8.9 ms and 8.5–8.9 ms, unchanged within noise, a put on a
store that costs nothing being 49 µs: on fjall the writes were never most of
a put. Batching is there for atomicity, and for engines that pay per write.
- A group is one batch: every member and every record it makes are there
  after a kill, or none is. A group of `GROUP_MAX` versions is a batch of
  that many entries with their pieces and markers, held in memory until it
  is handed over, as the signed group already is.

## §5 Collection and rule (the lines that changed)

## 5. Collection and rule — slices 1, 2, 4 (one key), 6 (rules by name, groups)
a writer's first `put` (`put_op`, `put_group`) into a collection of its own
  a state name of `C` (§11), and `put`, `put_op` and `put_group` into `C`,

## §5.1 Merge functions (lines that changed)

  withdraw another's version and its group. An apply that fails MUST leave

  back (members of a group waiting on another member, §5.5, and versions
  covered only by checkpoints the rule does not count, §5.2); the value

Merge state across restarts (§5.2):

  cuts, introductions), groups, refusals, equivocation evidence, and per
  arrives later builds it); `put`, `put_op` or `put_group` into it; `hold`
  or `release` of it; a version arriving for it; a group with a member in
  it being judged; a new members record over it; a revocation of a key

### 5.5 Groups of versions — slice 6

A **group** is a set of versions one writer signs to be counted all or
none: one transaction of one device across collections of one folder. A
reader counts a group's versions only once all of them are held and
readable, and none of them when any is refused, on every member alike and
in any arrival order.

- **Format.** A version of a group carries `Group` (§16.2): the group's
  `id`, the seq in its writer's log of the group's first version, and its
  `count`, `1 ≤ count ≤ 65,536` (`GROUP_MAX`, as many seqs as a summary
  node lists, §7; a chosen bound, not a limit of the design). The group `(w, id)` is
  exactly `w`'s versions at seqs `id` to `id + count − 1`, consecutive, one
  per collection and one per seq, all in collections of one folder — the
  same parent name, every component but the last — all declaring one
  `Seal`, and all kept `Forever` (until pruned): a member that expired
  would leave a reader that never held it unable to tell the group
  complete (§14.1).
- **A reader's memory.** While a group waits — incomplete, or for a key, an
  audience or a keep — a reader keeps each member it holds whole and
  opened in its store, not in memory (ndn-data: under
  `/localhost/ndn-data/parked/<log entry name>`), and in memory only what
  judging the group reads of it: its id, name, keep, declared seal and
  epoch. The member is listed not counted with why as before. Once the
  group is complete or refused its members are loaded and applied, or
  refused, together. A stalled group so costs a reader that index per
  member, not the members. A parked member is not applied, yet it was
  verified as it was parked, so it is kept across a restart: read back from
  its parked copy at start as any held entry, it parks again while its
  group waits, and a stalled group is never fetched again for it. Its seq
  is noted again as it is read back, so an equivocation it is part of is
  kept and reported after the restart too (§4). A
  member in pieces not held whole stays in memory while its pieces are
  fetched, so does a member held sealed that this device cannot open (no
  key of its epoch held, §9), and so does a member of a collection held
  for its owner (§13.2): a holder keeps, audits and leases exactly what it
  holds.
- **Writing.** `put_group` (§15) signs its items under one lock at
  consecutive seqs of the device's log, each carrying the group; no other
  entry of that log comes between them. It refuses, and writes nothing — no
  version signed, no seq taken, nothing published — when there are no
  items or more than `GROUP_MAX`, a collection appears twice, the
  collections are not all of one folder, the records in force of the
  collections list different readers (one was narrowed, say: a reader of
  one could then never complete the group), `batch` is set, `keep` is not
  `Forever`, or the rule of an item's collection refuses its operation:
  `BadRequest`, saying which item and why (next step `FixRequest`). When a
  collection's rule is unknown here it answers `RuleUnknown` (§5.1), and
  when a collection is not writable by this device, that collection's own
  error, unchanged; again nothing is written.
- **Verdict.** A reader judges each group `(w, id)` from what every reader
  of the group's folder holds alike: the group's own signed versions and
  their admission, the entries and listings `w` signed in the folder's
  collections, and the audiences of the epochs its members are sealed in:
  - **Malformed** — refused for good: a member's seq outside `id` to
    `id + count − 1`, members disagreeing on `count`, members in
    collections of different parents, two members in one collection,
    members whose declared `Seal`s differ as sets, sealed and unsealed
    members together, or two entries of `w` at one seq of the group in
    collections of its folder (equivocation, §4). An entry of `w` at a seq
    counts here when it is held kept `Forever`, or known (held, or listed
    by a node of `w` the reader verified, ever) and covered by `w`'s prune
    record, or known in a merge collection (whose nodes list every entry):
    what every reader following the folder learns from `w`'s signed nodes
    and fetches. Evidence once taken is kept: a node that later stops
    listing an entry — its writer's store lost it, say — takes nothing
    back. An entry outside the folder, or kept for its last `n` or until a
    date — which leaves `w`'s listing, so a reader starting later never
    learns of it — is not evidence against the group; cuts accept a seq
    only in its collection (§6.1, §8), so such an entry gains its writer
    nothing. An absent listing is never evidence: what an honest writer's
    node stops listing may be listed, and fetched, again (§7).
  - **Refused** — a member is refused for good: by the record in force of
    its collection (`NotMember`, `OutsideCut`, §6, §8), by a revocation cut
    or an untrusted chain (§8.1, §8.3), `Unsealed` (§9), by its rule's
    check (§5.2; an apply that fails only leaves its member not counted),
    or because the group is malformed. Then no member ever
    applies: each is a version refused for what it carries (§5.2), so later
    versions do not wait for it, and each is reported not counted
    (`Change::NotCounted`, the group refused). A member applied before is
    withdrawn, in every collection of the group: watchers are told
    `Withdrawn` with the reason `Refusal::Group` — the refused member and
    why — and `get` of each other member answers `Refused` with that
    reason, while `get` of the member refused for its own sake answers its
    own refusal (`OutsideCut`, `NotMember`, …). Versions by
    other writers made over a withdrawn member stay counted: a parent that
    never applies holds nothing back (§5.2).
  - **Not covered** — the members' epochs do not all admit the same
    readers: some epoch's audience, as the records held here name it
    (every reader a record naming the epoch lists, and the device that
    started it, §9), does not admit a reader listed by another member's
    epoch (epoch creators aside). A reader could then open some members
    and never others. No member counts, at any reader: each is reported
    not counted ("group waits: … sealed in the epoch …, whose readers do
    not include …; it counts once the owner adds them to that epoch"), and
    versions that depend on a member wait. A record that only adds
    readers keeps its epoch (§6), so audiences only grow: the group
    counts, at every reader alike, once records admitting them are held
    and the keys granted. The requirement comes from the epochs used,
    never from the seal the writer declares.
  - **Never counted** — a member is kept otherwise than `Forever`: no
    member counts and none is refused, at any reader; each is reported not
    counted, as an exclusion that waiting does not end ("group never
    counts: … kept …"; `NotCounted::Excluded`, not `Waits`: no later
    version brings a `Counted`, only the writer putting the items again as
    a group kept `Forever`), and versions that depend on a member — its
    writer's later versions in those collections among them — wait. A
    reader that never learns of that member (it left its writer's listing)
    finds the group incomplete and waits alike, so no reader applies what
    follows it and no honest writer builds on it: only the misbehaving
    writer's own later versions are held back.
  - **Unreadable here** — a member is held sealed and this device cannot
    open it: no member is shown — none delivered as a version, none in a
    value — each is reported not counted ("group not readable here"), and
    versions that depend on a member wait (stale).
  - **Incomplete** — fewer than `count` members are present: held,
    admitted and whole (one in pieces: every piece held, below), or known
    pruned (below). Each
    held member waits, reported not counted ("group incomplete: k of n"),
    and versions that depend on one wait.
  - **Complete** — all `count` members are present, and each held one is
    ready (§5.2), a dependency on another member of the group counting as
    met: all held members are applied together, across their collections,
    in seq order.
- **Pruned members.** A member this reader knows pruned (§14) — held
  before or not — counts as present for its group's verdict: prune is its
  writer's own retention, never a refusal, and every reader knows it alike
  from the signed prune record and the writer's summary, which keeps
  listing what it pruned. The group counts once every other member is
  present, and nothing counted is uncounted by a prune. Expiry has no such
  evidence for a reader that never held the member — the writer's node
  stops listing it — which is why a group with a member that may expire
  never counts.
- **Members in pieces.** A member whose payload travels in pieces (§13.1)
  is present once its record is admitted and every piece is held here —
  whether or not it is opened yet. It is opened (and, sealed, unsealed) as
  it applies, which only the group's verdict lets it do: a reader that
  required it opened before counting it present would wait for its group
  while the group waits for it, and the group would never count (ndf's
  report: a 37,847-octet operation in a group of three). A member whose
  pieces turn out not to open is refused (`BadSignature`, its writer
  signed what does not decode), and its group with it. The same holds for
  the writer's own device: what it applied in pieces is let go from memory
  (§13.1), so when it reads a collection again — a new members record, a
  re-admission, a revocation — its own members are pending and unopened,
  present by their pieces held, and its group counts again whole.
- A device holding a member of an incomplete group follows the member's
  folder (its parent name, §12), so that the others arrive.
- **A group counts only while every member counts.** While a member
  applied here is not counted — its rule's answer, or an apply that failed
  — every other applied member is not counted either: applied (later
  versions do not wait for it), held, shown, left out of its collection's
  value and newest, and reported not counted with the reason "group
  waiting on `<member>`: `<that member's reason>`", naming the first such
  member by seq. A member its rule does not count keeps its own reason.
  When every member counts, every member is reported counted. The rule
  computes counting over the whole applied set, waiting groups included,
  and the layer's holding back never feeds back into it, so the judgement
  is one pass and the same at every reader in any order. Refusal for good
  still withdraws the group (above).
- Groups work in merge, log and one-key collections alike: counted means
  applied, delivered, and a candidate for the newest.

## §6.2 Threat notes (paragraphs cut, and the lines that changed)

**A rule refusing or withholding** (the lines that changed):

other writers made, never refuses a version nor withdraws its group (it is
not counted, with the reason), so no writer can arrange a state that gets
another writer's group withdrawn. A version it refuses is kept against its

**Group griefing.** Only a group's own writer can make it incomplete, and
only its own versions: a member never sent keeps the others held and shown
as not counted, and what depends on them waits — stale, never wrong.
Another writer's version can depend on a member only if that writer held
the group complete, so the member then exists to be fetched from it. A
malformed group is refused by every reader alike, from its own signed
versions, and a group none of whose members are refused is counted whole
or not at all, never in part.

The paragraph "Seq reuse across collections" went on after "so a removed writer cannot inject an entry" with:

at a seq its cut kept elsewhere; and a group whose writer signed two
entries at one of its seqs, in collections of its folder, is malformed
(§5.5). The verdict reads only what every reader of the folder holds
alike — the writer's entries kept `Forever` and its signed listings there,
pruned entries included — never an entry outside the folder, which only
some readers fetch, nor one kept to expire, which a reader starting later
never learns of. A reader that has fetched one of two entries counts the
group until it holds the other, which the writer's node under the folder
lists, as a reader that has not yet heard of a removal cut keeps a version
until the cut arrives. Readers report any equivocation they hold
(`Change::Equivocation`), inside the folder or not.

**Narrowing races and seals declared falsely.** An owner narrowing one
collection's readers while a writer signs a group across it does not split
the verdict: a reader judges a group by the epochs its members are sealed
in and their audiences, never by the record in force it happens to hold,
so every reader with the same access judges it alike. A reader the
narrowing leaves out finds the group unreadable here, and counts none of
it. A writer that seals one member in an epoch leaving out a reader
another member's epoch admits — whatever seal it declares, larger,
smaller or none, and whether or not it leaves a member unsealed (then the
group is malformed) — so that one reader could count the group and
another never could, gains nothing: no reader counts a group while its
members' epochs do not all admit the same readers (§5.5), and it counts
everywhere once the owner admits them to every epoch.

**Expiring members.** A member kept for the last `n` versions or until a
date would vanish from its writer's listing once expired, and a reader
starting later could never learn it had existed, while readers that held
it counted the group and built on it. Group members are therefore kept
until pruned: `put_group` refuses another keep. A writer that signs one
anyway gains no split: a reader holding it never counts the group and
refuses none of it, and a reader that never learns of it finds the group
incomplete — both wait, so no reader applies the writer's later versions
there and no honest writer builds on them; only the misbehaving writer
is held back. Nothing is refused for a listing that is absent: an honest
writer's node may stop listing an entry its store lost and list it again
once found, and the group then counts everywhere. A prune leaves signed
evidence every reader fetches — the prune record, and the writer's
summary still listing the entry — so a pruned member counts as present
alike everywhere.

## §9 Seal (a line that changed)

  keep, the writer's date, its group (§5.5) — and the ciphertext's size;

## §11 Snapshot and state names (a line that changed)

the snapshot arrives; versions counted all or none are a group (§5.5).

## §13.5 What a device serves (lines that changed)

revocation cut or an untrusted chain (§8), its group (§5.5) or its rule's
  waiting in memory (pending, parked while its group waits, locked);
  source, is the equivocation §4 reports and §5.5 refuses a group for. A

## §15 Verbs (the lines that changed)

The verb table row, the verbs paragraph, and the `put_group` bullet:

| `put_group` | `put_group([(collection, fields \| operation)…], {type, keep}) → [(writer, seq)…]` | 6 |

`put_op` and `put_group` are forms of `put`, `share_folder` of `share`,

`get`, the `NotCounted` bullet's wording changed where `put_group` and groups were named:

  `Waits`: members of groups incomplete or unreadable here, §5.2, §5.5; see

- **`put_group(items, {type, keep})`** signs one version per item — fields
  (made into an operation by the rule's edit in a merge collection) or an
  operation — as one group (§5.5), and answers their ids in item order, or
  refuses as §5.5 says, writing nothing: the default records of new
  collections among them are signed only once every item passed, and as
  `put` signs them (§5).

- **A put never waits on other devices** (round 4). `put`, `put_op`,
  `put_group` and the batch forms return once the version is applied

  wait — the group of the version is incomplete (`group incomplete: 1 of
  2`), not readable here, waits for the epoch its readers are in, or a
  basis or pieces of it are still arriving; it ends when what it waits for
  arrives, and the version then counts (`Change::Counted`). **`Excluded(why)`**
  is a rule's own exclusion (the rule's `Counting::NotCounted`, an apply
  that failed, a group refused, a group member held back by a member its
  rule excludes, a group with a member kept otherwise than `Forever`
  (§5.5)): it does not end by waiting for what the layer waits for

  counted, with why (`Change::NotCounted`, §5.2, §5.5), and every such

  why when the rule does not count it, and a group member waiting for its
  group as `NotCounted` alone (its version comes once the group counts); a
  version held but not applied yet (it waits for an earlier one, its
  group, its key or its pieces) is not listed and comes once it applies,

  within one collection a writer's versions come in seq order (a group's
  members once their group counts), across collections in no common

## §16.2 TLV-TYPE numbers (the lines that changed)

The VersionRecord row below is shown as it stood; it now has no `[Group]`.

| 0x0520 | VersionRecord | Name (collection), Frontier (parents, each entry with its tip's Digest), TypeId, Seal, Keep, Dated, [Group] (§5.5), [Rule] (merge: the rule the operation was made for, §5.1), then Fields, MergeOp — or Block (§4.1), or Chunks (§13.1; in a collection of any rule from slice 6) — or, sealed, Sealed |

| 0x0557 | Group | Seq (the group's id: the seq of its first version), GroupCount; in a VersionRecord right after Dated (§5.5) |
| 0x0559 | GroupCount | NonNegativeInteger 1–65,536 (`GROUP_MAX`): the number of versions in the group |

In the paragraph beginning "Slice 6's numbers are odd for the same reasons", these lines went:

the folder removed would be admitted there — wrong, not stale. One passing
over `Group` would count the members of an incomplete or refused group in
part, which is the one thing a group forbids; one passing over
`GroupCount` could not tell a complete group from an incomplete one. One

## §16.3 Why these encodings (the bullet that was cut)

- **A group's id is its first seq**, and its versions are its writer's
  consecutive seqs (§5.5): a key's seqs are unique across its log, so
  `(writer, id)` names the group with no new identifier; a reader knows
  exactly which seqs make it up, so it can tell what is missing and fetch
  it by name from the summaries, and no other version can claim to belong
  (a seq outside the range is malformed). `put_group` signs under one lock,
  so nothing else of the device's log comes between. `GroupCount` makes
  completeness a fact of each member's own signed record.

## §17 Failure model (the table rows that changed)

Rows as they stood. Three rows lost only a clause and still stand without it: "Writer equivocates" now ends after "or of two kinds"; "A rule's apply fails on the state others made" ends "no version is refused for it"; "Version listed by a watch while it waits" lost its group parts.

| A rule's apply fails on the state others made | Applied, not counted, with the reason; no version or group is refused for it. | §5.1 |
| Writer equivocates | Both entries are kept and reported (`Change::Equivocation`), at one name or at one seq in two collections or of two kinds; a group over that seq is refused. | invariant 2, §4, §5.5 |
| Group member in pieces, not opened yet | Present once every piece is held; opened as it applies; the group counts whole, on readers and on the writer after it reads a collection again. | §5.5 |
| Group member never arrives | The group stays incomplete: its members held and shown not counted, what depends on them waiting — stale, never wrong. | §5.5 |
| Group member refused, or group malformed | No member counts, on every reader alike; members applied before are withdrawn in every collection (`Refusal::Group`); others' versions made over them stay counted. | §5.5 |
| Two members, or a member and another entry, at one seq of a group, in collections of its folder | The group is malformed at every reader of the folder once it holds both (an entry kept `Forever`, or listed and pruned, or listed in a merge collection), whatever their order; one outside the folder, or kept to expire, changes nothing; the equivocation is reported. | §4, §5.5 |
| Narrowing concurrent with a group | Judged by the epochs its members are sealed in and their audiences, alike everywhere; a reader left out finds it unreadable here and counts none of it. | §5.5, §6.2 |
| Group whose members' epochs admit different readers, whatever seal it declares | No reader counts it until every member's epoch admits every reader another member's epoch lists; sealed and unsealed members together make it malformed. | §5.5, §6.2 |
| `put_group` that cannot complete | Refused before anything is signed, saying which item and why — also for a keep other than `Forever`. | §5.5 |
| Group member pruned | It counts as present for its group's verdict, alike at every reader (the prune record and the writer's summary say so): the group counts once every other member is present, and nothing counted is uncounted by the prune. | §5.5, §14 |
| Group member that may expire | The group never counts and nothing of it is refused, at every reader: one holding the member and one that never learns of it both wait, so no reader applies the writer's later versions there and no honest writer builds on them. | §5.5, §6.2, §14.1 |
| Group member its writer's node stops listing (store loss) | Nothing is refused: the group waits, and counts everywhere — with versions made over the member — once the node lists it again and it is fetched. | §5.5, §7 |
| A large group stalls (a member never arrives, or never opens here) | Its members held whole and opened wait in the store, each costing memory only its index (id, name, keep, seal, epoch); members in pieces, members sealed in an epoch whose key is not held here, and members of a collection held for its owner stay in memory. Each is listed not counted with why; what depends on them waits — stale, never wrong. | §5.5 |
| Device restarts with group members parked | They are read back from their parked copies at start, verified when parked, and parked again while the group waits: nothing of a stalled group is fetched again, a member whose writer is gone still completes its group, and an equivocation a parked member is part of is noted again and still reported. A parked copy whose member applied, was refused or was let go is dropped. | §4, §5.5, §7 |
| Version listed by a watch while it waits (for an earlier version, its group, its key, its pieces) | Not listed: it comes once it applies, so no watch is handed a version twice; a group member waiting is listed `NotCounted` with why. | §15 |
| Reader that predates slice 6 | Refuses folder records and group members (odd TLVs) and waits for them — stale; it applies a collection's own record alone, without a folder's narrowing, until updated. | §16.2 |

## §18 Conformance: the slice-6 cases (the lines that changed)

first fetching the covered version it was made over, with no conflict), g1 (a
group counted all or none on arrival, and withdrawn whole when one member
is refused), g6 (a group with one member under a lock waits whole, each
other member not counted with a reason naming that member and its
reason, then counts whole once unlocked), g7 (a group of three whose
37,847-octet member travels in pieces counts whole at a reader once every
piece is held, and at the writer after a new members record makes it read
the folder again), g2 (`put_group` refuses a group that could not complete,
writing nothing), g3 (a group judged the same at every reader despite a
concurrent narrowing of one of its collections), g4 (a copy of a
writer's device signs seqs it already used in other collections: entries
at seqs a folder cut kept are refused `OutsideCut` in the collection the
cut did not list them under, at every reader, and a group one of whose
seqs carries a second entry is refused for its group at every reader),

Their features are `RuleByName`, `AppOps`, `MergePieces`, `Groups`,

The large-group case is g5 (one folder of 2,000 element collections; a
writer puts one edit into each as a single group, above the former bound
of 1,024; another member holds no member counted until all 2,000 are
held, then counts all of them, and a reader holding only some keeps them
in its store, not in memory, listed not counted with "group incomplete").

collections holding versions past its `since`, the parking of an
incomplete group's members, and parked members read back after a restart
(the group completes with nothing fetched, and an equivocation a parked
member is part of is still listed).

created under a watched folder delivers its version, a group member's
`NotCounted` and `Counted`, and a cross-collection equivocation once per
collection, each tagged; an equivocation across two folders shows a
watcher nothing of the other folder's content; a watch lists a group
member waiting as `NotCounted`, and a version waiting for an earlier one

## §18 Conformance: durability cases (the lines that changed)

written after it) and d5 (a child killed at a random moment inside a large
batch, then inside a `put_group`: after reopening each batch, each group, is
whole or absent, in order) run on both engines in `ndn-sync`'s
`tests/durability.rs` and `ndn-data`'s `device/batching_tests.rs`; the
power-loss case d2 also commits `apply` batches. d6 (a put, a `put_group`
reach the store as one batch, markers before pieces before the entry; for
of puts and groups, each one batch, converges among devices and survives a

## §18.1 Faulty mode (a line that changed)

A duplicated packet is idempotent: a version, group member, grant,
