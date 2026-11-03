# Data layer: named, signed, versioned data

- **Status:** Slices 1, 2 and 3 normative (slice 3: large payloads in
  pieces, hold records, leases capped by keep, audits and repair, `prune`
  of one's own writes and the erasure of fully pruned epochs, §13, §14);
  slices 1 and 2: versions, collections with
  owner-signed members records whose writers and readers are of any
  namespace, the merge rule and its function `/merge/yrs`, the log rule,
  removal cuts and the re-check when a cut arrives, seals (epoch keys and
  grants), types, signed nested summaries, snapshots, the sync notice and
  its reach across namespaces, the verbs `get`, `put`, `watch`, `snapshot`
  and `share` (adding, removing, changing the rule), `prune`'s scope, and
  their wire format (§16). Sections marked with a later slice are not yet
  normative beyond what they state; a section marked *open* has no
  normative content beyond its text.
- **Scope:** the data model shared by files, databases and network
  exchanges — versions, collections, members, summaries, cuts, snapshots,
  custody, prune, seals and types — and the seven verbs over it. The Rust
  contract and its reference implementation are the `ndn-data` crate
  (`crates/app/ndn-data`: `DataLayer`, `Device`); conformance cases are
  `ndn-data-conformance` in ndn-sim.
- **Out of scope:** views and lenses above the layer; trust-context encoding
  ([trust-context.md](trust-context.md)); link admission
  ([ndn-link.md](ndn-link.md)); State Vector Sync itself (ndn-svs v2, as
  `ndn-sync` implements it).

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174)
when, and only when, they appear in all capitals, as shown here.

## 1. Principle: end to end

The ends are the signing key and the reader. Caching, combining requests,
relaying and holding are performance or protection only. Whether data is
correct, newest, readable or still valid MUST be decided by the reader, from
the data, its name, the trust context and the cuts. A reader's correctness
MUST NOT depend on any forwarder, cache, repository or relay.

## 2. Invariants

Every implementation MUST hold all of these.

1. **Checkable anywhere.** Any version verifies from its bytes, its name,
   the trust context and the cuts — never from a server or a clock.
2. **Immutable per writer.** One `(writer, seq)` has one set of bytes. Two
   different versions with the same `(writer, seq)` are proof of
   misbehaviour attributable to that key; a reader MUST keep both and report
   them.
3. **Monotonic.** A writer's sequence and a collection's summary never go
   back. A reader MUST refuse a summary or members record older than one it
   has seen from the same signer, also after the reader restarts.
4. **Completeness is relative.** "I have everything" always means
   "everything in this signed summary".
5. **Stale, never wrong.** Failures MUST degrade to older verified data, and
   the reader MUST be told how old.
6. **Authority is in the data.** Writing follows the trust schema and the
   collection's members; reading follows the seal; a cut ends both from a
   point on.
7. **Retention is chosen at write.** Custody MUST NOT extend keep; prune
   only narrows, and only over the pruner's own writes.
8. **Nothing is lost by not understanding it.** A writer MUST keep every
   field it does not know.
9. **Forward-only, said plainly.** Revocation and deletion stop future
   reads; an implementation MUST NOT claim to recall copies already made.

No validity decision may read a wall clock. Dates are display and
retention only.

## 3. Names, devices, namespaces — slices 1, 2

- A **namespace** `O` is the name of a trust context
  ([trust-context.md](trust-context.md)): one or more components (`/alice`,
  `/home/bob`), none of them a KeywordNameComponent (type 0x20), a digest
  component or a SequenceNumNameComponent. It is the unit of the
  hierarchical trust schema, so it is the person data belongs to.
- A **collection name** is `<O>/32=data/<path>`: the namespace, the
  KeywordNameComponent `data` (the **marker**, which says where `O` ends),
  and a path of one or more components. No component of it besides the
  marker is a KeywordNameComponent or a digest component: keyword
  components mark the layer's own names (§16.1). A **folder** is
  `<O>/32=data/<path>` with a path that other collections extend, and
  `<O>/32=data` is the folder of every collection of `O`. The **owner** of
  collection `C` is its namespace, the components before its marker.
- `put`, `get`, `share` and `snapshot` take collection names; `watch` takes
  a collection or folder name (`<O>/32=data[/<path>]`). A verb given a name
  that is none of these — no marker, nothing before it, nothing after it
  where a collection is asked for, or another keyword or digest component —
  answers `BadName`, saying which and how the name must be formed
  (`NextStep::FixName`). `get` also takes log entry and state names (§11).
- A **device** `D` is the identity of one key: the key is named
  `<D>/KEY/<key-id>` (NDN key naming). `D` is the device's name in seals
  and the prefix it serves; it has no KeywordNameComponent or digest
  component (`<O>/<role>/<device>`, as ndn-cert names it).
- **A device's own namespace** is the namespace of the trust context that
  governs `D` in the device's validator: the held context whose namespace
  is the longest prefix of `D`. It is the group a device joins (§12), the
  namespace of the host's default members record (§5) and the only one
  whose collections it may `share` (§15). A device that no held context
  governs (only the ambient, root context matches it) MUST NOT start, and
  says so.
- **The owner rule.** A members record `<D>/32=log/<C>/seq=<n>` is signed
  by a device of `C`'s namespace `O` exactly when `D` lies under `O` and
  the trust context that governs the record's name in the reader's
  validator — the one its signature verified under, the held context whose
  namespace is the longest prefix of the name — is `O`'s own. A device of a
  longer held namespace is that namespace's device: with `/home` and
  `/home/bob` held, `/home/bob/member/laptop` owns `/home/bob/32=data/x` and
  not `/home/32=data/x`, although `/home` is a prefix of its name. A reader
  holding `/home` alone verifies that device's records under `/home` (its
  chain ends at `/home`'s anchor), so to it the device is `/home`'s.
- **The namespace of a name** here (a writer prefix, a device, a person)
  is that of the held trust context governing it, the one whose namespace
  is its longest prefix; a name no held context governs has none. A
  device that writes into or reads another person's collections holds that
  person's trust context — it verifies their entries with it — so the
  person's namespace is held wherever their data is used. Holding it is
  the person's gesture of pointing at someone (adopting their anchor
  link); nothing else names people.
- Every packet a device signs MUST be named under `D`, so any forwarder's
  hierarchical schema admits it and Interests for it route to the device.

## 4. Version and log — slices 1, 2 (blocks: slice 4)

A version is an immutable record signed by one key. It carries
`(writer, seq)`, parents, type, seal, keep, a date and a payload.

- A writer is one key, never a person. Each key keeps **one log**: every
  entry it signs about any collection — versions, members records (§6),
  snapshots (§11) — takes the next sequence number of that log. `seq` MUST
  increase by one with every entry and never goes back; entries of one key
  MUST NOT share a sequence space with any other key. A collection holds a
  subset of each writer's log, so its entries of one writer have gaps.
- Parents are the frontier (writer → highest seq) of the collection's state
  the writer had applied when it wrote (§5.2).
- The date is the writer's clock reading in milliseconds since the Unix
  epoch. A reader MUST NOT use it to accept or refuse anything.
- The payload of a version is one entry: the fields the writer set (§10),
  and the merge function's operation (§5.1) — empty under the log rule. A
  block of entries under one signature is slice 4.
- The seal a version carries is the collection's readers at the time of
  writing, as the writer declares it. In a sealed collection (§9) the
  payload travels encrypted (`Sealed`, §16.2) under the key of the epoch
  the writer's newest members record names; everything else in the record
  stays readable. Keep is recorded; enforcing it is slices 3 and 4.

A version is the Data packet `<D>/32=log/<C>/seq=<n>` whose Content is a
`VersionRecord` (§16.2), signed by the key `<D>/KEY/<id>`. A reader MUST
refuse (and MUST NOT apply) a log entry whose signature does not verify
against its trust context, whose signing key is not a key of the `D` its
name starts with, or whose record's collection is not the `C` in its name.

## 5. Collection and rule — slices 1, 2 (one key: slice 4)

A collection is a named, growing set of versions with a rule and a members
record. It exists when its first members record is signed (§6): `share`, or
a writer's first `put` into a collection of its own namespace (§3), which
signs the host's default record (merge with `/merge/yrs`, the namespace
writing and reading, sealed to it).

| Rule | Meaning |
|---|---|
| one key | One key writes; the newest is its signed head with a freshness bound. Slice 4. |
| log | Each member key appends; the collection is the union of exactly its members' logs. `get` returns the newest version. |
| merge | Member logs plus a named merge function every reader runs alike. `get` returns the merged state at a frontier. |

The collection, not the application, decides what "newest" means. A
collection's rule is the newest members record's; changing it starts the
collection again (§6).

Under the **log rule** the collection is the union of exactly the versions
its newest members record admits (§6): every member's versions reach every
reader that follows it, and a version by any other key reaches none — a
reader refuses it, and it is never delivered to a watcher. Versions are
delivered in the order of §5.2. The newest of a log collection is, of the
versions applied that no other applied version names as a parent (the
concurrent heads), the greatest by `(writer key name, seq)` — an order
every reader computes alike, with no clock.

### 5.1 Merge functions

A merge function turns a writer's edit into an **operation** carried in the
version (`MergeOp`) and folds operations into a state. Every reader that
applies the same versions MUST obtain the same state. A reader that does not
know a collection's function MUST NOT claim a state for it and says so.

`/merge/yrs` is a Yjs document. Its root map `fields` holds one entry per
field, each value a binary (`Uint8Array`). The operation of a version is the
Yjs update (lib0 v1 encoding) of its edit: set every field the version sets,
delete every field it sets to an empty value. Concurrent sets of one field
resolve as Yjs resolves them; different fields never conflict. A writer's
Yjs client id is the low 53 bits of SHA-256 over the TLV encoding of its key
name, and a reader MUST refuse an operation that inserts content under any
other client id. A Yjs peer may therefore apply the same updates (it sees
the fields as binaries). A reader ignores root-map entries of other Yjs
shapes; they stay in the document.

### 5.2 Applying versions

A reader applies an admitted version `v = (w, s)` of collection `C` only
when

1. every entry of `w` in `C` below `s` — as `w`'s summary (§7) lists them —
   is applied, unless it never applies: the record in force refuses it by
   its key (a cut that does not list it, §8), or it was held and refused for
   what it carries (`Unsealed`, §9; an operation the rule refuses), and
2. for every `(y, t)` in `v`'s parents, the reader has applied `y`'s entries
   in `C` up to `t`.

Until then `v` waits. The state's frontier `at` is, per writer, the highest
seq applied; by these rules every entry at or below it that applies at all
is applied, so `at` names exactly the versions the value is computed from.
A parent `(y, t)` that never applies is needed only up to the highest
version of `y` below it that does (for a cut, the highest it accepts): a
version written on top of refused work is not held back by it (what of the
refused work its operation depended on, the merge function decides).

## 6. Members — slices 1, 2

The members record is signed by a device of the collection's owner
namespace (the owner rule, §3). It lists the rule, the key-name prefixes
that may write — of any namespace (`/bob` writes into
`/alice/32=data/docs/plan`) — the audience that may read, the cuts of
removed writers, the epoch the collection is sealed in with its key check,
and, once the rule changed, where the current rule starts.

- A members record is an entry of its signer's log, `<D>/32=log/<C>/seq=<n>`
  with Content `MembersRecord` (§16.2). Its `Revision` is one more than the
  revision of the record in force at its signer (1 for the first), and from
  revision 2 it names that record as its **parent**: its revision and the
  SHA-256 of its `MembersRecord` TLV — the Content of the packet carrying
  it or, when the record in force was a merge of concurrent records
  (below), the `MembersRecord` that merge stands for, encoded as §16.2
  lists (its parent the one its records share, none when they name
  different ones). The digest is of the Content, not of the whole Data
  packet: a merge is carried by no packet, and devices holding the same
  records compute the same merge, so the same digest, whoever signed what.
- A reader MUST ignore a members record that the owner rule (§3) does not
  give to `C`'s namespace. The **record in force** is the merge of the
  records it holds of the highest `Revision`, one per signer (its latest);
  a record of a lower revision changes it only as the parent the records
  of the highest revision name (below). A reader keeps, besides those,
  every record of the revision below that it took and every merge of them
  it computed: the parents they may name.
- **Concurrent records.** Two devices of the owner may each sign revision
  `n` from their own view (the laptop adds Carol while the phone, offline,
  removes Bob). Their records merge, whatever order they arrive in:
  - **Against their parent.** When every record merged names one parent
    `P` and the reader holds it, writers and readers are `P`'s, plus every
    one a record lists that `P` does not (an addition), minus every one of
    `P`'s that a record does not list (a removal). A removal beats an
    addition: a writer prefix one record adds is no writer when it covers,
    or lies under, a prefix another record removed. Rule and `Since` are
    `P`'s unless a record changed them, then that record's; when several
    did, those of the one with the highest signer key name.
  - **Without one.** When the records name different parents or none, or
    the reader does not hold the one they name, writers are the
    intersection (a key is a writer only if every record admits it),
    readers the intersection, rule and `Since` those of the record with
    the highest signer key name. An addition is then lost until a record
    resolving the merge (below) arrives from a device that held `P`.
  - Either way cuts are the union by prefix (where two records cut one
    prefix, the intersection of what they accept), and the epoch (with its
    key check) is that of the record listing the fewest readers the merge
    leaves out, then the fewest readers (ties: the highest signer key
    name). Removals win.
  - **Resolving.** A merge is **resolved** — a device of the owner
    namespace that holds it and is of its audience MUST sign revision
    `n + 1` with the merged writers, readers, cuts and rule, naming the
    merge as its parent — in a new epoch when the merged readers leave out
    a reader of the epoch kept or, merged against `P`, a reader of `P` or
    of any record merged (a reader one record removed is still of the
    epoch another kept); and in the epoch kept, with its key check, when
    they only list a reader no merged record naming that epoch lists (one
    record added a reader while another moved to a new epoch). Devices
    resolving at once sign records of one revision, one parent and one
    audience, whose merge needs no more.
- **Admission.** A reader MUST apply to `C` only versions the record in
  force admits (and, as for every entry, the trust schema admits under the
  writer's own name): a key under a writer prefix is admitted; else a key
  under the prefix of one of the record's cuts is admitted exactly when the
  cut lists that version, and refused otherwise, `OutsideCut`, whatever
  date or seq it claims; any other key is refused `NotMember`. Versions that
  arrive before any members record wait for one. Admission depends on the
  record in force only, so every change of it re-checks everything held of
  `C` (§8).
- **Removing a writer.** A record that drops a writer prefix `P` of the
  record in force MUST carry a cut of `P` that lists, per key under `P`,
  exactly the seqs of that key's versions in `C` the signer holds verified
  — never entries a summary only listed. Cuts carry over to later
  revisions; a revision whose writers cover a cut's prefix again drops that
  cut, and the prefix's keys are admitted again (all of their versions, the
  owner having written them back in).
- **Readers.** The audience is exactly the readers listed — people (a
  namespace), devices and groups — plus the device that signed the record
  starting the epoch (§9). A group is a collection: its members are the
  readers its own record in force lists. No device reads for being of the
  owner's namespace: the host default record lists
  `Person(<own namespace>)`, and a record listing `Device(/alice/laptop)`
  alone leaves Alice's phone out of its epoch and every later one. A
  record with readers seals the collection (§9) and names its epoch; a
  record that drops a reader starts a new epoch; one that only adds keeps
  it and copies its key check.
- **Groups.** A device that holds a record naming `Group(G)` follows `G`
  (§12), so that it holds `G`'s record and hears its changes. When a device
  of `C`'s namespace that is of `C`'s audience takes a record of `G` that
  drops a reader, it MUST sign a new record of `C` in a new epoch, whoever
  owns `G`. Several owner devices rotating at once sign concurrent records,
  which merge as above.
- **Changing the rule.** A record whose rule differs from the previous
  revision's — or that seals a collection the previous revision left
  unsealed — carries `Since`: the frontier its signer had applied, joined
  with the previous `Since`. Versions inside `Since` stay held, readable by
  name and listed by `watch`, and are applied as history only: they order
  later versions (§5.2) and never enter the new rule's state. A state of
  `C` after the change is named by a frontier covering `Since`.

## 7. Summary — slice 1

A writer's summary of a namespace `O` is its own log's index over `O`: a
tree of **nodes**, one per name under `O` the writer wrote into (and every
name on the way there). The tree runs from `O` through its marker: the
root is the node of `O`, its one child the folder `O/32=data`, and below
that one node per path component down to each collection
`O/32=data/<path>`. A reader descends from a root only into the child
`32=data`; any other child of a root names no data of `O`. Completeness is
per writer: with many writers each publishes its own, and a reader gathers
them from the devices it hears move (§12) — the members records it holds
say which writers a collection gathers, of whichever namespace. A device's
own log is complete to itself; a summary is for the others. Nothing signs a
combined summary of many writers.

A node of name `X` carries:

- `Head`: the writer's highest seq in the subtree of `X`;
- `Entries`: the seqs of the writer's versions directly in `X`, as ranges —
  the seq → name mapping, since an entry's name is `<D>/32=log/<X>/seq=<n>`;
- `MembersEntries`: the seqs of its members records of `X`;
- its children: for each next name component under `X` with entries in its
  subtree, the child's component, `Head` and the implicit digest (SHA-256 of
  the whole Data packet) of the child's node. A node with more than 64
  children lists them on **pages** instead: 16 buckets by the first nibble
  of SHA-256 over the child component's TLV, each a page node listing its
  children, or (beyond 64 again) 16 sub-pages by the next nibble.

A node's content is fixed by the writer's log up to its head, so one node
name (`<D>/32=summary/<X>/seq=<head>`, a page
`<D>/32=summary/<X>/32=page/<buckets>/seq=<head>`) has one packet. Inner nodes
and pages are DigestSha256 packets; a reader MUST check each against the
digest its parent lists. The **root**, the node of `O` itself, is the only
signed one: `<D>/32=summary/<O>/seq=<head>`, signed by the device key,
FreshnessPeriod 0 so that discovery always reaches the writer. A writer
SHOULD sign a new root only when one is asked for and the tree changed.

A writer MUST serve every node and page that any root it signed lists, for
as long as it holds the log entries that node lists — in slice 1 a writer
never drops its own entries, so always, across its own restarts too (prune,
slice 3, ends this only for what it prunes). Keeping them costs no storage:
a node's content is fixed by the log up to its head, so a superseded node is
rebuilt from the log when asked for; a writer MAY keep recently superseded
packets ready. A writer MUST answer an Interest for a summary name that none
of its roots listed with a Nack. Hence the time a reader's descent takes is
bounded by the descent alone — its own fetches being answered — and never by
how fast or how long the writer keeps putting.

A reader:

- discovers a writer's root with `<D>/32=summary/<O>` (CanBePrefix,
  MustBeFresh), verifies it as a log entry is verified (§4), and checks
  that its subject is `O`, its writer field its signing key and its name's
  seq its `Head`;
- MUST refuse a root whose `Head` is lower than one it verified from that
  writer for `O`, or than the highest seq it holds of that writer under `O`
  (invariant 3, "rollback"). The highest `Head` verified per writer and
  namespace is durable: the reader keeps it with what it holds (the
  reference keeps the root itself), so a restarted reader refuses the same
  rollback;
- descends only into what it follows (the collections and folders it has
  put into, read or watched, and the names on the way to them), and only
  into children and pages whose digest differs from the one it last
  processed in full: an unchanged branch costs nothing. Watching a folder
  of 10,000 notes of which 37 changed costs the root, the `O/32=data` node,
  the folder node, the changed pages, the 37 notes and their new entries;
- descends the root it verified to the end: it fetches the nodes and pages
  that root lists, not a newer root's, until every branch it follows is
  processed. A node that is not answered leaves the descent incomplete; the
  branches processed in full stay processed, so the next descent skips
  them. Only after a descent does the reader take the writer's newer root,
  if the writer moved meanwhile, and descend from what it has processed.
  One complete descent of a root gives the reader everything that root
  covers in what it follows, however fast the writer keeps putting;
- MUST refuse a node (or page) whose `Entries` or `MembersEntries` ranges
  are not ascending and disjoint, reach above its `Head`, or list more than
  65,536 seqs together: a node lists no entry its head does not cover, and
  one node never makes a reader expand an unbounded list;
- fetches the entries the visited nodes list that it does not hold.

`watch` reports a `Summary` for each verified node of the watched name or
below it that it descends into: the collection, the signing writer,
frontier `{writer: Head}` and the node's inline children by digest (a paged
node lists none; its pages are not sub-collections).

## 8. Cut — slice 2 (removal), slice 5 (revocation)

A cut is a signed list of exactly which versions of a key or of a member's
keys stay valid: every version it lists stays valid; anything else by those
keys MUST be refused, whatever date or seq it claims. A removal cut is
carried by the members record that removes a writer (§6), signed with it by
the owner.

- A cut lists exact versions, never a limit. A writer's log is shared by
  all its collections, so its seqs in one collection have gaps; under a
  limit, a removed writer could sign a new entry at a seq of such a gap
  below it — a new name, so no equivocation — and be admitted. Under a list
  that entry is outside. The list is what the owner held verified: an entry
  a summary only listed is not in it.
- A cut replaces clock-based signing-time validity: no date in a version
  decides whether it is inside.
- **Re-check when a cut arrives.** When the record in force changes (a
  newer record, or one that merges with it, §6), a reader MUST read the
  collection again under it: admit or refuse every version it holds of the
  collection anew, and recompute the state from the versions admitted. A
  version it had applied that the new record refuses by a cut is
  **withdrawn**: it leaves the state, the reader MUST report it to every
  watcher of the collection as `Withdrawn` (the version and the cut),
  whatever the watcher's frontier, and `get` of it by name answers
  `Refused` (`OutsideCut`, next step: ask the owner). A version applied
  before and still admitted is not delivered again. The writer's own
  device does the same with its own versions.
- Withdrawing is forward-only (invariant 9): copies already read stay read.
- *Open (slice 5):* a cut can drop honest work (a stolen device's unseen
  offline edits). The owner MAY re-admit specific versions by signing them
  into the members record.

## 9. Seal — slice 2

A seal is a read policy over people, devices and groups (§6). An
application is never a seal audience: lenses hold no keys, and the host
opens only what the person pointed at. Holders without the key store and
forward ciphertext. Erasure is the destruction of the key.

- **Epochs.** A collection whose record in force lists readers is
  **sealed** in that record's epoch, `(D, n)`: the device that signed the
  record starting the epoch and that record's seq in its log. A record with
  no readers leaves the collection unsealed from then on.
- **Epoch keys.** The content key of an epoch is 32 random octets that `D`
  makes when it signs the record starting the epoch, and keeps with what it
  holds. Nothing derives it: no key of an epoch exists before its record is
  signed, and no device holds a secret that yields the keys of epochs to
  come. The record starting the epoch carries its **key check**
  (`KeyCheck`, §16.2): HKDF-SHA256 (RFC 5869) with the key as input keying
  material, no salt, and as info `ndn-data/seal/check/1`, the TLVs of `C`
  and of `D`, and `n` as 8 octets, big-endian; 32 octets. A record that
  keeps the epoch copies it. A device MUST take a key as epoch `E`'s of `C`
  — granted, or read back after a restart — only if it matches the check of
  a held owner-signed record of `C` naming `E` (the starting record's, when
  held); a key that does not is dropped.
- **Recipient keys.** Each device holds an X25519 **recipient key**, kept
  with its signing keys in its key store — never with the data it holds,
  which may be served or copied — and never sent; its public half is its
  **seal key**, the packet `<D>/32=seal/<public key>` signed by the device
  key. Epoch keys a device made or was granted stay with what it holds,
  wrapped to its seal key, under no name any device serves (the reference
  keeps grants as received and its own keys under
  `/localhost/ndn-data/epoch/<D>/…`).
- **Sealing.** A writer of a sealed collection encrypts each version's
  payload — its `Fields` and `MergeOp` TLVs — with ChaCha20-Poly1305 under
  the content key of the epoch its record in force names, a random 96-bit
  nonce, and the TLV of the version's own name as associated data; the
  record carries `Sealed` (the epoch and `nonce ‖ tag ‖ ciphertext`) in
  place of them. A reader opens it with that epoch's key; a payload that
  does not open under it is refused as a bad signature. A reader without
  the key holds the version verified and closed, applies nothing that waits
  on it, and asks for the key if it may hold it. A reader MUST refuse a
  version of a sealed collection that is not sealed, `Unsealed`, unless it
  lies inside the record's `Since`: its writer wrote it before hearing the
  record that sealed the collection, and relays have it in clear. A record
  that seals a collection its previous revision left unsealed sets `Since`
  (§6), so what was written before stays held, as history.
- **Grants.** A device asks for an epoch key with the Interest
  `<G>/32=grant/<GrantAsk>`, `GrantAsk` naming its own seal key, the
  collection `C` and the epoch `E`. The granter `G` MUST answer only when
  (1) an owner-signed record of `C` it holds names `E`, (2) the readers the
  held records naming `E` list, or `E`'s creator, admit the asker, (3) the
  record in force, when it seals `C`, admits the asker, and (4) `G` holds
  `E`'s key; anything else gets no answer, and `G` fetches nothing for it.
  It then fetches and verifies the asker's seal key (signed by the asker's
  device key) and answers, signed by its own key, with the key wrapped to
  it: a fresh X25519 key agrees a secret with the seal key, the wrapping
  key is HKDF-SHA256 of that secret (no salt; info
  `ndn-security/confidentiality/x25519-kek/1`, the ephemeral and the seal
  key), and the key is sealed under it (ChaCha20-Poly1305, the grant's name
  as associated data). Any device holding `E`'s key may grant it: the
  asker checks what it gets against the record. A granter keeps the grants
  it signed (the reference, its last 4,096), so asking again gets the same
  packet; past that it signs the name anew, a packet that opens to the same
  key. An asker asks only for an epoch a held record names and that it may
  hold by (2) and (3) as far as it can tell, the epoch's creator first,
  then every other device it knows to write into `C`'s namespace. Keys are
  per epoch for every reader: a device of the owner's own namespace is
  granted like any other (a second device of 10,000 collections, each in
  its own epoch, asks 10,000 grants once).
- **Forward only.** A removed reader is refused every grant from then on
  (condition 3), and the epoch that removal starts has a key that did not
  exist before, so nothing written after it reaches it; what it already
  opened it keeps, said plainly (invariant 9). A reader added by a record
  that only adds is of the epoch it keeps, and reads that epoch's history;
  an epoch that ended before a reader was listed stays closed to it.
- A device outside a sealed collection's audience answers `get` of it, of
  its states and of its versions with `Sealed` (next step: ask the owner).
- **What a relay sees.** Every relay, cache or repository carries the
  ciphertext and the grants (each wrapped to one device) and reads no
  payload and no key. It does see, in clear: every name (devices,
  collections and their paths, log seqs, summaries); members records —
  rule, writers, readers (people, devices, groups), cuts with the exact
  versions they keep, revision and `Since`; each epoch and its key check;
  each version's record but its payload — collection, writer, seq,
  parents, type, the seal it declares, keep, the writer's date — and the
  ciphertext's size; seal keys; and who asks whom for which epoch's key
  (the grant's name names the asker's seal key, the collection and the
  epoch), and when.

## 10. Type — slice 1

A type is a named, versioned content schema (`/types/note`, revision 2).
Revisions only add fields. Content is a set of named fields with opaque
values.

- A version sets fields: each field it carries is set to its value, a field
  carried with an empty value is removed, and every field it does not carry
  keeps its value. So a writer that knows only revision 1 keeps revision-2
  fields by construction (invariant 8); there is no "replace all" write.
- The type is recorded in the version for readers and lenses; it never
  changes how the merge function folds fields. A type MAY later declare
  richer field kinds (text merged by character); slice 1 has none.

## 11. Snapshot and state names — slice 1

A **state name** `<C>/32=state/<F>` names the merged value of merge
collection `C` at frontier `F` (the last component is a
GenericNameComponent whose value is a `Frontier` TLV). It is computed, never
fetched: a reader answers it by applying exactly the versions of `C` inside
`F` (§5.2) and MUST answer the same value on every device and however `C`
grows. A reader that does not hold every version inside `F` (as the
writers' summaries list them) MUST NOT answer a partial value.

A **snapshot** is an entry of its signer's log, `<D>/32=log/seq=<n>` (no
collection), Content `SnapshotRecord`: the names it pins, each an exact log
entry name or a state name. Publishing it is the atomic multi-object change
and makes a merged state citable: a link carries the snapshot's name.

## 12. Sync notice — slices 1, 2

Each namespace `O` has a **sync group** `<O>/32=sync`: `O`'s whole name,
however many components it has, then the KeywordNameComponent `sync`
(`ndn_security::sync_group`, the one definition the data layer and the
forwarder's libraries share). It runs as State Vector Sync (ndn-svs v2
dialect). A device joins its own namespace's group — `O` the namespace of
the trust context governing it (§3), so the very group the forwarder's
libraries carry for that context — and the group of every other namespace
whose collections it puts into, reads or watches, `O` read off the
collection's name at its marker (`/home/bob/32=data/notes` →
`/home/bob/32=sync`). Each member's state-vector entry is named by its
device name `D`.

**Publishing.** After every entry a device signs about collection `C` of
`O`, it publishes into `O`'s group and into the group of every other
namespace that `C`'s newest members record names — the namespaces of its
writer prefixes and readers (a group reader by its collection's namespace),
each as the held context governing it says (§3) — joining those groups
first. So the notice reaches every member's devices through the group of
their own namespace, which every forwarder holding that namespace carries
to its devices; no group needs to reach outside its namespace.

**Hearing.** The group only says "`D` moved". It carries no data and
decides nothing: a reader that hears it in any group fetches `D`'s root for
the group's namespace and for every other namespace it follows that `D`
writes into — `D`'s own, and each one of whose collections a members
record it holds lists a writer of `D`'s namespace (§7). The devices a
reader looks at for a namespace `O` (its first look, a watch, a key) are
those it heard in `O`'s group and those it heard in any group that write
into `O` by the same rule. Sync Interests are unsigned; a stranger in a
group costs a reader a root fetch, never a wrong answer. A device's
counter in a group starts at its log head when it joins, so it stays above
anything an earlier run of the same key announced.

The group needs no configuration, and no forwarder treats its name
specially: a forwarder carries it with an ordinary strategy choice and
ordinary routes, which the libraries that already know the namespace's
membership install from data the forwarder holds.

- **Strategy (trust-context and link libraries).** A forwarder that holds
  `O`'s trust context runs `<O>/32=sync` with the multicast strategy from
  the moment it holds the context — held at start, or adopted later
  (`ndn_namespace::sync_group`). A newer version of the context leaves the
  choice as it is. A relay that serves `O`'s devices without holding `O`
  runs the group with multicast while `O` is in transit there, from the
  first served device of `O` linked until the last one leaves
  ([ndn-link.md](ndn-link.md) §15.7).
- **Routes (link library).** A link carries `O` when its peer was admitted
  in `O`: as a member of `O`, held here, or as a device the forwarder
  serves for `O` without holding it. Such a link gets a route for
  `<O>/32=sync` beside the routes it gets for the peer's device name or
  namespace (`ndn_link::group_routes`), with the same lifecycle: added when
  the link is up, taken when a revocation takes the link's last membership
  in `O`, and gone with the link's face when the link ends. An enrollment
  link carries no group.
- **Members.** A device registers `<O>/32=sync` for its own sync face when
  it joins and does nothing else for the group. Its registration sits
  beside the link routes in the same entry, so the multicast strategy sends
  each Sync Interest to the local member and over every link that carries
  `O`, never back toward the face it came from.

A forwarder that neither holds `O` nor serves its devices (a hub with
default routes) forwards the group like any other name. A forwarder learns
no route from the face a Sync Interest arrived on.

**Reaching other people.** A person's devices reach another person's when
their forwarders link — directly (each names the other's device in a peer
entry) or through a relay both use — and hold each other's trust contexts
(§3). A forwarder routes a namespace it follows (holds without a
certificate in it) over every relay it uses, as it routes its own: one its
person added, and one its namespace advertises in its trust context
([ndn-link.md](ndn-link.md) §10, §15.5). The other person's device names
and, by route inheritance, their group go to the relay. The relay needs no
context of the people it carries: it serves their devices against their
roots (`open`, or `listed`), routes each linked device's name, its issuers'
key names and its namespace's group to it, runs the group with multicast
while the namespace is in transit, and forwards their Data unvalidated; the
devices validate it end to end, fetching the chain from the device that
signed it. Two people who each advertise a community relay and adopt
each other's anchor link reach each other with no further step. Nothing is
routed by hand and no route is learnt from traffic: the routes come from
the links' admitted identities and the contexts held, the groups a device
publishes into from the members records it holds.

## 13. Custody — slice 3

### 13.1 Large payloads

A version's payload `P` — `Fields` and `MergeOp` as §16.2 encodes them, or
its sealed ciphertext (§9) — of more than 6,144 octets (`INLINE_MAX`)
travels in pieces, in a log collection only: a merge collection carries
every operation inline, so `put` of a larger payload answers `TooLarge`
(next step: put it into a log collection and refer to it by name), and a
reader refuses a version in pieces of a merge collection (`NotInline`).

- Chunk `i` is `P[4096·i ..]`, at most 4,096 octets, the packet
  `<V>/seg=<i>` (`V` the version's name, `seg=` a SegmentNameComponent).
- The manifest tree lists the chunks with fan-out 128: depth `d` is the
  least `d ≥ 1` with `128^d` at least the number of chunks; nodes are
  numbered in heap order from the root (0; the children of node `k` are
  `128k+1 …`), the bottom level listing chunks, the others nodes. Node `k`
  is the packet `<V>/32=manifest/seg=<k>`, Content `Digest*` in order.
- Every piece is DigestSha256-signed; a Digest is SHA-256 of the child's
  whole Data packet (the implicit digest), as in summaries (§7). The signed
  VersionRecord carries `Chunks` (`Size`, `Digest` of the root node) in
  place of `Fields`/`MergeOp` — or, sealed, after a `Sealed` carrying only
  its `SealEpoch`. So each piece verifies on its own from wherever it came,
  and a sealed payload stays sealed in pieces: holders see the size.
- A reader lists such a version with `Payload::Large { size }` and reads it
  whole on `get` of its name (or of the log collection's newest): each
  piece from its store, else by name, else from each holder of a live lease
  it knows (§13.2) by the Interest `<H>/32=held/<Name TLV>`, which the
  holder answers (DigestSha256) with the packet inside; a piece that is not
  the one its parent lists is dropped and fetched elsewhere.

### 13.2 Hold records and leases

- A **hold record** is an entry of an owner device's log about collection
  `C` (Content `HoldRecord`: `C`, `Copies`, `KeepUntil` — until when — and
  the `Frontier` the asker had applied). It is the custody policy, taken
  only when owner-signed (the owner rule, §3). `hold(C, {copies, until})`
  signs one when the device's newest differs.
- A **lease** is an entry of the holder `H`'s log about `C` (Content
  `LeaseRecord`: `C`, the hold record's name, `KeepUntil`, and the
  `Frontier` `holds`). It promises every version of `C` inside `holds` that
  applies — admitted by the record in force, not pruned — with its pieces,
  each until the earlier of the lease's date and the version's keep. The
  newest lease of a holder for `C` supersedes its older ones. Both records
  are listed in summary nodes under `MembersEntries`, which from slice 3
  lists every entry of a collection that is not a version.
- **Keep caps hold.** A lease's date MUST NOT pass the hold record's, nor
  the latest `Keep::Until` date of the versions inside `holds` when every
  one of them is kept until a date. A holder signs no lease that would end
  by its clock, and a reader does not count a lease that breaks either
  bound (or whose hold record or versions it does not hold yet). Retention
  by expiry — deleting at keep — is slice 4.
- **Asking.** The owner device asks a holder with the Interest
  `<H>/32=hold/<HoldAsk>` (the hold record's name). A device holds only for
  the namespaces its host lists; it verifies the record, follows `C`, takes
  every version inside the record's frontier with every piece (fetching
  back what it lost: re-replication), signs the lease over what its store
  holds whole and answers with it (a DigestSha256 Data whose Content is the
  lease's packet). It signs a new lease when what it holds grows. Holders
  publish once into the groups of the namespaces they hold for, so owner
  devices know whom to ask. A holder serves every entry and piece of a
  collection it holds, whoever wrote it, by its own name and under
  `<H>/32=held/…`.

### 13.3 Audits

- Each `hold` audits every live lease: from the device's randomness it
  draws pieces (16 by default) uniformly from what the lease promises — the
  log entry of each version inside `holds` that applies and whose keep has
  not passed, and each manifest node and chunk of it — and asks each with
  the Interest `<H>/32=audit/<AuditAsk>` (`Nonce`, 16 fresh random octets,
  and the piece's name). `H` answers under that name, signed by its device
  key, FreshnessPeriod 0, `AuditAnswer`: the piece's whole packet, or
  `Missing`. A holder answers only for collections it holds.
- Verdict: **kept** when every answer is signed by `H` and is the piece (its
  digest is the one the auditor holds: the version packet's, or the one its
  manifest lists); **broken** when a signed answer is `Missing` or not the
  piece — signed evidence; **unanswered** when some ask got no answer.
  Only evidence makes a lease broken: a timeout is never a verdict, so a
  slow network can only cause a copy more, never a wrong judgement.
- **Repair.** A lease broken or unanswered, or one that holds less than the
  hold record asked, does not count. `hold` asks its holder again (it
  fetches back what it lost, from the writer or other holders), then the
  other devices heard in the namespace, in name order, until `copies`
  leases are live, hold what was asked and are audited kept.
- **Release.** A host MAY drop its own chunks of a large version that a
  live lease it audited kept holds (`Device::release`); otherwise it
  answers `NotHeld` (next step: hold first).

### 13.4 What a holder can and cannot do

- It cannot forge, alter or substitute data: every piece verifies against
  the writer's signature through the manifest. It cannot pass an audit for
  a piece it cannot produce when asked: the nonce makes every ask a new
  name, so no cache and no earlier answer answers it, and the pieces are
  the auditor's choice. A holder keeping a fraction `f` of what it promised
  passes one audit with probability at most about `f^16`.
- It cannot read sealed data it holds without being of the audience: it
  stores and serves ciphertext (§9 lists the metadata it sees).
- It cannot keep its promise past keep and be counted, nor extend a lease
  past the owner's date.
- It can fetch an asked piece from elsewhere at audit time (an audit proves
  it can produce the data, not that it stored it); two holders can collude
  that way, so `copies` holders owned by one party are one failure domain.
  It can stop answering: its lease becomes unanswered and repair starts,
  but nothing marks it broken without evidence. It sees which pieces are
  asked, and when.

## 14. Prune — slices 2 (scope), 3

A prune is an entry of the pruner's log about collection `C` (Content
`PruneRecord`: the prefix — `C` or one of the pruner's version names in it
— and the `Frontier` `upto`). It spreads like data.

- A prune MUST cover only versions the pruner wrote. A device asked to
  prune a log entry of another device, or up to a frontier naming another
  key, MUST refuse with `NotOwnWrites`, whose next step is to edit instead:
  removing another writer's data in a shared collection is an edit (a merge
  edit that removes the field) every reader applies, and the author's own
  version stays theirs, readable by its name. A reader ignores a prune
  record that names another key.
- It covers the signer's versions of `C` (or the one version named) with
  seq at most `upto`'s for its key. Prune applies to log collections: a
  merge collection's state is computed from every version, so `prune`
  answers `NotPrunable` (next step: edit instead).
- A reader that knows a prune MUST report `Pruned` for what it covers, not
  the data, drop its copies (record and pieces), tell its watchers
  (`Change::Pruned`) and serve none of it; later versions do not wait for
  it. A holder drops it too: its leases end for it, and audits never ask
  for it. The writer keeps a local tombstone so its summary still lists the
  entry (the log never changes).
- **What "erased" means.** A device destroys the key of epoch `E` of `C` —
  the key it holds, the key it made, the grants it kept — once `E` is not
  the record in force's epoch and every version of `C` it knows sealed in
  `E` is pruned; it then refuses that key if granted again. From then on
  every copy of that ciphertext anywhere, in any holder, cache or backup,
  is unreadable to whoever did not keep the key. Not erased: what a reader
  already opened (plaintext it kept, forward-only, invariant 9); a key a
  device copied out of the layer; versions of an epoch that still has
  unpruned versions — those are deleted by honest devices and holders
  only; and copies in caches, which expire by their own policy.
- **What a pruner can and cannot do.** It drops only its own versions; it
  cannot end another writer's data or another holder's promise for it, and
  it cannot recall copies already made.

## 15. Verbs — slices 1–3, host surface slice 7

| Verb | Shape | Slice |
|---|---|---|
| `get` | `get(name) → version or state + age` | 1 |
| `put` | `put(collection, content, {type, keep}) → (writer, seq)` | 1 (`batch`: 4) |
| `watch` | `watch(collection, since F) → summary, new versions…` | 1 |
| `snapshot` | `snapshot(names \| collections) → snapshot` | 1 |
| `hold` | `hold(prefix, {copies, until}) → custody` | 3 |
| `prune` | `prune(prefix, upto)` | 2 (refusing others' writes), 3 |
| `share` | `share(collection, {rule, readers, writers})` | 1 (adding), 2 (removing, the rule) |

Code mostly uses `get`, `put` and `watch`. `hold`, `prune` and `share` run
on host policy, or on the person's gesture. A function's answer is a `get` on
its name (slice 6). Exposure over forwarder management and the mobile FFI is
slice 7. A device answers a verb or option of a later slice with an error
that names the slice.

- **`get(C)`** of a merge collection answers its state now — `State` with a
  state name, `at` and the value; of a log collection, its newest version
  (§5) — with `Age::Newest`: the time since the device last knew nothing
  newer was outstanding in `C`'s sync group (it heard the group with no
  refresh pending, or finished one), measured on its monotonic clock. The
  first `get` of a collection the device does not follow looks at what the
  devices known to write into its namespace hold first (§12); a reader of a
  sealed collection holding versions it has no key for yet waits as long
  for the keys it asks for. Nothing held: `Unavailable`. Not of a sealed
  collection's audience: `Sealed`.
- **`get(state name)`** answers that exact state (`Age::Exact`), §11.
- **`get(log entry name)`** answers the version or snapshot (`Age::Exact`),
  fetching it when not held; a members record is not a version
  (`NotFound`); a refused entry answers `Refused` with the reason; a
  version sealed to an audience the device is not in, `Sealed`.
- **`put(C, content, {type, keep})`** signs the next entry of the device's
  log with parents = the state's `at`, applies it, and publishes it (§12).
  It requires a members record that lists the device's key among the
  writers; for a collection of another namespace the device first looks for
  one, and answers `Unavailable` when no device writing into that namespace
  was heard, else `NotAllowed`. In a sealed collection it seals the payload
  (§9), asking for the epoch key first if it lacks it: `Sealed` when it is
  not of the audience, `Unavailable` when no device granted the key.
- **`watch(C, since F)`** reports every held version of `C` (or of the
  collections under folder `C`, which may be `<O>/32=data`) outside `F`,
  then every version applied later, the summaries of §7, each outside `F`,
  and every version withdrawn (§8); it starts a refresh of every device
  known to write into the namespace. The stream ends when the device stops.
- **`snapshot(names)`** pins, for each name, the current state name of a
  merge collection or the exact name of a version or snapshot, and signs
  the `SnapshotRecord`.
- **`share(C, {rule, writers, readers})`** signs the next members revision
  (`C` of the device's own namespace only, §3: else `NotOwner`), with the
  cuts, epoch and `Since` of §6. A collection sealed to a group moves to a
  new epoch when the group drops a reader, signed by a device of the
  collection's own namespace (§6), whoever owns the group.
- **`hold(C, {copies, until})`** (a device of `C`'s namespace, else
  `NotOwner`) signs the hold record, audits every live lease and repairs
  (§13), and answers `Custody`: the live leases with this device's audit
  of each, and those found broken or unanswered before repair.
- **`prune(prefix, upto)`** of another device's entry, or up to a frontier
  naming another key, answers `NotOwnWrites`; of a merge collection,
  `NotPrunable`; else it signs the prune record and publishes it (§14).
- A verb given a name it cannot take answers `BadName` (§3).

## 16. Wire format — slices 1–3

### 16.1 Names

`D` is the device name, `C` a collection, `O` a namespace, `X` a name of a
summary tree: `O/32=data` or `O/32=data/<path>`, a folder or collection.
`32=` is a KeywordNameComponent, `seq=` a SequenceNumNameComponent (0x3A),
both from the NDN naming conventions.

| Name | Form |
|---|---|
| namespace `O` | one or more components; none a keyword, digest or `seq=` |
| device `D` | one or more components; none a keyword or digest |
| collection `C` | `<O>/32=data/<path>`, one or more path components; none a keyword or digest |
| folder | `<O>/32=data[/<path>]` (a watch target, a summary node) |

| Packet | Name | Signature |
|---|---|---|
| version, members record | `<D>/32=log/<C>/seq=<n>` | device key |
| snapshot | `<D>/32=log/seq=<n>` | device key |
| summary root of `O` | `<D>/32=summary/<O>/seq=<head>`, FreshnessPeriod 0 | device key |
| summary node of `X` | `<D>/32=summary/<X>/seq=<head>` | DigestSha256 |
| summary page of `X` | `<D>/32=summary/<X>/32=page/<buckets>/seq=<head>` | DigestSha256 |
| state (never fetched) | `<C>/32=state/<Frontier TLV>` | — |
| sync group | `<O>/32=sync` (State Vector Sync Interests) | — |
| seal key | `<D>/32=seal/<public key>`, Content `SealKey` | device key |
| grant | `<G>/32=grant/<GrantAsk TLV>`, Content `Grant` | the granter's device key |
| hold, lease, prune record | `<D>/32=log/<C>/seq=<n>` | device key |
| chunk of version `V` | `<V>/seg=<i>` | DigestSha256 |
| manifest node of `V` | `<V>/32=manifest/seg=<k>`, Content `Digest*` | DigestSha256 |
| hold ask (answer: the lease's packet) | `<H>/32=hold/<HoldAsk TLV>` | DigestSha256 |
| held packet (answer: the packet) | `<H>/32=held/<Name TLV>` | DigestSha256 |
| audit ask and answer | `<H>/32=audit/<AuditAsk TLV>`, Content `AuditAnswer`, FreshnessPeriod 0 | the holder's device key |

`<buckets>` is a GenericNameComponent whose octets are the buckets taken
from the node, one octet (0–15) each. Log entries are named after the
writer's device, not the collection, because a writer of another namespace
can only sign under its own (`/bob/laptop/32=log/alice/32=data/docs/plan/seq=3`).
Data packets carry no MetaInfo besides the root's FreshnessPeriod;
ContentType is BLOB.

Every name parses one way, and a reader MUST refuse one that does not:

- **Collection.** The namespace is the components before the first
  `32=data`; the path, the ones after it. A name with no marker, nothing
  before it, nothing after it, or another keyword or digest component is
  no collection.
- **Log entry.** `D` is the components before the first `32=log` (`D` has
  no keyword); the last component is `seq=<n>`; what lies between is empty
  (a snapshot) or a collection name.
- **Summary.** `D` is the components before the first `32=summary`; a last
  `seq=` component is the head; a `32=page` then the next-to-last
  component is the page. What remains is the subject: a namespace (the
  root) or a folder or collection name. Only a root's discovery name
  `<D>/32=summary/<O>` lacks the head — a namespace never ends in `seq=` —
  so a node or page name always carries it, and the subject's own last
  component is never read as the head. A subject without a marker is a
  namespace, never a node under one.
- **State.** `32=state` is the next-to-last component and the collection
  name precedes it.
- **Seal key.** `D` is the components before the first `32=seal`; one
  GenericNameComponent of 32 octets follows, the X25519 public key, equal
  to the `SealKey` the packet carries.
- **Grant.** `G` is the components before the first `32=grant`; one
  GenericNameComponent follows whose value is one `GrantAsk` TLV: a seal key
  name, a collection Name and a `SealEpoch`.

### 16.2 TLV-TYPE numbers

The data layer uses 0x0520–0x057F (registered in
[README.md](README.md#tlv-type-numbers)). Every number is even: a decoder
MUST skip an unknown even TLV inside these records and MUST refuse an
unknown odd one, so a later revision can add fields old readers pass over
(and fields they must not).

| Type | Name | Value |
|---|---|---|
| 0x0520 | VersionRecord | Name (collection), Frontier (parents), TypeId, Seal, Keep, Dated, then Fields, MergeOp — or, sealed, Sealed |
| 0x0522 | Frontier | FrontierEntry*, by writer |
| 0x0524 | FrontierEntry | Name (writer key), Seq |
| 0x0526 | Seq | NonNegativeInteger |
| 0x0528 | TypeId | Name, Revision |
| 0x052A | Revision | NonNegativeInteger |
| 0x052C | Keep | one of KeepUntil, KeepLastN, KeepForever |
| 0x052E | KeepUntil | NonNegativeInteger, ms since the Unix epoch |
| 0x0530 | KeepLastN | NonNegativeInteger |
| 0x0532 | KeepForever | empty |
| 0x0534 | Seal | Audience* |
| 0x0536 | Audience | AudienceKind, Name |
| 0x0538 | AudienceKind | NonNegativeInteger: 0 person, 1 device, 2 group |
| 0x053A | Dated | NonNegativeInteger, ms since the Unix epoch |
| 0x053C | Fields | Field*, by name |
| 0x053E | Field | FieldName, FieldValue |
| 0x0540 | FieldName | UTF-8 |
| 0x0542 | FieldValue | octets; empty removes the field |
| 0x0544 | MergeOp | octets: the merge function's operation |
| 0x0546 | MembersRecord | Name (collection), Revision, Rule, Writers, Readers, [Cuts], [SealEpoch, KeyCheck], [RuleSince], [Seq, Digest] (the parent, from revision 2: its revision, one below this record's, and the SHA-256 of its `MembersRecord`, §6) |
| 0x0548 | Rule | RuleKind [Name (merge function)] |
| 0x054A | RuleKind | NonNegativeInteger: 0 one key, 1 log, 2 merge |
| 0x054C | Writers | Name* (key-name prefixes) |
| 0x054E | Readers | Audience* |
| 0x0550 | SnapshotRecord | Name* (pins) |
| 0x0552 | SummaryNode | Name (subject), Writer, Seq (head), [PagePath], [Entries], [MembersEntries], [Children \| Pages] |
| 0x0554 | Entries | SeqRange* |
| 0x0556 | MembersEntries | SeqRange* |
| 0x0558 | SeqRange | Seq (low), Seq (high), low ≤ high; a list of them is ascending and disjoint, and a summary node's lie at or below its Head and hold at most 65,536 seqs together (§7) |
| 0x055A | Children | Child*, by component |
| 0x055C | Child | Name (one component), Seq (head), Digest |
| 0x055E | Digest | 32 octets: SHA-256 of the child's whole Data packet; in a `MembersRecord`, of the parent's `MembersRecord` (§6) |
| 0x0560 | Pages | Page*, by bucket |
| 0x0562 | Page | Bucket, Seq (head), Digest |
| 0x0564 | Bucket | NonNegativeInteger 0–15 |
| 0x0566 | PagePath | octets, one bucket each (pages only) |
| 0x0568 | Writer | Name (the writer's key) |
| 0x056A | Cuts | Cut*, by prefix |
| 0x056C | Cut | Name (removed writer prefix), then per key it keeps versions of, by key: Writer, Entries (exactly those seqs, §8) |
| 0x056E | SealEpoch | Name (the device that signed the record starting it), Seq (that record's seq) |
| 0x0570 | RuleSince | Frontier: what the owner had applied when the rule changed, or when it sealed the collection |
| 0x0572 | Sealed | SealEpoch, Ciphertext |
| 0x0574 | Ciphertext | octets: nonce (12) ‖ tag (16) ‖ ciphertext, ChaCha20-Poly1305 |
| 0x0576 | SealKey | 32 octets: X25519 public key |
| 0x0578 | GrantAsk | Name (the asker's seal key), Name (collection), SealEpoch |
| 0x057A | Grant | EphemeralKey, Ciphertext (the key, wrapped) |
| 0x057C | EphemeralKey | 32 octets: the granter's X25519 public key for this grant |
| 0x057E | KeyCheck | 32 octets: HKDF-SHA256 of the epoch's key (§9) |
| 0x0521 | Chunks | Size, Digest (the root manifest node's packet), in a VersionRecord in place of Fields and MergeOp, or after a Sealed without Ciphertext (§13.1) |
| 0x0523 | Size | NonNegativeInteger: the payload's octets, more than 6,144 |
| 0x0525 | HoldRecord | Name (collection), Copies, KeepUntil, Frontier (what the asker had applied) |
| 0x0527 | Copies | NonNegativeInteger |
| 0x0529 | LeaseRecord | Name (collection), Name (the hold record), KeepUntil, Frontier (what it holds) |
| 0x052B | PruneRecord | Name (collection or version), Frontier (up to) |
| 0x052D | HoldAsk | Name (the hold record) |
| 0x052F | AuditAsk | Nonce, Name (the piece) |
| 0x0531 | Nonce | 16 octets, fresh random per ask |
| 0x0533 | AuditAnswer | Piece or Missing |
| 0x0535 | Piece | octets: the piece's whole Data packet |
| 0x0537 | Missing | empty |

Slice 3's numbers are odd — critical — because the even ones of the block
are taken and because a reader that does not know them must not pass over
them: a version in pieces read as one without a payload, or a hold, lease
or prune record mistaken for nothing, would be wrong, not stale.

Names are the Name TLV (0x07). Inside a record, fields appear in the order
the table lists them; lists are sorted as stated, so equal content encodes
to equal bytes and equal nodes have equal digests.

### 16.3 Why these encodings

- **Reused:** the Name TLV, NonNegativeInteger, typed name components
  (keyword, SequenceNum), DigestSha256 and the implicit digest, ndn-svs v2
  for the notice, the hierarchical trust schema and the existing validator.
- **New records** because nothing existing carries them: a frontier (no NDN
  encoding of a version vector exists outside SVS's unsigned state vector),
  a version's parents/type/seal/keep/fields/operation, a members record, a
  snapshot's pins, and a Merkle summary node. SVS-PS mapping data was not
  reused: it maps one group's own sequence numbers to names, while a
  writer's log here spans many collections and its index must be signed and
  nested.
- **Pages** keep every summary packet small (at most 64 references) so a
  changed note in a folder of any size costs a logarithmic number of packets.
- **Seals reuse** `ndn-security`'s confidentiality content key
  (ChaCha20-Poly1305) and its key wrap `wrap_ck`, which seals a key under
  a key-encryption key. `wrap_ck` needs a key-encryption key both ends
  already share, and two people's devices share none: their only keys are
  signing keys (Ed25519 or P-256, possibly in a TPM or a YubiKey that signs
  and cannot agree keys). The one addition, `wrap_ck_to`, is the agreement
  that makes that key: an ephemeral X25519 key against the reader's
  published X25519 seal key, HKDF-SHA256 into the key-encryption key, then
  `wrap_ck`. Epoch keys, not the in-tree `ndn_security::abe` (rabe,
  opt-in): an audience here is a short list of people, devices and groups
  the owner's devices check against the owner-signed record they hold, so
  ABE's attribute authority is not needed — and would not remove the
  agreement, since an authority must deliver each reader's attribute keys
  confidentially too (`ndn-nacabe` does it with an X25519 sealed box);
  rabe's curve gives about 100-bit security and pairing crypto is heavy
  for phones and the browser build. ndn-ext's `ndn-sealed-box` does the
  same agreement but cannot be used from ndn-rs, and takes only ephemeral
  recipient keys.
- **Random epoch keys and a key check**, not keys derived from a secret
  per device: a derived key exists before its epoch does, so a reader
  could collect the keys of epochs to come, and every holder of the secret
  could never be left out of an audience. One random key per epoch costs a
  grant per epoch per reading device; the check (HKDF, the one key
  derivation of the layer) lets a reader verify any granted key against the
  owner-signed record, so any holder of the key may grant it.
- **Exact cuts** reuse `Writer` and `Entries`, the summary node's own
  fields for "this key's seqs", rather than a frontier: a frontier is a
  limit, and a cut must not be one (§8).
- **Pieces reuse** RDR's shape (segments under the object's name, one
  manifest the only signed root, DigestSha256 segments) and the summary's
  digest-of-packet links; RDR's flat manifest (`ndn-app`, TLV 0xF504) caps at
  256 segments and lists payload hashes, so the tree here is FLIC-like
  instead: nested, any size, digests of whole packets, the root in the
  signed record. A holder is asked for another producer's packet under its
  own name (`32=held`), which routes like any of its names; a forwarding
  hint would need every forwarder on the way to route the hint, which the
  link layer does not promise.
- **Leases and holds are log entries**, so they spread through summaries
  like everything else and carry the writer's own monotonic order; the
  audit answer is the one per-ask signature, under a nonce name no cache can
  hold.
- **A members record's parent** reuses `Seq` and `Digest`, the pair a
  summary's child and page name their packet by, in a position of its own
  rather than a new number: both are even, so a reader of the previous
  revision of this format passes over them and merges concurrent records
  by intersection, as it did. The digest is of the parent's Content
  because the record in force may be a merge no packet carries (§6).

## 17. Failure model

| Failure | Required behaviour | Rests on |
|---|---|---|
| Partition / offline | Reads and writes continue locally under each device's key; collections reconcile from summaries when a path returns. | §4, §7 |
| Lost device | Its leases lapse; repair copies elsewhere; a cut ends its key at what others had seen. | §8, §13 |
| Compromised key | The cut keeps what was signed before it and refuses the rest; sealed data re-keys forward. | §8, §9 |
| Bad or lying clock | No effect on validity. | invariant 1 |
| Member removed mid-edit | Edits inside the removal cut merge; later ones are refused, and a reader that applied one before the cut arrived withdraws it and says so. | §6, §8 |
| Holder withholds | The summary shows what is missing; fetch from another holder. | invariant 4 |
| Holder rolls back | A summary older than one already seen is refused, also by a reader that restarted since. | invariant 3, §7 |
| Writer never pauses | Each descent finishes against the root it started from, whose nodes the writer keeps serving; the reader then continues from there and keeps up. | §7 |
| Writer equivocates | Both versions are kept and reported. | invariant 2 |
| Old software writes | Unknown fields survive its edit. | invariant 8, §10 |
| Poisoned cache | Verification fails; the version is dropped and fetched elsewhere. | invariant 1, §4 |
| Stranger in a sync group | Costs a root fetch; its entries are refused `NotMember`. | §6, §12 |
| Removed reader | Refused every grant; the key of the epoch its removal starts did not exist before it, so the new epoch's versions stay closed to it; what it opened before it keeps. | §9 |
| Owner's devices edit members at once | Records of one revision merge against the parent they name, keeping every addition and removal, removals winning (by intersection when the parent is not held); a merge that leaves a removed reader in the epoch is resolved by a new record in a new epoch. | §6 |
| Group member removed | Every collection sealed to the group, of any owner, moves to a new epoch signed by a device of its own namespace. | §6 |
| Own device left out | An audience that does not list it leaves it out of the epoch and every later one; no device holds a secret that yields future keys. | §6, §9 |
| Removed writer fills a gap | A new entry at a seq below what its cut kept is refused: the cut lists exactly the versions kept. | §8 |
| Wrong key granted | Refused against the epoch's key check; the right key from any device is taken. | §9 |
| Writer behind on a seal | Its unsealed version is refused `Unsealed`; its later sealed versions do not wait for it. | §5.2, §9 |
| Relay or repository of another person | Carries ciphertext and grants wrapped to one device each; reads no payload and no key, and sees the metadata §9 lists. | §9 |
| Member offline | Its newest verified summary is what the reader is complete against; it catches up when the member returns. | §7 |

## 18. Conformance

`ndn-data-conformance` (ndn-sim) runs the study's use cases against an
implementation. Each case names the features it needs; a provider that
lacks one is reported "not implemented", naming it. The slice-1 cases are
c1 (offline notes on two devices, in the two-component namespace
`/home/bob`), c7 (an older lens keeps a newer field),
c8 (a laptop back after four months: 10,000 notes, 37 changed), c11
(citing a merged state) and o4 (a reader keeps up with a writer that never
pauses: it holds everything written before it looked, then every later
moment's versions, while the writer keeps putting and a second reader
makes it sign a new root many times a second). The slice-2 cases are c2
(Bob removed while offline: his later edit is refused whatever its date),
c4 (a note sealed to Alice opens for her host, and a device outside the
audience cannot read it), c9 (a family chat under the log rule: members'
messages reach every member, a non-member's post reaches no one), c10
(prune of another's comment refused, the removal done as an edit), o1 (a
cut that arrives after a version was accepted withdraws it), o3
(completeness with many writers, measured: a full check of every member's
summary and the catch-up of one new version, with 8 and with 32 writers),
and the slice-2 security review: r1 (two of the owner's devices remove
readers at once; neither removed reader opens what is written after), r2
(a member leaves a group another person's collection is sealed to; that
collection moves to a new epoch), r3 (the owner lists one of her devices
alone; her other device opens nothing written after) and r4 (one of the
owner's devices adds Carol while another, offline, removes Bob, both from
one record; Carol then writes and reads everywhere, Bob's later edits are
refused and he opens nothing written after).

The slice-3 cases are c5 (a photo the repo leased is pruned: no lease
outlives keep, readers report it pruned), h1 (a photo of hundreds of pieces
read whole and verified), h2 (a holder that silently lost what it leased is
caught by audit and repaired, and released data stays readable from it), h3
(a holder keeping three quarters of what it promised fails its audit), h4
(no lease outlives keep, before or after the keep passes), h5 (prune ends
leases: the holder drops what it covers, audits never ask for it) and h6
(sealed data held by a device outside its audience stays unreadable to it
and readable from it).
