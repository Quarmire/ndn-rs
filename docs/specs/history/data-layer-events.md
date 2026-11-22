> Superseded by NAME.md at ndn-rs <commit>. Kept for history; nothing here is normative.

# Device events text cut from `data-layer.md`

Device events (round 5: what no folder owns, told on one acknowledged, bounded stream; TLV 0x05E0–0x05FE) were removed from the data layer. The block 0x05E0–0x05FE is freed and quarantined, not reused. Equivocation evidence (§2, §4) and `Change::Equivocation` / `Change::Withdrawn` (§15) are not events and stay in `data-layer.md`. What follows is the text as it stood, in the order of `data-layer.md`.

## Header: Status (before §1)

- **Status:** Slices 1–6 normative, with device events (§21: what no folder
  owns, told on one acknowledged, bounded stream) and the durability barrier (§4.2:

## §2 Invariants: what two entries are (the lines that changed)

  never equivocation: no second packet is stored, no `Change::Equivocation`
  is told and no event is made (§21.3). ECDSA signatures are malleable in the

## §15 Verbs: what follows the introductions paragraph

Also beside the verbs, a `Device` tells its host what no folder owns on one
stream (§21): `events(after) → stream of events`, `pending_events()` and
`acknowledge(ids)`, delivered at least once and kept across restarts until
acknowledged; an event reports what the device already did and never
decides anything, and a watch keeps telling every `Change` it tells.

## §16.2 TLV-TYPE numbers (the lines that changed)

The data layer uses 0x0520–0x057F, 0x05B0–0x05BF for an introduction
code's link hint and a short code's hint record (below), and 0x05E0–0x05FE for the records a device keeps
of its events in its own store, which are never on the wire (§21.7), registered in
[README.md](README.md#tlv-type-numbers). A number is even unless the notes

## §17 Failure model (the last paragraph)

**Events under failure (§21).** A device's events are written with its other
local state and are behind the barrier with it (§4.2). A store whose flush fails
publishes nothing (§4.2) and makes `acknowledge` answer `Local`, naming the
barrier, until it succeeds; an event is never the reason a verb waits or fails,
and no verb's answer reads one. A host that never acknowledges costs a bounded
store: at most the cap of events, an overflow notice and the tombstones (§21.5);
one that acknowledges what it never saw is refused whole (§21.4). A device that
stops ends every stream; one that starts again delivers what was not
acknowledged (§21.6).

## §18 Conformance (the last paragraph)

Round 5's device events (§21) have their own cases, each also on the faulty
profile: v1 (Alice's laptop is copied; the copy signs a folder members record
at the seq the laptop signs a version at; Bob's and Carol's devices each
report the equivocation, a version against a members record, with both
entries by name, kind and digest and nothing of what they say), v2 (Alice
removes Bob on a plane; Carol accepts his next edit; when the cut arrives
Carol's device reports the cut and the withdrawn edit, though no one watches,
Bob's reports the cut, and Alice's, which signed it, does not), v3 (a
revocation adopted late is told with what it withdraws on a device no one
watches), v4 (an event not acknowledged is delivered again after a restart,
one acknowledged is not, an id never seen is refused) and v5 (thirty
equivocations of one key are one event and the cut event kept before them is
unchanged, the store's records not growing).

## §21 Device events (whole section)

## 21. Device events — round 5

What no folder owns: two different entries of one key at one seq (a members
record against a version included), entries withdrawn, cuts that took effect
and revocations adopted. A folder's `watch` tells the changes of the
collections under it (§15, `Change`); an event is told on the device, to its
host, whether or not anything is watched, and carries the evidence, what the
device already did and what to do. A `Device` offers `events(after) → stream`,
`pending_events()` and `acknowledge(ids)`; they are additional to the seven
verbs, as introductions (§19) are, and change none of them.

### 21.1 What an event is, and is not

- **An event reports; it never decides.** Everything an event says was done
  fail-closed before the event exists: both entries kept (§4), an entry
  refused (§8), a version withdrawn (§15), a key's later entries refused
  outside its cut. A device MUST NOT read an event to decide anything: no
  admission, walk, answer or serve depends on whether an event was made,
  delivered, acknowledged, coalesced or not kept. Events are a report, not the
  record; the record is the signed entries the device holds, and the evidence
  of an event MUST stay re-derivable from them (§21.5).
- **An event carries only what this device verified.** It is made from an
  entry the device verified and took (its signature, its chain and its
  admission judged as §3 and §8 say), from a members record taken as
  owner-signed (§6), or from a trust context its keyring adopted (§8). A
  packet that fails verification is refused before any of these and is never
  evidence. What a peer can cause is what it can already cause: an event
  exists only because the peer presented an entry the device verified.
- **An event carries names, never content.** The evidence is entry names,
  kinds, implicit digests, key names, versions of a trust context and counts.
  An event MUST NOT carry a version's fields, payload, operation or block
  entries, opened or not, nor anything of a collection its reader cannot
  read: the entry of another collection is given by its name, as
  `Equivocal::Elsewhere` gives it (§15). A host that wants more reads it with
  `get`, under the rules that govern a read.
- **An event is never published.** It lives in the device's own reserved
  namespace of its store (§21.6), under no prefix a device serves, in no
  summary, head, notice or lease; no peer can ask for one, and nothing
  of it is sent in answer to any Interest.

### 21.2 The event

| Field | Meaning |
|---|---|
| `id` | 16 octets: the first 16 of SHA-256 over `"ndn-data/event/1"` and the event's first detail as stored (§21.7); of an overflow notice, over `"overflow"` and its cursor. Equal on every device that derives the same evidence, and stable across restarts: a host deduplicates by it |
| `cursor` | the order of delivery on this device: strictly increasing, never reused, held in a durable counter (§21.6) |
| `first_seen` | this device's clock when it first reported the event; display only, as every date (§2) |
| `detail` | the first occurrence's evidence (below) |
| `count`, `last` | how many occurrences the event stands for (the first included) and, above 1, the newest coalesced one (§21.5) |

The kind, subject, meaning, next step and the words for what happened and what
to do follow from the detail, in one place per variant of the enum, so a later
round adds a variant with one arm of each:

| Kind | Subject (with the kind, the coalescing key) | Detail | Meaning (what this device already did) | Next step |
|---|---|---|---|---|
| `Equivocation` | the writer's key | the key, the seq, two entries (each name, kind, digest) | both entries kept as evidence, neither preferred (§4) | `UseOwnerDevice`: a device holding the owner's authority marks the key suspected (§8.1) and revokes it once confirmed |
| `Withdrawal` | the writer's key | the key, the collection, the entry (name, kind, digest), by what: a cut (the key cut and the key that signed it), the chain (the validator's verdict) or its group (the member refused) | the entry no longer counts here; its packet stays held | `AskOwner` for a cut or a chain (the owner may re-admit exactly, §8.2); none for a group |
| `Cut` | the key prefix cut | the collection or folder, whether a folder, the prefix, the signer, the record's log entry name, its revision, how many versions the cut keeps | the key's new entries are refused outside the cut (§8) | none: members(subject) shows the record; the owner can add the writer again |
| `Revocation` | the revoked name | the namespace, the name, the context's version | entries of the name outside its cut, and chains through it, are refused (§8.1) | none: the entries it refuses arrive as withdrawals |
| `Overflow` | this device | how many occurrences of each kind were not kept | events were not kept; the evidence is still held | none: acknowledge what was handled, which makes room |

The kinds are an exhaustive enum, documented as extended by later rounds, not
marked non-exhaustive: a host's `match` gains an arm when a round adds one.

### 21.3 What a device reports

A device MUST report each of these, as it notes the cause, whether or not
anything watches, and MUST NOT report while it reads its store back at start
(§21.6: what it held was reported when it arrived, and the events of that run
are read back with it). After that read it MUST report the revocations, cuts
and withdrawals below that its held state implies and its ledger does not
cover (§21.6), whichever run held the cause first.

- **Equivocation.** A verified entry of any kind — a version, a members
  record, a snapshot, a hold record, a lease, a prune record, an
  introduction's offer or use mark — that a key signed at a seq it used
  before under another entry name (§4: one sequence across collections and
  kinds); and a different packet under a log entry name the key signed
  another packet under, of any kinds (a version and a members record of one
  collection at one seq have one name), different meaning that the digests of
  the two signed regions (name through `SignatureInfo`) differ: another
  signature value over the same signed region — a flipped ECDSA `S`, a
  re-signing — is the same signed object and reports nothing (§4). The
  evidence is the entry first taken
  and this one, each by name, kind (`None` when the device never held it
  whole, as the members record of a signer who is not the owner, which it does
  not store) and digest of the packet verified (`None` when it holds no bytes
  to give one). For two packets under one name, an event needs the digest of
  the first one's signed region to compare, which a device that holds the
  first packet, or noted a record it did not store, has: a device that has
  neither reports nothing for it. A watch of a folder keeps telling `Change::Equivocation` for
  the versions among them (§15); the event is additional. A third entry at
  the seq is another occurrence for the same subject (§21.5).
- **Withdrawal.** A version delivered and refused again, exactly as
  `Change::Withdrawn` tells a watcher (§15: by a cut that arrived, a trust
  context adopted later, or its group, §5.5; and one withdrawn because the
  members record that admitted it is refused), told on the device with no
  watcher needed; and a held members, hold, lease or prune record or snapshot
  that a trust context adopted later refuses (§8), which no watch carries. A
  version refused as it arrived, or held and never delivered, is not
  withdrawn: it is not reported.
- **Cut.** A members record of the collection or folder that this device
  did not sign takes into force a cut the record in force before did not hold:
  one event per key prefix cut. A device MUST NOT report a cut it signed
  itself (its host made the gesture; another device of the owner reports it),
  and MUST NOT report the cuts of records it makes again from those held after
  a record is refused (§8: the removal they carry was reported when first taken).
  The device that receives the record from a second device reports it, as the
  first does.
- **Revocation.** A trust context its keyring adopted (§8) revokes a name the
  context before it for the namespace did not. The first context a device
  holds of a namespace reports none of its own: what it refuses is told as
  withdrawals. The context's cuts are not events: a re-admission, which
  accepts an entry again, is told as the entry's version (§15).
- **Overflow.** §21.5.

### 21.4 Delivery and acknowledgement

- **`events(after)`** returns a stream: the unacknowledged events with a cursor
  above `after`, in cursor order, and then every new event as it is
  reported. It ends when the device stops. It queues nothing that can fall
  behind: each step reads what is kept above the last cursor delivered, so a
  slow host loses nothing and is never told it lagged. `Cursor::default()`
  asks for all of it. An event whose count grows after it was delivered is not
  delivered again; `pending_events()` reads it with its current count.
- **At least once, idempotent by id.** Every call of `events` starts again from
  what is unacknowledged; so does a restart, which reads the events back before
  anything else (§21.6). A host MUST deduplicate by `id` and MAY keep its own
  cursor. A device MUST NOT deliver an acknowledged event again, except that
  it MAY once the tombstone of its id was dropped (below) and the cause is
  derived again, with the same id.
- **`acknowledge(ids)`** removes each event named, leaves a tombstone of its
  id, and returns once the store's barrier (§4.2) has passed: after it
  returns, no restart delivers them. It acknowledges every occurrence
  coalesced into the event so far (a host that wants the count reads it first).
  An id acknowledged already is accepted again, with no effect. An id that is
  neither kept nor a tombstone refuses the whole call with nothing changed:
  `BadRequest` (next step `FixRequest`) naming the id and saying to take ids
  from `events` or `pending_events` of this device. `Local` when the device
  stopped before the acknowledgement was behind the barrier: acknowledge again
  after it starts.
- **Tombstones.** The last `events_acked` (default 1024) acknowledged ids are
  kept, so that an event acknowledged is not delivered again when its cause is
  met again with the same evidence (the id is that of the evidence, §21.2).
  The start-up judgement of held entries does not report what a revocation
  refused: those entries come back refused, silently, and the events a host is
  owed for them are derived from the held state and the ledger (§21.6), which
  an acknowledgement does not touch: an acknowledged event is not made again
  because its fact is entered, tombstone or not. When more tombstones are kept
  the oldest goes; its event may then be reported again, with the same id, if
  its cause is met again and the ledger no longer holds its fact.

### 21.5 Flooding

A peer that can make a device note causes, by presenting entries it signed or
holds, MUST NOT be able to make it keep, store or deliver without bound, and
MUST NOT be able to push out an event already kept.

- **Coalescing.** At most one event is kept per `(kind, subject)`. Another
  occurrence with other evidence is coalesced: `count` grows by one, `last`
  becomes its evidence, the stored record is rewritten in place — no new
  record, no new cursor, no redelivery. The same evidence again changes
  nothing. The first occurrence's evidence stays until the event is
  acknowledged; a flood of one subject is one event.
- **The cap.** At most `events_unacked` (default 256, at least 1) events are
  kept unacknowledged, at most the cap divided by the number of kinds events
  are kept for (four: equivocation, withdrawal, cut, revocation; at least 1)
  of one kind, and at most a quarter of the cap (at least
  1) about one namespace (the one that governs the key or name the event
  names, else its first component), so that a flood of one or two kinds, or
  of the keys of one namespace, cannot take the room of the others. A new
  `(kind, subject)` past any of these limits is not kept: it is counted in the one
  **overflow notice**, an event of its own that carries, per kind, how many
  occurrences were not kept. The notice is outside the cap, is made once with
  its own cursor and delivered as any event, is updated in place as more are
  counted, and is removed by acknowledgement (a later drop then makes a new
  notice, with a new id). Nothing is dropped silently.
- **Nothing kept is evicted.** An event kept is removed only by
  acknowledgement. So a flood of one subject coalesces into its own event; a
  flood of distinct subjects fills the cap and then only grows the overflow
  counters; and the first event of every kind and subject that was kept
  survives until the host acknowledges it, whatever follows.
- **What is lost.** When more distinct `(kind, subject)` pairs arrive than the
  limits keep, the individual events beyond them: counted by kind in the notice,
  not named. Nothing else is lost, because events are a report and not the
  record: the evidence stays held and can be derived again from it — `watch`
  lists the equivocation evidence held of the versions under a name (§15),
  `members` the records in force and the cuts they hold (§15), `get` of a
  withdrawn entry answers its refusal (§8), and the trust contexts held say
  what they revoke. A host that was told of an overflow reads those.
- **Bounded state.** What the store keeps for events is at most
  `events_unacked` + 1 event records, `events_acked` tombstones and one head
  record, whatever the flood; nothing is kept in memory beyond the same.

### 21.6 Where events live, and restart

Events are kept in the device's own store under `/localhost/ndn-data/events/`,
the reserved namespace of the device's local state (as `signal-clock`, §20,
and the markers of §8 and §14 are): never served, listed, announced or
published (§21.1), and skipped by the log's restore.

| Name | Value |
|---|---|
| `/localhost/ndn-data/events/head` | 8 octets big-endian: the next cursor; written before an event takes a cursor below it, so a restart never gives a cursor twice |
| `/localhost/ndn-data/events/e/<cursor>` (8 octets) | an unacknowledged event, an `EventRecord` (§21.7) |
| `/localhost/ndn-data/events/a/<cursor>` (8 octets) | a tombstone: the 16-octet id of an acknowledged event |
| `/localhost/ndn-data/events/lb` | one octet: the mark that this store has a ledger, written (before anything else of the run) when a store has none |
| `/localhost/ndn-data/events/l/<n>` (8 octets) | a ledger fact, the `n`th entered: 16 octets (below). Not TLV: a hash, with no field a later revision could add |

At start, before the store is read back, a device MUST read its events
(dropping a record that does not decode). It MUST write an event before the
entry it reports where the entry is taken after it (equivocation: the event
precedes the entry), so that a store that keeps a prefix of its writes never
holds the second entry without the event. An event is stored with the
device's writes and is behind the barrier (§4.2) with them; it is delivered
at once and not after the barrier, so a power loss can take an event a host
saw together with the entries it reported (neither is then held, and nobody
else saw them), and an acknowledgement that was not yet durable is delivered
again. `acknowledge` waits for the barrier for exactly this reason.

**The ledger.** A revocation, a cut and a withdrawal by a cut or by its chain
are made of state the device holds: a trust context its keyring adopted, a
members record stored, a marker (§8) written. The cause is held first and
the event after, and a stop between them — a kill, a crash, a shutdown
before the adoption task ran — leaves a device that holds what it would hold
had it told the event, and has no event: nothing else derives it again. So a
device keeps a **ledger** of the facts it reported, under the names above, and
derives what the ledger does not cover.

- A **fact** is 16 octets of SHA-256 over what an event of these kinds
  reports: for a revocation the namespace and the name revoked (not the
  version of the context: a later context that keeps a revocation revokes
  nothing new); for a cut its subject, whether a folder, the key prefix cut,
  the signer and how many versions it keeps; for a withdrawal the name of the
  entry. An equivocation has none: the entries that are its evidence are held
  and are the record (§21.5).
- A fact is **entered with its event, in the same batch** (§4.2), whatever
  becomes of the event: made, coalesced into one kept, counted in the
  overflow notice, or not made because its id was acknowledged. The members
  record that takes a cut is in that batch with the events and facts of its
  cuts, and the markers of entries a context withdraws for their chain with
  the events and facts of their withdrawals, so that on a store with atomic
  batches a cause is held with its event or not at all. The first context of
  a namespace reports none of its own, and enters what it revokes.
- The ledger does not depend on acknowledgement: an event acknowledged, whose
  tombstone is gone, is not made again because its fact is entered. It keeps
  at most `events_unacked` + `events_acked` facts, the oldest going; and a fact
  leaves it when what it records is lifted — a context that no longer revokes
  the name, a record that no longer carries the cut, an entry taken back or
  re-admitted — so that the fact occurring again is news.
- After the store is read back and every entry held is judged again (§8), a
  device MUST **derive** the events of what it holds: each revocation of the
  trust contexts held, each cut of a record in force that it did not sign, and
  each entry stored and refused by a cut or for its chain (a stored entry was
  delivered, so its withdrawal is told; one refused as it arrived is not),
  and report each whose fact the ledger does not hold, in the order the live
  reports are made, entering its fact. What an earlier run did not get to
  report is reported now; so is a revocation in a context a host adopted while
  the device was off. The evidence of a derived event is that of one reported
  as the cause arrived, except that a cut names the first record of its signer
  held that carries it.
- A store with **no ledger** — no `lb`: one of a revision before the ledger,
  or a new one — holds a baseline: the device derives as above and enters the
  facts without reporting them, as the first context of a namespace reports
  none of its own, and the mark is there from then on.

What is still lost: an event whose fact the ledger no longer holds (past its
cap) may be reported again, with the same id, once its tombstone is also gone
(§21.4); and a stop on a store whose batch is not atomic (the default
`apply` writes one change after another, §4.2) can leave the cause with no
event, which the next start derives.

### 21.7 Wire: the store's event records

Events are never on the wire. Their records in the store are TLV, with
numbers 0x05E0–0x05FE (even, so a reader skips fields a later revision adds),
registered in [README.md](README.md#tlv-type-numbers). A number is reused where
its parent tells what it is.

| Type | Name | Value |
|---|---|---|
| 0x05E0 | EventRecord | EventId, Dated (first seen), Count, one detail, [Last] |
| 0x05E2 | EventId | 16 octets |
| 0x05E4 | Count | NonNegativeInteger: in an event, the occurrences it stands for; in a cut, the versions it keeps; in a Dropped, the occurrences not kept |
| 0x05E6 | Last | one detail |
| 0x05E8 | Equivocation | Name (the key), Seq, EntryRef, EntryRef (first, second) |
| 0x05EA | Withdrawal | Name (the key), [Name] (the collection), EntryRef, one of ByCut, ByChain, ByGroup |
| 0x05EC | CutEvent | Folder, Revision, Count (versions kept), Name ×4: subject, key prefix cut, signer, record |
| 0x05EE | RevocationEvent | Seq (the context's version), Name ×2: namespace, name revoked |
| 0x05F0 | Overflow | Dropped* |
| 0x05F2 | EntryRef | Name, [Kind], [Digest] |
| 0x05F4 | Kind | NonNegativeInteger: of an entry (0 version, 1 members, 2 snapshot, 3 hold, 4 lease, 5 prune, 6 introduction), or of an event (0 equivocation, 1 withdrawal, 2 cut, 3 revocation, 4 overflow) |
| 0x05F6 | ByCut | Name ×2: the key cut, the signer |
| 0x05F8 | ByChain | UTF-8: the validator's verdict |
| 0x05FA | ByGroup | Name: the member refused |
| 0x05FC | Folder | NonNegativeInteger, 0 or 1 |
| 0x05FE | Dropped | Kind, Count |

`Dated`, `Seq`, `Revision` and `Digest` are those of §16.2. The encoding of a
detail is also what its `id` hashes, so two implementations that write the same
evidence give it the same id.

### 21.8 Threat notes

- **Flooding.** An attacker who makes a device note causes — a key that signs
  entries at the seqs of its own earlier ones, a writer's entries a cut then
  withdraws, many cuts and revocations by an owner or authority that goes
  hostile — is limited by §21.5: per `(kind, subject)` one event however many
  occurrences; at most the cap of events, at most an equal share of it per
  kind (the cap over the five kinds events are kept for) and at most a
  quarter of it about one namespace, and one overflow notice; one record per
  kept event in the store; and nothing kept is evicted, so the attacker cannot
  hide the first event of another subject or kind behind its own. What it can
  do is fill the shares of its subjects' kinds and namespace with subjects of
  its own choosing and make later honest subjects of those only counted; the
  host then reads the evidence from what is held and acknowledges, which makes
  room. A subject is a key that signed something this device verified or a name
  an authority revoked, and the key need not be one a context the device holds
  for the folder trusts: the namespace of a foreign person who is her own
  authority is hers to mint device keys in without end, each a subject of an
  equivocation or a withdrawal. That is why the limits are per kind and per
  namespace: such a flood fills at most its namespace's quarter and its two
  kinds' shares, and a later cut or revocation, of another
  namespace or kind, is named, not only counted.
- **Forged evidence.** An event is made from verified data only (§21.1). A
  forged entry, a forged copy of a certificate or a replayed root is refused
  before it is noted (§8, §17.1) and makes no event; an entry whose
  signature verifies is the signer's, so what the event says the key
  signed it did sign. The digest is that of the packet verified here (exact
  wire bytes, as an implicit digest names them); a packet a relay changed is
  not that packet, and a relay that changes only a packet's signature value
  (an ECDSA `S` flipped to `n - S`, which still verifies) makes no
  equivocation: two packets are two things the key signed only when the
  digests of their signed regions differ (§4). An event naming a cut or a
  revocation is made from a record or a context judged as the layer judges
  them before. The evidence carries no content, so a peer cannot use an
  event to learn, or to make a device tell its host, what it cannot read.
- **Redelivery.** An event not acknowledged is delivered again after a restart
  and by every call, by design (§21.4): a host that acts on an event twice acts
  on the same `id`; a device that crashes in a loop delivers the same events
  each start, never more.
- **Acknowledgement replay.** An acknowledgement names ids. A replayed or
  duplicated one is accepted with no effect (the tombstone); one naming an id
  never seen is refused whole, so a host cannot be made to acknowledge what it
  has not been told by naming an id it guessed; and an acknowledgement of an
  event covers the occurrences coalesced into it so far, which the host can
  read first, so an occurrence that arrives after the acknowledgement is a new
  event. The ids are not secret: they are hashes of evidence.
- **The local namespace.** Nothing under `/localhost/ndn-data/events/` is
  served, whatever a peer asks, and an Interest for a name under it matches
  no entry (§3, §13.5: a device serves the log entries it holds, by name).
- **No judge.** An event does not make a key guilty or a refusal right: an
  equivocation is evidence that one key signed two things, which a copy of the
  key or a faulty device does; the layer's refusal of what a cut or a
  revocation excludes was already made without it. The next step a host takes
  (suspect, revoke, re-admit) is the owner's, signed as any other.

### 21.9 Conformance

`ndn-data`'s tests (`device/events_tests.rs`, and the revocation case in
`device.rs`) hold: a members record against a version at one seq, under two
names and under one, in either order; another signature value over the same
signed region (a high-S copy of a held ECDSA entry, a re-signing) no
equivocation, and two contents at one name still one; a withdrawal with no watcher, three
of one key coalesced into one event with the first and the last evidence; a
cut with nothing withdrawn, and the cut this device signed not reported; an
event delivered, not acknowledged, delivered again after a restart,
acknowledged and not delivered again, an id never seen refused, an
acknowledgement idempotent; a flood bounded with the first of each kind and
subject kept, an overflow notice counting the rest, one subject's flood
coalesced, the store's records not growing; a revocation and its withdrawal
reported once across restarts. The ledger (§21.6) is held by cases on the
memory store and, with a real process killed, on fjall and redb
(`device/events_tests.rs`, `device.rs`): a cut whose record is stored and
whose event is not, a revocation adopted and the entries it refuses, and a
withdrawal for the chain whose marker is stored, each reported after a
restart, once; the same acknowledged, with no tombstone kept, not reported
again; one reported before the stop reported once; a store with no ledger
holding what it has as a baseline, not news; a members record and the events
of its cuts in one batch. `ndn-data-conformance` has v1 (a members record
and a version at one seq, told on two readers' devices), v2 (a cut and the
version it withdraws told on every device that takes the cut, no watcher), v3
(a revocation adopted and what it withdraws, told on a device no one watches),
v4 (events outliving a restart until acknowledged) and v5 (a flood of one
subject is one event and the earlier event of another kind is unchanged), each
also on the faulty network (§18.1).
