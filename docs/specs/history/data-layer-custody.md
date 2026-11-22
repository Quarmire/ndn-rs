> Superseded by NAME.md at ndn-rs <commit>. Kept for history; nothing here is normative.

# Custody, prune and erasure text cut from `data-layer.md`

Custody (slice 3: hold records naming their holders, leases capped by keep, signed hold and audit asks, audits, repair, release of a device's own copy on whole proofs; `prune` of one's own writes and the erasure of fully pruned epochs, §13.2–§13.4, §14) was removed from the data layer. The numbers 0x0525, 0x0527, 0x0529, 0x052B, 0x052D, 0x052F, 0x0533, 0x0535, 0x0537, 0x0539, 0x053D, 0x0541, 0x0543 (the hold, lease and prune records, the hold and audit asks, the audit answer and its fields) and 0x0551 (the `Expired` audit answer) are freed and quarantined, not reused. `Nonce` 0x0531, `Asker` 0x053B and `Proof` 0x053F stay: introductions (§19) use them. §13.1 (large payloads), §13.5 (what a device serves) and §14.1–§14.2 (retention by expiry) stay in `data-layer.md`. What follows is the text as it stood, in the order of `data-layer.md`: sections cut whole first as they were, and, where a passage was rewritten rather than deleted, the old wording of the lines that changed (the new text is in `data-layer.md`).

## Header: Status and Scope (before §1)

  checkpoints covering by frontier, pieces in merge collections and the
  release of merge pieces only on an audited covering checkpoint, folder

  pieces, hold records naming their holders, leases capped by keep, signed
  asks, audits, repair and release on whole proofs, `prune` of one's own
  writes and the erasure of fully pruned epochs, §13, §14);

  and `share` (adding, removing, changing the rule), `prune`'s scope, and

  custody, prune, seals and types — and the seven verbs over it. The Rust

## §2 Invariants (invariant 7)

7. **Retention is chosen at write.** Custody MUST NOT extend keep; prune
   only narrows, and only over the pruner's own writes; every device drops
   what has passed its keep, by its own clock (§14.1).

## §4 Version and log and §4.2 Durability before publication (the lines that changed)

  stays readable. Keep is recorded at write; leases are capped by it
  (§13.2) and every device drops what has expired by it (§14.1).

    epoch is durable (§9);
  - ask a holder to hold under a hold record that is not durable, answer a
    hold ask with a lease before the lease is durable, or answer an audit
    ask before what it answers from is durable (§13.2, §13.3).

prefix that a device makes while a batch is open (erasing an epoch's key
scans the store for its grants; dropping a pruned version scans for its
pieces) MUST answer as the store would with the batch applied (what the

## §5 Collection and rule (the lines that changed)

  earlier one, no version of it applied, no lease, hold or members record

  does not exist held `put`, `get` and folder erasure here until restart).

## §5.2 Applying versions (the lines that changed)

   is pruned (§14), expired here (§14.1), or — in a log or one-key

    its writer, each holder of a live lease, each device whose version

  fits into a conflict carrying its words). This happens only after a
  release. A merge collection is never pruned nor expired (§14, §14.1),
  and a version's record — an inline operation with it — is never
  released; only a large version's chunks leave a device, by release
  (§13.3), which drops a device's own copy only once a covering checkpoint
  is proved held, and never drops the basis of a version held there (§13.3,
  step 6). `W`'s writer applied `W`'s basis whole and serves it, as does
  every device that merged `W` exactly (§13.1). A basis is therefore gone
  everywhere only once every device that held it whole released it, and a
  reader knows it as it knows a missing piece: every holder it asks
  answers without it, ask after ask (16 in a row, above). Every reader
  then merges `W` without it alike; one
  that finds it again (a holder returning) hands it, and its state moves
  to the exact merge, with every other reader's as they find it too; its
  watchers are told `Change::Remerged` when the value moved.

  version that no checkpoint applied here covers (above). Release (§13.3)
  counts only a checkpoint applied here.

  its log and summaries, heads, records (members, holds, leases, prunes,
  cuts, introductions), refusals, equivocation evidence, and per

  arrives later builds it); `put` or `put_op` into it; `hold`
  or `release` of it; a version arriving for it; a new members record

## §5.3 One key (the lines that changed)

  one member is that key: sync, watch, summaries, custody, prune, pieces,

  from its store, else by name, else from the holders of live leases it
  knows (`32=held`, §13.1). It answers `Got::Version` with

## §5.4 Range reads (a line cut)

  A pruned version within the bounds is in none of the lists (§14).


## §6.2 Threat notes (the paragraphs and lines that changed)

the digest check would not. A release never drops what holders lease, and
drops a device's own merge pieces only on a covering checkpoint applied
here and proved whole by audited holders (§13.3), so the covered versions
stay where the hold record says.

wherever something built on it is. This lets a holder under audit relay a
version's pieces from such a device rather than keep them: the release
proof (§13.3) then shows the pieces were held, at the audit, by the holder
or by a device that applied the version — no longer the holder alone. That
is acceptable because what release protects is that the pieces stay
obtainable after the writer drops its copy, and they are, from whoever
answered; it is bounded because every proof is fresh — a whole proof over
a new nonce, within the audit's deadline, costing the relaying holder the
whole version each time — so once no applier answers, the holder's next
audit fails and its lease is a breach the owner repairs, as with a holder
losing pieces (§13.3, §13.4). A device wanting the stronger guarantee keeps
its own copy, or holds with more copies.

readers. What a removed reader opened it keeps (invariant 9). A folder
epoch's key is erased only at a device that follows the folder whole and
has walked every device it knows (§14); a device that follows only some
collections under it keeps the key, as it cannot tell what the others
still hold.

**Release of merge pieces and permanent blocking.** In a merge collection
every later version waits for an earlier one's pieces (§13.1), so pieces
lost for good would block the collection for every reader lacking them.
A device therefore drops its own merge pieces only when a checkpoint
covering them is proved whole by `copies` audited holders, under
quarantine (§13.3); a holder relaying audits cannot make it release, as in
slice 3. A holder that loses merge pieces no checkpoint covers leaves the
readers lacking them waiting — stale — until repair brings them back.

## §6.3 Adopting a namespace for a folder (the lines that changed)

  can exchange signed asks (§13.2): the packets of **one device** of `P` that

  with its ask, §13.2) — with exactly two components, `<role>` and `<dev>`,

  - **an asker's proof** authenticates the device for the holder, granter
    or offering device that receives it, as every asker's proof does
    (§13.2); what it may then ask is decided by the records.

## §7 Summary (the lines that changed)

too (prune, slice 3, and expiry, slice 4, drop entries, not nodes: the
writer's tombstones keep each node's content, §14, §14.1). Keeping them

## §8.1 Revocation cut (the lines that changed)

  in `C` it keeps — versions, blocks, members records, hold, lease and
  prune records — and one with prefix `<D>/32=log` for `K`'s snapshots

  heads, seal keys, grants, audit answers, an asker's proofs — since no cut

  others; a hold, lease or prune record refused this way stops counting.

## §8.5 Time and §8.6 Threat notes (the lines that changed)

  §7), the one-key head's freshness and the age `get` reports (§5.3), the
  batch delay (§4.1) and the audit's clock skew (§13.3). None decides

  verified it; have a summary, head, seal key, grant or audit answer

## §9 Seal (the lines that changed)

forward ciphertext. Erasure is the destruction of the key.

  (§6.1), and nothing is sealed in its outgrown epoch meanwhile. A folder
  epoch's key is erased as a collection's is, across every collection under
  the folder (§14).

## §13 Custody (the heading and the lines of §13.1 that changed)

## 13. Custody — slice 3 (merge pieces: slice 6)

  each piece from its store, else by name, else from each holder of a live
  lease it knows (§13.2) by the Interest `<H>/32=held/<Name TLV>`, which the
  holder answers (DigestSha256) with the packet inside; a piece that is not

  assembles (at most `PAYLOAD_MAX`). A holder's repair (§13.3) and a merge
  version's pieces walk the same way.

- Besides its writer and the holders, a reader asks for those pieces the

## §13.2 to §13.4 (cut whole)

### 13.2 Hold records and leases

- A **hold record** is an entry of an owner device's log about collection
  `C` (Content `HoldRecord`: `C`, `Copies`, `KeepUntil` — until when — the
  `Frontier` `at` the asker had applied, and `Holders`: the holder devices
  the owner chose, by name, ascending). It is the custody policy, taken
  only when owner-signed (the owner rule, §3). `hold(C, {copies, until,
  holders})` signs one when the device's newest differs in any of them.
  Each copy is kept by a distinct device the record names: `hold` answers
  `BadRequest` (next step: `FixRequest`) when it names fewer holders than
  `copies`, or a name that is no device name (§16.1) or the asking device.
- A **lease** is an entry of the holder `H`'s log about `C` (Content
  `LeaseRecord`: `C`, the hold record's name, `KeepUntil`, and the
  `Frontier` `holds`). It promises every version of `C` inside `holds` that
  applies — admitted by the record in force, not pruned — with its pieces,
  each until the earlier of the lease's date and the version's keep. A
  reader keeps one lease per holder *device*: the newest by log seq,
  whichever of the device's keys signed it, so a device counts once however
  many keys it has. It counts a lease only when the hold record it answers
  is held and names that device a holder; the asking device never counts
  for itself (by device name, not key). Both records are listed in summary
  nodes under `MembersEntries`, which from slice 3 lists every entry of a
  collection that is not a version.
- **Keep caps hold.** A lease's date MUST NOT pass the hold record's, nor
  the latest `Keep::Until` date of the versions inside `holds` when every
  one of them is kept until a date. A holder signs no lease that would end
  by its clock, and a reader does not count a lease that breaks either
  bound (or whose hold record or versions it does not hold yet). Every
  device drops what has expired by its own clock (§14.1).
- **Asking.** The owner device `A` asks each holder `H` its record names
  with the Interest `<H>/32=hold/<HoldAsk>`: the hold record's name, a
  fresh 16-octet `Nonce`, and `Asker`, `A`'s proof of asking — a Data
  packet `<A>/32=ask/<binding>` signed by `A`'s device key, `binding` the
  SHA-256 of the hold label (§16.1) followed by `H`'s Name TLV and the
  `HoldAsk` TLV without its `Asker`. The proof binds the protocol, the
  holder and this one ask, so it serves no
  other. A device holds only for the namespaces its host lists, and
  answers a hold ask only when, in this order: `C` is of such a namespace;
  the proof's key locator names the device that signed the hold record —
  any other ask is dropped before a signature is checked; that asker has
  no other ask in progress here (one more ask of that asker — the same
  ask duplicated on the way, or the owner asking again, §13.3 — waits for
  the one in progress to end, at most a hold ask's lifetime: three first
  looks and one Interest lifetime, 14 s by default; any further one is
  dropped); the proof is named for this ask and
  verifies to a key of that device (at most `Config::asks_verifying`
  proofs, 8 by default, are verified at once);
  the record, fetched and verified, is that device's newest hold record for
  `C` and names `H`; and its date is past now. `H` then follows `C`, takes
  every version inside `at` with every piece (fetching back what it lost —
  re-replication — from the writer or another holder), signs the lease
  over what its store holds whole, and answers with it (a DigestSha256 Data
  whose Content is the lease's packet). The take runs in a task of its
  own, one per collection at a time, which outlives any one ask: over a
  lossy path a large collection takes longer than an ask lives. It goes in
  rounds — while a version inside `at` is not held, it refreshes every
  device writing into the namespace, then asks by its name every entry
  inside `at` it still does not hold, refuse or skip: each writer's newest
  inside `at`, and every earlier one a summary listed (a walk that listed
  an entry but did not take it under loss leaves it to the take, which
  must not wait on summaries for it); then it asks each
  piece it lacks once of each source — asked again after the pause of
  §17.1, at most 16 rounds (`REPAIR_ROUNDS`), stopping after 3 rounds in a
  row that brought no version heard of and no piece (`REPAIR_IDLE`). An
  ask that finds every version inside `at` kept whole (seen, not merely
  not yet known) is answered at once; else it waits for the take for a
  hold ask's lifetime less one Interest lifetime and is answered when the
  take is done (whole, or out of rounds: the lease holds what is kept),
  or, the take still under way, when it brought nothing since `H` last
  answered this record with less than `at` — before any such answer,
  nothing during the wait — no record inside `at` and no piece of what it
  lacks came, as nothing in reach has it — with the lease of what is
  kept, so the owner learns `H` keeps less than asked instead of asking
  again a take that gets nowhere. While the take brings more since that
  answer — even if nothing came during this wait — the ask is not
  answered: the owner asks again. A take that brought a record or a piece
  between two asks has not shown that it keeps all it can, and answering
  the same lease twice would end the owner's asks (below). The members
  record in force over `C` counts as one record the take lacks until `H`
  holds it — before it, no version is judged and the pieces a version
  lacks are not counted, so its arrival is never mistaken for nothing
  brought — and the last answer is the one given when this ask is
  answered, by any ask of the owner waiting beside it.
  It keeps its last 1,024 answers by
  name, so an ask asked again gets the same packet at no cost. It signs a
  new lease when what it holds grows. Holders join the groups of the
  namespaces they hold for, to hear what they keep; an owner asks only the
  devices its record names, never one heard in a group (sync Interests are
  unsigned, §12). A holder serves every entry and piece of a collection it
  holds, whoever wrote it, by its own name and under `<H>/32=held/…`.
- **What a holder stores** is bounded by what the owner signed. Of records,
  only those it accepts: owner-signed members and hold records, leases of
  a holder the hold record they answer names (or its own), and prunes it
  does not ignore (§14). Of another device's versions, only those of a
  collection it holds — a merge collection's as a log one's (slice 6), with
  their pieces — admitted by the record in force and inside the `at` of the
  hold record it accepted; re-replication fetches back that set and no
  more. Leases, audits and repair treat merge versions and their pieces as
  log ones.

### 13.3 Audits

- Each `hold` audits every live lease: from the device's randomness it
  draws pieces (16 by default) uniformly from what the lease promises — the
  log entry of each version inside `holds` that applies and whose keep has
  not passed by the auditor's clock (§14.1), and each manifest node and
  chunk of it — and asks each with the Interest `<H>/32=audit/<AuditAsk>`
  (`Nonce`, 16 fresh random octets, the piece's name, and `Asker`, the
  auditor's proof binding `H` and the ask as in §13.2, under the audit
  label, §16.1). An ask to which no answer signed by `H` comes back —
  lost, late, refused on the way as a packet (§4) or Nacked — is asked
  again after the pause of §17.1, each time as a new ask: a fresh nonce,
  so a new name and a new proof. At most `AUDIT_TRIES` (8) asks are sent
  for one piece in one audit; only when none got an answer signed by `H`
  is the piece unanswered. Once at least `AUDIT_TRIES` of the audit's asks,
  all pieces counted, went unanswered and `H` answered none, a piece is
  asked no more after `SILENT_ROUNDS` (3) asks: `H` is **silent** in this
  audit, which is unanswered. A lossy
  path (a fifth of the packets lost each way) leaves every one of eight
  asks unanswered under one time in three thousand, and an audit of 16
  pieces asks 48 before calling `H` silent; a path down costs the audit
  three Interest lifetimes and two pauses, not eight and seven. An answer
  counts only as the answer to the ask
  whose name it carries, judged under that ask's nonce, so a holder never
  passes with an answer to an earlier ask, and a retry is never evidence.
  A manifest node the
  auditor lacks, needed to list the chunks, it fetches from the writer or
  the holders, and at last asks of the audited holder itself through an
  audit ask, judged like any other.
- `H` answers only an ask about a collection it holds, from an owner device
  whose hold record held here names `H` (by the proof's key locator, before
  any signature is checked), with at most 64 audits of that asker in
  progress, its proof verified (§13.2). It answers under the ask's name,
  signed by its device key, FreshnessPeriod 0, `AuditAnswer`: `Piece`, the
  piece's whole packet; `PrunedBy`, the packet of the prune record that
  ended the piece's version (§14); `RefusedBy`, the packet of the members
  record of the revision in force there that refuses the version;
  `Expired`, empty: the piece's version expired by the holder's clock and it
  dropped it (§14.1); or `Missing`, it does not hold the piece and knows no
  record that ends it.
  The same answer cache as §13.2 applies.
- The auditor judges each answer:
  - `Piece` whose digest is the one the auditor holds (the version
    packet's, or the one its manifest lists): the piece is there.
  - `Missing`, or a `Piece` that is not the piece: signed evidence of a
    breach, as the auditor's own records say the piece should be there.
  - `PrunedBy`: the auditor verifies and takes the record (§14). It
    excuses the piece — which leaves the audit — when it covers the
    version; a verified prune that does not, or a record that is not a
    prune of the version's writer in `C`, is evidence. A record it cannot
    verify yet is no answer.
  - `RefusedBy`: verified and taken, it excuses the piece when the record
    in force at the auditor now refuses the version; when the auditor
    still admits it, the two views differ and it is no answer, never
    evidence.
  - `Expired`: the auditor checks it against the keep the version's writer
    signed. Kept `Forever`, or `Until(t)` with `t` later than the auditor's
    clock plus the clock skew it allows (a day by default): signed evidence
    of a breach, as no clock explains it — the holder dropped what it
    promised and claims expiry. Otherwise — `t` within the skew, or kept for
    the last `n`, as the holder may know newer versions the auditor does not
    — no answer, never evidence: the lease is unanswered for the piece and
    repair may ask again. So an auditor whose clock is behind the holder's
    cannot frame an honest holder that dropped at keep.
  - Nothing signed by `H` to any of the `AUDIT_TRIES` asks: no answer.
- Verdict: **broken** on any evidence; else **unanswered** when an ask got
  no answer, or no device produced a manifest node a promised version's
  chunks are listed in (the audit is unverified, never kept); else
  **kept**. Only evidence makes a lease broken: a timeout is never a
  verdict, so a slow network can only cause a copy more, never a wrong
  judgement.
- **Repair.** A lease not live, broken or unanswered, or one that holds
  less than the hold record's `at`, does not count. While fewer than
  `copies` count, `hold` asks every holder the record names whose lease
  does not count, all at once (a holder asked again fetches back what it
  lost), and audits each lease that comes back — except a holder silent to
  this call's audit of its live lease (above): it is listed unanswered
  among the leases found before repair, not asked to hold in this call,
  and asked again by the next. It asks no other device.
  A holder whose lease still does not count — no lease came back, as the
  ask or its answer was lost or the holder's take is still under way
  (§13.2), or the lease that came is not live, not audited kept, or holds
  less than `at` (the holder's own fetches met loss) — is asked again
  after the pause of §17.1, each time under a fresh nonce and proof, while
  fewer than `copies` count: at most `HOLD_TRIES` (16) hold asks per
  holder in one `hold` call — some four minutes of 14 s asks, for a holder
  taking a large collection over a lossy path — each lease that comes back
  audited afresh. It stops asking a holder that answers the same lease
  twice, audited kept: that holder keeps all it could take of what was
  asked (`H` answers with the same lease again only if its take brought
  nothing since its last such answer, §13.2), and the next `hold` asks
  again.
  Each such audit draws its pieces anew; it passes only with every piece
  answered, so a holder keeping a fraction `f` passes one `hold` call with
  probability at most about `HOLD_TRIES · f^16`, and staying silent on the
  pieces it lacks gains it nothing.
  `Custody` lists the live leases with this device's audit of each, those
  found broken or unanswered before repair, and `unkept`: the versions
  inside `at` that this device does not keep whole and that no lease
  audited kept holds.
- **Release.** A host MAY drop its own chunks of a large version
  (`Device::release`, by version or by collection) only on fresh evidence,
  never on a stored verdict:
  1. It holds the version whole, and its own hold record for `C`. The
     candidates are the holders that record names whose live lease holds
     the version.
  2. While it asks them it serves none of the version's chunks and
     manifest nodes, to anyone (quarantine); its log entry stays served.
  3. It asks each candidate one audit ask marked `Whole`, naming the
     version's log entry, under a fresh nonce (asked again, each time
     under a new nonce, while no signed answer comes back, up to
     `AUDIT_TRIES` asks; the proof is checked under the nonce of the ask
     it answers). The answer is `Proof`:
     SHA-256 over the nonce, then, for each piece of the version — its log
     entry, its manifest nodes in heap order, its chunks in order — the
     piece's length (8 octets, big-endian) and its whole packet. A holder
     lacking any piece answers `Missing` (or `PrunedBy`, `RefusedBy`). The
     releaser checks the proof against its own copy.
  4. It drops the chunks only when at least `copies` (at least one)
     distinct holder devices proved. Otherwise it keeps them, saying for
     each version which holder proved what (`Released::kept`), and when it
     released nothing it answers `NotHeld` with those reasons (next step:
     hold first).
  5. *Slice 6.* A version of a merge collection is released only on a
     checkpoint `CP` covering it (§5.2) that the device holds whole and
     checked: steps 2 to 4 are done for `CP` — the candidates are the
     holders the record names whose live lease holds `CP`, and `CP`'s
     pieces are quarantined while they prove it whole — and the version's
     chunks are dropped only when at least `copies` distinct holders prove
     `CP`. Otherwise they are kept, saying why ("no checkpoint covering it
     is proved held by N audited holders; write a checkpoint and hold it"),
     and when nothing is released the answer is `NotHeld`. A merge
     version's pieces hold back every later version of the collection
     (§13.1); a covering checkpoint proved held makes them unneeded by
     every reader that takes it.
  6. *Round 3.* A merge version that a version held here is made over
     apart from every checkpoint applied here covering it — the basis of
     a version written apart from the checkpoint (§5.2) — is not released:
     its chunks are kept, saying why ("the version `<key>` seq `<s>`,
     written apart from the checkpoint covering it, is made over it: its
     rule merges that version exactly only with it"). A device holding
     such a version is never the one that lets its basis go, so a basis is
     gone only once no device holding a version made over it held it
     (§5.2, when a basis is gone).

### 13.4 What a holder can and cannot do

- It cannot forge, alter or substitute data: every piece verifies against
  the writer's signature through the manifest. It cannot pass an audit for
  a piece it cannot produce when asked: the nonce makes every ask a new
  name, so no cache and no earlier answer answers it, and the pieces are
  the auditor's choice. A holder keeping a fraction `f` of what it promised
  passes one audit with probability at most about `f^16`.
- It cannot make an owner release on a copy it cannot produce: a release
  asks a proof over every piece of the version, under a fresh nonce, from
  each of `copies` distinct holders, while the releaser serves none of
  those pieces.
- It cannot be counted unless the owner's hold record names it, nor be
  counted twice under two keys; a device the owner did not choose gets no
  hold ask and its lease counts for nothing.
- It cannot be made to work by a stranger: an ask from a device that is not
  the owner device its record names costs it a parse, no signature check
  and no fetch; an owner's asks are bounded (one hold ask in progress and
  one waiting, and 64 audits in progress, per asker; `Config::asks_verifying`
  proofs verified at once), and a replayed ask is answered from the cache.
  An owner asking again under loss sends at most `HOLD_TRIES` hold asks
  per holder per `hold` call and `AUDIT_TRIES` audit asks per piece per
  audit (§13.3).
- It cannot be framed by records its auditor has not heard yet: a prune or
  a members record it followed is its answer, and it is evidence against it
  only where the auditor's own records prove the piece should be there.
  Nor by a lossy path: a lost ask or answer is asked again, and an ask
  still unanswered after the bound leaves the lease unanswered, never
  broken; a holder silent to an audit is unanswered, never broken, and is
  asked again by the next `hold`.
- It cannot read sealed data it holds without being of the audience: it
  stores and serves ciphertext (§9 lists the metadata it sees). A device of
  the namespace is an owner device (§3): it may sign the members record
  that defines the audience, so no audience rule binds it, and it reads
  and owns. A holder that must not read is therefore enrolled outside the
  namespace it holds for.
- It cannot keep its promise past keep and be counted, nor extend a lease
  past the owner's date. Serving past keep (a slow clock, or on purpose)
  makes no reader keep what it serves: each drops it by its own clock and
  stores nothing expired (§14.1).
- It can fetch an asked piece from elsewhere at audit time — a cache, or
  another holder — but not from the releaser during a release: an audit
  proves it can produce the data, not that it stored it. Two holders can
  collude that way, so `copies` holders owned by one party are one failure
  domain. It can stop answering: its lease becomes unanswered and repair
  starts, but nothing marks it broken without evidence. It sees which
  pieces are asked, and when.


## §13.5 What a device serves (the lines that changed)

log. Before, a device served only its own log, a holder's collections and
the merge versions it applied: a person whose phone writes and goes away
had their work reach others only while the phone, or a custody holder,
was online (ndf's REPLY-12 §1; case h10).

  every record (members, folder, hold, lease, prune, snapshot); stored, or

**What it never serves.** What a known prune covers — by the prune
records it holds, whether or not it held the version (§14) — and what
expired by its own clock (§14.1): retention and erasure are the writer's,
and a holder answering for pruned bytes would undo them. Erasure destroys
an epoch's key only once every version sealed in it is pruned (§14), so a
version of an erased epoch is never served either. Nothing refused or
withdrawn here: by the record in force (`NotMember`, `OutsideCut`), a
revocation cut or an untrusted chain (§8) or its rule's
check (§5.2) — another reader would refuse it too, and serving it would
only cost that reader a verification. This holds for a collection the
device holds for its owner (§13.2) as for any other: a holder keeps
outsiders' versions and packets withdrawn after it stored them, and
serves none of them (round 3, review L3). Nothing it holds unverified: a
packet that did not verify is never kept (§4). An own entry above the
durable head, and an own piece a release is auditing holders for, stay
unserved as before (§4.2, §13.3). An ask for an entry the device does not
hold costs it one lookup by name, whatever it holds of the collection
(ndn-data: `St::held` indexes every entry held, waiting or refused
included), so asks for made-up seqs cost no scan under its lock.

order, the holders of a live lease on the collection (§13.2), then, for
pieces, the devices whose versions are made over the version (§13.1),

holds vouches for as members or holders of the namespace — a summary
root of theirs for it verified (in this run or kept from an earlier one),
a version of theirs applied in a collection of it, a lease or hold record
of such a collection naming them, or a members record in force of a

  a digest names, when it asks by one), a piece against its manifest. The
  holders of a live lease, asked in turn before, are checked the same way.

A device that holds nothing of it answers with a Nack, at once. The writer
asked first, a reader that reaches it never waits on a holder. Outside a
walk, a reader that does not reach the writer asks the devices once the
writer's asks missed (§17.1), all at once, so one that is away too costs no
more than one of them, and only for what the writer did not answer. (Asked
one after another, devices away each cost a lifetime: a holder taking a
hold, which refreshes every writer it knows, outlived its asker's
patience; case g1.) A piece of a version being read is asked as a walk's
packets are: once the writer's first ask missed, beside its later asks,
the holders and the devices whose versions are made over it in turn, then
the other devices at once; the first answer that checks is taken. So a
device that holds nothing — its Nack lost or held back on the way — costs
the read no time beside the writer's own asks (round 3, faulty case h9:
asked after them, such a device cost every piece the writer's lost asks
missed `FETCH_TRIES` lifetimes more).

  collections; prune and expiry bound how long anything is served.

- *Erasure.* Prune and expiry are checked as a packet is asked for, by the
  prune records held and the device's clock; a device restarted with
  orphan pieces of a pruned version serves none of them (the prune
  records are restored, not only the versions held).

## §14 Prune and expiry (the prune part, cut whole; §14.1 and §14.2 stay)

## 14. Prune and expiry — slices 2 (scope), 3, 4 (expiry), 6 (folder epochs)

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
  seq at most `upto`'s for its key — versions only, never the signer's
  members, hold, lease or prune records or snapshots. `upto` MUST be below
  the prune record's own seq, or the prune would swallow versions written
  after it: `prune` answers `BadRequest` (next step: `FixRequest`) for an
  `upto` past the device's newest entry (the record takes the next seq),
  and a reader ignores a prune record whose `upto` reaches its own seq.
  Prune applies to log and one-key collections: a merge collection's state
  is computed from every version, so `prune` answers `NotPrunable` (next
  step: edit instead).
- A reader that knows a prune MUST report `Pruned` for what it covers, not
  the data, drop its copies (record and pieces), tell its watchers
  (`Change::Pruned`) and serve none of it — by the prune records it holds,
  whether or not it held the version, by its own name, under `32=held` and
  in audit answers, also after a restart, which drops pieces and records a
  prune covers that the store still keeps; a piece fetched for a pruned
  version is not stored. Later versions do not wait for it. A holder drops
  it too: its leases end for it, and audits never ask for it. The writer
  keeps a local tombstone so its summary still lists the entry (the log
  never changes).
- **What "erased" means.** A device destroys the key of epoch `E` of `C` —
  the key it holds, the key it made, the grants it kept or signed for
  others — once all of these hold: `E` is not the record in force's epoch;
  at least one version sealed in `E` is pruned; every version of `C` it
  knows of is pruned, held and of another epoch (or unsealed), or not held
  and never applies (refused); and every writer known to write into `C`
  has left `E`, as signed data shows — it is this device, the record in
  force admits no further version of it (cut, or not a writer), or it has
  a version in the record in force's epoch. Until then the erasure is
  pending, since a writer that has not moved on may still write into `E`;
  it is checked again whenever a version, a members record or a prune
  arrives. Erasing, the device stores an erased-epoch marker, which a
  restart loads before the keys, and from then on refuses that key if
  granted again — unless an admitted version sealed in `E` that no prune
  covers arrives (from a writer it had not heard of): then it takes the key
  again and removes the marker. From
  erasure on, every copy of that ciphertext anywhere, in any holder, cache
  or backup, is unreadable to whoever did not keep the key. Not erased:
  what a reader already opened (plaintext it kept, forward-only, invariant
  9); a key a device copied out of the layer; versions of an epoch that
  still has unpruned versions or a writer that has not left it — those are
  deleted by honest devices and holders only; and copies in caches, which
  expire by their own policy.
- **Folder epochs — slice 6.** A folder epoch (§9) is one key for every
  collection under the folder that inherits its readers, so it is erased
  by the same rule taken across all of them: a device destroys the key of
  epoch `E` of folder `F`'s records — held, made, granted — once `E` is
  not the epoch of `F`'s record in force; a version sealed in `E` is
  pruned in some collection under `F`; in every collection under `F` it
  knows of, every version it knows of is pruned, held and of another
  epoch (or unsealed), or not held and never applying; and every writer
  known to write under `F` has left `E` — it is this device, `F`'s record
  in force admits no further version of it, or it has a version in `F`'s
  epoch in force in a collection that reads in it. It must also know
  every collection under `F`: the erasure stays pending unless it follows
  `F` whole (every collection under it is inside what it follows, §12)
  and has walked in full the summary of every device it knows to write
  into `F`'s namespace since it last followed something new there. A
  device that follows only some collections under `F` keeps the key.
  The erased-folder-epoch marker is stored apart from collections' (a name
  may be both), loaded at restart before the keys, and lifted only as
  above: an admitted version sealed in `E` under `F` that no prune covers.
- **A prune asks for erasure.** A folder's epoch in force is never erased,
  and outlives most prunes: when a device of `F`'s owner namespace takes a
  prune record — its own or any writer's — that drops a version sealed in
  `F`'s epoch in force, in a collection under `F` reading in it, it owes
  `F` a new epoch (a new record of `F`, same writers and readers, §6.1),
  signed by a device of that namespace that is of `F`'s audience, so the
  pruned epoch can be erased once every writer has moved on. What is owed
  is computed again from the records and prunes held at every restart, and
  a record owed that could not be signed stays owed. A collection's own
  epoch in force is not rotated by a prune.
- **What a pruner can and cannot do.** It drops only its own versions; it
  cannot end another writer's data or another holder's promise for it, and
  it cannot recall copies already made.


## §14.1 and §14.2 (the lines that changed)

  every operation: it is edited instead, as `prune` answers `NotPrunable`,

  `Forever` never expires. Keep was set at write; nothing extends it, and
  custody neither (§13.2).

- **What every device does.** Every device — writer, holder or reader —
  MUST drop an expired version, record and pieces; MUST serve none of it,
  by its own name, under `32=held` or in audit answers; MUST NOT store one

  members record is taken — so a holder that took versions before their

- **Custody.** Leases are capped by keep (§13.2); audits never ask a piece
  whose keep has passed by the auditor's clock; a holder asked for a piece
  it dropped as expired by its own clock answers `Expired`, which is no
  answer and not evidence — unless the writer's signed keep proves it false
  beyond any clock skew the auditor allows (kept `Forever`, or until a date
  more than that skew past the auditor's clock), which is evidence of a
  broken lease (§13.3).

  only: its lease stops counting for what it dropped — and a holder whose
  clock runs ahead of its auditor's by more than the skew the auditor
  allows is judged broken for it — and nothing of any other device
  changes. A writer's clock moves only its own dates and its own listing

    later writes; nothing it signs later extends what it wrote, and only its
    own prune narrows it (§14);

  - can answer `Expired` in an audit: no answer, not evidence, within the
    clock skew the auditor allows or for a version kept for the last `n`;
    for a version whose writer-signed keep proves it has not expired (kept
    `Forever`, or until beyond the skew) it is evidence, and the lease is
    broken. A holder that lost what it promised can so escape evidence only
    within that skew, never the count: an unanswered lease counts for
    nothing and repair starts (§13.3);

## §15 Verbs (the lines that changed)

| `hold` | `hold(prefix, {copies, until, holders}) → custody` | 3 |
| `prune` | `prune(prefix, upto)` | 2 (refusing others' writes), 3 |

verbs stay seven. Code mostly uses `get`, `put` and `watch`.
`hold`, `prune` and `share` run on host policy, or on the person's

  every equivocation (§4), and every version withdrawn (§8), pruned (§14)
  or expired (§14.1); from slice 6 also every version held but not

  it is about (`Change::collection`): a version, withdrawal, prune,

- **`hold(C, {copies, until, holders})`** (a device of `C`'s namespace,
  else `NotOwner`) names the holder devices, at least `copies` of them,
  none of them this device: else `BadRequest`, whose next step,
  `FixRequest`, is to correct the request itself (name more holders, or
  devices). It signs the hold record naming them, audits every live lease
  and repairs by asking the named holders only (§13), and answers
  `Custody`: the live leases with this device's audit of each, those found
  broken or unanswered before repair, and `unkept`, what nothing confirms
  is kept (§13.3). Releasing the device's own copy of what holders keep is
  host policy outside the verbs (`Device::release`, §13.3).
- **`prune(prefix, upto)`** of another device's entry, or up to a frontier
  naming another key, answers `NotOwnWrites`; of a merge collection,
  `NotPrunable`; up to a seq past the device's newest entry, `BadRequest`
  (next step `FixRequest`); else it signs the prune record and publishes
  it (§14); a prune in a folder's epoch in force, by this device or any
  writer, makes the folder move to a new epoch (§14).

## §16.1 Names (the lines that changed)

| hold, lease, prune record | `<D>/32=log/<C>/seq=<n>` | device key |
| hold ask (answer: the lease's packet) | `<H>/32=hold/<HoldAsk TLV>` | DigestSha256 |
| audit ask and answer | `<H>/32=audit/<AuditAsk TLV>`, Content `AuditAnswer`, FreshnessPeriod 0 | the holder's device key |
| asker's proof (inside a hold, audit or introduction ask or answer, never fetched) | `<A>/32=ask/<binding>`, empty Content, FreshnessPeriod 0 | the asker's device key |

- **Hold ask, audit ask.** `H` is the components before the first
  `32=hold` (`32=audit`), a device name; one GenericNameComponent follows
  whose value is one `HoldAsk` (`AuditAsk`) TLV. A hold ask's record is a
  log entry with a collection.
- **Asker's proof.** `A` is the components before the first `32=ask`, a
  device name; one GenericNameComponent of 32 octets follows, the binding:
  SHA-256 of the protocol's label, then the holder's Name TLV followed by
  the ask's TLV without its `Asker` (§13.2, §13.3); in an introduction,
  the offering device's Name TLV followed by the ask's fields before its
  `Asker`, or the answer's fields before its `Asker` (§19.3). The labels,
  ASCII each ending in a zero octet so none is a prefix of another, are
  `ndn-data hold ask\0`, `ndn-data audit ask\0`, `ndn-data intro ask\0`
  and `ndn-data intro answer\0`. A receiver computes the binding with the
  label of the protocol it expects, so a proof made for one protocol
  never verifies as another's, whatever its fields.

## §16.2 TLV-TYPE numbers (the lines that changed)

is kept in [history/data-layer-groups.md](history/data-layer-groups.md)). A number is even unless the notes

| 0x0525 | HoldRecord | Name (collection), Copies, KeepUntil, Frontier (what the asker had applied), Holders |
| 0x0527 | Copies | NonNegativeInteger |
| 0x0529 | LeaseRecord | Name (collection), Name (the hold record), KeepUntil, Frontier (what it holds) |
| 0x052B | PruneRecord | Name (collection or version), Frontier (up to, below the record's own seq) |
| 0x052D | HoldAsk | Name (the hold record), Nonce, Asker |
| 0x052F | AuditAsk | Nonce, Name (the piece; with Whole, the version's log entry), [Whole], Asker |
| 0x0533 | AuditAnswer | one of Piece, Missing, Proof, PrunedBy, RefusedBy, Expired |
| 0x0535 | Piece | octets: the piece's whole Data packet |
| 0x0537 | Missing | empty: the holder does not hold the piece and knows no record that ends it |
| 0x0539 | Holders | Name* (the holder devices the owner chose), ascending; required in a HoldRecord |
| 0x053B | Asker | octets: the asker's proof, the Data packet `<A>/32=ask/<binding>` (§13.2) |
| 0x053D | Whole | empty: the audit asks one proof over every piece of the version (§13.3, release) |
| 0x053F | Proof | 32 octets: SHA-256 over the Nonce, then each piece's length (8 octets, big-endian) and whole packet: the log entry, the manifest nodes in heap order, the chunks in order |
| 0x0541 | PrunedBy | octets: the packet of the prune record that ended the piece's version |
| 0x0543 | RefusedBy | octets: the packet of the members record that refuses the piece's version |
| 0x0551 | Expired | empty, an AuditAnswer: the piece's version expired by the holder's clock and it dropped it (§14.1) |

Slice 3's numbers are odd — critical — because the even ones of the block
are taken and because a reader that does not know them must not pass over
them: a version in pieces read as one without a payload, or a hold, lease
or prune record mistaken for nothing, would be wrong, not stale. So with
the custody fields: a reader passing over `Holders` would count any
device's lease, a holder passing over `Whole` would answer a release with
one piece, and an auditor passing over `PrunedBy` would judge an honest
holder broken. A hold record without `Holders` is refused.

other range would answer the wrong entries. An auditor passing over
`Expired` would read an empty answer as no `AuditAnswer` it knows, and
must instead judge it against the piece's keep (§13.3). A reader passing

## §16.3 Why these encodings (the lines that changed)

- **Leases and holds are log entries**, so they spread through summaries
  like everything else and carry the writer's own monotonic order; the
  audit answer is the one per-ask signature, under a nonce name no cache can
  hold.
- **Holders named in the hold record**, not learned from sync: sync
  Interests are unsigned (§12), so a device heard in a group is no evidence
  of anything; the owner's signed choice is the one policy every reader
  checks a lease against.

  holder drop a stranger's ask for the cost of a parse. Its binding opens

- **Release by quarantine and a whole proof**, not a holder-specific
  encoding of the pieces: any encoding a holder can compute from its
  storage it can also compute from the plain pieces fetched from the
  releaser at the time of the ask. Only the releaser refusing to serve them
  removes that relay; the proof over every piece then makes the holder
  hold all of them at once.

- **`Expired` is an empty answer**, not a record: a holder's clock is
  evidence of nothing, so the answer says only that it dropped the piece at
  keep by its clock; the auditor judges it only against the writer's signed
  keep and its own clock with the skew it allows (§13.3, §14.1).

  when the referenced version is pruned while the operation still needs

  they bring is the release rule for merge pieces (§13.3), as a lost piece
  of a merge version would hold back every later one.

## §17 Failure model (the lines that changed)

| Lost device | Its leases lapse; repair asks the other holders the hold record names; the owner marks its key suspected on the root device, says when it was lost, and revokes it with a cut of what the root first verified before then; the entries left out are printed, and any honest one is re-admitted by exact name and digest. | §8.1, §8.2, §13 |
| Holder relays audits | Passes spot audits (they prove it can produce, not that it stores), but cannot make the owner release: a release asks a proof over every piece while the owner serves none of them. | §13.3, §13.4 |
| Stranger asks a holder | Dropped for the cost of a parse: only an owner device whose hold record names the holder may ask, and its asks are bounded. | §13.2, §13.3 |
| Holder hears a prune first | Its audit answer names the prune; the auditor verifies and takes it, and the piece is excused. | §13.3, §14 |
| Writer offline when an epoch is pruned | Erasure stays pending until it has left the epoch; a version it sealed in an erased epoch, arriving later, brings the key back. | §14 |
| Holder claims `Expired` | Within the auditor's clock skew, or for a version kept for the last `n`: no answer, not evidence — the lease does not count for the piece and repair may ask again. For a version its writer kept `Forever`, or until beyond that skew: evidence, the lease is broken (`Breach::Expired`). | §13.3, §14.1 |
| Folder epoch pruned | Erased once every writer under the folder left it and every collection under it known here is done with it; pending while the device does not follow the folder whole or has not walked every known device toward it (one nothing signed vouches for, once its walks spent their tries unreached, is not waited for, §5); a prune by any writer in the folder's epoch in force makes an owner device of its audience move the folder to a new epoch first, owed again after a restart until signed. The erasure survives a restart. | §9, §14 |
| Release of merge pieces without a covering checkpoint proved held | Refused: the pieces are kept, saying why, and `NotHeld` when nothing is released. | §13.3 |

## §17.1 Asking again under loss (the lines that changed)

  pruned (§14) or released (§13), not shown expired by its writer's newest node
  (§14.1), not cut or otherwise refused — then lies in a branch no walk

  the first look of `get`, `watch`, `put` or a hold (§15) — runs on its

  them: not covered by a checkpoint held whole, not pruned, cut or let go.
- **Inside a walk of a version's pieces** (§13.1) — a read, a holder's
  repair, a merge version's pieces — each piece is an owed fetch, asked in
  place up to `FETCH_TRIES` asks per source, at most `Config::window` of
  one walk's pieces at once; a piece that missed at every source leaves
  the others to be fetched and kept, and the walk ends without the
  payload. A read asks again as its caller does; the loops above ask
  again for merge pieces and a holder's take.

- **Custody asks** (§13.3) — within one `hold` call or release, never
  past it: an audit ask no answer signed by the holder came back to, as a
  new ask under a fresh nonce, up to `AUDIT_TRIES` (8) asks per piece per
  audit — but, once at least `AUDIT_TRIES` of the audit's asks went
  unanswered and the holder answered none, at most `SILENT_ROUNDS` (3)
  per piece (the holder is silent in that audit); a hold ask to
  a named holder whose lease does not count, under a fresh nonce and
  proof, up to `HOLD_TRIES` (16) asks per holder per call, while fewer
  than `copies` count — none to a holder silent to the call's audit of
  its live lease. A piece still unanswered after its bound leaves the
  audit unanswered, never broken; a holder still without a lease that
  counts, or silent, is left to the next `hold`.
- **A holder's take** of what an accepted hold record asks (§13.2) — in
  rounds, while a version inside `at` is not held or a piece of one
  is missing: at most `REPAIR_ROUNDS` (16) rounds per take, ended by 3
  rounds in a row (`REPAIR_IDLE`) that brought nothing; the owner's next
  hold ask starts the next take. Each round asks each entry inside `at`
  it can name and does not hold as an owed fetch (`FETCH_TRIES` asks). A
  hold ask waiting for the take is answered, with the lease of what is
  kept, once the take brought nothing since the last such answer (before
  one, during its wait), so an owner's asks of a holder whose take gets
  nowhere end at the same lease twice, and those of a holder whose take
  still brings pieces do not.

`RTO` reaches it and an ask is one Interest, as without re-expression. A
custody ask (§13.3) is expressed once: its call asks again, as a new ask
under a fresh nonce. A granter that sees two Interests of one grant ask

pruned, cut, expired past its keep, released, its collection or folder no

Custody asks are bounded per call: one `hold` sends a holder at most
`HOLD_TRIES` hold asks (each with a lifetime of three first looks and one
Interest lifetime) and, per audit, `AUDIT_TRIES` asks for each of its
`Config::audit_pieces` pieces — and a holder silent to the audit, as when
its path is down, at most `SILENT_ROUNDS` asks per piece (three Interest
lifetimes and two pauses in all, the pieces asked at once) and no hold
ask; a holder whose take brings nothing answers each hold ask within
its wait, so it costs a call two asks; a release asks each candidate at
most `AUDIT_TRIES` `Whole` asks. A holder runs one take per collection at
a time, of at most `REPAIR_ROUNDS` rounds, each asking every missing
piece once per source; hold asks arriving meanwhile start nothing beside

`HEARD_MAX` + 1 entries, and such a name holds back a default record, a
refusal or a folder erasure until its walks spent their tries (§5):

(5) A holder is asked again only by its owner, within the call that asked
it, up to the bounds above; it waits for at most one repeated hold ask of
an asker beside the one in progress (§13.2), and answers a repeated audit
ask, under its new nonce, as any other, never from an earlier answer.

(6) Re-expression is timed by what the device measured itself and bounded

(7) Nothing another party sends ends a walk that is owed: owing is judged

(8) Nothing another party sends makes a device stop asking for a walk: a

(9) Only a first look of the device's own announces again in a group

## §18 Conformance (the lines that changed)

messages reach every member, a non-member's post reaches no one), c10
(prune of another's comment refused, the removal done as an edit), o1 (a

The slice-3 cases are c5 (a photo the repo leased is pruned: no lease
outlives keep, readers report it pruned), h1 (a photo of hundreds of pieces
read whole and verified), h2 (a holder that silently lost what it leased is
caught by audit and repaired, and released data stays readable from it), h3
(a holder keeping three quarters of what it promised fails its audit), h4
(no lease outlives keep, before or after the keep passes), h5 (prune ends
leases: the holder drops what it covers, audits never ask for it), h6
(sealed data held by a device outside its audience stays unreadable to it
and readable from it), h7 (with one copy, the only holder's loss leaves the
photo kept nowhere, and `hold` reports it unkept, claiming no repair), and
from the slice-3 security review h8 (a holder that keeps nothing and
relays audits from the owner cannot make it release: the owner keeps its
copy, saying why) and h9 (a prune the holder heard before its auditor does
not frame it: its answer names the prune, and the audit passes).

The slice-4 cases are c6 (a soil sensor puts a reading a second, batched
by a minute, into a one-key collection whose one writer is the sensor's
key: signatures grow with blocks, not readings, no reading waits longer
than the delay accepted, every reading reaches the repo; signatures,
Interests, bytes and energy per reading are recorded, batched and
unbatched), s1 (a range read by time and by seq returns exactly the entries
in the range, with far fewer Interests than the stream has blocks), s2 (an
entry forged inside a block at the holder is never returned: the sensor
offline, the reader reads from the holder, and the genuine entry arrives
later), s3 (an entry spliced in from another block, likewise), s4 (after
keep passes, the holder and the reader drop the data, `get` answers
`Expired`, watch reports it, a range read lists it expired; a holder whose
slow clock still serves it does not make a right-clock reader keep it),
s5 (a replayed old head, the sensor offline, does not make `get(C)` answer
a version older than one already verified) and s6 (a stopped stream: the
sensor writes readings kept until a date, then one kept forever, and never
writes again; after the keep passes and the sensor, the repo and the
caches dropped the expired blocks, a phone that never held the stream
starts watching it and reports the reading kept forever within a bounded
time, reporting and storing none of the expired blocks).

covers are not fetched), b5 (releasing merge pieces without a covering
checkpoint proved held by audited holders is refused, saying why), b8 (a

another member works offline: back before any release, the member's edit

restart. d9 (a members record's batch holds the key of the epoch it starts
before the record, and the erasure of the old epoch's key in the same
batch, as one `apply`; a child killed at a random moment inside rotations
leaves, on both engines, a record of a collection only where its epoch's
key is held and the device writes into it; and on a store without atomic
batches, cut after every number of writes, the same) is in `ndn-data`'s
`device/batching_tests.rs`, with the check that a read by prefix inside a
batch sees what it stores, not what it removes, and applies nothing.

  120 s of virtual time (the harness's `AGAIN_PAUSE`, `AGAIN_FOR`); a
  `release` answered next step `HoldFirst` (§13.3: no holder proved it
  keeps the cover, perhaps only because its answers were lost) holds again
  and releases again within the case's own limit; it does neither on any
  other answer. Asking again is liveness only: a `RetryLater` or
  `HoldFirst` refusal decides nothing, and what the verb answers when it
  succeeds is judged as on a first try.

evidence (an equivocation, a breach, a refused version), and never stops
