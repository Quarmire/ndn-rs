# PSync conformance provenance

Behavioural provenance for the `ndn-sync` PSync FullProducer rework,
cross-checked against the on-disk C++ reference at `~/Documents/Dev/PSync`.
The **wire** formats (IBLT cell layout, name component, `PSyncContent`)
are unchanged and already covered by byte-level golden tests in
`crates/ndn-sync/src/psync.rs` (`ibf_cell_vector_matches_psync_cpp`) and
`psync_sync.rs` (`hash_name_matches_psync_cpp`). What follows pins the
*protocol* semantics that were added.

## Bounded, latest-version set (audit #1) — `ProducerBase`

`PSync/PSync/producer-base.cpp`:
- `updateSeqNo(prefix, seq)` (l.82): on a newer seq, `m_iblt.erase(hash(prefix/oldSeq))`
  then `m_iblt.insert(hash(prefix/seq))` — the set holds one element per
  prefix, not one per publication. `m_numOwnElements += (seq - oldSeq)`.
- seq `0` is never inserted (`if (oldSeq != 0)` guard, l.103).
- The IBLT name is `prefix.appendNumber(seq)` — a **generic** NameComponent
  carrying the NonNegativeInteger seq (1/2/4/8-byte width). ndn-rs mirrors
  this with `append_seq` / `parse_prefix_seq`; NLSR already publishes
  `user_prefix/<generic-NNI seq>` (`nlsr/sync.rs`), so no API change.

## Sync Interest num = cumulative (audit #2 heuristic)

`PSync/PSync/full-producer.cpp` `sendSyncInterest` (l.114):
`syncInterestName.appendNumber(m_numOwnElements)` — the trailing component
is the **cumulative** element count, not the current set size. ndn-rs now
sends `pb.num_own_elements`.

## Decode-failure full-state response (audit #2)

`full-producer.cpp` `onSyncInterest` (l.280 `if (!diff.canDecode)`):
- `numRcvdElements > m_numOwnElements` ⇒ we're behind; don't reply (wait).
- else ⇒ `state.addContent(prefix.appendNumber(seq))` for every prefix
  with `seq != 0`, `sendSyncData(..., 10ms)` — dump the whole state so the
  peer resynchronises (l.313-326). ndn-rs: `Action::Send(state_names())`
  when `num_elems <= num_own_elements`.

## Pending-interest table (audit #3)

`onSyncInterest` (l.339): when `diff.positive == 0 && diff.negative == 0`
the Interest is stored in `m_pendingEntries` with an expiry =
Interest lifetime; `satisfyPendingInterests` (l.491, called from
`publishName`) re-diffs each held Interest and replies when `positive > 0`,
erasing it. ndn-rs: `Action::HoldPending` on the channel path +
`satisfy_pending`. A synchronous direct-reply (CallbackFace) Interest can't
be held, so it gets an immediate (possibly empty) Data — matching the
existing NoRoute-Nack-avoidance behaviour.

## Relay-capable learned names (audit #4)

C++ keeps every name in the bi-map regardless of who published it, so any
node can answer a reconcile for names it learned. ndn-rs now routes
received Sync Data names through `ProducerBase::apply`, populating
`hash2name` so they are offerable (the prior code inserted only into the
IBLT, never the name table).

## Segmented Sync Data (audit #6) — `segment-publisher.cpp`

`PSync/PSync/segment-publisher.cpp` `publish` (l.40): a State larger than
`maxSegmentSize` (C++ default 8000) is split into Data named
`<interest-name>/<version>/seg=<i>`, each carrying `FinalBlockId = seg=N-1`,
held in an in-memory store and served on re-request. ndn-rs mirrors this in
the crate-internal `transfer` module **shared with the SVS Layer-1 fetcher**:
- producer: `segment_sync_data` → `transfer::segment_blob` chunks the
  (zlib-compressed) `PSyncContent` at `PSyncConfig::max_segment_size`
  (default 7000), `final_block_id_typed_seg`, signs `DigestSha256`; the
  driver stores every segment (bounded `SEG_STORE_CAP`) and serves a peer's
  `seg>=1` Interest verbatim.
- consumer: a seg=0 reply with `FinalBlockId > 0` triggers
  `transfer::windowed_fetch(base, 1..=last)` off the driver loop (so the loop
  keeps delivering the segment responses it depends on), reassembles the
  concatenated contents, and parses the `PSyncContent`. A single-segment
  reply (the common case) is unchanged on the wire.

## Partial Sync (audit #5) — `partial-producer.cpp` + `consumer.cpp`

The asymmetric producer/subscriber variant, in `psync_partial.rs`
(`join_psync_partial_producer` / `join_psync_partial_consumer`) over the
wire-compatible Bloom filter in `psync_bloom.rs`.

- **Bloom filter** (`detail/bloom-filter.cpp`): Arash Partow filter,
  MurmurHash3-keyed over the Name TLV value. The optimal-parameter search,
  128-entry predefined salt table, `(seed*0xA5A5A5A5)+1` mixing, and the
  `appendToName` layout (`count`, `fpp*1000`, raw bit-table) are ported
  byte-for-byte. Anchored on `tests/test-bloom-filter.cpp`:
  `BloomFilter(100, 0.001)` ⇒ 10 hashes / 180-byte table, `count=100`,
  `fpp=1`; loading those 180 bytes as `(200, 0.001)` (360-byte table) is
  rejected (`psync_bloom::tests`).
- **Hello** (`onHelloInterest`, l.82): `/<sync>/hello` ⇒ Data named
  `/<sync>/hello/<IBF>` whose content is the full `<prefix>/<seq>` list. The
  consumer (`onHelloData`, consumer.cpp l.156) emits updates for already-
  published subscribed prefixes straight from this list.
- **Sync** (`onSyncInterest`, l.108): `/<sync>/sync/<BF-count>/<BF-fpp>/
  <BF-bits>/<IBF>`; the producer subtracts IBFs, filters the positive
  difference through `bf.contains(name.getPrefix(-1))`, and replies
  `…/<current-IBF>`. Empty result ⇒ the Interest is held in
  `m_pendingEntries` and re-checked on every `publishName`
  (`satisfyPendingSyncInterests`, l.211). Undecodable IBF diff ⇒ ndn-rs
  replies with the whole subscribed-to set + a fresh IBF (resync) rather
  than the C++ application Nack; the consumer catches up either way.

Replies are segmented through the same `transfer` pipeline as Full Sync.
`SyncHandle::subscribe(prefix)` is honored only in Partial mode (the Full
producer/SVS return `SyncError::Unsupported`).

## Not yet implemented

- Consumer-side application-Nack content-type signalling (the resync-on-
  undecodable path above is used instead) and explicit retx beyond the
  periodic re-send.
