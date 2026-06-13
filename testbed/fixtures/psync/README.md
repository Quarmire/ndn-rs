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

## Not yet implemented

- Partial Sync (`partial-producer.cpp` + the Bloom-filter subscription
  consumer, `detail/bloom-filter.cpp`).
- Consumer-side Nack/retx beyond the periodic timer.
