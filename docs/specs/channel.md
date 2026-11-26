# Channel: ephemeral live data over a space

- **Status:** implemented. Stage 2 built: the setup (names, the ask, the session, judging at both ends, renewal, re-keying, ending, the announce, limits and refusals, the setup TLVs and their vectors). Stage 3 built: the frame (§11: header, key schedule and seal, messages, kinds, limits, short frames on L2, vectors, threat notes); the receiver (§12: the order of checks before any cryptography, the hold of frames that overtake their session, the replay window, the generation check, key epochs, the name table and its 50 ms hold, `HELLO`, standing values, the queues per mode and the gap rule, `Items`, limits, threat notes); and the sender (§13: `Heap::emit` and its refusals, the combining writer with its headroom rule and re-pack, the name-id table and the `CONTROL` bodies, the three modes, `stand`, what a new session is given, the carrier a face must provide, the `END` a closed channel sends, limits, threat notes). Stage 4 built: the forwarder's side table (§14: the `SideRoute` header 0x0370 that the session's own Data carries, the table and its limits and refusals, the peel and the fan-out, `UP` keep and unsub, teardown at every site a face goes down, the bar, the per-face rate, what each face carries, what a node does with it, the management commands, threat notes). Stage 5 built: checkpoints (§15: the signed record with its vectors, the sender's schedule, the receiver's judgement, evidence, the bar, the silence rule, `Trust::Verified`, the stated window, what is not judged, threat notes); §13.12 lists what stays accepted after both. Stage 6 built: the verbs `put`, `emit`, `get` and `kept` (§17: one stream of the kept values and the emissions of a space, with its order, duplicates, slow reader and refusals). Stage 7 built: the channel replaced the signals (presence and cursors are `emit` in `Latest` mode); the signals, their gate calls and their TLV block 0x0580–0x05AF are retired and the former specification is kept in [history/signals.md](history/signals.md); [heap.md](heap.md) §11 states the gate that remains, and `standing` is the channel's alone.
- **Implementation:** `ndn-heap`, module `chan` (`ndn-rs/crates/app/ndn-heap/src/chan/`): `wire.rs` (the records), `answer.rs` (the sender judges), `ask.rs` (the receiver asks and judges), `channels.rs` (the sender's table), `sessions.rs` (the receiver's store), `hub.rs` (the node's state, the announce, the maintenance task), `standing.rs` (membership). Stage 4 adds `route.rs` (the node's `Keep`, `Unsub`, gate and carrier over a connection to its forwarder) and `bar.rs` (the `IngressBar`); stage 5 adds `checkpoint.rs` (the record), `verify.rs` (the receiver's memory of accepted frames and its judgement), `evidence.rs` and `config.rs`, and its sender and receiver parts are in `tx.rs`, `queues.rs`, `rx.rs` and `items.rs`. The forwarder's side is in `ndn-packet`, `ndn-transport`, `ndn-engine`, `ndn-mgmt`, `ndn-face-local`, `ndn-app` and `ndn-face` (§14).
- **Scope:** an ephemeral **channel**: one device of a writer of a space sends live data (presence, a cursor, a drag) to the devices of the space's readers and writers, without making an entry. This file specifies how a channel is **set up** between two devices by signed NDN: who is answered, how a key reaches only the devices that may hold it, how a session ends, is renewed and is re-keyed; the **frame** (§11) that carries the data once it is set up: the header, the key schedule and the seal, the messages, the limits and the short-frame rule for raw L2 faces; the **side table** (§14) with which a forwarder copies a frame to the faces of the receivers; and the signed **checkpoints** (§15) by which a receiver tells the frames the sender sealed from a key holder's. It builds on [heap.md](heap.md) (names §2, the members record §5, epochs and audiences §6, the lapsed rule §9.3) and uses ndn-link's carrier ([ndn-link.md](ndn-link.md)) for what comes after setup.

The key words "MUST", "MUST NOT", "SHOULD" and "MAY" are as in BCP 14, in capitals only.

## 1. Terminology

| Term | Meaning |
|---|---|
| space | An `ndn-heap` space `<O>/32=data/<c1…c4>` ([heap.md](heap.md) §2.1). Its members record ([heap.md](heap.md) §5) says who writes and who reads. |
| sender | A **writer's device** that emits in a space. A channel has exactly one sender. |
| receiver | A device of a reader or a writer that holds a channel's session. |
| channel | One sender's emissions in one space in one mode, for the life of one session: a random 64-bit **channel id**, one key, one name-id table, one sequence. A sender has at most one channel per (space, mode). |
| session | What the sender's signed Data gives a receiver: the channel id, the key (wrapped), the carriers, the mode, the table. It lives until its lifetime passes or it is re-keyed. |
| ask | The receiver's signed Interest that requests a session. |
| key epoch | A counter of the channel's re-keys (`S_KEY_EPOCH`). The key of a channel changes with it; the id does not. |
| key holder | A device that holds a channel's key: the sender and every receiver it answered. |
| standing | A key **stands** for a space when the person it belongs to is listed by the space's record in the role asked, the key's role is one that may act as an owner device, and the trust context that governs it does not revoke it and this node does not mark it suspected (§4.1). |
| announce | An unsigned Interest a sender pushes into the space's sync group to say it has a channel. A hint, never a proof (§9). |
| route | One path of a channel's frames through one forwarder: an id, one source face and one or more sink faces (§14). |
| side table | A forwarder's table of routes. It copies each channel frame to the sinks of its route and knows nothing else of it (§14). |
| checkpoint | A frame the sender signs: the hashes of the frames it sent in a range of sequences. It is how a receiver tells the sender's frames from a key holder's (§15). |
| bar | A forwarder's refusal of the channel frames a face sends it, for a time, after a frame that came over that face was shown to be a forgery (§14.7). |

## 2. Names

- **The ask and its answer** are named `<sender>/32=chan/<ParametersSha256Digest>`, where `<sender>` is the **sender's device name**: the components before the keyword, a device name (no keyword and no digest component). Exactly one component follows the keyword, and it is a ParametersSha256DigestComponent of 32 octets. Nothing else parses as a channel name. The Interest carries ApplicationParameters (§3) and is signed by the **receiver's device key**; the Data of exactly that name is signed by the **sender's device key**.
- **Why the name is under the sender.** Every packet a device signs is named under that device ([heap.md](heap.md) §2.2): the validator picks the trust context, the schema and the anchors by the name, a node serves exactly the prefix of its own device, and one Interest cannot gather one Data from every writer (the PIT is satisfied once). So a receiver asks each sender by that sender's name. The space and the wanted prefix are in the ApplicationParameters, which the signature and the parameters digest cover.
- **`chan` is a core keyword.** The keyword router ([heap.md](heap.md) §2.4) sends `<device>/32=chan/…` to the channel setup; an extension is never given it.
- **The announce** is named `<sync group of the space>/32=chan/<ParametersSha256Digest>`: the space's sync group `<O>/32=sync/<c1>[/<c2>…]` ([heap.md](heap.md) §2.5) followed by the same two components.

## 3. The setup

### 3.1 The ask

The ask is an Interest named `<sender>/32=chan/<digest>`, `MustBeFresh`, InterestLifetime 4 s, ApplicationParameters = one `CHAN_ASK` (§7), at most 8 KiB. It is signed: an `InterestSignatureInfo` with the receiver's device key name as KeyLocator, a `SignatureNonce` and a `SignatureTime`. A node signs no Interest but this one (and only for a `CHAN_ASK`, and for a device that lies under neither `/localhost` nor `/localhop`): a signed Interest of a device's key is a command wherever that key is trusted.

The ask names the space, the path prefix the receiver wants (empty: everything), the mode (`Latest`, `Reliable`, `Window`), the receiver's X25519 recipient key (the key `K` is wrapped to), the carriers it can use, the lifetime it wants in seconds, in a sealed space the epoch it holds in force, whether it holds **no session** of the channel (`ASK_NEW`), and up to four certificates (`ASKER_CERT`: 4,096 octets each, 6,144 in all) of its signer's chain, so the sender judges the signature from what is held and carried and **fetches nothing**. A receiver sets `ASK_NEW` when it holds no live session of that (sender, space, mode): a first ask, or one after it let the session go. The sender is not told when a receiver lets go, so a device it remembers that says `ASK_NEW` is **claiming** to be new again, and the sender cannot check the claim: a device it never listed is given what a new receiver is given (§13.7) at once, a **claim** is given it only when the channel's replay limiter admits it (at most one a second per channel, and only while the stream's queue has room: the limiter of `ASK_SINCE`, §13.7) and is otherwise refused `Busy` with the time to wait.

### 3.2 The session

The session is the Content of a Data of exactly the ask's name, signed by the sender's device key, `FreshnessPeriod` 0, carried in an NDNLPv2 packet with `CachePolicy = NoCache`: nothing of a channel's setup is cached. A session (not a refusal) also carries the **`SideRoute` header** `(channel id, 30 s)` (§14.3), which is what makes every forwarder on its reverse path install a route for the channel's frames; it is not covered by the signature. The Content is one `CHAN_SESSION` (§7), at most 8,000 octets. It names the channel id (8 octets, random from the system's CSPRNG), the sender and the space and the mode, the **key epoch**, the key's id (the first 8 octets of HKDF-SHA256 of `K` with info `ndn-channel/id/1`), the **wrapped key**, the AEAD (1 AES-256-GCM when the CPU has AES and carry-less multiplication, else 2 ChaCha20-Poly1305: every receiver supports both), the carriers on offer, the name table bound so far (at most 64 binds and 4 KiB), the checkpoint period (0 when the sender sends no checkpoints, §15.3), in `Window` mode the window, the lifetime in seconds counted **from receipt on the receiver's monotonic clock**, in a sealed space the audience epoch the sender judged the receiver by, the largest datagram frame, the next sequence the sender will use, and up to four certificates of the sender's chain (`S_CERT`).

- **The key.** `K` is 32 random octets from the CSPRNG per sender, per space, per mode, per session. It is never derived from a space's epoch key (a derivation would hand every member of an epoch every sender's key unasked, and a public space has no epoch key). The epoch decides the **audience** (who is judged in); it does not decide the key. The AEAD of a frame never uses `K` directly: it uses `HKDF-SHA256(K, "ndn-channel/frame/1" ‖ channel id ‖ key epoch)`.
- **The wrap.** `S_WRAP` is the 32-octet ephemeral X25519 public key followed by the sealed key (`nonce (12) ‖ tag (16) ‖ ciphertext (32)`), made as a grant's key is ([heap.md](heap.md) §6.5): X25519 between the ephemeral key and the ask's recipient key, a key-encryption key `HKDF-SHA256(shared, info "ndn-security/confidentiality/x25519-kek/1" ‖ ephemeral ‖ recipient)`, and the AEAD of `K` under it with the **Name TLV of the answering Data as the AAD**. So the key opens only with the recipient's secret and only under that name.
- **One channel, many receivers.** A second receiver's ask for the same (space, mode) is answered with the same channel id and the **current** key.

### 3.3 Judging the asker

The sender judges the ask in this order, cheapest first, so a stranger costs nothing and a member costs one signature verification. The steps that decline without a word answer a Nack and sign nothing.

1. **The name and the size.** The name parses as `<this device>/32=chan/<digest>`; the ApplicationParameters are at most 8 KiB, hash (as the Interest's `ParametersSha256Digest` is made) to the digest, and parse as a `CHAN_ASK`; the Interest is signed and its KeyLocator names a key of a device (`<device>/KEY/<id>`); the space is a space name and is open here as a member. Otherwise a `NoRoute` Nack. An ask over 8 KiB is counted and Nacked unread.
2. **Standing.** The key stands as a **listed** person ([4.1](#41-standing)): a writer or a reader the record lists, a key whose role is owner-capable, not revoked, not suspected, **by the entries held now**. A public space does not make a reader of an unlisted person: **channels need a listed person**, because a channel's key is wrapped to a judged key (kept data in a public space stays readable by anyone; live data does not). Otherwise a `NoRoute` Nack. This is a lookup: no signature is checked for a stranger.
3. **The clock, then the verification budget.** The ask's `SignatureTime` must be within 120 s of this device's clock (the one wall-clock reading of the setup), else a `NoRoute` Nack before any signature is checked; an ask with no `SignatureTime` is a `NoRoute` Nack too. Then one token of the **verification budget**, one bucket for every ask that reaches the signature: 64 a second, a burst of 256 (a whole channel asking after a re-key), whoever the asks name. Over it a `Congestion` Nack (`Busy`, `RetryLater`). The budget charges no asker: the key an unverified ask names is whatever its sender wrote, so a bucket of that key charged here would be anyone's to empty.
4. **The signature.** The Interest signature verifies by the live rule from the certificates held and the at most four carried, **fetching nothing**; the carried certificates are held only as unverified copies for the hop they answer and dropped again unless the walk reaches a trust anchor. The signer is judged by the trust context of **its own device**, not of the name the Interest is under. A chain not held and not carried is `Pending`: a `NotYet` Nack, which says "ask again when you carry your chain". A signature that does not verify is a `NoRoute` Nack. This is the one expensive step, bounded by the budget of step 3: the asks that reach it name a listed person's key and are fresh, and are not necessarily the person's own.
5. **Replay, then the asker's rate.** The replay guard of signed Interests (the asker's `SignatureNonce` and `SignatureTime` against what was seen for that key; it remembers the last 1,024 asks of a key, the 240 s an ask is good for at the rate below) answers a repeated ask with a `Duplicate` Nack. A restart empties the guard: an ask captured in the 240 s before it can be replayed once after it (§10). A replayed ask would only yield a session wrapped to the asker's own recipient key, which only it can open, so the guard limits cost and decides no trust. An honest asker signs every ask afresh (a new nonce), so a `Duplicate` it gets is a copy of an ask that already arrived (a retransmission on the path): its next ask is accepted, `Busy`, `RetryLater`. Then the **asker's rate**: a token bucket per asker key, 4 asks a second, a burst of 8, charged only now that the signature verified and the ask is no copy (the asker is a member and the key is its own; a copy or a forgery never costs a member a token). Beyond it a `Congestion` Nack: the Nack says "slower", not "no", and the asker's next step is to ask again later (`Busy`, `RetryLater`).

The asker is now a verified member, and what follows is answered with a **signed** record (a session or a refusal), read again under one lock of the record, as the key that signed the ask:

6. Standing again. The record may have moved while the signature was checked; if the key no longer stands, a `NoRoute` Nack.
7. **This device is a writer** of the space (`standing` for its own key, writers only). It always is, or it would have no channel; if it is not, a `NoRoute` Nack and its channels of that space end.
8. **A sealed space's audience.** The sender's epoch in force must exist (else `NotReady`); if the ask names an epoch that is not the epoch in force, a sender that has never seen it answers `StaleEpoch` and one that has seen it and has moved on answers `NotReady`; the asker's person must be in the audience of the epoch in force (else a signed `NotAudience` refusal: an authenticated asker learns only what a plain read of a sealed path tells it).
9. **The mode needs a stream.** A `Reliable` or `Window` ask whose carriers list no stream is a `NoStream` refusal. So is one whose first hop toward the asker has none: the sender's forwarder says whether the face the ask came in over carries the stream class (§14.9), and the refusal says that no ordered stream reaches the asker and to ask with `Latest`, or put the value instead. A `Latest` ask over such a hop is answered, with a session whose carriers are the datagram alone (§14.9).
10. **The caps** ([§6](#6-limits-and-refusals)): channels per sender and receivers per channel; else a signed `TooMany`.
11. The channel of the asked mode is found or made; the asker is added to it (§3.5); the key is wrapped; the Data is signed.

### 3.4 Judging the sender

The receiver judges the answer in this order:

1. The Data's name equals the Interest's name.
2. The Data verifies as the sender's by the durable rule ([heap.md](heap.md) §9: the signature and the certificate chain, no clock except for a key whose role needs a cut), from the certificates held and the at most four the session carries, fetching nothing; the key that signed it is a key of the device the name is under. A Data that cannot be judged now is not used.
3. **The sender is a writer now**: its key stands as a writer, not revoked, not suspected. A reader's device never emits: a Data signed by one is `SenderNotWriter`, whatever it holds.
4. A `CHAN_REFUSAL` is told as it is: it is signed, so it is the sender's word.
5. The session names the sender, the space and the mode that were asked.
6. **A sealed space.** `S_AUDIENCE_EPOCH` must equal the epoch in force at the receiver. One the receiver knows and that is no longer in force is a sender that has not caught up: `StaleEpoch`, ask again soon. One the receiver does not hold waits for the record: `NotReady`.
7. **The key opens** under the receiver's recipient secret with the Data's Name TLV as the AAD, and is the key the session names (`S_KEY_ID`).
8. **The session is installed**, its lifetime counted from receipt on the monotonic clock. If a session of the same channel id is held it is **renewed**: the key epoch moves, the lifetime restarts. A session of the same sender and mode with another channel id replaces the old one: the sender began a new channel. A session whose channel id is held by **another** (space, sender, mode) is refused (`BadAnswer`, which says whose channel holds the id) and installs nothing: the id is in the clear in every frame, and no sender may take another's.

**An answer that comes after a release is discarded.** A receiver **releases** a channel when the last `Items` taking its (space, mode) is dropped (§14.10). The release's `Unsub` and the route that a late answer's Data installs race at the forwarders, so such an answer says nothing of what the receiver holds. The receiver therefore counts releases of each (space, mode). An ask records that counter **before** it decides `ASK_NEW` (§3.1) and sends its Interest. When the answer has been judged (steps 1 to 7), the session is installed only if no release of that (space, mode) happened since the ask began; the check and the insert are one step under the session store's lock. Otherwise the answer is discarded with `ChanError::Superseded` (next step `RetryLater`: ask again if a stream still wants the channel) and the next ask is new (`ASK_NEW`: `HELLO`, names and standing values follow). The order is a counter, not a clock. A renewal of a held session is not affected. A discarded answer's route is given up with one best-effort `Unsub`, sent only if no other ask of that (space, mode) is in flight and no session holds the id (another ask's answer lays the route again, and the `Unsub` could take it); a route left standing lapses at its TTL (§14.6). An ask that began after the last `Items` was dropped (an announce-driven one) and installed a session that no `Items` takes lets it go at once, as a release does, so that the next ask is not made as a renewal. `NoPath` (§14.10) is unchanged.

### 3.5 What the sender keeps

The sender's channel table holds, per (space, mode), the channel's id, its key and key epoch, when the key was made, the next sequence, the audience epoch the receivers were judged by, and, per receiver **device**, the key that signed its last ask, the key epoch it was last given, when, and for how long. A session's lifetime is the ask's, clamped to between a minute and 24 hours, and one hour when the ask names none; it is never refused for this. A receiver is a receiver until its lifetime and 5 s of grace passed since it was last given a key. A channel nobody holds for a default lifetime ends: its key is zeroed.

### 3.6 Ended, renewed, re-keyed

A channel's life is bounded by five things, each a signed record or a local fact, never a timer alone:

1. **The members record, and the trust generation.** The sender re-judges every receiver, offline, in one call, when the space's record changes or a trust context that revokes keys is adopted (both wake the node's maintenance task; it also looks every 250 ms): a receiver that no longer stands (its person left the record, or its key is revoked or suspected) or whose person left the audience of the epoch in force is **dropped**, and the channel is **re-keyed at once**. A channel whose audience epoch moved is re-keyed too. These are two causes, so removing a reader of a **sealed** space re-keys twice: once for the removal, and again when the owner's next epoch (which the removal owes) arrives and moves the audience. Between them the old epoch is no longer in force (a person it names is no longer a reader) and no audience can be judged: a receiver that still stands is kept, none is dropped for the want of an epoch, and the next ask is answered `NotReady`. Nothing re-keys without one of these causes. A sender that is no longer a writer ends its channels of the space. A receiver does the same for every sender it holds, against the writers of the record: a session caches the pair `(trust generation, the space's fold version)` it was judged under and exposes `is_current()` (two atomic loads); when either has moved the sender is judged again from what the node holds before another frame is delivered, and a sender that no longer stands as a writer ends the session with `NotMember` and the reason. A receiver whose own person left the space drops its sessions of it.
2. **A grant** of a link ends the link, and its faces go down: every route over them goes with them (§14.6). A link that loses the identity that authorized channel frames and stays has its routes dropped by the forwarder ([ndn-link.md](ndn-link.md) §9 item 8).
3. **The lifetime.** A session is **usable** until its lifetime and a 5 s grace passed since receipt, counted on the monotonic clock. A session past that is not used and is dropped.
4. **The sender stops answering,** and ends the channel with a `CONTROL END` frame on the stream when it closes it (§13.11): a removed receiver's asks are Nacked; a stopped sender answers none.
5. **The route's lifetime.** A sink at a forwarder lapses 30 s after its last `Keep` (§14.6); a receiver that left or was removed stops sending them.

**Renewal.** A receiver asks again at 75 % of the lifetime, with the same channel id; the answer carries the same `S_ID`, a new lifetime and, because a receiver that holds the current key and asks after half its lifetime renews, a **new key** (`S_KEY_EPOCH` + 1) unless the channel was re-keyed in the last 5 minutes. An ask sooner than that, from a receiver that holds an older key, or inside those 5 minutes, is given the key as it is. **No receiver can make the others ask again at will**: the asker names its lifetime, but one under a minute is raised to a minute (the renewal threshold is never under 30 s), and what an asker can cause by renewing or by vanishing is one re-key in 5 minutes; only a removal or revocation, which are signed records, re-key at once. A renewal that failed is tried again after 10 s.

**Re-keying is pulled.** The sender re-keys at once when a receiver is removed or the trust generation moved, when the sealed space's epoch changed, and before the sequence passes 2^63; at a renewal and when a receiver's lease ran out it re-keys **at most once in 5 minutes** (`REKEY_MIN`): a renewal inside that time is given the key as it is, and the lapses of a stretch are one re-key, made when the 5 minutes have passed. It seals under the new key from the next frame and answers asks with it. A receiver that sees a frame under a key epoch it does not hold asks again, **at most once a second per sender**; the sender answers every asker it still judges in and Nacks the removed. **Nothing is pushed to a receiver**: nothing a removed member could be sent, nothing to forge.

**The key before.** A receiver accepts the key before the current one for `REKEY_GRACE` (5 s) after the answer that gave it the new key epoch, so frames in flight are not lost. (A frame under a key the receiver does not hold is not authenticated, so it starts no grace: it would be a time anyone who can reach the device could choose.) A removed member's forgeries under the old key are bounded to that grace and then to the checkpoint window (§15.9).

**After a removal** the removed member holds the old key and can read what was sealed under it; it cannot open anything sealed after the re-key.

## 4. Who may take part

### 4.1 Standing

`standing(space, key, who)` is the one question both ends ask. It holds when: the key names a device (`<device>/KEY/<id>`); the trust context governing the key (the node's own for a person it holds, else the view adopted for the person while a listing of the space names her) names a person the record lists as `who` says; the key's role is one that acts as an owner device where the namespace declares the role layout (a `guest` or a `node` device is none, [heap.md](heap.md) §9.9); the context does not revoke the key; and this node does not mark it suspected. `who` is **Writer** (a writer; the owner always is: what the sender is judged as) or **Listed** (a writer or a reader the record lists: what a channel asks of a receiver; a public space makes no reader of an unlisted person). The answer is read from what is held at the call: it flips on the first call after the entry that removes a person, or the context that revokes a key, is held.

### 4.2 Who may call what

A device **sends** only as a writer; it **receives** as a reader or a writer the record lists. A follower (a node that follows the space's group but is no member) takes no part in channels: `get` refuses it `Live::Emitted`, and it may read kept values with `Live::Off` (§17.7). A `guest` or `node` device never sends or receives.

## 5. Surface

On a node's handle: `ask_channel(space, device)` and `ask_channel_in(space, device, mode)` ask a sender and return the session's `ChannelInfo`; `sign_interest(prefix, parameters)` signs the one Interest a node signs: `<device>/32=chan` with `parameters` that decode as a `CHAN_ASK`, for a device that lies under neither `/localhost` nor `/localhop` (refused for any other name, any other parameters, or a reserved device). Every refusal is a `ChanError`, which says why and, by `next()`, what to do in the heap's `NextStep` vocabulary. For the frame layer: a session store (`RecvSessions`: `get(id)`, `unknown_epoch(id, now)`), a session (`RecvSession`: `frame_key(low, now)`, `usable(now)`, `is_current()`, `recheck(node)`, `terms()`) and the sender's table (`Channels`: `current(space, mode)`, `open`, `note_seq`, `close`), all in `ndn-heap`'s `chan` module.

## 6. Limits and refusals

| What | Limit | Over it |
|---|---|---|
| Ask size / session size | 8 KiB / 8,000 octets | Nacked unread / the sender drops the certificates it carries |
| Asks per asker key | 4 a second, burst 8, charged after the signature verified | a `Congestion` Nack |
| Channels per sender / receivers per channel | 64 / 256 | a signed `TooMany` refusal, retry in 30 s |
| Session lifetime | 1 h default, at least 1 min, at most 24 h, renewed at 75 % | the ask's lifetime is clamped, not refused; a receiver refuses a session that names another |
| Re-keys of one channel from a renewal or a lapsed lease | one per 5 min | the renewing receiver is given the key as it is; a lapse waits (the lapses of a stretch are one re-key) |
| Asks whose signature is verified | 64 a second, burst 256, whoever they name | a `Congestion` Nack, before the signature |
| `SignatureTime` of an ask | within 120 s of the sender's clock | a `NoRoute` Nack, before the signature |
| Lifetime grace / key grace | 5 s / 5 s | the session is not used / the old key is not accepted |
| Asks for an unknown key epoch | once a second per sender | dropped undecrypted |
| Announce-driven asks | one per device per 10 s, 32 in progress per space | ignored |
| Announce | 1 KiB of ApplicationParameters | ignored |

Every refusal a person can see says why and what to do, in the heap's `NextStep` vocabulary.

| Refusal | Code | `NextStep` | Said by |
|---|---|---|---|
| `NotAudience` | 1 | `AskOwner` (ask the owner to add you as a reader, or to write an epoch that lists you) | the sender, signed |
| `Busy` | 2 | `RetryLater` | the sender, signed |
| `NoStream` | 3 | `FixRequest` (ask with `Latest`, or `put`) | the sender, signed |
| `StaleEpoch` | 4 | `RetryLater` (retry in 1 s) | the sender signed; the receiver for a session on an older epoch |
| `TooMany` | 5 | `RetryLater` | the sender, signed |
| `NotReady` | 6 | `RetryLater` (retry in 2 s) | the sender signed; the receiver for a session on a newer epoch |
| `NotAnswered` (a `NoRoute` Nack) | | `RetryLater` | the network: not a member by the entries the sender holds, or no certificate it trusts, or no channel to give |
| `Busy` (a `Congestion`, `NotYet` or `Duplicate` Nack) | | `RetryLater` | the sender: over its rate for this device (`Congestion`), the chain of the asker's key not held and not carried (`NotYet`: carry the chain, the ask does), or a copy of an ask it saw (`Duplicate`: the next ask is signed afresh) |
| `Unreachable` (no answer) | | `RetryLater` | none |
| `SenderNotWriter` | | `FixRequest` (ask a device of a writer) | the receiver |
| `BadAnswer` | | `RetryLater` | the receiver |
| `Superseded` | | `RetryLater` (ask again if a stream still wants the channel) | the receiver: the answer to an ask that began before the channel was let go |
| `NotAllowed` | | `AskOwner` | the receiver, for its own device |

## 7. TLV types

The setup's TLV-TYPEs are the block **0x0660–0x06BF**, registered to this file in the [specification registry](README.md#tlv-type-numbers). Odd numbers are critical: an unknown odd type inside these records is a malformed record. Even numbers are skippable and reserved for additive fields, as in [heap.md](heap.md) §3.4: an unknown even type is skipped. Numbers are NonNegativeIntegers. `Name` values are a Name's components, as the value of the TLV. `ASKER_CERT` is heap's 0x063D.

| Type | Name | Value |
|---|---|---|
| 0x0661 | `CHAN_ASK` | `ASK_SPACE`, `ASK_PREFIX`, `ASK_MODE`, `ASK_RECIPIENT`, `ASK_CARRIERS`, `ASK_LIFETIME`, `ASK_EPOCH`?, `ASK_SINCE`?, `ASK_NEW`?, `ASKER_CERT`* (0x063D) |
| 0x0663 | `ASK_SPACE` | Name |
| 0x0665 | `ASK_PREFIX` | Name: the path prefix the receiver wants (a filter and a hint for the table; the channel carries the whole space's emissions of the sender) |
| 0x0667 | `ASK_MODE` | 1 `Latest`, 2 `Reliable`, 3 `Window` |
| 0x0669 | `ASK_RECIPIENT` | 32 octets: the asker's X25519 recipient key |
| 0x066B | `ASK_CARRIERS` | the carriers the asker can use: a list of kind octets (1 datagram, 2 stream, 3 face-bytes, 4 L2, 5 ring), at most 16 |
| 0x066D | `ASK_LIFETIME` | seconds the asker wants (clamped by the sender to 60 to 86,400; 0: none named, an hour) |
| 0x066F | `ASK_EPOCH` | an EpochId (`Name(creator)`, `SEQ` 0x060B): the epoch the asker holds in force (sealed spaces) |
| 0x0671 | `ASK_SINCE` | `Window` only: the first sequence the asker still needs replayed |
| 0x0672 | `ASK_NEW` | empty (even, skippable by an older sender): the asker holds no session of the channel. A device the sender never listed is a new receiver (`HELLO`, binds, standing values, replay); a device it lists is **claiming** to be new again, and is given the same only if the channel's replay limiter admits the claim (§13.7), else the ask is refused `Busy`; a value or a second `ASK_NEW` is malformed |
| 0x0673 | `CHAN_SESSION` | the Data's Content: the fields below |
| 0x0675 | `S_ID` | 8 octets: the channel id (random, CSPRNG) |
| 0x0677 | `S_SENDER` | Name: the sender's device |
| 0x0679 | `S_SPACE` | Name |
| 0x067B | `S_MODE` | as `ASK_MODE` |
| 0x067D | `S_KEY_EPOCH` | NonNegativeInteger (at most 2^32 − 1), counts re-keys; the frame header carries its low 8 bits |
| 0x067F | `S_KEY_ID` | 8 octets: the first 8 of HKDF-SHA256(K, info `"ndn-channel/id/1"`) |
| 0x0681 | `S_WRAP` | 32 octets ephemeral X25519 key, then `nonce (12) ‖ tag (16) ‖ ciphertext` of `K` (32), wrapped to `ASK_RECIPIENT` (§3.2), AAD = the Data's Name TLV |
| 0x0683 | `S_AEAD` | 1 AES-256-GCM, 2 ChaCha20-Poly1305 |
| 0x0685 | `S_CARRIER` | repeatable: a kind octet, then its parameters |
| 0x0687 | `S_TABLE` | `S_BIND`*, at most 64 binds and 4 KiB (the rest follow on the stream) |
| 0x0689 | `S_BIND` | `B_ID`, `B_NAME` |
| 0x068B | `S_CKPT_MS` | checkpoint period in ms, 1 to 2,000 (a receiver holds it there); 0: this sender sends no checkpoints on the channel (its carrier has no stream) and a receiver waits for none (§15) |
| 0x068D | `S_WINDOW` | `Window` mode: `W_MESSAGES`, `W_BYTES`, `W_MS` |
| 0x068F | `S_LIFETIME` | seconds, from receipt, on the receiver's monotonic clock; 60 to 86,400 (a session that names another is refused) |
| 0x0691 | `S_AUDIENCE_EPOCH` | an EpochId (sealed spaces) |
| 0x0693 | `S_FRAME_MAX` | the largest frame the sender will send on a datagram carrier |
| 0x0695 | `S_SEQ` | the next sequence the sender will use |
| 0x0697 | `S_CERT` | repeatable, at most 4 and 6,144 octets in all, each at most 4,096: a certificate Data of the sender's chain |
| 0x0699 | `CHAN_REFUSAL` | `R_CODE`, `R_TEXT`, `R_RETRY` |
| 0x069B | `R_CODE` | 1 `NotAudience`, 2 `Busy`, 3 `NoStream`, 4 `StaleEpoch`, 5 `TooMany`, 6 `NotReady` |
| 0x069D | `R_TEXT` | UTF-8, at most 256 octets: why, and what to do |
| 0x069F | `R_RETRY` | milliseconds |
| 0x06A1 | `CHAN_ANNOUNCE` | `S_SENDER`, `ASK_MODE`+ (each mode once): the ApplicationParameters of an announce |
| 0x06A3 | `B_ID` | NonNegativeInteger: a name id |
| 0x06A5 | `B_NAME` | Name |
| 0x06A7 | `W_MESSAGES` | messages a window replays |
| 0x06A9 | `W_BYTES` | octets a window replays |
| 0x06AB | `W_MS` | milliseconds a window replays |

The whole `CHAN_ASK` is at most 8 KiB and the whole `CHAN_SESSION` at most 8,000 octets: larger is refused when written and when read. The field order above is the order written; a reader accepts any order and refuses a field twice or a required field absent.

## 8. Test vectors

Hex, one record each, as the implementation writes them (the same octets are asserted in `chan/wire_tests.rs`).

`CHAN_ASK`: space `/alice/32=data/notes`, prefix `/cursors`, mode `Latest`, recipient 32 × `11`, carriers 1 and 2, lifetime 3600, epoch (`/alice/laptop`, seq 3), since 9, one certificate `c0de01`:

```
fd066180fd0663140805616c69636520046461746108056e6f746573fd0665090807637572736f7273fd06670101fd0669201111111111111111111111111111111111111111111111111111111111111111fd066b020102fd066d020e10fd066f16070f0805616c69636508066c6170746f70fd060b0103fd06710109fd063d03c0de01
```

`CHAN_SESSION`: id `0102030405060708`, sender `/bob/phone`, the same space, mode `Window`, key epoch 2, key id 8 × `aa`, a 40-octet wrap of `bb`, AES-256-GCM, carriers 1 and 2 with no parameters, one bind (1, `/cursor/x`), checkpoint 20 ms, window (256, 1,048,576, 10,000), lifetime 3600, audience epoch (`/alice/laptop`, 3), frame limit 1200, sequence 7, one certificate `c0de02`:

```
fd0673f0fd0675080102030405060708fd06770c0803626f62080570686f6e65fd0679140805616c69636520046461746108056e6f746573fd067b0103fd067d0102fd067f08aaaaaaaaaaaaaaaafd068128bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbfd06830101fd06850101fd06850102fd068718fd068914fd06a30101fd06a50b0806637572736f72080178fd068b0114fd068d14fd06a7020100fd06a90400100000fd06ab022710fd068f020e10fd069116070f0805616c69636508066c6170746f70fd060b0103fd06930204b0fd06950107fd069703c0de02
```

`CHAN_REFUSAL`: `NotAudience`, "ask the owner to add you as a reader", retry 0:

```
fd069932fd069b0101fd069d2461736b20746865206f776e657220746f2061646420796f75206173206120726561646572fd069f0100
```

`CHAN_ANNOUNCE`: sender `/bob/phone`, modes `Latest` and `Window`:

```
fd06a11afd06770c0803626f62080570686f6e65fd06670101fd06670103
```

## 9. The announce

A sender pushes, once when it opens a channel, at every change of the space's members, and every 30 s while the channel lives, **one unsigned Interest** `<sync group of the space>/32=chan/<digest>` whose ApplicationParameters are a `CHAN_ANNOUNCE` (the sender's device and its modes), InterestLifetime 1 s, HopLimit 8. Nobody answers it and nothing caches it. It rides the group every member's forwarder already carries ([heap.md](heap.md) §2.5).

A receiver takes it as a **hint only**:

1. The parameters are at most 1 KiB and hash to the digest in the name; the group is a space this device holds as a member.
2. **Offline**, the announcing device's person (the person of the trust context governing it) must be a **writer** of the space, and the record must hold an **admitted entry of that device** (its key was judged for the space and its certificate is held). The announce is unsigned, so any name under a writer's namespace passes for one of her devices; a name no entry of which is held is counted and ignored. A stranger's announce costs this lookup and nothing else: no ask, no signature, no packet.
3. The device must be **wanted**: this device holds a registration of interest in live data of the space (an `Items` of a `get` in stage 6 holds one). Without one the hint is counted and ignored: a device that wants nothing live asks nobody.
4. Each device is asked at most once in 10 s, and at most 32 announce-driven asks are in progress per space; the rest are ignored. The ask is the setup of §3, one per announced mode, judged as any ask is: the announce decides nothing.

The sync driver never sees an announce: the sync face's reader takes a name of this shape off the face before the driver would see it. (A name under a group whose next component is not a version is not a Sync Interest in any case: the multi-group driver routes an Interest to a group by a trailing `v=` version component and drops one that has none.)

## 10. Threat notes for the setup

- **A stranger's ask.** A person the record does not list gets a `NoRoute` Nack after a table lookup: no signature is verified, none is made, nothing is fetched. A counter of the sender's signature walks proves it. An ask that names a listed person's key but is not signed by it (a forgery) costs one verification and a `NoRoute` Nack, and is charged to **nobody's rate** (the rate is charged after the signature verifies): forgeries draw on the one verification budget (§3.3 step 3), so a flood of forged asks naming a member cannot empty that member's own bucket.
- **A replayed ask.** An ask signed more than 120 s from the sender's clock is refused before its signature is checked; within that time the guard answers a repeat of a signed ask with `Duplicate` (it remembers the last 1,024 asks of each key: the 240 s an ask is good for). A sender that restarted has an empty guard: an ask captured in the 240 s before the restart can be replayed once after it, and is answered with a session wrapped to the **asker's** recipient key, which only the asker opens: whoever replays the ask holds nothing, and the receiver it adds is the asker's own device, whose lease ends with the ask's lifetime.
- **A forged session.** The session is a Data of the sender's device, judged by the durable rule; a Data signed by a key that is no writer is refused. A session on an epoch the receiver does not accept is refused. The wrapped key opens only with the receiver's own secret under the Data's name: a session copied to another name, or another device, opens nothing.
- **A stale or future epoch.** A sender on an older epoch is `StaleEpoch` (ask again soon); one on an epoch the receiver has not seen waits for the record (`NotReady`). Neither installs a session.
- **Removal.** The sender drops a removed receiver and re-keys at once; the receiver's asks are Nacked; it holds the old key and can read what was sealed under it, and nothing sealed after. A removed or revoked sender is dropped by every receiver at the first frame after the node holds the removing record or the revocation.
- **The announce is a hint.** It is unsigned; whoever can reach the sync group can send one. The worst it does is make a device that wants live data ask a device of a writer that the record holds an admitted entry of (a name nobody holds an entry of is ignored: the announce proves no key, so any name under a writer's namespace would otherwise take an ask slot), at most once in 10 s per device and 32 at a time per space; every ask is judged by signature at the sender and every answer by signature at the receiver. A writer's device that has written no entry of the space is asked by name (`ask_channel`), not by hint.
- **Clocks.** No decision about who is a member, which key stands, or whether a session is genuine rests on a clock. Lifetimes are counted on the receiver's **monotonic** clock from receipt, so a clock that steps changes nothing. The only wall-clock reading is a signed Interest's `SignatureTime`: the sender refuses an ask signed more than 120 s from its own clock (§3.3 step 3), so the replay guard need remember 240 s of asks and no more, and an ask captured and replayed later is refused whatever the guard holds. It decides no trust: an asker whose clock is off is not answered (a `NoRoute` Nack; `NotAnswered` names the clock) and asks again when it is right.
- **Cost of an ask.** A stranger: a lookup. A member whose ask is fresh and inside the verification budget: one signature verification at the sender (certificates held and carried, nothing fetched), one signature made, one X25519 agreement and one AEAD seal; at the receiver, one signature verification, one X25519 agreement and one AEAD open. An ask outside the 120 s costs a lookup and a Nack; one over the asker's rate costs one verification and a Nack. Forged asks that name a member's key cost verifications out of the **budget** of 64 a second and charge nobody's rate: a flood of them can use the budget up (members' asks then get `Congestion` and retry) and changes no state of any channel.

## 11. The frame

A channel frame is **not an NDN packet and not TLV**: it is a compact binary record, because it is on the hot path and a relay routes on its first ten octets. It travels as a *side frame* on a face that carries one ([ndn-link.md](ndn-link.md) §3.1; the face's `send_side`; a face carries side frames only if it opts in, by a `side_frame_max()` above its default of 0, so a face that frames, decodes or codes what it sends refuses every frame `NotCarried`, and a frame that does not start with the marker is refused `Malformed` by every face), is marked by a first octet of `0x00` (TLV-TYPE 0 is not assigned: no Interest, Data, Nack or NDNLPv2 packet starts with it), and is never fragmented, retransmitted or judged by the link service.

Implementation: the routing header and the `UP` record are in `ndn-transport` (`side_header.rs`); the rest of the header, the seal, the messages and the limits are in `ndn-heap` `chan` (`frame.rs`, `aead.rs`, `message.rs`, `varint.rs`, `limits.rs`, and, for the checkpoint hash ring, `ring.rs`). The forwarder's table that routes the frames is §14.

### 11.1 The header

Cleartext, and authenticated as the AEAD's additional data (§11.2).

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | `0x00`, the **marker** |
| 1 | 1 | `ver:3 \| class:1 \| kind:4`, high bit first. `ver` is 1. `class` is 0 for a datagram and 1 for a stream. `kind` is 0 `DATA`, 1 `CHECKPOINT`, 2 `CONTROL`, 4 `UP`. |
| 2 | 8 | the **channel id**, big-endian (for an `UP`, the route id) |
| 10 | 1 | the **key epoch**, low 8 bits |
| 11 | 8 | `seq0`, big-endian: the sequence of the frame's first message |
| 19 | 1 | `count`: the messages in the frame, 1 to 255; 0 for `CHECKPOINT` and `CONTROL`, which take one sequence |
| 20 | … | the body: the AEAD ciphertext, then the 16-octet tag |

A sealed frame has 36 octets of overhead (20 header, 16 tag), spread over every message in it.

The first octets that exist are exactly five: `0x20` `DATA` on a datagram, `0x30` `DATA` on a stream, `0x31` `CHECKPOINT`, `0x32` `CONTROL`, `0x24` `UP`. `CHECKPOINT` and `CONTROL` are always streams and `UP` is always a datagram; a kind on another class is malformed, and so is a kind that is not assigned, a version other than 1 and a marker other than `0x00`.

**What a relay reads.** The first ten octets, and nothing else: marker, `ver|class|kind`, id. A relay forwards a frame on the class it arrived on, routes it by the id, and never opens, re-packs or re-seals it. A relay refuses (drops, counted) a frame that is shorter than ten octets, whose marker is not `0x00`, whose version is not 1, whose kind is not assigned or is on a class it never uses.

**What a receiver of a sealed frame checks, in this order:**

| Check | Refusal |
|---|---|
| at least 10 octets, marker, version, kind and class as above | the routing header is malformed |
| at least 20 octets | `Truncated` |
| kind is `DATA`, `CHECKPOINT` or `CONTROL` (an `UP` is not sealed) | `NotSealed` |
| `count` is 1 to 255 for `DATA` and 0 otherwise | `Count` |
| `seq0` is below 2^63, and so is the sequence of the last message (`seq0` + `count` − 1, or `seq0` for a kind that takes one) | `SequenceExhausted` |
| at least 46 octets | `TooShort` |
| at most the frame limit that applies (§11.6) | `TooLarge` |
| the tag verifies | `Authentication` |
| the messages parse and nothing follows them but padding (§11.4) | the message's refusal |

Every refusal drops the frame; a stream peer that sends more than it was granted is closed with the link's `Protocol` error. A receiver that gets `Authentication` for a key epoch whose low octet it does not hold asks for the session again ([§3.6](#36-ended-renewed-re-keyed)); it never guesses a key.

### 11.2 Key and nonce

- **Channel key** `K` is the 32 random octets of the session (§3.2). It is never used as an AEAD key.
- **Frame key** = HKDF-SHA256 (RFC 5869) with `K` as the input key material, no salt, output length 32, and `info` = the ASCII octets `ndn-channel/frame/1` (19 octets) ‖ the channel id (8 octets, big-endian) ‖ the **full** key epoch as a `u32` (4 octets, big-endian). A key is per channel and per key epoch, so a re-key changes it even with the same channel id.
- **Key id** = the first 8 octets of HKDF-SHA256 with `K` as the input key material, no salt and `info` = the ASCII octets `ndn-channel/id/1` (16 octets). The session carries it so a receiver can match a key to a session.
- **AEAD** (`S_AEAD`, chosen by the sender, fixed for the session): 1 AES-256-GCM, 2 ChaCha20-Poly1305. Both take the 32-octet frame key and a 12-octet nonce and give a 16-octet tag. A sender SHOULD choose AES-256-GCM when its CPU has AES and carry-less multiply instructions and ChaCha20-Poly1305 when it has not (a device with neither, and a WebAssembly build, which has none); a receiver MUST open either, as its session says.
- **Nonce** (12 octets) = the key epoch's **low octet**, three zero octets, `seq0` big-endian.
- **Additional data** = header octets 0 to 19: **all 20 octets** of the header.
- **Plaintext** = the body's messages (§11.4) or, for `CHECKPOINT` and `CONTROL`, the record, then any padding (§11.3). **Ciphertext** is as long as the plaintext, then the 16-octet tag.

**A (key, nonce) pair is never reused, with no durable counter.** A key is fresh for every session and every re-key. Under one key, `seq0` rises for the life of the channel and every frame takes at least one sequence, so two frames never share a `seq0`; `seq0` is below 2^63. The nonce carries only the epoch's low octet, but the key is derived from the whole epoch: epochs 256 apart have the same nonce layout and different keys, so no pair recurs. A receiver MUST NOT hold two epochs of one channel whose low octets are equal: when a session at a new epoch arrives it replaces the older keys of the channel it would collide with. **A frame is sealed once.** A sender that re-packs the messages of a frame that was never sent (because the path's size fell) takes **new sequences** for the new frame; it never seals a second plaintext under a sequence it used.

A sender that reaches sequence 2^63 refuses to emit (`SequenceExhausted`: re-key the channel, which is a new session, before sending more).

### 11.3 Short frames on L2

A NIC pads an Ethernet payload under 46 octets with zero octets, and the receiver cannot tell the padding from the frame; a sealed frame with padding appended has its tag read at the wrong place and fails the AEAD. **So no frame is ever shorter than 46 octets on any carrier**, and a short frame is padded by its sender, in a way that the receiver can tell from content.

1. **Sealed frames (`DATA`, `CHECKPOINT`, `CONTROL`).** When 20 (header) + the plaintext + 16 (tag) is fewer than 46 octets, the sender appends padding **inside the AEAD plaintext**: the octet `0x80` followed by zero octets, the shortest that makes the frame 46 octets (at least one octet). The padding is therefore authenticated, and the tag is still the last 16 octets. `0x80` is the PAD flag (§11.4): a receiver stops parsing at it and requires every octet after it to the end of the plaintext to be zero; any other octet there makes the frame malformed. `count` counts real messages only. A sender MAY pad a longer frame the same way (to hide a length); a receiver accepts any padding of this form.
   - A `CHECKPOINT` or `CONTROL` record is self-delimiting (every field has a fixed size or a length), so the receiver reads the record and then requires the rest of the plaintext to be nothing, or a PAD flag and zeros.
2. **The `UP` record (§11.5), which is not sealed.** It is 11 octets of meaning followed by zero octets to 46. A sender sends all 46. A receiver accepts a frame of an `UP` kind of **11 or more** octets whose octets after the 11th are **all zero**, and refuses any other (`NonZeroPadding`): the same rule reads the record whether the carrier padded it or not.
3. A receiver refuses a sealed frame of fewer than 46 octets (`TooShort`).

### 11.4 Messages

The plaintext of a `DATA` body is `count` messages, then optional padding.

```
message = flags (1) | [original sequence (varint)]  if STANDING or REPLAYED
          | name id (varint) | [name length (varint) | name octets]  if NAMED
          | [stand seconds (varint)]  if STAND | length (varint) | payload
flags:  bit 0 NAMED    the full name rides here (the id is bound by this message)
        bit 1 STAND    the sender lets this emission stand
        bit 2 STANDING a replay of a standing value after a session start
        bit 3 REPLAYED a `Window` replay
        bits 4-6       reserved: zero
        bit 7 PAD      the octet 0x80 and nothing else in it: zero octets to the end of the plaintext
```

- **Varint** is the QUIC variable-length integer (RFC 9000 §16): the two high bits of the first octet give the length 1, 2, 4 or 8 octets, the rest is the value, big-endian, at most 2^62 − 1. A writer uses the shortest form; a reader accepts a longer one and refuses one that runs past the plaintext.
- The message's **sequence** is `seq0` + its index in the frame.
- **STANDING and REPLAYED** carry the *original sequence* the message first went out under, as the varint after the flags. They exclude each other (both set is malformed). An original sequence is a varint, so below 2^62, and **below the message's own sequence** (a replay is of something sent before: a writer never builds, and a reader refuses, an original that is not).
- **Name id** is 1 to 4,096. **Name octets** are the Name's components as the value of the Name TLV, at most 255 octets (the empty name is allowed). **Stand seconds** are a varint, at most 3,600 (the longest a sender stands an emission, §13.6). **Length** is the payload's length: at most the session's message limit (§11.6).
- A reader refuses (the frame is dropped) a message that runs past the plaintext, a reserved flag bit, STANDING with REPLAYED, an original sequence not below the message's own, PAD with any other bit, a name id outside 1 to 4,096, a name over 255 octets, stand seconds over 3,600, a payload over the message limit, fewer messages than `count` or a PAD before the `count`th, and octets after the last message that are not padding. Overhead per message is 3 octets while the id is below 64 and the payload below 64 octets, and 4 to 5 beyond.

### 11.5 Kinds

- **`DATA` (0):** messages. On the datagram class for `Latest` messages that fit, on the stream otherwise.
- **`CHECKPOINT` (1):** a signed checkpoint of the frames sent (§15). Always on the stream. Its record is §15.2. The sender records every frame it sends except a `CHECKPOINT` frame (`ring.rs`: the frame's own `Bytes`, a reference and no copy, kept for at most 4,096 frames **and 4 MiB** per channel, the oldest forgotten and counted) and the hash a checkpoint lists, the first 16 octets of SHA-256 for a frame of at most 2,048 octets and of BLAKE3 above, is **computed when the ring is drained** for a checkpoint, not when the frame is sent.
- **`CONTROL` (2):** always on the stream. The plaintext is `op (1) | …`: 1 `BIND` (id, name), 2 `UNBIND` (id), 3 `HELLO` (the first frame after a session starts: the sender's current sequence), 4 `END`, 5 `STANDING_BEGIN`, 6 `STANDING_END`. It takes one sequence.
- **`UP` (4):** the unsealed 11-octet record `0x00 | 0x24 | id (8) | op (1)`, `op` 1 `Keep` or 2 `Unsub`, then zero octets to 46 (§11.3). It is accepted only from a face that is a sink of the route and changes nothing but that face's own entry (§14.5).

### 11.6 Limits

Each is enforced where the codec is: a writer refuses to build what a receiver refuses, and a receiver refuses what a writer would not build.

| What | Limit | Over it |
|---|---|---|
| Frame, any kind | at least 46 octets | `TooShort` |
| Datagram frame | `min(`the path's maximum datagram size`,` `S_FRAME_MAX)`; sized at send time by the sender | a frame the path's size fell under is re-packed once under new sequences, then its messages go to the stream |
| Stream frame | 1 MiB by default (what the faces grant: `ndn_transport::side_header::STREAM_FRAME_GRANT`); `S_FRAME_MAX` raises it to 16 MiB + 1 KiB | the receiver refuses it and closes the link `Protocol` if a peer sends more than it granted |
| Message payload | the default stream frame less 1 KiB (1 MiB − 1 KiB), at most 16 MiB; must fit a stream frame | `TooLarge` |
| Messages per frame | 255 | the next frame |
| Name | 255 octets | `TooLarge` |
| Names per channel | 4,096 (ids 1 to 4,096) | `TooLarge` |
| Sequence | below 2^63 | `SequenceExhausted`: re-key before |

A frame limit counts the whole frame (header, body and tag). The message limit is the frame limit less 1 KiB (`MESSAGE_FRAME_SLACK`): the room one maximal message takes with its header (at most 280 octets) and the frame's own 36, so that a message at its limit fits a frame at its limit. The default is **one constant derived from the other**: the frame default is the stream frame the faces grant, and the message default is that less the slack (`message_limit_for`), so a message at the channel's default limit is never refused by the face (before, the message default was 1 MiB against a grant of 1 MiB: a 1 MiB message was refused at `emit` for a size the channel itself allowed). With `S_FRAME_MAX` the stream limit is the message limit plus 1 KiB.

### 11.7 Frame test vectors

Hex. Every frame below is asserted by the implementation (`chan/frame.rs`, `chan/aead.rs`, `ndn-transport` `side_header.rs`); the key schedule is cross-checked against `openssl kdf HKDF`, and `ring` and RustCrypto are held to the same octets by a test.

Inputs: `K` = the octets `00 01 02 … 1f`; channel id `0102030405060708`; key epoch 258 (`0x0102`, so the header carries `02` and the nonce starts `02`); `seq0` = `1122334455667788`.

```
key id          62939e166fa5dba1
frame key       91de2d89433d466f77cb1018f68c9fdbba620980522e4ee557c168bbf1a8d196
```

A header (class stream, `DATA`, channel id as above, key epoch octet `ab`, `seq0` as above, `count` 7):

```
00300102030405060708ab112233445566778807
```

**1. `DATA` on a datagram, AES-256-GCM,** two messages: id 1 `hello`, and id 2 NAMED with the name octets `080161` (`/a`) and `world!`. Plaintext, 21 octets:

```
00010568656c6c6f01020308016106776f726c6421
```

Nonce `02000000 1122334455667788`. Frame, 57 octets:

```
00200102030405060708021122334455667788027a717a4fb0a19e51de28cca72d34bb909c205895e5d097a1937e7ce5f579f4fd1c32a18e7f
```

**2. The same two messages, ChaCha20-Poly1305:**

```
002001020304050607080211223344556677880219081b0319ad28f01191a9adb047d8cf9edab2e3b08a19ea53d2b9e33b47704bf5da4b2cf6
```

**3. `DATA` on a stream, ChaCha20-Poly1305,** one message, id 1, empty payload: 3 octets of message, so 36 + 3 is under 46 and the plaintext carries 7 octets of padding (`80` and six zeros), 10 octets in all (`00010080000000000000`). Frame, 46 octets:

```
003001020304050607080211223344556677880119081eeb7cc1449f10937cd4a971a420bf82233f87e8846faf36
```

**4. `CHECKPOINT` on a stream, AES-256-GCM,** a 30-octet plaintext `01 02 … 1e` (a stand-in for the framing: the record of a checkpoint is §15.2, and §15.12 has a frame with a real record), `count` 0:

```
00310102030405060708021122334455667788007b727c23d0cbf536d620c4a3215bb2f7e24027e5d13ac14f1f042a165ae413a2371eb6c94c4f120297429b26ee95
```

**5. `CONTROL` on a stream, ChaCha20-Poly1305,** `HELLO` (op 3) carrying the sender's current sequence `1122334455667788` as a varint (`d122334455667788`): 9 octets, so one octet of padding (`80`) makes the frame 46 octets. Plaintext `03d122334455667788` `80`:

```
00320102030405060708021122334455667788001ad83c58389422e898139cdf1fd88c4f66931d9a5f646184dfc6
```

**6. `UP`,** route id `0102030405060708`, `Keep` (`01`) and `Unsub` (`02`), 46 octets each (11 octets of meaning and 35 zero octets):

```
00240102030405060708010000000000000000000000000000000000000000000000000000000000000000000000
00240102030405060708020000000000000000000000000000000000000000000000000000000000000000000000
```

### 11.8 Threat notes for the frame

- **What the tag covers.** The AEAD tag covers the whole header (marker, version, class, kind, channel id, key epoch, `seq0`, `count`) as additional data, and every message (ids, names, flags, lengths, payloads) and the padding as ciphertext. So a relay cannot alter, reorder within a frame, truncate, extend, change the count of, or re-label a frame. It does **not** prove **which key holder** sealed it: every receiver holds the key, so a receiver can forge a frame another receiver accepts. Attributing frames to the sender's device is what signed checkpoints are for; this section makes no such claim.
- **A relay forges or alters.** It has no key. Any change to any octet fails the AEAD at the receiver; a frame moved to another channel fails the key (the channel id is in the key derivation) and the additional data (the id is in the header); a frame copied from another session fails the key. A frame with zero octets appended or removed fails the tag. The padding of a short frame is inside the AEAD for this reason.
- **Cost of a forged frame** to a receiver: a ten-octet routing-header parse, a table lookup by channel id and one AEAD attempt (0.12 µs to seal 64 octets with AES-256-GCM through `ring`, measured; opening is of the same order), bounded by the channel quota. A frame that is oversized, shorter than 46 octets, malformed, or of an unknown channel costs no cryptography. A forged `UP` costs a parse and is dropped unless it comes from a sink face of the route, and then it can only change that face's own entry.
- **A reused nonce** would reveal the XOR of two plaintexts (and, under AES-GCM, the authentication key). §11.2 is why it does not happen: a fresh key per session and per re-key, a `seq0` that rises, no sequence sealed twice. The one hazard is a sender that re-seals different messages under a sequence it used; the codec's writer takes the sequence from the caller, so the caller owns the rule (§11.2).
- **Key material in memory.** The frame key and `K` are zeroed when dropped. `ring` and RustCrypto do not zero their expanded key schedules; a prepared cipher lives no longer than its session.
- **Length.** A frame's length is visible to a relay. A sender that must hide a message's length pads (§11.3 allows a longer pad).
- **A malformed frame never panics the receiver.** Every refusal of §11.1 and §11.4 returns an error; the property tests feed arbitrary octets to the opener, the message reader and the routing-header parser.

## 12. The receiver

What a device does with the frames of the sessions it holds as a receiver (§3.4), from the octets the host read to the `Items` of a `get` call (§12.7, §17). Implementation: `ndn-heap`, `chan` (`rx.rs` the frame path, `replay.rs`, `rx_names.rs`, `latest.rs` and `fifo.rs` the queues, `items.rs`).

The host hands the node one whole frame at a time (a datagram, or one frame of the stream) with an opaque id of the face it came over (`NodeHandle::deliver_frame(frame, ingress)`; with a forwarder (§14.10) it is the forwarder's own id of the face, which decides what the early-frame hold shares between (§12.8) and is the face the evidence of a checkpoint names and the node bars (§15.5)). Frames of one channel are taken one at a time and in the order they were handed over; frames of different channels do not wait for each other. No timer task runs for the receiver: what must expire is swept by the next frame of the channel, by a poll of an `Items`, and by the node's maintenance pass.

### 12.1 What is checked, in this order

Each row costs at most the work it names, and **a frame that fails a row costs nothing below it**. Rows 1 to 10 are before any cryptography; row 11 is the first.

| # | Check | Refusal (counted) |
|---|---|---|
| 1 | at least 46 octets (§11.3) | `short` |
| 2 | at most 16 MiB + 1 KiB, the largest frame any session may grant (§11.6) | `oversize` |
| 3 | the header parses (§11.1): marker `0x00` (`marker`), version 1 (`version`), a kind that is assigned, sealed and on its class (`kind`: an unassigned kind, `CHECKPOINT` or `CONTROL` on a datagram, an `UP`), a `count` the kind allows (`count`), a `seq0` and last sequence below 2^63 (`sequence`) | the counter named |
| 4 | a session of this channel id is held; if none is, a **stream** frame is **held** (below) and a datagram is dropped, and nothing under row 4 is done | `unknown_channel` (every frame of an id with no session), `held_unknown_full`, `held_unknown_evicted`, `held_unknown_expired` |
| 5 | the frame is within the limit of its class: a datagram at most the session's `S_FRAME_MAX` (at least 46, at most 16 MiB + 1 KiB), a stream frame at most the larger of 1 MiB and `S_FRAME_MAX` (§11.6) | `oversize` |
| 6 | a `Reliable` or `Window` channel's data comes on the stream | `wrong_class` |
| 7 | **back pressure:** a stream data frame of a `Reliable` or `Window` channel waits while an `Items` that blocks (§12.6) has a full queue | none: the host's read of the stream waits |
| 8 | the **generation check** (§12.3): the sender still stands | `not_member`, and the session ends |
| 9 | the session holds the key epoch the header names (§12.3) | `unknown_epoch` (and `epoch_limited`, `epoch_asks`) |
| 10 | the replay window has not seen `seq0` and has not passed it (§12.2) | `replayed`, `too_old` |
| 11 | one AEAD attempt under the key of that epoch | `unauthentic`, counted with every attempt in `aead_attempts` |
| 12 | the tag verified: `seq0` is at most 2^24 above the highest seen and `S_SEQ` (§12.2), then marked seen | `too_far` (refused, marks nothing, the sender is asked again) |
| 13 | the messages parse as a whole, or the `CONTROL` record does (§11.4, §11.5) | `malformed`; nothing of the frame is delivered |

A refused frame changes nothing but a counter, except row 8, which ends the session. Every counter is in the node's channel statistics (`Stats.rx`), and a test reads them: *a flood of junk costs a length test, a header parse or a lookup, never an AEAD attempt.*

**Row 4: a stream frame of a channel with no session is held.** The sender queues `HELLO`, its binds, the standing values and a `Window`'s replay when it builds the session Data (§13.7), and the Data and the stream take different paths: those frames can reach this device before it has judged the Data and installed the session, and a stream frame cannot be asked for again. A **stream** frame that passed rows 1 to 3 and names a channel id no session holds is therefore **held**, not decrypted, not counted against any session, and `deliver_frame` says `Held`: a **copy** of its octets, for at most **2 s**, on the receiver's monotonic clock, swept by the next frame, by a session's install, by an `Items` poll and by the node's maintenance pass (no timer). A frame is not authenticated, so the hold is **shared between faces** by the `ingress` id the host gave `deliver_frame`: one face holds at most **16 frames and 2 MiB**, the node at most **64 frames and 4 MiB** in all (two and four times the frame a face grants the stream, `STREAM_FRAME_GRANT`, 1 MiB: one number, so a frame of the grant can be held). A frame that does not fit its own face's share, or is larger than the share (2 MiB: a session that grants frames beyond the 1 MiB default is the only sender of one), is dropped (`held_unknown_full`, and `Dropped(UnknownChannel)`), so the **first** frames of a face, the `HELLO` and the binds, are the ones kept. When the node's bound is reached by a frame of a face that holds less than another, the **oldest frame of the face that holds the most** (its share is the larger of its fraction of the 64 frames and of the 4 MiB; a tie goes to the face whose frame has waited longest) is pushed out and counted (`held_unknown_evicted`) and the arriving frame is held; if the arriving frame's own face holds the most (or ties for it), the arriving frame is dropped (`held_unknown_full`) and nothing is pushed out. A face that floods the hold with frames of channel ids it makes up therefore cannot keep another face's early frames out. One that outlived 2 s is dropped (`held_unknown_expired`). Every frame of an id with no session counts `unknown_channel`. When a session of that id is **installed** (a new session; a renewal is of a channel already held), the held frames of the id are given to the receiver again, **in the order they arrived**, through the whole of §12.1 as any frame, and stream frames of the id that arrive meanwhile queue behind them: the channel takes frames directly only when none is left held. Frames of a session this device holds are never held.

**A datagram is not held:** one of an id no session holds, or of an id whose held frames are being taken in (it would overtake them), is dropped at once (`Dropped(UnknownChannel)`), and that is right because **nothing relies on it**. Only the data of a `Latest` channel goes on a datagram (a `Reliable` or `Window` frame on one is `wrong_class`; `CONTROL` and `CHECKPOINT` are refused on one, row 3). A `Latest` receiver counts no gap, so it neither notices a missing datagram nor asks for it, and the sender does nothing for a receiver that missed one: a newer message of the same name replaces an older one, so the next emission of the name makes up for it; what stands under a name is replayed to a new receiver on the stream (§13.7 step 4), which is held; the binds a datagram needs are in the session's table or follow on the stream (§13.7 steps 1 to 3). A datagram that is early is lost, as a datagram may be, and the hold's room is kept for the frames that cannot be asked for again.

### 12.2 The replay window

Each channel has a window of the last **4,096 frame sequences** and a bitmap beside the highest `seq0` marked. Frames are keyed by `seq0`: every frame takes at least one sequence and `seq0` rises for the life of a channel (§11.2), so two frames never share one, and a repeated `seq0` is a repeated frame.

- **Check before the AEAD.** A `seq0` the bitmap has set is `replayed`; one at least 4,096 below the highest is `too_old` (the window cannot say whether it was seen). Both are dropped before any cryptography: a flood of copies of a genuine frame costs a comparison each.
- **Mark after the AEAD.** `seq0` is marked only once a frame of that sequence **authenticated**. A forged copy of a genuine frame (the same header, an octet of the body changed) fails the AEAD, marks nothing and so cannot burn the genuine `seq0`. A genuine frame that arrives after a forged copy is delivered.
- **A bound on the jump.** After the AEAD and before the mark, a frame whose `seq0` is more than **2^24** (16,777,216) above the higher of the window's highest `seq0` and the session's `S_SEQ` as the sender last answered is refused (`too_far`, `Dropped::TooFar`), marks nothing, and makes the receiver ask the sender again (at most once a second per sender, the limit of §12.3's key epoch asks); the answer moves `S_SEQ`, so a receiver that was cut off for more than 2^24 sequences takes the next frame instead of being stuck until its session ends. Before any frame is marked the reference is `S_SEQ`: the first frame of a session is above it by what the sender sent while the ask and the install went by. Restart and renewal need no exception: a restart is a new channel id and a new window; a re-key keeps the channel's sequences; a `Window` replay takes new sequences at the sender's counter, and so does `HELLO`. **Why:** a holder of the key can seal any `seq0` below 2^63, and a window that marked one would make every genuine frame after it `too_old`; the bound limits the jump to 2^24 sequences. In `Latest` the per-name comparison (§12.6) inherits the bound: a message's sequence is its frame's `seq0` plus its index, and a `STANDING` or `REPLAYED` message's original sequence is below its own (§11.4), so no message carries a sequence above its frame's.
- **A window moved past the sender.** A key holder can still seal one frame within the bound, and the window then stands ahead of the sender: every genuine frame is `too_old` until the sender passes the frame's sequence (hours, at a thousand frames a second). On a channel **with** checkpoints the silence rule ends the session at 3 s: the frame is above every range the sender signs, so no checkpoint ever judges it (§13.12 item 3, §15.7). On a channel **without** (the sender's key is not Ed25519, or the path has no stream, §15.3) nothing judges the frame and no clock runs, so the window is repaired from what the sender signed: a frame refused `too_old` whose `seq0` is at or above the `S_SEQ` the sender last answered makes the receiver ask the sender again (the one-a-second limit of the other asks, and not again for 30 s once an answer showed the refusals were of genuinely old frames, so a flood of old copies costs one ask). The answer's `S_SEQ` is signed, and every frame the sender sent before it made the answer is below it: a window whose highest was at or above it was moved by a frame the sender did not send. It is then **put back** at that `S_SEQ`: it forgets what it marked and refuses every `seq0` below it from then on (counted `window_rebased`), and the sender's frames from there are taken again; the ones refused meanwhile are lost (`Latest` loses them; a `Reliable` or `Window` receiver sees a gap, §12.6). **Residual:** the repair is not a prevention. A holder can seal a far frame again after each put-back, once a second at the ask's rate, and keep such a channel's frames refused most of the time (§13.12 item 22).
- **Within a frame** the messages are numbered `seq0` + index (§11.4); the window is not asked about them.
- **Across sessions** a replayed frame fails the AEAD: a key is fresh for every session and every re-key (§11.2).
- No clock is read.

### 12.3 The generation check and the key epoch

- **Generation.** A session holds the pair `(trust generation, the space's fold version)` it was judged under, and every frame compares it with the node's by two atomic loads (`is_current`). When either moved, the receiver judges the sender again **before** the frame is looked at further, offline and synchronously: the sender must still be a writer by the entries held and this device a member (§3.6). If it fails, the session ends with `NotMember` and is dropped, the `Items` are told (§12.7), and **the frame is refused**. So the first frame after the node holds the record that removes the sender is refused; frames the sender sent before the record arrived were delivered. The node's maintenance pass makes the same judgement when it runs; whichever notices first ends the session, and later frames find no session (`unknown_channel`).
- **Key epoch.** The header carries the low octet of the key epoch. The session holds the key of the epoch last given and, for 5 s after the answer that gave it, the key before it (§3.6). A frame under an octet the session does not hold is **not tried**: it costs a lookup, and as it is not authenticated it changes nothing of the session. The sender is asked again for the session (§3.6), **at most once a second per sender**; frames that arrive meanwhile are dropped (`unknown_epoch`, of which `epoch_limited` did not ask). Nothing is guessed.
- **Frame limits** and the AEAD are those the session's last answer set.

### 12.4 The name table at the receiver

Each channel has a table from name id to name, filled by the session's table (§3.2), by `BIND` records on the stream, and by `NAMED` messages (the id is bound by the message), emptied by `UNBIND`.

- A `BIND` or a `NAMED` message that binds an id to the octets it already has changes nothing and decodes nothing. Another name replaces the old one and is **another binding** of the id: what is queued under the old binding is not mistaken for the new name's.
- An id outside 1 to 4,096, or octets that are not a Name's components, are refused (`bad_bind`).
- **A datagram can overtake the stream.** A message whose bare id the table does not know is **held for 50 ms**. If the bind arrives inside that time (a `BIND` or a `NAMED` message of the id), the message is delivered after it, in the order it was held. If the bind arrives at 50 ms or later, or never, the message is **dropped and counted** (`unknown_name`). At most **64 messages are held per channel**: one that finds 64 held is dropped at once (`hold_full`, and `unknown_name`). A bind that arrives late drops what it finds held instead of delivering it, so the outcome does not depend on when the sweep ran. The hold is swept by the next frame of the channel, by an `Items` poll and by the node's maintenance pass, never by a timer.

### 12.5 `HELLO`, `END` and standing values

- **`HELLO`** records the sequence the sender says its next message takes, and tells every `Items` that takes the channel that **the path works** (`Items::hello_seen`); the `NoPath` rule reads it (§14.10). In `Reliable` and `Window` it is also where the receiver's stream begins (§12.6).
- **`END`** ends the session (`Closed`): the `Items` are told once what they hold has been read, and later frames find no session (a stream frame is held for 2 s like any frame of an unknown channel, §12.1, and then dropped; a datagram is dropped). A sender sends one when it closes a channel (§13.11). On a channel that announces checkpoints (§15) the session ends only once a verified checkpoint lists the `END` (§15.6).
- **Standing values.** The messages between `STANDING_BEGIN` and `STANDING_END` carry the `STANDING` flag and the original sequence (§11.4). Each is delivered as an emission whose `seq` is the **original** sequence and whose `stands` is its stand seconds (what is left of the stated lifetime). A `STANDING` message outside the bracket is dropped (`standing_stray`). In `Latest` the original sequence is also what a message is compared by (§12.6): a standing value older than a live message of its name is not delivered.

### 12.6 Modes at the receiver

| | `Latest` | `Reliable` | `Window` |
|---|---|---|---|
| Frames | datagrams, and the stream for what does not fit one | the stream only | the stream only |
| Queue | **coalescing:** the newest message per (channel, name binding), a FIFO of the names that have one, at most **4,096 pairs** and **1 MiB** charged (below) per `Items` | a FIFO of at most **1 MiB** charged (`queue_bytes`) per `Items` | as `Reliable` |
| A newer message of a name | replaces the queued older one in its place | queued after it | queued after it |
| An older or repeated sequence of a name | dropped, even after the newer was read | n/a | n/a |
| A gap in `seq0` | none noticed | `Lagged { missed }` in its place | `Lagged { missed }` in its place, and the sender is asked again from the first missing sequence |
| Queue full | the oldest pair is evicted and counted: `Lagged` | `Block` (default): the stream is not taken until there is room; `Drop`: the oldest messages are discarded and a `Lagged` stands in their place | as `Reliable` |

- **The gap rule.** In `Reliable` and `Window` each stream frame must start where the last one ended: `seq0` equals the previous `seq0` plus the sequences it took (its `count`, or one for a `CONTROL` or `CHECKPOINT` frame). A frame that starts later says that many sequences are missing, and every `Items` that takes the channel is told **in the place** the messages are missing, before the frame's own messages. `missed` counts sequences (a control record takes one like a message does). Where the stream begins is the `seq0` of a first frame that is a `HELLO`; otherwise the sequence the session's answer named (`S_SEQ`), so that frames lost between the answer and the first frame are not silent either. A frame that starts earlier than expected does not move the expectation back.
- **`Window` asks again.** On a gap the receiver asks the sender for the session again with `ASK_SINCE` = the first missing sequence (a full signed ask, §3.1), at most once a second and never while one is in flight; the sender replays what its window holds from there as `REPLAYED` messages on the stream, under new frame sequences. If the window no longer holds the range, the new session's `S_SEQ` says so and the `Lagged` stands.
- **`REPLAYED` messages** carry the original sequence. One whose original was **already delivered** is dropped (`duplicates`); one that was not is delivered as an emission whose `seq` is the original. The receiver keeps the delivered sequences as at most 64 ranges; when a new range would pass the bound, the two oldest are joined, which counts the gap between them as delivered: a replay of a message that old is dropped, never repeated.
- **Coalescing and the bound.** A message is queued under the key (channel, name id, binding). The newest sequence of a key is kept after its message is read, so an older message that arrives later is dropped; those records are forgotten when there are 8,192 of them, so what is forgotten is a name quiet for thousands of other names' messages. A new name when 4,096 are queued, or when its message would take the queue past 1 MiB charged, evicts the oldest queued names until it fits: that is this consumer being slow, and it is told (`Lagged`), unlike a replacement, which is the mode. A replacement that grows evicts other names and never its own; a message larger than the bound is taken when the queue is otherwise empty.
- **What a queued message is charged.** In both queues a message is charged **what it pins** plus 64 octets, so a flood of empty messages, and a flood of tiny messages in frames padded to a megabyte (a receiver accepts any amount of zero padding after the messages), are bounded in memory and not only in count. A payload is a slice of the opened frame only when the frame is at most 9,000 octets (the most a datagram frame carries, so the datagram lane costs no allocation per message) or the payload is at least half of the frame; the payload of a larger frame is **copied out** and charged its own length. The octets of a name bound to an id are always copied. A message that shares a frame is charged the larger of its payload and the frame's octets over the frame's message count, so the messages of a frame together are charged what the frame is. With `Block` the bound is checked before a stream frame is taken, so the queue can pass it by the one frame in hand and never by more; with `Drop` messages are discarded from the front until the new one fits (a message larger than the bound is taken when the queue is empty). **What the charge does not bound:** a key holder can leave one message of each of 4,096 frames of 9,000 octets queued in `Latest` (the others of each frame replaced), which pins 4,096 × 9,000 octets, 36 MiB, per `Items` while the charge says 1 MiB; a frame over 9,000 octets cannot do this, since its payloads are copied out.

### 12.7 `Items`

`Heap::get(Select, GetOptions)` returns an `Items`, a `Stream` of `Result<Got, GetNotice>`: the kept values of the space and the emissions of its channels as one stream (§17). This section is the emission side of it: the sink the receiver pushes into. `trust` is `Trust::Prompt` or `Trust::Verified` (§15.8); `GetOptions::live` is `Live::Emitted` (the default) or `Live::Off`, which installs no sink; a follower is refused `Live::Emitted`.

- **Creating it does no I/O.** It takes every message of every session of the space this device holds, in the modes it joined (`Modes`), whose path matches `Select::Path` (exactly) or `Select::Prefix`. The sink is installed when `get` returns, so a message that arrives before the first poll is queued, not lost. While it exists, this device is *listening* to the space (§9): announces of writers' channels make it ask. Asking a sender for a session is otherwise the caller's (`NodeHandle::ask_channel_in`); `get` sets up no session itself.
- **`Got`** carries the path (relative to the space), the payload (a slice of the opened frame when the frame is at most 9,000 octets or the payload is most of it, a copy of its own otherwise: §12.6), the writer's person and device, and `Kind::Emitted { seq, stands }`. The person is the one of the sender's device as judged when the session was set up (§3.4), not read from the frame (§17.6).
- **Order.** Within a channel as §12.6. Across channels, the order messages were queued in. How the emissions interleave with the kept values: §17.3.
- **Notices.** `Lagged { missed }` as above. `LiveEnded(Ended { writer, reason })` when a session ends (`NotMember` when the sender no longer stands, `Closed` for an `END` (once a checkpoint lists it, §15.6), `Lapsed`, `Left`, `BadCheckpoint` and `Unverifiable` (§15.6, §15.7)), told **after** the messages queued before it; a session replaced by a newer one of the same sender and mode is not told, since the `Items` simply goes on with the new one. `LiveEnded(NoPath { why })` when no `HELLO` came within 2 s of the session's install (§14.10). `Retracted { writer, from, to }` is raised by checkpoints (§15.5).
- **`next_batch(&mut Vec<Got>) -> usize`** moves everything queued that is an item into the buffer (the kept listing first, then the kept changes, then the emissions), under one lock per source, with no wake per item and no allocation when the buffer has room; it stops before a notice (the next `next()` yields it) and never waits.
- **Back pressure** (§12.6) is applied by the receiver before it takes a stream frame, so it reaches the sender through the stream's flow control. An `Items` that is never read stalls the stream of a `Reliable` or `Window` channel with `Block`; dropping it frees the stream.
- **Dropping an `Items`** cancels its sink and closes its kept watcher: nothing more is queued for it. The stream ends when the node stops.

### 12.8 Limits and counters of the receiver

| What | Limit | Over it |
|---|---|---|
| Frame | 46 octets to 16 MiB + 1 KiB; per class as §12.1 row 5 | `short`, `oversize`, dropped before cryptography |
| Replay window | 4,096 frame sequences per channel; a `seq0` at most 2^24 above the highest seen (or `S_SEQ`) | `replayed`, `too_old`, before the AEAD; `too_far` after it, the sender is asked again |
| Asks for an unknown key epoch | once a second per sender | `epoch_limited`, dropped untried |
| Messages held for an unbound id | 64 per channel, 50 ms | `hold_full`, `unknown_name` |
| Frames held for a channel with no session (stream frames only; both bounds are multiples of `STREAM_FRAME_GRANT`, 1 MiB) | 16 frames and 2 MiB per face (`ingress`), 64 frames and 4 MiB in all, 2 s each | a frame over its face's share, or from the face that holds the most of a full hold: dropped, `held_unknown_full`; from a face that holds less: the oldest frame of the largest face is pushed out, `held_unknown_evicted`; `held_unknown_expired` |
| Names per channel | 4,096 | refused (`bad_bind`) |
| `Latest` queue | 4,096 names and 1 MiB charged per `Items` | the oldest names evicted, `Lagged` |
| `Reliable`/`Window` queue | 1 MiB charged per `Items` (what a message pins + 64 octets, §12.6) | back pressure, or the oldest dropped and `Lagged` |
| Delivered original sequences kept for `REPLAYED` | 64 ranges per channel | the two oldest joined |
| `Window` re-asks | once a second per channel, one in flight | the gap stands as `Lagged` until the next |
| Accepted frames kept for checkpoints | 4,096 frames, 2 MiB a channel, and the channel's equal part of the node's 8 MiB, at least 64 KiB (§15.4) | the farthest frame (the lowest of the highest run) is forgotten and counted `unchecked`; a frame far above all held, when the channel is full, is refused (`unchecked`); `budget_starved` when the node's bytes are taken by channels over their part |
| Frames held for a lane (silence, `Verified`) | 4,096 frames and 2 MiB a channel, within the channel's part of the node's 8 MiB (§15.4, §15.7) | the oldest is dropped, `held_dropped`, `Lagged`; `budget_starved` as above |
| Checkpoints verified | a channel: a burst of 64, then 2 a period (at least 4 a second); the node: a burst of 256, then 4,000 a second (§15.4) | dropped unread, `checkpoints_over_rate`; never a forgery |
| A second authentic frame at one sequence | 3 AEAD attempts a sequence, 64 kept a channel (§15.6) | compared only |
| Silence | frames held after `max(4 × period, 100 ms)` with no verified checkpoint; the session ends at 3 s (§15.7) | `held`; `Unverifiable` |
| Cost of a frame | one allocation for a frame of at most 9,000 octets, whatever its message count, none per message; a message of a larger frame costs one (its copy) unless it is most of the frame; `next_batch` none | |

The counters (each a `u64`, in `Stats.rx`): `frames`, `short`, `marker`, `version`, `kind`, `truncated`, `count`, `sequence`, `oversize`, `unknown_channel`, `held_unknown_full`, `held_unknown_evicted`, `held_unknown_expired`, `wrong_class`, `not_member`, `unknown_epoch`, `epoch_limited`, `epoch_asks`, `replayed`, `too_old`, `too_far`, `aead_attempts`, `unauthentic`, `malformed`, `accepted`, `messages`, `unknown_name`, `name_held`, `hold_full`, `bad_bind`, `standing_stray`, `duplicates`, `gaps`, `reasks`, `controls`, `hellos`, `checkpoints`, `no_sink`, `ended`. `epoch_asks` and `epoch_limited` count the asks made, and the asks held back by the one-a-second limit, for a frame under an unknown key epoch and for a frame far ahead (`too_far`).

The counters of checkpoints (stage 5) are `checkpoints` (every `CHECKPOINT` frame taken, above), `checkpoints_verified`, `checkpoints_over_rate`, `unverifiable_checkpoints`, `bad_checkpoints`, `mismatches`, `conflicts`, `unchecked`, `budget_starved`, `held`, `held_dropped`, `resets` and `unverifiable` (§15.10), and `window_rebased` (§12.2).

### 12.9 Threat notes for the receiver

- **A flood of junk.** A frame that is short, oversize, malformed, a repeat, below the replay window, or under a key epoch it does not hold costs a length test, a header parse or one lookup. A stream frame of a channel this device holds no session of costs the same plus a bounded copy into the hold (below); a datagram of one costs no copy. None reaches the AEAD (`aead_attempts` proves it). A flood under a key epoch the session does not hold also makes no more than one ask a second per sender.
- **A forged frame of a held channel** costs one AEAD attempt and is refused (`unauthentic`); it burns no sequence, so it cannot make the receiver drop the genuine frame that follows (§12.2). The attempts are bounded by what the link delivers; the replay window drops copies of a genuine frame before the attempt.
- **A forged copy of a genuine `seq0`** is the same: refused by the tag, marks nothing.
- **A held-back bare id cannot grow memory.** At most 64 messages per channel are held, for 50 ms; the 65th is dropped at once; the number of channels is bounded by the sessions (§6).
- **A flood of frames of unknown channel ids cannot grow memory, and cannot crowd out another face's early frames.** Each costs the header checks, one lookup and, if the hold has room, one copy of the frame (a stream frame; a datagram is dropped before any copy): at most **16 frames and 2 MiB from one face** and **64 frames and 4 MiB in all**, **2 s each**, whatever the number of ids. A frame that does not fit its face's share is dropped at once (`held_unknown_full`), so what a face sent first stays; a frame of a face that holds less than the face holding the most pushes that face's oldest frame out (`held_unknown_evicted`); one nobody claimed in 2 s is dropped when the next frame, an install, an `Items` poll or the node's maintenance pass sweeps (`held_unknown_expired`). The 64 frames are four faces' full shares, so a fifth face still gets room by eviction, and a frame of the stream grant (1 MiB) can be held. The share is per `ingress` id the host gives (§12). A held frame is **not decrypted and decides nothing**: no key is tried, no sequence marked, no session or channel made. It is a copy of the bytes, not a slice of the host's read buffer, so a held frame pins nothing of the host's.
- **A key holder** can seal frames the receiver accepts (§11.8): it can send a `BIND` that renames an id, a `STANDING` bracket, an `END`, a gap, a `HELLO`. Each is bounded as above (the table has 4,096 ids, the hold 64 messages, the delivered ranges 64) and none changes who the sender is. Attributing frames to the sender's device is the work of signed checkpoints (§15): a frame a holder made is exposed by the next checkpoint that covers it, and an `END` ends nothing until one lists it. A holder cannot make the replay window jump more than 2^24 sequences with one frame (§12.2), but within that bound it can still mute a name in `Latest` until a checkpoint reaches the sequence (§13.12 item 3).
- **A removed sender** is refused at the first frame after this device holds the removing record (§12.3). Frames it sealed before the record arrived were delivered; frames sealed with the old key by a holder after the re-key fail the AEAD.
- **A slow consumer** cannot make memory grow without bound: 4,096 names and 1 MiB charged (plus the frame in hand), per `Items`. With `Block` it stalls the stream of a `Reliable` or `Window` channel (the sender is told by flow control); with `Drop`, or in `Latest`, it is told it lagged.
- **Clocks.** No decision about who is a member or what is genuine rests on a clock. The 50 ms hold, the 2 s hold of frames of a channel with no session and the one-second limits are counted on the receiver's monotonic clock and decide only what is kept for a moment and how often a sender is asked.

## 13. The sender

Implementation: `ndn-heap` `chan/emit.rs` (`Heap::emit`, the writer gate), `tx.rs` (the combining writer), `queues.rs` (the pending sets), `table.rs` (the name-id table), `history.rs` (the window and the standing values), `control.rs` (the `CONTROL` bodies), `carrier.rs` (the carrier a host gives the node), `verbs.rs` (the public types of `emit` and `get`).

### 13.1 `Heap::emit`

`emit(path, bytes, EmitOptions)` sends `bytes` to the receivers of the channel of `opts.mode` over this space. `EmitOptions { mode, stand, congestion }`: `mode` is `Latest` (default), `Reliable` or `Window(Window)`; `stand` is a lifetime (§13.6); `congestion` is `Drop` or `Block`. `EmitOptions::latest()` is the default, and `EmitOptions::reliable()` and `EmitOptions::window(w)` say `Block` (the `Drop` of the type's `Default` is the default of `Latest` alone).

Before anything is sent the call passes **the writer gate**: this device's key stands as a **writer** of the space by the entries held now, which is the gate of §4.2, and, in a sealed space, an epoch is in force. The gate is passed again only when the trust generation or the space's fold version moved (two atomic loads), so the steady state of `emit` takes no log lock. The first `emit` of a mode also opens the channel of (space, mode) in the sender's table (§3.5), so asks can be answered and the announce (§9) names the mode. A device with no receiver sends nothing and the call returns at once (§13.2).

| Refusal | When | `NextStep` |
|---|---|---|
| `NotWriter` | this device is no writer of the space | `AskOwner` |
| `NotReady` | the space's record is not held here, or a sealed space has no epoch in force | `RetryLater` |
| `TooLarge { what, size, max }` | a message over 1 MiB; a name over 255 octets; `names in one channel` (4,096); `standing names in one channel` (256); `standing octets in one channel` (64 KiB); `stand lifetime in seconds` (3,600); a message that fits no datagram on a path with no stream; more channels than the sender may keep (64) | `FixRequest` |
| `Congested { retry_after }` | `Drop` found the queue full of what cannot be dropped (a frame being written, a control frame); try again in 100 ms | `RetryLater` |
| `NoStream { what }` | `Reliable`, `Window` or a standing value on a path whose carrier has no stream; a standing value on a channel that has a receiver behind a hop with no stream (§14.9) | `FixRequest` |
| `FixRequest` | `Latest` with `Block`: "Latest never blocks; a newer emission replaces an older one. Use Reliable" | `FixRequest` |
| `SequenceExhausted` | the channel used its last sequence (§13.2) | `RetryLater` |
| `Local` | this device's own failure | `FixLocal` |

No receiver is **not** an error. A refusal changes nothing: no sequence is taken, no name is bound.

### 13.2 The combining writer

No timer decides when a frame leaves. A channel has two **lanes**, the datagram lane and the stream lane, each with a pending set and a `writing` flag.

1. **Sequences are taken at emission, under the channel's lock.** So the order of a queue is the order of the sequences, and a message that is dropped leaves a gap a receiver sees. A frame holds a **run of consecutive sequences** (`seq0 + index`): a `Latest` message that a newer one replaced leaves a gap, and the run ends at it. A `CONTROL` frame takes one sequence like any frame. Sequences are below 2^62 (a `HELLO` and a replayed message carry one as a varint; the frame's own limit is 2^63): at the limit `emit` says `SequenceExhausted`, the channel sends its `END` (§13.11) and is closed in the sender's table (a receiver's next ask makes a new channel, a new id and a new key), and the next emission begins it.
2. **The pending sets.** `Latest`: one slot per name id, in the order of the sequences; a newer message replaces an unsent older one of its name and moves to the back (the replaced sequence is never sent); at 1 MiB of waiting payload the oldest slot that is not in a frame being written is dropped and counted. `Reliable` and `Window`: a FIFO of messages and control frames, 1 MiB of payload; a full queue makes `Block` wait for room and `Drop` drop the oldest message that is not in a frame being written (counted; its sequence is a gap).
3. **The datagram lane.** If its `writing` flag is clear the caller of `emit` sets it and **is the writer**: it packs messages of consecutive sequences into a frame up to the carrier's room (`min(datagram_max(), 9,000)` read for every frame) or 255 messages, seals it **once** (the frame stays sealed: a re-pack takes new sequences), hands it to the carrier, and goes on for up to `COMBINE_MAX = 4` frames; it then looks at the set again under the lock that clears the flag. What is left goes to the carrier's writer task through `on_ready` (§13.8), which writes until nothing waits. A message that arrives while the flag is set waits for the writer, which looks again before it clears the flag. **An emitter that wrote and found nothing more waiting asks the carrier for a call back (`on_ready`) when the write follows another inline write within `BURST_GAP` (50 µs, measured on the emission's own clock reading; no timer, and no frame waits for it)**, and until the carrier makes it the emissions that follow only queue: the first two messages of a burst leave at once, inline, as frames of one, and the rest of a loop that does not stop between emissions leaves together, in as few frames as the carrier's room needs, when the carrier's writer task runs. **An isolated message asks for nothing**: no wake of the carrier's writer task and no allocation (a counted invariant, `tx_tests::an_isolated_message_asks_no_call_back_and_a_burst_does` and the allocation test). Without the call back a loop made one frame, one seal and one carrier call of every message. A close drains what waits before it queues its `END`. So **an idle link sees one message leave at once, inline, as a frame of one**, and **a batch forms while the writer is busy, the carrier refused, or the emitter has not yielded since its last frame**.
4. **The headroom rule is the carrier's.** `try_send_datagram` refuses with `Full` when the link has enough queued ahead (ndn-link.md: `QUEUE_FLOOR` to `QUEUE_CAP`). A `Latest` message then stays pending, coalescing, and `emit` never waits; the writer asks the carrier for a call back, and while one is asked for, later emissions only queue (they do not seal a frame the carrier would refuse).
5. **A message stays in its queue until its frame was handed over.** A frame the carrier refused loses nothing; a message replaced while its frame was sealed is sent and not counted replaced.
6. **An oversize `Latest` message** (it fits no datagram frame) goes on the stream, in a frame of its own run (of as many consecutive messages as fit the smaller of 1 MiB and `stream_frame_max()`); until the stream took it a newer message of its name replaces it, and an oversize message replaces an unsent small one. On a path with no stream it is refused `TooLarge`; so is a message whose frame fits no frame the stream takes.
7. **A frame the path's size fell under** (`try_send_datagram` says `TooLarge { max }`) is re-packed once at `max` with **new sequences** (counted `resized`); if that frame falls again, its messages go to the stream (counted `resized`). A message that was replaced meanwhile is not re-sent.
8. **The stream lane** is written by a task of the node (a stream frame may wait on flow control, which an emitter cannot be cancelled in): one frame at a time, in the order of the sequences, a run of data messages up to 1 MiB (or the carrier's `stream_frame_max()` when smaller) and 255 messages, or one control frame. `Block` waits for **queue room**, not for the stream.
9. **The ring.** Every frame sent, on either lane, is recorded in the ring of sent frames (`ring.rs`) as a reference to the frame, and **nothing is hashed on the writer's path**: the hash is computed when the ring is drained (a checkpoint reads it, §15.3: `SentFrames::take_below` hands it the frames to hash, and the hash definition is `frame_hash`, unchanged). The ring keeps the frames alive, so it is bounded in octets as well as frames (4,096 and 4 MiB per channel: 4,096 frames of up to 1 KiB, fewer of larger ones), **and the octets are resident memory**: a frame is built in a buffer sized for what was pending, and a frame that used less of it than the buffer has to spare (more than a quarter and 64 octets) is copied to an allocation of its own size when it is sealed, at the cost of one more allocation, so the ring never keeps a buffer much larger than the frame in it. A frame pushed out by either bound is forgotten and counted (`forgotten`), and the next checkpoint's range begins past it (§15.3). A `CHECKPOINT` frame is not recorded. Measured: the hash was a sixth of the writer thread at 1 KiB and 8 KiB; taking it off the path raised throughput 1.16 and 1.18 times (SHAPES-CHANNEL.md 18.x).

Cost (measured by `the_64_byte_latest_path_allocates_nothing_per_message_beyond_the_frame`): an idle 64-octet `Latest` message allocates **exactly 2** (its frame's buffer and the shared header `Bytes` freezing adds); 14 messages queued while the carrier is full allocate **0**, and the one frame that carries them **2** in all.

### 13.3 The name-id table

A channel carries every path its sender emits in the space under the mode. Ids are allocated from 1, in order, at most 4,096 live. A new name takes an id and a `BIND` (§13.4) joins the stream's FIFO at once (it takes the sequence before the message's). **A datagram can overtake the stream**, so the first three messages under an id and every message within 200 ms of its bind are `NAMED` (the name inline); later ones are bare. On a path with no stream there is no `BIND` and every message names itself.

At 90 % of the table (3,687 live ids) a **new** name first frees the ids not used for 60 s (an `UNBIND` each), at most once a second; at 4,096 live a new name is refused `TooLarge { what: "names in one channel", size: 4097, max: 4096 }`. A freed id is reused only after every older free id: it was idle for 60 s before it was freed, so no datagram naming it can still be in flight. The session's table (`S_TABLE`) holds the first binds in the order of the ids, at most 64 and 4 KiB; the others follow as `BIND` frames right after `HELLO` (§13.7).

### 13.4 `CONTROL` bodies

A `CONTROL` frame takes one sequence, travels on the stream, and carries `op (1)` and the record, then nothing but padding (§11.3). Varints are §11.4's.

| op | Name | Body |
|---|---|---|
| 1 | `BIND` | name id (varint, 1 to 4,096), name length (varint, at most 255), the name's octets |
| 2 | `UNBIND` | name id (varint) |
| 3 | `HELLO` | the sequence the sender's **next** message takes (varint, below 2^62) |
| 4 | `END` | none: the sender ends the channel (§13.11); the receiver ends the session (`Closed`, §12.5) |
| 5 | `STANDING_BEGIN` | none: standing values follow |
| 6 | `STANDING_END` | none: the standing values are over |

A record that is empty, of an unassigned op, cut short, with a name id outside 1 to 4,096, a name over 255 octets or anything but padding after it is refused. Golden octets: `HELLO` with next sequence `1122334455667788` is `03d122334455667788`; `BIND` id 2 for `/a` is `010203080161`; `UNBIND` 2 is `0202`; `END` is `04`.

### 13.5 Modes as built

- **`Latest`**: datagrams for messages that fit, the stream for those that do not; the newest per name; never blocks; a `Full` carrier only makes messages wait.
- **`Reliable`**: every message on the stream, in the order of the sequences; `Block` (the default of `EmitOptions::reliable()`) waits for queue room, `Drop` drops the oldest queued message and counts it.
- **`Window`**: as `Reliable`, and the sender keeps what it sent (at send time, replays excluded): the last **256 messages, 1 MiB, 10 s**, whichever is least; the most a caller may ask for is 4,096 messages, 16 MiB and 5 minutes (a larger window is clamped, not refused). The channel's window is the one its latest emission gave; the session says it (`S_WINDOW`). A joiner is replayed the window on the stream, before live frames (§13.7). **The cost of the replay:** a replay is written on the carrier's one route, so every receiver of that carrier gets it too (a receiver drops a replayed message whose original sequence it already has, §12.6), and each replayed message takes a new sequence on the stream.
- **No stream (an L2 path)**: `Reliable`, `Window` and a standing value are refused `NoStream`; every `Latest` message names itself. A path has no stream when the carrier's own face has none, or, for one receiver, when the first hop toward it has none (§14.9): that receiver's `Reliable` or `Window` ask is refused `NoStream`, and while a `Latest` receiver behind such a hop holds the channel every message of the channel names itself, a standing value is refused `NoStream` and a message that fits no datagram `TooLarge`.

### 13.6 `stand`

With `opts.stand` the sender holds the **last emission of the path** for the stated lifetime (at most one hour), and the message carries the `STAND` flag with the lifetime in seconds. At most 256 names and 64 KiB of payload stand per channel; over either, `TooLarge` (and the path's earlier standing value stays). An emission of the path **without** `stand` removes what stood under it: the last emission is the one that stands. A standing value is replayed to a new session (§13.7). A sender with no receiver still holds it, and a `Window` message sent with no receiver still enters the window: both are for a receiver that joins later. Such an emission takes a sequence and sends no frame.

### 13.7 What a new receiver is given

When the sender admits an ask (§3.3 step 11) the session carries the sender's **table** (§13.3), its **window** (`Window` channels), `S_FRAME_MAX` (9,000: the most a datagram frame carries; the sender sends `min(path size now, 9,000)`) and the next sequence. If the carrier has a stream and the asker's **device was not a receiver before** (**fresh**: it takes a place in the table, which the 256 receivers of a channel bound), or its ask says `ASK_NEW` and the channel's replay limiter below admits it (a **claim**; a renewal is neither), these frames follow on the stream, in this order, taking sequences in this order:

1. `HELLO` (the sequence the next message takes);
2. a `BIND` for each live bind the session's table did not take;
3. the names the replays below need that were not bound are bound (a `BIND` each);
4. `STANDING_BEGIN`; each standing value as a message with the `STANDING` flag, the **original sequence**, its name **inline** (`NAMED`) and `stand seconds` = **what is left** of the lifetime (whole seconds, rounded up; a value with none left is not sent); `STANDING_END`;
5. in `Window` mode, the window from `ASK_SINCE` (the whole window when the ask names none) as messages with the `REPLAYED` flag, the original sequence and the name inline.

A receiver that is not new and asks with `ASK_SINCE` in `Window` mode is given only step 5, and only if the sender has not replayed such an ask **within the last second on this channel** and the stream's queue has room for the replay under 1 MiB (`queue_bytes`, counting what already waits); otherwise the ask is answered with the session and **no replay** (`replay_refused`; a debug log says which limit), the session's `S_SEQ` tells the receiver the window was not replayed, and its gap stands as `Lagged` until its next ask. A receiver that is **fresh** is replayed once whatever the queue holds (§13.10).

**A claim is judged by the same limiter.** `ASK_NEW` from a device the sender lists is only what the asker says, and a signed ask is cheap (4 a second per key): were it believed, any member could make the sender queue a `HELLO`, the binds, the standing values and the window's replay on the stream, which goes to every receiver of the channel, 4 times a second, and each would arm the stream's route gate (§14.10) so that the stream's next frame, checkpoints included, waited up to a second for a `Keep`. The sender therefore asks the limiter before it queues anything: a claim is **admitted** when no replay (of a claim or of an `ASK_SINCE`) was queued on this channel within the last second and the stream's queue has room under `queue_bytes` for the window, the standing values and what already waits. The one admitted is welcomed like a fresh device (steps 1 to 5) and **only then** is the gate armed (`Carrier::receiver_added`). A claim that is not admitted queues nothing, arms nothing and is refused `Busy` (`replay_refused`), with `retry_ms` the time left of the second (a second, when the queue is full) and a text that says why and to ask again with the same ask. It is refused, not answered with a bare session, because a session with no `HELLO` would end `NoPath` two seconds on, a false word about the path; and the receiver has lost nothing by the refusal (the sender still lists it). The receiver's ask fails with `ChanError::Refused { code: Busy }` (next step `RetryLater`) and it asks again after `retry_ms`. A receiver that returns in a quiet second is admitted at once; one that returns in the same second as another claim, or as an `ASK_SINCE` replay, waits up to a second. A fresh device is not metered by this: it takes a place in the table, which the 256 receivers bound, and a channel cannot be made to replay without one.

The frames are queued when the session is built, before the session Data is signed: they may reach the carrier before the receiver has installed the session. The receiver **holds** such frames (§12.1, the hold of frames of a channel with no session) and takes them in, in the order they arrived, when it installs the session, so a `Window` joiner loses neither the `HELLO`, nor the standing values, nor the replay; with the side table (§14) the frames follow the session over the route its Data installed, and a carrier that gates its stream on a route waits for the new receiver's `Keep` before it sends them (§14.10).

### 13.8 The carrier a face must provide

`ndn-heap` cannot depend on the faces, so the host gives the node a `Carrier`: `NodeHandle::attach_carrier` for one of its own (one fixed route: every frame of every channel goes to it), or `NodeHandle::attach_forwarder` over a connection to a forwarder, whose side table routes the frames by channel id (§14.10). A carrier MUST:

- `datagram_max()`: the largest datagram frame the path takes **now** (it follows path MTU discovery; the sender reads it for every frame); 0 if there is no datagram class.
- `has_stream()`: whether it has an ordered, reliable stream.
- `stream_frame_max()`: the largest frame `send_stream` takes whole. The sender packs a stream frame to the smaller of it and the channel's own limit (1 MiB, the grant of the faces), so a face that grants its peer less makes frames of what fits (`ndn-face-quic` grants exactly the channel's default, `STREAM_FRAME_GRANT`); a message whose frame fits no frame the stream takes is refused `TooLarge` at `emit` (`what`: "message that fits no frame of the stream"), before a sequence is taken. A frame over it is a carrier that broke the contract: its refusal ends the stream's writing and what waits is counted lost.
- `try_send_datagram(frame)`: never block. Take the frame, or refuse it: `Full` when the headroom rule says so; `TooLarge { max }` when the path no longer takes a frame this size; `Closed` when the link is gone.
- `send_stream(frame)`: take a whole frame onto the stream, in the order of the calls, and complete when the stream took it (it waits for flow control). The sender calls it again only after the last call completed and never drops a future in progress, so a frame is written whole or not at all.
- `on_ready(drain)`: call `drain` **once, from the carrier's own writer task, when `try_send_datagram` would take a frame again** (the next time that task runs if it already would; not from inside `on_ready`). `drain` sends what waits, never blocks, and may call `try_send_datagram` and `on_ready`. The sender asks for it after a refusal, and after an inline write that follows another within `BURST_GAP` (§13.2 item 3; an isolated message asks for nothing), so **a carrier that never calls it stalls the channel**: the emissions after the first two of a burst wait for it. A call on one that is not the attached carrier any more is not waited for.
- `receiver_added(channel)` (defaulted, does nothing): called when a receiver is judged in as new (a fresh device, or a claim the replay limiter admitted, §13.7) or a `Window` receiver's replay of a start was queued, and the stream frames that follow its session are queued: never for an ask whose frames were refused. A carrier that gates its stream on a route (§14.10) uses it.

A carrier that meets this is all the sender needs: no timer, no task of its own, no knowledge of channels.

### 13.9 Limits of the sender

| What | Limit | Over it |
|---|---|---|
| Frames one emitter writes before it hands over | 4 (`COMBINE_MAX`) | the carrier's writer task, without bound |
| Messages per frame | 255 | the next frame |
| Datagram frame | `min(path size, 9,000)`, read per frame | re-packed once, then the stream (`resized`) |
| Waiting payload per channel | 1 MiB | `Block` waits; `Drop` drops the oldest; `Latest` drops the oldest slot; `Congested` when nothing can be dropped |
| Names per channel | 4,096; the table frees idle ids at 3,687 | `TooLarge` |
| Standing names / octets / lifetime | 256 / 64 KiB / 1 h | `TooLarge` |
| History window | 256 messages, 1 MiB, 10 s by default; at most 4,096, 16 MiB, 5 min | clamped |
| Window replay to a receiver that is not new (`ASK_SINCE`) | once a second per channel, and only while the queue's 1 MiB has room for it | no replay, `replay_refused` |
| Sequence | below 2^62 | `SequenceExhausted`: the channel ends |
| `Congested` retry | 100 ms | |
| Checkpoint period | 20 ms by default; 1 ms to 2 s (§15.9) | held to the nearest bound |
| Frames the checkpoint ring keeps to be listed | 4,096 frames and 4 MiB a channel | the oldest is forgotten, counted `unchecked` (§15.3) |
| Idle checkpoint | one empty checkpoint every 5 s while a receiver holds the channel (§15.3) | |

### 13.10 Threat notes for the sender

- **A local application cannot exhaust the sender's memory.** Every queue is bounded: 1 MiB of waiting payload per channel, 4,096 names, 256 standing names and 64 KiB standing, a window of at most 16 MiB (and 4,096 messages) per `Window` channel, a ring of at most 4,096 frames and 4 MiB. A burst of new names costs one sweep a second at most.
- **A slow receiver cannot block a `Latest` sender.** `emit` never waits in `Latest`; a full carrier only makes messages wait, replaced by newer ones, in at most 4,096 slots; the oldest slot is dropped at 1 MiB. What a slow receiver costs the others is nothing the sender decides (the headroom rule is the carrier's, and a relay that cannot keep up drops visibly, §12.6).
- **`Reliable` blocks only its own sender.** `Block` waits for queue room of **that channel**; another channel, another mode and every `Latest` sender are unaffected. With `Drop` it never waits, and what it dropped is a gap every receiver sees.
- **No name-table exhaustion by a stranger.** Only a writer's device emits (§13.1); the table is the sender's own; a receiver cannot make the sender bind a name. 4,096 ids and one sweep a second bound the cost of a sender that makes up names.
- **A replay amplifies by the number of receivers on the route**, never more than one window or 64 KiB of standing values per **new** receiver, and only for a receiver that was not admitted before (**fresh**: bounded by the 256 receivers of a channel), for a **claim** of `ASK_NEW` the limiter admits, or for a `Window` receiver that names a start: a renewal costs no replay. A claim and a `Window` receiver that names a start share one limit: one replay a second per channel, never past the queue's 1 MiB (§13.7), so a receiver that asks as fast as it can sign cannot grow the sender's queue, keep the stream busy replaying, or re-arm its route gate: the ones refused queue and arm nothing, and a claim is told `Busy`.
- **A re-key** replaces the cipher the next frame is sealed with (the writer reads the channel's key epoch for every frame); a frame is never sealed twice and a sequence is never sealed twice under a key, so a (key, nonce) pair never recurs (§11.2).
- **Clocks.** The 200 ms of a bind, the 60 s of an idle id, the age of a window and the lifetime of a standing value are counted on the sender's monotonic clock; no decision about who is a member or what is genuine rests on them.

### 13.11 The end of a channel

A channel ends when its sender closes it, and the sender then **seals and sends one `CONTROL END` frame on the stream** (§13.4), under the key in force when it ended, to the receivers that hold the channel. Three things close a channel: this device being no writer of the space any more (`chan_rejudge` closes every channel of the space), the node being closed (`Node::close` ends each of its channels, then stops), and the sequence limit (§13.2 item 1: the last sequences are kept for the `END`). The last receiver leaving does **not** end a channel; a channel that has had no receiver for an hour (the default lifetime) is dropped from the table and has nobody to tell, and a receiver whose lease ran out is dropped and the channel re-keyed (§3.6), not ended.

- **The key.** The channel's table entry is taken out first and its key stays in force until the `END` is queued: the frame is sealed under the key epoch of the channel when it ended, never under one this sender had last refreshed to and never under none. The channel's key is dropped (zeroed) only after that.
- **What goes first.** What waits on the stream (the messages of a `Reliable` or `Window` channel, the control frames) is written, in order, and the `END` after it; a receiver therefore delivers what was queued and then says the live part ended (`Closed`, §12.5). What waits for a datagram, and what only the stream's `Latest` lane held, is lost, counted (`lost_closed`).
- **Best effort, never blocking.** The frame is written by the stream's writer task; the call that closes the channel returns at once. `Node::close` first ends every channel of the node and waits for the frames to be written for at most 500 ms, so a stream that takes nothing does not hold the node's close, and then stops every task (`close` returns once each has ended, heap.md §4.5 rule 5); `Node::shutdown` stops at once and sends no `END`.
- **When no `END` goes.** No receiver holds the channel (`Live::receivers` is 0), the carrier has no stream, no carrier is attached, the key is of another channel, or the sequence space is spent: the channel is over all the same, and a receiver learns it as it always did, by its asks being Nacked and its session's lifetime (§3.6).
- **Once.** A second close of the same channel sends nothing more; after it the sender takes no emission (`emit` makes the next channel: a new id and a new key).
- **What `END` is worth.** It is sealed under the channel's key, which every receiver holds, so any receiver, and any holder of the key, can seal one (§12.9). On a channel that announces checkpoints (§15) the receiver ends the session only when a verified checkpoint of the sender lists the `END` (§15.6), and the sender queues one right after its own (§15.3), so a forged `END` ends nothing. It decides nothing about who is a member.

### 13.12 Accepted residuals (after stages 4 and 5)

Before stages 4 and 5 a frame that opened under a channel's key was not known to be the sender's: every receiver holds the key. Stage 5 authenticates the sender by its signed checkpoints (§15) and stage 4 binds a frame to the face it arrived on (§14.4); §15.11 says what they closed of the earlier list. **A frame that opens is still the work of a holder** until a checkpoint covers it. A holder is any receiver the sender admitted (readers included) and a removed member until the re-key. Each item is expected and bounded as stated.

1. **Delivery before a checkpoint.** A frame a holder forged is delivered to a `Prompt` receiver for at most the stated window `W` (§15.9) and is then exposed (§15.5). A reader of a sealed space can thereby write live data to the other receivers for that long, which `heap.md` does not allow it to write in the space. The same holds for old content sealed again under a new `seq0`, for a forged `BIND`, `NAMED` message or `UNBIND` (read until the checkpoint retracts it; up to 4,096 names a channel) and for forged `HELLO` and standing brackets (§12.9). `Trust::Verified` delivers none of them.
2. **Frames no checkpoint judges.** A frame accepted after the checkpoint that covers it was verified (a datagram that arrives after the stream's checkpoint, or a holder's frame at a sequence the sender used and this receiver has not accepted yet), a frame in the range of a checkpoint that never arrived (a congested relay drops stream frames, §14.4), and a frame the ring forgot (the receiver's 4,096 frames, 2 MiB a channel and 8 MiB a node; the sender's 4,096 frames and 4 MiB) are **not judged**, and are counted `unchecked`. A holder can place a forgery at such a sequence. A late datagram on a channel whose sender then goes quiet has no later checkpoint to move the silence clock past it within 3 s (the idle checkpoint comes every 5 s, §15.3), so the receiver's session ends `Unverifiable` and, as in item 4, the receiver asks again: any network that delays datagrams behind the stream does it (the conformance cases c19-c22, on the faulty profile, ask again when it happens).
3. **A forgery far ahead.** A frame sealed at a `seq0` above the sender's, within 2^24 of the highest the receiver has seen (§12.2), is judged only when the sender's range reaches it. Until then, in `Latest`, it mutes that name's genuine messages until its record is forgotten, and it moves the replay window; on a channel with checkpoints the silence rule holds delivery after `max(4 × period, 100 ms)` and ends the session at 3 s (§15.7). Past the bound the frame is refused (`TooFar`): no frame moves the window further than 2^24 at once. **Within** the bound a frame can make the sender's later frames `too_old` until the session ends, on a channel with checkpoints, or until the receiver asks the sender where it stands and puts the window back, on one without (§12.2, item 22).
4. **A holder can end a session.** It seals a checkpoint that does not verify: the session ends `BadCheckpoint`, evidence is made and the face the checkpoint came over is asked to be barred (§13.12 item 24), which fails closed (§15.6). Or, when the sender is idle, it makes the receiver accept a frame the sender's next checkpoint does not reach within 3 s: the session ends `Unverifiable` (§15.7). The receiver can ask again (§13.11) and does not do so by itself. A forged `END` alone ends nothing (§15.6).
5. **Withholding.** A holder or a relay on the route can drop frames and checkpoints. It shows as a gap in `Reliable` and `Window` (§12.6), and not at all in `Latest`; no checkpoint attributes it, because loss is not forgery. The silence rule bounds what flows unchecked, not what is dropped. A holder that replaces a genuine frame with its own at the same `seq0` is exposed (§15.11).
6. **Attribution is to a link.** Evidence names a holder of the key and the face the frame arrived on at the receiver's forwarder, which is the nearest hop upstream; a hop that carried a holder's frame from further away is the one barred (§14.12). A bar costs that link the channel frames it sends to that forwarder for 60 s, doubling for each repeat to an hour (a bar asked for again while one is live changes nothing), and is local to that forwarder. It is not a cut in both directions: the forwarder still sends the face the frames of routes it is a sink of, and the `Keep` and `Unsub` the face sends for those routes still count (§14.7). A multicast Ethernet face is one face for the whole segment, so its bar is the segment's (item 20).
7. **The ingress is a number the host chooses.** `deliver_frame` takes it. With `attach_forwarder` it is the forwarder's id of the face, which the forwarder sets and not the frame, but a host that gives every face one number has one share of the early-frame hold (§12.8) for all of them, and a peer that opens many faces holds many shares and the node's 4 MiB is then the only bound. Frames of different senders that come over one link share one ingress. A link's identity is a device, never a person.
8. **The early-frame hold.** A `Window` joiner's early replay or standing frames beyond one face's share (16 frames or 2 MiB) are lost, and the stream cannot ask for them again.
9. **Stale grace.** A removed member keeps the old key, and with it the read of what was sealed under it, for the 5 s of grace counted from the answer that gave the others the new key (§3.6).
10. **Retained memory.** A key holder can keep 4,096 payloads of up to 9,000 octets alive in a `Latest` queue (about 36 MiB) by sending small messages in frames of that size: the queue is charged what each message pins (§12.6), and a frame over 9,000 octets is copied out first.
11. **A restart empties the ask replay guard.** An ask captured in the 240 s before a sender's restart can be replayed once after it (§3.3 step 5). It yields a session wrapped to the asker's own key and a receiver entry for the ask's lifetime, nothing readable to the replayer.
12. **Announce.** It is a hint: a device is asked only if the space's record holds an entry of it (§9), so a writer's device that has never written is asked by name, not by hint.
13. **Fair share is per link, not per person** (`ndn-link.md` §9): a grantee with N links holds N shares, and the floors of more than `capacity / floor` active links add up to more than the capacity. The link layer has a device and no person at the quota.
14. **The first congestion window is 4 × `path_mtu_max`.** A connection's first congestion window is `max(14,720, 4 × path_mtu_max)` octets, 36,000 at the default 9,000, which exceeds RFC 9002 §7.2 on a real 1,452-octet path (about 25 packets in the first round trip). It is there because quinn gates a `CONNECTION_CLOSE` that has ack-eliciting data pending by the congestion window and an MTU probe in flight uses the window, so a refusal sent right after the handshake needs room (without it the refused peer read a stateless reset, not the reason, about one run in two). It is bounded: before the path is validated the server sends at most three times what it received; quinn paces at window over round trip; after a loss or timeout the window collapses to the minimum; a connection that carries nothing holds none of it. The 4× margin for other data in flight is not measured, so it was not narrowed.
15. **One task reads every channel's frames.** A node's frames reach it through one task (§14.10), which gives each to `deliver_frame` and waits there for room in a blocked `Reliable` or `Window` `Items` (§12.6). While it waits, the frames of the node's other channels queue in the app face's side inbox (256 frames, 8 MiB) and are dropped, counted, when it is full. The forwarder is never stalled by it. What the task spends on checkpoints is bounded before it is paid: a holder of the key can seal a genuine checkpoint again at any number of fresh sequences, each of which would cost a hash and an Ed25519 verification (about 41 µs), so a channel verifies a burst of 64 and then two a period (at least four a second), the node a burst of 256 and then 4,000 a second (§15.4), and the rest are dropped unread and counted `checkpoints_over_rate`, neither a forgery nor a bad checkpoint. A flood of them costs the task an AEAD attempt each; a genuine sender never meets the bound. While checkpoints are dropped, frames waiting for one stay held and the silence rule applies (§15.7).
16. **A path with no stream.** A channel whose carrier has no stream sends no checkpoints (§15.3): nothing exposes a forgery there, `Trust::Verified` is refused, and what is delivered is authenticated only as a holder's. A sender behind a forwarder learns whether the first hop toward each receiver carries the stream (§14.9): it refuses a `Reliable` or `Window` ask over a hop that does not, `NoStream`, and gives a `Latest` receiver behind one a session that offers no stream, announces no checkpoints and is sent no `HELLO` or `BIND`, so that receiver's channel has no checkpoints either. **Not learned:** a hop beyond the sender's own forwarder (a relay whose sink is an Ethernet face) is invisible to the sender; the relay drops the stream-class frames (`class_unsupported`) and the receivers behind it get no `HELLO`, no `BIND` and no checkpoint (§14.9).
17. **Deferred carriage.** IPC connections carry no channel frames (§14.10), and no node uses the ring carrier (§14.9). The next steps are stated there. The radio faces are sinks (§14.9); no channel has been run over a real radio.
18. **A member can still occupy the replay slot and the gate once a second.** A claim of `ASK_NEW` and an `ASK_SINCE` share one limit of a replay a second per channel (§13.7); a member (4 asks a second per key) that sends one every second takes the slot each time: a legitimate receiver that returns in that second is refused `Busy` and waits up to a second, again and again, and each admitted ask arms the stream's route gate once (§14.10), so the stream's next frame waits for a `Keep` that this member need not send, up to `ROUTE_WAIT` (1 s), once a second. What the member cannot do is more than that: no ask queues a second replay in the second, none grows the queue past 1 MiB, and a refused one arms nothing. The stream is delayed, not stopped, and checkpoints go after the wait; a fresh receiver (a device never listed) is never refused by it. The remedy is to remove the member from the space.
19. **The ring carrier's limits** (§14.9). (a) *Not Linux:* there are no `memfd` seals, so the data fd is an `O_RDONLY` open of an owner-only object: a reader of another uid cannot write the ring, but a process of the same uid that can reopen the object read-write can (forge a frame that opens only under the key, or end the stream), and a holder of any ring fd can `ftruncate` it, which faults the writer. On Linux the kernel refuses both, to the same uid too. The named (non-anonymous) regions of a `ShmFace` (`SpscFace::create`, found by name) are unsealed on every platform; the channel ring does not use them. (b) A reader writes its own registry page, so it can keep its wake flag set: the writer then makes one `write(2)` to that reader's wake pipe on each publish (at most 32 readers; the pipe's capacity bounds what queues). It harms no other reader. (c) A holder of the secret can take all 32 places and keep them: every later attach is refused (`Declined`, with the reason) until one leaves or the owner restarts the ring. It is an audience member, who could as well drop what it relays. A place is freed when the reader's end of its wake pipe closes, so a reader that stays alive and reads nothing keeps its place (it is lapped, not waited for). (d) A process without the secret can hold up to 16 handshakes at once (8 for one uid) for 5 s each. While it does, an attach by another process of the same uid is refused at once and retried for 2 s; it is shut out itself after 16 handshakes left unfinished (64 for its uid) for 60 s. So a same-uid process without the secret can delay same-uid attaches in bursts of 5 s until its own bound shuts it out; a client of another uid is served up to the 16 in flight in all. (e) The application end of an `SpscFace` that writes a cursor out of range closes its own face, with a stated reason (`closed_reason`, and an `error` log); one that keeps the ring in bounds and full costs the engine a copy per packet, and the reader yields to the runtime every 32 packets.
20. **A shared Ethernet segment is not an identity (the multicast face).** A unicast `NamedEtherFace` hands the forwarder only the frames its named peer sent, on Linux as on macOS and Windows (§14.9), so a third station cannot speak as that face. A `MulticastEtherFace` is **one face for every station on the segment** by construction: the forwarder cannot tell the stations apart, so any station on the segment can (a) send an `Unsub` or a `Keep` for the multicast sink (the first `Unsub` removes the sink for every station; a `Keep` holds it for a station that left), (b) send frames of a route the multicast face is the source of, whose id is in the clear on the wire (they fail the AEAD at every receiver or, from a key holder, fall to the checkpoints, §15), and (c) grief with the bar: a bar of the multicast face is a bar of the **whole segment**, so the channel frames every station sends over it are dropped for the bar's length (60 s, doubling to 1 h, §14.7), and a station that makes a receiver see a contradicted frame over the segment makes it bar the segment again. A station on a shared medium is a device, never a person (item 7). Bounded by what the table already bounds (§14.2: sinks per route, routes per face, the bar's cap), by the per-face rate on the segment's sink face (`ethernet_rate`, §14.8, off by default) and by the receivers' per-ingress shares (§12.8, item 7). Not fixed: the medium has no source identity the forwarder can check; a segment whose stations are not all trusted carries channels through unicast faces, or not at all.
21. **No rate on what a source face sends in.** One frame from a route's source is up to 64 sink sends (sinks per route, §14.2). The table limits what it hands one **sink** face (`SideRate`, §14.8: a per-face seam, on by default only on the radio kinds and off on Ethernet and every other kind; `SideConfig::ethernet_rate` and `SideTable::set_rate(face, rate)` turn it on), and no rate what a **source** face sends in, so the forwarder does up to 64 non-blocking sends for each frame a source face reads, as fast as that face delivers (a frame that fails a step costs nothing below it, §14.4; a sink that cannot take a frame drops it, counted). Accepted: the per-face rate seam exists and is the control an operator uses; no second mechanism is added.
22. **A far frame can keep a channel without checkpoints refused (§12.2).** After the replay window is put back, a holder can seal another frame as far above as the bound lets it and the window moves past the sender again; the receiver asks the sender again at the ask's one-a-second rate and puts the window back from the signed `S_SEQ`. So a holder that spends one frame a second can keep a `Latest` channel without checkpoints refused for most of the time, and the frames it refuses are lost. Not fixed: nothing signed says where a frame belongs on such a channel except the sender's answer to an ask, and a prevention that does not use it would refuse a receiver that was cut off for a long time. A channel with checkpoints ends the session instead (§15.7).
23. **The node's budget for checkpoints and holds is divided by channel (§15.4).** A node divides its 8 MiB for frames kept for checkpoints and frames held among its checkpointing channels, each at most 2 MiB and at least 64 KiB, and a channel over its part gives the excess back at the maintenance pass (250 ms) after the part shrank. A peer that holds the keys of many channels holds many parts: it cannot take what the others need, but a node with more than 128 channels that hold anything is past what the budget can give each of them 64 KiB of, and until the excess is given back a channel within its part finds the node's bytes taken: its frames go `unchecked` (or are dropped from the hold) and `budget_starved` is counted and told in a `warn` once in 30 s. Not attributed: the budget is not divided by link or person.
24. **The bar's outcome is not in the alert (§14.7).** `Alert::ChannelForgery` and `Alert::ChannelCheckpoint` are raised at once, and the bar is asked of the node's `IngressBar` in a task of its own, so the alert says the face was asked to be barred and not that it was. The node's log says what became of it: `NOT barred` when no `IngressBar` is attached, `barred for N s`, or `could NOT be barred` with the forwarder's reason (the node's own face, a face it does not hold). The `EndReason::BadCheckpoint` text says whether a bar was asked.
25. **Evidence is bounded (§15.5).** A node keeps the last 64 pieces of evidence and at most 4 MiB of frames and proofs between them (the oldest go first), and a frame or proof over 128 KiB is kept as its length and SHA-256: a third party cannot check the sender's signature against a hash, only that a frame it is given is the one the node saw.
26. **A receiver whose first `Keep` the forwarders hold back stalls the sender's stream for a second (§14.5, §14.10).** The sender holds the stream frames of a channel (`HELLO`, binds, checkpoints) for the `Keep` of each receiver it just judged in, at most `ROUTE_WAIT` (1 s). A forwarder passes a sink's `Keep`s upstream within a burst of 8 and then one every 5 s, so the first `Keep` of up to eight receivers behind one link (a relay) reaches the sender at once. A ninth receiver that joins before the burst has paid back (one every 5 s) finds its `Keep` held, and the sender's stream frames (its checkpoints too) wait the second out; during it a `Latest` receiver defers the data frames a checkpoint has not vouched for and may drop them. Not fixed: the `UP` record carries no receiver, so a forwarder cannot tell a receiver's first `Keep` from a repeat, and a limit that did not bound the `Keep`s a sink passes would let one face make the table send one frame per `Keep` it is sent.
27. **A lost first `Keep`, or a session held longer than `ROUTE_WAIT`, drops the `HELLO` and the receiver is told `NoPath` (§14.5, §14.10).** The sender's stream gate waits at most `ROUTE_WAIT` (1 s) for the first `Keep` of a channel (§14.5). That `Keep` is one datagram, sent when the receiver installs the session and then every `KEEP_EVERY` (10 s); on a lossy network it can be lost, and on a slow one it can come later than the wait (so can the session Data that lays the route it travels). A channel whose wait ran out without any `Keep` drops the stream frame, the `HELLO` among them, and every later stream frame until a `Keep` comes. The receiver then has no frame in `NO_PATH_AFTER` (2 s) and is told `NoPath`. It cannot tell this from a forwarder that does not carry channel frames, so the refusal says both (§14.10): update the forwarder, **or** the first `Keep` or the session was lost or held up on the way and the receiver should ask again. A new ask is a new session with a new `Keep`; the host does it (the conformance cases c19-c22 do). Accepted: the protocol sends no `Keep` again before `KEEP_EVERY` and the sender waits no longer than `ROUTE_WAIT`, because the wait is what keeps a stalled receiver from holding a channel's checkpoints (item 26), and a retry inside the protocol would be a second timer every receiver pays for to cover a loss only a lossy link makes; the cost is one more ask by a receiver that was told why.

## 14. The forwarder's side table

A forwarder that carries channels holds one table for their frames, the **side table**. It copies each frame to the faces that asked for it, once per face, and knows nothing of what a frame is. This section says what the table keeps (§14.1, §14.2), how a route comes to be (§14.3), how a frame and a keep-alive go through it (§14.4, §14.5), how a route is kept and ends (§14.6), how a face is barred (§14.7) and paced (§14.8), what a face has to carry (§14.9), what a node does to use the table (§14.10), the management commands and counters (§14.11) and the threat notes (§14.12).

Implementation: `ndn-packet` (`lp/`: the `SideRoute` header), `ndn-transport` (`Transport::forward_side_from`, `side_header.rs`), `ndn-engine` (`side.rs`: the table; `dispatcher/inbound.rs`: the peel; `dispatcher/outbound.rs`: the install), `ndn-mgmt` (`modules/side.rs`), `ndn-face-local` (the app face's side inbox), `ndn-app` (`Connection`), `ndn-face` (`l2/`: the Ethernet faces), `ndn-heap` (`chan/route.rs`, `chan/bar.rs`: the node's part) and, in ndn-ext, `ndn-link` (`FaceSink`, [ndn-link.md](ndn-link.md) §9).

### 14.1 The table

`SideTable` is owned by the `ForwarderEngine` (`ForwarderEngine::side()`; `EngineConfig::side` sets it). It is **generic**: it holds opaque 64-bit ids, `FaceId`s, times and counters, and nothing else. It never sees a name, a key, a space, a person or a mode; it decrypts and verifies nothing; the one kind of frame it reads is `UP` (§11.5), its own keep-alive. It is not the FIB and not the PIT: routes come and go with sessions, and nothing in the table is a name.

A **route** has an id (the channel id, which the table treats as 64 opaque bits), **one source face**, one to 64 **sink faces**, and counters of the frames and octets it routed. A **sink** is a face, an expiry and the time its last `Keep` was passed upstream. A face may be the source of some routes and a sink of others. The source is the face the setup Data arrived on, the next hop toward the sender; a sink is a face whose Interest that Data answered, a hop toward a receiver.

### 14.2 Limits and refusals

The bounds are `SideLimits`, set by a host in `EngineConfig::side` (`SideConfig`).

| What | Default | Over it |
|---|---|---|
| Routes in the table | 4,096 | the install is refused `TableFull` |
| Routes one source face feeds | 256 | `SourceFull` |
| Sinks on one route | 64 | `SinkCap` |
| Routes one face is a sink of | 1,024 | `SinkFaceFull` |
| TTL of a sink | the header's `ttl_secs`; 0 is 30 s (`ttl_default`) | a TTL over 300 s (`ttl_max`) is clamped to it |
| `Keep`s passed upstream | a sink passes 8 in quick succession (`keep_forward_burst`: the first `Keep` of each receiver behind one link), then one every 5 s (`keep_forward_min`) | the `Keep` refreshes the sink and goes no further |
| Sweep of lapsed sinks | every 1 s, on the engine's clock | |
| Bar | 60 s, doubling to 1 h (§14.7) | |
| Rate of a sink face | 1 MB/s on radio kinds, off on Ethernet kinds (§14.8) | the frame is dropped for that sink, `quota` |
| The app face's side inbox | 256 frames and 8 MiB | `Full`, counted |

`SideTable::install` refuses with a `SideRefusal`, leaves the table as it was, and each refusal is counted (`refused_*`, §14.11):

| Refusal (`label`) | What it says |
|---|---|
| `TableFull` (`table_full`) | the table holds its most routes |
| `SourceFull` (`source_full`) | the upstream face already feeds its most routes |
| `SinkCap` (`sink_cap`) | the route already fans out to 64 faces |
| `SinkFaceFull` (`sink_face_full`) | the receiver's face is already a sink of its most routes |
| `SourceMismatch` (`source_mismatch`) | a route with this id exists with another source: the id is in use or the path changed; wait for the old route to lapse |
| `SinkIsSource` (`sink_is_source`) | the receiver's face is the face the Data arrived on: a route cannot loop back |
| `Quarantined` (`quarantined`) | the upstream face is barred (§14.7) |
| `FaceGone` (`face_gone`) | a face of the route is no longer on this forwarder |
| `NotCarried` (`not_carried`) | a face of the route cannot carry channel frames (`side_frame_max` is 0 or it carries no datagram class: a TCP, UDP or WebSocket face, a bare IPC socket): a route over it could never carry a frame or a `Keep`; the receiver is reached over a link that does, or through a relay |
| `NotAsked` (`not_asked`) | the Data did not come from a face its Interest was sent out of: a route is installed only from the face that answered the request |

The message of each names what to look at and what to raise or end.

### 14.3 How a route is made

**The label.** A route is made by the session's own Data. The Data carries an NDNLPv2 header, `SideRoute` (`LP_SIDE_ROUTE`, TLV-TYPE **0x0370**; `ndn_packet::lp::SideRoute { id, ttl_secs }` in `LpHeaders::side_route`). Its value is exactly 10 octets: the route id (8, big-endian) then the TTL in seconds (2, big-endian). A value of any other length makes the whole LpPacket a decode error (fail closed). The type is even, so a decoder that predates it skips it (last paragraph of this section). It follows the NDNLPv2 header order: after every header of a lower type (`CachePolicy` 0x0334, `CongestionMark` 0x0340, the A-LAL fields 0x0360 to 0x0364) and before the Fragment; one out of order or twice is a decode error, as for any LP header. On a fragmented Data it counts only on the final fragment, the one the reassembled packet continues as. The registry is the NDNLPv2 table of [README.md](README.md#ndnlpv2-header-numbers). The wire of a header with id `1122334455667788` and TTL `0x99AA` (39,338 s; a forwarder clamps it to 300 s) is:

```
fd03700a112233445566778899aa
```

**The install.** The Data pipeline installs routes in the step that sends a matched Data on, after the PIT matched and, where the engine validates Data, after the Data validated. For each face `f` in the PIT entry's in-records other than the face `a` the Data arrived on, it calls `install_live(id, a, f, ttl, faces)` and sends the Data to `f` **with the header again**, carrying the TTL the table kept (the header's, 0 becoming 30 s and more than 300 s becoming 300 s). The next forwarder does the same. The install is made only if (1) the Interest went **out of `a`**, that is, an out-record of the PIT entry the Data consumed names `a` (the PIT stage marks a Data that no out-record accounts for, and every `f` is then refused `NotAsked`: the Data is forwarded as ever, only the route is refused); (2) both faces are **on this forwarder**, which `install_live` reads under the table's own lock (the teardown of a face leaves the face table before `remove_face` takes that lock, §14.6, so an install either sees the face gone, `FaceGone`, or has its sink removed by the teardown that follows); and (3) both faces **carry channel frames**: `side_frame_max` is not 0 and the datagram class is carried (`NotCarried` otherwise, §14.9). The header is echoed to `f` only with an installed route, so a face that cannot carry channel frames (a TCP or WebSocket face, a bare-TLV IPC socket) never gets a header, a sink or a route, and its Data is the Data an NDN consumer expects (bare TLV on a face that uses none). A Data that carries the header goes to a face that carries side frames in an LpPacket even where the face does not use LP framing (as one with a PitToken does). Installing a sink the route already has refreshes its TTL; another face adds a sink.

**A refusal** (§14.2) is counted and logged at `warn` with the route, the two faces and the reason, and that face gets the Data **without** the header: it still gets the session and gets no frames, so its receiver reports `NoPath` after 2 s (§14.10).

**When nothing is installed.** A Data served from the Content Store carries no header (the session Data is `NoCache`, so none is); a Data that matched no PIT entry has no in-record, so no sink; a Data from a face no Interest of this forwarder went out of installs nothing (`NotAsked`: any station on a shared medium, or a hop that does not validate, can send a Data whose name is pending, and its arrival face is then no source); a face that cannot carry channel frames is neither sink nor source (`NotCarried`); and the arrival face is never offered.

**Where the faces are.** At the sender's own forwarder the Data arrives from the sender's app face, which becomes the source. At the receiver's forwarder it arrives from a link and the receiver's app face is the sink. At a relay both are links. A route therefore runs from the sender's app face through every hop to the app face of every receiver, and exists only where a receiver's Interest went.

**Why a stray or forged header does little.**

- A route is installed only for a Data that matched a PIT entry, so a face becomes a sink only if it **asked**: its Interest is the in-record.
- The source is the face the Data arrived on, and only if an Interest of this forwarder went out of that face (`NotAsked` otherwise); it is therefore a face an Interest to the sender went out of. A frame of the id from any other face is dropped (§14.4).
- The table counts everything (§14.2). A second Data that names an id already routed from another source is refused `SourceMismatch`. The ids are 64 random bits (§3.2) and a forwarder holds at most 4,096 routes, so two live routes collide by chance with probability about 2^-41.
- What a hostile next hop can do is send frames into the routes it is the source of. They fail the AEAD at every receiver or, from a key holder, fall to the checkpoints (§15).
- None of this rests on validation: a forwarder that validates no Data (a relay in transit, ndn-link.md §15.7, or a profile with security off) installs on the PIT match alone.

The label is **not** covered by the Data's signature: it is a claim of the hop that sent the Data on. A hostile next hop is on the path anyway; with the label it can also name an id that is not the channel's (the receiver then reports `NoPath`), or the id of a channel not yet routed here (that channel's own session Data is then refused `SourceMismatch` here until the squatted route lapses, at most 300 s without `Keep`s). The receiver's judgement of the Data (§3.4) is no judgement of the label.

**A forwarder that predates the header.** It skips the even type, forwards the Data without it and installs nothing. No frame crosses it, and the receiver reports `NoPath` with the next step "a forwarder between you and the sender does not carry channel frames: update it" (the text adds the other cause it cannot tell apart, a lost or delayed first `Keep`: ask again, §13.12 item 27). The setup has no other path to fall back to: it **fails closed**.

### 14.4 The data path

**The peel.** The reader of every face looks at the first octet of what it read. If it is `0x00` the frame is a channel frame: the reader adds it to the face's `in_side_frames` and `in_side_bytes`, stamps the face's activity (§14.6), calls `SideTable::on_frame(face, frame, faces)` and reads on. That is one comparison, made before NDNLPv2 detection and before the pipeline's bounded channel, so a channel frame never costs a PIT entry, a task, an `in_drops` count or a malformed-packet verdict, and an NDN packet never takes this path (no NDN packet starts with `0x00`, [ndn-link.md](ndn-link.md) §9 item 7). A frame the table does not route is dropped there, counted.

**A locally originated frame** takes the same path: the sender's node sends it into its app face (`Connection::send_side`, §14.10), the face's reader peels it, and the face is the `from` of `on_frame`.

**`on_frame`** never blocks, so the reader goes on reading the face's NDN packets whatever a sink does with the frame. It does, in this order, and a frame that fails a step costs nothing below it:

1. Parse the 10-octet routing header and, for an `UP`, its 11-octet record: `malformed`.
2. `from` is barred (§14.7) and the frame is not an `UP`: `quarantined`. (An `UP` is a face's own sink management and passes the bar, §14.5.)
3. Look the id up (a map read): no route, `unrouted`.
4. An `UP`: §14.5.
5. Any other kind: `from` must be the route's source, else `wrong_source`. Then fan out.

**Fan-out.** For each sink:

- A sink whose expiry has passed is skipped, even before the sweep removes it.
- A sink face with a rate (§14.8) whose bucket is empty is skipped: `quota`.
- A sink face that is no longer on the forwarder: `sink_full`.
- Otherwise the table calls `Face::forward_side_from(frame.clone(), class, from)`, `class` being the header's class bit. `Bytes::clone` is a reference count: the frame is **not copied per sink**. A taken frame counts in `frames_out`; the result `Full` counts `sink_full`, `Unsupported`, `NotCarried` and `PeerLacksChannels` count `class_unsupported`, and any other refusal counts `sink_error`.

**`forward_side_from(frame, class, ingress)`** is the non-blocking hand-over of a frame to a transport: `Transport`, `ErasedTransport` and `Face` all have it. `ingress` is the face the frame arrived on at this forwarder. The default ignores it and calls `forward_side` (itself `Unsupported` by default); a transport that delivers into an application keeps it, so that the application can say which link a frame came over (§14.9). Each also has **`side_carries(class)`**: whether the transport's medium carries side frames of that class, a fact of the medium and not of the queue's room. The default is whether `side_frame_max` is nonzero (a transport that opted in takes both classes); a transport with no ordered, reliable stream says `false` for the stream class (the Ethernet faces, and the writer of the ring carrier, §14.9), and the default `send_side` refuses a class the transport does not carry `NotCarried`. The engine exposes it as `ForwarderEngine::face_carries_side(face, class)` (`false` for a face it does not hold) and learns nothing of what the frames mean.

**A sink that cannot take a frame loses it, visibly.** The relay drops it for that sink, counts it (`sink_full`, `quota`, `class_unsupported`, `sink_error`; `side/list` shows them) and goes on. A receiver behind it sees a gap in `Reliable` and `Window` (§12.6); in `Latest` nothing is noticed (§12.1). A relay is lossy under congestion, and says so.

### 14.5 `UP`: keep and unsub

A face sends an `UP` frame (§11.5) to say something about a route it is a sink of. The table reads it as its own, answers nothing, and changes only that face's own sink.

- **`Keep`** from a sink refreshes **that sink's** expiry to its TTL from now (§14.6). The table passes the frame to the route's source face as a datagram (its octets unchanged, the sink's face as the ingress) and notes it, while that sink is within its **burst**: it may pass `keep_forward_burst` (8) `Keep`s in quick succession, and after that one more for every 5 s (`keep_forward_min`) that went by (a cell-rate limiter: each passed `Keep` is paid for with 5 s, and one passes while at most seven are still owed). A `Keep` the source could not take is not noted, so the next one tries again. A sink's first `Keep` goes up at once at every hop, so the sender learns that a receiver's route is up. **Why a burst and not one at once:** at the hop before a relay, the relay's one link is a single sink for every receiver behind it, so the second receiver's first `Keep` is not that sink's first. Held 5 s, it would leave the sender's stream gate (§14.10) waiting for it until `ROUTE_WAIT` ran out, a second in which the sender's checkpoints and binds stand still and a `Latest` receiver, holding frames a checkpoint has not vouched for, drops them. The burst lets the first `Keep` of eight receivers behind one link through at once; the rate over a longer time is what it was, one frame per sink every 5 s at each hop. A ninth receiver that joins within the seconds the burst takes to pay back waits for the sender's gate as an ask whose `Keep` was lost does (§13.12 item 26).
- **`Unsub`** from a sink removes that face's sink. If the route has no sink left it is removed and the `Unsub` goes on to the source; otherwise nothing goes up.
- An `UP` from a face that is not a sink of the route is dropped (`wrong_source`), barred or not: a bar (§14.7) does not stop a face's own `Keep` and `Unsub` (they are bounded as any are), so the routes it receives over stay up and the senders upstream go on sending to it; one for an unknown id, `unrouted`; one that does not parse, `malformed`.

### 14.6 Lifetime and teardown

- **TTL.** A sink lapses its TTL after its last install or `Keep`. The 1 s sweep removes lapsed sinks and a route left with none, and counts `sinks_lapsed`. A receiver that left or was removed stops sending `Keep`, so its entries lapse at every hop within the TTL. A removed member that goes on sending `Keep` holds a sink and is sent ciphertext it cannot open: the forwarder judges no membership (§14.12).
- **The session Data asks for 30 s** (`SIDE_TTL`); a node sends a `Keep` for each session it holds every 10 s (`KEEP_EVERY`, a third of the TTL, so two lost ones still leave the sink alive) and an `Unsub` when it lets a session go (§14.10).
- **A face that goes down takes its routes with it.** `SideTable::remove_face(face)` drops every route the face is the source of and every sink on it, and a route left with no sink. It is called wherever the engine removes a face, **after** the face has left the face table (§14.3): `ForwarderEngine::remove_face` and `EngineDiscoveryContext::remove_face`, the tail of the face's reader (the persistent branch too), the idle reaper, the close after a send error and `faces/destroy` of a face with no token. The 1 s sweep also drops every route whose source or sink face is no longer in the face table, as a catch for any other exit. The bar of the face and its history stay (§14.7) and its rate goes.
- **A link that loses an identity and stays.** When a link loses an identity but another membership still admits it, `Links` calls `FaceSink::side_remove_face(face)` for each of its faces: channel authority is link-wide and a route's id cannot be tied to a namespace, so any identity lost counts, which is the fail-closed reading. No frame then crosses the link on the strength of the lost identity; a receiver behind it asks again and the new Data installs what the remaining identities allow ([ndn-link.md](ndn-link.md) §9 item 8).
- **Activity.** The quiet-close rule counts a face with a side route as routed and counts the octets of channel frames on its stream as activity only while the forwarder holds such a route ([ndn-link.md](ndn-link.md) §16.2). The engine's own idle reaper, which removes a connectionless on-demand face (UDP and the like) after 5 minutes without traffic, counts a channel frame as traffic as it counts an NDN packet: a frame **received** on the face (stamped by its reader), a frame **handed to it as a sink** and an `UP` record passed to it as a route's source (stamped by the side table). A face that carries only channel frames is not reaped, and its routes stay; one that carries nothing is still reaped, with its routes.
- **No route, no send.** `SideTable::sinks(id)` is the number of live sinks. A sender whose route has none sends nothing that reaches anyone (§14.10).

### 14.7 The bar

A face is **barred** when a frame that came over it is shown to be a forgery (§15.5, §15.6). A bar is on what the face **sources**: the channel frames it sends to this forwarder for the routes it is the source of. NDN traffic over the face goes on, the forwarder still sends the face the frames of routes it is a sink of, and the face's own sink management (`Keep`, `Unsub`) still counts: a bar does not cut the link in both directions.

- **What a barred face loses.** The frames it sends as a route's source are dropped (`quarantined`), and no route is installed with it as the source (`Quarantined`). Its `UP` records, `Keep` and `Unsub`, are **not** dropped: they are its own sinks' management, bounded as any are and `WrongSource` unless the face is a sink of the route. Dropping them would let every sink the face holds lapse within the TTL and end the senders' routes to it, so the bar would cut what the forwarder sends it as well; and a barred relay's receivers, who did not forge anything, would lose their routes with it.
- **`bar(face, now)`** applies the next length of the face's history: 60 s, doubling for each repeat on the same face (120 s, 240 s, …) to 1 h, and 60 s again once the face has gone an hour after its last bar ended without another. It returns the length applied. **While a bar is live a call changes nothing**, history included: one incident reported twice (a checkpoint lags the frames) is one bar and not two doublings, and the call returns what is left of the live bar. The next call after the bar ended doubles.
- **`quarantine_for(face, now, length)`** bars for a length from now and keeps a longer bar the face already has; the length is capped at 1 h (a length of `u64::MAX` milliseconds is an hour, never a bar that does not end) and the call returns the length applied; **`lift(face)`** ends the bar now and keeps the history, so the next `bar` still doubles. Times are nanoseconds on the table's clock (`SideTable::now()`, §14.12).
- **History.** A face's bar and its history are kept per face id and survive `remove_face`, so a face dialled again at the same id is still barred; the sweep forgets a history an hour after its last bar ended.
- **Who bars.** A node that has evidence (§15.5) asks its forwarder through its `IngressBar` (`NodeHandle::attach_bar`; `attach_forwarder` attaches one over the node's connection, `Connection::side_quarantine`). An embedded engine's connection calls `bar(face, now)` and refuses its own app face, since barring that would cut the app off from its forwarder and no link delivered the frame, and refuses a face the engine does not hold (the id is the host's to choose, a bar is state per face, and a refusal creates none). An operator or an out-of-process host uses the signed management command `side/quarantine` (§14.11). **What is said of the outcome:** the alert is raised at once and says the face was asked to be barred, not that it was; with no `IngressBar` attached the node logs that the face is `NOT barred` and what to do, and a connection's bar logs `barred for N s` or `could NOT be barred` with the forwarder's reason (§13.12 item 24).
- **A bar of a shared segment.** A multicast Ethernet face is one face for every station on the segment (§14.9), so a bar of it is a bar of **all** of them: every station's channel frames over that face are dropped for the bar's length, and a repeat doubles it for all. A station that makes a receiver see a contradicted frame there bars its neighbours too (§13.12 item 20).
- **The bar is local.** It is made at the forwarder of the node that holds the evidence. Nothing carries it to another forwarder, upstream or beside.

### 14.8 The rate of a face

`SideRate { bytes_per_sec }` is a token bucket on what the table hands one **sink face**, with one second of burst. A frame is admitted while the bucket holds tokens, whatever its size, and charged its length (the bucket may go negative, so a large frame is not refused for ever at a low rate); over it the frame is dropped for that sink and counted `quota`. `UP` records passed upstream are not charged.

The default is 1 MB/s on the radio kinds (`FaceKind::Wfb`, `WifiAware`, `WifiDirect`), so a channel cannot fill a radio, and off on the Ethernet kinds (`Ethernet`, `EtherMulticast`) and on every other kind. `SideConfig::radio_rate` and `ethernet_rate` set it per kind, `SideTable::set_rate(face, rate)` per face; a face gets its kind's rate when it is added. A radio face also has its own bound below the table, the phy's side lane (§14.9), which refuses `Full` at once; the rate is the table's, the lane's bound is the radio's, and neither waits.

### 14.9 What a face carries

A face carries channel frames only if it opts in (§11: `side_frame_max()` above 0) and answers `forward_side_from` without waiting.

- **The in-process app face** (`ndn-face-local`). `side_frame_max` is 1 MiB (`STREAM_FRAME_GRANT`: a channel's datagram frame, 9,000 octets, and a shared-memory slot, 8,960, both fit). The engine's `forward_side_from(frame, class, ingress)` pushes `(frame, ingress)` into the face's **side inbox**, apart from the NDN packets (which stay on `recv`), at most 256 frames and 8 MiB. It never waits: a frame that finds either bound is refused `Full` and counted (`InProcHandle::side_dropped`), and its receiver sees the gap as a congested link's. Without an ingress (`forward_side`) the face refuses `Unsupported`. The app's own frames go the other way through the face's reader (`InProcHandle::send`, `try_send`).
- **QUIC link faces** (ndn-ext `ndn-face-quic`, through `ndn-link`): both classes, the datagram by the headroom rule and the stream through a bounded queue; `Full` when there is no room. Which links carry channel frames at all is [ndn-link.md](ndn-link.md) §9 item 8.
- **Ethernet faces** (`NamedEtherFace`, `MulticastEtherFace`, ndn-face `l2/`, the Linux `AF_PACKET` faces): the **datagram class only**. `forward_side` pushes into the face's send queue and flushes without waiting: `Full` when the queue has no room, `TooLarge` over the MTU (a frame is never fragmented), `Malformed` for a frame that is not a channel frame, and `NotCarried` for the stream class, so a hop with no stream does not silently carry a reliable channel (the table counts `class_unsupported`). A NIC pads a payload under 46 octets; §11.3 is why no frame is that short. The macOS and Windows Ethernet faces have no `forward_side`. **Each frame leaves for its own destination.** A `SOCK_DGRAM` packet socket takes the destination of every frame of one `sendto` from the call's address (the address inside a TPACKET_V2 TX frame is not read on transmit), so the ring (`af_packet.rs`) keeps the destination each frame was queued with in a preallocated per-slot table and flushes one run of frames of the same destination per `sendto`, with the queue lock held across the call. A unicast reply queued among channel frames to the multicast group, or the reverse, therefore reaches the station it was queued for; a run the kernel did not take keeps its destination and goes first at the next flush, and a queued frame keeps its slot until it is flushed (a push into a full ring is refused, never overwrites). **A unicast face hears its one peer.** On a shared segment any station can address this station's MAC, and a unicast face stands for one named peer, not for the segment: `NamedEtherFace::recv_bytes` hands the forwarder only the frames whose source is the named peer's MAC (as the macOS and Windows variants do) and drops the rest before the forwarder sees them, so a third station cannot speak as that face (send an `UP` for its sinks, send frames of a route it sources, make the forwarder bar it). A `MulticastEtherFace` stands for every station and cannot be filtered so (§13.12 item 20).
- **`MulticastEtherFace` as one sink.** A frame sent to it is **one** Ethernet frame to the NDN multicast group for every station on the segment. A station that is no receiver sees a sealed frame and, holding no route for its id, drops it (`unrouted`). A station that is a receiver holds a route whose source is the face its multicast face is on, learnt from the same session Data (the Data's in-record includes the multicast face). Two receivers behind one multicast face cost the sender's link one frame.
- **Shared memory** (ndn-ext `ndn-face-shm`, `SpscFace`): a frame is one ring slot (`side_frame_max` is the slot size). The ring is reliable and ordered, so both classes are carried; `send_side` waits for a free slot, and `forward_side` is a non-blocking push (`Full` at once when no slot is free, `Malformed` and `TooLarge` as for any face) that wakes a parked reader. The push side of the ring is exclusive (a lock), because the sender's task and the engine's reader tasks both push.
- **Radio faces** (`Radio`, `WifiPhy`, `BlePhy`, and the face a `WifiPhy::into_face` mounts): all take channel frames without waiting (`Transport::forward_side`), through ndn-radio's **`SideLane`**, one per phy: a bounded queue of **64 frames and 128 KiB** (`Radio::with_side_limits`, `WifiPhy::with_side_limits`, `BlePhy::with_side_limits`) drained by **one writer task** that sends each frame as the phy's own NDN send does. A frame that finds no room is refused **`Full` at once** (the forwarder counts `sink_full`; the receiver sees a congested link's gap); a frame over the octet bound or the smallest picked MTU is `TooLarge`, one without the marker `Malformed`. A `Radio` over several phys queues a frame on **every picked phy or on none** (`Full` if any picked queue has no room; counted in `Radio::side_stats`). **The datagram class only:** a radio has no stream, so the stream class is `NotCarried` (counted `class_unsupported`), and so is a phy that cannot carry a side frame (a BLE phy with NDNts framing, `side_frame_max` 0, refuses both classes). **A channel flood does not starve NDN.** The writer and the NDN send path (`send_bytes`, the async `send_side`) take one send at a time through a **one-permit first-come first-served gate**, so a channel flood delays an NDN packet by at most the one frame in flight and an NDN flood delays a queued channel frame by one send; the lane fills and the forwarder sees `Full`. The control bypass (`send_robust`) stays outside the gate. A `WifiPhy` nobody has read from has no medium yet and refuses `Io` saying so.
- **The ring carrier** (`RingFace` in ndn-face-shm): a lossy broadcast ring of 256 slots of `frame_max + 256` octets (`frame_max` from 36 octets to 1 MiB) with one writer and at most 32 readers **at a time**. The writer is a send-only sink: `forward_side` publishes without waiting and is never full, a reader that falls more than 256 frames behind is lapped and counts it (`RingStats::lapped`), and only the datagram class is carried (a stream-class frame is `NotCarried`, counted `class_unsupported`). A reader maps the ring read-only and carries nothing out (`side_frame_max` is 0), so a local reader **cannot forge a frame**: what it reads is what the writer's process wrote. **On Linux the kernel enforces that against a reader of the same uid too:** every region of the ring is a `memfd` sealed against shrinking and growing, and the data region against any write (`F_SEAL_FUTURE_WRITE`), so no writable mapping, `write(2)` or `ftruncate` of it succeeds through any descriptor of it, a `/proc/self/fd/N` reopen with `O_RDWR` included (`EPERM`). Each reader is handed a registry page **of its own**, which the writer maps read-only: a reader writes only its own wake flag and cursor, cannot reach another reader's flag or the header a later attach reads, and cannot make the writer's mapping fault. A reader refuses a region its owner did not seal, and says so. Where there is no sealing (not Linux) the guarantee is across uids only (§13.12 item 19). A frame that is not marked or is under 36 octets is dropped and counted; a one-octet `0x00` frame is the writer's end. A reader finds the ring by a control socket named from the ring's name, and the handoff of its descriptors is gated by a capability token bound to a 32-octet secret (a mutual challenge, so the secret never crosses the socket). **The handshake is bounded:** each connection's runs in a task of its own and ends after 5 s in all (`HANDSHAKE_TIMEOUT`, on both ends), at most 16 at a time and 8 for one uid, so a peer that connects and sends nothing, or one octet at a time, holds one place for 5 s and never the accept loop; a client whose owner is silent gets `NotServing` ("did not answer within 5 s") and does not wait. **The handoff never stops serving because of failed attempts:** a connection that fails at any step (a reader that authenticates and leaves, a socket error, a refusal) is logged with why and what to do, and the loop goes on. A reader's place is freed when it leaves (nothing holds the read end of its wake pipe), so a ring serves any number of readers over its life; when all 32 places are held by live readers an attach is refused at once, `Declined`: "ring has no free reader slots … ask the owner to restart it". The handoff counts failed attempts per peer credential (uid and pid from `SO_PEERCRED`; peers whose credential cannot be read share one bucket) and, because a process can fork to take a new pid, also per uid in a larger bound. A wrong proof, or a handshake not finished in time, is an attempt; a connection that closes without a word (a writer probing whether the name is live) is not. A process with 16 failed attempts, or a uid with 64, inside a 60 s window (monotonic, from the first failure) is closed without a word read, authorized or not, until the window ends, with a `warn` once and a `debug` per refusal that say who and when; other peers are served throughout. The table of counters holds at most 1,024 entries and drops the oldest. This bounds availability only: who may attach is decided by the token alone, never by this table or a clock. A user who can run a process as the same uid as a reader can still keep that uid out for one window; that uid already holds whatever the token protects.
- **TLV-framed streams** (a TCP or Unix socket): `NotCarried`. The codec finds the end of a frame from its first octets read as a TLV header, and the marker is TLV-TYPE 0 followed by a byte read as a length, so a side frame written as is would put the reader out of step with the NDN packets behind it.
- **The App, Shm and Unix faces and the route label.** Their readers do no LP detection (`uses_lp` stays off: a bare Data is what NLSR's PSync needs), the link service does not unwrap an LpPacket, and decode takes `0x64` on every face kind, so a session Data that an app sends in an LpPacket carrying the label reaches the pipeline intact. A Data that carries a PitToken goes **to** such a face in an LpPacket, so the consumer MUST accept one (`ndn-app`'s connections do). A Data that carries the label goes in an LpPacket only to a face that carries channel frames (the App and Shm faces): a Unix socket carries none (`NotCarried`, above), is never made a sink and gets bare TLV (§14.3).

Not built: IPC connections carry no channel frames (§14.10), and no node uses the ring carrier: `CarrierHost` (`offer_ring`, `attach_ring`) is a trait in `ndn-heap` that no host implements, and `ASK_CARRIERS` kind 5 is not carried.

**A hop with no stream.** The node's own face on its forwarder carries both classes (`ConnectionCarrier::has_stream` reads `Connection::side_carries_here(Stream)` once; a connection whose own face has none gives a carrier with none, and `Reliable`, `Window` and a standing value are refused `NoStream` at the emission, §13.5). What the hop toward a receiver carries is learnt when the receiver asks. The ask reaches the sender through its forwarder over a face: the first hop toward the asker, the face the session Data goes back over and so the sink of the route. The connection says which (`LpInfo::incoming_face_id`, handed on by `Responder::incoming_face`), and `Connection::side_carries(face, Stream)` answers from the face itself (`Face::side_carries`, `ForwarderEngine::face_carries_side`). A hop with no stream (an Ethernet face) gives: **`Reliable` and `Window`**: the ask is refused with a signed `NoStream` that says no ordered stream reaches the asker and to ask with `Latest` or put the value instead; no route is laid. **`Latest`**: the ask is answered with a session that offers the datagram carrier alone and announces no checkpoints (`S_CKPT_MS` 0). The sender queues no welcome for that receiver (`HELLO`, binds, standing values), and the receiver, whose session offers no stream, waits for no `HELLO` and is never told `NoPath` for want of one. While any such receiver holds a channel, **every message of the channel names itself** (none relies on a `BIND` that receiver never got), and, at the emission, a standing value is refused `NoStream` and a message that fits no datagram `TooLarge`; the channel's other receivers keep the stream and its checkpoints. The stream frames sent for those receivers also go to the route's sink on the hop with no stream, which refuses them (`class_unsupported`, counted). A standing value that stood before the receiver joined is not replayed to it, and no `END` reaches it: its session ends by its lifetime (§3.6). **Not learned:** only the face of the sender's own forwarder toward the asker is judged. A hop further on (a relay whose sink is an Ethernet face) is invisible to the sender: the relay refuses the stream-class frames (`class_unsupported`), and a receiver behind it gets the datagrams that name themselves and no `HELLO`, `BIND`, `END` or checkpoint, and is told `NoPath` after 2 s for want of a `HELLO` (§14.10). A connection that cannot see its forwarder's faces says nothing against the path. That path is not exercised end to end over a NIC (AF_PACKET needs `CAP_NET_RAW`; the Ethernet tests run over an in-memory bus, and the heap's tests drive the answer with a connection that reports no stream).

### 14.10 What a node does

`NodeHandle::attach_forwarder()` (or `attach_forwarder_with(datagram_max)`) gives a node over a `Connection` that reaches a forwarder (an embedded engine's `app_face`) everything below, over that one connection. It is `HeapError::Local`, with the reason and what to use, if the connection carries no side frames. A node that attached none sends, keeps and tells nothing of this.

**`Connection`** (`ndn-app`) has, for this: `send_with(wire, LpHeaders)` (a Data or Interest in an LpPacket carrying the headers, the default of every connection), `side_frame_max()`, `send_side(frame, class)` (waits for room), `try_send_side` (never waits: `Full`, `NotCarried`, `TooLarge`, `Malformed` for a frame that is no channel frame), `side_ready()` (completes when `try_send_side` may take a frame), `recv_side()` (the next frame the forwarder routed to the connection, with the id of the face it arrived over), `side_carries(face, class)` (whether the forwarder's face carries the class: what a sender asks of the first hop toward an asker, §14.9; `true` for a connection that cannot see its forwarder's faces), `side_carries_here(class)` (the same of the connection's own face) and `side_quarantine(face)`. The in-process, engine and demux connections carry them. `IpcConnection` and a bare connection do not: `side_frame_max` is 0 and `send_side` and `side_quarantine` refuse with `AppError::Unsupported` and a sentence that names the next step. The daemon's socket carries TLV packets and a `0x00`-marked frame is none; the next step is a marker-aware carriage on that connection, or to run the node over `EngineAppExt::app_face`. `side_quarantine` there is the signed `side/quarantine` command.

**The sender.**

- The session Data goes out with `SideRoute { id: the channel id, ttl: 30 }` and `NoCache`. `Extension::answer` returns `Option<host::Answer { wire, side: Option<(u64, u16)> }>` ([heap.md](heap.md) §10.9): a plain Data, or one with the label.
- A datagram frame leaves by `try_send_side`, a stream frame by `send_side`. The carrier reports a datagram limit of 1,200 octets (`DATAGRAM_FRAME_MAX`: what one QUIC datagram carries at the smallest path MTU, because a sink may be a link), which a host with only local sinks may raise, up to the channel's 9,000, with `attach_forwarder_with`; a message that does not fit goes on the stream (§13.2 item 6). Its stream limit is the connection's `side_frame_max`, 1 MiB.
- **The gate.** A marked frame is peeled in the face reader and can overtake the Data that is still installing the route. So a **stream** frame of a channel waits, for at most `ROUTE_WAIT` (1 s), for an `UP` `Keep` to come back to the sender: the first `Keep` of the channel, and one more after each receiver judged in as new and whose frames were queued (a fresh device, a claim the replay limiter admitted, §13.7; an ask that was refused queues nothing and arms nothing). A `Keep` that reached the sender proves every hop holds the route. If none ever comes the frame is dropped and counted, and each later stream frame of that channel is dropped without waiting until a `Keep` comes (**no route, no send**). If the channel already had `Keep`s and only a newcomer's is missing, the frame goes after the wait: the receivers that are routed need it. **Datagrams are never gated**; a datagram with no route is dropped at the forwarder (`unrouted`).
- **One `Keep` for each ask made as new.** The receiver sends the first `Keep` of a session when it installs it (§14.10), and, for each ask it made as new (`ASK_NEW`: no session of the channel held when the ask was built), one more when that ask's answer is taken, **also when another ask's answer installed the session first**. An explicit `get` and an announce-driven ask in flight together are both made as new; the sender welcomes the first as a fresh device and the second as a claim, and each arms the gate for one more `Keep`. The second answer finds the session installed and its `Keep` entry standing, so without its own `Keep` the sender's stream frames (a second `HELLO`, binds, checkpoints) would wait the whole `ROUTE_WAIT` for the next maintenance pass, and a `Latest` receiver would defer and drop the messages sent meanwhile (found by the e2e `channels` scenario under load; test `an_answer_to_a_second_new_ask_in_flight_sends_its_own_keep_at_once`).

**The receiver.**

- One task of the node reads `recv_side` and gives each frame to `deliver_frame` with the forwarder's face id as the `ingress` (§12). A `Keep` that arrives at a sender is not delivered to the receiver path: it releases the sender's gate. The engine's reader never calls `deliver_frame`, so a blocked `Reliable` queue (§12.6) stalls this task and not the forwarder (§13.12 item 15).
- **Keep and Unsub.** When a session is installed the node sends one `Keep` for it at once (the gate above waits for it); the maintenance pass sends one every 10 s for each session it holds. When a session ends, is replaced or is removed, and when the last `Items` that takes it is dropped, the node sends one `Unsub` and no `Keep` follows. The last case ends the session as `Left` and **drops the channel's receiving state at once**: nobody is told (an `Items` made later has not seen the session it would be told of, so it gets no `LiveEnded(Left)`), and a later `get` over the same sender needs a new ask, which says `ASK_NEW` (§3.1) and makes a new route. An `UP` the connection had no room for is tried again at the next pass. `UP` frames go as datagrams.
- **Ask against release.** An ask whose answer arrives after a release of its (space, mode) installs no session and is told `Superseded` (§3.4): the route its Data laid is given up by one best-effort `Unsub` when no other ask of the channel is in flight and no session holds it, and the next ask is new.
- **`NoPath`.** A session that offers a stream and has no `HELLO` 2 s after it was installed (`NO_PATH_AFTER`), that an `Items` wants, tells that `Items` `LiveEnded(NoPath { why })`, once. The text says that no frame of the sender's channel reached this device in 2 s and gives the two causes the device cannot tell apart, each with its remedy: a forwarder between the two does not carry channel frames (update it), or this device's first `Keep` or the session was lost or held up on the way, so the sender dropped its first frame (ask again; §13.12 item 27). It does not say which hop. `LiveEnd::next()` is `FixLocal` for it (and `RetryLater` for an `Ended`). The causes are a forwarder that predates the label (§14.3), an install a hop refused (that hop's `side/list` counts and its log says why), a hop beyond the sender's own forwarder with no stream (§14.9), a sender that sends nothing, and a first `Keep` lost or a session held longer than `ROUTE_WAIT` on a lossy or slow network. A session that offers no stream (the first hop toward this device has none, §14.9) is sent no `HELLO`: nothing is waited for, and it is never told `NoPath`.
- **The bar.** `ConnectionBar` over `Connection::side_quarantine` is attached by `attach_forwarder`; a node with another `IngressBar` (`attach_bar`) bars through that. Without one a node still alerts and bars nothing.

### 14.11 Management and counters

`/localhost/nfd/side/list` and `/localhost/nfd/side/quarantine` (`ndn-mgmt` `modules/side.rs`; module `SIDE`, verbs `LIST` and `QUARANTINE` in `ndn-mgmt-wire`). As every ndn-rs module that is not an NFD one, each requires a **signed** command Interest.

- **`side/list`** is read-only and answers status text: a line of counters (`routes`, `sinks`, `frames_in`, `bytes_in`, `frames_out`, `bytes_out`), the drops by reason (`unrouted`, `wrong_source`, `malformed`, `class_unsupported`, `quota`, `quarantined`, `sink_full`, `sink_error`), the `UP` counters (`keeps`, `keeps_forwarded`, `unsubs`, `sinks_lapsed`), the refused installs by reason (§14.2), one line per route (the id in hex, the source face, each sink with the time left before it lapses, frames, octets, age) and one per barred face (the face, the time left). It is text, not a TLV dataset.
- **`side/quarantine`** takes `FaceId` (required: it does not default to the requesting face) and, optionally, `ExpirationPeriod` in **milliseconds**. Without it the bar is the face's next one by its history (60 s, doubling, §14.7); a call while a bar is live changes nothing and names what is left of it; with a value, that long, **at most 1 h** (a longer value is clamped and the answer names the length applied); `0` lifts the bar. The answer says `face barred` or `bar lifted` and names the length applied in `ExpirationPeriod`. It refuses with status 400 and a sentence when `FaceId` is missing or names no face on the forwarder (a lift is not refused), answers 404 to any other verb of the module, and answers **403 over `/localhop`** whoever signed it: `/localhop/nfd` is a neighbour's route registration (`rib/register`, `rib/unregister`) and nothing else, so a key the localhop anchors accept cannot bar a link or read the routes ([mgmt-trust.md](mgmt-trust.md), Side routes). The commands are logged at `warn`.

The per-face counters `in_side_frames` and `in_side_bytes` are in the engine's face state; `status` does not show them. [mgmt-trust.md](mgmt-trust.md) lists the module among the management commands.

### 14.12 Threat notes for the side table

- **A relay forges or alters.** It holds no key. Any change fails the AEAD at the receiver (§11.8). What a relay can do is drop, delay or repeat frames: drops are counted at the relay, repeats fall to the replay window (§12.2).
- **A face that is not the route's source** sends a frame of the id: it is dropped before any sink (`wrong_source`), so it makes no copy. A face that is not a sink sends an `UP`: dropped. Neither changes any entry.
- **Flooding.** A channel frame costs the reader one comparison, a header parse and a map read, and never a pipeline pass. Unknown ids, barred faces and malformed frames cost no more. A frame from the source of a route costs a fan-out; what bounds it is the sinks (at most 64 a route), the per-face rate on radio faces and the link's own limits ([ndn-link.md](ndn-link.md) §9 item 9).
- **Table exhaustion.** A route needs a PIT-matched Data, so a face cannot make itself a sink without having asked. The table is bounded in all, per source face, per sink face and per route (§14.2), and a sink lapses in its TTL (30 s as the heap asks, 300 s at most) unless it is kept. A member that opens sessions is bounded by the sender's 64 channels and 256 receivers a channel (§6). One face that reaches its own limit loses its own routes and no other face's; the 4,096 of the table are shared.
- **Amplification.** One frame in is one frame per sink, at most 64 a route, and a sink exists only if its face asked and keeps asking. One `UP` in is at most one `UP` out. The frame is not copied per sink, only handed to each.
- **A route squatter.** A frame of an id from a face that is not the route's source is dropped; a second Data for an id routed from another source is refused (`SourceMismatch`). The label itself is a claim of the next hop (§14.3).
- **A removed member that keeps its sink.** It keeps sending `Keep` and is sent ciphertext: it holds the old key only until the re-key (§3.6) and the forwarder judges no membership. Its sink costs the forwarder one fan-out per frame, within the limits above.
- **Barring an honest relay.** The bar is made by a receiver's node on the face the contradicted frame **arrived on at that node's forwarder**: the link to the nearest hop upstream (§14.7). A member (a key holder) can inject frames only through a face that is the source of the route at its own forwarder, as any hop can, and a frame goes on from hop to hop with nothing added. So if the member's device is that nearest hop, its own link is barred; if it is further upstream and the hop between is honest, **the honest relay's link is barred** at the receivers' forwarders, because nothing carries attribution upstream. What the bar costs the relay: the channel frames it sends to that forwarder (of every channel) are dropped for 60 s, then 120 s and so on to an hour for each repeat, and routes with the relay as source are not installed; its NDN traffic is untouched and the other forwarders are not told. What the member needs for it: a frame a signed checkpoint contradicts, or a checkpoint that does not verify (§15.6), which a key holder can make at will. A conflict alone (§15.6) bars nobody. The evidence (§15.5) names the face; an operator lifts a bar with `side/quarantine` (length 0). The bar is a response to a **link**, not a verdict on a person.
- **Clocks.** No decision about who may send rests on a clock. TTLs, bars and the sweep are on the forwarder's **monotonic** engine clock: the table counts nanoseconds since it was made (`Runtime::now`, an `Instant`, never `unix_nanos`), so a step of the host's wall clock (NTP, a VM that resumed, an operator setting the date) neither lapses every sink nor lifts every bar; a step of +301 s changes nothing, time that passes still lapses a sink. The table's stamps are read as ages (the idle reaper compares the table's idle time, not a stamp of the other clock). They decide how long a route or a bar lives.

## 15. Checkpoints

A frame that opens under a channel's key was sealed by **a holder** of the key (§11.8). A checkpoint is how a receiver learns which of the frames it accepted the **sender** sealed: the sender signs, with its device key, a list of the hashes of the frames it sent, and a receiver compares the list with the frames it accepted. This section says what the record is (§15.2), what the sender writes and when (§15.3), what the receiver keeps and does (§15.4 to §15.8), the window in which a forgery can be delivered (§15.9), the bounds (§15.10), what checkpoints do and do not do (§15.11), the vectors (§15.12) and the threat notes (§15.13).

Implementation: `ndn-heap` `chan`: `checkpoint.rs` (the record, its signature and its vectors), `ring.rs` (the sender's frames and `frame_hash`), `tx.rs` and `queues.rs` (the sender's loop), `verify.rs` (the receiver's memory and its judgement), `rx.rs` (what a verified, mismatched or bad checkpoint does), `evidence.rs`, `config.rs`, `bar.rs`.

### 15.1 What a checkpoint is for

**Checkpoints detect; they do not prevent.** Between two checkpoints a key holder that relays or injects frames can alter or invent frames under the sender's key, and a receiver acts on them (`Trust::Prompt`) before the next checkpoint shows it. What a checkpoint buys:

- A forgery by a **non-holder** (a relay, a stranger, a removed member after its re-key) is refused at once by the AEAD (§11.8).
- A forgery by a **holder** is delivered to a `Prompt` receiver for at most the stated window (§15.9) and is then **exposed** by a signature the holder cannot make, with evidence against the link it came over (§15.5).
- `Trust::Verified` (§15.8) delivers a frame only once a checkpoint lists it, so it **prevents** delivery of a holder's forgery, at a stated latency.
- Silence is not trust (§15.7): a relay that drops the checkpoints cannot keep unverified frames flowing.

Ephemeral data only: kept data stays signed per entry.

### 15.2 The record

A `CHECKPOINT` frame (§11.5) is on the stream, sealed under the channel key with `count` 0, and takes one sequence. Its plaintext is the record, then any padding of §11.3:

```
lo (varint) | hi (varint)             the sequences it covers: [lo, hi)
n (varint)                            the frames listed, at most 4,096
n × ( seq0 delta (varint) | h (16) )  the frames sent with lo <= seq0 < hi, in order of seq0
signature (64)                        Ed25519 by the sender's device key
```

- **Varints** are the QUIC variable-length integer (§11.4). A writer uses the shortest form and a reader **refuses** a longer one, so that the digest below is the one the sender signed.
- **The list.** The first `seq0 delta` counts from `lo`, each later one from the entry before it, so the entries rise. A delta of 0 after the first lists a `seq0` twice, which no sender does. Each entry is `seq0` and the 16-octet hash of the frame.
- **The hash** `h` is the first 16 octets of `H(the frame's octets as they went on the wire: header, ciphertext and tag)`, `H` being SHA-256 for a frame of at most 2,048 octets and BLAKE3 above (the length selects it: nothing is negotiated). A receiver hashes the octets as they came. It is a hash, and not the AEAD tag, because a holder can forge a tag for any content and cannot find a second preimage of a frame the sender sent.
- **The signature** is made with the **device key the session Data was signed with**, over the message below.

**The signed message** is these octets, in this order, 92 in all:

| Field | Octets |
|---|---|
| the label `ndn-channel/checkpoint/1` | 24 |
| the channel id, big-endian | 8 |
| the key epoch, the whole of it, big-endian (the header carries only its low octet) | 4 |
| `lo`, big-endian | 8 |
| `hi`, big-endian | 8 |
| `n`, big-endian | 8 |
| SHA-256 of the list's octets exactly as written (the `n` pairs: for `n` of 0, SHA-256 of nothing) | 32 |

The channel id and the key epoch bind a checkpoint to its channel and its key: sealed again into another channel, or into the same channel under another epoch, it fails its signature (and under another key it fails to open). The range is signed too.

**What a reader refuses.** A reader drops a record (counted `malformed`) that ends inside a field, has a varint not in its shortest form, has `hi` below `lo`, lists more than 4,096 frames, lists a `seq0` outside `[lo, hi)`, or has anything after the signature but padding. A writer refuses to write a list that does not rise or lists a frame outside the range.

**The range is what the sender vouches is complete:** a frame with `lo <= seq0 < hi` that a receiver accepted and the list does not hold, or holds with another hash, was not sent by the sender. A frame the sender sent after the record was built has `seq0 >= hi`.

### 15.3 The sender

- **Who signs.** The channel's sender signs with the device key the session Data is signed with, which the receiver holds a certificate chain for. Only an Ed25519 key signs checkpoints. A sender whose key is of another kind sends none, and so does a sender whose carrier has no stream, since a checkpoint rides the stream. Such a channel announces `S_CKPT_MS` of 0 in its session (§7) and its receivers wait for nothing (§15.7).
- **What it lists.** The sender records every frame it hands to a carrier, on either lane, **except a `CHECKPOINT` frame** (§13.2 item 9): the data frames and the `CONTROL` frames. A checkpoint covers `[lo, hi)`. `hi` is the **watermark**: below the first sequence still waiting in any queue (a message that waits, or is in a frame being written, may still be sent as a frame whose `seq0` is that low, and a later checkpoint is to judge that frame), below the next sequence to be taken, and never below the last checkpoint's `hi`. `lo` is the last checkpoint's `hi`, raised past anything the ring forgot, so a frame the sender no longer holds is never a mismatch. The checkpoint lists the frames in the ring with `lo <= seq0 < hi` and takes them out of the ring; a frame at `seq0 >= hi` stays for the next. The ranges of successive checkpoints tile the sequences, and a frame is listed by at most one.
- **The schedule.** The first frame sent since the last checkpoint arms a timer of one **period** (`ChannelConfig::checkpoint`, §15.9). When it fires, a checkpoint is queued on the stream's queue if frames were sent and none is waiting (one that waits lists everything sent by the time it is written). A checkpoint takes the next sequence when it is queued and goes through the stream in the order of the sequences, so it follows every frame sent on the stream before it. What it lists is decided when it is written, and the frames are hashed and signed with no lock held. That is **at most one signature a period and a channel**, whatever the frame rate, and none while nothing was sent.
- **After an `END`** the sender queues one more checkpoint at once, which lists the frames before it and the `END` itself (§15.6).
- **While idle**, with a receiver held and a stream, the node's maintenance pass queues one **empty** checkpoint (a range and a signature, no frame) when 5 s have passed since the last. It is a liveness signal; no receiver waits for it.
- **A checkpoint that cannot be signed or sealed** leaves its frames in the ring for the next (counted `checkpoint_failed`, never expected).
- **The ring** is bounded (§13.2 item 9, §15.10); frames it forgot are counted `unchecked`.

### 15.4 The receiver

A receiver whose session announces a period (`S_CKPT_MS` above 0, held to 1 ms to 2 s) keeps, **per channel**, one **slot** for each `seq0` it accepted a frame at. A slot holds the frame's octets **as they came** (a copy: the AEAD opens the original in place) until a checkpoint judges it, and then only the frame's hash and the signed checkpoint frame that vouched for it. At most 4,096 slots (the replay window's size), 2 MiB of octets a channel, and the channel's **part of the node's 8 MiB** (one budget with the frames held for a lane, §15.7, §15.8): the 8 MiB is divided equally among the node's channels that checkpoint, each part at most 2 MiB and at least 64 KiB, and a channel that holds more than its part (the part shrinks when a channel is added) gives the excess back at the node's next maintenance pass (250 ms). A peer that holds the keys of many channels therefore holds many parts and cannot take what the other channels need (§13.12 item 23). Past a bound the receiver forgets frames **of the same channel**, the **farthest** first: the lowest `seq0` of the highest run of sequences (a run is broken by a gap of more than the replay window). The frames of a sender are one run, so this is the oldest of them; a frame a key holder sealed far above them is a run of its own and goes first, and when the channel is full a frame more than the replay window above everything held is refused instead of pushing the sender's frames out. Each frame forgotten or refused is **counted** `unchecked`: a frame nobody judges is not a mismatch. A frame that cannot be kept because the node's bytes are taken by channels that hold more than their part, while this channel is within its own, is counted `unchecked` and `budget_starved` too and is not judged; the node says so in a `warn` log once in 30 s.

**Verification is bounded before it is paid.** After the AEAD and before the record is read, a checkpoint takes a token from its channel's bucket and one from the node's. A channel's bucket holds 64 and fills at two a period of the sender's (at least four a second, so a slow sender is not starved); the node's holds 256 and fills at 4,000 a second. The clock is the node's monotonic clock and is used for the rate only. A checkpoint that finds a bucket empty is **dropped unread** and counted `checkpoints_over_rate`: it is neither a forgery nor a bad checkpoint, nothing is concluded about it, frames waiting for one stay held, and the silence rule applies (§15.7). A genuine sender sends one checkpoint a period and never meets the bound (§13.12 item 15).

A `CHECKPOINT` frame is taken like any frame (§12.1) up to the AEAD; then:

1. The record is read (§15.2); one that does not parse is dropped, `malformed`.
2. It is verified under the sender's **Ed25519 key**: the key that signed the session Data, which the receiver found in a certificate it vouches for when it took the sender's answer (set at every install and renewal). If no certificate of it was found the checkpoint cannot be verified and says nothing against the sender: it is counted `unverifiable_checkpoints` and the silence rule applies (§15.7). A signature that does not verify is a **bad checkpoint** (§15.6).
3. A verified checkpoint **judges** the slots. A frame below `lo` that was never judged is forgotten, counted `unchecked` (ranges only rise, so no checkpoint will cover it). Each frame with `lo <= seq0 < hi` is **settled** if the list holds its hash at its `seq0`, and is a **mismatch** if not. A listed frame the receiver does not hold is ignored: **loss is not forgery**. A frame above `hi` is not judged and keeps the silence clock (§15.7).
4. It then releases what lanes were held for it (§15.7, §15.8).

The sender's key must still stand: the generation check (§12.3) runs before every frame, a checkpoint's included, and a sender that no longer stands ends the session `NotMember`.

### 15.5 A mismatch

A mismatch is **evidence**. Everything below happens at once, for each frame the checkpoint contradicts:

1. **Evidence.** `ChannelEvidence` is made and kept: the last 64 (`EVIDENCE_KEPT`) and at most 4 MiB of frame and proof octets between them (`EVIDENCE_OCTETS`, the oldest going first), in memory, readable with `NodeHandle::channel_evidence()` (oldest first). It has a `kind` (`Mismatch`, `Conflict` or `BadCheckpoint`), the channel id, the sender's device, the key epoch, the frame's `seq0`, **the frame octets the node accepted**, the face it came over (`ingress`), **the signed checkpoint frame** that contradicts it (`proof`: for a `Conflict`, the frame accepted first; for a `BadCheckpoint`, empty) and the node's clock. A frame or a proof over 128 KiB (`EVIDENCE_PART_KEPT`) is not kept: the evidence holds its length and its SHA-256 (`frame_digest`, `proof_digest`) in its place, because a stream frame is up to 1 MiB and 64 of them with their proofs would hold tens of MiB of the node for a peer's choosing (§13.12 item 25). A third party that is given the channel key can open both frames and check the signature against the sender's key. `encode()` writes it (version 2; every integer big-endian; a varint is the QUIC one):

  ```
  version (1, = 2) | kind (1: 1 Mismatch, 2 Conflict, 3 BadCheckpoint)
  channel id (8) | key epoch (4) | seq0 (8) | ingress face (8) | when, ms (8)
  sender: length (varint) | its Name as a complete Name TLV
  frame: length (varint, of the frame as it was) | kept (1: 1 octets follow, 0 SHA-256 follows) | the octets, or the 32-octet SHA-256 of them
  proof: the same
  ```

  Version 1 (every part whole, no `kept` octet) is no longer written or read.
2. **`GetNotice::Retracted { writer, from, to }`** is told to every `Prompt` `Items` that took the channel: the items it was given with a `seq` from `from` to `to` (inclusive) are not the writer's. Delivered items stay delivered; the stream takes nothing back, and the application discards. For a data frame `from` and `to` are its sequences. If the contradicted frame **wrote the name table** (a `BIND`, an `UNBIND`, or a data frame with a message that carries its own name) or is another `CONTROL` frame, `to` is the highest sequence accepted at that time, because everything after it may have been read under a table or a state a holder wrote. Only the frame accepted **first** at its sequence (the one that was delivered) is retracted; a second frame was only an event.
3. **The link is barred** (§14.7): asked once for each face that carried a contradicted frame, in one checkpoint, through the node's `IngressBar`. With none attached nothing is barred and the node says so (`NOT barred`, §13.12 item 24).
4. **`Alert::ChannelForgery { writer, channel, key_epoch, seq, via }`** arrives as a `Change::Alert` and as a `warn` log; `via` is the face, which was asked to be barred (the alert does not say the bar was applied). The host maps it to the link's key and device with `Links::report()` (ndn-ext) and decides what to do about a person's device; `Node::suspect` stays the only reporting call, applies to a device key the host can name, and a link-level offender gets the bar and not a suspicion.
5. **A rebinding frame resets the names.** If the contradicted frame wrote the name table, the receiver puts the table back to the session's, counts `resets`, and asks the sender for the session again (at most once a second per sender, as §12.3).

A mismatch does not end the session. A frame the checkpoint contradicts **never reaches a `Trust::Verified` receiver** (§15.8), and a forged frame that is the same as a withheld genuine one is **not** redelivered when the genuine one arrives (the sequence is spent).

### 15.6 Conflicts, replays, `END` and a bad checkpoint

- **A conflict.** The replay window drops a second frame at a `seq0` it has seen (§12.2), which would hide a holder's second frame. So the receiver answers for a frame at a seen sequence: one with the same octets as an accepted frame (or hashing to a settled one) is a copy and is dropped for a comparison; one that **differs** gets **one AEAD attempt**, at most **3 a sequence**, so garbage costs no more, and, if it opens, is a **conflict**. The frame accepted first stays the one delivered; the second is **an event, not a delivery** (`Delivery::Conflict`, counted `conflicts`), and evidence of kind `Conflict` is made at once. **Nobody is barred and no alert is raised**: either face may be the honest one, and the checkpoint that covers the sequence says which frame the sender did not send (the other one is then a mismatch, §15.5). Both frames stay in the slot for that, at most 64 second frames a channel.
- **A second frame at a sequence a checkpoint already listed** is a mismatch at once: the first frame was settled by a verified checkpoint, so this one is provably not the sender's. Its face is barred and the alert raised.
- **A replayed checkpoint** changes nothing. It is bound to its channel id, key epoch and range; a record sealed again at a new sequence verifies, covers frames already judged and so judges nothing, and **lifts no hold** (§15.7): the hold lifts only when nothing accepted waits past `unchecked_max`. A record re-sealed for another channel, another key epoch or another range fails its signature. A checkpoint whose own sequence was already seen is read as a second frame and judged as usual, but does not count in the lanes' gap rule.
- **`END` is held until a checkpoint lists it.** Any holder can seal an `END` (§13.11), so on a channel that announces checkpoints an `END` the receiver accepts ends nothing by itself: it is held, and the session ends `Closed` only when a verified checkpoint **lists** it. The sender queues one right after its `END` (§15.3). A forged `END` is not listed by the sender's checkpoint: it is a mismatch, the hold is forgotten, and the session goes on. A session that announces no checkpoints ends at once, as before.
- **A bad checkpoint.** A checkpoint that opened under the channel key and does not verify under the sender's key was made by a holder. The receiver makes evidence of kind `BadCheckpoint`, **asks for the bar of the face it came over**, raises `Alert::ChannelCheckpoint { writer, channel, key_epoch, via }` and **ends the session** with `EndReason::BadCheckpoint` (`LiveEnded`), which says that a holder of the key made it, whether a bar was asked of the face (with no `IngressBar` attached it says the face is not barred and what to do), and that the receiver should ask the sender again once that link is dealt with. This **fails closed**: the session's frames are not to be trusted, and a holder can end a session this way at will (§13.12 item 4).

### 15.7 Silence is not trust

A receiver's **silence clock** starts when a frame is accepted and none is waiting for a verified checkpoint, and each verified checkpoint moves it to the oldest frame still waiting above its range (none: it stops). `unchecked_max` is `max(4 × period, 100 ms)`.

- **Past `unchecked_max`** a `Prompt` receiver **holds** what follows: frames accepted from then on are not delivered, counted `held`, until a verified checkpoint lifts the hold. They are then delivered in the order they were accepted, except any the checkpoint contradicts, which are dropped (and are evidence). The held frames are bounded: 4,096 frames and 2 MiB a channel, and the node's 8 MiB in all; past a bound the oldest is dropped, counted `held_dropped`, and the `Items` are told a gap (`Lagged`).
- **At 3 s** with no checkpoint that verifies, the session **ends** with `EndReason::Unverifiable` (`LiveEnded`), counted `unverifiable`; the frames still held are told as missed first. The reason says to ask the sender again and why: a link that drops the sender's stream, where checkpoints ride, a sender that stopped signing, or a holder racing the sender.
- The clock is read at every accepted frame and by the node's maintenance pass (every 250 ms), so a channel that goes quiet is ended too.
- **A checkpoint the receiver cannot verify** (§15.4 step 2) counts for nothing: the rule applies.
- **A channel that announces no checkpoints** (no stream, §15.3) has no clock: nothing is waited for, nothing exposes a forgery, and what is delivered is authenticated only as a holder's. `ChannelInfo::checkpoint` is `None` and so is its `detection_window`.
- **A sender that is idle** gives a receiver nothing to wait for: a receiver with nothing unchecked has no clock, and the idle checkpoint (§15.3) is liveness, not a requirement.

### 15.8 `Trust::Verified`

`GetOptions::trust` is `Trust::Prompt` (the default: §15.1) or `Trust::Verified`. A `Verified` `Items` has a **lane** of its own at the receiver, with its own name table and its own hold queue; a `Prompt` and a `Verified` `Items` of one space share the channel and the slots.

- **What it delivers.** A frame only after a verified checkpoint **lists it with the same hash**, in the order the frames were accepted. A frame the checkpoint does not list is dropped and is evidence (§15.5); it never reaches the lane. No forgery of a holder is ever delivered. The cost is up to one checkpoint period of latency (W of §15.9), so it cannot meet the latency target of a presence channel: use it where a forged cursor is worse than a late one.
- **When a checkpoint is lost.** A checkpoint covers only its own range, so a frame whose checkpoint was lost is never listed. It is **dropped, counted** (`held_dropped`, and `unchecked` when a later checkpoint's range passes it) and told as `Lagged` as soon as a later checkpoint's `lo` passes it, and after 3 s at the latest; it is **never** delivered unverified. If no checkpoint verifies within 3 s the session ends `Unverifiable` (§15.7), as for `Prompt`.
- **A channel with no checkpoints** (§15.3) is never delivered to a `Verified` `Items`: each is told once `LiveEnded` with `EndReason::Unverifiable`, whose text says to ask for `Trust::Prompt` or to use a path with a stream.

### 15.9 The stated window

`W = P + d + ε`: the checkpoint **period** `P`, the one-way delay `d` of the stream to this receiver, and verification queueing `ε` of 1 ms (`VERIFY_EPSILON`: one Ed25519 verification, 41 µs, plus scheduling). At the default period and a 1 ms path, **22 ms**.

- **`P`** is `ChannelConfig::checkpoint`, set by `Config::channel` (default `CHECKPOINT_DEFAULT`, **20 ms**), held to **1 ms to 2 s** (`CHECKPOINT_MIN`, `CHECKPOINT_MAX`: a value outside is taken as the nearest bound). A sender signs at most `1 / P` times a second a channel: 50 at the default, 1,000 at 1 ms. It is carried in each session (`S_CKPT_MS`, in ms), which is how a receiver learns it, and a receiver holds it to 1 ms to 2 s too.
- **`ChannelConfig::detection_window(delay)`** and **`ChannelInfo::detection_window(delay)`** compute `W` (the second for the period the sender announced, `None` for a channel with no checkpoints); the `Items` documentation states it.
- **What it says.** Inside the window an emission is authenticated as "a holder of the channel key's"; after a covering checkpoint verified it is authenticated as the sender's. A frame a holder forged is delivered to a `Prompt` receiver for at most `W` before the next checkpoint that covers it exposes it, **provided** the checkpoint arrives and the frame is not accepted after the checkpoint that covers it (§15.11).
- **The period is a liveness bound, never a correctness one.** A checkpoint that is late or lost leaves frames unchecked (held, for `Verified`) and never makes a frame look forged.
- **Tested** on a paused clock with a real sender at periods of 20 ms, 100 ms and 1 ms: a forgery is not exposed before one period has passed and is exposed within `W`.

### 15.10 Limits and counters

| What | Limit | Over it |
|---|---|---|
| Checkpoint period | 20 ms by default; 1 ms to 2 s | held to the nearest bound |
| Signatures a sender makes | at most one a period for each channel, and none while nothing was sent | |
| Idle checkpoint | one empty one every 5 s while a receiver holds an idle channel with a stream | |
| Frames one checkpoint lists | 4,096 | the ring forgot the older ones; `lo` rises past them |
| The sender's ring | 4,096 frames and 4 MiB a channel (§13.2 item 9) | the oldest is forgotten and counted `unchecked` |
| The receiver's slots | 4,096 frames, 2 MiB a channel, the channel's equal part of the node's 8 MiB (at least 64 KiB) | the farthest frame is forgotten and counted `unchecked`; a far frame is refused; `budget_starved` |
| Checkpoints verified | a channel: a burst of 64, then two a period (at least four a second); the node: a burst of 256, then 4,000 a second | dropped unread, `checkpoints_over_rate` |
| Second frames kept for a conflict | 64 a channel | not kept (still evidence) |
| AEAD attempts at a seen sequence | 3 a sequence | compared only |
| Evidence kept | the last 64 and 4 MiB of frame and proof octets; a part over 128 KiB is a hash | the oldest goes |
| Frames held for a lane | 4,096 and 2 MiB a channel, within the channel's part of the node's 8 MiB | the oldest dropped, `held_dropped`, `Lagged`; `budget_starved` when the node's bytes are taken |
| Silence | hold after `max(4 × period, 100 ms)`; end at 3 s | `held`; `Unverifiable` |
| Frames a `Verified` lane waits for a listing | 3 s | dropped, `Lagged` |

The receiver's counters in `Stats.rx` (§12.8) gain `checkpoints_verified`, `checkpoints_over_rate`, `unverifiable_checkpoints`, `bad_checkpoints`, `mismatches`, `conflicts`, `unchecked`, `budget_starved`, `held`, `held_dropped`, `resets` and `unverifiable`. The sender's counters in `Stats.tx` gain `checkpoints`, `empty_checkpoints`, `checkpoint_failed` and `unchecked`.

### 15.11 What checkpoints do not do, and what they close

**They do not:** prove delivery, order or completeness (loss is not forgery; `Reliable` and `Window` show a gap by the gap rule, §12.6, and a `Latest` gap is invisible by design); catch a forged frame no receiver accepted; attribute a forgery to a person (only to a **key holder** and to the **link** it came over); stop a forged frame being delivered inside the window; make a path without a stream verifiable (§15.3); or hide a sender that equivocates, which is a holder too.

**What is not judged.**

- **A frame accepted after the checkpoint that covers it was verified** is never judged: the slot is made when the frame is accepted, a checkpoint judges the slots it finds, and the next checkpoint's `lo` is past it (counted `unchecked`). So a datagram that arrives after the stream's checkpoint, or a holder that places its own frame at a sequence the sender used and this receiver has not accepted yet, after the covering checkpoint, is not exposed.
- **A frame in the range of a checkpoint that never arrived** (a relay dropped a stream frame, §14.4) is never judged either.
- **A frame forged far ahead of the sender's sequence** is judged only when the sender's range reaches its `seq0`. Until then it is above every range: it can mute that name in `Latest` and advance the replay window (within the 2^24 bound of §12.2), and the silence rule holds delivery after `max(4 × period, 100 ms)` and ends the session at 3 s.
- **A holder can end a session** with a checkpoint that does not verify (§15.6), or on a channel that is idle by making a receiver accept a frame no checkpoint reaches within 3 s (§15.7); either way the receiver asks again.

**What this closes of the residuals §13.12 listed before stages 4 and 5** (the list as it was: 1 forge, 2 re-seal, 3 end the session, 4 truncate and withhold, 5 rename, 6 no ingress binding, 14 stage 4 reminders; the rest are §13.12 now):

| Was | Closed | What remains (§13.12) |
|---|---|---|
| Forge | **Detected**: a frame the sender did not seal is a mismatch with evidence, a bar on its link, an alert and a `Retracted`; never delivered to `Verified` | delivery to `Prompt` inside `W` (item 1); frames no checkpoint judges (item 2); attribution to a link and not a person (item 6); no checkpoints on a path with no stream (item 16) |
| Re-seal old content | **Detected** as a mismatch (the sender's checkpoint does not list it) | delivery inside `W` (item 1); a far-ahead sequence (item 3) |
| End the session | A forged `END` ends nothing: it is held until a checkpoint lists it, and is a mismatch if none does | a holder can end a session by a bad checkpoint, or by the silence rule (item 4) |
| Truncate and withhold | A holder that **replaces** a frame with its own at the same `seq0` is a mismatch; withheld frames of `Reliable` and `Window` show as a gap, and a lost frame is not forgery | pure withholding is not prevented or attributed, and is invisible in `Latest` (item 5) |
| Rename | A contradicted `BIND`, `UNBIND` or self-naming message retracts everything accepted since, resets the table and asks the sender again | a rename is read until the checkpoint exposes it (item 1) |
| No ingress binding | The forwarder drops a frame from any face but the route's source (§14.4) and the node is given the forwarder's own face id as the ingress | `deliver_frame` still takes a number the host chooses; the ingress is the nearest hop's face (item 7) |
| Stage 4 reminders | The engine's reader never calls `deliver_frame`; the source face is checked by the table and the app face's inbox is bounded and counts its drops | one task reads the inbox of every channel (item 15) |

### 15.12 Vectors

Hex, as the implementation writes them (asserted by `chan/checkpoint_tests.rs`). The record was computed independently with Python and `openssl pkeyutl -sign -rawin` (Ed25519) from the layout of §15.2: a wrong label, a missing field, a wrong byte order or a different list digest fails there.

Inputs: the device key is the Ed25519 seed of 32 octets of `42`, whose public key is `2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12`; channel id `0102030405060708`; key epoch 258 (`0x0102`, so the header carries `02`); `lo` 5, `hi` 40; three entries, at `seq0` 5, 9 and 30, whose hashes are the runs of 16 octets `10 11 … 1f`, `20 21 … 2f` and `30 31 … 3f` (stand-ins: not hashes of frames).

**The record,** 118 octets: `lo`, `hi` and `n` are `05 28 03`; then the entries `00` + `101112…1f`, `04` + `202122…2f` (delta 4 from 5) and `15` + `303132…3f` (delta 21 from 9); then the 64-octet signature.

```
05280300101112131415161718191a1b1c1d1e1f04202122232425262728292a2b2c2d2e2f15303132333435363738393a3b3c3d3e3f1e4039039753d79a846efebc1432d95ca2e74c5144a0cfa066f4849aef5fa2f5ff672d55a3ecd789bd39d1fbefc80b8da11741956099501db2eefcc459776506
```

**The `CHECKPOINT` frame** of that record, 154 octets: AES-256-GCM, `K` the octets `00 01 02 … 1f`, class stream, kind `CHECKPOINT`, `count` 0, `seq0` `1122334455667788`, the key epoch and channel id above (so the frame key and the nonce are those of §11.7). It opens, in `ring` and in RustCrypto, to the record above.

```
00310102030405060708021122334455667788007f587c27c5dce02dcb3fd9b8344ca7fcef4f2aeec00cf775253a142c60d2f6041ecc423b0010cb806ef7bee93e3424843e6f4bdba790fd51c5e356718e6ea52a48b62e32ef535e8dca5142d0b55f30765ec9caceefe196969c401d5b9ba2d67f908216f4ba7c0147f0834f65b98700fe03b5927b24adc0d747f104795a4c82527091e4ed14e2
```

### 15.13 Threat notes for checkpoints

- **A member forges another sender's frames.** It holds `K` (it asked) and can seal, and it can inject into links it is on. It is exposed by the next checkpoint that covers the frame (§15.5), with evidence against the link; `Trust::Verified` never delivers it. A member that **withholds** (drops the genuine frame and delivers its own at the same `seq0`) leaves the receiver with a frame the checkpoint contradicts, which is a mismatch too. What it cannot do is make a checkpoint for the sender: that takes the sender's device key.
- **A stolen channel key.** The thief reads and forges under the key until the next re-key (the session's lifetime, 1 h by default, or the first removal); its forgeries fall to the checkpoints, and it cannot sign a checkpoint or open a session. It can end a session with a bad checkpoint (§15.6), which fails closed.
- **A stolen device key** signs sessions and checkpoints as the device until it is revoked or its person is removed; revocation and removal end its sessions on the generation move (§12.3). This is the exposure a device key always has ([heap.md](heap.md) §9.9).
- **Flooding.** A frame that is oversized, malformed, of an unknown channel, a replay, of a face that is not the route's source or from a barred face costs a comparison or a lookup and no cryptography. A checkpoint from a **non-holder** fails the AEAD first. One from a holder costs an AEAD attempt and, if it opens, one Ed25519 verification (about 41 µs); the first that does not verify ends the session and bars the face, and one that verifies (an old record sealed again) costs a verification and changes nothing (§15.6). The sender signs at most once a period for each channel, whatever the frame rate.
- **Replay.** A replayed frame is dropped by the replay window; a replayed checkpoint is bound to its channel, key epoch and range (§15.6); a session Data replayed to a receiver fails its fresh ask (§10).
- **A removed member as a relay** between two others holds the old key until the re-key. For `REKEY_GRACE` (5 s) after a receiver first sees the new epoch, and for the window of §15.9, it can forge under the old key; afterwards its frames fail the AEAD (§3.6).
- **Memory.** What a receiver keeps for checkpoints is bounded (§15.4: 4,096 slots, 2 MiB a channel, the channel's equal part of the node's 8 MiB) and counted when forgotten or refused; what it holds for a lane is bounded too (§15.7); evidence is bounded at 64 pieces and 4 MiB (§15.5); and the cost of verifying checkpoints is bounded per channel and per node before the signature check (§15.4).
- **Clocks.** No decision about membership, authenticity or replay rests on a clock. The period, the silence clock and the 3 s are counted on the receiver's monotonic clock and decide only how long a frame is waited for.

## 16. Measured

Informative. This section records what was measured of the stage-3 implementation (§16.1 to §16.6) and of stages 4 and 5 (§16.7), how, what the figures leave out, and what was tried and removed. Nothing in it is normative. The design note (SHAPES-CHANNEL.md §18 and §19) holds the raw tables, the commits and the scripts.

### 16.1 Method

- **The rung.** `examples/chan_ping.rs` of `ndn-face-quic` runs `Heap::emit` (`Latest`) into `Heap::get` (`kept: false`) between two nodes (`/bob/phone` writes, `/carol/tablet` reads). The space and the channel are made by the signed setup of §3. The frames cross **one** QUIC link on loopback. The `Carrier` is an adapter over `LinkFace::forward_side` (the datagram lane), `send_side` (the stream lane) and `side_limits`. The two nodes share one forwarder, so the setup's Interests do not cross the link; the frames do.
- **Cores.** Pinned to four cores (`taskset -c 10-13`) of a shared 64-core AMD EPYC 7532 host, with two runtimes of one worker each: the sender's writer task and the QUIC driver share a worker.
- **Throughput.** 0.5 s of warm-up, then 3 s a size. Each figure is the median of 3 pairs run back to back and interleaved (a channel run, then the raw run, alternating the order). The raw rows are the QUIC datagram and stream rows of `carrier_bench` at the same `path_mtu_max`, with the socket buffer and the bounded GSO batch a link has. The count is what `Items` yields; the emitter rotates 256 paths.
- **Latency.** The half round trip of a 64-octet message: 14 pairs, each the p50 of 10,000 timed round trips after 1,000 warm-up ones, the outer 1 % dropped, against the raw QUIC datagram. *Cold* is the host as it is; *hot* adds four busy loops on other cores.
- **Per-message CPU.** Without a link: a carrier that records frames and releases one at a time; 64 octets, 14 messages to a frame, 2,000,000 messages, 3 runs; the sender is `Heap::emit` through the sealed frame on one thread, the receiver is `deliver_frame` and the take from `Items`, by `poll_next` or by `next_batch`.
- **`path_mtu_max`.** 9,000 (datagrams of 8,962 octets) and 1,452 (datagrams of 1,414), so a jumbo-frame path and an Ethernet path are both measured.
- **Load.** The tuned figures of §16.2 were taken at host load 5.1–6.2 (the host was shared), which put about ±5 µs of noise on single latency pairs.

### 16.2 After the stage-3 tuning

At `path_mtu_max` 9,000. The ratio is to the raw QUIC datagram row; the last column names the raw stream row where it was measured.

| size | channel, messages/s | × raw datagram | × raw stream |
|---|---|---|---|
| 8 B | 2.110 M | 0.17 | |
| 64 B | 1.837 M [1.829, 1.858] | 0.23 | |
| 128 B | 1.532 M | 0.23 | |
| 256 B | 1.263 M | 0.30 | |
| 512 B | 0.873 M | 0.43 | |
| 1 KiB | 570 k [554, 618] (raw datagram 1,271 k) | 0.449 | 0.80 (raw stream 713 k) |
| 8 KiB | 89 k [87, 93] (raw stream 148 k; raw datagram 180 k) | 0.49 | 0.60 |

At `path_mtu_max` 1,452: 8 B 1.853 M; 64 B 1.535 M; 1 KiB 302 k against a raw datagram 429 k (0.70); 8 KiB, which goes on the stream, 54.7 k messages/s (3.6 Gbit/s) over 256 rotating paths against a raw stream 66 k (0.83).

The 64-octet half round trip, at 9,000, medians of 14 pairs (the range of the pair ratios in brackets):

| | channel | raw datagram | channel ÷ raw |
|---|---|---|---|
| cold | 42.7 µs | 30.7 µs | 1.37 [0.78, 2.08] |
| hot | 46.1 µs | 37.7 µs | 1.24 [1.01, 1.45] |

Per message at 64 octets, 14 to a frame: the sender 469 ns (`next_batch`) and 477 ns (`poll_next`); the receiver 280 ns by `next_batch` and 333 ns by `poll_next`. The per-message budget the design set was 500 ns. At 64 octets nothing is allocated per message beyond the frame (asserted by `the_64_byte_latest_path_allocates_nothing_per_message_beyond_the_frame`, §13.2).

These figures are those of the tuning pass that ends at the design note's §18.6. Changes made after it (the one limit `STREAM_FRAME_GRANT`, the receiver keeping its last channel, the sender's one-lock idle decision, and the fixes of the security review: a message in a stream frame over 9,000 octets that is under half of it is copied out of the frame, the hold, the ring's exact-size frames, the setup's bounds) were **not** followed by a new full table; the one latency comparison made after the first three (24 interleaved pairs, for the receiver change) showed no detectable difference. The verdict of §16.6 therefore stands on these figures, and the optimisation pass (§16.6) starts with a fresh table.

### 16.3 Why the gaps remain

**Latency.** The channel's code runs cold once a message is alone on the link: the sender spends about 5 µs beyond quinn's `send_datagram` (the call the raw row makes too) and the receiver about 2.5 µs, against 1.4 µs a message when the same path runs hot in the per-message row. The 1.1× allowance is about 3 µs. The call back to the carrier and the wake of the `Items` consumer together are under 1.5 µs of the excess, and an isolated message asks for no call back (`BURST_GAP`, §13.8). The measured cause is the **cold footprint of the idle path**: the name table, the standing map, `Pending`, the ring and the lock are each touched by a lone message. Further measurements:

- The half round trip is **bimodal per process** on this host: the channel at 32–33 µs on good runs and 40–47 µs on bad ones, the raw datagram at 28.5–29.5 µs.
- With the sender's and the receiver's threads pinned to one core and the main thread to another the run is stable: 35.0 µs against 30.2 µs, a ratio of 1.16.
- A per-ping timer makes no difference: 39.9 µs against 40.3 µs.
- An earlier attribution of 4.5 µs "outside `Heap::emit`" does not exist: measured, it is 0.03 µs before and 0.06 µs after the receiver change, so it was cold-start cost of the measurement.

**Throughput.** From 128 octets up the writer thread carries two AEAD passes over every octet: the channel's seal of the frame (§11.2) and quinn's own encryption of the packet, on one worker that also runs quinn's driver. The raw row does only the second. Removing the channel's seal entirely in a scratch run (not shipped) gives the ceiling: the sender's frames a second rise from 82.5 k to 103 k at 1 KiB (+25 %) and from 91.5 k to 107–121 k at 8 KiB, which is about 0.61 times the raw datagram at 1 KiB and about 0.72–0.82 times the raw stream at 8 KiB. So the 0.9 targets at 1 KiB and 8 KiB cannot be met with two AEAD passes on one worker. At 64 octets the same scratch run reaches 1.95–1.98 M messages/s against 1.79–1.87 M with the seal in, so the 1.94 M compared against is reachable only barely even with a free seal.

### 16.4 What the tuning changed in the specified behaviour

1. **The stream frame limit (§13.8, §11.6).** At `path_mtu_max` 1,452, 8 KiB messages over 256 paths stalled: 0 messages in the window. The cause was a stream frame of 1,049,252 octets, built from 128 queued messages, over the 1,048,576 octets the face grants. The face refused it, the refusal was taken as a dead stream, and every later emission rebuilt and re-sealed a 1 MiB frame (AES-GCM was 60 % of the sender thread). `Carrier::stream_frame_max()` is the fix: the stream lane packs to the smaller of it and the channel's own limit, and a message whose frame fits no frame the stream takes is refused `TooLarge` at `emit`. After it the same row is 54.7 k messages/s. The limits are now one constant: `ndn_transport::side_header::STREAM_FRAME_GRANT` (1 MiB) is the face's stream-frame limit and the channel's stream-frame default, and the message default is derived from it (the grant less 1 KiB), because a message at the earlier default was refused at `emit` (`TooLarge`, size 1,048,624, max 1,048,576), which the test `a_message_of_the_default_limit_fits_a_frame_the_face_grants` caught.
2. **The ring hashes lazily (§13.2 item 9).** The checkpoint hash was a sixth of the writer thread at 1 KiB and 8 KiB (16–17 % of its samples). Recording a frame now keeps a reference and the hash is computed when the ring is drained. Interleaved before and after, 6 pairs: 64 B ×1.03, 1 KiB ×1.16 (506 k to 571 k), 8 KiB ×1.18 (74 k to 86 k).
3. **The receiver keeps its last channel.** A run of frames for one channel takes no session lookup. The saving is small and was not separable in latency: no detectable difference over 24 interleaved pairs.
4. **The idle write is one lock round.** An emitter that writes inline decides in the same lock round that commits its frame whether the lane is idle; the earlier path packed again and took a third lock. The per-frame message counter is one add. An isolated message asks for no call back (§13.8); that change had no measurable end-to-end effect (p50 median −0.5 µs over 20 interleaved pairs).

### 16.5 Tried and removed

**Authenticate-only for unsealed spaces.** The idea was to send the frames of an unsealed (public) space under a MAC and no encryption. It was measured and **dropped**: every frame in every space stays AEAD sealed (AES-256-GCM; ChaCha20-Poly1305 only where `ring` does not build or the CPU has no AES), and nothing of the work reached the wire, the codec or the sources. The reason is cost on the measuring host (AMD EPYC 7532: AES-NI and PCLMULQDQ, no VAES; `ring` 0.17): **no MAC beats `ring`'s AES-GCM seal above about 150 octets**, because the seal is one stitched AES-NI and PCLMUL kernel and every MAC has to process the whole frame as additional data, which `ring` does not stitch. ns a frame, medians:

| octets | AES-256-GCM seal | AES-GMAC (`ring`) | ChaCha20-Poly1305 tag only (`ring`) | keyed BLAKE3 to 16 |
|---|---|---|---|---|
| 64 | 157 | 113 | 188 | 133 |
| 1,200 | 484 | 1,033 | 621 | 1,498 |
| 8,962 | 2,647 | 7,364 | 3,615 | 3,340 |
| 65,000 | 18,410 | 52,645 | 25,169 | 20,643 |

At 8,962 octets, the size the gates run at, GMAC is 2.8 times the seal, a ChaCha tag-only 1.37 times and BLAKE3 1.26 times. Only at 64 octets does a MAC win (GMAC 113 against 157 ns). Only on a CPU without AES (and on wasm32), where the seal is ChaCha, would a ChaCha tag-only be cheaper than the seal: 8–18 % (0.82–0.92 of ChaCha's own seal, from 64 octets to 1 MiB). That is not the host the gates run on, and nothing was built for it.

**Taking the seal off the writer thread.** Two designs were built, measured against the shipped one in interleaved pairs (medians, host load 4–8), and **removed** because each was slower. Messages/s, shipped then variant:

| design | 64 B | 1 KiB | 8 KiB |
|---|---|---|---|
| the whole drain on a writer thread | 1,825 k to 739 k | 558 k to 461 k | 86 k to 57 k |
| seal one frame ahead on a seal thread | 1,792 k to 1,680 k | 619 k to 430 k | 93 k to 61 k |

The cause is that a drain is about one frame long on a single worker, so nothing overlaps: the seal is not hidden and every frame pays a hand-over between threads. The first design also made the QUIC driver wake across threads (48 % of the sender thread was in libc); the second spent about a quarter of its time waiting on the seal thread. The latency with and without an offload was not measured, because none shipped.

**The copies.** A read of the path from `Heap::emit` to quinn found one copy of a message's payload by the channel (into the frame buffer, which batching needs) and none for the seal, which is in place, nor for the datagram carrier. The one copy that could go is in ndn-ext: a stream frame of 16 KiB or less is copied once behind its 4-octet length prefix. It was not changed.

### 16.6 Where this leaves the gates

Against the targets of the design note every performance gate **except 8 B is missed**: the 64-octet half round trip (1.37 cold and 1.24 hot against 1.1), the 64-octet rate (1.837 M, about 5 % under the 1.94 M compared against), 128 octets to 1 KiB (0.23 to 0.449 of the raw datagram against 0.9) and 8 KiB (0.60 of the raw stream at 9,000 and 0.83 at 1,452 against 0.9). 8 B passes (2.110 M at 9,000, 1.07 times the figure compared against). What remains of the gap is the cold footprint of the idle path (latency) and the two AEAD passes on one worker (throughput), both of §16.3. What is not yet done and would help: the receiver's open off the reader thread (which needs `deliver_frame` to stop returning a per-frame result), the 4-octet prefix copy of ndn-ext's `side.rs`, a sender cache in `Heap::sender` (0.07 µs), a smaller cold footprint of the idle path, and striping a link over several connections (the design note's §17.6, undecided).

**The owner's decision** is to finish stages 4–7 first and then to do **one focused performance pass**; the open items above are left to that pass.

### 16.7 Stages 4 and 5

**Method.** The **baseline** is the stage-3 tree of §16.1, ndn-rs `33a2fd95` with ndn-ext `407bbaf`, built in scratch worktrees; **current** is the tree with stages 4 and 5. Pinned to cores 10 to 13 (`taskset -c 10-13`), 3 s a row, baseline and current alternating in pairs with the order flipped each pair. The whole table was run twice, before and after the fix of `ASK_NEW` (§3.1), and the two runs agree. The host was shared and **busier than §16.1's**: the 1-minute load was 11.7 to 16.5 (median 14.5). **Read every figure as ±5 %.** The raw logs are not in the repository.

**One link, `chan_ping`, baseline against current** (the rung of §16.1; the nodes use the one-link carrier of that rung, not a forwarder):

| row | baseline | current | ratio of medians | pair ratios |
|---|---|---|---|---|
| 8 B messages/s | 2.151 M | 1.882 M | 0.875 | .92 .90 .86 |
| 64 B messages/s | 1.909 M | 1.681 M | 0.881 | .84 .90 .87 |
| 1 KiB messages/s | 626 k | 539 k | 0.861 | .87 .84 .87 |
| 8 KiB messages/s | 91.0 k | 82.7 k | 0.909 | .92 .84 .93 |
| 64 B half round trip p50, cold (14 pairs) | 33.3 µs | 33.0 µs | 0.985 | range 0.61 to 1.60 |
| 64 B half round trip p50, hot (14 pairs) | 34.1 µs | 41.0 µs | 1.21 | range 0.96 to 1.98 |
| 64 B p99, cold / hot | 52.0 / 50.8 µs | 48.8 / 63.6 µs | | |
| per-message CPU, sender (`poll_next` / `next_batch`) | 532 / 448 ns | 553 / 467 ns | 1.040 / 1.043 | |
| per-message CPU, receiver (`poll_next` / `next_batch`) | 304 / 276 ns | 314 / 279 ns | 1.033 / 1.009 | |

- **Throughput is 0.86 to 0.91 of the baseline at every size.** It is real (both runs, every pair). The first run read 0.83 to 0.90.
- **Hot latency read +18 % and +21 % in the two runs. Cold latency is not separable:** the first run read +21 %, the second −1.5 %, and the range of the pair ratios is wide.
- **Per-message CPU moves 1 to 4 %.** That row uses a carrier with no stream, so it carries no checkpoints.
- **The raw carrier is unchanged**, which clears the carrier and the host: a separate `carrier_bench` control (defaults, MTU 1,452, so not comparable to §16.2's raw rows) read 28.5 µs cold and 28.9 µs hot, and baseline against current throughput 0.974 (1 KiB datagram), 0.999 (1 KiB stream) and 1.009 (8 KiB stream). The channel against the raw half round trip: cold 1.16 in both trees, hot 1.17 in the baseline and 1.39 now.
- **The cause was not isolated.** The checkpoint rows below point at checkpoints [INFERENCE: not shown].
- **An oddity, not diagnosed:** in the current tree the per-message row delivers 99.97 to 99.99 % of the messages (the baseline 100 %), and the shortfall grows with the run [INFERENCE: a non-data frame takes a tap's release slot and `Latest` supersedes that round].

**The cost of checkpoints** was measured in a forwarder-attached direct shape (a sender and a receiver, each on its own forwarder, over one real QUIC link), comparing the default period of 20 ms with the largest, 2,000 ms, 3 interleaved pairs. It is the **difference** between two periods, not against a build with no checkpoints, and it includes the stream writes, the wake-ups and the hashing of frames, not only the signatures. Share of one core:

| rate (64 B) | sender, 20 ms | sender, 2,000 ms | receiver, 20 ms | receiver, 2,000 ms | difference |
|---|---|---|---|---|---|
| 1,000 messages/s | 3.75 % | 3.87 % | 5.54 % | 3.83 % | sender −0.12, **receiver +1.71** |
| 100 messages/s | 1.48 % | 1.11 % | 1.77 % | 1.04 % | sender +0.37, **receiver +0.73** |

- **The design target** was under 0.5 % of a core for each active sender, on both sides. **The sender meets it** (+0.37 % at worst). **The receiver misses it:** +0.73 % at 100 messages/s and +1.71 % at 1,000.
- **Throughput** in the same shape at 20 ms is 0.75 (64 B) and 0.77 (1 KiB) of the 2,000 ms run; the 64 B p50 is 39.6 against 35.9 µs and p99 56 against 46 µs. Part of the 2 s gain is probably that the sender's ring evicts frames before they are hashed, so it is not a clean cost of signing [INFERENCE: the cost follows the rate of frames, which is frame hashing, §15.3].

**Through a relay** (`chan_relay`: a sender, a relay and receivers A and B, each on its own forwarder, joined by real QUIC links; the relay holds no identity, trust or data layer, only routes and the side table; forwarder-attached nodes). Medians of 3 runs (14 for the latency rows); ranges in brackets:

| | direct | one relay, one receiver | one relay, two receivers (A / B) |
|---|---|---|---|
| 64 B messages/s | 1.276 M | 529 k [527 k, 715 k] | 949 k / 981 k, 1.91 M in all |
| 1 KiB messages/s | 208 k | 146 k [95 k, 189 k] | 108 k / 120 k |
| 64 B half round trip p50 | 36.2 µs | 72.0 µs | 83.9 µs |
| 1 KiB half round trip p50 | 45.5 µs | 97.9 µs | 86.4 µs |

- **One relay hop roughly doubles the half round trip.**
- **The sender's link carries one copy of each frame** with two receivers behind the relay (the relay's frames out are twice its frames in; a test asserts it). Each receiver gets about what the single one does, so the total is about twice.
- **The relay rows are noisy**, and one relay against two inverts on throughput and on the 1 KiB latency: read no order into them. At saturation the receivers' app-face inboxes also drop (`sink_full`).
- **The 1 KiB gap to the one-link row (208 k against 539 k)** is the default datagram frame of a forwarder-attached node, 1,200 octets (`DATAGRAM_FRAME_MAX`, §14.10): a 1 KiB message fills a frame, where the one-link carrier packs several. `attach_forwarder_with` raises it when every sink is local. That is a setting of the host, not of the table.

**Rung C3: one sender, four receivers behind the relay** (SHAPES-CHANNEL.md §13, stage 4 gate). This rung is measured in ndn-ext, not in versus (`ndn-ext/crates/faces/ndn-face-quic/examples/chan_relay.rs`, shape `relay4`; the fact is also asserted by `tests/chan_relay.rs::four_receivers_behind_a_relay_get_every_message_and_the_sender_link_carries_one_copy_of_each_frame`). Method: the topology of the relay rows with receivers A to D (each on a forwarder and a runtime of its own, a QUIC link each to the relay, one link from the relay to the sender), run as `chan_relay shapes=direct,relay1,relay4 only=c3:64:400,thr:64,lat:64 repeat=3 secs=3`: the `c3` row sends 400 messages of 64 B in windows of 20, each window delivered to all four receivers before the next, and compares the frame counters of the sender's link, the relay's table and its links; `thr` is the back-to-back rate each receiver's `Items` yields; `lat` is the half round trip of each receiver in turn (the sender pings, that receiver pongs, the other three receive and count the pings), 10,000 timed round trips after 1,000 warm-up, as in the rows above (hot only: the example has no cold row). **Measured on a shared host, not pinned, load average 15 to 17 (the example was run without `taskset`); the repetitions differ by far more than ±5 %, so read the ranges, not the medians.**

- **The sender link carries one copy of each frame: PASS in all three repetitions.** For 400 messages the sender's link sent 802 frames (the messages and the checkpoints and `HELLO` that followed), the relay received 802 and sent 3,208 = 4 × 802, each of the four relay links sent 802 and each receiver's link received 802; every receiver got all 400 messages. The same row with one receiver behind the relay (`relay1`) and with the direct link gives 803 / 802 frames out of the sender, so the sender's cost does not grow with the receivers.
- **Throughput, 64 B**, medians of 3 [min, max]: A 410 k [394 k, 816 k], B 583 k [389 k, 833 k], C 440 k [437 k, 446 k], D 567 k [387 k, 739 k] messages/s, 1.98 M [1.63 M, 2.83 M] in all; one receiver behind a relay 909 k [905 k, 921 k]; direct 1.20 M [875 k, 1.27 M]. The sender emitted 1.1 to 1.5 M messages/s in each; the receivers' app-face inboxes drop at saturation, so the per-receiver figures are shares of that.
- **Half round trip, 64 B p50 [min, max] (p99 median)**: direct 53.2 µs [51.4, 57.6] (106 µs); one relay, one receiver 102.5 µs [88.8, 134.0] (287 µs); four receivers A 111.8 µs [102.3, 160.0] (305 µs), B 133.6 µs [122.6, 170.7] (471 µs), C 161.4 µs [158.3, 166.9] (529 µs), D 97.7 µs [94.3, 148.0] (214 µs). The relay hop costs about 50 µs on the median over the direct link on this host. The four-receiver medians sit between 98 and 161 µs, about one relay hop above the direct link for the best and about two for the worst; the ranges of the repetitions overlap those of the one-receiver row, so **the rung does not show the fourth receiver's latency to be worse than one relay hop gives for the first**, and it does not show it to be equal either: a quiet, pinned run is needed to decide that, and none was made. The direct figure here (53 µs) is above the one-link row of the table above (36.2 µs) [INFERENCE: because of the load of this run], so no gate against stage 3's latency is claimed from these numbers.

**Not run.** N1 (there is no such harness in ndn-ext: the `ndn-link` ladder measures something else) and any radio path (the radio sinks, §14.9, are tested in ndn-radio against test bearers; no channel was measured over a radio). `Trust::Verified`'s latency and a real network interface were not measured.

**The gates.** The gate of stage 4 and 5 that the one-link rung stays within 3 % of stage 3 (SHAPES-CHANNEL.md §13) is **not met**: throughput is 9 to 14 % down and hot latency up about 20 %. The checkpoint gate of under 0.5 % of a core per active sender is met by the sender and **missed by the receiver**. **Nothing was tuned**, by the owner's decision (§16.6): the performance pass after stage 7 owns these figures.

### 16.8 What the figures do not cover

- A real network interface: every run is loopback.
- `Reliable` and `Window` (only `Latest` was measured); `Trust::Verified`'s latency; and the setup's Interests crossing the link in the one-link rung (its two nodes share one forwarder; the relay rows of §16.7 do cross the links).
- Zenoh was not rerun on this host; comparisons to it use the figures of the design note's baseline (§1.2), taken at another load. Zenoh was not measured at 128 B to 512 B.
- A full table after the changes made since the tuning pass (§16.2), and the latency with and without an offload.
- A quiet host: the figures were taken at load 5–6 on a shared host, and single latency pairs vary by ±5 µs.

## 17. The verbs: put, emit, get

A space has three verbs and a point read. This section states what `get` does with the first two, exactly; [heap.md](heap.md) §10.3 and §10.4 state the kept side (the register, `watch`).

| Verb | What it is | Who may call it |
|---|---|---|
| `put(path, bytes, opts)` | **kept**: signed by the writer's device key, chained, stored, synced; the register's head of `path` ([heap.md](heap.md) §10.1) | a writer (§4.2, [heap.md](heap.md) §10.3) |
| `emit(path, bytes, opts)` | **ephemeral**: sent over the space's channel (§13.1), never an entry, stored and served by nobody | a writer (§13.1) |
| `get(what, opts)` | **one stream**: the kept values of the space, then their changes, merged with the emissions of its channels, filtered by `what` | a reader or a writer; a follower for kept values only |
| `kept(path)` | the head's value now, from what this node holds; never waits, never touches the network | a reader or a writer |

```rust
pub fn get(&self, what: Select, opts: GetOptions) -> Result<Items, HeapError>;
pub async fn kept(&self, path: &Name) -> Result<Option<Item>, HeapError>;

pub enum Select { Path(Name), Prefix(Name) }
pub struct GetOptions {
    pub kept: bool,              // kept values and their changes (default true)
    pub live: Live,              // Live::Emitted (default): also emissions; Live::Off
    pub modes: Modes,            // which channel modes to join (default: all the senders offer)
    pub trust: Trust,            // Trust::Prompt (default) | Trust::Verified (§15.8); emissions only
    pub congestion: Congestion,  // Block (default) | Drop; Reliable and Window emissions only
}
pub struct Items;                // Stream<Item = Result<Got, GetNotice>>
impl Items {
    pub async fn next(&mut self) -> Option<Result<Got, GetNotice>>;
    pub fn next_batch(&mut self, buf: &mut Vec<Got>) -> usize;
    pub async fn caught_up(&mut self);
    pub fn hello_seen(&self) -> bool;
}
pub struct Got { pub path: Name, pub bytes: Bytes, pub by: Name, pub writer: Name, pub kind: Kind }
pub enum Kind { Kept(Kept), Emitted(Emitted) }
pub struct Kept { pub id: EntryId, pub as_of: Option<Duration>, pub removed: bool }
pub struct Emitted { pub seq: u64, pub stands: Option<Duration> }
pub enum GetNotice {
    Lagged { missed: u64 },                          // emissions the mode dropped (§17.5)
    Withdrawn { id: EntryId, why: Refusal },         // a kept entry this stream gave was refused after the fact
    LiveEnded(LiveEnd),                              // the emission part ended (§12.7); kept values go on
    Retracted { writer: Name, from: u64, to: u64 },  // a checkpoint contradicted emissions (§15.5)
}
```

### 17.1 What `get` creates

`get` is synchronous and does no network I/O. When it returns, **both feeds are registered**: the kept watcher (the register's heads under `what` are listed and the watcher registered in one step under the space's lock, so no change falls between them) and, with `Live::Emitted`, the emission sink (§12.7). Nothing that happens after the call is lost for want of a first poll. `get` asks no sender for a session: that is `ask_channel_in`, or the announce-driven ask of a device that is listening (§9). Dropping the `Items` closes both feeds and releases the sink's sessions (§14.10).

### 17.2 `kind` is the authority

Every item says what it is. **`Kind::Kept`** is durable and signed: the head of its path in the register, an entry the writer's device signed, chained, and that this node judged ([heap.md](heap.md) §3.8, §9). **`Kind::Emitted`** is neither: it was authenticated as the sender's by the channel's AEAD and, after the sender's signed checkpoint, as the sender's alone (§15), it is not an entry, and **it is never the current value of a path**: no emission replaces, hides or confirms a kept value. An application that needs "the value" reads `Kept`; one that wants "what is being done now" (a cursor, a drag) reads `Emitted`. A `stand` replay (§13.6) is an `Emitted` with `stands` set to what is left of the stated lifetime; it is not kept either.

### 17.3 The order

1. **The kept listing comes first, always**: every path under `what` that has a value, as the register's head, in path order (canonical NDN order of the path), each as `Kind::Kept` with `removed: false`. A path with no value (never written, or removed) has no item. A value in pieces that is not whole here is not listed; it is given as a kept change when its last piece is held.
2. **`caught_up()` resolves after the listing was yielded**: when every path that had a value when `get` returned has been given by `next` or `next_batch`. Called before the listing was read, it reads the rest of it into the `Items`' own buffer (the next `next` gives it, before anything else): it never waits for the caller. At once when `kept` is `false`.
3. **Emissions that arrive during the listing are held** (queued in the sink under the bounds of §17.5) **and come after it**: nothing emitted is yielded before the last item of the listing.
4. **After the listing, the two sources alternate fairly**: when both have something queued, the one that was not taken last is taken first, so neither starves the other. **No order is promised between a kept item and an emitted one**: an emission made after a `put` can reach a receiver before the `put` does (kept data travels by sync, emissions by the channel), and the reverse.
5. **Within a source**: kept items are in the order the register applied the changes of this node, and **never an older value of a path after a newer one**; emitted items are in the mode's order (§12.6): `Reliable` and `Window` in sequence order, `Latest` the newest per sender and name, never an older after a newer; across channels, arrival order.
6. **A notice comes after the items queued before it in its own source**: `Lagged`, `LiveEnded` and `Retracted` after the emissions (§12.7), `Withdrawn` after the kept items.

A joiner therefore gets the **current kept state** (the listing), then what changes, and with it what is being emitted, without a connect step and without a gap between the listing and the changes.

### 17.4 Duplicates

- **A path both put and emitted** gives **two items**: one `Kept` and one `Emitted`. They are never merged and never deduplicated, even when their bytes are equal. An emission is never suppressed by a `put` (there is no mark between the two): a stale emission after a later `put` of the same writer is delivered, and `kind` tells the application which one is the value.
- **A kept entry is yielded once per `Items`.** The `Items` remembers the entry it gave at each path, and never gives the same entry again, also not after a lag (§17.5). An application that is told an entry twice (the same `Kept::id`) by an implementation that repeats the current value after a lag may treat it as the same value; it is never told an **older** value of a path after a newer one.
- A `stand` replay is `Emitted` with `stands`, as §17.2; it never becomes `Kept`.
- **A removal** is `Kind::Kept` with `removed: true`, empty `bytes` and `id` the removing entry. It is given only for a path this `Items` gave a value of; a path that never had a value in this stream gives none.
- **`Withdrawn { id, why }`** is given for an entry this `Items` gave and that was the value it had given at its path when it was refused ([heap.md](heap.md) §3.8, §10.4): drop what was derived from `id`. The entry the refused one superseded returns as the next `Kept` (or, with none left, a removal).

### 17.5 A slow reader

**Kept: never lost.** The kept queue holds at most `Config::watch_queue` changes (4,096 by default), as a `watch`'s does. When a change does not fit, the stream is **not told a loss**: when it has read what was queued, it takes the space's lock, forgets what was dropped, and in the same step reads from the store the heads under `what`. It then gives, in path order and before any later change, every head that is not the entry it already gave at its path, and a removal for every path it gave a value of that has none now. So **every path's current value is delivered**, and a path that changed several times while the reader was behind is given its **latest** value and never an older one after a newer. The intermediate values are skipped **by state**, not lost data: the log and `watch` ([heap.md](heap.md) §10.4) have the history. A slow reader never slows a `put`, a fetch or another reader.

**Emitted: as the mode says** (§12.6): `Latest` keeps the newest per sender and name (coalescing is not a loss and is not told) in at most 4,096 pairs and 1 MiB charged, evicts the oldest pair past the bound and tells `Lagged { missed }`; `Reliable` and `Window` queue at most 1 MiB, and `Congestion::Block` (the default) **stalls the stream** so that the back pressure reaches the sender and nothing is lost, `Congestion::Drop` discards the oldest and tells `Lagged { missed }` in its place. **Kept items are unaffected**: the two sources have separate queues; a stalled or overflowing emission queue delays no kept item, and the other way round.

### 17.6 `by` and `writer`

`writer` is the device that signed the entry (kept) or sent the channel (emitted). `by` is the **authenticated** person of that device and nothing the sender or the frame says: for `Kept`, the namespace of the trust context that validated the signing key of the entry ([heap.md](heap.md) §9.1), which the node derived when it admitted the entry; for `Emitted`, the person of the sender's device **as this node judged it when the session was set up** (§3.4), kept with the session. A `Got` of either kind for the same writer has the same `by` unless the trust contexts changed in between.

### 17.7 Refusals: who may call what

`get` refuses at creation, each with a reason and a next step ([heap.md](heap.md) §10.5):

- **`BadRequest`** for `kept: false` with `Live::Off`: it asks for nothing; ask for kept values, emissions, or both.
- **`NotAllowed`** for `Live::Emitted` on a space this device only follows: a follower takes no part in channels; open the space as a member, or read the kept values with `Live::Off`. A follower **may** read kept values with `Live::Off`.
- **`Sealed`** (`AskOwner`) for kept values of a sealed space whose audience does not list this device's person: a **non-member**, or a member that was **removed** (as soon as this node holds the record that removes her), gets no kept value. With `kept: false` the call succeeds (it does no I/O), and a non-member gets **no emission** either: no sender answers her ask (§3.4, §4.1), so she holds no session. A kept feed whose queue overflowed after its reader was removed ends instead of re-reading the register (it gives nothing more).

`put` and `emit` need a writer (`NotAllowed` and `NotWriter` otherwise). `get` needs a reader or a writer. `kept` answers as before ([heap.md](heap.md) §10.3).

### 17.8 What `get` does not do

It does not resume (`watch` with a `Frontier` does, [heap.md](heap.md) §10.4); it does not give history, only the current value of each path and what changes after; it does not make a session (§17.1); it does not order an emission against a `put` (§17.3 item 4); and it adds nothing to the wire: no field of an entry or of a frame is new for it.
