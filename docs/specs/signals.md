# Signals: ephemeral live data between the members of a folder

- **Status:** Draft (round 4)
- **Scope:** *Signals*: presence, cursors, drags at 60 Hz, live unsigned edits and game input exchanged between the members of a folder or collection. A signal is never a version, never stored and never cached. This spec defines:
  - who may send and receive (the members record, through the gate of [data-layer.md](data-layer.md) §20);
  - run keys and run headers;
  - the packet: its body, its run signature and its seal;
  - the push into the namespaces' sync groups, and the local leg over shared memory;
  - what a receiver checks, in order, and what it delivers;
  - limits, errors, the wire format and threat notes.
- **Implementation:** the gate is `ndn_data::signal` (ndn-rs `crates/app/ndn-data`). Everything else is `ndn_surface::signal`, feature `signals` (ndn-ext `crates/surface/ndn-surface`). No forwarder, link or trust-context library treats signals specially.
- **Related specs:** [data-layer.md](data-layer.md) (members §6, §6.1, §6.3; seals §9; sync groups §12; the gate §20), [ndn-link.md](ndn-link.md) (relays and transit §15.7), [trust-context.md](trust-context.md) (revocations).

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 ([RFC 2119], [RFC 8174]) when, and only when, they appear in all capitals, as shown here.

---

## 1. Terminology

| Term | Meaning |
|---|---|
| scope | A folder or a collection of the data layer. Its members record in force governs its signals. |
| member | For signals: a device whose key a writer prefix of the scope's record in force covers, or which the record's audience admits, and whose key no trust context it holds revokes ([data-layer.md](data-layer.md) §20). |
| sender | The device key that signed a run's header: `/<ns>/<…device>/KEY/<id>`. |
| run | One sender's signals in one scope under one ephemeral Ed25519 **run key**, from its header's `RunStart` until its `RunNotAfter`. |
| run header | A Data packet, signed by the device key, binding the run key, the run's start and end and its local ring (§3). |
| packet | One signal or a batch of signals, signed by the run key, sealed in a sealed scope (§4). It travels as the ApplicationParameters of a push Interest (§5) and as a frame on the run's ring (§6). |
| signal key | A sealed scope's key for signals: derived from the content key of the scope's epoch inside the data layer ([data-layer.md](data-layer.md) §20). |
| group | A namespace's sync group `<O>/32=sync` ([data-layer.md](data-layer.md) §12). |
| address | An application-defined label within a sender's signals, such as `cursor`, `presence` or `drag/<element>`. A newer signal for an address replaces the older one. |

## 2. Model

1. A signal is never a version. No signal, packet or run header is ever written into a device's store or log, counted into a collection's state, served, or answered for by anyone.
2. A signal is never cached. It never travels as Data (§5.4), so no content store can keep it.
3. Only members send and receive (§7). A receiver checks the sender's membership on every packet, against the record in force at that moment.
4. A signal is authenticated by its run key, and the run key by the sender's device key. A receiver MUST verify the run signature of every packet it delivers, including packets that came from this host (§6): local faces are not validated by a forwarder.
5. In a sealed scope every packet is sealed under the signal key. Only the readers of the epoch can open it.
6. Signals are lossy. Per sender, signals are ordered by sequence. A receiver delivers the newest signal per (sender, address) and refuses replays (§8).
7. A signal expires. One past its `Expires` is never delivered.
8. **Commit:** live work becomes versions only through the data layer's ordinary `put` / `put_op` (one version, or a group, signed by the writer's device key). Signals themselves never become versions, and nothing in this spec turns one into a version.

## 3. Runs

### 3.1 The run key

A sender opens a run with a fresh Ed25519 key pair drawn from the operating system's randomness. The secret key MUST NOT leave the process and MUST NOT be stored. The **RunId** is the first 16 octets of SHA-256 of the run's 32-octet public key, so a RunId names exactly one run key.

A header alone doesn't prove that its signer holds that key. Every reader of a run's header sees its public key, and a member can sign a header of its own that binds it. A receiver therefore admits a header only from a packet whose `RunSignature` verifies under the run key that header binds (§8.1 step 4). That signature covers the header, so it proves possession of the run's secret key. Only then may a member's header claim a RunId, and only its own.

### 3.2 The run header

The run header is a Data packet:
- **Name:** `<device>/32=signal/<scope>/32=run/<RunId>`: `<device>` the device name of the signing key, then the KeywordNameComponent `signal`, the scope's components, the KeywordNameComponent `run`, and a GenericNameComponent of the 16 RunId octets. Like every packet the data layer signs (a log entry is `<device>/32=log/<subject>/…`), it is named under its signer's device, since a validator picks the trust context, schema and anchors by the packet's name. For a self-certifying member adopted for the folder, the folder's scoped view judges it, as it judges that member's log entries about the folder ([data-layer.md](data-layer.md) §6.3);
- **Content:** a RunHeaderBody (§11);
- **Signature:** by the sender's device key, as the data layer signs its own packets. No FreshnessPeriod.

The body binds:
- `RunKey`: the run's public key;
- `RunStart`: the run's first sequence, the sender's clock in microseconds since the Unix epoch when the run opened;
- `RunNotAfter`: when the run ends, in ms since the Unix epoch, at most 24 h after the run opened;
- `LocalRing` (optional): the 32-octet secret of the run's local ring (§6).

The device key signs the header only while the device is a member of the scope ([data-layer.md](data-layer.md) §20). The header is never published under its name and never answered for. It travels only inside packets (§4).

The run header's name is the **only** place a scope's Name travels in a signal (§4.1): every later packet names its scope by a digest of it. A receiver learns a run's scope from this device-signed header, so the header binds the RunId to the scope. The header, with its signer's key name twice (in its name and its KeyLocator), MUST fit a packet of its own, which bounds a scope's name (§4.3).

### 3.3 Sequences

A run's first signal takes `RunStart`; each next signal takes the next integer. Sequences are **per sender**. A renewal (§3.4) starts the new run at the sequence after the old run's last. A new run that continues nothing (a restart, another scope's run) starts at the sender's clock in microseconds at its opening, so above every sequence of an earlier run, as long as a sender makes fewer than a million signals per second and its clock doesn't step back. A receiver orders a sender's signals by sequence across its runs (§8.3). A sequence is at most 2^64 − 2. The replay window counts one above the highest sequence it has seen, so a receiver refuses 2^64 − 1 at decode (`malformed`), and a sender refuses (`TooLarge`) a batch that would run past it. Every receiver's arithmetic on sequences is checked: no packet, verified or not, can make it overflow.

Two runs of one sender in one scope at once (two processes of one device, each with a run its device key signed) share the sender's sequence space: a receiver orders them as one sender's. They MUST use distinct addresses, or the later-opened run's signals hide the other's as stale.

### 3.4 Renewal and end

A sender SHOULD open a new run (a new run key, a new header) once 90 % of a run's lifetime has passed, and continue its sequences in it. A run ends at `RunNotAfter`, when its sender closes it (its ring tells local readers), or when the sender's process ends. Remote receivers forget a run at its `RunNotAfter` (plus the clock skew they allow), or sooner when a newer run of the same sender replaces it (§8.4).

## 4. Packets

### 4.1 The body

A **SignalBody** carries, in order:
1. the **ScopeDigest** of the packet's scope;
2. the RunId;
3. optionally the run's header (`RunHeader`, the header's whole Data wire);
4. zero to 32 `Signal`s, each with its sequence, address, `Expires` and payload, in ascending sequence order with no repeated sequence; at least one unless the RunHeader rides;
5. the `RunSignature`: Ed25519 by the run key over the octets `"ndn-signal/2"` followed by every octet of the SignalBody's TLV-VALUE that precedes the RunSignature TLV, so the ScopeDigest, the RunId, the header and the signals are all covered.

**The scope digest.** `ScopeDigest` is the first 16 octets of SHA-256 over the octets `"ndn-signal/2 scope"` followed by the scope's Name TLV: TLV-TYPE 0x07, TLV-LENGTH and the components, each in the minimal encoding (a `Name` decoded from a run header's name and re-encoded gives the same octets). **The scope's Name never rides in a packet.** It lives in one place, the run header's name `<device>/32=signal/<scope>/32=run/<RunId>` (§3.2), which the device key signs. After the header, a packet names its run by RunId and its scope by digest alone. So a long scope name costs one header packet and no signal anything (§4.3).

A receiver resolves a digest to a scope it subscribes to (§8.1 step 3): the digests of its subscribed scopes are held in a table, and it refuses to subscribe to a scope whose digest another subscribed scope holds, a collision that costs about 2^64 SHA-256 evaluations to find and that only the owner of both scopes could make (§13.9). It learns a run's scope from the run's admitted header and checks that the header's scope has the packet's digest. Why the digest binds the packet to its scope, and why a packet replayed into another scope fails, is §13.9.

The header rides in a run's first packet, and again in the first packet sent once 1 s has passed since it last rode. When the header is due and doesn't fit beside the signals within the packet limit (§4.3), the sender first pushes a **header-only** packet (the header and no signal, signed by the run key, counted against its rate) and then the signals. A receiver takes a header-only packet as the run's admission only and delivers nothing from it. A receiver that lost the header holds the run's packets as unknown until the next one (§8.1).

### 4.2 The seal

In a sealed scope the packet is a **SignalSealed** instead:
- `KeyId`: the 8-octet id of the signal key used ([data-layer.md](data-layer.md) §20);
- `SealNonce`: 24 random octets;
- `Ciphertext`: XChaCha20-Poly1305 under the signal key and the nonce, over the plaintext `SignalBody [SignalPadding]`, with AAD `"ndn-signal/2"` followed by the KeyId octets, its 16-octet tag appended.

**Padding.** A sender pads every sealed packet, so that its whole encoding is a multiple of 128 octets, never above 1,024. It does this with one `SignalPadding` of zero octets after the SignalBody, inside the plaintext. A packet within 3 octets of 1,024 stays unpadded, because no padding element is shorter than 4 octets. A receiver accepts at most one `SignalPadding` after the body and ignores its octets. It refuses anything else after the body (`malformed`). The padding lies outside the run signature, but the AEAD tag covers it, so nobody can alter it unnoticed, and it carries nothing. A relay then learns a sealed packet's size only to within 128 octets. Unsealed packets are not padded: their contents are plain anyway. The cost is at most 127 octets per sealed packet, and no copy.

The body is signed first and then sealed. A sender seals under the first key `signal_scope` gives: the key of the epoch in force at the sender. A packet of a sealed scope MUST NOT be sent unsealed, and a receiver MUST refuse a SignalBody for a scope whose record in force is sealed.

**Superseded epochs.** `signal_scope` also lists the keys of the scope's earlier epochs, because a sender that doesn't hold the newer record yet still seals under its epoch. A receiver opens a packet under such a key only during a **grace** of 60 s (`EPOCH_GRACE`) after it first saw that epoch superseded: it asks `signal_scope` again at most every 5 s while known key ids arrive, and at most once a second for an unknown one. Past the grace the packet is `unknown_key`, dropped undecrypted. A removed member keeps the old epoch's key, so without the grace it could seal packets that every receiver opens for as long as the line lasts, and push headers that hold admission slots. The grace bounds that to one minute after the receiver learns of the new epoch. A sender that is still behind after that is dropped until it holds the newer record, and then seals under it.

### 4.3 Size

A packet's whole encoding is at most 1,024 octets. An address is at most 64 octets and a payload at most 768. A packet carries at most 32 signals.

**Room.** A packet names its scope by a 16-octet digest, never by the scope's Name (§4.1), so what a signal can take does not depend on how the scope is called. The fixed parts of a packet, each with its TLV-LENGTHs in their longest form, are:

| Part | Octets |
|---|---|
| `SignalSealed` around its plaintext (key id 12, nonce 28, the ciphertext's framing 6 and tag 16, its own framing 6); a sealed packet is then padded (§4.2) | 68 |
| `SignalBody`'s own framing (6), ScopeDigest (20), RunId (20), RunSignature (68) | 114 |
| each `Signal` beside its address and payload: its framing (6), SignalSeq (12), Expires (12), the address's framing (4) and the payload's (6), with the 8-octet integers of a clock in µs and ms | 40 |
| a `RunHeader` element beside the header's Data wire | 6 |

So a signal of **address + payload up to 802 octets** (1,024 − 68 − 114 − 40), with an address of at most 64 and a payload of at most 768, always fits one packet, sealed or not, whatever its scope is called. This is the **room** of a packet; a sender counts it without the scope's name (`Signals::room(scope)` answers it, and 0 for a scope that no run can be opened in, below). A signal of 512 octets always fits. A batch takes at most 40 octets of framing per signal.

**The header-only packet.** The run header rides in a packet of its own when it doesn't fit beside the signals (§4.1). Sealed, that packet takes 68 + 114 + 6 octets beside the header, so **a run header of at most 836 octets** fits. A header holds the scope's Name once and the signing device's key name twice (in its name and in its KeyLocator), plus about 200 octets of Data fields, a 64-octet signature and the run's key, times and ring secret. A scope's name of at most **`SCOPE_MAX` = 384 encoded octets** (its Name TLV) therefore fits, for a device whose key name (`<device>/KEY/<id>`) is up to 140 octets: the conformance tests hold to exactly this. A scope longer than that is refused at `subscribe` and `open` with `ScopeTooLong`, which states the limit and says to name the folder or collection shorter. A device with a longer key name than 140 octets can have less scope to spend: its `open` refuses a scope its own header would not fit, with `ScopeTooLong` stating the length its header does allow. No signal's room depends on the scope: only whether a run can be opened at all.

**Measured sizes** (ndn-surface `examples/signals_bench.rs`, address `cursor` of 6 octets, payload of 16, a short scope, the group `/alice/32=sync`, a device `/alice/laptop`), packet / push Interest in octets, independent of how long the scope is called:

| Case | Unsealed | Sealed (padded, §4.2) |
|---|---|---|
| 1 signal | 170 / 244 | 256 / 334 |
| 1 signal, run header riding (once a second) | 410 / 488 | 512 / 590 |
| batch of 8, per signal | 72.2 / 82.0 | 96.0 / 105.8 |
| batch of 8 with the header, per signal | 102.0 / 111.8 | 112.0 / 121.8 |

The run header is 240 octets here. A packet costs one push Interest per group (§5.2).

## 5. The push

### 5.1 Groups

A sender pushes each packet into the group of every namespace the scope's record in force names: the scope's own namespace, the namespace of each writer prefix, of each reader (a group reader by its collection's namespace) and each self-certifying writer adopted for the folder. These are exactly the groups the data layer publishes a notice about the scope into ([data-layer.md](data-layer.md) §12), as `signal_scope().groups` lists them. Each member's devices hear the packet in the group of their own namespace, which every forwarder holding that namespace carries to its devices, and which every relay serving its devices carries with the multicast strategy while the namespace is in transit ([ndn-link.md](ndn-link.md) §15.7).

### 5.2 The push Interest

For each group `<O>/32=sync`, the sender expresses one Interest:
- **Name:** `<O>/32=sync/32=signal/<ParametersSha256Digest>`;
- **ApplicationParameters:** the packet;
- **InterestLifetime:** 1,000 ms; **HopLimit:** 8; no CanBePrefix, no MustBeFresh, no ForwardingHint; unsigned.

No one answers it. A sender ignores any Nack it receives for it. The name is unique per packet (its parameters digest), so a forwarder never aggregates two packets in one PIT entry. A copy that reaches a forwarder twice is suppressed by its nonce.

**The push budget.** A relay that serves under quotas counts every packet a device sends on its link: by default 100 per second per key, burst 200, Interests, Data and Nacks alike ([ndn-link.md](ndn-link.md) §15.3). A packet costs one push Interest **per group**. So a process holds a push budget, counted in push Interests and shared by all its runs: 80 per second, burst 160, by default (`SignalOptions::push_rate`, `push_burst`). That leaves a fifth of a relay's quota to the device's Data, sync and certificate traffic. A send whose packets times groups exceed what is left is refused `RateLimited { retry_after }`, and the run's per-run limit is spent only together with the budget. One send larger than the burst is let from a full budget and then repaid at the rate. In practice:
- a run at 60 Hz fits into one group;
- into `n` groups it fits at 80/`n` packets per second, so it batches: `send_batch` with several addresses, or several frames, per packet;
- a host whose links carry no quota (its own relays, a forwarder with no serving quota, an in-process engine) MAY raise the budget.

### 5.3 Receiving

A device that receives signals registers its own namespace's group `<ns>/32=sync` (`signal_scope().listen`) on a connection of its own. On a forwarder this is an ordinary prefix registration. On an in-process engine the host routes the group to that connection's face, as it routes the data layer's sync face. The group's multicast strategy then delivers every Interest under it to every local registration and over every link that carries the namespace, never back toward the face it came from.

The group's prefix is shared by two protocols: State Vector Sync takes `<group>/v=2` (`v=3` in the ndnd dialect), and signals take `<group>/32=signal`. Each ignores the other's Interests: SVS refuses a name whose next component isn't its version, and a signal receiver ignores every name that is not `<group>/32=signal/<ParametersSha256Digest>` with a matching digest.

### 5.4 Why Interests and no Data

A pushed Interest needs no forwarder change: no unsolicited Data, no new strategy, no new route. It crosses relays like a Sync Interest. It also keeps signals out of every content store, because only Data enters one. A pull would cost a round trip per signal; a pushed Interest costs one way. Data with NDNLPv2 `CachePolicy = NoCache` would remain the right carriage for any later signal answer ([§13.7](#137-carriage)), but this spec defines none.

## 6. The local leg

A run MAY open a **local ring**: an `ndn-surface` broadcast ring (one writer, any number of read-only readers, lossy: it never blocks the sender and laps a slow reader). Its surface name is `<scope>/32=signal/32=ring/<RunId>` and its attach secret is the header's `LocalRing`. Every packet the run pushes is also published on its ring, with the same octets.

A receiver that admits a run header carrying a `LocalRing` checks whether the ring's control socket (derived from the surface name, ndn-surface rendezvous) exists on this host. If it does, the receiver attaches with the secret and reads the run's packets off the ring from then on. The ring's packets go through the same checks as pushed ones (§8). They are verified, deduplicated and counted against the run alike; `Signal.local` tells which way a signal came. The forwarder's later copies of the same packets meet a full replay window and are dropped before verification.

So discovery rides the push: a host on which two members run learns of each other's rings from the first packet. In a sealed scope the secret travels inside the seal, so only the scope's readers can attach. A ring's mapping is read-only to readers, and each frame is copied out once before verification. A lossy ring can be overwritten during a read, so a borrowed view could change between the signature check and delivery.

## 7. Membership

A device sends and receives the signals of a scope only while it is a member by the record in force over the scope at the device ([data-layer.md](data-layer.md) §20):
- `subscribe` and `open` are refused `NotMember` otherwise (also when the device is a writer outside a sealed scope's audience: it may not hold the key), `NotReady` when no record over the scope is held yet, or (sealed) when no key of the epoch in force is held yet (its ask is started). Neither follows the scope: a device that doesn't follow it yet hears no record of it, and the refusal says to follow it (watch it, or get a collection under it) and ask again;
- every `send` checks again: from the moment the sender's device holds a record removing it (or revoking its key), `send` is refused `NotMember`;
- a receiver admits a run header only from a packet whose run signature verifies under the run key the header binds (§3.1), and then only through `signal_sender` and `signal_admit`. The header must be named `<device>/32=signal/<scope>/32=run/<RunId>` for this scope, with `<device>` its signing key's device. Its key must be a member's, and this is asked first (`signal_sender`, offline), so a stranger's header costs nothing more. Its signature must verify by the device's validator by the **live** rule: its certificates valid now and none revoked (for a self-certifying member adopted for the folder, the folder's scoped view, [data-layer.md](data-layer.md) §6.3). The chain is walked from the certificates held first. A missing certificate is fetched only while fewer than 2 headers of the signer's namespace wait for certificates, and not for a device whose last fetch for a header brought none in the last 30 s (§13.5);
- a receiver checks `signal_member(scope, sender)` for **every packet** before delivering it. The check is synchronous, under the device's lock, against the record in force at that call. It also fails for a key that the trust context governing it revokes. A run whose packet fails it is let go at once;
- a receiver lets go of every run it holds when `signal_revocations` moves: a trust context revoking keys was adopted (the device's own, or a newer version of a view adopted for a person's namespace that revokes more). Each run is admitted again from its next header, so its chain is walked again under the revocation, and a revoked **issuer** ends the runs of the keys it certified. Such adoptions are rare, and a run's header rides again within a second.

## 8. What a receiver does

### 8.1 Order of checks

For each push Interest under its group, and each frame off a ring it attached, a receiver:
1. takes only `<group>/32=sync/32=signal/<digest>` whose digest is the SHA-256 of the ApplicationParameters (a ring frame is taken as is), at most 1,024 octets, else `malformed`;
2. if sealed: looks the KeyId up among the signal keys of the scopes it subscribes to (asking `signal_scope` of every subscribed scope again when the id is unknown, at most once a second, and every 5 s while known ids arrive), else `unknown_key`, dropped undecrypted, as is a packet under a superseded epoch's key past its grace (§4.2); opens the seal and decodes the body, else `malformed`; the key gives the scope, and a body whose ScopeDigest is not that scope's is refused (`malformed`);
3. decodes the SignalBody, else `malformed` (an unknown critical element, a ScopeDigest of another length, or a `/1` body that starts with the scope's Name are `malformed`). An unsealed body names its scope by ScopeDigest: the scope is the one subscribed here with that digest, and a digest of no subscribed scope is `unsubscribed`. It refuses an unsealed body for a sealed scope (`malformed`);
4. finds the run by RunId:
   - while the run's header is being admitted, the packet waits behind it, in arrival order, at most 32 packets per run (beyond: `unknown_run`). Once the run is held they are processed in that order from step 5; if the header is refused, each is counted with the header's refusal;
   - if no run is held and the body carries a header, the receiver admits nothing before the packet proves possession of the run key. In order:
     1. it checks that `RunId` is SHA-256 of `RunKey` truncated to 16 octets (else `bad_signature`);
     2. it checks that the header's name is the run header of this RunId and of the scope the packet's digest resolved to in step 3 (else `malformed`): the header's scope is where the run is held, so a header of S1 carried in a packet claiming S2 is refused here (§13.9);
     3. it checks that `RunNotAfter` plus the clock skew allowed is not past (else `expired`) and is at most 24 h plus that skew ahead (else `malformed`);
     4. it takes one signature check from the scope's and the process's budgets for packets not verified yet (§10, else `flood`);
     5. it verifies the packet's `RunSignature` under the header's `RunKey`, else `bad_signature`. This is the proof of possession (§3.1);
     6. it asks `signal_sender`, offline: the signer's key must be a member (else `not_member`; `unknown_run` when no record is held yet), and this gives its namespace;
     7. it takes an admission slot: at most 8 headers per scope and 2 per sender namespace are admitted at once (beyond: `flood`);
     8. it admits the header through `signal_admit`, which verifies the chain (§7).

     A refusal is counted (`bad_signature`, `not_member`, `malformed`; `unknown_run` when the record isn't held yet or the certificate isn't to be had now) and the run is not held. Holding it obeys §8.4. The packet that carried the header verified at sub-step 5, and is not verified again;
   - if no run is held and no header rides: `unknown_run`, dropped unverified;
   - a held run's packet whose digest is not its scope's is `malformed`; a header-only packet of a held run is done; a packet past its run's `RunNotAfter` plus the skew is `expired`; a sequence below `RunStart` is `malformed`;
5. applies the replay window (§8.2, `replayed`), then takes one signature check from the scope's and the process's budgets for packets not verified yet (§10, `flood`). A flood of copies costs no verification. A flood of forgeries spends only the budgets of unverified checks, never the budgets of verified traffic;
6. verifies the RunSignature, else `bad_signature`;
7. checks `signal_member(scope, sender)`, else `not_member`, and the run is let go;
8. checks the window again (a copy may have been taken meanwhile, `replayed`); charges the run's and the scope's receive rates of verified packets (§10, `flood`); and marks the packet's sequences seen;
9. for each signal: drops it if `Expires` plus the clock skew allowed (30 s by default) is past (`expired`), or if `Expires` is more than 60 s plus that skew ahead (`malformed`); drops it if a newer signal of the same sender and address was delivered (`stale`); otherwise delivers it to every subscriber of the scope and notes its sequence as the newest for (sender, address).

A packet marks its sequences as seen in the run's window only once it passes step 8, so a forged copy can't burn an honest packet's sequences. A forged copy also can't use up the run's receive rate.

### 8.2 Replays

Each run keeps a window of the 1,024 highest sequences seen. A sequence already seen, or below the window, is a replay. A sequence below `RunStart` is malformed. The window lives as long as the run is held. A receiver that forgot a run (it restarted, or the run was replaced) bounds replays by `Expires` alone (§13.2).

### 8.3 The newest per address

A receiver delivers a signal only if its sequence is above the last one delivered for the same (sender, address), across the sender's runs. Under loss and reordering, a later arrival of an older signal is dropped as stale. A subscriber that reads slower than signals arrive gets the newest per (sender, address), never a backlog: a newer signal for a pair still unread replaces the unread one in place.

### 8.4 Runs held

A receiver lets go of a run once its `RunNotAfter` plus the skew is past. It holds at most:
- **4 runs per sender key.** A newly admitted run of a key at this cap replaces that key's run with the lowest `RunStart` if its own `RunStart` is higher. Otherwise it is refused (`flood`).
- **16 runs per sender namespace** (the namespace `signal_sender` gives). A person listed by a writer prefix can certify as many keys and devices as it likes, but they all fall in one namespace.
- **64 runs per scope.**

At the namespace cap or the scope cap, the receiver first lets go of every run there whose sender is no member now (`signal_member`), so a removal frees the removed member's slots at once. Failing that, it lets go of the run whose last verified packet is oldest, if that was at least 60 s ago (`RUN_IDLE`). Otherwise the new run is refused (`flood`). A run whose packet fails `signal_member` is let go at once (§8.1 step 7). So is every run when `signal_revocations` moves (§7).

## 9. Sending

`SignalRun::send` (and `send_batch`, `send_for`):
1. checks the device's membership and refreshes the scope from `signal_scope` (its groups, its keys), refusing as §7 says;
2. checks the limits (§10): `TooLarge`, and `RateLimited { retry_after }` for the run's packet rate or the process's push budget (§5.2), each spent only with the other;
3. builds the SignalBody (the header if due), signs it, and seals it in a sealed scope;
4. pushes one Interest per group (§5.2), and publishes the packet on the run's ring.

A run's own signals are never delivered to its own process: the forwarder never returns an Interest to the face it came from. A sender that wants its own echo reads it from its own state.

## 10. Limits

| What | Limit | Over it |
|---|---|---|
| Address / payload / packet | 64 / 768 / 1,024 octets; 32 signals per packet; address + payload at most 802 | sender `TooLarge`; receiver `malformed` |
| Scope name | at most `SCOPE_MAX` = 384 encoded octets (§4.3); a signal's room (address + payload) is 802 octets in every scope within it | `ScopeTooLong` at `open` and `subscribe` |
| Expires | at most 60 s after now | sender `TooLarge`; receiver `expired` |
| Run lifetime | at most 24 h (1 h by default), renewed at 90 % | receiver: a header past its `RunNotAfter`, `expired` |
| Sender rate | 120 packets/s per run, burst 30, and the push budget | `RateLimited { retry_after }`: send after it, batch with `send_batch`, or send less |
| Push budget | 80 push Interests/s per process, burst 160 (`SignalOptions::push_rate`, `push_burst`); a packet costs one per group; one send over the burst is let from a full budget | `RateLimited { retry_after }` |
| Sequence | at most 2^64 − 2 | sender `TooLarge`; receiver `malformed` |
| Sealed packet size | padded to a multiple of 128 octets, at most 1,024 | n/a |
| Receiver rate | 240 verified packets/s per run, 2,000 per scope | `flood`, charged once the run signature verifies |
| Signature checks of packets not verified yet | 8,000/s per scope, 16,000/s per process (about 0.8 s of one core); a header's proof of possession takes one too | `flood`, before verification |
| Runs held | 4 per sender key, 16 per sender namespace, 64 per scope; at a cap, runs of senders no longer members go first, then runs with no packet verified for 60 s | `flood` |
| Header admissions | 8 at once per scope, 2 per sender namespace; certificates fetched for at most 2 headers of a namespace at once, none for 30 s for a device whose fetch brought none | `flood`; `unknown_run` |
| Superseded epoch keys | opened for 60 s after this receiver first sees the epoch superseded | `unknown_key` |
| Replay window | 1,024 sequences per run | `replayed` |
| Newest per address | 1,024 (sender, address) pairs per scope; the least recently updated goes | n/a |
| Clock skew allowed | 30 s by default | n/a |

## 11. Wire format

TLV-TYPE numbers 0x0580–0x05AF ([README.md](README.md#tlv-type-numbers)). Every number is even: a decoder MUST skip an unknown even TLV inside these records and MUST refuse an unknown odd one, as in [data-layer.md](data-layer.md) §16.2. Numbers are NonNegativeInteger as in NDN.

| Type | Name | Value |
|---|---|---|
| 0x0580 | SignalBody | ScopeDigest, RunId, [RunHeader], Signal* (0–32; at least one unless RunHeader rides), RunSignature |
| 0x0582 | SignalSealed | KeyId, SealNonce, Ciphertext |
| 0x0584 | KeyId | 8 octets |
| 0x0586 | SealNonce | 24 octets |
| 0x0588 | Ciphertext | XChaCha20-Poly1305 ciphertext of `SignalBody [SignalPadding]`, with its 16-octet tag appended |
| 0x058A | RunId | 16 octets |
| 0x058C | RunHeader | the run header's whole Data wire |
| 0x058E | Signal | SignalSeq, Address, Expires, Payload |
| 0x0590 | SignalSeq | NonNegativeInteger, at most 2^64 − 2 |
| 0x0592 | Address | 0–64 octets |
| 0x0594 | Expires | NonNegativeInteger, ms since the Unix epoch |
| 0x0596 | Payload | 0–768 octets |
| 0x0598 | RunSignature | 64 octets, Ed25519 |
| 0x059A | RunHeaderBody | RunKey, RunStart, RunNotAfter, [LocalRing] |
| 0x059C | RunKey | 32 octets, Ed25519 public key |
| 0x059E | RunStart | NonNegativeInteger, µs since the Unix epoch |
| 0x05A0 | RunNotAfter | NonNegativeInteger, ms since the Unix epoch |
| 0x05A2 | LocalRing | 32 octets |
| 0x05A4 | SignalPadding | octets, ignored (zero when sent); only inside a Ciphertext, after the SignalBody |
| 0x05A6 | ScopeDigest | 16 octets: the first 16 of SHA-256 over `"ndn-signal/2 scope"` and the scope's Name TLV (§4.1) |

```
SignalPacket  = SignalBody / SignalSealed
SignalBody    = SIGNAL-BODY TLV-LENGTH ScopeDigest RunId [RunHeader] *32Signal RunSignature
                ; at least one Signal unless RunHeader is present
SignalSealed  = SIGNAL-SEALED TLV-LENGTH KeyId SealNonce Ciphertext
SealedPlain   = SignalBody [SignalPadding]   ; the plaintext of Ciphertext
Signal        = SIGNAL TLV-LENGTH SignalSeq Address Expires Payload
RunHeaderBody = RUN-HEADER-BODY TLV-LENGTH RunKey RunStart RunNotAfter [LocalRing]
```

Run header name: `<device>/32=signal/<scope>/32=run/<RunId>`. Local ring surface name: `<scope>/32=signal/32=ring/<RunId>`. Push Interest name: `<O>/32=sync/32=signal/<ParametersSha256Digest>`.

## 12. Errors

| Refusal | When | What to do |
|---|---|---|
| `NotMember { scope, why }` | this device is not a member by the record in force, or its key is revoked | ask the scope's owner to share it with this person or device |
| `NotReady { scope, why }` | no record over the scope held yet; or sealed and the key of the epoch in force not held yet (its ask is started) | ask again later (`NextStep::RetryLater`) |
| `TooLarge { what, size, max }` | an address, payload, batch or ttl over its limit, or a batch whose sequences would run past 2^64 − 2 | send less, or put a version |
| `ScopeTooLong { scope, size, max }` | the scope's name is over `SCOPE_MAX` (384) encoded octets, or over what this device's own run header leaves (§4.3) | name the folder or collection with a shorter name (`NextStep::FixName`) |
| `ScopeDigestCollision { scope, other }` | `subscribe`: another subscribed scope has the same 16-octet scope digest (§4.1) | drop the subscription to `other` first, or name `scope` otherwise (`NextStep::FixName`) |
| `RateLimited { retry_after }` | over the run's sending rate, or over the process's push budget (packets × groups, §5.2) | send after `retry_after`, batch with `send_batch`, or send less |
| `Closed` | the run or the process's signals ended | open a new run |
| `Io(why)` | the forwarder connection or the local ring failed | reconnect |
| `Data(DataError)` | the data layer refused the scope for another reason (a bad name, a local fault) | what the data error's own next step says |

A receiver never answers a sender. It counts and logs (at `debug`, with the reason and what would admit the packet) every packet and signal it drops: `malformed`, `unknown_key`, `unknown_run`, `unsubscribed`, `bad_signature`, `not_member`, `replayed`, `stale`, `expired`, `flood`.

## 13. Threat notes

### 13.1 A forged sender

A member can't make signals that are delivered as another member's. A packet is delivered under the run whose RunId it carries. The RunId is the hash of exactly one run key. The run key is bound to its sender by a header that sender's device key signed. A receiver admits that header only from a packet that the run key itself signed (§3.1, §8.1 step 4). Signing a header is not enough: a member who copies another run's public key into a header of its own can't sign a packet under it, so its header is refused (`bad_signature`) and claims nothing. This holds for every receiver, including one that never held that run: one that subscribed late, restarted, or lost the run's first packet. It also stops a forged `RunStart` or `LocalRing` from being set for someone else's run. Forging therefore needs the other member's run secret key, or their device key. A sealed scope's signal key is shared by every reader, so any reader can make ciphertext that opens. It still can't make a RunSignature that verifies under another member's run key: the seal gives confidentiality, the run key gives authenticity. A non-member can't get a header admitted. `signal_sender` refuses its key before anything is verified, and `signal_admit` verifies the device key's chain to an anchor. Its packets are dropped at step 4 (`unknown_run`) or refused there, without verifying their bodies. A local process gains nothing from local delivery: frames off a ring are verified exactly like pushed packets, and a ring's mapping is read-only to its readers.

### 13.2 Replay

Within a held run, the window refuses every sequence it has seen, and a sequence only counts as seen after its packet verified. So a copy, from a relay or the forwarder's second path, is delivered at most once. Across a receiver's restart (or a run it let go), a replayed packet of a run whose header still rides in the replayed traffic can be admitted again. Its signals are still dropped once their `Expires` (plus the clock skew allowed) is past. A replay can thus show a signal at most once more, and only within its own validity: by default 2 s plus 30 s of skew. An application whose signals must never be replayed, even this way, uses versions instead. A replay into another scope fails (§13.9).

### 13.3 A removed member

A removal is a members record. A receiver checks membership on every packet against the record in force, so the first packet it checks after it holds the removing record is refused, and the removed member's run is let go. At a run cap, a removed member's runs are let go first (§8.4), so its slots are free at once. The same holds for the sender's own `send`. In a sealed scope, the removal starts a new epoch whose key the removed member never gets. Senders that hold the record seal under the new epoch's key, which the removed member can't open. Until a sender holds the removing record it may still seal under the old epoch. The removed member can read those packets, as it could read the old epoch's versions. A receiver opens packets under the old epoch's key only for 60 s after it first sees the epoch superseded (§4.2). After that, the removed member can't make a packet any receiver opens, not even a header that would take an admission slot. Membership comes from the signed record, never from timing: a receiver that doesn't hold the record yet still admits the member, and admits no one else. The grace only bounds how long a superseded key still opens packets.

### 13.4 A stolen run key

A run key lives only in its sender's memory. A thief who takes it can sign packets of that run until `RunNotAfter` (1 h by default, at most 24 h). It can send sequences the honest sender hasn't used yet, and receivers keep whichever packet arrives first for a sequence. It can't open a new run or extend this one: that takes the device key. It can't move the run into another scope: the device-signed header names the scope, and the run signature covers the scope's digest (§13.9). Removing the device, or revoking its key or an issuer above it, ends the stolen run on every receiver that holds the record or revocation (§13.3, §7). Short runs bound the exposure: a sender that suspects its process memory SHOULD open a new run and let the old one lapse. A stolen **device** key is the data layer's revocation case. Once a receiver holds the revocation, `signal_member` refuses the key's runs at once, and `signal_admit` admits no new header signed by it. Once it holds an issuer's revocation, every run is let go and admitted again from its next header (§7), and those certified by the revoked issuer are refused.

### 13.5 Flooding and denial of service

- **Before verification:** a receiver drops a packet that is oversized, malformed, sealed under an unknown key or a superseded one past its grace, of an unknown run without a header, or a replay. A flood of such packets costs a decode and a table lookup each, never a signature check or a decryption under a guessed key.
- **Forged packets of a held run:** whoever knows a RunId can push packets that carry it with fresh sequences and a bad signature. This is any relay or local process in an unsealed scope, and a member or a removed member within its grace in a sealed scope. Each such packet costs one Ed25519 check, taken from a separate budget for packets not verified yet: 8,000/s per scope and 16,000/s per process. The run's and the scope's receive rates are charged only once a packet verifies (§8.1 step 8), and only a verified packet marks sequences seen. Forgeries below that budget therefore cost CPU only, and the genuine sender's packets are all delivered. A flood above it, about 8 MB/s of push Interests into one scope, also drops the genuine packets as `flood`, as any flood above a receiver's capacity does. The flooder needs that bandwidth at the receiver.
- **Headers:** a header costs a membership check and one Ed25519 check (its proof of possession) before anything else. A stranger's header ends there. So does a header that copies another's run key. A member's header then costs a certificate-chain walk once per run, from the certificates held first. The cost is bounded in four ways:
  - at most 8 headers are admitted at once per scope and 2 per sender namespace, so headers naming one namespace's devices can't hold another's slots;
  - a certificate not held is fetched for at most 2 headers of one namespace at once;
  - none is fetched for 30 s for a device whose last fetch brought none, so a fresh key id per header drives no fetch per header;
  - a header whose certificate is held is admitted without a fetch and needs no fetch slot.

  An outsider who pushes headers naming random keys of a member's devices, which an unsealed scope permits, can hold that one namespace's 2 fetch slots. It then delays only that namespace's devices whose certificates aren't held here yet, never other namespaces or devices whose certificates are held.
- **Runs held:** a sender key holds at most 4 runs, a sender namespace 16 and a scope 64. One person's many keys or devices therefore can't fill a scope. At a cap, runs of senders that are no longer members are let go first, then runs idle for 60 s (§8.4).
- **A member flooding:** a member can send up to the receive rate (240 verified packets/s per run, 2,000 per scope) before its packets are dropped. Its own device refuses beyond 120/s. Each delivered signal costs one Ed25519 verification per packet (about 50 µs) and replaces the sender's previous signal for that address, so a slow subscriber never queues a backlog. The owner removes a member who abuses this.
- **The network:** a push Interest lives 1 s in a PIT and has HopLimit 8. A forwarder's ordinary Interest limits apply to it as to any Interest. A relay under quotas counts a device's pushes against its per-key quota; the push budget keeps a device's signals inside it (§5.2), so its Data, sync and certificate traffic isn't dropped for them.
- **The local ring:** its attach handshake refuses a process without the secret. ndn-surface's handoff stops serving new readers after 16 refused attaches. A local process can thus block later local attaches to a run, never its pushes. Readers that can't attach still get the pushed copies.

### 13.6 What relays and others see

A relay forwarding a push Interest sees:
- the group: the namespace of a member, as it already sees for sync notices;
- **the sender's device, at the first hop.** The relay a device links to knows the link's authenticated identity, and so whose packets these are. Relays further on see the link they came over;
- **which namespaces share a scope.** One packet goes out into every group of the scope with the same parameters digest (and, sealed, the same KeyId), so a relay that carries two or more of those groups links them;
- **how many runs are active.** The header rides in a packet about once a second per run and adds about 300 octets. Even sealed and padded, a relay can count those larger packets, and so the runs;
- the packet's timing and rate, and its size: exact in an unsealed scope; in a sealed scope only to its 128-octet bucket (§4.2), so a cursor and a presence update of similar size look alike;
- in a sealed scope, the 8-octet KeyId (constant over an epoch, so packets of one scope and epoch can be linked to each other), the nonce and the ciphertext.

In a sealed scope it doesn't see the scope's name, nor its digest (inside the seal, as the name was on the `/1` wire), the sender's key (beyond what the first hop knows of the device), the run, the addresses or the payloads: the run header travels inside the seal. In an **unsealed** scope everything in the packet is plain to every forwarder on the path. That is now a **digest** of the scope name in every packet, and the scope's Name itself only in the packets that carry the run header (about once a second per run, in the header's name `<device>/32=signal/<scope>/32=run/<RunId>`), together with the sender's key name. On the `/1` wire every packet carried the Name. A relay that has seen one header packet of a run reads the scope's name for every packet of that run, as before. A relay that has seen none and holds a candidate name can confirm it against the digest, and can't invert the digest. An unsealed scope's signals are as public as its versions: seal the scope to keep them private. A relay can drop or delay packets, or replay them (§13.2, §13.9), and can't forge or alter one (§13.1).

On the host, the forwarder's multicast delivers the push to every local face that registered the group, so any local process can register it. In a sealed scope it learns what a relay learns. In an unsealed scope it reads the packets, as a relay could.

### 13.7 Carriage

Signals never travel as Data. A future signal answer (for example a header asked for by name) MUST carry NDNLPv2 `CachePolicy = NoCache`, which the ndn-rs forwarder honours (`stages/cs.rs`). This spec defines none.

### 13.8 Clocks

`Expires` and `RunNotAfter` are read on the receiver's clock with the skew it allows. A receiver whose clock runs more than that skew ahead of a sender's drops the sender's signals as expired. One running behind admits them longer, and replays (§13.2) longer with them. Membership, authenticity and replay decisions come from signed data and the window alone.

The clock decides two more things, both about liveness, never about who is a member:
- **Live admission.** A header is admitted only while the signer's certificate chain is valid on the receiver's clock (§15). A run admitted earlier is held until its `RunNotAfter`, at most 24 h, even if the certificate expires in between. Its renewal needs a valid certificate.
- **Superseded epochs.** A superseded epoch's key opens packets only for 60 s after this receiver first saw the epoch superseded (§4.2).

### 13.9 The scope digest

After a run's header, a packet names its scope by a 16-octet digest (§4.1) and the scope's Name travels only in the device-signed header's name (§3.2). This is what each party binds, and why a packet can't be used in another scope.

**What binds what.**
1. The **run signature** covers the packet's ScopeDigest, RunId and signals (domain `"ndn-signal/2"`, §4.1). Nobody without the run's secret key can change the digest of a packet, or put another's signals under a digest.
2. The **run header**, signed by the sender's device key, binds the RunId (the hash of the run key) to the scope: its name holds the scope, and its content holds the run key. A receiver admits it only from a packet the run key signed (§3.1).
3. A **receiver holds a run in one scope only**, the scope of the header it admitted: a packet of that run is judged only if its digest is that scope's (§8.1 step 4), and a run is held only if the header's name gives the scope the packet's digest resolves to (§8.1 step 4).

**A packet replayed into another scope fails.** Take a packet P of run R in scope S1, replayed so that it claims S2.
- *If the receiver holds R*, it holds it in S1. P's digest resolves to S2 (the receiver subscribes to both), and S2 is not R's scope: `malformed`. The signature isn't reached, and if it were, altering the digest invalidates it (`bad_signature`).
- *If the receiver doesn't hold R* and P carries R's header: the header's name says S1, the packet says S2: `malformed`, before anything is verified or admitted.
- *If it carries no header*: the run isn't held, `unknown_run`.
- *A member who signs a header of his own for S2 that binds R's run key* gets nowhere: he can't sign a packet under R, so his header is refused (§3.1, §13.1).
- *Sealed scopes*: the key gives the scope, so a packet sealed under S1's signal key is opened only as S1's; a member of both scopes can re-seal the plaintext under S2's key, but can't re-sign it, and the digest inside names S1.

So the property `/1` had by signing the scope's name, that a packet can't move to another scope, is kept by the signed digest and the device-signed header together, and nothing about a replay within S1 changes (§13.2).

**Collisions.** The digest is the first 16 octets of SHA-256 over a domain tag and the scope's Name TLV. The tag keeps it apart from every other use of SHA-256 here (RunId, parameters digests). Two scope names with one digest cost about 2^64 evaluations to find, and only a party that owns both names (their data markers sit in the owner's namespace, so a scope name chosen by one owner) could find one for its own two scopes; a collision with another's existing scope is a second preimage, 2^128. A receiver subscribes to at most one scope per digest (`ScopeDigestCollision`), so even such a pair confuses no receiver: both would need the same subscriber.

**What it doesn't do.** The digest hides nothing: in an unsealed scope a relay that holds a candidate name confirms it; in a sealed scope the digest is inside the seal. It doesn't make a header cheaper to forge or to admit (§8.1 step 4, §13.5). And a receiver that never saw a header of a run can't tell which scope an unsealed packet of it is meant for beyond the digest, so it holds the packet as unknown (`unknown_run`), as before.

## 14. Conformance

Conformance cases (ndn-sim `ndn-data-conformance`, ids `e1`–`e16`) cover:
- a member's signals reaching the other members over the network;
- a non-member that can neither send nor receive;
- a member that can't forge another's signals;
- replays refused;
- a removed member stopped at once;
- a sealed scope whose relay sees only ciphertext;
- nothing in any content store;
- the newest per address under loss;
- a commit turning live work into one version;
- 60 Hz with several senders.

Cases added after the round-4 review:
- **e11:** a member's header claiming another member's run is refused at a receiver that doesn't hold that run yet;
- **e12:** a flood of headers naming keys whose certificates can't be had doesn't keep a genuine new run out;
- **e13:** forged packets of a held run don't starve its genuine packets;
- **e14:** one namespace's many runs don't fill a scope, and a removal frees its runs' slots at once;
- **e15:** a packet at sequence 2^64−1 breaks nothing;
- **e16:** a revoked issuer ends the runs of the keys it certified.

Case added with the scope digest wire (`ndn-signal/2`):
- **e17:** a scope named with as many octets as `SCOPE_MAX` allows, sealed and unsealed, still carries a signal of 512 octets from sender to receivers, and a scope one octet over is refused at `open` and `subscribe` with the limit stated.

ndn-surface's tests cover the local leg over shared memory and one link between two engines. The real-daemon end-to-end scenario `signals` (ndn-fwd `testbed/e2e`) carries cursors between two people through a relay that holds no context of theirs and has no route set by hand.

## 15. Decisions

- **Push into the sync groups, not a new prefix.** The groups already reach every member's devices through every relay with no configuration ([data-layer.md](data-layer.md) §12). A second per-namespace prefix would need the same routes, strategy choices and transit lifecycle added to the link and trust-context libraries. Sharing the group costs each SVS face a parse of the signal Interests it ignores, and each signal receiver a parse of the Sync Interests it ignores.
- **An asymmetric run key, not a shared one.** A symmetric key shared with the receivers would let any member forge any other's signals (ndf-rs, REPLY-to-ndn-workspace-1 §E). Signing every packet with the device key would make a chain walk per sender and expose the device key to a 60 Hz signing loop. A run key costs one Ed25519 signature per packet.
- **Sign, then seal.** A relay then sees no sender identity, and a member can't strip and re-sign another's packet without its run key.
- **XChaCha20-Poly1305 with random nonces.** One signal key serves every sender of an epoch, and an epoch can last months. A 24-octet random nonce keeps collisions negligible at any packet count.
- **The header rides inline, about once a second.** No pull path, so nothing about a signal is ever answered or cacheable. A receiver that lost the header waits at most a second, and packets it can't place cost nothing to drop.
- **Membership checked per packet, synchronously.** "A removed member stops at once" then means: at the first packet after the record is held, independent of any event delivery.
- **Proof of possession before admission.** A header binds a run key with the device key's signature, but anyone who reads the header can copy that run key into a header of their own. Admitting a header only from a packet its run key signed closes that gap for one Ed25519 check, the same check every packet costs anyway (round-4 review H1).
- **Live admission by the live rule.** Versions are judged by the durable rule, so that a version once accepted stays accepted after its certificate expires. A signal is never stored, so nothing needs its verdict to outlast the moment. Under the durable rule an expired but unrevoked device key could open runs for as long as nobody revoked it. Under the live rule ([trust-context.md](trust-context.md) §6.3, live uses) it opens none once its certificate expires. Of the two this is the conservative choice, and it is the rule live exchanges already use. Its cost is a sender whose certificate lapsed: it can't open runs until its device renews the certificate, and receivers log `bad_signature`, saying an expired certificate is one cause.
- **Budgets of forgeries apart from verified traffic.** A receiver can't tell a forgery from a genuine packet before verifying it. So the CPU that forgeries may spend is capped separately, well above the verified rates, and the verified rates are charged only after verification. A forger then has to outrun the CPU budget, not one run's 240/s, to starve a sender.
- **Caps per namespace, not per key.** Keys and devices are free for a person listed by prefix, and namespaces are not. A removal or a revocation frees slots through `signal_member` and `signal_revocations`: signed data, read at the moment a slot is needed.
- **A push budget per process, counted per group.** Each packet is one Interest per group, and a relay under quotas counts each. Budgeting packets × groups below the relay's default quota keeps a 60 Hz sender from crowding out its own device's Data and sync. The alternative, batching automatically inside `send`, would need a flush timer per run and would hide latency from the application. With the budget, the application sees `RateLimited` and batches itself.
- **Pad sealed packets to 128-octet buckets.** It costs at most 127 octets and no copy, and it hides which kind of small signal a packet carries. Larger buckets (powers of two) would double the octets of a 60 Hz stream for little more. The header's size and the rate of headers still show the number of runs (§13.6).
- **Name the scope by digest after the header (round 4, N9).** On the `/1` wire every packet carried the scope's whole Name, so a scope named in words left a 512-octet signal no room, and an application had to count the name's octets itself. The Name now rides once, in the device-signed run header; later packets carry a 16-octet digest of it. A signal's room is then the same in every scope (802 octets of address and payload), and a scope's length costs only the header packet, bounded by `SCOPE_MAX` (§4.3). The alternatives each lose something. A numeric scope id assigned by the sender would need a binding that the signature covers anyway, which is the digest, but would not be checkable by a receiver from the scope it subscribes to. A shorter header, by dropping the scope from its name, would break the rule that a validator picks the trust context by the packet's name (§3.2). A digest checked against the name in the signed header, the run signature covering the digest, and a receiver that holds a run in one scope only, bind every packet to its scope with no new trust (§13.9).
- **Sixteen octets of digest.** The digest is not a secret and need not resist more than a collision between two scopes that someone owns: 2^64 work for a collision of two chosen names, 2^128 for a second preimage of a victim's scope. A receiver refuses to subscribe to a second scope of an equal digest, so even an owner who found one gains nothing at a receiver. More octets would cost every packet, 60 times a second, for no gain.

[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119
[RFC 8174]: https://www.rfc-editor.org/rfc/rfc8174
