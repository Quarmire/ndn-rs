# Invite: introductions to a space by a code

- **Status:** Normative. The introductions of `ndn-invite`: a stranger who holds
  only a code joins a [heap](heap.md) space, with no second gesture by the owner
  and no prior trust either way. It carries over the protocol of the former
  data layer's §19 ([history/data-layer-remainder.md](history/data-layer-remainder.md): offer, code, ask, answer, proofs, short
  codes, hint records, grants, departures) onto the space of `ndn-heap`, and
  changes three things: an offer is **no longer a log entry** (§5), the
  inviter's effect on the space is **one `Heap::change`** whose entry the answer
  names (§9.4), and a joiner is told it may write only when it holds the entry
  that admitted it (§8.5). The TLV numbers and the wire of the exchange are kept
  (§16); the labels of the cryptography are renamed (§4.5). The formats are
  incompatible with the removed `ndn-data`'s only in those labels, the offer's name and the
  answer's `ADMITTED` field (§20).
- **Scope:** the exchange between an **inviter**'s device and a **joiner**'s
  device; what the inviter's device keeps and signs; the code's three forms; the
  hint record behind a short code; the grants and mirror grants that follow the
  membership; the departures; the host trait `Host`; the introduction surface
  and the folder-scope predicates a link layer filters by; the policy. The Rust
  contract and its reference implementation are the `ndn-invite` crate
  (`crates/app/ndn-invite`: `Invites`, `Host`, `Surface`); conformance cases are
  heap.md §13.5 (i1–i26).
- **Out of scope:** what a space is, its members fold, its seal and its grants of
  epoch keys ([heap.md](heap.md)); trust-context encoding
  ([trust-context.md](trust-context.md)); the text forms of a link
  ([trust-envelope.md](trust-envelope.md)); link admission, slots and rates
  ([ndn-link.md](ndn-link.md)); NDNCERT enrollment
  ([ndncert-extensions.md](ndncert-extensions.md)). This crate imports no
  forwarder and no link layer: the host gives both through `Host` (§12).

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174)
when, and only when, they appear in all capitals, as shown here.

## 1. Purpose, model and invariants

### 1.1 Purpose

The owner's device makes a one-use **offer** to a space and shows its **code**.
The joiner's device sends an **ask**, sealed to the offering device, that proves
the code's secret bound to its own key. The offering device **answers**: it has
its host adopt the asker's anchor, adds the asker's person to the space's
members with **one members entry**, and names that entry in the answer. The
joiner has its host adopt the inviter's anchor, opens the space, and returns
once it may write there. Each side's host may then link with the other
(§10).

Everything a side decides, it decides from what it holds, signed and durable:
the code's secret, the signed offer, the signed credentials, the members entries
of the space. No decision is taken because a forwarder, a cache or a relay said
so (invariant 1 of heap.md §1.3 holds here too).

### 1.2 The model

- The **inviter** is a device `D` of a namespace `O` (a **person**, heap.md
  §1.2) that is an **owner device** of the space `S` it offers
  (`S = <O>/32=data/…`, heap.md §2.1). Only an owner device signs a members
  entry, so only an owner device can offer.
- The **joiner** is a device `J` of a person `P` that the space does not list
  yet and that holds no trust of `O` yet. `P` is a namespace the joiner's host
  can adopt (`Host::adopt`, §12) or a self-certifying namespace `/user/<h>`
  adopted from its genesis (§9.3).
- An **offer** is a signed Data `<D>/32=intro/32=offer/<id>` (§5.1) naming the
  space, the role it grants (reader or writer), its expiry, its count of wrong
  tries, the **commitment** to its secret and the inviter's seal key. It holds
  nothing secret: the secret is in the code only.
- A **code** is what the inviter shows the joiner: a link, a words form or a
  short code (§6). The three carry the same 16-octet secret and the same anchor
  fingerprint.
- An **ask** is an Interest `<D>/32=intro/<ParametersSha256Digest>` whose
  ApplicationParameters are the ask, sealed to the offering device (§8.2).
  The **answer** is the Data that answers it (§9).
- A **hint record** is the Data `<D>/32=hint/<token>` a short code names (§7).
- The inviter's **host** and the joiner's **host** are the objects behind
  `Host` (§12): the trust anchors, the link layer, the link hint.
- The **surface** is what a link layer may carry for introductions, grants and
  departures (§13).

### 1.3 Invariants

Every implementation MUST hold all of these.

1. **Fail closed.** Anything that does not check is refused or left unanswered,
   never accepted on a guess. An error before the exchange's last durable step
   leaves the offer as it was.
2. **One offer, one key.** An offer admits at most one asker key, ever. A second
   key presenting the same offer, before or after a restart, is `Used` and counts
   nothing (§9.2 step 6, §9.5).
3. **A try is counted before it is answered.** A wrong proof is counted in
   durable storage before any reply is sent; a restart never gives an asker its
   tries back (§9.6).
4. **The secret never travels in the clear.** It is in the code, in the
   commitment only as a hash, and inside the sealed ask only as an HMAC under a
   key derived from it (§4).
5. **Authority is in the data.** A grant follows the space's members entries and
   nothing else: removal from the space ends the grant and tells the person
   (§10, §11). A grant never widens what the entries admit (§10 rule 5).
6. **A name is not a guess.** An offer is named by 16 random octets; the surface
   is two prefixes; an Interest that names nothing the device holds for the
   asker is met with silence (§2.3, §18).
7. **Every refusal says why and what to do** (`InviteError::next()`, §17).
8. **Nothing is lost by a lost answer.** The same key asking again is answered
   again, whatever happened to the first answer (§9.5, §8.6).

### 1.4 Clocks

An offer's expiry, the pause between wrong tries counted toward the overall cap,
a departure mark's end and a grant's date are judged by **the offering device's
clock** (`Node::now`, heap.md `Config::clock`), alone. No other decision of this
crate reads a clock. A clock that is slow keeps an offer open longer and counts
toward the cap more slowly; a clock that is fast does the reverse (§18). The
joiner's waits are bounds on how long it waits, never reasons for a verdict
(§8.5).

### 1.5 Non-goals

- **No second use.** An offer admits one key. To invite two people, make two
  offers.
- **No offers in the log.** A space's log holds the membership the offer made,
  never the offer or its use (§5).
- **No migration.** An offer, code state or grant note of the removed `ndn-data` is not read:
  state lives under `/localhost/ndn-invite/` (§15) and a code made by
  `ndn-data` (whose labels differed, §4.5) is refused as one that does not check.
- **No custody of the code.** The device keeps no secret (§5.2); a lost code is
  a closed offer and a new one.
- **No authentication of refusals.** A refusal on the wire denies, never admits
  (§18).
- **No routing.** What a link layer routes for a joined space, and what a
  forwarder carries, is the host's; this crate says what the introduction
  surface may carry and what a grant lets a link name (§13).

## 2. Names and packets

`D` is the offering device, `J` the asking device, `O` and `P` their namespaces,
`S` a space, `E` an entry's name. `32=` is a KeywordNameComponent (TLV-TYPE
0x20), as heap.md §2. Names under `/localhost/ndn-invite/` are the keys of a
node's store (§15) and MUST NOT be served, announced, or accepted as the name of
any packet received.

### 2.1 Name classes

| Packet | Name | Content | Signature |
|---|---|---|---|
| offer | `<D>/32=intro/32=offer/<id>`, `id` one GenericNameComponent of 16 octets | one `INTRO_OFFER` (§16) | a key of `D` (through `Node::sign_packet`) |
| ask (an Interest) | `<D>/32=intro/<ParametersSha256Digest>` | ApplicationParameters: one `INTRO_ASK` | — |
| answer | the ask's name | one `INTRO_ANSWER` (§16) | DigestSha256 (the offering device's proof is inside) |
| asker's proof (inside an ask or an answer; never fetched) | `<A>/32=ask/<binding>`, empty Content, FreshnessPeriod 0 | — | the signer's device key |
| hint record (§7) | `<D>/32=hint/<token>`, `token` one GenericNameComponent of 16 octets | one `INTRO_HINT` | a key of `D` |

An offer's `<id>` is the only part of its name that is not derived from `D`; it
is drawn from the device's entropy and is not a sequence number (§18).

### 2.2 Parse rules

Every name parses one way, and a node MUST refuse a name that does not parse.

- **Offer.** `D` is the components before the first `32=intro` (a device name,
  no keyword); then the keyword `32=offer` (a KeywordNameComponent, as `32=intro` is) and
  one GenericNameComponent of 16 octets, and nothing after.
- **Introduction ask.** `D` is the components before the first `32=intro`; then
  exactly one ParametersSha256DigestComponent, the SHA-256 of the Interest's
  ApplicationParameters TLV, whose value is one `INTRO_ASK` TLV: one
  `EPHEMERAL_KEY` and two `CIPHERTEXT`, the wrapped content key, then the sealed
  `AskBody`. The ask travels in the parameters, not the name: its credentials
  take a few KB, and a link reads an Interest's name from its first fragment. An
  ask whose digest is not its parameters' is no ask.
- **Hint record.** `D` is the components before the first `32=hint`; exactly one
  GenericNameComponent of 16 octets follows, the token (§4.4), and nothing after
  it. A longer name, a token of another length or of another component type is
  no hint record.
- **Asker's proof.** `A` is the components before the first `32=ask`, a device
  name; one GenericNameComponent of 32 octets follows, the **binding**: SHA-256
  of the protocol's label, then the offering device's Name TLV followed by the
  ask's fields before its `ASKER`, or the answer's fields before its `ASKER`
  (§8.2, §8.3). The labels are in §4.5. A receiver computes the binding with the
  label of the protocol it expects, so a proof made for one protocol never
  verifies as another's.

The first of these a name can be is decided by the component after `32=intro`:
`32=offer` makes an offer fetch, a ParametersSha256DigestComponent an ask. Nothing
else under `32=intro` is served.

### 2.3 The two prefixes, and silence

The crate registers one `Extension` with `Node::extend` (the sibling surface of
heap.md, documented there as the interface for `ndn-invite` only). The extension is held weakly by the node: once the `Invites` handle and its
clones are gone, it answers nothing. Its keywords are `intro` and `hint`, which
carry the exchange, and `ask`, which only lets the node sign the proof packets
`<X>/32=ask/<binding>` an ask and an answer carry (the node signs only under a
keyword an extension registered, §18.1) and answers nothing under it. The node's
keyword router (heap.md §2.4) hands an Interest whose first keyword is one of them
to `Extension::answer`, and to nothing else. The device's whole introduction
surface is therefore **two prefixes**:

```text
introduction_prefixes(D) = [ <D>/32=intro, <D>/32=hint ]
```

what a link dialled for an introduction routes, and no other name of `D`
(ndn-link.md §13.3, §13.3A). The previous design's third prefix, `<D>/32=held`,
is gone: the offer is fetched directly (§8.2).

**Silence.** `Extension::answer` returns `None` for an Interest it will not
answer, and the node Nacks it as it does every unanswerable name (heap.md §2.4,
§7.6): the same for a name that does not parse, a name that parses and names no
offer or token this device holds, an ask that does not open (§9.2 step 1), an ask whose asker proved no key (step 3) and an
ask that names no offer this device holds (step 4). A refusal that names a reason travels
only inside an answer to an ask that opened and whose asker proved a key (§9.2),
never as the response to a name. A prober who does not hold a code therefore
learns nothing of what the device holds: an offer name is 128 random bits, a hint
token is 128 bits of an HMAC, and a miss looks like every other miss.

## 3. The exchange

One exchange, in the order it happens; each step is specified where it is
referenced.

1. **Offer** (§5). The inviter's `offer(S, { role, until, tries })` draws a
   16-octet secret and a 16-octet id, signs the offer packet
   `<D>/32=intro/32=offer/<id>` with the device key, keeps the proof key, and makes
   the code. It returns the code only once every note it relies on is durable.
2. **Code** (§6). The inviter shows the link, the words form or the short code to
   the joiner out of band. A short code names no offer: it names the inviter's
   device, a first contact and the secret; the offer is named by a hint record
   the inviter makes on request (§7).
3. **Join** (§8). The joiner judges the code before it dials, dials the inviter
   by the link hint or the short code's first contact, fetches the hint record
   when the code is short, fetches the offer, and sends the **ask**: its
   credentials and its proof packet, the proof of the secret bound to its key,
   all sealed to the offer's seal key.
4. **Answer** (§9). The inviter opens the ask, judges it in ten ordered checks,
   has its host adopt the asker's anchor, signs **one members entry** that adds
   the asker's person to the space, keeps the acceptance and the use mark
   durably, makes the grant, and answers with the acceptance: the space, the
   role, the entry's id as `ADMITTED`, its credentials, its proof packet and the
   answer proof.
5. **Admission** (§8.5). The joiner checks the answer against the code, has its
   host adopt the inviter's anchor, opens the space, notes that it was admitted,
   and waits until the fold lists it, the epoch key is held and the `ADMITTED`
   entry is applied. `join` then returns.
6. **After** (§10, §11). The inviter's grant and the joiner's mirror grant follow
   the space's members entries until a removal ends them.

## 4. Cryptography

Audited RustCrypto primitives only (`hmac`, `hkdf`, `sha2`, `subtle`,
`zeroize`, X25519 and Ed25519 through `ndn-security`).

### 4.1 Secret, commitment, proof key

1. The **secret** is 16 octets from the device's entropy (the operating
   system's by default), `SECRET_LEN`. 128 bits stay because an offer's
   commitment is public in the offer packet, and a shorter secret could be
   searched offline.
2. The **commitment** is SHA-256(`ndn-invite/intro/commit/1` ‖ secret).
3. The **proof key** is HKDF-SHA256 with the secret as input keying material,
   no salt, and as info `ndn-invite/intro/proof/1` ‖ the offer's Name TLV: an
   offer's key opens no other offer.
4. The **ask proof** is HMAC-SHA256 under the proof key over
   `ndn-invite/intro/ask/1` ‖ the offer's Name TLV ‖ the asker key's Name TLV ‖
   its public key digest ‖ the nonce.
5. The **answer proof** is HMAC-SHA256 under the proof key over
   `ndn-invite/intro/answer/1` ‖ every field of the acceptance before `PROOF`.
6. Proofs are compared in constant time (`subtle`). The proof key and the secret
   are zeroized when dropped.
7. Asks are **sealed** with heap.md §6.2's X25519-to-ChaCha20-Poly1305 wrap: a
   fresh content key wrapped to the offer's `SEAL_KEY`, and the body sealed under
   it, both binding `<D>/32=intro` (its Name TLV) as associated data.

### 4.2 What the inviter keeps of the secret

The inviter keeps **no secret**. It keeps the proof key, wrapped to its own
recipient key (heap.md §6.2) under `key/<id>` (§15) and authenticated by a MAC under
a key derived from the recipient secret, which is all it needs to verify an ask and to
prove an answer. It never keeps the secret itself, so a copy of its store opens no code.
A note that is not wrapped to the device's own recipient key, or whose MAC does not
check (the recipient key is public, so a wrap is anyone's to make), is ignored, and its
offer answers nothing (§18.1).

### 4.3 The seal key

The offer carries the offering device's `SEAL_KEY`: the X25519 public key of its
recipient key (`Node::recipient`), the key the node's seal key packet carries
(heap.md §6.2). An ask is opened only by the device that holds the matching
secret key.

### 4.4 What a short code adds

A short code adds two derivations and one checksum.

- The **hint token** is the first 16 octets of HMAC-SHA256 under the secret as key
  over `ndn-invite/intro/hint/1`: an HMAC output reveals nothing of a 128-bit
  key, so the name made of it is unguessable without the code and tells nothing
  of it. `HINT_TOKEN_LEN` = 16.
- The **checksum** of a short code's words is the first 12 bits of
  SHA-256(`ndn-trust/intro-short/1` ‖ the bound text ‖ `0x00` ‖ payload) (§6.3).
  It detects a typo; it is no authenticator (it has no key, and anyone can
  compute it for a code of their own), and nothing is trusted on its account.
  This label belongs to trust-envelope.md's short-code family and is not renamed.
- The **fingerprint** is SHA-256 of the anchor's public key (an Ed25519 key's 32
  raw octets, trust-envelope.md §4.4). A short code of a named namespace carries
  not that but its **keyed fingerprint**: the first 10 octets of HMAC-SHA256 under
  the secret as key over `ndn-invite/intro/fp/1` ‖ the whole 32-octet fingerprint
  (§6.4), which the joiner computes again from the anchor of the verified
  credentials and compares in constant time (`Mac::verify_truncated_left`; a tag
  of any other length is no match). The whole fingerprint is carried plain by a
  self-certifying namespace's code and by a link, and a plain 16-octet prefix by
  the words form; they are compared in constant time too.

### 4.5 Labels

The labels are ASCII. The five that bind a proof to a protocol, and the ones that
bind a key or a tag to a code, were renamed from `ndn-data/intro/…/1` to
`ndn-invite/intro/…/1`: a proof, tag or commitment made by the removed `ndn-data`
never verifies here.

| Use | Label |
|---|---|
| commitment | `ndn-invite/intro/commit/1` |
| proof key (HKDF info) | `ndn-invite/intro/proof/1` |
| ask proof | `ndn-invite/intro/ask/1` |
| answer proof | `ndn-invite/intro/answer/1` |
| hint token | `ndn-invite/intro/hint/1` |
| keyed fingerprint | `ndn-invite/intro/fp/1` |
| asker's proof binding, ask (ends in a zero octet) | `ndn-invite intro ask\0` |
| asker's proof binding, answer (ends in a zero octet) | `ndn-invite intro answer\0` |
| grant note MAC key (HKDF) | `ndn-invite/grant-note/mac-key/1` |
| mirror note MAC key (HKDF), and MAC | `ndn-invite/mirror-note/mac-key/1`, `ndn-invite/mirror-note/mac/1` |
| short-code checksum | `ndn-trust/intro-short/1` (unchanged) |

The two binding labels end in a zero octet so none is a prefix of another.

## 5. Offers

### 5.1 The offer packet

An **offer** is a Data packet named `<D>/32=intro/32=offer/<id>` (§2.1), signed by a
key of the offering device through the host surface (`Node::sign_packet`), whose
Content is one `INTRO_OFFER` TLV (§16.1):

| Field | Meaning |
|---|---|
| `Name` | the space `S` it offers: a space name (heap.md §2.3) of the offering device's namespace |
| `ROLE` | the role it grants: 0 reader, 1 writer |
| `KEEP_UNTIL` | its expiry, ms since the Unix epoch, judged by the offering device's clock |
| `TRIES` | the number of wrong tries of one asker key that close it to that key (at least 1) |
| `DIGEST` | the commitment to its secret (§4.1) |
| `SEAL_KEY` | the offering device's seal key, to which asks are sealed |

Nothing secret is in it. `S` MUST be a space whose owner is the offering device's
namespace and the offering device MUST be an owner device of it (it signs the
members entry, §9.4). A reader takes an offer only when the packet's signature
verifies under a key of the offer name's device `D` that chains to the anchor the
code names (§8.2, §8.3 S7); an offer decoded from any other packet is not an
offer.

**An offer is a packet, not a log entry.** It has no seq, it is in no hash chain,
it is listed in no summary or sync vector, and no other device of the inviter
knows it. It lives in the inviter's store under `offer/<id>` and is served by the
extension (§2.3, §5.5). The previous design made an offer an entry of the
offering device's log, so its name `<D>/32=log/<F>/seq=<n>` was guessable and
public; this one cannot be guessed (§18).

### 5.2 What the inviter keeps

The offering device keeps, in its store under `/localhost/ndn-invite/` (§15),
each under a name no device serves:

| Key | Value |
|---|---|
| `offer/<id>` | the signed offer packet, as signed (its Content is the `INTRO_OFFER`) |
| `key/<id>` | the proof key, wrapped to the device's recipient key |
| `hint/<id>` | the hint token, wrapped the same way; only for an offer with a short code |
| `tries/<id>` | the wrong tries counted toward the overall cap (4 octets, big-endian) and when the last was counted (8 octets, big-endian, ms by the device's clock) |
| `tries/<id>/<digest>` | the wrong tries of one asker key, by its public key's digest (4 octets, big-endian) |
| `using/<id>` | while a use is under way, the key it is for: its Name TLV, then the public key's digest (32 octets) |
| `accepted/<id>` | once used, the acceptance it answered (one `INTRO_ANSWER`, §9.3) |
| `used/<id>` | the use mark: one `INTRO_USED` naming the offer, the key the offer was used by and its public key's digest |
| `closed/<id>` | the closing mark: one octet, `1`; the offer admits no one new |

Each is durable (`Node::flush`) before the reply that depends on it (§9.6). `<id>` is the offer's 16 octets as one
generic component (§15). `key/<id>`, `hint/<id>`, `using/<id>`, `used/<id>`, `tries/<id>` and `tries/<id>/<digest>` end in
a 32-octet HMAC-SHA256 over their own key's Name TLV and their value, under a key derived from the device's recipient
secret (§18.1): a note that does not check is **unread** and fails closed (a use mark or use under way: a use by a key
nobody knows; tries: the cap; a proof key: the offer is not held and an ask of it gets no answer), and a note moved to another key does not check. A device writes
`used/<id>` at most once and never changes it (the first mark naming a key stands); `closed/<id>` is written by `close_offer`, by the
overall cap and by a start after an unclean stop or a rollback (§5.4), and writing it again changes nothing. Only the offering device marks its offer: the marks are local,
not served, and authenticated by the MAC, not signed, because nobody else reads them. Other devices of the inviter do not hold an offer they
did not make: an ask of it gets no answer (§9.2 step 4, §18).

### 5.3 Offering

`offer(S, { role, until, tries })` on a device of `S`'s namespace that has `S` open (heap.md §10.2):

1. MUST refuse an `S` that is no space name or that is not open here (`BadRequest`: create it or open it, then offer
   it), an `S` of another namespace (`NotOwner`, from the heap), `tries` = 0 or an expiry already past by its clock
   (`BadRequest`), and a host whose anchor is not this namespace's signed trust context with a chain to this device's key
   (`Local`: fix the host's enrollment). MUST also refuse, before anything is made or shown, an `S` whose creation this
   device has not seen (`Heap::members_known`; `NotReady`: the same call can succeed once the creation is held) and a
   device that is not an **owner device** of `S` (heap.md §2.1: its name under the owner's, its key vouched for as the
   owner's person, its role `admin` or `member`; `Heap::owner_device`): `NotOwner` from the heap, next step
   `UseOwnerDevice` — a `guest` or `node` device (a phone lent for a weekend, a relay) shows no code, since the
   members entry that admits a joiner is `Heap::change`'s and only an owner device signs it (§9.4). A code from such a
   device would admit nobody and leave its joiner with silence. Nothing is stored or served on a refusal.
2. Draws a fresh 16-octet secret and a fresh 16-octet id from the device's entropy (`InviteConfig::entropy`, the operating
   system's by default), wraps the proof key (and, for a short code, the hint token) into its store, signs the offer
   through `Node::sign_packet`, and keeps it.
3. Returns the code only once the offer, the wrapped proof key and, when there is a short code, its wrapped hint token
   are durable (one batch for the first two): a reply before could let a power loss take the offer and leave a joiner
   holding a code for it. The offer is served, and the code shown, only after that.

### 5.4 Closing an offer

`close_offer(offer)` on the device that made the offer writes `closed/<id>` and returns once it is durable: the offer admits
no one new, every ask by a key other than the one it was used by is refused `Closed`, even with the right secret, and it still
answers the key it admitted, with the acceptance kept for its use and nothing else, until the offer expires (§9.2 step 5). It
also drops the signed hint packet kept for the offer's token, so the next request for the token is answered with the gone mark
(§7.1 item 7). A host that closes an offer as soon as it sees the new member needs no pending close of its own for a joiner
whose answer was lost.

An offer is **closed**, judged on every ask and every hint request from durable data and never cached, when any of these holds:

- `closed/<id>` is held;
- all askers' wrong tries are at the device's cap (§9.6): the overall counter reached `wrong_tries_max`; the ask that reaches it
  also writes `closed/<id>`;
- the device may hold notes older than what it did: **every offer held is closed**, `closed/<id>` written for each, (a) when the
  node opened a space an offer names after a stop it did not make (`Heap::started_unclean`: a crash, a power cut, an image copied while
  the device ran), at the start of the introductions, and (b) each time a space an offer names raises `Alert::RolledBack`
  (`Heap::rollbacks`, heap.md §4.8: the device's store is older than what its peers hold), before the next ask or hint request of any
  offer is judged. The marks are in the store before that judgement and flushed after; one lost to a stop is written again by the unclean
  start that follows. A backup restored under a running device could otherwise roll `used/<id>`, `using/<id>` or `tries/…` back and
  let a code be used again (§18.1). An offer made after an alert is not about it, but the next alert of any space an offer names closes it
  too, and a stop of this device that was clean closes nothing. The cost: a crash closes the offers, a joiner whose use was under way meets `Closed`, and the owner makes a new offer;
- the space's members no longer list the person the offer was used by — or, while a use is under way, the key being admitted
  (`Heap::removed_by` names a removal of that device's person, heap.md §10.3): a removed member never comes back by its code
  (§9.5). This is a derivation, **not** a mark: nothing is written, the offer is closed for as long as the removal stands in
  the fold.

What the offer granted stays until a members entry removes it. Another device's offer, or a name that is no offer this device
holds, is `BadRequest`; closing a closed offer does nothing more. The hint record of a closed offer is its gone mark (§7.1 item 3).

### 5.5 When an offer is served

The extension answers an Interest for `<D>/32=intro/32=offer/<id>` with the stored
packet, as signed, for as long as the device holds the offer: an offer is never
pruned (§7.1 item 7), and one made before a restart is read back from the store at
start. It does not judge the expiry itself: a closed offer and an expired one are
served as an open one is, and the one place an expiry is read is the ask (§9.2
step 7), which answers `Expired` to a joiner that holds the right secret. What an
introduction link carries is narrower (§13.1): the offer's name crosses it only
while the offer has not expired, so a stranger whose dial arrives after the last
offer expired meets no link, and a joiner that reaches the device by name still
gets a clear refusal. Only a name that parses as an offer of this device and
names one it holds is answered; any other name under `32=intro` is silence (§2.3).

## 6. The code

`offer` makes three forms together (`Code { offer, link, words, short, short_why
}`; `Code::share()` is the short code when there is one, else the link: what a
host shows):

- the **link**, a trust-envelope `intro` link
  ([trust-envelope.md](trust-envelope.md)) or its https mirror, in the compact
  form of §6.2: the inviter's namespace, its anchor fingerprint (SHA-256 of its
  root anchor's public key, whole), the offer's name, the secret, the inviter's
  link hint (§6.1), and as many relay hints — the relays the inviter's trust
  context advertises, by device name (`/<namespace>/<role>/<device>`; its
  certificate is `/<namespace>/<role>/<device>/KEY/<key-id>/<issuer>/<version>`)
  — as `IntroPolicy::code_relays` allows and one QR holds; the secret, the offer
  and the fingerprint are never dropped;
- the **words form**: the offer's name, then 24 BIP39 English words encoding the
  secret followed by the fingerprint's first 16 octets (its checksum catches a
  mistyped word); the words carry no hint and no relay;
- the **short code**: one line, the inviter's device name, a first contact and 20
  or 36 words. It names no offer: a signed hint record the inviter serves does
  (§7).

`join` tells them apart by the text alone, before it does anything else (§8.1). A
text that starts with `/` is the words form when the number of words after its
first token is exactly 24 (a second token that starts with `/`, `[` or a digit is
a first contact and is not counted), and a short code otherwise; a short code
with a count other than 20 or 36 is refused, saying how many words it found and
which counts exist (§17.2). Any other text is read as a link. The three forms of
one offer carry the same secret and fingerprint (the short code's, a prefix of it
for a named namespace); the link and the words form are made always, the short
code only when the conditions of §6.6 hold.

### 6.1 The link hint

The **link hint** is what lets a joiner with no daemon, no route and no peer entry
reach the inviter's device by its key. A host that listens for links gives it
(`Host::link_hint`, once per `offer` and once for each hint record made on
request, §7): the device's **link key** — SHA-256 of its public key as a
certificate carries it, 32 octets, the fingerprint a link handshake proves
(ndn-link.md §3.3) — and at most `LINK_HINT_CANDIDATES_MAX` = 8 **candidates**,
the addresses of its listening link socket, most promising first (an address
another computer can reach, then one of a bridge or container interface, then
loopback and link-local ones; ndn-link.md §14.2), each a kind (host, reflexive,
advertised, mapped; ndn-link.md §14.2), an IPv4 or IPv6 address and a UDP port.

It is the value of the envelope's `LinkHint` (0x0478): the TLVs `LINK_KEY`
(0x05B0, the 32 octets) and `LINK_CANDIDATE` (0x05B2, once per candidate: one
octet of kind — 0 host, 1 reflexive, 2 advertised, 3 mapped — then the address, 4
or 16 octets, then the port, 2 octets big-endian). Even types: a reader skips what
it does not know. A writer encodes each distinct dialable candidate once, up to
the bound. A reader keeps the first 8 distinct candidates whose kind it knows and
whose address is dialable (not unspecified, multicast or broadcast, and port ≠ 0)
and, unless its policy allows them (`IntroPolicy::local_candidates`, off by
default), not loopback (`127.0.0.0/8`, `::1`) or link-local (`169.254.0.0/16`,
`fe80::/10`): the inviter's own gathering never offers those to a device
elsewhere, and a stranger's code must not make a device send datagrams to services
on itself or on its link. A device that is the inviter's on one machine (tests, a
demo) turns the policy on. A reader refuses a hint that names no key or two, or a
candidate that is not 7 or 19 octets: the join then goes on without the hint,
which only helps to reach.

### 6.2 The full link, compact

One encoder writes the link's body (trust-envelope.md §4.3): the inviter's
namespace once, as a Name (`IntroNamespaceWire`, 0x0490) and not as text; the
offer's name (`IntroOfferWire`, 0x0492) and each relay (`IntroRelayWire`, 0x0494,
in the order of the trust context) as a **relative name** — one octet `k`, how
many leading components it shares with the namespace, then its remaining
components as wire — so a self-certifying component is 34 octets, not 96
characters of escapes, and appears once beside its repeats; the secret and the
whole fingerprint; the link hint (0x0478, §6.1), at most
`IntroPolicy::code_candidates` candidates (default 3, the first ones); and at most
`IntroPolicy::code_relays` relays (default 2), **by name, not by key**: a key
alone gives a joiner nothing to route or dial by, and a relay's name is what a
ForwardingHint is. The names a link carries are in the canonical text of `Name`
(`Introduction::check`). The old text tags (Namespace 0x0489, Offer 0x0475,
RelayHint 0x0476) are read, never written.

The offer's name in a link is the new one, `<D>/32=intro/32=offer/<id>`, in the same
`IntroOfferWire` field: the envelope carries a `Name` and assumes nothing of its
shape (trust-envelope.md §4.3). A link made by the removed `ndn-data` named a log entry
(`<D>/32=log/<F>/seq=<n>`): the joiner reads a code whose offer is no `<device>/32=intro/32=offer/<id>` as a
`BadRequest` (the offer's name is no offer's; check the code), before anything is dialled (§8.1).

The link stays within one QR (`ndn_trust_envelope::qr::MAX_TEXT_LEN` = 2331
characters). A hint costs 34 octets and 9 (IPv4) or 21 (IPv6) per candidate, a
third more as base64url. When a link does not fit, the maker drops relay hints
first, all of them, then the hint's last candidates one by one, then the hint
itself; an offer name so long that the link does not fit without them is `Local`.
A joiner needs no hint record from a link: the link names the offer and, with its
link hint, the key to dial.

### 6.3 The short code

One line a person can read aloud or type (`ShortCode::encode`,
`ShortCode::parse`):

```text
short      = device SP [ contact SP ] word{20}     ; a named namespace: 10 octets, the fingerprint keyed by the code's secret
           | device SP [ contact SP ] word{36}     ; the whole 32 octets of the fingerprint
device     = an absolute NDN URI of the inviter's device D, not the root: /alice/member/laptop
contact    = "[" IPv6 "]" ":" port                 ; [2001:db8::7]:4433
           | IPv4 ":" port                         ; 192.0.2.7:4433
           | relay-name                            ; an absolute NDN URI, starting with "/"
word       = a BIP39 English word, 11 bits
```

1. **Tokens.** Whitespace of any amount separates the tokens. The first is the
   device. The second is the contact when it starts with `/`, `[` or an ASCII
   digit — no word of the list does — else there is none. All the rest are words,
   and exactly 20 or 36 of them. Case and spacing do not matter in the words; a
   device or relay name is case-sensitive.
2. **`161=*`.** A component written `161=*` (type 0xA1, the single octet `*`)
   stands, in the device name and in a relay name, for the self-certifying
   component equal to the anchor's whole fingerprint: the 32 octets are in the
   words, not written a second time as 96 characters of escapes. It is valid only
   with 36 words; with 20 it is refused (`Placeholder`, §17.2). A writer MUST write
   `161=*` for every self-certifying component of the device and of a relay name
   that equals the whole fingerprint, and writes the whole fingerprint exactly
   when the device's namespace is the self-certifying one it is the digest of; it
   MUST refuse a name that has a literal `161=*` component. A reader that finds
   `161=*` reads the name with the fingerprint in its place and names the
   namespace as the device's prefix up to that component. A 36-word code without
   `161=*` is valid: the names are literal.
3. **Words and checksum.** `payload = secret (16) ‖ fingerprint (10 or 32)`, the 10
   octets being the **keyed fingerprint** (§6.4); the words encode `payload ‖
   checksum (12 bits)`, eleven bits to a word (trust-envelope.md §5.8): 26 octets
   are 220 bits, **20 words**; 48 octets are 396 bits, **36 words**. The checksum
   is the first 12 bits of SHA-256(`ndn-trust/intro-short/1` ‖ the **bound text**
   ‖ `0x00` ‖ payload). The bound text is the canonical text of what precedes the
   words: the device name re-rendered from the parsed Name (each component as
   `Name` writes it, `161=*` where item 2 says), then, when there is a contact,
   one space and the contact re-rendered (a parsed socket address in its standard
   form, or a relay name as the device). So spelling that parses to the same name
   and address (case of hex digits, an expanded IPv6 address) does not matter, and
   **a typo anywhere** — a word, a digit of the port, a letter of the device name —
   is caught with probability 1 − 2⁻¹². Words of the 24-word form are unchanged
   and still read.
4. **No correction.** 12 bits cannot single out one repair among the 20 × 2047
   single-word edits (about ten of them satisfy the checksum), so a typo is
   refused with the text that names what to check, never repaired.
5. **The contact.** An address MUST NOT have port 0, be unspecified, multicast or
   (IPv4) the broadcast address: the code is then refused (`Contact`). A loopback
   (`127.0.0.0/8`, `::1`) or link-local (`169.254.0.0/16`, `fe80::/10`) address is
   refused (`Local`) unless `IntroPolicy::local_candidates` is on: a code from a
   stranger is not made to send datagrams to services on the joiner's own machine
   or link, as for a link hint. A relay is a device name; nothing is dialled for
   it.
6. **Order of refusals.** The reader refuses, in this order, a device name that is
   no name (`Device`), a contact that is neither (`Contact`), a word count other
   than 20 or 36 (`Words`), `161=*` with 20 words (`Placeholder`), a word off the
   list (`UnknownWord`, by position among the words, from 1), a checksum that does
   not match the words, the device name and the contact (`Checksum`), an address no
   device can dial (`Contact`), and a loopback or link-local address (`Local`).
   Each is a `BadRequest` of the joiner's `join`, before anything is dialled, with
   the text of §17.2.

The words are the one thing that cannot be fetched beside the code's few facts:
the secret (16 octets, never fetched, never on a wire in clear) and the anchor's
fingerprint. The device name is in the text because the hint record is fetched at
its name and an Interest is routed by it; the contact is the only way to reach the
inviter before the record is held.

### 6.4 The fingerprint a short code carries

A named namespace's code carries `keyed_fingerprint(secret, anchor) =
HMAC-SHA256(key = secret, "ndn-invite/intro/fp/1" ‖ anchor)[..10]`, `anchor`
being the 32-octet fingerprint of the namespace's anchor, not the first octets of
`anchor` itself. It is the same number of octets and words as a plain truncation.
The joiner computes it again from the whole fingerprint of the anchor the verified
credentials carry and compares in constant time. The code of a self-certifying
namespace carries the whole 32 octets: they are the namespace's name, not a
truncation of it. A code made before the keyed fingerprint carries the plain first
10 octets, which no longer match any anchor: it is refused as an anchor mismatch
that says so (§17.2). The 24-word form, which a link and `Code::words` also give,
carries a plain 16-octet prefix, and is judged as a prefix of the anchor's
fingerprint, compared in constant time. Why 80 keyed bits, and why 128 plain bits
for the words form, are in §18.

### 6.5 Lengths (informative; measured, the same secret in each)

Characters of the one line of a short code (device name, contact, words), and of
the compact link (`ndn-trust://intro/…`), with the names of the code's tests:

| Short code | Characters | Words |
|---|---:|---:|
| IPv4 `192.0.2.7:4433`, `/alice/member/laptop` (named) | 167 | 20 |
| IPv6 `[2001:db8:1234:5678:9abc:def0:1234:5678]:65535` (the longest), named | 201 | 20 |
| relay `/alice/node/relay`, named | 171 | 20 |
| no contact, named | 154 | 20 |
| IPv4, `/user/161=*/member/laptop` (self-certifying) | 273 | 36 |
| IPv6 `[2001:db8:1:2:3:4:5:6]:4433`, self-certifying | 288 | 36 |
| relay `/user/161=*/node/relay`, self-certifying | 281 | 36 |
| the longest IPv6, self-certifying | 305, over `short_width`: no short code | 36 |

| Compact link | Characters |
|---|---:|
| named, no hint, no relays | 202 |
| named, 2 relays | 293 |
| self-certifying, no hint, no relays | 285 |
| self-certifying, 3 IPv4 candidates | 388 |
| self-certifying, 3 IPv6 candidates | 436 |
| self-certifying, 3 IPv6 candidates, 2 relays | 489 |
| self-certifying, 2 IPv4 and 1 IPv6 candidate, 2 relays | 457 |

Words average about 5 characters, so a different secret moves each figure by a few
characters. The label rename of §4.5 changes the keyed fingerprint's input, not the
length of anything; the figures are those of the ported tests. The checksum, for
the fixed corpus of the code's tests (a payload of 26 octets, then 48): of 40 940
substitutions of one word, 8 went undetected (chance expects 10), and of 73 692,
22 (chance 18); of 19 and 35 adjacent swaps, none; of 304 single-character edits of
the device name and address, none.

### 6.6 When a short code is made

`offer` makes the short code, and with it publishes the hint record, only when
`IntroPolicy::short_code` is on (the default), the host gives a first contact and
the line fits `IntroPolicy::short_width` characters (default 294: three lines of 98
columns, counted in characters with the spaces). The first contacts are, in order,
the dialable candidates of the host's link hint, which is in ndn-link's order (an
address another computer can reach first; loopback and link-local ones last, and
only under `local_candidates`), then the namespace's relays (up to 8), and the first
whose line fits is taken: a longer address or name gives way to the next. With none,
`Code::short` is `None` and `Code::short_why` says why, naming what to do (give the
link, or the words with the offer's name): policy off (`IntroPolicy::short_code`);
no first contact; or the device name and the number of first contacts tried, and
that the line would be at least so many characters, past `short_width`. A longer
name is the owner's choice; the link still works. Nothing of a hint is published
then.

## 7. Hint records

What the joiner fetches by a short code's first contact, and the only thing a short
code's offer names: a record the inviter makes **on request** and signs. A link or
the words form fetches no hint record.

### 7.1 The record

1. **Name.** `<D>/32=hint/<token>` (§2.1), `token = HMAC-SHA256(key = secret,
   "ndn-invite/intro/hint/1")[..16]` (`hint_token`; `hint_name`, `hint_prefix`,
   `parse_hint_name`; `HINT_TOKEN_LEN` = 16). It is unguessable without the code
   (128 bits of an HMAC key), and it reveals nothing of the secret, which is never in
   a name or on a wire. The offer's own name is not used.
2. **Data.** Signed by the device key through `Node::sign_packet`, with
   `FreshnessPeriod` 5 s (`HINT_CACHE`): a cache does not hold an address past the
   time the device would give it. Its Content is one `INTRO_HINT` (0x05B4, §16.2):
   `HINT_OFFER` (0x05B6), the offer's name, so that the signed record is bound to
   the offer at a name only the secret's holder can ask for; `LINK_KEY` (0x05B0) and
   at most `LINK_HINT_CANDIDATES_MAX` (8) `LINK_CANDIDATE` (0x05B2), the host's
   current `Host::link_hint` (with no hint from the host: the device's own key and no
   candidate); `HINT_RELAY` (0x05B8), the device names of the relays the namespace's
   trust context advertises, in its order, at most `HINT_RELAYS_MAX` (8);
   `HINT_UNTIL` (0x05BC), the offer's expiry, informational; and `CREDENTIALS`
   (0x056F), the inviter's signed trust context and the certificate chain of the
   signing key, as an answer carries them, which is what lets the joiner verify the
   signer with nothing but the code's fingerprint. A reader skips an unknown even TLV;
   it refuses a record that repeats a field, names no offer, key, expiry or
   credentials, has more than 8 relays, or has content after the `INTRO_HINT`;
   candidates are read as a link hint's are (§6.1: at most 8 distinct dialable ones,
   loopback and link-local only under `local_candidates`).
3. **Gone mark.** For an offer no longer served, the same Data holds `INTRO_HINT {
   HINT_GONE, CREDENTIALS }`: `HINT_GONE` 3 expired, 4 closed (any other refusal of
   the offer is written as 4), and the inviter's credentials as a record carries
   them, signed alike. It carries nothing else and is a clear refusal where there
   would be silence. Its Data has **`FreshnessPeriod` 0**: a cache holds a record for
   `HINT_CACHE`, never a mark, so a party on the path cannot leave a forged mark in a
   cache to answer the joiner's retries. The joiner verifies a mark as it does a
   record (§8.3 S5): a mark that does not verify is anyone's, and ends nothing
   (§17.1 `GoneUnproven`). A reader refuses a mark without credentials, or with
   anything else of a record.
4. **On request.** The device makes the record when the Interest comes, from the
   host's link hint and the namespace's relays as they are then, so a restarted
   inviter or a moved address is current. It signs one record per token and keeps it
   5 s, answering the same Data again while the offer's state (record, or which gone
   mark) is unchanged (a gone mark too is kept 5 s by the inviter; its Data's
   `FreshnessPeriod` is 0, item 3); a change, a closing mark included, is signed at
   once. A device whose host cannot give credentials answers nothing.
5. **Served while the offer is open.** The record is served while the offer is open
   (not expired by the device's clock, not closed in the sense of §5.4: `closed/<id>` held, the overall
   wrong tries at the cap, §9.6, or a removal of the person it was used by), and a gone mark after, when
   `IntroPolicy::hint_while_open` is on (the default). With it off the record is
   served until the device stops, with no gone mark. Either way the offer answers by
   its own rules (§9.2): a hint that outlives its offer joins no one.
6. **Unknown tokens.** An Interest for a hint name of this device whose token is not
   one of its own offers' is answered as every unanswerable name is, by a Nack
   (`NoRoute`): the same for every token a prober can try, so nothing of any token is
   revealed, and a joiner with a mistyped but checksummed code fails its tries at
   once. Over an introduction link such an Interest is not even carried (§13.1). A
   name of another device is not answered either.
7. **What the device keeps.** `offer` makes the token from the secret, wraps it to the
   device's recipient key under `hint/<id>` beside the offer's proof key (the same
   kind of note, which wraps 32 octets: the token is the first 16 of them; a writer of the store cannot make one read), and keeps `token →
   offer` in memory, rebuilt from the store at start for the offers it holds (a note
   not wrapped to the device's key is ignored, and its offer publishes no hint). The
   offer packet holds nothing of the hint. A hint record exists only for an offer that
   was given a short code. The token, one name per offer, and its durable note stay for
   as long as the offer's note is held — offers are never pruned — because item 5 gives
   a gone mark to the token of a closed or expired offer, across a restart too; what is
   kept of the **signed packets** lives `HINT_CACHE` and no more: a packet older than
   that is dropped whenever a hint Interest is answered or refused (an unknown token's
   too), a token is kept, or an offer closes, and a closing drops the packet kept for
   that offer's token at once. Nothing a prober asks for grows what the device keeps.

The hint family is served by the same extension as the offer (§2.3); `introduction_prefixes`
(§2.3) names both its prefixes, and `Surface::carries` (§13.1) carries exactly one name of
the `32=hint` family: `<D>/32=hint/<token>` of a token the device holds.

## 8. Joining

`join(code)` takes a short code, the link (or its https mirror) or the words.

### 8.1 Judging the code before anything is sent

Before it dials, fetches or asks anything, the code is judged: the dial gives
whoever holds the code's key a link, and the device name a code claims is only a
claim.

1. A code that names a namespace the offer's device `D` is not under is altered:
   `Forged`. Ask the inviter for a new code.
2. The namespace a code names is judged as in §8.2 step 4.
3. A device `D` under a namespace this device already trusts is refused
   `InviterConflict { inviter: <that namespace>, why }` (`AskOwner`: do not use the
   code) unless the code names that very namespace, or none, and its fingerprint —
   or the prefix of one a short code or the words carry — is that of one of that
   namespace's anchors this device holds: the same anchor is a party known already,
   and a second invitation from it is welcome. Without the exception a code could
   claim a device of a namespace this device trusts, and the link, with that
   namespace's Interests, would go to whoever holds the key.

Before these, for every form of code: a code whose device is this device, or lies under this device's own namespace, is a
`BadRequest` ("the code offers a space of this device's own namespace: it is yours already"), and a code whose offer is no
offer's name is a `BadRequest` too (§6.2).

### 8.2 The steps

0. **Dials the inviter by the code's link hint**, when the link form of the code
   carries one, before any Interest: `Host::dial(hint, D, within)`, `within` being
   `Config::first_look`, once per `join`. The host's link layer tries the hint's
   candidates and links only to the device whose key the hint names. Until that
   device shows a certificate of a namespace this device holds, the link routes
   only `D`'s introduction prefixes (`<D>/32=intro`, `<D>/32=hint`, §2.3) — never
   `D`'s other names, which only the code claims (ndn-link.md §10, §13.3); once this
   device holds its namespace the link is made again and the device is identified.
   `Ok`: the Interests of the steps below go over that link by name, with no
   ForwardingHint. An error — the host has no dialer, no candidate answered within
   the bound, an address presented another key — is not a refusal: the join goes on
   at once as it would without a hint, by the relays the code names, else those its
   own namespace's trust context advertises, else by name. A hint that does not read
   is ignored the same way. The dial carries no secret and judges nothing of the code
   (§18). **A join that fails after its dial succeeded** — for any reason, `NotReady`
   included — calls `Host::undial(hint, D)` before it returns: the host takes down the
   link the dial made, unless it was up before the dial or has been identified since
   (the default does nothing: a host with no link layer dialled nothing). A retry
   dials again.
1. **Fetches the offer** as `<D>/32=intro/32=offer/<id>` (§2.1), `D` and `<id>` the
   offer name's. The offer is a Data signed by a key of `D`; the joiner's forwarder
   needs no trust of `D` to carry it, and the joiner does not take it on the
   forwarder's word (step 3 and §8.3 S7 judge it). No answer after its retries:
   `NotReady` (`RetryLater`): the inviter is offline or unreachable, and the offer
   waits until its expiry. A packet under the name that is not the offer's record,
   or an offer whose name is not the one asked: `Unknown`.
2. **Sends the ask**, the Interest `<D>/32=intro/<ParametersSha256Digest>` whose
   ApplicationParameters are one `INTRO_ASK`: `AskBody` — the offer, a fresh nonce,
   the ask proof (§4.1) bound to its own key and its digest, its credentials (its
   namespace's signed trust context, as its host gives it, then its key's
   certificates up to that context's anchor) and its proof packet
   `<J>/32=ask/<binding>` signed by its key, the binding SHA-256 of the intro-ask
   label (§4.5), `D`'s Name TLV and the body's fields before it — sealed: a fresh
   content key wrapped to the offer's `SEAL_KEY` and the body sealed under it, both
   binding `<D>/32=intro` (its Name TLV) as associated data. Before sending, the
   joiner checks that its own credentials verify its proof packet (else `Local`: its
   enrollment is broken). It sends the same Interest again on no answer, up to 8 sends in all
   (`ASK_TRIES`; the inviter keeps its answer by the ask's name, §9), then answers `NotReady` as in step 1.
3. **Takes the answer**, a DigestSha256 Data of the ask's name whose Content is an
   `INTRO_ANSWER`. A refusal is reported as it is (§17.1). An acceptance MUST pass
   every check, else the join answers `Forged` (`RetryLater`) and adopts nothing: it
   names the offer, this device's key and its digest; its `PROOF` verifies under the
   proof key the code's secret yields; its credentials open (§9.2 step 2) to a
   context whose anchor fingerprint is the code's (whole for a link and a 36-word
   short code, a plain prefix for the words form, the keyed fingerprint of §6.4 for a
   20-word short code), whose namespace is the code's (when it names one) and a prefix
   of `D`; the inviter's proof packet `<D>/32=ask/<binding>`, the binding SHA-256 of the
   intro-answer label (§4.5) and the answer's fields before it, and the offer packet are
   both signed by a key of `D` that chains to that anchor through those certificates;
   the offer's commitment is the code's secret's; the space and role are the offer's;
   and the space's owner namespace is the inviter's. When the answer names an `ADMITTED`
   entry, the device that signed it lies under the inviter's namespace (`Forged`
   otherwise, and no Interest is sent for an entry of a device outside it); whether the
   entry itself is admitted is the heap's to judge (§8.5), and a name that no entry
   answers to is a wait that ends in `NotReady`, never an admission.
4. **The inviter's namespace is no other's**, judged by this device (the words and a
   short code of a named namespace name none, so it is judged here for them too): not
   the root, not one the policy refuses (`IntroPolicy::refuses`, §14), not this
   device's own namespace nor under or over it, not under or over any namespace this
   device trusts, and not one it trusts under another anchor (the same namespace under
   the same anchor is a party it knows: joining a second space of theirs). Else
   `InviterConflict { inviter, why }` (`AskOwner`: do not use the code), and nothing is
   adopted: a stranger's code can never make this device trust a name it trusts
   already, nor names under or over it.
5. **Has its host adopt the inviter's anchor** (an inline anchor link of the context
   the answer carried, `Host::adopt`); a refusal is `Local` (fix the host and join
   again with the same code: the same key asking again is answered again). A
   self-certifying inviter namespace `/user/<h>` not held is adopted from its genesis
   by name, never from the credentials (trust-context.md §4.5.3: the host fetches
   version 1 and the newest; a version 1 the credentials carry only checks against the
   fetched one, a different one refused as a fork; with no network to fetch over, the
   host refuses, saying to join again once the inviter's devices are reachable), so the
   credentials only count if they are that namespace's: every anchor they carry MUST
   then be an anchor of the context the host holds for it (by public key), else
   `InviterConflict` (`why`: its credentials carry anchors its namespace, adopted from
   its genesis, does not hold). For any other namespace the host adopted these very
   credentials, or holds the namespace already. Then, for every namespace, the
   inviter's proof packet and its offer packet are checked again by this device's
   validator — by the context it now holds (its anchors, schema and revocations),
   through the credentials' certificates — and MUST still be signed by the key that
   signed them under the credentials, a device of the inviter, else `InviterConflict`
   (`why`: it answered with a key its namespace, as this device holds it, does not
   certify). Takes into its validator the certificates on the chain from the key that
   signed the inviter's proof packet to its anchor, named under the inviter's
   namespace — no other certificate the answer carries — and goes on with the
   admission, step 6.
6. **Admission** (§8.5): opens the space, notes that it was admitted, and returns
   only once it may write.

### 8.3 Joining by a short code

A short code names no offer and no key, so steps 0 and 1 above are replaced by the
steps below, in this order; steps 2 to 6 then run as written, with the offer's name
from the verified record. A link or the words form fetches no hint record. Until the
record has named it, a refusal or a `NotReady` carries the inviter's device name in
place of the offer's, never the token.

- **S1. Read** the code (§6.3). A code that does not read is a `BadRequest` (§17.2)
  and nothing is dialled, fetched or asked. A 36-word code whose device name has the
  self-certifying component equal to the fingerprint also names its namespace, the
  device's prefix through that component, so that it is judged as a link that names
  one is.
- **S2. Judge before any dial**, as in §8.1, with a fingerprint that may be a prefix:
  a device of this device's own namespace is `BadRequest` ("the code offers a space of
  this device's own namespace: it is yours already"); a namespace the code names (a
  36-word code with `161=*`) over a whole fingerprint is judged as in step 4,
  `InviterConflict`; a device under a namespace this device trusts already,
  `InviterConflict` unless an anchor of that namespace begins with the code's
  fingerprint. **What waits for the record.** The refusals that need the inviter's
  namespace itself — the policy's (`IntroPolicy::refuses`), a namespace that lies over
  or under one this device trusts, one that overlaps this device's own through a
  prefix of it — run before the dial only for a code that names the namespace (a link;
  a 36-word code over a whole fingerprint). A short code names none: any prefix of the
  device's name may be its namespace, so judging a prefix would refuse an inviter whose
  namespace is longer. Those refusals run on the verified record (S5 check 10), before
  the record's key is dialled and before anything is asked. They disclose nothing of the
  joiner: the first contact's hello is empty (S3).
- **S3. Reach the first contact.** *An address:* `Host::dial_first(D, address,
  Config::first_look)` (§12), once. An error is `NotReady` (`RetryLater`), not a refusal
  of the code: the address may be wrong or the inviter's device off. The dial sends an
  **empty hello** — no certificate, no membership (ndn-link.md §13.3A): whoever holds the
  address learns nothing of the joiner, and the inviter, which gives an introduction link
  to a device with no certificate while an offer is open, still answers. Whoever answers
  is linked with the two introduction prefixes of `D` as its only routes (ndn-link.md
  §13.3A), and **what it may send in is bounded as well** (the link's inbound scope): answers
  under those prefixes, and Interests only under the joiner's own device names (the inviter
  fetches the joiner's seal key there), nothing else, so it cannot make the joiner's forwarder ask
  the joiner's other links for anything. The key it proved is the link's name, nothing more. An address dialled
  after the inviter's last offer expired meets no link (§13.1: the inviter refuses it as
  any device nobody knows), so the join reports the first contact did not answer. *A
  relay:* nothing is dialled; the relay's device name is the ForwardingHint of the fetch
  below. **A relay by name, not by key:** a key alone gives the joiner nothing to route or
  dial by, and 32 octets would cost 24 words; a name is what a ForwardingHint is and what
  the joiner's forwarder already routes through a relay it uses. The relay serves nothing
  new: it forwards `<D>/32=hint/<token>` toward `D` as it forwards the offer fetch and the
  ask, and the inviter's link to it carries those names because the surface says so
  (§13.1). The joiner's forwarder MUST reach the relay's name (a relay it is linked to, or
  a name its routes cover), the precondition of every relay fallback (below); a join that
  cannot says so. *No contact:* the Interests go by name.
- **S4. Fetch** the record `<D>/32=hint/<token>` (§2.1), as often as the offer is fetched
  (step 1: up to 8 tries of `Config::lifetime`): over an address first contact by name over
  its link; over a relay with the relay as ForwardingHint. None came: `NotReady`
  (`RetryLater`), and the first link, if any, is taken down.
- **S5. Verify**, before anything else is sent, in this order, and **nothing is dialled,
  asked or adopted** on a failure. A failure is one of two kinds, because only damage in
  flight is worth a retry. Up to the signature (checks 1–4), a packet damaged in flight
  and an impostor's packet fail alike, so the refusal is `Hint` (`RetryLater`, as `Forged`
  is: the host's retry fetches it again). Once the signature is good — the packet is
  authentic, made by a key that credentials which open vouch for — what fails is no damage
  in flight but a record of another party: `HintMismatch` (`AskOwner`, no retry: do not use
  this code's first contact; ask for a new code):
  1. the Data's name is exactly the one asked, else `Hint` (`wrong name`);
  2. its Content decodes as a hint record or gone mark (§7.1), else `Hint` (`wrong record`);
  3. its credentials open — a trust context signed by one of its own anchors, valid now,
     then certificates (§9.2 step 2) — else `Hint` (`credentials`);
  4. its signature is good by the public key of a certificate that the credentials chain to
     their anchor (`Opened::authentic_signer`: the signer's own chain and the signature,
     not the trust schema), else `Hint` (`signer`);
  5. the context's namespace is a prefix of `D` and, when the code names one, equals it,
     else `HintMismatch` (`namespace`);
  6. the anchor's fingerprint is the code's: equal when the code carries 32 octets, the
     prefix when it carries the words form's 16, the keyed fingerprint (§6.4) when it
     carries a short code's 10 — all in constant time — else `HintMismatch` (`anchor`),
     whose text says that the code may have been made before the keyed fingerprint and that
     the inviter has to give a new one;
  7. the signing key is a key of device `D`, and the context's trust schema lets it sign
     this name, else `HintMismatch` (`signer`);
  8. **a gone mark** that passed 3–7 ends the join as it says, `Closed` or `Expired`
     (`AskOwner`), and no further step runs. A gone mark that failed any of 3–7 is
     `GoneUnproven` (`RetryLater`) — "the first contact says the offer is closed but
     can't prove it: retry, or ask the inviter" — never `Closed` or `Expired`: anyone on the
     path can make a mark that proves nothing (§18); Content that is neither a record nor a
     mark was already refused by check 2 (`Hint`, `wrong record`);
  9. the record's offer is an offer name of device `D` (§2.2), else `HintMismatch` (`offer`);
  10. the namespace is judged as an inviter's (step 4), now that the fingerprint is whole and
      proven, before the record's key is dialled: `InviterConflict`.

  **Retries are bounded.** `Hint` and `GoneUnproven` say `retry at most 3 times`
  (`HINT_RETRIES_MAX`), and a host that retries by itself on `RetryLater` MUST stop there for
  the same code and tell the user to ask the inviter for a new code: each retry dials the
  first contact again, and a first contact that damages the same record four joins in a row
  is broken or hostile. Three: one retry meets a single corrupted packet intact, a second a
  burst, a third is the margin. A user's own retries are not counted.
- **S6. Keep or take down the first contact's link, then dial.** The first contact's link was
  made with no key to expect, so whoever holds the address completed its handshake: it is kept
  only when the key it proved is the verified record's key. When it is, and nothing more is
  dialled, the Interests go by name over that link. When it is not — whatever the record
  offers: candidates or none — the link is `undial`led **at once**, before the offer is fetched
  or the ask is sent, and it is used for nothing more: not its routes, not a fallback if the dial
  below fails. Then, when the record has candidates, `Host::dial(record link, D,
  Config::first_look)` as in step 0; an error is not a refusal, and the join goes on by
  forwarding hints. The ForwardingHint of the Interests, when no link carries them, is the first
  contact's relay, then the record's relays, else the joiner's own namespace's relays (as in step
  0); none, routed by name. A link of a key other than the record's therefore never outlives the
  verified record in any join: a party at the address that relays the genuine record, and drops
  the dial to the record's key, gets neither the offer fetch nor the ask, nor a link or route once
  the join is over (§18).
- **S7. The offer.** The offer's name now comes from the verified record. The joiner fetches it
  (step 1) and, **before it seals the ask**, refuses `Forged` (`RetryLater`) when the offer packet
  is not signed by a key of device `D` that chains to the anchor of the record's verified
  credentials (the record's opened credentials judge the packet as they judged the record's own
  signature, S5 check 7): with the commitment public, a party on the path could otherwise
  substitute the offer's `SEAL_KEY` together with a commitment copied from the genuine packet, and
  read the ask. It then refuses `HintMismatch { why: "offer: <offer> was not made with this code's
  secret" }` when the offer's commitment is not the code's secret's — judged only on an offer the
  record's credentials vouch for: a short code's secret is whole and checksummed, so a mismatch
  means the record named another offer, and an ask would only count a wrong try. The link and the
  words form keep step 3's order (a mistyped secret there is `WrongProof`; nothing vouches for the
  offer before the answer, whose credentials judge it as step 3 says). Then steps 2 to 6 run, every
  check of today's flow included: the answer proves the secret, the commitment is the code's, the
  fingerprint matches the answer's credentials, the device is under the inviter's namespace.
- **S8. A join that fails** after a dial calls `Host::undial` for the record's key, and for the first
  contact's key when that link is still up (it is up only when it is the record's key, S6), as step 0
  does: the first link, which proved no certificate until the namespace is held, is not kept (it is
  taken down by the key the handshake proved). A join that succeeds keeps only a link whose key is
  the verified record's.

Absent a dial that succeeded, the joiner's Interests carry a ForwardingHint: the relays the code names,
else those its own namespace's trust context advertises; none, routed by name. Hints only reach (§18).

### 8.4 No walk

The joiner of the previous design followed the folder and then waited for a walk of every device of the
inviter's namespace toward it (a summary tree). This layer has no summaries: a space replicates exactly its
members' logs (heap.md §3.8, §7), so there is nothing to walk. The wait is §8.5.

### 8.5 The wait: returns once the joiner may write

After step 5, `join`:

1. calls `Node::open(space)` (heap.md §10.2: idempotent, never waits for the network); the heap then asks for what it lacks —
   the epoch key by its grant, among it (heap.md §6.5, §7.8);
2. calls `Node::note_joined(space)` **before** the wait's first look. The note is the node's own, stored at
   `/localhost/ndn-heap/joined/<space>`, never served (heap.md §10.9): while it stands and the fold does not list this
   device's person, a `put` the fold would refuse as `NotAllowed` (`AskOwner`) answers `NotReady`
   (`RetryLater`) in its place, because the entry that lists the person is on its way. The node removes the
   note when the fold lists the person (owner, writer or reader), and when a removal of the person arrives that the note did
   not name while no `ADD` of hers stands; `note_joined` keeps nothing for a space that lists the person already. The note is
   durable with the node's next flush, so a restart between the answer and the entry still tells the device to wait;
3. waits, for at most `Config::first_look * 3 + Config::lifetime` counted from the start of the wait (the bound of
   every wait of a join), polling the heap every 20 ms, until **all** of these hold, checked in this order:
   1. the space's creation is held (`Heap::members_known`);
   2. the fold lists this device's person: for a writer, as a writer **and** as a reader (a writer of a sealed space must
      be a reader to hold the key, heap.md §5.7); for a reader, as a reader (`Heap::members()`, heap.md §5.4; a public
      space lists every person as a reader);
   3. the epoch key is held (`Heap::holds_epoch_key`, heap.md §10.3; a public space needs none);
   4. when the answer names an `ADMITTED` entry, that entry is held and applied (`Heap::applied`, heap.md §10.3): the entry
      that admitted it, in the log of the owner device that signed it. While it is not applied the join fetches it by name
      (`Node::fetch_entry` of `<device>/32=log/<space>/seq=<n>`: the writer is asked, then the members that vouch for its
      log), so a notice that never reaches the joiner does not keep the entry from it. An answer that names none (the
      space listed the person already when it was answered, §9.4) waits for the fold alone;
4. keeps the **mirror note**, durably, and tells the host (§11 rule 17);
5. returns `Joined { space, role, inviter }` — the offer answered **and** all of the above held, so a `put` in the space is
   refused for want of none of them.

When the bound passes: `NotReady { name: <space>, why }` with next step `RetryLater`, `why` naming the first thing
missing ("the creation of the space has not been heard here yet", "the members of the space held here do not list this
device's person as a writer (or reader) yet", "the epoch key of the space (its grant) is not held here yet", "the members
entry `<device>` seq `<n>` that admitted this device is not applied here yet") and what to do: join again with the same
code (the offer answers the device it admitted), or put again; both are safe. A device that is lost is marked suspected or
revoked, and is not waited for then.

### 8.6 `join` is idempotent for the same code

A second call by the key an offer admitted asks the offer again, which answers it as it answered the first
(§9.2 step 6: the same key asking again is answered again, and a closed offer still answers the key it
admitted until it expires, §5.4), and then waits for the same things. It never answers "already used" to the
device it admitted.

**A removed joiner who joins again.** The acceptance kept for the use names the entry that once admitted the device, and
that entry stays applied; the fold, however, no longer lists the person. The note of §8.5 step 2 is made with the digests of the
removals held when it was made, so the removal of the earlier invitation does not end it (heap.md §10.9): the join ends at the
bound of §8.5 with `NotReady` naming that the members do not list this device's person, and a `put` made meanwhile is
`NotReady` rather than `AskOwner`. Only a removal the note did not name, arriving while no `ADD` of the person stands (an
admission undone before this device ever saw it listed), ends the note and makes the refusal `NotAllowed` again. This differs
from the former data layer (§19.3 step 6 of history/data-layer-remainder.md), whose note let go at a record of the admission's revision or later that left the device out
(§20): a removed joiner is told to retry, not to ask the owner, and a new offer is what admits it again.

## 9. Answering

The offering device answers an ask of its own name in its own task, one ask at a
time, so a use, a counted try and a closing mark each see the one before. It keeps the
last 1,024 answers it signed, each by the ask's name (the oldest dropped first): the same ask asked
again gets the same answer while it is kept, and a refusal or an answer is never computed twice for one ask.

**What a forwarder on the path sees.** The answer is a DigestSha256 Data (`offer.rs`, `sign_digest_sha256`), so any forwarder can carry
and cache it; its authenticity is the proof inside, never the forwarder's. The offer and the hint record are signed by `D` and need the
host's transit rule to reach a joiner that does not yet trust `D` (§12.1). The ask is an Interest whose parameters are sealed to the
offering device (§4.1).

### 9.1 A crowd of asks is bounded

The device holds at most `IntroPolicy::asks_queued` asks at once (32 by default),
verifying or waiting for their turn: one more gets no answer (a Nack), says so in its
log, and its asker retries. It opens and verifies at most `InviteConfig::asks_verifying`
at once (8 by default), before any unwrapping.

### 9.2 The checks, in order

1. **It opens**: the name's digest is its parameters', the content key unwraps with
   its recipient key and the body decodes, under `<D>/32=intro`. Else no answer (a
   Nack): nothing to address a refusal to.
2. **Its credentials parse**: a trust-context Data whose signature verifies under one
   of the context's own anchors, valid now (`SignedTrustContext::open_received`), then
   certificates (at most 8); the claimed key — the proof packet's KeyLocator — is an
   anchor of the context (a key that is its own anchor) or has a valid certificate among
   them. Else no answer.
3. **The asker proved a key**: the proof packet, named `<J>/32=ask/<binding>` for this ask (the
   binding covers this device, the offer and the body: a proof of another ask is none), verifies by a validator
   that holds the presented context alone and the presented certificates (the hierarchical schema and certificate
   validity checked), signed by a key of `J`. Else no answer: a forgery, or a broken
   enrollment the joiner's own check (§8.2 step 2) reports. **This comes before every refusal**: a refusal
   travels only to an asker that proved a key (§17.1), so that a party that holds no proving key learns
   nothing of what the device holds, and what is said from here on is addressed to the proved key. The ask path
   pays this signature in any case.
4. **The offer is its own and known**: named under this device
   (`<D>/32=intro/32=offer/<id>`), an offer it holds (`offer/<id>`), its proof key in its
   store (`key/<id>`). Else **no answer** (a Nack), the same as for any other miss (§2.3): an ask that names no
   offer this device holds is met with silence even when its asker proved a key, so that a guessed id learns nothing.
5. **Not closed to this key.** An offer is *closed* when `closed/<id>` is held, when
   at least `IntroPolicy::wrong_tries_max` wrong tries are counted toward the overall
   cap, or when the fold shows a removal of the person it was used by (§5.4). A closed offer
   admits no one new: it answers `Closed`, except to the key `used/<id>` names (not a use
   a stop interrupted, which was never completed; `using/<id>` alone is no use), which it
   answers as step 6 says — the acceptance kept for its use, and nothing else — while the
   offer has not expired by this device's clock, and `Expired` after. This comparison is
   made on the key step 3 proved. So closing never makes an offer answer more than it did: an open
   offer's user is answered whenever it asks (step 6), a closed offer's until the offer
   expires.
6. **Not used by another key**: `used/<id>` — or a use under way that a stop interrupted
   (`using/<id>`) — naming another key or digest is `Used`; nothing is counted. Used by this
   key, it answers the acceptance it kept for the use (`accepted/<id>`; made again, without `ADMITTED`, from the proof key
   when none was kept), and does nothing else: no step below runs again, no anchor is adopted and no members entry is
   signed — a person a later members entry removed is never added back by its code. A key whose use a stop interrupted
   (`using/<id>` naming it, no `used/<id>`) goes on through steps 7–10 and the use again.
7. **Not expired**: its expiry is after this device's clock now. Else `Expired`.
8. **The asker's tries are not spent**: fewer wrong tries of this key counted than the
   offer's `TRIES`. Else `Closed`.
9. **The proof is right** (§4.1), for that key and its public key's digest. Else the wrong
   try is counted against the key, and toward the overall cap once the pause after the last
   one counted there has passed (`IntroPolicy::backoff`, 1 s by default, doubled by each
   counted, by this device's clock); both made durable before the answer (§9.6). At the
   overall cap the device writes `closed/<id>`, durable before the answer, and answers
   `Closed`; at the key's `TRIES`, `Closed`; below, `WrongProof { left }`, the key's wrong
   tries left.
10. **The asker's namespace is no other's**: a prefix of `J`; not the root; not one the policy
    refuses (§14) — fewer components than `IntroPolicy::min_components` (1 by default: `/alice` is
    a person's namespace, the root never), equal to, under or over a name of
    `IntroPolicy::reserved` (by default `/localhost`, `/localhop`: scopes, never a person's), or
    equal to or over a name of `IntroPolicy::shared` (§14); not the inviter's own nor under or
    over it; not under or over any namespace this device trusts; and not one it trusts under
    another anchor. The same namespace under the same anchor is a party it knows already, and is
    not refused. Else `Conflict` (`FixLocal`).

### 9.3 The use

Then the use. The device, in this order:

1. **Notes the key the use is for**, durably: `using/<id>`.
2. **Has its host adopt the asker's anchor** (`Host::adopt` of an inline anchor link of the
   presented context; a self-certifying asker namespace is adopted from its genesis, as in §8.2
   step 5, and then every anchor of the presented context MUST be an anchor of the context the
   host holds for it, by public key, else `Conflict`).
3. **Checks the asker's proof packet again** by this device's validator — by the context it now
   holds for the asker's namespace, through the presented certificates — which MUST find the same
   key, else `Conflict` (a key the held version revokes, shown with an older version, does not
   ask); takes into its validator the certificates on the verified chain from the asker's key to
   its anchor, named under the asker's namespace, and no other presented certificate.
4. **Makes the members entry**, one `Heap::change(MembersChange { add_writers: [ns] if the role is
   writer, add_readers: [ns], remove: [] })` of `S` (§9.4), unless the fold lists `ns` already in every role asked. The
   `EntryId` it returns goes into the answer as `ADMITTED`.
5. **Keeps the acceptance, the use mark and the grant** in one durable batch (`Node::flush`) before the answer:
   `accepted/<id>` (the acceptance it answers: the offer, the asker's key and digest, the space, the role, `ADMITTED`, the
   inviter's credentials and the inviter's proof packet, the answer proof), `used/<id>` (the key and the digest), the grant note
   (§10 rule 3), and the removal of `using/<id>`: all of it is there before the answer, or none.
6. **Tells the host** (`Host::grant`, once, §10 rule 3), and only then sends the answer.

If the adoption or the entry fails, the device drops `using/<id>` durably — the offer is not spent — and gives
no answer (a Nack); if the host adopts the asker but the namespace it adopted from its genesis does not hold the presented
anchors, or the asker's proof does not verify under the namespace as this device now holds it, the device drops
`using/<id>` the same way and answers `Conflict`. The joiner's retry is judged again. If the durable batch of step 5 fails,
`using/<id>` stays and the device gives no answer: a retry in the same run runs the use again (step 6 of the checks lets no
other key in, and no other key is counted). A stop after step 1 and before the batch is a stop the node did not make, so the
next start closes every offer (§5.4): the retry meets `Closed`, nobody is admitted by the offer, and the owner makes a new one.

### 9.4 The inviter's effect on the space

The inviter's whole effect on the space is **one members entry**, signed by this device through the
heap: `Heap::change(MembersChange { add_writers, add_readers, remove: [] })`, with the asker's person
`ns` (the namespace the exchange adopted, never one the asker merely claims over another) as a writer when the role
is writer and as a reader (a writer of a sealed space MUST also be a reader, heap.md §5.7). Everything the heap
does for a members change follows from it: a reader's `ADD` names the epoch in force, so the reader is in its
audience and is granted its key by the pull of heap.md §6.5 with no new epoch (heap.md §10.3). The crate signs no
entry of its own, adds nothing to the space but this entry, and needs no walk or note from the joiner beyond §8.5.

**When no entry is made.** The device reads `Heap::members()` first. When the fold lists `ns` already in every role
asked (as a writer when the role is writer, and as a reader — a public space lists every person as a reader) it signs
nothing, and the answer carries **no `ADMITTED`**: the joiner then waits for the fold alone (§8.5). Otherwise it makes the
one entry; the heap itself skips a role in which the person already stands.

The entry's `EntryId` (the device, seq and signed-region digest of the entry `change` returned, heap.md §10.3) goes into
the answer as `ADMITTED` (§16.1): the id `Heap::change` returned, which is the last entry the change signed — its Members entry,
or the Epoch entry it owed a sealed space, which follows it in the same log (heap.md §10.9). It says which entry admitted the
joiner: the joiner waits for exactly that entry (§8.5), so it never returns before it is applied here, and an entry that raced it
(another owner device's entry, a removal) cannot be taken for it. The inviter's `change` is subject to heap.md §10.3: `NotOwner`
from a device that is not an owner device (`offer` refuses such a device first, §5.3, so what is left is a device that stopped
being one after its offer was made), `Refused` from a revoked or suspected key, `Local`
from the disk.
When it fails, the device drops `using/<id>`, signs nothing more, and gives no answer (a Nack): the joiner's retry is
judged again.

### 9.5 Replay: one key never two

An ask replayed by anyone gets the answer kept for it: bound to the asker's key and digest, it admits
only the asker's person, which the fold already lists; it shows the replayer the space's name, the role
and the inviter's public credentials (the answer is not sealed). A replay after the inviter's device
dropped the kept answer is judged again by the checks of §9.2: a used offer answers its user's kept
acceptance (`accepted/<id>`: it admits nothing) and anyone else `Used`, counting nothing; an unused
offer counts a wrong try again against the replayed key (when it was one). Because `used/<id>` is
written at most once, durable before the answer, and checked before every other step that could admit
(step 6), **an offer admits one key and never two**, across a restart, across a replay, and across two
asks that race (the device answers one ask at a time).

The removal of the member an offer brought lasts: the offer's user asking again — a fresh ask, before or
after a restart — is answered the acceptance kept for its use and never admitted again (§9.2 step 6),
and no other key can use it, whichever owner device removed the member. While the fold shows a removal of the
person the offer was used by (`Heap::removed_by`, §5.4) the offer counts as closed, with no mark written (§5.4): it
admits no one new, and its user alone is still answered until the offer expires, with the acceptance kept for its use
and nothing else. Nothing is adopted or signed, so asking does not make a removed member a member again, and what the
answer shows is what the code's holder already had.

### 9.6 Wrong tries, and their durability

A wrong proof (step 9) is counted twice, and **both counts are durable (`Node::flush`) before the
answer**:

- against the asker's key: `tries/<id>/<digest>`, by the public key's digest;
- toward the overall cap: `tries/<id>`, once the pause since the last try counted there has passed
  (`IntroPolicy::backoff`, doubled by each counted, by this device's clock). A try within the pause
  counts against its asker alone.

At the overall cap (`IntroPolicy::wrong_tries_max`, 16 by default) the device writes `closed/<id>`,
durable before the answer, and answers `Closed`. A restart reads the counters back from the store and
never gives a key its tries back (case i4). A stranger spends only its own tries — it cannot close an
offer meant for someone else, and a used offer counts no tries at all (case i11). Counting costs one
durable write on the path of a wrong try; it MUST NOT delay a right one.

### 9.7 A forged ask

An ask without the secret fails step 9 and is counted; it cannot be turned into another key's
membership: the proof binds the offer, the key, its digest and the nonce. An ask without valid
credentials (step 2) or whose proof packet does not verify (step 3) costs one signature check and gets no
answer. A forged ask grants nothing, whatever it counts (case i6).

## 10. Grants

An offer that admits a person can make the host's link layer link with that person,
with no change of the host's serving policy: an inviter that keeps the narrow policy
(serve devices of the namespaces it holds a certificate in) still links with the one
person it admitted and with no other it merely holds a context of. The link layer is
the host's (ndn-link.md §8.7); this crate only tells it, durably, whom. A **grant**
says: the device holding link key `K` may link, as a person of namespace `N`, in the
role `R` the space's members in force give it, for as long as the members list it —
and, only if a date `U` is set, until `U`.

```rust
pub struct Grant {
    pub key: [u8; 32],            // the asker key's public-key digest
    pub namespaces: Vec<Name>,    // the asker's namespace, as the join adopted it
    pub folder: Name,             // the space the offer admitted it to (the field keeps its name)
    pub role: Role,               // the role the fold gives it NOW
    pub until: Option<Timestamp>, // the inviter's clock; None: no date
}
pub struct Departure {            // a person let go by a held members entry
    pub key: [u8; 32],            // the person's device key (the grant's key)
    pub namespaces: Vec<Name>,
    pub folder: Name,             // the space
    pub record: Name,             // <signer device>/32=log/<space>/seq=<n>
    pub until: Timestamp,         // this device's clock: not shown after it
}
trait Host {                      // the grant part (§12)
    fn grant(&self, grant: &Grant) {}                        // default: nothing
    fn revoke_grant(&self, key: &[u8; 32], folder: &Name) {} // names the space; default: nothing
    fn departure(&self, departure: &Departure) {}            // just before revoke_grant; default: nothing
}
```

The field names `folder` and `Departure::record` were kept from the removed `ndn-data` so that ndn-link's code, which
names them, compiles with a changed import only; here `folder` is a **space** and `record` the log name
of a members **entry** (§11). The host's side of every call is §12.

1. **When it is made.** A device MUST make a grant when it answers an ask with an acceptance for the first
   time (§9.3 step 5, 6): after the asker's anchor is adopted, the asker added to the space and the
   acceptance made, and as the same durable step that keeps the acceptance and the use mark. It MUST NOT
   make one for an ask refused for any reason, for an ask whose use fails before the mark (the offer is
   not spent, §9.3), or when `IntroPolicy::grant_for` is `Some(Duration::ZERO)` (nothing is kept, nothing
   is told).
2. **What it names, and its date.** The key is the public-key digest of the asker's key as the exchange
   proved it (§9.2 steps 3–9); `namespaces` is the one namespace the join adopted (never one the asker
   merely claims over another); `folder` is the offer's space; `role` is the offer's at the admission and,
   from then on, whatever the fold makes of the namespace (rule 6). **By default a grant has no date**
   (`grant_for` `None`, `until` `None`): it follows the members, lasting while the fold lists the person
   and ending when it does not, so removal is the control and there is no day on which every link
   silently stops. `Some(d)` bounds it as well: its `until` is the device's clock when it answered plus
   `d`, and the host may renew it (rule 10). **A Reader admitted to a public space is granted nothing**: a public space
   (`Readers::Anyone`) lists nobody as a reader, so no members' entry can remove one (`Heap::change` answers "nothing to sign"
   for a person with no `ADD`), and a grant for them could never end by the rule below (rule 7) — a link slot only the host
   could take away, for data any carrier serves. The admission is made and answered as for any asker; the device keeps no note,
   tells the host nothing and says why in its log. A Writer of a public space is granted: the entry that removes them ends it.
3. **Durable before the answer, told after.** The device keeps a grant note `grant/<id>` (§15) in its
   local store: the offer, the key's digest, the namespace, the space, the role, whether it has a date and
   `until`, whether it ended, and a MAC (rule 11). The note is written with the acceptance under the
   `Node::flush` the use mark waits for, so a durable use mark means a durable note; the device then calls
   `Host::grant` once, and only then sends the answer. A note is the device's own and never served or
   published. **No TLV-TYPE is registered or used for it:** its value is a fixed-width local form: a version octet (3;
   a version 2 note, written before departure marks, is still read), flags (1 ended, 2 dated, 4 marked — a mark only on
   an ended note), the role (0 reader, 1 writer), `until` (8 octets, big-endian, zero when undated), the key digest
   (32 octets), three Name TLVs each behind a 2-octet big-endian length — the offer, the space, the namespace — on a
   marked note the mark's date (8 octets) and its record Name in the same form (rule 14), then the 32-octet MAC;
   like the other notes under `/localhost/ndn-invite/`. A note this version does not read, or whose MAC does not
   check, is ignored, and the device logs which and why (a person whose note is ignored has no grant: offer
   the space to them again).
4. **A retry grants nothing.** An asker answered again (§9.2 step 6: the acceptance kept) MUST NOT be
   granted again and its date MUST NOT move, however many times it asks and after any restart or close of
   the offer. Another key presenting a used offer is refused and granted nothing.
5. **Never wider.** A grant informs; it MUST NOT change what the members admit (heap.md §5), the epoch keys
   a device may hold (heap.md §6.5) or what the layer answers. It names the space and the role so the host
   can narrow a link (a reader's link sends Interests only), never to admit more. The host MUST use a grant
   only to link with the named key as a person of the named namespaces, never for the person's other keys
   or namespaces.
6. **In force, in the role the fold gives.** `Invites::grants` lists the grants whose offer this device made
   and used by the very key the note names, that have not ended, whose date (if it has one) has not passed
   by the device's clock, and whose space's fold lists the namespace as a writer or as a reader
   (`Heap::members()`, heap.md §5.4; in a public space every person is a reader unless a held entry removed it).
   Its `role` is **derived from the fold at every call**: a writer if the fold lists the namespace as a writer, else a
   reader — never the role the offer had. **The grants are re-evaluated on every `Change::Members`, `Change::Alert` and
   `Change::Lagged` of a followed space (`Heap::watch`, heap.md §10.4), every half of the node's `svs.sync_interval` (never
   faster than every 10 ms: the poll the plan keeps for a watcher that is slow), and once at start**: a restart installs every live
   grant and every departure mark in force again through `Host::grant` and `Host::departure`. When a change alters the role of a
   grant, the device updates the note durably and calls `Host::grant` again with the grant as it now stands (the host replaces its
   grant; ndn-link closes a link made under the old scope); a writer demoted to a reader is a reader at once, not at the grant's end.
   It is derived from the notes and the fold, so it is the same after a restart, less what ended. While the space is not open here,
   or its creation is not held, **no grant of it is in force and the host is told `Host::revoke_grant` for it, once** (fail closed:
   the members of a space that cannot be read cannot say the person is still in — an owner device elsewhere may have removed them
   while the space was closed here — so a link the grant opened is not left standing on a fold that was not seen). The note does
   **not** end: the space may only be closed here, so the note waits for the fold to be seen. The first judgement that finds the space
   known and the fold listing the person **installs the grant through `Host::grant`** again (it is not among what the host was told in
   this run, whether its space was not restored when the invitations started or was closed since), once; one that finds the fold leaving
   the person out ends it as rule 7 says, with its departure mark.
   The watch of a space is subscribed from everything held (`Frontier::everything`, heap.md §10.4): it replays no head and reads no
   value, since only the members' changes matter, and the first judgement after subscribing covers what changed before it. One
   `Grant` is listed for each live note (rule 13).
7. **It ends** at its date, if it has one (the link layer judges it by its own clock; the device does not
   announce a lapse), when the host ends it (rule 9), or when the fold of **the grant's own space** lists the
   namespace neither as a writer nor as a reader (each note is judged against the fold of its own space, so a
   person left out of one space keeps the grants of their other spaces: rule 13). The device checks this on
   every `Change::Members` of a space and at start, whoever of the space's owner namespace signed the entry
   that removed the person, not only the offering device. It MUST then call, **in memory and first**,
   `Host::departure` (rule 14, when a mark is made) and then `Host::revoke_grant` once with the key and the
   space — the safe direction, so that a slow or failing flush never delays the link layer's end — and only
   then mark the note ended (with its departure mark) durably: a stop in between leaves a note not yet ended,
   which the next start judges again (the host revokes again, harmlessly), never a link that outlives its
   removal for want of a flush. An ended grant never returns: a person readmitted by a later entry is no
   longer granted by the old offer (they join again with a new code). A change that drops the person also
   closes the offers that person used (§9.5).
8. **The host's part.** `grant`, `revoke_grant` and `departure` are called from the device's tasks and MUST
   NOT block or call back into the crate. A host whose link key is not the key the device knows (the asker's
   *device* key) adopts the grant itself with the link key it knows. A host with no link layer ignores all
   three.
9. **The host ends a grant.** `Invites::end_grant(key)` marks every grant note of that key not yet ended as
   ended, durably (`Node::flush`, before it returns), so a restart does not bring it back; it returns `true`
   if there was one not yet ended (past its date or not), `false` if none. It tells the host nothing: the host
   that calls it ends its link layer's grant itself. The person stays a member of the space — removing them is
   a members entry, which also ends the grant. A host that only calls the link layer's own revoke
   (`Links::revoke_grant`) has made an in-memory change that a restart undoes; ndn-link's `LinkHints` calls
   this. `Invites::end_grant_in(key, space)` ends only the grants of that key of one space (the person's other
   spaces' stand) and makes no mark.
10. <a id="renew"></a>**The host renews a grant.** `Invites::renew_grant(key, until)` sets the date of every
    grant of that key not ended **and** that the fold of its space still lists the person for — one past its
    old date is renewable, one an entry left out or the host ended is not (offer the space again) — durably,
    and returns the grant as it now stands (the first by offer when several offers admitted the key) or `None`
    when there was none to renew. `Some(t)` is the new date and MUST be after the device's clock (else
    `BadRequest`, saying so: give a later date, `None`, or end the grant); `None` gives it no date, so it
    follows the members. It tells the host nothing: the caller installs the returned grant. ndn-link's
    `LinkHints::grant` calls it when it is given a later date than the one in force.
11. **Notes are authenticated.** Of what a grant rests on only the use mark's key is named by the exchange, not
    the note's `ended` flag, date or role, so the note carries a MAC: HMAC-SHA256 over every octet before it
    under a key derived (HKDF-SHA256, the domain label `ndn-invite/grant-note/mac-key/1`) from the device's
    recipient secret, which the key store keeps and the data store does not. A party that can write the data
    store but not the key store therefore cannot clear `ended`, extend or remove a date, change a role or move
    a note to another name: the note fails its check and is ignored, with a logged warning that says so
    (rule 3) — so a removed person is not resurrected by an edited store. The MAC is the choice over deriving
    the ended state from signed data because the host's end (rule 9) has no signed record behind it to derive
    from. **What it does not do:** it does not detect *rollback*. A party that restores an older, genuine copy
    of a note (one whose `ended` flag was clear, or whose date was earlier or later) brings back an older state
    of that note. That is bounded by what the device holds besides the note: a grant the fold does not list is
    not in force whatever the note says (the fold, not the note, is the judge, and the end is told again), and
    no note can name a person whose key `used/<id>` does not name. What rollback can bring back is a grant the
    *host* ended while the fold still lists the person, or an older date: end it again. A **departure mark** is
    inside the MAC (rule 14): it can be neither added to a note the host ended, nor cleared from one an entry
    ended, nor moved (its date extended), without the note failing its check and being ignored.
12. **Faulty networks.** A lost answer is the joiner's retry (rule 4); a grant is made once per admission, on a
    clean or a faulty network; a departure's entry is fetched by name like any entry, asked again under loss
    (heap.md §7.4).
13. **A set of grants per person.** Each admission makes a note of its own, so two offers — of two spaces, or
    of one — to the same key make two grants of one key that differ in `folder`, and `Invites::grants` lists
    **one `Grant` per live note**, sorted by key, then space. The device judges **each note against the fold of
    that note's space** (rule 7): a change that leaves the person out of space `S` ends `S`'s grant and `S`'s
    note and no other, and `Host::revoke_grant(key, S)` names `S`. A host's link layer MUST therefore keep, per
    key, a **set of (space, role) entries**: a grant adds the entry of its space or replaces the entry of the
    same space, and never closes a link while another entry of the key stands; a `revoke_grant(key, S)` ends the
    entry of `S` and closes the key's links only when it was the last (ndn-link.md §8.7).

## 11. Departures and mirror grants

Rules 14, 15, 17 and 18 continue the numbering of §10 (the numbers of the rules of §19.8 of the former data layer, history/data-layer-remainder.md, kept so that a test or a
note can cite one number for one rule). Rule 16, the co-writers, is the surface's and is §13.3.

14. **A person let go is told: the departure mark.** When a held members entry ends a grant by leaving the person out (rule 7), and
    `IntroPolicy::departure_for` is not zero (default seven days), the note keeps a **departure mark**: the log name of the members entry
    that removed the person — `<signer device>/32=log/<space>/seq=<n>` — and the date after which the mark is no longer shown (`until`,
    by this device's clock, the end's time plus `departure_for`). The entry is the one `Heap::removed_by(person)` names, a function of the
    entries applied (heap.md §10.3): of the applied Members entries that remove an `ADD` of the person's, the one of lowest signed-region
    digest (heap.md §1.5), so every device that holds the same entries names the same one; it is `None` for a person the space still lists,
    one it never listed, and the owner. When it names none (the person was dropped by a cut that no members operation names), **no mark is made**
    and the link layer just closes (a fallback that is never an open link). A mark is made **only when a held entry ends the grant**:
    `Invites::end_grant` and
    `end_grant_in` (the host's end, which no entry lets the person go by) make none, and a host that wants none for any end sets
    `departure_for` to `Duration::ZERO`. The mark is inside the MAC (rule 11). `Host::departure` is called **once, just before
    `revoke_grant` of the same grant** (in memory, before the note is durable, so a link layer that narrows its link at its last entry's
    end already holds the mark), and never when no mark is made. `Invites::departures()` lists the marks **in force**: of ended notes whose
    MAC checks and whose use mark bears them out, whose `until` has not passed by the device's clock, and **not superseded** by a live
    grant of the same key for the same space (the person was invited again); sorted by key, then space. A host that links installs them at
    start (`Host::departure` for each), as it installs the grants. Two notes of one key keep a mark each. A mark's record is **named,
    never carried, by this crate**: `departure_carries(record, name)` (a pure function of two names: the entry's name with or without its
    implicit digest, its pieces `<record>/32=piece/seg=<i>` and `<record>/32=piece/32=manifest/seg=<k>`, nothing else) is what a link
    layer's departure link filters by (ndn-link.md §8.8).
15. **The departed person's side.** `Surface::take_departure(from, space, record)` is what the person's host calls when its link layer was
    told, by the inviter's, which entry let it go (`Departure`, ndn-link.md §8.8). `from` is the **authenticated device of the peer that
    told it** (the link layer's: a full link, whose peer's certificate validated in a namespace this device holds; never an enrollment or
    introduction link). It fetches `record` by name with `Node::fetch_entry` (heap.md §10.9): the writer is asked, then the members that
    vouch for its log. The entry is taken **as any held entry**: the signature and chain are validated, the entry is judged
    and applied as ever, so this device's own space then no longer lists it, it withdraws what it wrote after the cut and takes no more
    writing there. **The name carries no authority**; the call MUST refuse (`BadRequest`, saying why and what to do) unless (a) `space`
    is a space name, (a2) `from` lies under the owner namespace of `space` (only a device of the space's own namespace lets a member go
    of it; checked first, so a refusal costs the fetch slot and the minute's bound nothing), (b) `record` is a log entry whose space is
    `space`, (c) this device has the space open (it is, or was, a member), and (d) the record's device lies under this device's own
    namespace or a namespace this device holds a trust context of. The call does not separately require that what is fetched is a
    members entry: the heap admits an entry only as the judge of heap.md §3.8 allows, and an entry that is no members entry changes
    nothing about who the space lists (§20). An entry already held is `Ok` at once (for a `from` that passed (a2)). At most
    **one take of a space is in flight** and at most **six begin a minute** (the device's clock; a bound on a hostile inviter's stream of
    hints, not a correctness rule): the call is `NotReady` — ask again — for either, and when the entry could not be fetched. Correctness
    never depends on timing: the person's own space keeps being judged by the entries it holds, whether it was told or not.
17. **The mirror grant: the joiner's end.** A successful `join` keeps, after the entry that admits the device is applied (§8.5), a
    **mirror note** — durable before `join` returns, the host told after (`Host::grant`): the inviter's **key** (the digest of the key that
    signed the answer, which the join verified belongs to the offering device under the anchor the code named), the **space**, and the
    inviter's namespace as the space's **owner**. It is the mirror of the inviter's note (rule 2) and is kept the same way: a fixed-width
    local value under `mirror/<space>/<key>` (§15; never served, never on the wire, **no TLV-TYPE registered**): a version octet (1),
    flags (1 ended), the inviter's role (0 reader, 1 writer), the inviter's key digest (32 octets), the space and the owner as Name TLVs
    each behind a 2-octet big-endian length, then an HMAC-SHA256 over every octet before it (32 octets), under a key derived (HKDF) from the
    device's recipient secret **with labels of its own** (§4.5), so a mirror note is never read as an inviter's
    note nor the reverse; a note that fails its check, or is of a version not read, is ignored with a warning that says why and
    what to do (join again with a new offer). The note names **no role the device trusts**: the entry's role is **re-derived from the fold
    at every judgement** — a writer when the space lists the owner's namespace as a writer, else a reader, never wider than the fold says —
    and the entry **stands only while the fold lists this device's person** (a writer when the fold lists it as a writer, else a reader; a
    public space lists every person as a reader — and a device that **only reads** a public space keeps no mirror note, for the same
    reason as rule 2: nothing could end it but the host). A space not open here: no entry (nothing to judge by, so nothing is granted). The note
    is kept **only for a space owned by the inviter's own namespace** (`owner(space) == owner`): a hostile offer that names a space of the
    joiner's own namespace — whose fold lists the joiner — would otherwise grant the inviter a link into it. When the note is not kept
    (that, or a fold that does not list this device's person, or a space not open here) the join says so in its log, keeps nothing, and still
    returns `Joined`: it is the grant that is missing, not the admission, and a new offer makes it. `Invites::grants()` lists a live mirror entry like any grant (key = the inviter's, `namespaces = [owner]`, `folder` the space,
    the inviter's role, `until = None`: it follows the fold); `Host::grant` is called once the note is durable and again when a change alters
    the inviter's role; `Host::revoke_grant(key, space)` when a change leaves this device's person out (in memory first, then the note is
    marked ended durably); **`Host::departure` is never called for a mirror**: the person who is let go is told by the inviter (rules 14–15),
    and a mirror only admits the inviter's own link. The entry **ends** with the change that no longer lists this device, or with the host:
    `Invites::end_grant(key)` ends the key's inviter notes *and* mirror notes, `end_grant_in(key, space)` those of the space (durable, no
    mark, the host is not told, as for the inviter's notes); `renew_grant` never touches a mirror (it has no date). One entry for each
    `(inviter key, space)`: a second join of the same space by the same key replaces the entry (a re-invitation after a let-go starts it
    again), another key of the same person is another entry, and the entries of other spaces stand (the per-entry ends of rule 13; the link
    layer closes the link when the last entry of the key ends, ndn-link.md §8.7). **Mutual invitations**: Ann invites Bob to A and Bob invites
    Ann to B; each device holds an inviter's note of one space and a mirror note of the other for the same peer key, and they are entries of
    different spaces (a space has one owner, so an inviter's note and a mirror of one `(key, space)` cannot both exist): neither replaces the
    other, `end_grant_in` ends one, `end_grant(key)` ends both. A host whose link key is not its device key calls `Links::grant` for the
    inviter's link key itself, as it does for the grants it makes.
18. **The spaces joined, and what the link routes for them.** `Invites::joined_folders()` lists, for each live mirror entry whose fold still
    lists this device's person, a `JoinedFolder { inviter, owner, folder, role, writers }`: the inviter's key, the owner, the space (the field
    keeps its name), **this device's** role, and the **other writers' namespaces** the fold lists **minus** the owner's, this device's own
    namespace and every namespace **above or below** it (a hostile inviter's entry cannot make the joiner route its own names, or `/` or a
    broad parent of them, toward the inviter), **and minus every name that could take a name from a better route of this device's own.** A
    writer in the fold is a person the inviter's owner devices listed, and a forwarder takes the longest matching prefix first, so a route at a
    name beats every shorter route for the names under it, whatever its cost. A name `W` is therefore listed only when
    `IntroPolicy::refuses(W)` says nothing against it (not the root, not `/localhost` or `/localhop`, not a broad shared name such as `/user`
    or `/com`, not fewer than `min_components`); **and** it names itself: it is the namespace of a trust context held here or a
    self-certifying person's namespace, never a free-form prefix; **and** it lies neither above nor below any namespace held here or adopted
    for a space, except an exact match (the same prefix, where cost decides). Only names that are namespaces, at most `JOINED_WRITERS_MAX`
    (16) in the order of `Name`, sorted by space then inviter. It is **derived on every call** from the fold and the MAC'd note, never cached,
    and carries no authority: the link layer routes by it (ndn-link.md §8.7 rule 18: the prefix `W` of each writer namespace over the link of
    exactly that inviter, and, **only when this device's role is writer**, `<W>/32=sync` beside it — the writers' groups are the writer-push
    route, and a reader is routed `W` only), and the inviter's per-packet filter still decides what crosses. `Invites::joined_changes()` is the
    **change notification**: a `tokio::sync::watch::Receiver<u64>` whose value is raised, and never repeats within a run, whenever the list
    derived differs from the one the value stands for — at a join, after every `Change::Members` of a joined space, at a host's end — and
    **only then** (a settle that changed nothing moves nothing). A watcher reads `joined_folders()` after each change; a surface whose
    `Invites` is gone yields a receiver whose sender is dropped (`changed()` errors at once and ends the watcher). The grants have a pull
    surface (`Invites::grants()`) and a push the host forwards (`Host::grant` / `revoke_grant`); the joiner's routes need no host forwarding,
    so a host that already calls `LinkHints::serve(&invites)` does nothing more.


## 12. The host

`Host` is what the crate asks of the object that embeds it: the trust anchors, the link layer, the link
hint. It is the previous design's `Introducer` less `adopt_scoped` and `release_scoped`, which are
heap.md §9.4's `Adopter` (they adopt a person for one space's judging, not for the node, and belong to the
node, not to the invitations). A host implements `Host` for `Invites::start` and `Adopter` for
`Node::start`; the two are independent.

```rust
pub trait Host: Send + Sync {
    fn anchor(&self) -> Option<Bytes>;
    fn adopt<'a>(&'a self, link: &'a TrustEnvelope) -> Adopting<'a>;
    fn link_hint(&self) -> Option<LinkHint> { None }
    fn dial<'a>(&'a self, hint: &'a LinkHint, inviter: &'a Name, within: Duration) -> Dialing<'a> { /* Err: no link layer */ }
    fn dial_first<'a>(&'a self, inviter: &'a Name, addr: SocketAddr, within: Duration) -> FirstDialing<'a> { /* Err: no link layer */ }
    fn undial(&self, hint: &LinkHint, inviter: &Name) {}
    fn grant(&self, grant: &Grant) {}
    fn revoke_grant(&self, key: &[u8; 32], folder: &Name) {}
    fn departure(&self, departure: &Departure) {}
}
pub type Adopting<'a>    = BoxFuture<'a, Result<(), String>>;            // LocalBoxFuture on wasm
pub type Dialing<'a>     = BoxFuture<'a, Result<(), String>>;
pub type FirstDialing<'a> = BoxFuture<'a, Result<[u8; 32], String>>;
```

| Method | When the crate calls it | What it MUST do | Default |
|---|---|---|---|
| `anchor` | to give credentials: the signed trust-context Data of this device's namespace, whole, as the host adopted it (what an inline anchor link carries), by `offer`, a join, an answer and a hint record | return it, or `None` when none can be made: `offer` and `join` then refuse with `Local` (fix the host's enrollment), and a hint request is met with silence | — (required) |
| `adopt(link)` | after the crate checked `link`, an inline anchor link (`TrustEnvelope::Anchor`: namespace, fingerprint, signed context): by the joiner at §8.2 step 5, by the inviter at §9.3 step 2 | `Ok` once this device's validator trusts the namespace; an error says why not. A host on a forwarder adopts through it so the forwarder also validates and routes the namespace. A self-certifying `/user/<h>` not held is adopted by name over the network (version 1 fetched and checked against the name, the newest reached from it; the context the link carries is never taken alone, a version 1 only compared with the fetched one, a different one refused as a fork); with no network to fetch over, refuse, saying to join again once the person's devices are reachable | — (required) |
| `link_hint` | once per `offer`, and once for each hint record made on request (§7.1 item 4) | the device's link key and at most `LINK_HINT_CANDIDATES_MAX` candidates, so a joiner with no routes and no daemon dials this device by key | `None`: the code carries no hint |
| `dial(hint, inviter, within)` | by the joiner, once per `join`, before any Interest (§8.2 step 0, §8.3 S6) | try `hint.candidates` in order and link only to the device whose key is `hint.key` (the handshake proves it; an address that answers with another key is no link), within `within` in all. `Ok` once a link is up that carries `inviter`'s introduction names to it, **in transit** (§12.1). Send nothing of the code's secret | an error saying the host has no link layer to dial with and what to do |
| `dial_first(inviter, addr, within)` | by the joiner, once, for a short code's address first contact (§8.3 S3) | dial **one** address with **no key to expect** and an **empty hello** (no certificate, no membership: ndn-link.md §13.3A); `Ok(key)` is the SHA-256 of the public key the handshake proved; until the joiner holds the inviter's namespace the link routes only `introduction_prefixes(inviter)` (§2.3), carried in transit (§12.1), never the names the code claims for the device, and receives answers under those prefixes and Interests under the joiner's own device names only | an error saying the host has no link layer, so the join says the first contact could not be reached |
| `undial(hint, inviter)` | by the joiner, when a join fails after a dial, and at once when the verified record's key is not the first contact's (§8.3 S6, S8) | take down the link the dial made, unless it was up before the dial or has been identified since | nothing |
| `grant(grant)` | by the inviter, once after the acceptance and the note are durable (§10 rule 3); again when a change alters the role (§10 rule 6); at start for every live grant; by the joiner for a mirror grant (§11 rule 17) | install the grant (§10 rules 5, 8, 13) | nothing |
| `revoke_grant(key, space)` | when the fold stops listing the person (§10 rule 7), in memory and **before** the note is durable | end the entry of `(key, space)`; close the key's links when it was the last (§10 rule 13) | nothing |
| `departure(departure)` | just before `revoke_grant` of the same grant, only when a mark is made (§11 rule 14); at start for every mark in force | keep the mark so the link layer can tell the person which entry let it go (ndn-link.md §8.8) | nothing |

**Guarantees of the crate to the host.**

1. Every call is made from the crate's own tasks. `grant`, `revoke_grant` and `departure` are not awaited and MUST NOT block or
   call back into the crate (§10 rule 8).
2. `grant` is called after, never before, the note it reports is durable; `revoke_grant` is called before the
   note's end is durable (§10 rule 7).
3. `adopt`, `dial` and `dial_first` are called only after the code was judged (§8.1) and, for a short code,
   only after the hint record verified (§8.3 S5), except `dial_first`, which is the first thing a short code's
   address causes and is made with no key and an empty hello for that reason.
4. `adopt` is never called with a link the crate did not check; the host need not check it again, and MUST NOT
   adopt anything else on the crate's account.
5. A host with no link layer implements `anchor` and `adopt` only; every other method has a default that does
   nothing or says, in its error, what to do instead.


The futures are boxed (`LocalBoxFuture` on wasm32, as ndn-heap's other aliases): the crate holds the host as
`Arc<dyn Host>`.

### 12.1 The host carries the introduction in transit (normative)

The joiner's forwarder holds no trust of the inviter: the inviter's namespace is adopted only at §8.2 step 5, after the offer and the
answer have been fetched. What the exchange fetches is therefore carried by the host's forwarder **without validating it**, and judged
by this crate alone:

- the **offer** `<D>/32=intro/32=offer/<id>` and the **hint record** `<D>/32=hint/<token>` are Data signed by a key of `D` (through
  `Node::sign_packet`), which a validating forwarder that does not yet trust `D`'s namespace cannot validate;
- the **answer** is signed with **DigestSha256** (`offer.rs`: `DataBuilder::new(…).sign_digest_sha256()`), named as the ask: its
  authenticity is the offering device's proof inside it (the answer proof of §4.1 and the inviter's proof packet, checked at §8.2
  step 3), not the forwarder's.

Rules for a host that implements `Host::dial`, `Host::dial_first` or carries a join's Interests by forwarding hint:

1. From the first contact (`dial_first` or `dial` returned `Ok`, or the first Interest of a join with no dial) until `undial` or until
   the join ends (it succeeded and the host holds and identifies the inviter's namespace, or it failed and `undial` took the link down), the
   host **MUST carry `introduction_prefixes(inviter)`** (`<D>/32=intro`, `<D>/32=hint`, §2.3) **in transit**: Data under them is forwarded
   to the pending Interests only, **unvalidated** and **not cached** (ndn-link.md §15.7 describes transit for served namespaces).
2. It carries those two prefixes of that device and nothing else of it: the link of a first contact routes no other name of `D` (§8.3 S3).
3. Transit grants no trust. The crate verifies every packet itself before it acts: the hint record at §8.3 S5, the offer at S7 and §8.2
   step 3, the answer at §8.2 step 3.
4. A host that does not carry the prefixes in transit fails the join at the offer fetch: the offer does not reach the joiner, no
   answer comes within the eight tries, and `join` returns `NotReady` ("the inviter's device … does not answer", `join.rs` `offline`)
   after calling `undial`. This is a host's defect, not the code's: the join is refused, never accepted unverified.

Implementations: ndn-link's `LinkHints::dial` and `LinkHints::dial_first` pass `introduction_prefixes(inviter)` as the link's routes
(ndn-link `src/hints.rs`, over `Links::dial_by_key` and `Links::dial_first`); the conformance stand-in host does it explicitly; the
`ndn-heap` tool (`ndn-fwd`, a host with no link layer, so no `dial` call) asks its daemon to carry the two prefixes in transit
(`security/transit`, mgmt-trust.md "Transit") for the length of each `join` verb, naming the inviter by `Invites::inviter_of(code)` (the
device a code names, read as `join` reads it, with nothing dialled or asked): a host with no dial has no other call before the first
Interest.

## 13. The introduction surface and the folder scope

A host that listens for links asks this crate **what may cross a link**, by name, per packet. `Invites::surface()` gives a
`Surface` (`Clone + Send + Sync`, holding the crate's state **weakly**, so the host's links never keep the invitations alive); its
decisions are pure functions of names and of state held now, and nothing is cached.

### 13.1 What an introduction link carries

The surface is **open** while an offer of the device has not expired by its clock — a closed offer counts, since it still answers
the key it admitted until it expires. With no offer open, a stranger is refused a link as any device nobody knows (ndn-link.md §8.6),
and a joiner that dials after the last offer expired meets no link, not a gone mark (§8.3 S3).

Over the link `Surface::carries(name)` is true for exactly these names of the device `D`, and no other:

1. the ask, `<D>/32=intro/<ParametersSha256Digest>` (exactly one digest component after `32=intro`, §2.2), while the surface is open: no
   other name under `<D>/32=intro` crosses, neither the bare prefix nor a name of another form;
2. the offer's own packet, `<D>/32=intro/32=offer/<id>` (§2.2), for an offer of this device that has not expired (a well-formed
   offer name of another id, or of an offer past its expiry, is not carried);
3. a short code's hint record, `<D>/32=hint/<token>` (§2.2), `token` that of one of the device's own offers with a short code, whether
   the offer is open, closed or expired: the answer is then its gone mark (§7.1 item 3).

No other name crosses: not another name of the `32=hint` family (the prefix alone, a token the device does not hold), not any log
entry, piece, seal key or held copy the device holds by name — though the device serves them to its members — and nothing of another
device. The offer is fetched by its own name, so the previous design's `32=held` family is gone. **The two prefixes**
`introduction_prefixes(D)` = `[<D>/32=intro, <D>/32=hint]` are what a dialled link routes, the surface's per-name decision is what it
carries (ndn-link.md §13.3, §13.3A). `Surface::open()` answers whether some offer has not expired, for the link layer to decide
whether to admit a stranger at all.

### 13.2 What a grant link carries: `folder_carries`

A grant admits a person to the *link*; the layer above answers by name to whoever asks, and some of what it holds is not sealed (a public
space, the members entries themselves). So a grant link carries only the names of **the space of the grant**, as a pure function of the
two names by the grammar of heap.md §2.3: nothing is looked up and nothing is cached. `folder_carries(space, name)` is true for
(with or without a trailing implicit digest — an Interest may name the packet it wants whole):

- an entry `<D>/32=log/<space>/seq=<n>` **of this space** (any device, whatever device wrote it), and a piece or manifest node
  `<E>/32=piece/…` of such an entry (heap.md §2.2); never an entry of another space, even one whose name extends this space's;
- a seal key `<W>/<role>/<device>/32=seal/<public key>` of a device of the space's **own owner namespace** (exactly two components below
  the owner, the first a role of the layout), and a grant ask `<G>/32=grant/<GrantAsk>` of this space **to a device of the owner's
  namespace** (the epoch's creator, or another owner device that holds the key: heap.md §6.5); no other seal key, no other granter;
- a held copy `<H>/32=held/<Name TLV>` about a name carried by these rules, to the depth of two held names, and not deeper.

Not carried by these predicates: the sync group of the space (the link layer routes the owner's `<O>/32=sync` and filters to the granted
space's own group, which the heap names, `ndn_heap::wire::sync_group_of(space)`: ndn-link.md §8.7 rules 10 and 20, and §13.3 below; the namespaces'
own groups are the link layer's too), certificates and the trust
context (the link layer's: they are the namespaces', not the space's), introductions (the surface's, §13.1), anything that is not a name
of this layer. `false` for a `space` that is no space name, so a grant for no space carries nothing.

### 13.3 Co-writers (rule 16)

`Surface::grant_carries(space, name)` is what a link layer asks, per packet, for a grant link: `folder_carries(space, name)` or
`writer_carries(space, writer_namespaces(space), name)`, the writers read **live, on every call**, from the fold of `space`
(`Heap::members()`; no cache), so a writer the fold no longer lists drops out at the next call and one it lists appears at the next.

The namespaces are **derived by the device, once, for every use** (`Surface::writer_namespaces(space)`): each writer person the fold
of `space` lists now (a person is a namespace, matched exactly, heap.md §1.2: the fold lists persons, not name prefixes, so nothing
is looked up through trust contexts), the space's own owner excluded (`folder_carries`'s), sorted and without repeats; empty when the
space is not open here or its creation is not held. The functions take these namespaces, never the writers' names, and match a name's
namespace **whole**: a writer namespace `/home/carol` unlocks the names of `/home/carol`'s devices — never those of the broader
`/home` its name merely starts with.

`writer_carries(space, namespaces, name)` adds only what a writer invited by an invitation of its own needs to reach the other
writers' devices and keys:

- the **seal keys** of the devices of each listed `W` (the exact name `<W>/<role>/<device>/32=seal/<public key>`), so that one writer
  can ask the other's device for a grant (ndn-link.md §8.7 rule 20);
- a **grant ask** `<G>/32=grant/<GrantAsk>` of this space to a device `G` of a listed `W`, in the same exact device form (a co-writer reads
  in the epoch too, so the asker's granter list names it, heap.md §6.5), and no other: a member must not make the owner's forwarder relay
  grant asks of its choosing to devices that never held the key;
- a held copy about a name carried by these rules, nested to the depth `folder_carries` unwraps held names to, and not deeper.

Nothing of a writer outside the space is added: the other writers' entries and pieces of the space are carried
already, whatever device wrote them. A reader-role grant gains nothing by it: the link layer's push scope stays the person's own devices'.

**The space's sync group is the link layer's, in two halves** (ndn-link.md §8.7 rules 10 and 20; the hook is ndn-link's
`Introductions::sync_group(space)`, answered by `ndn_heap::wire::sync_group_of(space)`, heap.md §2.5). The link layer **routes** the
owner-wide prefix `<O>/32=sync` over every full link to a granted key (the heap node registers that prefix in the forwarder, and a
longer route would shadow it), while its **filter** carries only the Sync Interests `<group>/v=N[/…]` of the granted space's own group,
exactly: not the owner's other spaces, and not a nested space `n/f1` under `n`. The predicates of this section do not decide it.

### 13.4 What a departure link carries: `departure_carries`

`Surface::departure_carries(record, name)` is the filter of a departure link (ndn-link.md §8.8), a pure function of two names: the
members entry `record` itself, its pieces and manifest nodes, each with or without an implicit digest, and nothing else — not another entry
of the space, not the entry's neighbours. `false` when `record` names no log entry of a space.

### 13.5 The scope's guarantees

1. Every predicate is a pure function of its arguments and of the fold held now: a name outside the space is refused whatever a link was
   admitted for, and a person the fold no longer lists carries nothing at the next packet.
2. No predicate widens what the members or the epoch keys admit (§10 rule 5): the link carries a name the layer would answer by name to
   anyone who asks; sealing and the fold decide what the answer shows.
3. The surface answers for the invitations that hold it: once they are gone it carries nothing (`open()` is false, the predicates are false).

## 14. Policy

`IntroPolicy` is what a device allows of an introduction. **Policy is in data, mechanism in code**: every
number below is a field, and a deployment changes it without changing the crate.

| Field | Default | Meaning |
|---|---|---|
| `min_components` | 1 | the fewest name components a namespace an introduction brings has; the root, over every name, is never brought, whatever this says |
| `reserved` | `/localhost`, `/localhop` | names no introduction brings, nor a name under or over one: scopes that are never a person's |
| `shared` | `/user`, `/com`, `/org`, `/net`, `/edu`, `/gov`, `/mil`, `/int`, `/info`, `/biz`, `/arpa`, `/ndn`, `/example`, `/test`, `/local`, `/invalid` | broad names shared by many people's namespaces and held by no one: typed prefixes (`/user`, whose `/user/<hash>` names are people's) and top-level names. No introduction brings one of them **or a name over it**; a name under one (`/user/<hash>`, `/com/acme`) is a person's like any other. A deployment frees a name by removing it from the list |
| `wrong_tries_max` | 16 | wrong tries of one offer, all askers' together, that close it for everyone, durably: the backstop under per-asker counting (`Offer::tries`), which anyone can make new askers for |
| `backoff` | 1 s | the pause after a wrong try counted toward `wrong_tries_max`, doubled by each one counted (by the offering device's clock); a wrong try within the pause counts against its asker alone, so closing an offer for everyone takes strangers about `backoff` · 2^`wrong_tries_max` |
| `asks_queued` | 32 | asks a device holds at once, verifying their asker or waiting for their turn; one more gets no answer (a Nack) at once, and its asker retries |
| `local_candidates` | `false` | whether a code's link hint, or a short code's first contact, may name this machine's own addresses (loopback, link-local), which a join then dials (§6.1, §6.3) |
| `grant_for` | `None` | an optional hard bound on how long a grant lasts after the admission it follows, by the offering device's clock; `None`: it follows the members; `Some(Duration::ZERO)`: no grant is made (§10 rules 1, 2) |
| `departure_for` | 7 days (`DEPARTURE_FOR`) | how long a departure mark lasts; `Duration::ZERO`: no mark is made (§11 rule 14) |
| `short_code` | `true` | make a short code and publish its hint record (§6.6) |
| `short_width` | 294 | the most characters of a short code's line (§6.6) |
| `hint_while_open` | `true` | serve the record only while the offer is open, a gone mark after (§7.1 item 5) |
| `code_candidates` | 3 | the most link-hint candidates a full link carries (the record serves all 8) |
| `code_relays` | 2 | the most relays a full link names |

`InviteConfig` holds the crate's own bounds that are not a person's policy: `asks_verifying` (8, §9.1, at least 1) and `entropy`
(where an offer's secret and id and an ask's nonce come from; the operating system's randomness by default). The timings a join
waits by (`first_look`, `lifetime`, §8.5) are the node's `Config` (heap.md §10.2).

**What `refuses(ns)` says.** `IntroPolicy::refuses(ns)` answers why no introduction brings the namespace `ns`, if
it does not, in a text that completes "the namespace `<ns>` …": the root; fewer than `min_components`
components; equal to, under or over a name of `reserved`; equal to or over a name of `shared`. Every
refusal names the field that says so and what to do ("remove it from `IntroPolicy::shared` if your people's
namespaces sit under it"). It is the one test the inviter applies to the asker's namespace (§9.2 step 10), the
joiner to the inviter's (§8.2 step 4) and the surface to the writer namespaces it lists for a joined space
(§11 rule 18).

**Reserved names.** `/localhost` and `/localhop` are scopes, never a person's: a namespace equal to,
under or over one is refused whichever way the introduction goes.

**Broad-name shared defaults.** A broad name would be the joiner's root over every name under it the inviter does not trust
yet, so by default a stranger cannot claim `/com`, `/org` or any other name of the default list; a name under
one (`/com/acme`) is a person's and is refused `Conflict` only while this device trusts an overlapping
namespace under another anchor. A deployment whose people's namespaces sit under a prefix not on the list adds
it to `shared`.

## 15. Store keys

Everything the exchange keeps lives in `Node::store()` under `/localhost/ndn-invite/`, never served, announced or
accepted as the name of a packet received (§2). Each value is durable (`Node::flush`) before the reply that depends
on it. `<id>` is an offer's 16-octet id as one generic component; `<space>` the space's Name TLV as one generic
component; `<key>` the public-key digest, 32 octets, as one generic component.

| Key | Value | Written | By |
|---|---|---|---|
| `offer/<id>` | the signed offer packet | at `offer` | inviter |
| `key/<id>` | the proof key, wrapped to the device's recipient key, then a MAC | at `offer` | inviter |
| `hint/<id>` | the hint token, wrapped the same way, then a MAC; only with a short code | at `offer` | inviter |
| `tries/<id>` | the overall wrong tries (4 octets) and when the last was counted (8 octets), big-endian | each wrong try (§9.6) | inviter |
| `tries/<id>/<digest>` | one asker key's wrong tries (4 octets, big-endian) | each wrong try | inviter |
| `using/<id>` | the key a use under way is for: its Name TLV, then the digest (32 octets) | start of the use (§9.3 step 1); dropped on failure and in the batch of step 5 | inviter |
| `accepted/<id>` | the acceptance answered to the key that used the offer (one `INTRO_ANSWER`) | with `used/<id>` (§9.3 step 5) | inviter |
| `used/<id>` | the use mark: one `INTRO_USED` naming the offer, the key and its public key's digest (§16.1) | with the acceptance; at most once | inviter |
| `closed/<id>` | the closing mark: one octet, `1` | `close_offer`, the overall cap, a start after an unclean stop, each `RolledBack` (a removal closes by derivation, nothing is written, §5.4) | inviter |
| `grant/<id>` | the grant note, MAC'd (§10 rule 3, 11) | with the acceptance | inviter |
| `mirror/<space>/<key>` | the mirror note, MAC'd (§11 rule 17) | when the admission is held | joiner |

The values of `grant/…` and `mirror/…` are fixed-width local forms and are not TLV (§10 rule 3); the value of `used/…` is one
`INTRO_USED` TLV (§16.1) and of `accepted/…` one `INTRO_ANSWER`; `used/…`, `using/…` and `tries/…` are followed by their MAC (§18.1). The
proof key and the token are wrapped to the device's recipient key (heap.md §6.2), each bound to its own key's Name TLV as associated
data, and **followed by a MAC** under a key derived from the recipient secret: the wrap alone proves nothing, the key it is made to
being public. So a party that can write the store cannot make a note read nor move one to another key; it can delete one (§18.1).
No key of this table is a Name that any function answering an Interest knows: a note is never answered, whatever the
Interest asks, `CanBePrefix` included.

**The store's other tenants.** The crate writes only these keys, and reads nothing under `/localhost/ndn-heap/`.
The node's own durability rules (heap.md §4) govern the flush; the crate's keys carry no sequence numbers and need
no reservation: a lost write is a lost answer, which is the joiner's retry (§1.3 invariant 8).

## 16. Wire formats

### 16.1 TLV-TYPE numbers

The crate kept **every number of §19 of the former data layer** (history/data-layer-remainder.md; README registry, [README.md](README.md#tlv-type-numbers)):
the even and odd rules of that spec stand. Odd numbers are critical: a decoder refuses a record holding one it
does not know. Even numbers are skippable and reserved for additive fields. The odd numbers of the block are
odd for the same reasons as there: a reader passing over `INTRO_OFFER` would take an offer for nothing; one
passing over `ROLE` would admit a reader as a writer; `TRIES` would close an offer at the wrong count;
`INTRO_REFUSED` would be read as an admission without its fields; `INTRO_ASK`, `INTRO_ANSWER` and `CREDENTIALS` are
read only by a device that implements this specification.

| TLV-TYPE | Name | Value |
|---|---|---|
| 0x0561 | `INTRO_OFFER` | `Name` (the space), `ROLE`, `KEEP_UNTIL` (its expiry), `TRIES`, `DIGEST` (the commitment), `SEAL_KEY` (the offering device's): the Content of an offer packet (§5.1) |
| 0x0563 | `INTRO_USED` | `Name` (the offer), then `WRITER` and `DIGEST` (the asker key it was used by and its public key's digest) when used, neither when closed: the value of `used/<id>` (§5.2); the closed form is read but not written (`closed/<id>` is one octet). It is no longer a log record |
| 0x0565 | `INTRO_ASK` | `EPHEMERAL_KEY`, `CIPHERTEXT` (a content key wrapped to the offer's `SEAL_KEY`), `CIPHERTEXT` (the `AskBody`: `Name` (offer), `NONCE`, `PROOF`, `CREDENTIALS`, `ASKER`, sealed under it): an ask Interest's ApplicationParameters (§8.2 step 2) |
| 0x0567 | `INTRO_ANSWER` | `Name` (offer), `WRITER` (the asker key), `DIGEST` (its public key's digest), then `Name` (space), `ROLE`, `ADMITTED`, `CREDENTIALS`, `ASKER` (the offering device's proof), `PROOF` — or `INTRO_REFUSED`, with no `PROOF`: an answer's Content (§8.2 step 3, §9) |
| 0x0569 | `ROLE` | NonNegativeInteger: 0 reader, 1 writer. (heap.md's `ROLE` 0x062B reads 0 writer, 1 reader: they are different TLVs, and this one is an offer's, never a members operation's) |
| 0x056B | `TRIES` | NonNegativeInteger: in an offer, the wrong tries that close it (≥ 1); in a refusal, those left |
| 0x056D | `INTRO_REFUSED` | NonNegativeInteger: 1 unknown, 2 used, 3 expired, 4 closed, 5 wrong proof (then `TRIES`, left), 6 conflict (the code a joiner's own `Hint` refusal would have: it is never sent) |
| 0x056F | `CREDENTIALS` | octets: whole Data packets, a signed trust context then the certificates of its signer key's chain to that context's anchor, at most 8 |
| 0x052A | `ADMITTED` | one nested TLV naming the members entry that admitted the asker: `Name` (the owner device that signed it), `SEQ` (0x0526), `DIGEST` (0x055E; the entry's signed-region digest, heap.md §1.5), each exactly once; an answer's field, optional in the grammar (`None` in an answer that names none), written after `ROLE` and before `CREDENTIALS`, so inside the bytes the answer proof covers. The number is the old `Revision`'s, a NonNegativeInteger there; the proof labels of §4.5 already keep an answer of one crate from verifying in the other (§20) |
| 0x0526 | `SEQ` | NonNegativeInteger: a sequence number; only inside `ADMITTED` (the data layer's `Seq` number, reused) |
| 0x052E | `KEEP_UNTIL` | NonNegativeInteger, ms since the Unix epoch; an offer's expiry |
| 0x0531 | `NONCE` | 16 octets, fresh random per ask |
| 0x053B | `ASKER` | octets: the asker's proof, the Data packet `<A>/32=ask/<binding>` (§2.1) |
| 0x053F | `PROOF` | 32 octets: HMAC-SHA256 under the proof key an offer's secret yields, over the fields of an introduction's ask or answer before it (§4.1) |
| 0x055E | `DIGEST` | 32 octets: the commitment in an offer, a public key's digest in `INTRO_USED` and `INTRO_ANSWER`, an entry's signed-region digest in `ADMITTED` |
| 0x0568 | `WRITER` | `Name` (the asker's key) |
| 0x0574 | `CIPHERTEXT` | octets: nonce (12) ‖ tag (16) ‖ ciphertext, ChaCha20-Poly1305 |
| 0x0576 | `SEAL_KEY` | 32 octets: X25519 public key |
| 0x057C | `EPHEMERAL_KEY` | 32 octets: the sealer's X25519 public key for this ask |

The names are this crate's spelling of the numbers of the former data layer's §16.2 (`IntroOffer`, `IntroUsed`, `IntroAsk`,
`IntroAnswer`, `Role`, `Tries`, `IntroRefused`, `Credentials`, `Revision`, `KeepUntil`, `Nonce`, `Asker`, `Proof`,
`Digest`, `Writer`, `Ciphertext`, `SealKey`, `EphemeralKey`); the numbers do not change.


### 16.2 The link hint and the hint record (even numbers)

The code's link hint (§6.1) uses two even numbers of the block 0x05B0–0x05BF. They are the value of the `intro`
envelope's `LinkHint` field (0x0478, [trust-envelope.md](trust-envelope.md)), not of a stored record; a reader skips an
unknown even TLV among them. A short code's hint record (§7.1) uses five more of the block, all even: the Content of the
Data `<D>/32=hint/<token>` (§2.1), with the same reader rule.

| TLV-TYPE | Name | Value |
|---|---|---|
| 0x05B0 | `LINK_KEY` | 32 octets: SHA-256 of the inviter device's public key as a certificate carries it (an Ed25519 key's 32 octets); the key a link handshake must prove (ndn-link.md §3.3); exactly once |
| 0x05B2 | `LINK_CANDIDATE` | one octet of kind (0 host, 1 reflexive, 2 advertised, 3 mapped), the IP address (4 octets for IPv4, 16 for IPv6), the UDP port (2 octets, big-endian); 7 or 19 octets; repeatable, at most 8 kept, in order of preference (§6.1) |
| 0x05B4 | `INTRO_HINT` | a hint record's Content (§7.1), one TLV and nothing after it: `HINT_OFFER`, `LINK_KEY`, `LINK_CANDIDATE`*, `HINT_RELAY`*, `HINT_UNTIL`, `CREDENTIALS` in this order — or, for an offer no longer served, `HINT_GONE` then `CREDENTIALS` and nothing else |
| 0x05B6 | `HINT_OFFER` | one Name TLV: the offer's name; exactly once |
| 0x05B8 | `HINT_RELAY` | one Name TLV: a relay device that reaches the inviter; repeatable, at most 8 (a record with more is refused) |
| 0x05BA | `HINT_GONE` | NonNegativeInteger: 3 expired or 4 closed (the codes of `INTRO_REFUSED`); with `CREDENTIALS` the whole of a gone mark, which is verified as a record is (§8.3 S5) |
| 0x05BC | `HINT_UNTIL` | NonNegativeInteger: the offer's expiry in milliseconds; informational (the offer judges its own); exactly once |

### 16.3 The numbers the block does not use

The README's rows 0x0520–0x057F (only the numbers §16.1 lists; the rest of that block is retired and MUST NOT be reused) and 0x05B0–0x05BF point to this specification. The
shared numbers of §16.1 (0x052A, 0x0526 inside it, 0x052E, 0x0531, 0x053B,
0x053F, 0x055E, 0x0568, 0x0574, 0x0576, 0x057C) were the former data layer's, reused here as they were; none is renumbered. A decoder
of this crate and a decoder of the removed `ndn-data` read the same bytes for them; they differ in the labels of the proofs (§4.5), in
the offer's name and in `ADMITTED`'s shape (§20).

### 16.4 Wire rules

1. A reader MUST refuse an odd TLV it does not know, a field that repeats where it is exactly once, a field missing where it is
   required, and content after a value that is one TLV.
2. An `INTRO_ANSWER` is an acceptance (with `PROOF`) or a refusal (`INTRO_REFUSED`, no `PROOF`); an acceptance without a
   proof, or a refusal with one, is malformed.
3. An offer allows at least one wrong try (`TRIES` ≥ 1) and offers a space name (heap.md §2.3): an offer of what is no space is
   malformed.
4. A use mark names an **offer**, never a log entry or any other name, and names its key with its digest or neither.
5. `ADMITTED` is one nested TLV naming one entry whole: a half-written one, a twice-written field or a digest of another size is
   refused.
6. Credentials are Data packets, whole, and at least one.

## 17. Refusals and their next steps

Every refusal says why, and what to do, in its own words (`InviteError`'s `Display`), and `next()` says the same
in a class (`NextStep`, heap.md §10.5); `retry()` says the same call can succeed later (`next() == RetryLater`).
`InviteError::refusal()` gives the `IntroRefusal` of an introduction, which `ndf` maps to its `Code::BadCode`.

### 17.1 The refusals of an introduction

`InviteError::Refused(IntroRefusal)`:

| `IntroRefusal` | When | Next | Retry |
|---|---|---|---|
| `Unknown` | what the joiner fetched under the offer's name is no offer's record (never on the wire: an ask for an offer the offering device holds none of gets no answer, §9.2 step 4) | `AskOwner` (a new code) | no |
| `Used` | another key joined with this offer | `AskOwner` | no |
| `Expired` | past its expiry by the offering device's clock | `AskOwner` | no |
| `Closed` | closed to everyone but the key that used it: this key's wrong tries spent, all askers' at the device's cap, `close_offer`, or the member it brought removed by a members entry (the key the offer was used by is still answered, until the offer expires, §9.2 step 5) | `AskOwner` | no |
| `WrongProof { left }` | the proof of the secret is wrong; counted against this key, `left` more allowed it | `FixRequest` (check the code) | no |
| `Conflict` | the asker's namespace overlaps the inviter's or one the inviter trusts, is one it trusts under another anchor, or one the policy refuses (§9.2 step 10); or, for a self-certifying asker namespace adopted from its genesis, the presented credentials carry an anchor the held context does not; or the asker's proof does not verify under the context the inviter's device holds (a key it revokes, shown with an older version) (§9.3) | `FixLocal` (renew the device's certificate when it is the last) | no |
| `InviterConflict { inviter, why }` | the joiner refuses the inviter's namespace (§8.2 step 4; never on the wire): `why` says what it overlaps; or, for a self-certifying inviter namespace adopted from its genesis, the answer's credentials carry an anchor the held context does not; or the inviter's proof or offer does not verify under the context the joiner holds (§8.2 step 5) | `AskOwner` (do not use the code) | no |
| `Forged` | an acceptance fails a check of §8.2 step 3, or an offer fails S7 (never on the wire) | `RetryLater` | yes |
| `Hint { why }` | what answered at a short code's first contact came damaged or does not prove itself (§8.3 S5, checks 1–4; never on the wire; its code, were it sent, is 6): `why` begins with the check that failed — `wrong name`, `wrong record`, `credentials`, `signer` (the signature is not good by a key the credentials chain to their anchor). Damage in flight fails these checks as an impostor's packet does, and the packet is intact the next time, as a corrupted answer is (`Forged`) | `RetryLater`: retry at most 3 times (`HINT_RETRIES_MAX`), then do not use this code's first contact: ask for a new code | yes, bounded |
| `HintMismatch { why }` | a record that **verifies** (its signature is good by a key that credentials which open vouch for) but is not the inviter this code names (§8.3 S5, checks 5–7 and 9; S7; never on the wire; code 6): `why` begins with `namespace`, `anchor` (also: the code was made before the keyed fingerprint), `signer` (not a key of the code's device, or not one the schema lets sign this name) or `offer` (no offer of the device, or not made with the code's secret). No damage in flight does this | `AskOwner` (do not use this code's first contact: ask for a new code) | no |
| `GoneUnproven { why }` | a gone mark that fails any check of §8.3 S5 (3–7): anyone on the path can make one (never on the wire; code 6) | `RetryLater`: retry at most 3 times, or ask the inviter | yes, bounded |

The inviter unreachable is `NotReady { name: <offer> }` (`RetryLater`): the offer waits. A code that does not
parse is `BadRequest`; a host without a link layer when one is needed, or one that refuses an adoption, is `Local`.
Other errors wrap the heap's (`InviteError::Heap`, with the step of what they wrap): `NotOwner` (`UseOwnerDevice`)
from an offer of a space this device does not own, `Refused` from a revoked or suspected own key.

An offer is **never** refused to a prober that holds no code: it is silence (§2.3). A refusal travels only in the
answer to an ask that opened and whose asker **proved a key** (§9.2 step 3, before any refusal is decided): an ask whose
asker proved none, and an ask that names no offer the device holds, are met with silence, so a prober that cannot prove a key
learns of a held offer neither that it is open, nor used, nor closed.

### 17.2 A short code adds

Each says why and what to do; `D` is the inviter's device name, which stands for the offer's name until the record
names it.

| Situation | Error | Says (the text a program shows) |
|---|---|---|
| a word count other than 20 or 36 | `BadRequest` (the root) | `the code has N words; a short code has 20 or 36 words, today's words form 24: the code was cut off or has extra words: copy it again whole` |
| a word off the list | `BadRequest` | `word N is not a BIP39 English word: check word N` (N from 1, among the words) |
| the checksum does not match | `BadRequest` | `the code does not read (a word, the address or the device name is mistyped, or two words are swapped): check each against what you were given; the inviter's device name and address are part of the check` |
| a first contact that is neither an address nor a relay's name, or no device can dial it | `BadRequest` | ``the code's first contact `x` is neither a dialable address (`192.0.2.7:4433`, `[2001:db8::7]:4433`) nor a relay's name (starting with /): check it against what you were given`` |
| `161=*` with 20 words | `BadRequest` | ``the device name uses `161=*`, the whole fingerprint, which only a 36-word code carries: the code was cut off, or copied from a code of another shape; copy it again whole`` |
| a loopback or link-local first contact, `local_candidates` off | `BadRequest` | ``the code's first contact A is an address of this machine or its link; this device does not dial one from a code (`IntroPolicy::local_candidates`): ask for a code with an address of the inviter's device that can be reached from here, or allow it in the policy for two devices of one machine`` |
| a device name that is no name | `BadRequest` | ``the code's device name `x` is not an NDN name (starting with /, not the root): check it against what you were given, or copy the code again whole`` |
| the address does not answer the dial | `NotReady` (`RetryLater`) | `the first contact A did not answer (reason): check the address and that the inviter's device is on, then retry; or ask for a new code` |
| the hint record is not fetched in its tries | `NotReady` (`RetryLater`) | `the inviter's hint for this offer was not fetched from the first contact (offline, wrong address or relay, a relay this device cannot reach, or the offer is closed): retry, check the code, or ask for a new code` |
| a gone mark that verifies | `Refused(Closed)` or `Refused(Expired)` | the texts of the rows of §17.1 |
| the record does not verify: damage or no proof | `Refused(Hint { why })` (`RetryLater`) | `what answered at the first contact does not prove it is the inviter's, or came damaged (why): retry at most 3 times; if it is refused every time, do not use this code's first contact: ask the inviter for a new code, and check the code was copied whole` |
| the record verifies but is not the code's inviter's | `Refused(HintMismatch { why })` (`AskOwner`) | `what answered at the first contact proves itself, but not as the inviter this code names (why): this is not damage in flight and a retry will not change it: do not use this code's first contact, ask the inviter for a new code, and check the code was copied whole`; for `anchor`, `why` ends: `or the code was made before the keyed fingerprint: ask the inviter for a new one` |
| a gone mark that does not verify | `Refused(GoneUnproven { why })` (`RetryLater`) | `the first contact says the offer is closed but can't prove it (why): retry, or ask the inviter; retry at most 3 times, then ask the inviter for a new code` |

### 17.3 The joiner's wait

`NotReady { name: <space>, why }` (`RetryLater`) from `join` when the bound of §8.5 passes: `why` names which of the
four conditions is missing, and what to do ("join again with the same code, or put again; both are safe").

### 17.4 The offer's own refusals

`offer` refuses with `NotOwner` (an `S` of another namespace, or a device that is not an owner device of it),
`BadRequest` (`tries` = 0; an expiry already past; a space not open here or without its creation held), `Local` (a
host that cannot give a link when it must, a store that cannot make the offer durable), each saying what to do.

## 18. Threat notes

Each note of §19.7 of the former data layer (history/data-layer-remainder.md) is carried over, adapted where the design changed; the notes the redesign adds come
first, and the ones that changed say so.

### 18.1 What the redesign changes

- **An offer cannot be guessed.** An offer's name is `<D>/32=intro/32=offer/<id>`, the id 16 octets from the device's
  entropy: 128 bits. Before, an offer was an entry of the offering device's log, named by a sequence number
  that anyone could count to and listed in the device's summaries, so anyone could ask with it. Now a name the device
  does not hold, and a name it holds but will not serve, is **met with silence** (a Nack, the same for every miss, §2.3):
  a prober learns neither that an offer exists nor what its refusal would be.
- **The surface is two prefixes.** A link dialled for an introduction routes `<D>/32=intro` and `<D>/32=hint` and no
  other name of `D` (§2.3). The previous design's `<D>/32=held` prefix is gone; an offer is fetched by its own name, and
  no log entry, summary or held copy of the device crosses an introduction link (§13.1).
- **An offer is not in the log.** The log of a space holds the membership the offer made and nothing of the offer, its use or
  its closing, so what a member or a relay holds of the space says nothing of who was invited, when, with what expiry or
  how many tries. The use mark is a note of the offering device (`used/<id>`), local and authenticated by a MAC (below): **only that device
  sees the offer used**, and another device of the inviter gives no answer to an ask of it (the old design's note "every device of
  the inviter sees the offer used" no longer holds, and need not: an offer is answered only by the device that made it).
- **The notes an offer is judged by are authenticated, and fail closed.** The recipient key a note is wrapped to is
  public, so the wrap proves nothing of who wrote it: `key/<id>`, `hint/<id>`, `using/<id>`, `used/<id>`, `tries/<id>` and
  `tries/<id>/<digest>` each end in an HMAC-SHA256 under a key derived (HKDF, labels `ndn-invite/offer-note/…`) from the
  recipient secret the key store keeps, over the note's own key name and value. A party that can write the data store and
  not the key store cannot make a proof key (which would admit whoever knew the secret it names), a use mark, a use under way or
  a count that reads, nor move a note to another key. A note that is there and does not read fails **closed**: a proof key that
  does not read makes the offer not held (an ask of it gets no answer); a use mark or a use under way that does not read is a use by a key nobody knows
  (`Used` to every asker, its user included); a count that does not read is the cap (`Closed`, for that asker or for all). The
  offer is a signed Data and the device checks its own signature when it reads its offers at a start: a note the device's key
  did not sign is not an offer of the device's, so one written into the store is neither served nor judged. `closed/<id>` takes any
  value (a forgery only closes) and `accepted/<id>` is not read when it does not decode (the acceptance is made again, never
  admitting). **Residual, narrowed:** a MAC cannot protect a note against its **deletion** or against its replacement by an
  older note that read, so a backup restored under the device could roll `used/<id>`, `using/<id>` or `tries/…` back and let a
  code be used a second time. What the device does about it: it **closes every offer it holds** (`closed/<id>`, as `close_offer`
  does) (a) at a start after a stop the node did not make, which is what a copy of a running device shows
  (`Heap::started_unclean` of a space an offer names), and (b) each time a space an offer names raises `Alert::RolledBack`
  (`Heap::rollbacks`, kept per space, which counts every alert: an entry signed under this device's name lies above what it reserved, so
  its store is older than what its peers hold: heap.md §4.8), before the next ask or hint of any offer is judged. The cost is that every crash, and every start after
  one, closes the offers: a joiner whose use was under way meets `Closed` and asks for a new code, and the owner makes one (an
  admission already made stays: a used offer's user is still answered, §9.2 step 5). **What a restore can still do:** (1) restore
  an image that was stopped cleanly and that no peer can contradict — nothing signed since the backup is held by a peer, or no peer
  has yet been reached — so the space shows no rollback: the offers of that image are open, as they were when it was taken, and a code
  can be used once more; (2) ask in the window between the start and the first vector of a peer, which is what raises the alert.
  Neither gives more than one use of a code the owner made, to a holder of its secret, within its expiry; the members entry that
  admits the second key is signed by this device and is seen by every member. Rolling back `tries/…` alone is harmless: the secret
  is always 16 octets (128 bits), so wrong tries given back buy no useful number of guesses. The store of a device is the device's, and
  its protection (permissions, encryption at rest, backups that are not restored under a running device) is the host's.
- **The inviter's effect is one entry.** Nothing but one `Heap::change` reaches the space (§9.4). The entry is signed by the
  heap's rules, judged by every reader as any members entry (heap.md §3.8 step 6), and the joiner waits for exactly it
  (§8.5): an entry that raced it, or a fold that listed the person by another carrier, is not taken for it.
- **The signing the host surface lends is bounded.** The node signs for the extension only a name `<this device>/32=<keyword>/…`
  of a keyword the extension registered (`intro`, `hint`, `ask`): the key signs offers, hint records, answers and the proof packets
  `<X>/32=ask/<binding>` and cannot be made to sign an entry's name, a certificate's, another device's or any octets the caller names
  (heap.md §10.2; the node offers no raw signing).
- **A refusal travels only to an asker that proved a key.** The asker's proof packet is checked (§9.2 step 3) before the offer is
  looked up, closed, used or expired: an ask whose asker proved no key, and an ask that names an offer this device does not hold, are
  met with silence. A party that holds no proving key learns of a held offer neither that it is open, nor used, nor closed; a random
  id, and the id of an offer the device never made, learn nothing even from an asker that proved a key. The signature check that this
  needs is one the ask pays in any case, bounded as a crowd of asks is (§9.1).
- **Only an owner device shows a code.** `offer` refuses a device that is no owner device of the space (a `guest` or `node` device
  of the owner's namespace, in a namespace that declares the role layout) and a space whose creation it has not seen, before the offer
  is made, stored or served (§5.3), so a code is never shown that admits nobody and leaves its joiner with silence; a device that was
  one when it made an offer and no longer is gives no answer at the admission (§9.4). Nothing is widened by this: the admission was
  always `Heap::change`'s, and refused to such a device.
- **A grant of a space this device cannot read is revoked.** The grant's fold is the space's members; while the space is not open
  here, or its creation is not held, the host is told `revoke_grant` once and the note stays, so a link the grant opened is not left
  standing on a fold that was not seen (rule 6 of §10); opening the space installs it again if the person is still listed. Residual:
  the joiner's own mirror notes keep the earlier rule (nothing is done while the space is not open here): they admit only the
  inviter's own link, which this device did not ask to be cut.
- **Grant-link routes persist until the link ends.** A grant installs the link's routes when the link is admitted, and the routes
  stay until the link ends; ending or revoking the grant does not remove them. What crosses the link is not decided by the routes: the
  link's name filter and its `answers_in` filter are judged at every packet against the grants in force then (ndn-link.md §8.7 rules
  5 and 10), so a person whose grant ended sends an Interest along a route that is still there and gets a Nack, and receives nothing:
  the cost of the persistence is a Nack at the link, never data.

### 18.2 Carried over

- **Code theft.** The code is a bearer secret until used: whoever presents it first, within its expiry, joins with its role.
  One use binds it to one key (§9.2 step 6); the owner sees who joined in the space's members and removes them as any member
  (heap.md §5.6). The removal lasts: a used offer's user asking again — a fresh ask, before or after a restart — is answered the
  acceptance kept for its use and never admitted again (§9.5), and no other key can use it, whichever owner device removed the
  member. A removal the offering device holds of the person an offer was used by (or was being used by), by whichever owner device
  signed it, closes that offer by derivation (§5.4): the offer then admits no one new, and its user alone is still answered, until
  the offer expires, the acceptance kept for its use and nothing else: nothing is adopted or signed, so asking does not make a
  removed member a member again, and what the answer shows is what the code's holder already had — the space's name, the role and
  the inviter's public credentials. Only the offering device judges its offers, and it writes no mark for this; a removal it has not
  yet taken closes nothing yet.
  `close_offer` closes an offer to everyone new at any time, and keeps answering its user so: a host that closes an offer as soon as
  the new member appears loses no joiner whose answer was lost. Keep expiries short.
- **A rollback after the first.** Every `Alert::RolledBack` closes the offers held when the next ask or hint is judged, not only the
  first of the process: the count is kept per space (`Heap::rollbacks`, which counts every alert, also those the 32 standing alerts no
  longer hold). An offer made after an alert is open until the next one (a copy of this device's key that signs above its
  reservation raises it again), which closes it as well.
- **Replay.** An ask replayed by anyone gets the answer kept for it: bound to the asker's key and digest, it admits only the asker's
  person, which the fold already lists; it shows the replayer the space's name, the role and the inviter's public credentials (the
  answer is not sealed). A replay after the inviter's device dropped the kept answer is judged again: a used offer answers its
  user's kept acceptance (admitting nothing) and anyone else `Used`, counting nothing; an unused one counts a wrong try again against
  the replayed key (when it was one). **One key is admitted, never two** (§9.5, case i5).
- **Forged asks.** An ask without the secret fails step 9 and is counted; it cannot be turned into another key's membership: the
  proof binds the offer, the key, its digest and the nonce. One without valid credentials costs one signature check and gets no
  answer (case i6).
- **Offline guessing.** The offer and its commitment are public; the secret has 128 bits, so neither the commitment nor an observed
  proof can be searched for it.
- **Tries brute force.** Wrong tries are counted durably, across restarts, per asker key: past the offer's `TRIES` it is closed to that
  key for good, even to the right secret. A stranger spends only its own tries — it cannot close an offer meant for someone else — and
  a used offer counts no tries at all. Anyone can make new keys, so all askers' wrong tries are bounded too
  (`IntroPolicy::wrong_tries_max`), counted with a backoff that doubles after each (`IntroPolicy::backoff`): at the cap the offer
  closes for everyone, a denial, never an admission, and reaching it takes strangers about `backoff` · 2^`wrong_tries_max` (some 18
  hours by default), past any short expiry. Online guessing gains nothing: each guess is one in 2^128. And the guess needs the
  offer's name first, which a prober does not have (§18.1).
- **A crowd of asks.** Each ask costs an unwrap, an AEAD open and a signature check before it is judged; at most
  `InviteConfig::asks_verifying` are opened at once, and past `IntroPolicy::asks_queued` held an ask gets no answer at once, so a
  crowd costs bounded work and memory and delays honest asks only until it ebbs.
- **Inviter impersonation.** An acceptance must prove the secret and be signed by the offering device under the anchor whose
  fingerprint the code carries (128 bits of it in the words form, 80 in the short code of a named namespace, the whole 32 octets in
  a link and in the short code of a self-certifying one: see the note on the short code's fingerprint below); a party that served a
  substituted offer and opened the ask learns the joiner's public credentials, cannot answer as the inviter, and can at most relay
  the ask to the real inviter — whose answer admits exactly the joiner. A refusal is not authenticated: a forged one denies, never
  admits, and an on-path party can deny anyway.
- **Link and words codes: the offer's seal key is not authenticated when the ask is sealed.** A short code's record vouches for the
  offer before the ask is sealed (S7); a link or a words code has no record, so nothing vouches for the offer packet until the
  answer's credentials are judged (§8.2 step 3). With the commitment public, an active party on the transit path that serves a
  substituted offer — its own seal key, the genuine commitment — is sealed the ask and reads it: the joiner's public credentials
  (its namespace's trust context and certificates), its device name and its proof of the secret. **It gains no admission:** it
  cannot sign the answer as the inviter's device under the anchor the code's fingerprint names, so the joiner refuses its answer
  (`Forged`, `InviterConflict`) and adopts nothing; relaying the ask to the real inviter admits exactly the joiner, whose key, digest
  and nonce the proof binds; and a passive observer sees only sealed bytes. What is lost to such a party is the privacy of the joiner's
  public credentials and device name. A host that wants the offer authenticated before the ask is sealed uses a short code.
- **Joiner impersonation.** The asker's key must chain to the anchor it presents, and a namespace already trusted under another
  anchor, one under or over any namespace the inviter trusts or its own, the root, or one the policy refuses is refused
  (`Conflict`): a joiner cannot speak for a namespace the inviter knows, take over a name under one (a device name of a person the
  inviter trusts, whose validation would then pick the joiner's longer context), become the trust root over the shared `/user` or a
  scope, nor shadow names of the inviter's own. A joiner can claim any namespace that overlaps none the inviter trusts — that is
  what a stranger is; the owner sees which one joined. A broad name would be the joiner's root over every name under it the inviter
  does not trust yet, so by default a stranger cannot claim `/com`, `/org` or any other name of the default `shared` list (§9.2
  step 10); a name under one (`/com/acme`) is a person's and is refused `Conflict` only while this device trusts an overlapping
  namespace under another anchor.
- **Inviter impersonation of a namespace the joiner trusts.** A code is made by anyone. The joiner judges the inviter's namespace as
  the inviter judges the joiner's (§8.2 step 4) before it adopts anything, so a stranger's code cannot replace the anchor of a
  namespace the joiner trusts, nor claim one under or over it (`InviterConflict`).
- **Reuse across the inviter's devices.** An offer is answered only by the device that made it, which alone holds its proof key and
  its use mark; another device of the inviter gives no answer to an ask of it (see §18.1 for what changed).
- **Clock.** Expiry, and the overall cap's backoff, are judged by the offering device's clock alone: a slow one keeps an offer open
  longer and counts toward the cap more slowly, a fast one closes it early and counts sooner; no other decision reads a clock, and
  certificate validity in the credentials is checked as a live exchange.
- **Unauthenticated hints.** Relay hints in the code, the joiner's own namespace's relays and the link hint's addresses are
  reachability only: a lying hint fails to reach, and nothing a relay or a dialled address carries is trusted — the offer, the ask
  and the answer are judged by the checks above.
- **The link hint: the key is authenticated, the address is not.** The dial's handshake proves the key (§8.2 step 0): an address
  whose device presents another key is no link. So a joiner reaches the device holding the key its code names, or nobody; an address
  an attacker substituted in a code can only make the dial fail, or reach a party that lacks the key and fails the same handshake. A
  code altered to name another key reaches that key's holder, which is the inviter-impersonation case above: the party learns the
  joiner's public credentials and can answer nothing the code's anchor fingerprint and secret check (§8.2 step 3). The secret never
  leaves in the dial: the dial carries a handshake and a hello, and the secret travels only inside the sealed ask.
- **Dialling candidates.** A hint holds at most `LINK_HINT_CANDIDATES_MAX` (8) addresses, and a reader keeps no more. A hostile code
  could aim a joiner's dial at third parties: at most that many QUIC handshakes' first datagrams per join, every one unanswered unless
  something there speaks QUIC, so nothing is amplified and no more is sent than the join's own retries send. Unspecified, multicast and
  broadcast addresses and port 0 are never dialled. The dial is bounded in time (§8.2 step 0). A code can have a joiner send a
  handshake to an address of its own host or network; that is all it can make it do.
- **Privacy.** The code shows the inviter's device key, and the addresses of its listening socket (its interfaces', reflexive and
  advertised ones), to whoever sees it: the screen showing the QR, the message carrying it. A host that does not want that gives no
  hint (`Host::link_hint`). A short code shows the device's name and one first contact (an address or a relay's name) and no key; the
  hint record behind it shows the key, up to 8 addresses and the relays to whoever holds the code, while the offer is open.
- **The hint's lifetime is the offer's.** The addresses are those of the moment the offer was made; once the offer expires (or is
  closed to everyone new) the code admits nobody, whatever the addresses say. A joiner dialling a stale address fails within its bound
  and goes on by relays (§8.2 step 0); an inviter whose address changed makes a new offer.
- **A stranger's link.** The inviter answers a joiner it knows nothing of on a link that carries the offer fetch, the hint record and
  the ask and nothing else, within slots and rates (ndn-link.md §8.6): what that link lets a stranger send is what any party can already
  ask of the device by name **and holds the unguessable name for**, and the ask is judged and bounded as §9 says.
- **Short code: a relay or a man in the middle cannot substitute addresses.** The hint record is signed by `D`'s device key, chained to the
  anchor the code's fingerprint names, named by the secret's token and naming the offer. A changed byte fails the signature; an unrelated
  record fails the name or the signer check; a record of another offer of `D` is a different name and, presented under this token, names
  an offer that is not committed to the secret, refused before the ask (§8.3 S7); and nothing is dialled before all of that passed (S5). A
  relay or an on-path party may *withhold* the record (the join says it could not fetch it) or *replay* an old genuine one (below); it
  cannot make the joiner dial an address of its choosing, nor trust a key it chooses.
- **Short code: the first contact is a hint.** It reaches whoever holds the address or relay, and that party can serve what it likes;
  everything it serves is verified against the code (the fingerprint, the signer, the offer: §8.3, S5) before anything is dialled, asked or
  adopted, and the offer it relays is verified by the record's credentials before the ask is sealed to its seal key (S7). The link made to
  an address routes the two introduction prefixes of `D` and no other name, whatever namespace the party shows (ndn-link.md §13.3A), so a
  stranger at the address is never sent the Interests of a namespace the joiner holds; and what the party sends in is bounded: answers under
  those prefixes, and Interests only for the joiner's own device names (the inviter fetches the joiner's seal key there, heap.md §6.5), so it
  cannot make the joiner's forwarder ask the joiner's other links for anything under the joiner's identity (ndn-link.md §13.3 rule 3). A
  loopback or link-local first contact is refused unless `IntroPolicy::local_candidates` (§6.3), as a link hint's candidates are.
- **Short code: the first contact's link does not outlive a wrong party.** The dial expects no key, so anyone on the path to the address
  completes its handshake with a key of their own and may relay the genuine hint record, which names the inviter's key. Whenever the
  verified record's key is not the link's, the join takes the link down at once and never sends the offer fetch or the ask over it,
  whether the record offers an address (a party that blocks the record's key only makes the dial fail, and the join goes by the record's
  relays or by name) or none (S6). After a successful join no link or route to such a party remains, so it keeps no path for `<D>/32=intro`
  or `<D>/32=hint` Interests, and a link made again to it, once the joiner holds the namespace, is refused when it shows no certificate
  (ndn-link.md §13.3 rule 4).
- **Short code: the party at the first contact learns nothing of who is joining but the joiner's address.** A link hint pins the key: a dial
  to an address whose party presents another key fails the handshake before any link message. A short code's address is dialled with **no
  key to expect** (`Host::dial_first`), so whoever answers there is a stranger, and the dial's hello is **empty** (ndn-link.md §13.3A): no
  certificate chain, no memberships. The party learns the joiner's IP address and that a joiner with this code's address exists, nothing of
  its person, device or groups. The inviter needs nothing more to answer: it gives an introduction link to a device with no certificate while
  an offer is open (ndn-link.md §8.6), also when it admits enrollment links (the link then carries both errands), and the ask carries the
  joiner's credentials sealed to the inviter's seal key. The full hello is sent once the joiner holds the inviter's namespace, on the link made
  again to the party the join judged. Namespace-level refusals that wait for the record (S2) therefore disclose nothing either.
- **Short code: probing.** The hint record's name is derived from the secret, so it is unguessable (128 bits) without the code, and the secret
  itself is in no name or wire. A prober who does not hold the code can neither fetch nor test for a record: an Interest for an unknown token is
  a Nack, the same for every token (§7.1 item 6), and over an introduction link it is not carried at all; a known token answers only its record
  or its gone mark. The offer's own name is as unguessable (§18.1).
- **Short code: the record's lifetime, and what it reveals.** While the offer is open the record shows the key, up to 8 addresses and up to 8
  relays that the inviter would give to anyone holding the code; an on-path observer of the Interest learns the token and so can fetch the record
  until the offer closes (that observer already sees where the traffic goes), and a cache holds it at most its `FreshnessPeriod`, 5 s. Closed or
  expired: a gone mark, nothing more. The record is made on request from the host's current hint, so it names no address the host has since lost;
  it is not in any log and not served after the device stops. With `hint_while_open` off it is served until the device stops, which is a longer
  exposure of the addresses, not a longer admission (the offer answers by its own rules).
- **Short code: replay of an old record.** The record is bound to the offer by its name and content; its `HINT_UNTIL` and a signature give no time
  the joiner checks. An old genuine record of this offer shows stale addresses, which costs a failed dial within its bound (the dial proves the key),
  never a wrong peer; a record of another offer is never accepted for this one. A genuine gone mark never turns back into a record: an offer is not
  reopened.
- **Short code: a gone mark proves itself, or ends nothing.** A gone mark carries the inviter's credentials and is signed as a record is; the joiner
  runs the same checks on it (§8.3 S5: the credentials open, the signature is good under them, their namespace, anchor and signing device are the
  code's) and only a mark that passes ends the join as it says (`Closed`, `Expired`: `AskOwner`, for good). An on-path party that answers the token's
  Interest (the token is in the Interest) with an unsigned mark, a mark signed by another key, one carrying another namespace's or anchor's credentials
  or none, gets `GoneUnproven`: `RetryLater`, "the first contact says the offer is closed but can't prove it: retry, or ask the inviter", bounded to 3
  retries (S5). It cannot make the user throw away a code that is still valid. Nothing is dialled, asked or adopted on a mark either way, and the
  offer's own answer alone judges the offer. The mark's Data has `FreshnessPeriod` 0, so no cache keeps a forged mark to answer the retries; the
  inviter signs a mark once per 5 s per state and no more (§7.1 item 4). What an on-path party can still do is what it can always do: withhold the
  record (the join says it could not fetch it), or replay an old genuine mark of this very offer, which an offer that closed does not outgrow.
- **Short code: a typo.** The 12-bit checksum covers the words, the device name and the first contact: a mistyped word, a digit of the port or a letter
  of the device name is refused with probability 1 − 2⁻¹² and never tried (§6.3). The 1 in 4096 that passes meets the other checks: a mistyped secret is
  an unknown token (a Nack, so the tries end at once), a mistyped address or relay is a first contact like any other (the party there is verified
  against the fingerprint, which a typo cannot make match).
- **Short code: what the fingerprint is for, and what it costs to beat.** The fingerprint ties the answer at the first contact to the inviter's namespace
  before anything is dialled or asked: a party who has seen the code, or only its token, cannot steer the joiner to a namespace of its own by a collision
  worked out beforehand. A **named** namespace's code carries not the anchor's own octets but `HMAC-SHA256(secret, "ndn-invite/intro/fp/1" ‖
  anchor)[..10]` (§6.4). A plain truncation of the anchor's SHA-256 would have a **long-lived** target, the namespace's own fingerprint, the same for
  every code it ever makes: one search for a key whose SHA-256 begins with those 10 octets could be run offline, without a time limit, once, and its result
  would serve every code of the namespace for good. The keyed tag has no such target: it depends on the code's secret, which no one holds before that code
  is made, and which a party who has seen only the token or the address does not hold at all. So the search for a key *A′* whose tag under this code's
  secret is the code's can start only **after the code has leaked**; it serves **that one code** (a key found for it is useless for any other code, of the
  namespace or another, and for any later one); and it has to finish **within that offer's lifetime**, before the offer is used or closed. Its success
  probability is 2⁻⁸⁰ per key, so 2⁸⁰ ≈ 1.2 × 10²⁴ key generations in expectation (the median is about 0.7 of that). Assumption, not a measurement: 10¹²
  keys per second, a rate chosen to favour the attacker: one code then costs about 1.2 × 10¹² s, some 38 000 years, and an offer's hour allows
  3.6 × 10¹⁵ keys, a chance of about 3 × 10⁻⁹. The number of offers open at once does not make one code cheaper to hit: each candidate key must match
  *this* code's tag, computed with *this* code's secret. An attacker who holds the secrets of N leaked codes and is content with any one tests each
  candidate against N tags — N tag computations per key, 2⁸⁰ in all — so only the number of key generations falls (to 2⁸⁰/N), never the number of tag
  computations; and each such code is one he could have used himself, so what he gains is only to bring that joiner to a namespace of his own. The tag is
  not a second factor beside the secret: everyone who holds the secret can compute it, and the joiner's answer is proved by the secret alone (S7, the
  answer's proof, 2¹²⁸ more). A party who has only seen the token needs the secret too, which the joiner refuses a record without (S7). **A
  self-certifying namespace** takes all 32 octets (its name *is* the fingerprint, so `161=*` writes it once, in the words), as a link does: not a
  truncation, so there is nothing to search for. **The words form** (24 words, also `Code::words`) carries a plain 16-octet prefix of the anchor's
  fingerprint and is judged as a prefix, in constant time. Its target is a namespace's long-lived fingerprint, so its search is offline and unbounded in
  time, and multiple over namespaces; that is why it is 128 bits and not 80: 2¹²⁸ ≈ 3.4 × 10³⁸ key generations for one namespace, and 2⁹⁸ ≈ 3 × 10²⁹
  against N = 2³⁰ namespaces, some 3 × 10¹⁷ s, about 10¹⁰ years, at the assumed rate. A code made before the keyed fingerprint carries the plain 10 octets
  of a named namespace and is refused as an anchor mismatch that says to ask for a new code (§17.1). The lengths that fill whole words with the 12-bit
  checksum are 10, 21 and 32 octets of fingerprint (16 + n ≡ 4 mod 11): 10 is the shortest, and each octet costs about 0.73 of a word.
- **A grant is authority to link, not to read** (§10). It is host visible and informs the link layer only: the space's members and the epoch keys still
  decide what a link is answered, so a grant never widens what the person reads or writes. A leaked code gives its thief the one use, and so the
  membership, whoever uses it first; the grant adds the link of that key, and ends with the membership (a removal), by the host's end, or by its date if
  one is set (by default none). A grant names one key: a person's other keys, including a stolen second device, have none, and the same key presenting
  another namespace is not granted it (the grant lists the asker's namespace alone). A grant that outlives a removal is closed three ways: the check on
  every `Change::Members` and at start, whoever signed the entry (the removal need not come from the offering device); its date; `Host::revoke_grant`,
  called before the end is durable. A removal whose entry this device has not yet taken leaves the person linked until it is taken (and, with a
  `grant_for` set, at most until the date). The grant's role is re-derived from the fold, so a demotion narrows it at once. The grant note is MAC'd
  under a key from the device's recipient secret: a writer of the data store alone cannot clear its `ended` flag or extend it; rollback to an older
  genuine copy is bounded by the fold and the use mark (§10 rule 11). A grant is never made for an ask refused, for a retry or when the policy makes
  none, and no grant is made from an address or a name: only the asker's key that the exchange proved.

## 19. Conformance

The cases i1–i26 of heap.md §13.5 run over `ndn-heap` with this crate: the conformance suite has one provider, and each case keeps the id it had when the suite also ran the removed `ndn-data`.
The rules above that a case guards, and the tests this crate names for them:

| Case | Property | Rules |
|---|---|---|
| i1 | A stranger with only a code becomes a member with the role the offer names and each side reads what the other writes | §3, §8.5, §9.3, §9.4 |
| i2 | A code once used admits nobody else; its user asking again is answered again | §9.2 step 6, §9.5, §8.6 |
| i3 | A code past its expiry admits nobody | §9.2 step 7, §5.5 |
| i4 | Wrong tries count durably across a restart, then the offer closes for good (`wrong_tries_survive_a_restart`) | §9.6, §15 |
| i5 | A code replayed by a third party admits one key, never two (`a_replayed_ask_admits_one_key_never_two`) | §9.5, §1.3 (2) |
| i6 | An ask forged without the secret is counted and grants nothing (`a_forged_ask_counts_and_grants_nothing`) | §9.2 step 9, §9.7 |
| i7 | A join while the inviter is unreachable is refused as not ready and spends nothing | §8.2 steps 1, 2, §17.3 |
| i8 | A joiner cannot claim a namespace that overlaps one the inviter trusts | §9.2 step 10, §14 |
| i9 | A code cannot make the joiner trust a namespace overlapping one it trusts | §8.1, §8.2 step 4 |
| i10 | Removing a member who joined by a code lasts: asking again with the code never makes it a member again | §9.5 |
| i11 | A stranger cannot close someone else's offer; a used offer counts no tries | §9.6 |
| i12 | A member removed from another device of the owner never comes back by its code | §9.2 step 6, §9.5 |
| i13 | A closed offer admits no one new yet answers the writer it admitted until it expires | §5.4, §9.2 step 5 |
| i14 | A join returns once the joiner may write and says what it waits for | §8.5, §17.3 |
| i15 | An offer's admission makes one grant to link, for the admitted key only | §10 rules 1–4 |
| i16 | A held entry that leaves the person out ends the grant, and a restart keeps the rest | §10 rules 6, 7 |
| i17 | A held entry that demotes the person changes the grant's role, and a restart keeps it | §10 rule 6 |
| i18 | Two offers to one person are two grants, and an entry ends one space's alone | §10 rule 13 |
| i19 | A person let go takes the entry that lets them go and says so | §11 rules 14, 15 |
| i20 | Writers invited by separate invitations read each other through the inviter's copy | §13.3 |
| i21 | A member let go and invited again joins the sealed space and writes again | §8.5, §10 rule 7 |
| i22 | The joiner's list of joined spaces follows the members in force | §11 rule 18 |
| i23 | The joiner holds a grant for the inviter, told once and re-derived from the entries | §11 rule 17 |
| i24 | Mutual invitations make an inviter's entry and a mirror entry that end one by one | §11 rule 17 |
| i25 | A short code joins: one line, a first contact dialled once, a hint record fetched | §6.3, §7, §8.3 |
| i26 | A short code is refused saying why: a typo, a wrong count, a closed, expired or unanswered offer, an altered record | §17.2 |

The new tests this crate adds for what changed: `an_offer_is_served_as_an_extension_under_32_intro_offer` (§2.3, §5.5) and
`the_offer_name_cannot_be_guessed` (§2.3, §18.1: 16 random octets; refusal is silence); and for the stage-7 review:
`an_unproven_ask_gets_silence_for_an_unknown_used_or_closed_offer` (§9.2 steps 3–5, §17.1),
`a_guest_or_relay_device_makes_no_offer` and `a_space_whose_creation_is_not_held_makes_no_offer` (§5.3),
`a_grant_whose_space_is_not_open_is_revoked_and_installed_again_when_it_opens` (§10 rule 6),
`an_unclean_start_closes_every_open_offer`, `a_rolled_back_store_closes_every_open_offer`,
`a_later_rollback_closes_the_offers_made_since_the_first` (§5.4, §18.2) and
`a_stop_between_using_and_the_members_change_closes_the_offer_at_the_next_start` (§5.4, §9.3, §18.1).

## 20. Differences from the former data layer's §19

What changed from §19 of the former data layer ([history/data-layer-remainder.md](history/data-layer-remainder.md)), the specification of the removed `ndn-data` crate.
Everything not listed here is carried over as written (with `folder` read as `space`, `Introducer` as `Host`, `Device` as `Invites`,
`DataError::Introduction` as `InviteError::Refused`).

| data-layer §19 | This specification | What changed, and why |
|---|---|---|
| §19.1 an offer is a log entry `<D>/32=log/<F>/seq=<n>` | §5.1 a Data `<D>/32=intro/32=offer/<id>`, `id` 16 random octets, signed through `Node::sign_packet`, stored and served by the invite extension | the offer's name could be counted to and was public and listed; it cannot now be guessed, and a miss is silence (§2.3, §18.1) |
| §19.1 the use mark and the closing mark are log entries | §5.2 local notes `used/<id>`, `closed/<id>` under `/localhost/ndn-invite/` | nothing of an offer's use is in any log; only the offering device sees the offer used (§18.1) |
| §19.1 the offer names a folder | §5.1 it names a space (`<O>/32=data/…`, heap.md §2.3); field and method names (`folder` in `Grant`, `Departure`, `JoinedFolder`) are kept | the data layer's folder is the heap's space; ndn-link's code names the fields |
| §19.2 the surface carries `<D>/32=held/<e>` and the ask; `introduction_prefixes` returns three names | §2.3, §13.1 the surface carries the ask, the offer by its own name `<D>/32=intro/32=offer/<id>` and the hint token; `introduction_prefixes` returns `[<D>/32=intro, <D>/32=hint]` | the offer is fetched directly; no held copy crosses an introduction link |
| §19.3 step 1 fetches `<D>/32=held/<offer>` (DigestSha256) | §8.2 step 1 fetches the signed offer packet itself; the joiner checks its signature (steps 3, 5; S7) | the offer is a signed packet now |
| §19.4 the use signs the folder's next members record by `share_folder` | §9.3, §9.4 one `Heap::change(MembersChange { add_writers: [ns] if Writer, add_readers: [ns], remove: [] })` | the heap's operation fold replaces members records and revisions |
| §16.2 `IntroAnswer`'s optional `Revision` (0x052A: the members revision in force) | §16.1 `ADMITTED` (0x052A: the `EntryId` of the entry `change` returned, nested `Name`, `Seq` 0x0526, `Digest`) | the joiner waits for the entry that admitted it, not for a revision number |
| §19.3 step 6 the joiner waits for the members record, the epoch key and a walk of every device toward the folder, with a joined note holding the offer's expiry and the revision | §8.5 the joiner opens the space, notes `Node::note_joined`, and waits until the fold lists it, the epoch key is held and `ADMITTED` is applied; there is no walk | a space replicates exactly its members' logs: there are no summaries to walk |
| §19.6 labels `ndn-data/intro/{commit,proof,ask,answer,hint,fp}/1`, asker-proof bindings `ndn-data intro ask\0`, `ndn-data intro answer\0`, grant-note and mirror-note labels `ndn-data/…` | §4.5 `ndn-invite/intro/…/1`, `ndn-invite intro ask\0`, `ndn-invite intro answer\0`, `ndn-invite/grant-note/…`, `ndn-invite/mirror-note/…`; `ndn-trust/intro-short/1` unchanged | a proof, tag or note of one crate never verifies as the other's |
| §19.1, §19.8 rule 3 the notes live under `/localhost/ndn-data/intro/…` | §15 under `/localhost/ndn-invite/…`, each durable (`Node::flush`) before the reply | one prefix per crate; no `ndn-data` state is read |
| §19.8 rules 6, 7 grants judged against the members record in force, checked on every record taken | §10 rules 6, 7 judged against the fold (`Heap::members()`), re-evaluated on every `Change::Members` and at start | the fold replaces records and revisions |
| §19.8 rule 14 the departure mark names the record chosen by reading revisions held from the highest down | §11 rule 14 the entry `Heap::removed_by(person)` names | one function of the entries held replaces the revision walk |
| §19.8 rule 15 `take_departure` fetches the record by name | §11 rule 15 `Node::fetch_entry`, judged and applied as any entry | the host surface lends the fetch |
| §19.8 rule 16 `writer_carries` adds summary roots, `writer_sync` adds `<W>/32=sync` | §13.3 `writer_carries` adds the seal keys, the grant asks and held copies; no summary roots, no `writer_sync` | the heap has no summaries, and a space's sync group is its owner's |
| §19.7 "every device of the inviter sees the offer used" (the use mark is in its log) | §18.1 only the device that made the offer sees it used; another device gives no answer to an ask of it | an offer is answered only by the device that made it |
| §19.9 `Device::local_notes` | not carried: the link memory of ndn-link keeps its own notes under `/localhost/ndn-link/memory/` | not an introduction |
| `Introducer::adopt_scoped`, `release_scoped` | `Adopter` of heap.md §9.4 | they adopt a person for one space, and belong to the node |
| `DataError::Introduction { why }` | `InviteError::Refused(IntroRefusal)`; `InviteError::{Heap, Local, NotReady, BadRequest}` | `InviteError::next()` and `refusal()` keep the old mapping for `ndf`'s `Code::BadCode` |
| §19.3 step 6 the joined note lets go at a record of the admission's revision or later that leaves the device out | §8.5 step 2, §8.6 heap.md §10.9's note: it ends when the fold lists the person, or when a removal it did not name arrives while no `ADD` of hers stands | a removed joiner who joins again with its code waits and is `NotReady` (retry), not `AskOwner` |
| §19.4 the answer carries the admission's revision whenever one is signed | §9.4 no entry is made, and no `ADMITTED` named, when the fold lists the person in every role asked | one `Heap::change` or none |
| §19.1 the offering device checked `F` was a folder it signs members records of | §5.3 `offer` checks the space is open here and of this namespace; whether the device is an owner device is `change`'s to judge at the answer | the check lives where the owner rule is judged |
| §19.8 rule 15 (e) what is fetched is a members record of the folder's line | §11 rule 15 what is fetched is judged by `fetch_entry` as any entry; no separate check that it is a members entry | the heap's admission is the one judge |
| §19.7 a removal closes offers by a closing mark in the log | §5.4 a removal of the person an offer was used by closes it by derivation, nothing written | no mark is signed or kept for it |
| §19.2 the offer is served while unexpired (it was a log entry the link carried while unexpired) | §5.5 the extension serves an offer it holds whatever its expiry; the introduction link carries it while unexpired (§13.1) | the ask judges expiry (`Expired`), the link judges openness |
| §19.4 the notes an offer is judged by (proof key, use mark, tries) were notes under the barrier, unauthenticated | §4.2, §5.2, §18.1 each ends in a MAC under a key derived from the recipient secret, and an unreadable one fails closed; the device's own signature on its offers is checked at a start | the recipient key is public, so a wrap proves nothing of who wrote it |
| §19.8 rule 2 a grant for every admission | §10 rule 2, §11 rule 17 a Reader of a public space is granted nothing, and a device that only reads a public space keeps no mirror note | no entry could end such a grant; only the host could |
| §19.3 step 3 the answer's namespace checks | §8.2 step 3 an `ADMITTED` entry of a device outside the inviter's namespace is `Forged`, and no Interest is sent for it; the space's owner must be the inviter's namespace | the joiner fetches no entry a stranger names |
| §19.2 the surface carries `<D>/32=intro/…` | §13.1 only the ask's digest form `<D>/32=intro/<ParametersSha256Digest>`, the offer's own name and the hint token | no bare prefix or other name under `32=intro` crosses |
| §19.3 the joiner's forwarder carried the offer as a `32=held` DigestSha256 wrapper | §12.1 the host carries `<D>/32=intro` and `<D>/32=hint` in transit from the first contact; the offer and hint records are signed by `D` | the offer is no wrapper any more, so the forwarder cannot validate it before the inviter's anchor is adopted |

Other specifications named the old crate's pieces where they spoke of the introductions (ndn-link.md §13.3A named the introduction's prefixes
as three names and the `Introducer` trait; §19 of the former data layer as a whole): they now name this crate's pieces, and the former text is kept in history/data-layer-remainder.md.
