# Network coding (FEC)

`ndn-coding` (`crates/ndn-coding`) adds end-to-end forward error
correction over named Data. A producer publishes K source + (N−K) parity
segments per generation; a consumer recovers the payload once any K of the
N segments arrive. Every coded segment is an ordinary named, signed Data
object, so caches, the PIT, and signature verification work unchanged —
the forwarder is never modified.

This is phase **F1**. In-network recoding (F2) and link-layer coding (F3)
are out of scope; see "What's not here".

## When it helps

FEC pays off when segments are lost, or when an object is fetched over
multiple paths or to multiple receivers: a receiver that misses a source
segment fetches a parity segment instead of waiting for a retransmission.
On a single clean path it is pure overhead — you fetch K, they all arrive,
and the parity is unused. Reach for it on lossy or multi-path links.

## Producer

`CodedProducer` wraps an `ndn-app` `Producer`. Encode one object as a
generation and serve its N coded segments by name:

```rust,ignore
use ndn_coding::{CodedProducer, FecPolicy};

let policy = FecPolicy::systematic(8, 12).unwrap();   // K=8, N=12
let coded = CodedProducer::new(producer, policy);
coded.serve_object("/alice/clip/v=3".parse()?, payload, /*generation*/ 1).await?;
```

Each segment is served at `<object>/<index>` (index `0..N`). Sources are
`0..K`, parity `K..N`.

## Consumer

`CodedFetcher` pulls K-of-N segments and recovers the payload, requesting
parity when a segment is slow or lost:

```rust,ignore
use ndn_coding::CodedFetcher;

let fetcher = CodedFetcher::new();
let payload = fetcher.fetch(&consumer, "/alice/clip/v=3".parse()?, &policy).await?;
```

The fetcher sends a window of segment Interests, correlates each reply by
the FEC index in its metadata, and on a per-segment timeout pulls the next
(parity) index — stopping as soon as the decoder reaches rank K. Spreading
the segment Interests lets the forwarder's strategy answer them over
different next-hops or caches; that is where the multi-path benefit comes
from. Tune the window and timeouts with `FetchConfig`.

## Building blocks

If you need finer control, the core layer is usable directly and carries
no async runtime (it builds for `wasm32` / embedded with
`--no-default-features`):

- `segment_payload(payload, &policy, generation_id)` → the N coded
  segment bodies.
- `CodedAssembler::absorb_content(content)` → `Some(payload)` once K
  independent segments have been absorbed.

```rust,ignore
use ndn_coding::{segment_payload, CodedAssembler};

let segments = segment_payload(&payload, &policy, 1)?;
let mut asm = CodedAssembler::new();
for seg in &segments {
    if let Some(recovered) = asm.absorb_content(&seg.content)? {
        // recovered == payload
        break;
    }
}
```

## Policy and management

Which prefixes are coded — and with what K/N and role — is policy, set two
ways:

- **Config**: `[[coding.policy]]` blocks in the forwarder TOML.
- **Management**: `/localhost/nfd/coding/{set,unset,list}`, with a role of
  `produced` (content this node publishes) or `consumed` (content it
  fetches).

The encode/decode mechanism itself is the library API above; you do not
drive it over the management protocol.

## Wire format

A segment's `Content` is a `FecMetadata` TLV (generation, role, index, K,
N, field, optional padding length) followed by the row bytes. The arithmetic
is GF(2^8) with a Vandermonde generator, so any K of the N segments
suffice. The full layout is in `docs/notes/coding-wire-spec-2026-05-22.md`;
the TLV codes are provisional pending F2.

## What's not here

- **F2 — in-network RLNC recoding.** A recoded packet is a new linear
  combination the producer never signed, so authenticating it end-to-end
  needs a trust-model decision that has not been made. Gated behind the
  `f2-recode` feature; not implemented.
- **F3 — link-layer (inter-flow) coding.** Belongs in a face/link driver.
