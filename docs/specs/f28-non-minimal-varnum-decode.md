# F28 — Non-minimal VAR-NUMBER on the SVS wire: canonicity gap, maintainer decision package

**Status: RULED — (b) accept-and-document (2026-07-09).** No decode change to `read_varnumber`;
the posture is documented in-code and here; the normative question moves to the NDN-TLV spec.
Closed on the NDF side; ball in the spec's court. (Actions in §7.)

**Date:** 2026-07-09. **Prepared from:** direct reading of the reference decoders (sources local).

> **One correction the ruling made to this package** (recorded so the reasoning stays honest):
> an earlier draft called a strict-on-decode `ndn-sync` an *"interop fork."* That is a shade too
> strong. Strict decode would reject **nothing a conformant peer sends** — all three encoders
> (ndn-cxx, ndnd, ndn-sync) emit minimal — only non-minimal wire, which today comes solely from a
> non-conformant or adversarial sender. So the real choice is **Postel-liberalism (accept
> malformed-but-decodable) vs strict canonicity (reject non-canonical)** on input no honest peer
> produces — a legitimate maintainer call, decided below on its merits, not by a reflex "fork"
> label. §4/§5 reflect the corrected framing.

---

## 1. The gap

`ndn_sync`'s TLV var-number reader accepts **non-minimally-encoded** VAR-NUMBERs:

```rust
// crates/protocols/ndn-sync/src/tlv.rs  (read_varnumber)
0xFD => { /* read 2 bytes big-endian, return */ }   // no check that value >= 253
0xFE => { /* read 4 bytes big-endian, return */ }   // no check that value >= 65536
0xFF => { /* read 8 bytes big-endian, return */ }   // no check that value >= 2^32
```

So the outer state-vector TLV length `5` can arrive as the minimal `0x05` **or** the non-minimal
alias `0xFD 0x00 0x05` (or `0xFE 0x00 0x00 0x00 0x05`, …), and the decoder accepts all of them.
NDN-TLV is meant to be canonical (a value has one wire form), so multiple accepted encodings for
one value is a **canonicity** gap.

**Red-capable repro (already in tree, `#[ignore]`d):**
`crates/protocols/ndn-sync/tests/props.rs :: svs_non_minimal_outer_length_is_rejected`. Un-ignore
it and it goes **RED against the current decoder** — it asserts the alias is rejected, and the
decoder accepts it. That RED *is* the demonstrable gate for a maintainer.

---

## 2. Interop matrix — the crux (read from source, all three local)

| Implementation | Decoder | Non-minimal VAR-NUMBER on decode |
|---|---|---|
| **ndn-cxx** (C++, the decoder **ndn-svs** uses) | `encoding/tlv.hpp` `readVarNumber` → `readNumber(1U << (firstOctet & 0b11), …)` | **ACCEPTS** — reads the marked width as a big-endian integer, **no minimality check**. Its unit tests (`tests/unit/encoding/tlv.t.cpp`) cover only minimal round-trip and truncation; there is **no** non-minimal-rejection test. |
| **ndnd** (Go) | `std/encoding/primitives.go` `ReadTLNum` / `ParseTLNum` | **ACCEPTS** — switch on `0xfd/0xfe/0xff` → read 2/4/8 bytes, **no minimality check**. |
| **ndn-sync** (Rust, this repo) | `src/tlv.rs` `read_varnumber` | **ACCEPTS** — same shape, **no minimality check**. |

**Both reference implementations enforce minimal width on *encode* but accept non-minimal on
*decode*.** (ndn-cxx `writeVarNumber` / ndnd `EncodingLength` produce minimal; neither rejects a
non-minimal input.)

### Consequence for the "who is the outlier?" question

`ndn-sync` is **not** the lenient outlier — it **matches ndn-cxx and ndnd exactly.** The comment
in `props.rs` that motivated this finding ("NDN TLV is canonical; ndn-cxx rejects it") is
**factually wrong** and has been corrected in this session (comment only, no behaviour change).

Crucially, all three decode the *same* bytes to the *same value* (`0xFD 0x00 0x05` → `5`
everywhere). So there is **no cross-implementation value disagreement** today — this is a
canonicity gap (a value has multiple accepted encodings), **not** an interop divergence.

**What tightening `ndn-sync` alone would actually do** (corrected from an earlier "interop fork"
overstatement): it would reject **no conformant peer** — every encoder emits minimal — only
non-minimal wire from a non-conformant/adversarial sender. It would *not* fork interop with honest
peers. What it *would* do is **move the divergence**: for the same non-minimal Interest, strict
nodes drop it while lenient ndn-cxx/ndnd nodes process it — so the network aggregates it
inconsistently (see §3). A canonicity gap is network-wide by nature; one strict receiver cannot
close it, only relocate it. That is the real reason not to do it unilaterally — see §5.

---

## 3. Severity — honest characterization

**LOW (canonicity / wire hygiene). Not a memory-safety or DoS issue.**

- **No panic, no unbounded work.** A non-minimal length still decodes to the same bounded value;
  the SVS resource caps (`SY-1` MAX_TRACKED_PRODUCERS, `SY-2` MAX_GAP_SPAN) apply *after* decode in
  `merge`, so they are not bypassed. Verified against the code path.
- **No interop break.** Every implementation decodes the alias to the same value.
- **Real (small) blast radius — non-canonical wire:**
  - An SVS Sync Interest carrying ApplicationParameters gets a `ParametersSha256DigestComponent`
    in its name. A non-minimal length changes the parameter bytes → a different params digest →
    a different Interest **name** for a semantically identical state vector. This defeats forwarder
    **Interest aggregation / storm-suppression** for such Interests, and means "the same" sync
    state can appear under two names (a content-addressing wrinkle if raw bytes ever key a dedup or
    digest structure). SVS *semantics* are unaffected — the decoded vector is what is merged.
  - A non-conformant or adversarial sender is the only source: `ndn-sync`'s **encoder never emits
    non-minimal** (it only *accepts* it). So the exposure is "how strictly to treat non-conformant
    input," not "reject a conformant peer."

Do not inflate this to a security fix; do not dismiss it as a non-issue. It is a canonicity
deviation shared by the whole reference ecosystem.

---

## 4. Options

- **(a) Tighten `ndn-sync` unilaterally (reject non-minimal).** ❌ **Rejected — for the right
  reason.** Not because it "forks interop" (it rejects nothing a conformant peer sends), but
  because a unilateral strict *receiver* does not close the gap — it **relocates** it: strict nodes
  drop a non-minimal Interest that lenient ndn-cxx/ndnd nodes process, so aggregation becomes *more*
  inconsistent, not less. The canonicity problem is network-wide; only an ecosystem-level fix (spec
  mandates minimal-on-decode → all three tighten together) closes it. And by the waterline,
  enforcing canonicity in the *shared sync wire decoder* is the wrong layer for it (see §5).
- **(b) Accept-and-document (match the reference) + raise a spec clarification.** ✅ **Recommended.**
  Keep the lenient decode (parity with ndn-cxx/ndnd), add a doc note on `read_varnumber` that
  non-minimal is accepted deliberately for reference parity, and raise the *normative* question
  with the NDN-TLV spec / ndn-cxx / ndnd maintainers: **should NDN-TLV decoders reject non-minimal
  VAR-NUMBER?** The de-facto answer today is "no." If the written spec mandates minimal-on-decode,
  then **all three** implementations are non-conformant and the fix must be **ecosystem-coordinated**,
  not ndn-sync-first.
- **(c) Ecosystem-wide strict decode.** The path **iff** the spec clarification in (b) rules
  "decoders must reject." Then ndn-cxx, ndnd, and ndn-sync tighten together, and the `props.rs`
  repro is un-ignored across the ecosystem as the shared regression gate.

---

## 5. Ruling — (b) accept-and-document

**Adopted: leave `read_varnumber` lenient, change no decode behaviour, move the normative question
to the spec.** Two reasons decide it:

1. **A unilateral strict receiver moves the divergence, it does not close the gap.** The canonicity
   harm is that a non-minimal length yields a different `ParametersSha256DigestComponent` for the
   same state vector, defeating forwarder aggregation. If only ndn-sync rejects it while ndn-cxx and
   ndnd accept it, the network processes that Interest at some nodes and drops it at others — *more*
   inconsistent aggregation, not less. The gap is network-wide by nature; the genuine fix is
   ecosystem-level (spec mandates minimal-on-decode → all three tighten together), which is exactly
   what the spec-clarification issue is for.
2. **The waterline: this is not ndn-sync's canonicity to enforce.** `ndn-sync` is ndn-workspace's
   shared wire decoder — below the waterline, "moving bytes" — and should match the NDN ecosystem
   it is part of. NDF's canonicity needs are met **above** the waterline, where they are already
   enforced: NDF's Block layer (`ndf-core`) has its own strict header decoder over ndn-tlv's
   VAR-NUMBER, plus the strict `from_utf8` the fuzzer earned. NDF already gets strictness exactly
   where it matters (the Block layer); the SVS Sync Interest VAR-NUMBER is the *sync protocol's*
   wire, and there matching the reference is correct. Making the shared decoder
   stricter-than-reference to serve an NDF concern already handled at NDF's own layer would enforce
   the same invariant in the wrong place.

The repro stays `#[ignore]`d and **red-capable on demand** — un-ignoring it is a one-line change to
be made **in company with ndn-cxx/ndnd** the day (if ever) the spec mandates strict, never as a
silent ndn-sync-only tightening.

---

## 6. Actions (ruling (b))

1. **No decode change** to `read_varnumber`. ✅
2. **Document the posture in-code:** a doc-comment on `read_varnumber` (`src/tlv.rs`) records the
   deliberate leniency — reference parity with ndn-cxx/ndnd, canonicity enforced above at the NDF
   Block layer, pointer to this file — so the next fuzzer-finder or reader does not re-flag it. ✅
3. **File the spec-clarification issue upstream** (NDN-TLV / named-data spec; cc ndn-cxx, ndnd) —
   the draft is §7. This is the lever that could eventually flip all three implementations together.
4. **Keep the repro `#[ignore]`d and red-capable** (`props.rs`), comment corrected. It becomes the
   regression gate the day the spec mandates strict.
5. **Ledger:** F28 → **RULED (b)**, closed on the NDF side, ball in the NDN-TLV spec's court.

---

## 7. Upstream spec-clarification issue (ready to file — NDN-TLV / named-data spec, cc ndn-cxx, ndnd)

> **Title:** NDN-TLV VAR-NUMBER — must decoders reject non-minimal encodings, or is minimal-on-encode
> sufficient?
>
> **Body:** The NDN Packet Format encodes TLV-TYPE / TLV-LENGTH as VAR-NUMBER. All reference
> encoders emit the minimal width, but the reference **decoders accept non-minimal encodings**
> without rejection — verified in source:
> - ndn-cxx `readVarNumber` (`ndn-cxx/encoding/tlv.hpp`): `len = 1U << (firstOctet & 0b11)`, reads
>   that many bytes, no minimality check; unit tests cover only minimal round-trip + truncation.
> - ndnd `ReadTLNum` / `ParseTLNum` (`std/encoding/primitives.go`): reads the marked width, no check.
> - ndn-sync `read_varnumber` matches both.
>
> So `0xFD 0x00 0x05` and `0x05` both decode to `5` everywhere. This is a **canonicity** gap (a
> value has multiple accepted wire forms), not a value disagreement. It matters because a
> non-minimal length changes an Interest's `ParametersSha256DigestComponent`, so a semantically
> identical Sync Interest gets a different name — defeating forwarder aggregation *inconsistently*
> if some nodes decode strictly and others leniently.
>
> **Question:** Is non-minimal VAR-NUMBER decode conformant? If the spec intends canonical wire,
> decoders need a coordinated strict mode + a canonical-wire test vector, adopted across ndn-cxx,
> ndnd, and ndn-sync together (a unilateral strict receiver only relocates the inconsistency).
> If minimal-on-encode is sufficient, please state that decoders MAY accept non-minimal, so
> implementations can document the posture and fuzzers stop re-flagging it.

---

## 8. Repro (verbatim location)

`crates/protocols/ndn-sync/tests/props.rs :: svs_non_minimal_outer_length_is_rejected` — takes a
canonical V2 state vector, rewrites the outer TLV length as a non-minimal 3-byte alias of the same
value, and asserts `WireDialect::V2.decode_state_vector(..).is_none()`. Currently `#[ignore]`d;
un-ignore to reproduce the RED (the decoder accepts the alias) that this package is about.
