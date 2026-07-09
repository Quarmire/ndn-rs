# F28 — Non-minimal VAR-NUMBER on the SVS wire: canonicity gap, maintainer decision package

**Status:** decision package for the ndn-rs maintainer (and, if the ruling goes that way, the
NDN-TLV spec / ndn-cxx / ndnd maintainers). **This document does not merge a fix** — a shared
wire decoder is not ndn-rs's (or NDF's) to tighten unilaterally.

**Date:** 2026-07-09. **Prepared from:** direct reading of the reference decoders (sources local).

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

**Therefore: tightening `ndn-sync` alone would *create* a divergence where none exists** — it
would reject wire that ndn-cxx and ndnd both accept, making ndn-sync the strict outlier and
forking the de-facto interop contract.

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

- **(a) Tighten `ndn-sync` unilaterally (reject non-minimal).** ❌ **Rejected.** Makes ndn-sync
  stricter than *both* reference decoders; it would drop wire ndn-cxx and ndnd accept — a
  unilateral fork of the shared decoder's de-facto contract. A shared wire decoder is not
  ndn-rs's / NDF's call to tighten alone.
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

## 5. Recommendation

**Adopt (b): do not unilaterally tighten `ndn-sync`.** Document that its VAR-NUMBER decoder is
deliberately lenient for reference parity, and open a spec-clarification issue upstream. Leave the
`svs_non_minimal_outer_length_is_rejected` repro `#[ignore]`d (its assertion encodes the *strict*
posture, which is not the reference behaviour), with a corrected, accurate rationale. It stays
**red-capable on demand**: a maintainer un-ignores it to *see* that ndn-sync (like ndn-cxx and
ndnd) accepts the alias. Promote it to a live regression gate **only** after an ecosystem decision
in (b)/(c) — never as a silent ndn-sync-only tightening.

**Suggested upstream issue (ndn-rs maintainer):** "Ledger F28 as accept-and-document; ndn-sync
matches ndn-cxx/ndnd (both lenient on decode); the canonical-decode question is spec-level, not an
ndn-sync bug. No code change to the decoder pending an NDN-TLV spec ruling."

**If escalated (NDN-TLV spec / ndn-cxx / ndnd):** "NDN-TLV VAR-NUMBER: encoders emit minimal;
decoders (ndn-cxx `readVarNumber`, ndnd `ReadTLNum`) accept non-minimal without rejection. Is
non-minimal decode conformant? If not, decoders across the ecosystem need a coordinated strict mode
(and a canonical-wire test vector)."

---

## 6. Repro (verbatim location)

`crates/protocols/ndn-sync/tests/props.rs :: svs_non_minimal_outer_length_is_rejected` — takes a
canonical V2 state vector, rewrites the outer TLV length as a non-minimal 3-byte alias of the same
value, and asserts `WireDialect::V2.decode_state_vector(..).is_none()`. Currently `#[ignore]`d;
un-ignore to reproduce the RED (the decoder accepts the alias) that this package is about.
