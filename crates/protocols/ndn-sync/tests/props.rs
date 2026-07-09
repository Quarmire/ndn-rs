//! Property-based tests for the sync wire codecs: SVS state vectors (v2 and
//! v3 dialects) and the PSync IBLT. Decode paths face hostile network input,
//! so the properties are "never panic" and "roundtrip identity".

use bytes::Bytes;
use ndn_packet::{Name, NameComponent};
use ndn_sync::psync::Ibf;
use ndn_sync::psync_sync::{decode_ibf, encode_ibf};
use ndn_sync::svs::MAX_TRACKED_PRODUCERS;
use ndn_sync::{StateEntry, WireDialect, decode_svs_data};
use proptest::prelude::*;

/// A non-empty node Name of arbitrary generic components.
fn arb_name() -> impl Strategy<Value = Name> {
    prop::collection::vec(prop::collection::vec(any::<u8>(), 0..16), 1..4).prop_map(|comps| {
        Name::from_components(
            comps
                .into_iter()
                .map(|v| NameComponent::generic(Bytes::from(v))),
        )
    })
}

fn arb_entries() -> impl Strategy<Value = Vec<StateEntry>> {
    prop::collection::vec(
        (arb_name(), any::<u64>(), any::<u64>()).prop_map(|(name, boot, seq)| StateEntry {
            name,
            boot,
            seq,
        }),
        0..8,
    )
}

proptest! {
    /// V3 (ndnd) state vectors carry (name, boot, seq) and roundtrip exactly,
    /// preserving entry order.
    #[test]
    fn svs_v3_state_vector_roundtrip(entries in arb_entries()) {
        let wire = WireDialect::V3.encode_state_vector(&entries);
        let decoded = WireDialect::V3
            .decode_state_vector(&wire)
            .expect("encoder output must decode");
        prop_assert_eq!(decoded, entries);
    }

    /// V2 (ndn-svs) state vectors have no boot dimension on the wire: encode
    /// ignores `boot` and decode reports `boot = 0`, so the roundtrip
    /// identity holds on entries with `boot` zeroed.
    #[test]
    fn svs_v2_state_vector_roundtrip(entries in arb_entries()) {
        let wire = WireDialect::V2.encode_state_vector(&entries);
        let decoded = WireDialect::V2
            .decode_state_vector(&wire)
            .expect("encoder output must decode");
        let expected: Vec<StateEntry> = entries
            .into_iter()
            .map(|e| StateEntry { boot: 0, ..e })
            .collect();
        prop_assert_eq!(decoded, expected);
    }

    /// Both dialect decoders (and the raw v3 codec) tolerate arbitrary bytes
    /// (up to ~64KiB) without panicking; also retried with the shared 0xC9
    /// outer TLV-TYPE byte spliced in so the input reaches the inner parsers.
    #[test]
    fn svs_decode_never_panics_on_arbitrary_bytes(
        data in prop::collection::vec(any::<u8>(), 0..65536)
    ) {
        let raw = Bytes::from(data.clone());
        let _ = WireDialect::V2.decode_state_vector(&raw);
        let _ = WireDialect::V3.decode_state_vector(&raw);
        let _ = decode_svs_data(&raw);

        if !data.is_empty() {
            let mut forced = data;
            forced[0] = 0xC9;
            let raw = Bytes::from(forced);
            let _ = WireDialect::V2.decode_state_vector(&raw);
            let _ = WireDialect::V3.decode_state_vector(&raw);
            let _ = decode_svs_data(&raw);
        }
    }

    /// CANONICAL REJECTION (adversary bench, FIELD-REPORT-2 §7(b)): an oversized state vector —
    /// more producers than SY-1's `MAX_TRACKED_PRODUCERS` cap — must be REJECTED at decode
    /// (`None`), before it can reach `merge` and force unbounded per-peer state. Red-capable:
    /// without the SY-1 clamp the decoder would accept it. (The no-panic + roundtrip halves are
    /// the properties above; this is the "non-canonical → clean reject, never an accept" half.)
    #[test]
    fn svs_oversized_vector_is_rejected(extra in 1usize..64) {
        // One valid entry per producer, `MAX + extra` of them — over the cap by construction.
        let n = MAX_TRACKED_PRODUCERS + extra;
        let entries: Vec<StateEntry> = (0..n)
            .map(|i| StateEntry {
                name: format!("/n/{i}").parse().unwrap(),
                boot: 0,
                seq: 1,
            })
            .collect();
        for dialect in [WireDialect::V2, WireDialect::V3] {
            let wire = dialect.encode_state_vector(&entries);
            prop_assert!(
                dialect.decode_state_vector(&wire).is_none(),
                "an over-cap state vector ({n} > {MAX_TRACKED_PRODUCERS}) must be rejected, \
                 not accepted into unbounded per-peer state ({dialect:?})"
            );
        }
    }

    /// CANONICITY GAP (F28) — a **fuzzer FINDING**, deliberately NOT a guarantee. A non-minimal
    /// VarNum length on the outer state-vector TLV (e.g. `0xFD 0x00 0x05` for the value 5) is an
    /// alias that a *strict* decoder would reject. `crate::tlv::read_varnumber` is LENIENT (its
    /// 0xFD/0xFE/0xFF arms accept any 2/4/8-byte value with no minimality check), so it accepts
    /// the alias — un-ignore this to see it go RED against the current decoder.
    ///
    /// **RULED (b) accept-and-document (2026-07-09): stays `#[ignore]`d; do NOT tighten
    /// `read_varnumber`.** Verified against source: the reference decoders ndn-sync shares this SVS
    /// wire with are BOTH lenient too — ndn-cxx `readVarNumber` (`encoding/tlv.hpp`) and ndnd
    /// `ReadTLNum` (`std/encoding/primitives.go`) accept non-minimal VarNums with no check. ndn-sync
    /// MATCHES them; all three decode the same bytes to the same value (a canonicity gap, not an
    /// interop divergence). A unilateral strict receiver would only RELOCATE the inconsistency
    /// (strict nodes drop what lenient nodes process), and canonicity is enforced above the
    /// waterline at the NDF Block layer, not in this shared sync decoder. Low severity (no panic,
    /// no unbounded work — the SY-1/SY-2 caps hold). Full matrix, ruling, and the upstream
    /// spec-clarification draft: `docs/specs/f28-non-minimal-varnum-decode.md`. This repro is the
    /// regression gate the day (if ever) the spec mandates strict — un-ignoring it is then a
    /// one-line change made IN COMPANY with ndn-cxx/ndnd, never alone.
    #[test]
    #[ignore = "F28 RULED (b) accept-and-document: read_varnumber is lenient by design (parity with \
                ndn-cxx/ndnd, both verified lenient); canonicity is enforced above at the NDF Block \
                layer. Do not tighten unilaterally. Package: docs/specs/f28-non-minimal-varnum-decode.md"]
    fn svs_non_minimal_outer_length_is_rejected(entries in arb_entries()) {
        prop_assume!(!entries.is_empty());
        let canonical = WireDialect::V2.encode_state_vector(&entries);
        // Canonical layout: [TYPE=0xC9][len: minimal VarNum][value…]. Rewrite the length as a
        // non-minimal 3-byte form (0xFD hi lo) of the SAME value — an alias the strict reader
        // must refuse.
        let body_len = (canonical.len() - 2) as u16; // 1 type byte + 1 minimal len byte
        if canonical.len() >= 2 && canonical[1] < 0xFD && body_len as usize == canonical[1] as usize {
            let mut aliased = Vec::with_capacity(canonical.len() + 2);
            aliased.push(canonical[0]); // type
            aliased.push(0xFD); // 2-byte-length marker
            aliased.extend_from_slice(&body_len.to_be_bytes()); // non-minimal length
            aliased.extend_from_slice(&canonical[2..]); // value
            let raw = Bytes::from(aliased);
            prop_assert!(
                WireDialect::V2.decode_state_vector(&raw).is_none(),
                "a non-minimal VarNum length is an alias and must be rejected"
            );
        }
    }

    /// PSync IBLT: encode_ibf → decode_ibf (with the sender's
    /// expected_entries) reproduces the cell array exactly.
    #[test]
    fn psync_iblt_roundtrip(
        expected_entries in 1usize..60,
        keys in prop::collection::vec(any::<u32>(), 0..24),
    ) {
        let mut ibf = Ibf::from_expected(expected_entries);
        for key in &keys {
            ibf.insert(*key);
        }
        let wire = encode_ibf(&ibf);
        let decoded = decode_ibf(&wire, expected_entries).expect("encoder output must decode");
        prop_assert_eq!(decoded.raw_cells(), ibf.raw_cells());
    }

    /// decode_ibf tolerates arbitrary (non-zlib / truncated / mismatched)
    /// bytes without panicking.
    #[test]
    fn psync_iblt_decode_never_panics(
        data in prop::collection::vec(any::<u8>(), 0..8192),
        expected_entries in 0usize..100,
    ) {
        let _ = decode_ibf(&data, expected_entries);
    }
}
