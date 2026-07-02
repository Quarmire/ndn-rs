//! Property-based tests for the sync wire codecs: SVS state vectors (v2 and
//! v3 dialects) and the PSync IBLT. Decode paths face hostile network input,
//! so the properties are "never panic" and "roundtrip identity".

use bytes::Bytes;
use ndn_packet::{Name, NameComponent};
use ndn_sync::psync::Ibf;
use ndn_sync::psync_sync::{decode_ibf, encode_ibf};
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
