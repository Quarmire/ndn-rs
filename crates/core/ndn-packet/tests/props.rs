//! Property-based tests for the packet codecs. The wire surface parses
//! hostile network input, so the properties enforced here are "never panic"
//! (arbitrary bytes into every decoder) and "roundtrip identity" (builder →
//! encode → decode preserves the fields).
//!
//! Gated on `std` because the encode builders need the hashing features
//! (same gate as `w1_overflow.rs`).
#![cfg(feature = "std")]

use std::time::Duration;

use bytes::Bytes;
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::lp::{LpPacket, encode_lp_with_headers};
use ndn_packet::{
    CachePolicyType, Data, Interest, LpHeaders, MAX_PERSISTENT_LIFETIME_SECS, Name, NameComponent,
    tlv_type,
};
use proptest::prelude::*;

/// A GenericNameComponent with arbitrary (bounded) value bytes.
fn arb_generic_component() -> impl Strategy<Value = NameComponent> {
    prop::collection::vec(any::<u8>(), 0..24).prop_map(|v| NameComponent::generic(Bytes::from(v)))
}

/// A non-empty Name of arbitrary generic components (Interest/Data decode
/// rejects an empty Name, and generic components sidestep the
/// ParametersSha256DigestComponent placement rules).
fn arb_name() -> impl Strategy<Value = Name> {
    prop::collection::vec(arb_generic_component(), 1..6).prop_map(Name::from_components)
}

/// One URI-roundtrippable name component. The NDN URI escaping is total, so
/// generation is now unconstrained:
///
/// * generic values are fully arbitrary bytes, including empty and `=` — the
///   Display path percent-encodes everything outside the RFC 3986 unreserved
///   set (so `=` cannot re-parse as a typed prefix) and applies the periods
///   rule so an empty or all-periods value survives the round-trip;
/// * typed integer components (seg=/v=/t=/seq=/off=) roundtrip for any u64
///   via their decimal form, and digest components via their hex form.
fn arb_uri_component() -> impl Strategy<Value = NameComponent> {
    let generic = prop::collection::vec(any::<u8>(), 0..24)
        .prop_map(|v| NameComponent::generic(Bytes::from(v)));
    // Keyword values may contain '=': `keyword=` is matched before the
    // typed-prefix fallback, and the remainder percent-decodes verbatim.
    let keyword = prop::collection::vec(any::<u8>(), 0..24)
        .prop_map(|v| NameComponent::keyword(Bytes::from(v)));
    prop_oneof![
        4 => generic,
        1 => keyword,
        1 => any::<u64>().prop_map(|s| {
            // No public NameComponent::segment constructor; go via append_segment.
            Name::root().append_segment(s).components()[0].clone()
        }),
        1 => any::<u64>().prop_map(NameComponent::version),
        1 => any::<u64>().prop_map(NameComponent::timestamp),
        1 => any::<u64>().prop_map(NameComponent::sequence_num),
        1 => any::<u64>().prop_map(NameComponent::byte_offset),
        1 => any::<[u8; 32]>().prop_map(|d| NameComponent::new(
            tlv_type::IMPLICIT_SHA256,
            Bytes::copy_from_slice(&d)
        )),
        1 => any::<[u8; 32]>().prop_map(|d| NameComponent::new(
            tlv_type::PARAMETERS_SHA256,
            Bytes::copy_from_slice(&d)
        )),
    ]
}

proptest! {
    /// Interest/Data/LpPacket decode never panic on arbitrary bytes (up to
    /// ~64KiB). Also retried with the correct outer TLV-TYPE byte spliced in
    /// so the fuzz input reaches past the first type check more often.
    #[test]
    fn decoders_never_panic_on_arbitrary_bytes(
        data in prop::collection::vec(any::<u8>(), 0..65536)
    ) {
        let raw = Bytes::from(data.clone());
        let _ = Interest::decode(raw.clone());
        let _ = Data::decode(raw.clone());
        let _ = LpPacket::decode(raw);

        if !data.is_empty() {
            for type_byte in [0x05u8, 0x06, 0x64] {
                let mut forced = data.clone();
                forced[0] = type_byte;
                let raw = Bytes::from(forced);
                let _ = Interest::decode(raw.clone());
                let _ = Data::decode(raw.clone());
                let _ = LpPacket::decode(raw);
            }
        }
    }

    /// InterestBuilder → encode → Interest::decode preserves name, flags,
    /// HopLimit, and InterestLifetime. Lifetime is generated within the
    /// decoder's 1-hour clamp (X-3) so the value survives exactly.
    #[test]
    fn interest_roundtrip(
        name in arb_name(),
        can_be_prefix in any::<bool>(),
        must_be_fresh in any::<bool>(),
        hop_limit in prop::option::of(any::<u8>()),
        lifetime_ms in prop::option::of(0..=u64::from(MAX_PERSISTENT_LIFETIME_SECS) * 1000),
    ) {
        let mut builder = InterestBuilder::new(name.clone());
        if can_be_prefix {
            builder = builder.can_be_prefix();
        }
        if must_be_fresh {
            builder = builder.must_be_fresh();
        }
        if let Some(h) = hop_limit {
            builder = builder.hop_limit(h);
        }
        if let Some(ms) = lifetime_ms {
            builder = builder.lifetime(Duration::from_millis(ms));
        }
        let wire = builder.build();

        let interest = Interest::decode(wire).expect("builder output must decode");
        prop_assert_eq!(interest.name.as_ref(), &name);
        prop_assert_eq!(interest.selectors().can_be_prefix, can_be_prefix);
        prop_assert_eq!(interest.selectors().must_be_fresh, must_be_fresh);
        prop_assert_eq!(interest.hop_limit(), hop_limit);
        // The builder always emits InterestLifetime (default 4000 ms).
        let expected_ms = lifetime_ms.unwrap_or(4000);
        prop_assert_eq!(interest.lifetime(), Some(Duration::from_millis(expected_ms)));
    }

    /// DataBuilder (DigestSha256) → Data::decode preserves name, content,
    /// and FreshnessPeriod.
    #[test]
    fn data_roundtrip(
        name in arb_name(),
        content in prop::collection::vec(any::<u8>(), 0..512),
        freshness_ms in prop::option::of(any::<u32>()),
    ) {
        let mut builder = DataBuilder::new(name.clone(), &content);
        if let Some(ms) = freshness_ms {
            builder = builder.freshness(Duration::from_millis(u64::from(ms)));
        }
        let wire = builder.sign_digest_sha256();

        let data = Data::decode(wire).expect("builder output must decode");
        prop_assert_eq!(data.name.as_ref(), &name);
        prop_assert_eq!(
            data.content().map(|c| c.as_ref()),
            Some(content.as_slice())
        );
        let freshness = data.meta_info().and_then(|mi| mi.freshness_period);
        prop_assert_eq!(
            freshness,
            freshness_ms.map(|ms| Duration::from_millis(u64::from(ms)))
        );
    }

    /// The NDN canonical order on Names is a total order: consistent with
    /// equality, antisymmetric, and transitive.
    #[test]
    fn name_canonical_order_is_total(
        a in prop::collection::vec(arb_generic_component(), 0..5).prop_map(Name::from_components),
        b in prop::collection::vec(arb_generic_component(), 0..5).prop_map(Name::from_components),
        c in prop::collection::vec(arb_generic_component(), 0..5).prop_map(Name::from_components),
    ) {
        use std::cmp::Ordering;

        // Consistency with Eq, and antisymmetry.
        prop_assert_eq!(a.cmp(&b), b.cmp(&a).reverse());
        prop_assert_eq!(a.cmp(&b) == Ordering::Equal, a == b);

        // Transitivity (both directions).
        if a <= b && b <= c {
            prop_assert!(a <= c);
        }
        if a >= b && b >= c {
            prop_assert!(a >= c);
        }
    }

    /// A strict prefix always sorts before its extension.
    #[test]
    fn name_strict_prefix_sorts_before_extension(
        prefix in prop::collection::vec(arb_generic_component(), 0..5).prop_map(Name::from_components),
        extension in prop::collection::vec(arb_generic_component(), 1..4),
    ) {
        let mut extended = prefix.clone();
        for comp in extension {
            extended = extended.append_component(comp);
        }
        prop_assert!(extended.has_prefix(&prefix));
        prop_assert!(prefix < extended);
    }

    /// Name → URI (Display) → Name (FromStr) is the identity for the
    /// component set produced by `arb_uri_component` (see its doc comment for
    /// why generation is constrained).
    #[test]
    fn name_uri_roundtrip(comps in prop::collection::vec(arb_uri_component(), 0..6)) {
        let name = Name::from_components(comps);
        let uri = name.to_string();
        let parsed: Name = uri.parse().expect("Display output must parse");
        prop_assert_eq!(parsed, name, "URI was {}", uri);
    }

    /// encode_lp_with_headers → LpPacket::decode preserves the fragment and
    /// every header. PitToken is generated non-empty (NDNLPv2 requires >= 1
    /// byte) and CachePolicyType code 1 canonicalizes to NoCache.
    #[test]
    fn lp_packet_roundtrip(
        fragment in prop::collection::vec(any::<u8>(), 0..2048),
        pit_token in prop::option::of(prop::collection::vec(any::<u8>(), 1..32)),
        congestion_mark in prop::option::of(any::<u64>()),
        incoming_face_id in prop::option::of(any::<u64>()),
        next_hop_face_id in prop::option::of(any::<u64>()),
        cache_policy_code in prop::option::of(any::<u64>()),
    ) {
        let cache_policy = cache_policy_code.map(|code| {
            if code == 1 {
                CachePolicyType::NoCache
            } else {
                CachePolicyType::Other(code)
            }
        });
        let headers = LpHeaders {
            pit_token: pit_token.clone().map(Bytes::from),
            congestion_mark,
            incoming_face_id,
            next_hop_face_id,
            cache_policy,
        };
        let wire = encode_lp_with_headers(&fragment, &headers);

        let lp = LpPacket::decode(wire).expect("encoder output must decode");
        prop_assert_eq!(lp.fragment.as_deref(), Some(fragment.as_slice()));
        prop_assert_eq!(lp.pit_token.as_deref(), pit_token.as_deref());
        prop_assert_eq!(lp.congestion_mark, congestion_mark);
        prop_assert_eq!(lp.incoming_face_id, incoming_face_id);
        prop_assert_eq!(lp.next_hop_face_id, next_hop_face_id);
        prop_assert_eq!(lp.cache_policy, cache_policy);
    }
}
