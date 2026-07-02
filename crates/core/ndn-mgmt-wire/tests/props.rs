//! Property-based tests for the NFD management wire codecs: every public
//! decode entry point must never panic on arbitrary bytes, and the richest
//! codec (ControlParameters, plus ControlResponse wrapping it) must
//! roundtrip from arbitrary field values.

use bytes::Bytes;
use ndn_foundation_types::{Name, NameComponent};
use ndn_mgmt_wire::{
    ControlParameters, ControlResponse, FaceStatus, FibEntry, GeneralStatus, PendingApproval,
    RibEntry, StrategyChoice, parse_command_name,
};
use proptest::prelude::*;

/// A Name of arbitrary components (type in the TLV u32 range, bounded value
/// bytes). The mgmt name codec preserves component types verbatim.
fn arb_name() -> impl Strategy<Value = Name> {
    prop::collection::vec(
        (
            1u64..0x1_0000_0000,
            prop::collection::vec(any::<u8>(), 0..16),
        ),
        0..4,
    )
    .prop_map(|comps| {
        Name::from_components(
            comps
                .into_iter()
                .map(|(typ, value)| NameComponent::new(typ, Bytes::from(value))),
        )
    })
}

/// ControlParameters with every field drawn arbitrarily. Split into three
/// sub-tuples to stay within proptest's tuple arity.
fn arb_control_parameters() -> impl Strategy<Value = ControlParameters> {
    let stage1 = (
        prop::option::of(arb_name()),   // name
        prop::option::of(any::<u64>()), // face_id
        prop::option::of(".*"),         // uri
        prop::option::of(".*"),         // local_uri
        prop::option::of(any::<u64>()), // origin
        prop::option::of(any::<u64>()), // cost
        prop::option::of(any::<u64>()), // flags
        prop::option::of(any::<u64>()), // mask
        prop::option::of(any::<u64>()), // expiration_period
        prop::option::of(any::<u64>()), // face_persistency
    );
    let stage2 = (
        prop::option::of(arb_name()),                                // strategy
        prop::option::of(any::<u64>()),                              // mtu
        prop::option::of(prop::collection::vec(any::<u8>(), 0..40)), // shm_control_token
        prop::option::of(any::<u64>()),                              // base_cong_interval
        prop::option::of(any::<u64>()),                              // def_cong_threshold
        prop::option::of(any::<u64>()),                              // capacity
        prop::option::of(any::<u64>()),                              // count
        prop::option::of(any::<u16>()),                              // fec_k
        prop::option::of(any::<u16>()),                              // fec_n
        prop::option::of(any::<u8>()),                               // fec_field
    );
    let stage3 = (
        prop::option::of(any::<u8>()),             // fec_role
        prop::option::of(any::<u8>()),             // rl_direction
        prop::option::of(any::<u32>()),            // rl_interest_pps
        prop::option::of(any::<u32>()),            // rl_interest_burst
        prop::option::of(any::<u64>()),            // rl_data_bps
        prop::option::of(any::<u64>()),            // rl_data_burst_bytes
        prop::option::of(any::<u8>()),             // rl_overflow
        prop::option::of(any::<u32>()),            // rl_queue_max
        prop::collection::vec((".*", ".*"), 0..3), // partial_failures
    );
    (stage1, stage2, stage3).prop_map(|(s1, s2, s3)| {
        let (name, face_id, uri, local_uri, origin, cost, flags, mask, exp, persistency) = s1;
        let (strategy, mtu, token, base_cong, def_cong, capacity, count, fec_k, fec_n, fec_field) =
            s2;
        let (fec_role, rl_dir, rl_pps, rl_burst, rl_bps, rl_bytes, rl_overflow, rl_queue, pf) = s3;
        ControlParameters {
            name,
            face_id,
            uri,
            local_uri,
            origin,
            cost,
            flags,
            mask,
            expiration_period: exp,
            face_persistency: persistency,
            strategy,
            mtu,
            shm_control_token: token.map(Bytes::from),
            base_cong_interval: base_cong,
            def_cong_threshold: def_cong,
            capacity,
            count,
            fec_k,
            fec_n,
            fec_field,
            fec_role,
            rl_direction: rl_dir,
            rl_interest_pps: rl_pps,
            rl_interest_burst: rl_burst,
            rl_data_bps: rl_bps,
            rl_data_burst_bytes: rl_bytes,
            rl_overflow,
            rl_queue_max: rl_queue,
            partial_failures: pf,
        }
    })
}

proptest! {
    /// Every public decode entry point tolerates arbitrary bytes (up to
    /// ~64KiB) without panicking.
    #[test]
    fn decoders_never_panic_on_arbitrary_bytes(
        data in prop::collection::vec(any::<u8>(), 0..65536)
    ) {
        let raw = Bytes::from(data.clone());
        let _ = ControlParameters::decode(raw.clone());
        let _ = ControlParameters::decode_value(raw.clone());
        let _ = ControlParameters::decode_all(&data);
        let _ = ControlResponse::decode(raw.clone());
        let _ = ControlResponse::decode_value(raw.clone());
        let _ = GeneralStatus::decode(raw.clone());
        let _ = FaceStatus::decode_all(&data);
        let _ = FibEntry::decode_all(&data);
        let _ = RibEntry::decode_all(&data);
        let _ = StrategyChoice::decode_all(&data);
        let _ = PendingApproval::decode_all(&data);
        // parse_command_name takes a Name; feed it whatever names the fuzz
        // bytes happen to decode into.
        if let Ok(name) = Name::decode(raw) {
            let _ = parse_command_name(&name);
        }
    }

    /// ControlParameters encode → decode is the identity for arbitrary field
    /// values, both through the outer 0x68 wrapper and the bare value form.
    #[test]
    fn control_parameters_roundtrip(params in arb_control_parameters()) {
        let decoded = ControlParameters::decode(params.encode())
            .expect("encoder output must decode");
        prop_assert_eq!(&decoded, &params);

        let decoded_value = ControlParameters::decode_value(params.encode_value())
            .expect("encoder value output must decode");
        prop_assert_eq!(&decoded_value, &params);
    }

    /// ControlResponse (status code + text + optional ControlParameters body)
    /// encode → decode is the identity.
    #[test]
    fn control_response_roundtrip(
        status_code in any::<u64>(),
        status_text in ".*",
        body in prop::option::of(arb_control_parameters()),
    ) {
        let response = ControlResponse {
            status_code,
            status_text,
            body,
        };
        let decoded = ControlResponse::decode(response.encode())
            .expect("encoder output must decode");
        prop_assert_eq!(decoded, response);
    }
}
