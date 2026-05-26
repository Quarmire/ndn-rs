//! Phase-2 witnesses for the engine/identity synthesis (`.claude/prompts/
//! trust-context-synthesis-implementation-2026-05-25.md` §Phase 2). Each test
//! backs one of the `testbed/tests/audit/tcs0{6..8}_*.sh` witness scripts.

use std::sync::Arc;

use bytes::Bytes;
use ndn_identity::trust_context::{SyncBundle, TrustContext};
use ndn_packet::{Name, SignatureType};
use ndn_security::{Certificate, TrustSchema};

fn name(s: &str) -> Name {
    s.parse().unwrap()
}

/// Mints a Certificate whose signed_region + sig_value round-trip through the
/// SyncBundle wire codec. The bytes are stub placeholders — chain verification
/// is out of scope for the wire-shape witness.
fn synth_signed_cert(cert_name: &str) -> Certificate {
    let n: Arc<Name> = Arc::new(cert_name.parse().unwrap());
    let mut signed_region = Vec::new();
    signed_region.extend_from_slice(&n.encode_to_tlv());
    signed_region.extend_from_slice(&[0x14, 0x00]);
    signed_region.extend_from_slice(&[0x15, 0x01, 0x00]);
    Certificate {
        name: n,
        public_key: Bytes::from_static(&[]),
        valid_from: 0,
        valid_until: u64::MAX,
        issuer: None,
        signed_region: Some(Bytes::from(signed_region)),
        sig_value: Some(Bytes::from_static(&[0xAA; 64])),
        sig_type: SignatureType::SignatureEd25519,
    }
}

/// tcs06 — a SyncBundle carrying an anchor add round-trips through the wire
/// codec. (Sibling-device propagation over SVS is wired in a follow-up; the
/// wire shape witnessed here is the payload SVS delivers.)
#[test]
fn tcs06_context_sync_anchor_propagation() {
    let anchor = synth_signed_cert("/home/bob/KEY/root");

    let mut tc = TrustContext::adopted(name("/home/bob"), std::time::SystemTime::now(), "tcs06");
    tc.anchors.push(anchor.clone());
    tc.ca_endpoints.push(name("/home/bob/_/ca"));

    let bundle_a = tc.export_for_sync();
    let wire = bundle_a.encode_wire();
    let bundle_b = SyncBundle::decode_wire(&wire).expect("decode ok");

    assert_eq!(bundle_b.context_name, bundle_a.context_name);
    assert_eq!(bundle_b.anchors.len(), 1, "anchor delta delivered");
    assert_eq!(bundle_b.anchors[0].name, anchor.name);
    assert_eq!(bundle_b.ca_endpoints, bundle_a.ca_endpoints);
}

/// tcs07 — confirm the base SyncBundle wire payload carries no
/// private-key material. Any Phase-4 wrapped-key TLV must ride its own type
/// code and remain opt-in per recipient.
#[test]
fn tcs07_context_sync_no_private_keys() {
    let bundle = SyncBundle {
        context_name: name("/home/bob"),
        anchors: vec![synth_signed_cert("/home/bob/KEY/root")],
        schema: TrustSchema::accept_all(),
        ca_endpoints: vec![name("/home/bob/_/ca")],
    };
    assert!(!bundle.carries_private_keys());

    let wire = bundle.encode_wire();
    let private_key_tlv = ndn_identity::trust_context::sync_tlv::TC_SYNC_WRAPPED_KEY_FOR_DEVICE;
    assert!(
        !contains_tlv_type(&wire, private_key_tlv),
        "wire must not carry TC_SYNC_WRAPPED_KEY_FOR_DEVICE in the base bundle"
    );
}

/// Helper: shallow scan checking whether the wire bytes contain a TLV header
/// for `target`. Adequate for the no-private-keys assertion since we only
/// care about presence/absence at the top level of the bundle.
fn contains_tlv_type(wire: &[u8], target: u64) -> bool {
    let mut i = 0;
    while i < wire.len() {
        let Ok((t, tn)) = ndn_tlv::read_varu64(&wire[i..]) else {
            return false;
        };
        let Ok((l, ln)) = ndn_tlv::read_varu64(&wire[i + tn..]) else {
            return false;
        };
        if t == target {
            return true;
        }
        let header = tn + ln;
        let l_us = l as usize;
        let total = match header.checked_add(l_us) {
            Some(x) => x,
            None => return false,
        };
        i += total;
    }
    false
}
