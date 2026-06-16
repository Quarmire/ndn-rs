//! N.13 — `ndn_cert::ca::serialize_cert` must emit a parseable NDN Data
//! TLV. NDNCERT 0.3 carries issued certificates as real Data packets so
//! the requester can validate them via the same trust machinery used
//! for any other Data; a custom binary blob bypasses that.

use bytes::Bytes;
use ndn_cert::ca::{deserialize_cert, serialize_cert};
use ndn_packet::Data;
use ndn_security::SecurityManager;

#[test]
fn n13_serialize_cert_returns_parseable_data_tlv() {
    // Issue a real self-signed cert so it carries signed_region +
    // sig_value, then assert the serialize_cert output parses as Data.
    let mgr = SecurityManager::new();
    let key_name: ndn_packet::Name = "/test/alice/KEY/k1/self/v=1"
        .parse()
        .expect("test name must parse");
    mgr.generate_ed25519(key_name.clone()).unwrap();
    let signer = mgr.get_signer_sync(&key_name).unwrap();
    let pubkey = signer.public_key().unwrap();
    let cert = mgr
        .issue_self_signed(&key_name, pubkey, 365 * 24 * 3600 * 1_000)
        .unwrap();

    let wire = serialize_cert(&cert);
    let data = Data::decode(Bytes::from(wire.clone())).expect(
        "serialize_cert must emit a parseable NDN Data TLV \
         (NDNCERT 0.3 carries issued certs as Data packets)",
    );
    assert_eq!(*data.name, key_name);

    // Round-trip: deserialize_cert must accept the same bytes and
    // recover the cert structure.
    let recovered = deserialize_cert(&wire).expect("deserialize_cert must round-trip");
    assert_eq!(recovered.name, cert.name);
    assert_eq!(recovered.public_key, cert.public_key);
}
