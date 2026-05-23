//! Witness: an ABE ciphertext is a well-formed NDN-TLV container that survives
//! being carried as the Content of a signed Data packet, and the policy gate
//! holds end-to-end (satisfying attributes decrypt; non-satisfying fail) for
//! both CP-ABE (BSW) and MA-ABE (AW11).
//!
//! This is the integration half of the `ndn-abe` witness (the unit tests in the
//! crate cover the in-memory scheme round-trips). See
//! `testbed/tests/audit/abe01_cpabe_policy_gate.sh`.

use ndn_abe::{
    aw11_authgen, aw11_decrypt, aw11_encrypt, aw11_global_setup, aw11_keygen, bsw_keygen,
    bsw_setup, decrypt, encrypt, AbeCiphertext, AbeSchemeId, CIPHERTEXT_SCHEMA_VERSION,
};
use ndn_foundation_types::{Hash, Name, TlvDecode, TlvEncode};
use ndn_packet::{encode::encode_data_digest_sha256, Data};

/// Round-trip an `AbeCiphertext` through a signed Data packet and return the
/// container recovered from the decoded Data's Content.
fn through_signed_data(ct: &AbeCiphertext) -> AbeCiphertext {
    let content = ct.encode_to_bytes();
    let name: Name = "/example/abe/object/v=1".parse().unwrap();
    let wire = encode_data_digest_sha256(&name, &content);

    // The Data must decode as a structurally valid packet (it is DigestSha256
    // signed over the Name..SignatureInfo region).
    let data = Data::decode(wire).expect("ABE-carrying Data decodes");
    let recovered = data.content().expect("Data has Content").clone();
    AbeCiphertext::decode_from_bytes(recovered).expect("Content is a well-formed AbeCiphertext")
}

#[test]
fn cpabe_ciphertext_rides_signed_data_and_policy_gates() {
    let policy = ndn_abe::PolicyExpr::parse("dept:eng AND clearance:high").unwrap();
    let kgc_name: Name = "/example/kgc".parse().unwrap();
    let (mp, ms) = bsw_setup().unwrap();
    let hash = Hash::of(&mp.public_key_bytes);

    let plaintext = b"one-to-many payload under a policy";
    let ct = encrypt(&policy, plaintext, &(kgc_name, hash, mp.clone())).unwrap();

    // The container is a valid NDN-TLV and survives carriage in a signed Data.
    let recovered = through_signed_data(&ct);
    assert_eq!(recovered, ct);
    assert_eq!(recovered.scheme, AbeSchemeId::BSW);
    assert_eq!(recovered.schema_version, CIPHERTEXT_SCHEMA_VERSION);

    // Satisfying attributes decrypt the recovered container.
    let ok = bsw_keygen(&mp, &ms, &["dept:eng".into(), "clearance:high".into()]).unwrap();
    assert_eq!(decrypt(&recovered, &ok).unwrap(), plaintext);

    // Non-satisfying attributes do not.
    let no = bsw_keygen(&mp, &ms, &["dept:eng".into()]).unwrap();
    assert!(decrypt(&recovered, &no).is_err());
}

#[test]
fn maabe_ciphertext_rides_signed_data_and_policy_gates() {
    // Two authorities; the policy requires one attribute from each.
    let global = aw11_global_setup().unwrap();
    let (pk1, mk1) = aw11_authgen(&global, &["DEPT:ENG"]).unwrap();
    let (pk2, mk2) = aw11_authgen(&global, &["CLEARANCE:HIGH"]).unwrap();

    let policy = "\"DEPT:ENG\" and \"CLEARANCE:HIGH\"";
    let plaintext = b"multi-authority payload";
    let blob = aw11_encrypt(&global, &[&pk1, &pk2], policy, plaintext).unwrap();

    // Wrap the AW11 ciphertext in the same NDN-TLV container, scheme=LewkoWaters.
    let ct = AbeCiphertext {
        schema_version: CIPHERTEXT_SCHEMA_VERSION,
        scheme: AbeSchemeId::LewkoWaters,
        policy_source: "/auth-a/dept:eng AND /auth-b/clearance:high".into(),
        kgc_refs: vec![],
        rabe_ciphertext_bytes: blob,
    };

    let recovered = through_signed_data(&ct);
    assert_eq!(recovered, ct);
    assert_eq!(recovered.scheme, AbeSchemeId::LewkoWaters);

    // A user holding both grants decrypts.
    let ok = aw11_keygen(&global, &mk1, "alice", &["DEPT:ENG"]).unwrap();
    let ok = ndn_abe::aw11_add_attr(&global, &mk2, "CLEARANCE:HIGH", &ok).unwrap();
    assert_eq!(
        aw11_decrypt(&global, &ok, &recovered.rabe_ciphertext_bytes).unwrap(),
        plaintext
    );

    // A user missing one authority's grant does not.
    let no = aw11_keygen(&global, &mk1, "eve", &["DEPT:ENG"]).unwrap();
    assert!(aw11_decrypt(&global, &no, &recovered.rabe_ciphertext_bytes).is_err());
}
