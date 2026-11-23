//! The two digests of a packet.

use bytes::Bytes;
use ndn_packet::Data;
use sha2::{Digest, Sha256};

/// The implicit digest of a packet: SHA-256 over its whole wire encoding. It
/// names exact bytes, which is what a piece or a cut manifest (a DigestSha256
/// packet) is addressed by.
pub(crate) fn implicit_digest(wire: &[u8]) -> [u8; 32] {
    Sha256::digest(wire).into()
}

/// The digest of what the signer of `wire` signed: SHA-256 over its signed
/// region, the Name through the `SignatureInfo`, which excludes the signature
/// value.
///
/// Two packets with one signed digest are one signed object: they differ only
/// in the signature value, which an ECDSA signature leaves malleable (`S` and
/// `n - S` both verify; a signer that randomizes signs the same content to
/// another value each time) and which no one but the signer's key may be held
/// to. Ordering, parent and chain links, tie-breaks, cut tips and equivocation
/// are all decided by this digest, never by [`implicit_digest`].
///
/// A packet that does not decode as Data has no signed region and never
/// verifies, so no entry of a log is one; its digest is its implicit digest,
/// which no verified packet shares by accident.
pub(crate) fn signed_digest(wire: &Bytes) -> [u8; 32] {
    match Data::decode(wire.clone()) {
        Ok(data) => signed_digest_of(&data),
        Err(_) => implicit_digest(wire),
    }
}

/// [`signed_digest`] of a packet already decoded.
pub(crate) fn signed_digest_of(data: &Data) -> [u8; 32] {
    Sha256::digest(data.signed_region()).into()
}
