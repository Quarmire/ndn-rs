//! Layer: spec — shared no_std NDN security core.
//!
//! The security analog of `ndn-fwd-core`: one definition of the
//! security-critical *primitives + wire ops* (Ed25519 sign/verify over a Data's
//! signed region, the signed-Data layout, SHA-256/HMAC to come), used
//! byte-identically by the native engine (`ndn-security`) and the constrained
//! forwarder (`ndn-embedded`) — instead of each re-deriving the signed-Data
//! wire. no_std, **no alloc** (slice-based), so it runs on the bare-metal floor.
//!
//! Out of scope here (and rightly so): key *storage* (PIB/TPM backends),
//! `TrustSchema` evaluation, and async cert fetch / NDNCERT — the heavy
//! machinery that stays in `ndn-security` or is offloaded to capable nodes.
//! What lives here is the part that must be identical on every platform.

#![no_std]
#![forbid(unsafe_code)]

use ndn_tlv::{read_varu64, write_varu64};

const TYPE_DATA: u64 = 0x06;
const TYPE_NAME: u64 = 0x07;
const TYPE_NAME_COMPONENT: u64 = 0x08;
const TYPE_CONTENT: u64 = 0x15;
const TYPE_SIGNATURE_INFO: u64 = 0x16;
const TYPE_SIGNATURE_VALUE: u64 = 0x17;
const TYPE_SIGNATURE_TYPE: u64 = 0x1b;
const TYPE_KEY_LOCATOR: u64 = 0x1c;
const SIG_TYPE_ED25519: u8 = 5;

/// Minimal slice TLV writer (no alloc).
struct W<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> W<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn bytes(&mut self, d: &[u8]) -> Option<()> {
        let end = self.pos.checked_add(d.len())?;
        self.buf.get_mut(self.pos..end)?.copy_from_slice(d);
        self.pos = end;
        Some(())
    }
    fn varu64(&mut self, v: u64) -> Option<()> {
        let mut tmp = [0u8; 9];
        let n = write_varu64(&mut tmp, v);
        self.bytes(&tmp[..n])
    }
    fn tlv(&mut self, typ: u64, val: &[u8]) -> Option<()> {
        self.varu64(typ)?;
        self.varu64(val.len() as u64)?;
        self.bytes(val)
    }
}

fn name_val(buf: &mut [u8], components: &[&[u8]]) -> Option<usize> {
    let mut w = W::new(buf);
    for c in components {
        w.tlv(TYPE_NAME_COMPONENT, c)?;
    }
    Some(w.pos)
}

/// Encode an **Ed25519-signed** Data into `out`: `Name + Content +
/// SignatureInfo(Ed25519, KeyLocator=key_name)`, with `SignatureValue` = the
/// 64-byte signature over the signed region (Name..SignatureInfo). Deterministic
/// signing — no entropy needed. Returns the encoded length.
pub fn sign_data_ed25519(
    out: &mut [u8],
    name_components: &[&[u8]],
    content: &[u8],
    signing_key: &[u8; 32],
    key_name: &[&[u8]],
) -> Option<usize> {
    use ed25519_dalek::{Signer, SigningKey};

    // Signed region: Name + Content + SignatureInfo.
    let mut region = [0u8; 512];
    let mut w = W::new(&mut region);

    let mut nbuf = [0u8; 256];
    let nlen = name_val(&mut nbuf, name_components)?;
    w.tlv(TYPE_NAME, &nbuf[..nlen])?;

    w.tlv(TYPE_CONTENT, content)?;

    // SignatureInfo = SignatureType(Ed25519) + KeyLocator{ Name(key_name) }.
    let mut klname = [0u8; 256];
    let klen = name_val(&mut klname, key_name)?;
    let mut kl = [0u8; 260];
    let mut klw = W::new(&mut kl);
    klw.tlv(TYPE_NAME, &klname[..klen])?;
    let kl_len = klw.pos;
    let mut si = [0u8; 300];
    let mut siw = W::new(&mut si);
    siw.tlv(TYPE_SIGNATURE_TYPE, &[SIG_TYPE_ED25519])?;
    siw.tlv(TYPE_KEY_LOCATOR, &kl[..kl_len])?;
    let si_len = siw.pos;
    w.tlv(TYPE_SIGNATURE_INFO, &si[..si_len])?;

    let region_len = w.pos;

    let sk = SigningKey::from_bytes(signing_key);
    let sig = sk.sign(&region[..region_len]);

    // DATA( signed-region + SignatureValue(0x17, 64-byte sig) ).
    let inner_len = region_len + 2 + 64;
    let mut o = W::new(out);
    o.varu64(TYPE_DATA)?;
    o.varu64(inner_len as u64)?;
    o.bytes(&region[..region_len])?;
    o.tlv(TYPE_SIGNATURE_VALUE, &sig.to_bytes())?;
    Some(o.pos)
}

/// Verify an Ed25519-signed Data `wire` against `public_key`. True iff the
/// SignatureValue verifies over the signed region (Name..SignatureInfo).
pub fn verify_data_ed25519(wire: &[u8], public_key: &[u8; 32]) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let Ok((typ, type_len)) = read_varu64(wire) else {
        return false;
    };
    if typ != TYPE_DATA {
        return false;
    }
    let Some(rest) = wire.get(type_len..) else {
        return false;
    };
    let Ok((inner_len, len_len)) = read_varu64(rest) else {
        return false;
    };
    let inner_start = type_len + len_len;
    let Some(inner) = wire.get(inner_start..inner_start + inner_len as usize) else {
        return false;
    };

    // The SignatureValue (0x17) terminates the signed region.
    let mut pos = 0;
    let mut signed_end = None;
    let mut sig_bytes: Option<&[u8]> = None;
    while pos < inner.len() {
        let Ok((t, tl)) = read_varu64(&inner[pos..]) else {
            return false;
        };
        let Ok((l, ll)) = read_varu64(&inner[pos + tl..]) else {
            return false;
        };
        let voff = pos + tl + ll;
        let Some(vend) = voff.checked_add(l as usize).filter(|&e| e <= inner.len()) else {
            return false;
        };
        if t == TYPE_SIGNATURE_VALUE {
            signed_end = Some(pos);
            sig_bytes = Some(&inner[voff..vend]);
            break;
        }
        pos = vend;
    }
    let (Some(signed_end), Some(sig_bytes)) = (signed_end, sig_bytes) else {
        return false;
    };
    if sig_bytes.len() != 64 {
        return false;
    }
    let Ok(vk) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    let mut arr = [0u8; 64];
    arr.copy_from_slice(sig_bytes);
    vk.verify(&inner[..signed_end], &Signature::from_bytes(&arr))
        .is_ok()
}

// Content confidentiality (the no_std baseline). Provability (signing) and
// confidentiality are orthogonal in NDN: sign the *encrypted* Data so caches
// still verify + forward without decrypting. Key distribution / access control
// (NAC, ABE) layer on top of this primitive.

use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, Tag};

/// Encrypt `buffer` in place with ChaCha20-Poly1305, returning the 16-byte
/// detached authentication tag. `aad` is authenticated but not encrypted (e.g.
/// the Data name). No allocation. `None` only on a bad key length.
pub fn seal_in_place(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    buffer: &mut [u8],
) -> Option<[u8; 16]> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).ok()?;
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(nonce), aad, buffer)
        .ok()?;
    let mut out = [0u8; 16];
    out.copy_from_slice(&tag);
    Some(out)
}

/// Decrypt `buffer` in place; returns `true` iff `tag` authenticates under
/// (`key`, `nonce`, `aad`). On failure the buffer contents are unspecified and
/// must be discarded.
pub fn open_in_place(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    buffer: &mut [u8],
    tag: &[u8; 16],
) -> bool {
    let Ok(cipher) = ChaCha20Poly1305::new_from_slice(key) else {
        return false;
    };
    cipher
        .decrypt_in_place_detached(Nonce::from_slice(nonce), aad, buffer, Tag::from_slice(tag))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use ed25519_dalek::SigningKey;
    use ndn_packet::Data;

    #[test]
    fn aead_round_trips_and_rejects_tampering() {
        let key = [3u8; 32];
        let nonce = [9u8; 12];
        let aad = b"/ndn/sensor/temp";
        let mut buf = *b"22.5C reading payload";
        let plain = buf;

        let tag = seal_in_place(&key, &nonce, aad, &mut buf).expect("seal");
        assert_ne!(buf, plain, "ciphertext differs from plaintext");

        // Correct key/nonce/aad/tag -> recovers plaintext.
        let mut ct = buf;
        assert!(open_in_place(&key, &nonce, aad, &mut ct, &tag));
        assert_eq!(ct, plain);

        // Tampered ciphertext -> rejected.
        let mut bad = buf;
        bad[0] ^= 0xFF;
        assert!(!open_in_place(&key, &nonce, aad, &mut bad, &tag));

        // Wrong key / wrong AAD -> rejected.
        let mut ct2 = buf;
        assert!(!open_in_place(&[4u8; 32], &nonce, aad, &mut ct2, &tag));
        let mut ct3 = buf;
        assert!(!open_in_place(&key, &nonce, b"/ndn/other", &mut ct3, &tag));
    }

    #[test]
    fn signed_data_verifies_decodes_and_rejects_tampering() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = sk.verifying_key().to_bytes();

        let mut out = [0u8; 512];
        let n = sign_data_ed25519(
            &mut out,
            &[b"ndn", b"sensor"],
            b"22C",
            &[7u8; 32],
            &[b"ndn", b"KEY", b"k1"],
        )
        .expect("sign");

        // Verifies under the right key…
        assert!(verify_data_ed25519(&out[..n], &pk));
        // …fails under a wrong key…
        let wrong = SigningKey::from_bytes(&[9u8; 32])
            .verifying_key()
            .to_bytes();
        assert!(!verify_data_ed25519(&out[..n], &wrong));
        // …and fails if the signed region is tampered.
        let mut bad = out;
        bad[12] ^= 0xFF;
        assert!(!verify_data_ed25519(&bad[..n], &pk));

        // It is a well-formed NDN Data (decodes via ndn-packet, Ed25519 sig).
        let data = Data::decode(Bytes::copy_from_slice(&out[..n])).expect("decode");
        assert_eq!(data.name.components().len(), 2);
    }
}
