//! Minimal HMAC-SHA256 (RFC 2104) implementation backed by the `sha2`
//! crate. Replaces `ring::hmac` so the crate compiles for
//! `wasm32-unknown-unknown` without dragging in `ring`'s C dependencies.
//!
//! Constant-time tag comparison is provided by [`verify`] using
//! `subtle::ConstantTimeEq` semantics implemented inline.

use sha2::{Digest, Sha256};

const BLOCK_SIZE: usize = 64;
const TAG_SIZE: usize = 32;

pub fn sign(key: &[u8], msg: &[u8]) -> [u8; TAG_SIZE] {
    let mut block_key = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let h = Sha256::digest(key);
        block_key[..TAG_SIZE].copy_from_slice(&h);
    } else {
        block_key[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0u8; BLOCK_SIZE];
    let mut opad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] = block_key[i] ^ 0x36;
        opad[i] = block_key[i] ^ 0x5c;
    }

    let inner = {
        let mut h = Sha256::new();
        h.update(ipad);
        h.update(msg);
        h.finalize()
    };

    let mut h = Sha256::new();
    h.update(opad);
    h.update(inner);
    h.finalize().into()
}

/// Constant-time comparison of an HMAC-SHA256 tag against the result of
/// signing `msg` with `key`. Returns `true` iff `tag` matches.
pub fn verify(key: &[u8], msg: &[u8], tag: &[u8]) -> bool {
    let expected = sign(key, msg);
    if tag.len() != expected.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..expected.len() {
        diff |= expected[i] ^ tag[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4231_test_case_1() {
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let want: [u8; 32] = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];
        assert_eq!(sign(&key, data), want);
    }

    #[test]
    fn verify_round_trip() {
        let key = b"secret";
        let msg = b"hello world";
        let tag = sign(key, msg);
        assert!(verify(key, msg, &tag));
        assert!(!verify(key, b"hello", &tag));
        assert!(!verify(key, msg, &tag[..31]));
    }
}
