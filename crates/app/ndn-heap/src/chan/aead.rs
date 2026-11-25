//! The two AEADs a frame is sealed with, and the prepared key that seals and
//! opens with either.
//!
//! `S_AEAD` in a session is [`Aead::code`]: 1 AES-256-GCM, 2
//! ChaCha20-Poly1305. Both take a 32-octet key (the frame key), a 12-octet
//! nonce and give a 16-octet tag, and both come from `ring` where `ring`
//! builds. `ring` does not build for `wasm32-unknown-unknown`, so there the
//! same two AEADs come from RustCrypto (`aes-gcm`, `chacha20poly1305`): same
//! algorithm, same wire format, and a native test that holds the two to the
//! same octets. [`Aead::preferred`] picks AES-GCM when the CPU has AES and
//! carry-less multiply and ChaCha20-Poly1305 otherwise, which on wasm32 (no
//! such instructions) is always ChaCha20-Poly1305.
//!
//! Neither library zeroes its expanded key schedule when dropped; the
//! 32 octets of the [`FrameKey`] it came from are zeroed, and a
//! [`FrameCipher`] should live no longer than its session.

// Nothing outside the codec's tests calls this until the channel writer and
// receiver (stage 3, part 2) are wired; that change removes this attribute.
#![allow(dead_code)]

use super::key::FrameKey;
use super::limits::TAG_LEN;

/// Octets of an AEAD nonce.
pub(crate) const NONCE_LEN: usize = 12;

/// An AEAD a frame may be sealed with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Aead {
    /// AES-256-GCM (`S_AEAD` 1).
    Aes256Gcm,
    /// ChaCha20-Poly1305 (`S_AEAD` 2).
    ChaCha20Poly1305,
}

impl Aead {
    /// The `S_AEAD` code.
    pub(crate) const fn code(self) -> u8 {
        match self {
            Aead::Aes256Gcm => 1,
            Aead::ChaCha20Poly1305 => 2,
        }
    }

    /// The AEAD with `S_AEAD` `code`, if one is assigned.
    pub(crate) const fn from_code(code: u8) -> Option<Aead> {
        match code {
            1 => Some(Aead::Aes256Gcm),
            2 => Some(Aead::ChaCha20Poly1305),
            _ => None,
        }
    }

    /// The AEAD this machine seals fastest: AES-256-GCM when the CPU has AES
    /// and carry-less multiply (runtime detection on x86 and AArch64),
    /// ChaCha20-Poly1305 otherwise. A receiver opens either.
    pub(crate) fn preferred() -> Aead {
        if hardware_aes() {
            Aead::Aes256Gcm
        } else {
            Aead::ChaCha20Poly1305
        }
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
fn hardware_aes() -> bool {
    std::is_x86_feature_detected!("aes") && std::is_x86_feature_detected!("pclmulqdq")
}

#[cfg(target_arch = "aarch64")]
fn hardware_aes() -> bool {
    std::arch::is_aarch64_feature_detected!("aes")
        && std::arch::is_aarch64_feature_detected!("pmull")
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
fn hardware_aes() -> bool {
    false
}

/// An opening failed: the tag did not verify. The frame is dropped; nothing
/// of it is used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OpenFailed;

/// A frame key prepared for one AEAD, so a frame costs one seal or open and no
/// key schedule.
pub(crate) struct FrameCipher {
    aead: Aead,
    key: imp::Key,
}

impl FrameCipher {
    /// `key` prepared for `aead`.
    pub(crate) fn new(key: &FrameKey, aead: Aead) -> Self {
        Self {
            aead,
            key: imp::Key::new(key.expose(), aead),
        }
    }

    /// The AEAD this cipher seals and opens with.
    pub(crate) fn aead(&self) -> Aead {
        self.aead
    }

    /// Encrypts `buf` in place and returns the tag over `aad` and the
    /// ciphertext. `nonce` must never repeat under this key.
    pub(crate) fn seal_detached(
        &self,
        nonce: [u8; NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
    ) -> [u8; TAG_LEN] {
        self.key.seal(nonce, aad, buf)
    }

    /// Verifies the tag that ends `ciphertext_and_tag` over `aad` and decrypts
    /// in place: on success the plaintext is the first `len - 16` octets of
    /// the slice. On failure the slice's contents are unspecified.
    pub(crate) fn open_in_place(
        &self,
        nonce: [u8; NONCE_LEN],
        aad: &[u8],
        ciphertext_and_tag: &mut [u8],
    ) -> Result<(), OpenFailed> {
        if ciphertext_and_tag.len() < TAG_LEN {
            return Err(OpenFailed);
        }
        self.key.open(nonce, aad, ciphertext_and_tag)
    }
}

impl std::fmt::Debug for FrameCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrameCipher")
            .field("aead", &self.aead)
            .finish_non_exhaustive()
    }
}

#[cfg(not(target_arch = "wasm32"))]
use native as imp;
#[cfg(target_arch = "wasm32")]
use rustcrypto as imp;

/// `ring`: where it builds.
#[cfg(not(target_arch = "wasm32"))]
mod native {
    use ::ring::aead::{AES_256_GCM, Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};

    use super::{Aead, NONCE_LEN, OpenFailed, TAG_LEN};

    pub(super) struct Key(LessSafeKey);

    impl Key {
        pub(super) fn new(key: &[u8; 32], aead: Aead) -> Self {
            let algorithm = match aead {
                Aead::Aes256Gcm => &AES_256_GCM,
                Aead::ChaCha20Poly1305 => &CHACHA20_POLY1305,
            };
            Key(LessSafeKey::new(
                UnboundKey::new(algorithm, key).expect("both algorithms take a 32-octet key"),
            ))
        }

        pub(super) fn seal(
            &self,
            nonce: [u8; NONCE_LEN],
            aad: &[u8],
            buf: &mut [u8],
        ) -> [u8; TAG_LEN] {
            let tag = self
                .0
                .seal_in_place_separate_tag(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::from(aad),
                    buf,
                )
                .expect("a frame is at most 16 MiB, far below the AEADs' limits");
            tag.as_ref().try_into().expect("a tag is 16 octets")
        }

        pub(super) fn open(
            &self,
            nonce: [u8; NONCE_LEN],
            aad: &[u8],
            ciphertext_and_tag: &mut [u8],
        ) -> Result<(), OpenFailed> {
            self.0
                .open_in_place(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::from(aad),
                    ciphertext_and_tag,
                )
                .map(|_| ())
                .map_err(|_| OpenFailed)
        }
    }
}

/// RustCrypto: where `ring` does not build (wasm32), and in native tests, to
/// hold it to `ring`'s octets.
#[cfg(any(target_arch = "wasm32", test))]
mod rustcrypto {
    use aes_gcm::Aes256Gcm;
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::aead::{AeadInPlace, KeyInit};
    use chacha20poly1305::ChaCha20Poly1305;

    use super::{Aead, NONCE_LEN, OpenFailed, TAG_LEN};

    pub(super) enum Key {
        Aes(Box<Aes256Gcm>),
        ChaCha(Box<ChaCha20Poly1305>),
    }

    impl Key {
        pub(super) fn new(key: &[u8; 32], aead: Aead) -> Self {
            let key = GenericArray::from_slice(key);
            match aead {
                Aead::Aes256Gcm => Key::Aes(Box::new(Aes256Gcm::new(key))),
                Aead::ChaCha20Poly1305 => Key::ChaCha(Box::new(ChaCha20Poly1305::new(key))),
            }
        }

        pub(super) fn seal(
            &self,
            nonce: [u8; NONCE_LEN],
            aad: &[u8],
            buf: &mut [u8],
        ) -> [u8; TAG_LEN] {
            let nonce = GenericArray::from_slice(&nonce);
            let tag = match self {
                Key::Aes(k) => k.encrypt_in_place_detached(nonce, aad, buf),
                Key::ChaCha(k) => k.encrypt_in_place_detached(nonce, aad, buf),
            }
            .expect("a frame is at most 16 MiB, far below the AEADs' limits");
            tag.into()
        }

        pub(super) fn open(
            &self,
            nonce: [u8; NONCE_LEN],
            aad: &[u8],
            ciphertext_and_tag: &mut [u8],
        ) -> Result<(), OpenFailed> {
            let nonce = GenericArray::from_slice(&nonce);
            let (body, tag) = ciphertext_and_tag.split_at_mut(ciphertext_and_tag.len() - TAG_LEN);
            let tag = GenericArray::from_slice(tag);
            match self {
                Key::Aes(k) => k.decrypt_in_place_detached(nonce, aad, body, tag),
                Key::ChaCha(k) => k.decrypt_in_place_detached(nonce, aad, body, tag),
            }
            .map_err(|_| OpenFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chan::key::ChannelKey;

    const BOTH: [Aead; 2] = [Aead::Aes256Gcm, Aead::ChaCha20Poly1305];

    fn frame_key() -> FrameKey {
        ChannelKey::from_bytes([7; 32]).frame_key(1, 0)
    }

    #[test]
    fn the_codes_are_the_s_aead_values_and_nothing_else_is_assigned() {
        assert_eq!(Aead::Aes256Gcm.code(), 1);
        assert_eq!(Aead::ChaCha20Poly1305.code(), 2);
        for code in 0..=255u8 {
            match Aead::from_code(code) {
                Some(a) => assert_eq!(a.code(), code),
                None => assert!(code != 1 && code != 2),
            }
        }
        assert!(BOTH.contains(&Aead::preferred()));
    }

    /// `ring` and RustCrypto produce the same ciphertext and tag and open each
    /// other's: the wasm32 seal is the same wire as the native one.
    #[test]
    fn ring_and_rustcrypto_produce_the_same_octets_for_both_aeads() {
        let key = frame_key();
        for aead in BOTH {
            let ring = FrameCipher::new(&key, aead);
            let rc = rustcrypto::Key::new(key.expose(), aead);
            for len in [0usize, 1, 15, 16, 17, 64, 1_200, 9_000] {
                let plain: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
                let nonce = [3, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8];
                let aad = b"twenty octets of aad";
                let mut a = plain.clone();
                let tag_a = ring.seal_detached(nonce, aad, &mut a);
                let mut b = plain.clone();
                let tag_b = rc.seal(nonce, aad, &mut b);
                assert_eq!((a.clone(), tag_a), (b, tag_b), "{aead:?} {len}");

                let mut wire = a;
                wire.extend_from_slice(&tag_a);
                let mut other = wire.clone();
                rc.open(nonce, aad, &mut other).unwrap();
                assert_eq!(other[..len], plain[..]);
                ring.open_in_place(nonce, aad, &mut wire).unwrap();
                assert_eq!(wire[..len], plain[..]);
            }
        }
    }

    #[test]
    fn a_wrong_key_nonce_aad_tag_or_ciphertext_does_not_open() {
        let key = frame_key();
        let other = ChannelKey::from_bytes([8; 32]).frame_key(1, 0);
        for aead in BOTH {
            let cipher = FrameCipher::new(&key, aead);
            let nonce = [0u8; NONCE_LEN];
            let mut wire = b"payload octets".to_vec();
            let tag = cipher.seal_detached(nonce, b"aad", &mut wire);
            wire.extend_from_slice(&tag);

            let mut ok = wire.clone();
            assert_eq!(cipher.open_in_place(nonce, b"aad", &mut ok), Ok(()));
            let mut bad = wire.clone();
            assert_eq!(
                FrameCipher::new(&other, aead).open_in_place(nonce, b"aad", &mut bad),
                Err(OpenFailed)
            );
            let mut bad = wire.clone();
            let mut n2 = nonce;
            n2[11] = 1;
            assert_eq!(cipher.open_in_place(n2, b"aad", &mut bad), Err(OpenFailed));
            let mut bad = wire.clone();
            assert_eq!(
                cipher.open_in_place(nonce, b"aae", &mut bad),
                Err(OpenFailed)
            );
            for i in 0..wire.len() {
                let mut bad = wire.clone();
                bad[i] ^= 1;
                assert_eq!(
                    cipher.open_in_place(nonce, b"aad", &mut bad),
                    Err(OpenFailed)
                );
            }
            let mut short = [0u8; TAG_LEN - 1];
            assert_eq!(
                cipher.open_in_place(nonce, b"aad", &mut short),
                Err(OpenFailed)
            );
        }
    }
}
