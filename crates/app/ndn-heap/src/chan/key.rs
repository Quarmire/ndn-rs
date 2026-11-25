//! The channel key and the frame key derived from it (channel.md, key schedule).
//!
//! `K` is 32 random octets per sender, per space, per mode, per session
//! ([`ChannelKey::random`]), wrapped to each judged receiver in the session
//! and never derived from a space's epoch key. The AEAD never uses it
//! directly: a frame is sealed under `HKDF-SHA256(K, "ndn-channel/frame/1" ‖
//! channel id ‖ key epoch)` ([`ChannelKey::frame_key`]), so a re-key changes
//! the key a frame is sealed under even with the same channel id.
//!
//! Keys are zeroed when dropped and never appear in `Debug`.

use std::fmt;

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// The domain label of a frame key.
const FRAME_KEY: &[u8] = b"ndn-channel/frame/1";

/// The domain label of a channel key's id.
const KEY_ID: &[u8] = b"ndn-channel/id/1";

/// The octets of a channel key's id ([`ChannelKey::id`]).
pub const KEY_ID_LEN: usize = 8;

/// A channel's session key `K`.
#[derive(Clone)]
pub struct ChannelKey(Zeroizing<[u8; 32]>);

impl ZeroizeOnDrop for ChannelKey {}

impl ChannelKey {
    /// A fresh key from the operating system's randomness.
    pub fn random() -> Self {
        let mut key = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(&mut key[..]).expect("the operating system provides randomness");
        Self(key)
    }

    /// The key whose octets are `bytes` (a session's unwrapped key).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// The key's 32 octets, for wrapping to a receiver.
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    /// The key's id: the first 8 octets of HKDF-SHA256 with `K` as input key
    /// material, no salt and info `ndn-channel/id/1`. A session carries it so
    /// a receiver can match a key to a session.
    pub fn id(&self) -> [u8; KEY_ID_LEN] {
        let mut id = [0u8; KEY_ID_LEN];
        Hkdf::<Sha256>::new(None, &self.0[..])
            .expand(KEY_ID, &mut id)
            .expect("8 octets is a valid HKDF-SHA256 output length");
        id
    }

    /// The key frames of `channel` are sealed under at `key_epoch` (the count
    /// of re-keys, not only its low octet): HKDF-SHA256 with `K` as input key
    /// material, no salt and info `ndn-channel/frame/1` ‖ the channel id (8
    /// octets big-endian) ‖ `key_epoch` (4 octets big-endian).
    pub fn frame_key(&self, channel: u64, key_epoch: u32) -> FrameKey {
        let mut key = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(None, &self.0[..])
            .expand_multi_info(
                &[FRAME_KEY, &channel.to_be_bytes(), &key_epoch.to_be_bytes()],
                &mut key[..],
            )
            .expect("32 octets is a valid HKDF-SHA256 output length");
        FrameKey(key)
    }
}

impl fmt::Debug for ChannelKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChannelKey")
            .field("id", &self.id())
            .finish_non_exhaustive()
    }
}

/// The key one channel at one key epoch seals frames under.
#[derive(Clone)]
pub struct FrameKey(Zeroizing<[u8; 32]>);

impl ZeroizeOnDrop for FrameKey {}

impl FrameKey {
    /// The key's 32 octets (an AES-256-GCM or ChaCha20-Poly1305 key).
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for FrameKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FrameKey").finish_non_exhaustive()
    }
}
