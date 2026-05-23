//! 32-byte SHA-256 newtype.

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    #[cfg(feature = "std")]
    pub fn of(bytes: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Self(out)
    }

    pub const fn zero() -> Self {
        Self([0u8; 32])
    }

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for Hash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Hash(")?;
        for &b in self.0.iter().take(6) {
            write!(f, "{:02x}", b)?;
        }
        write!(f, ")")
    }
}

// Guards the `std` feature, which gates `Hash::of` and was previously a
// dead/non-compiling configuration (`alloc` was not in scope under `std`).
#[cfg(all(test, feature = "std"))]
mod tests {
    use super::Hash;

    #[test]
    fn of_matches_known_sha256() {
        // SHA-256("abc")
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(Hash::of(b"abc"), Hash::from_bytes(expected));
    }
}
