//! QR parameters every producer renders with (trust-envelope.md §5.6): one
//! error-correction level, byte mode, the smallest version that fits, and the
//! size limit that follows from them. Renderers call [`encode`]; size checks
//! use [`MAX_TEXT_LEN`] (or [`TrustEnvelope::qr_uri`](crate::TrustEnvelope::qr_uri),
//! which falls back to a by-reference anchor link when an inline one is too
//! large).

use qrcode::bits::Bits;
use qrcode::types::QrError;
pub use qrcode::{EcLevel, QrCode, Version};

/// The error-correction level every producer renders at: M (about 15 %
/// recoverable), sturdier than L for a code scanned off a screen or paper.
pub const EC_LEVEL: EcLevel = EcLevel::M;

/// The longest text one QR symbol holds at [`EC_LEVEL`] in byte mode: the
/// version-40 capacity (ISO/IEC 18004). [`encode`] succeeds exactly for texts
/// up to this length.
pub const MAX_TEXT_LEN: usize = 2331;

/// Encode `text` as one QR symbol in byte mode at [`EC_LEVEL`], in the smallest
/// version that holds it. Byte mode keeps the limit independent of the text's
/// content (no segment optimizer), so [`MAX_TEXT_LEN`] is exact.
pub fn encode(text: &str) -> Result<QrCode, QrError> {
    for version in 1..=40 {
        let mut bits = Bits::new(Version::Normal(version));
        if bits.push_byte_data(text.as_bytes()).is_ok() && bits.push_terminator(EC_LEVEL).is_ok() {
            return QrCode::with_bits(bits, EC_LEVEL);
        }
    }
    Err(QrError::DataTooLong)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ANCHOR_FINGERPRINT_LEN, TrustEnvelope};
    use bytes::Bytes;

    /// A URI-shaped text of exactly `len` bytes over the base64url alphabet.
    fn text_of_len(len: usize) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let prefix = "ndn-trust://recovery/";
        let mut s = String::with_capacity(len);
        s.push_str(prefix);
        let mut x: u32 = 0x9e37_79b9;
        while s.len() < len {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            s.push(ALPHABET[(x % 64) as usize] as char);
        }
        s
    }

    /// The renderer and the limit agree: a text fits exactly when it is at
    /// most `MAX_TEXT_LEN` bytes, and the largest one fills a version-40
    /// symbol at level M.
    #[test]
    fn limit_matches_the_renderer() {
        for len in [
            21,
            122,
            123,
            152,
            153,
            1000,
            2330,
            MAX_TEXT_LEN,
            MAX_TEXT_LEN + 1,
            2953,
        ] {
            let text = text_of_len(len);
            assert_eq!(
                encode(&text).is_ok(),
                len <= MAX_TEXT_LEN,
                "{len}-byte text"
            );
        }
        let largest = encode(&text_of_len(MAX_TEXT_LEN)).unwrap();
        assert_eq!(largest.version(), Version::Normal(40));
        assert_eq!(largest.error_correction_level(), EC_LEVEL);
        assert_eq!(EC_LEVEL, EcLevel::M);
    }

    /// The versions the spec's vectors state (§8.1: 125 characters, version
    /// 8 at M; §8.4: 230 characters, version 11).
    #[test]
    fn vector_versions() {
        let anchor = TrustEnvelope::Anchor {
            namespace: Some("/home/bob".into()),
            fingerprint: Some(core::array::from_fn(|i| i as u8)),
            version: Some(2),
            context_data: None,
            context_content: None,
        }
        .to_uri();
        assert_eq!(anchor.len(), 125);
        assert_eq!(encode(&anchor).unwrap().version(), Version::Normal(8));
        assert_eq!(
            encode(&text_of_len(230)).unwrap().version(),
            Version::Normal(11)
        );
    }

    /// An inline anchor too large for one symbol is shown by reference; one
    /// that fits is shown as is; a large envelope of another kind has no QR.
    #[test]
    fn qr_uri_falls_back_to_the_anchor_by_reference() {
        let fp = [7u8; ANCHOR_FINGERPRINT_LEN];
        let anchor = |context: usize| TrustEnvelope::Anchor {
            namespace: Some("/com/example/users/alice-smith".into()),
            fingerprint: Some(fp),
            version: Some(3),
            context_data: Some(Bytes::from(vec![0x06; context])),
            context_content: None,
        };
        let small = anchor(200);
        assert_eq!(small.qr_uri(), Some(small.to_uri()));

        let large = anchor(2000);
        assert!(large.to_uri().len() > MAX_TEXT_LEN);
        let shown = large.qr_uri().expect("a by-reference anchor fits");
        assert!(encode(&shown).is_ok());
        assert_eq!(
            TrustEnvelope::from_uri(&shown).unwrap(),
            TrustEnvelope::Anchor {
                namespace: Some("/com/example/users/alice-smith".into()),
                fingerprint: Some(fp),
                version: Some(3),
                context_data: None,
                context_content: None,
            }
        );

        let recovery = TrustEnvelope::Recovery {
            bundle: Bytes::from(vec![0; 2000]),
        };
        assert_eq!(recovery.qr_uri(), None);
    }
}
