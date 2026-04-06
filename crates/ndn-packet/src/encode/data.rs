use std::time::Duration;

use bytes::Bytes;
use ndn_tlv::TlvWriter;

use super::{write_name, write_nni};
use crate::{Name, SignatureType, tlv_type};

// ─── DataBuilder ─────────────────────────────────────────────────────────────

/// Configurable Data encoder with optional signing.
///
/// ```
/// # use ndn_packet::encode::DataBuilder;
/// # use std::time::Duration;
/// let wire = DataBuilder::new("/test", b"hello")
///     .freshness(Duration::from_secs(10))
///     .build();
/// ```
pub struct DataBuilder {
    name: Name,
    content: Vec<u8>,
    freshness: Option<Duration>,
}

impl DataBuilder {
    pub fn new(name: impl Into<Name>, content: &[u8]) -> Self {
        Self {
            name: name.into(),
            content: content.to_vec(),
            freshness: None,
        }
    }

    pub fn freshness(mut self, d: Duration) -> Self {
        self.freshness = Some(d);
        self
    }

    /// Build unsigned Data with a DigestSha256 placeholder signature.
    pub fn build(self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::DATA, |w| {
            write_name(w, &self.name);
            if let Some(freshness) = self.freshness {
                w.write_nested(tlv_type::META_INFO, |w| {
                    write_nni(w, tlv_type::FRESHNESS_PERIOD, freshness.as_millis() as u64);
                });
            }
            w.write_tlv(tlv_type::CONTENT, &self.content);
            w.write_nested(tlv_type::SIGNATURE_INFO, |w| {
                w.write_tlv(tlv_type::SIGNATURE_TYPE, &[0u8]);
            });
            w.write_tlv(tlv_type::SIGNATURE_VALUE, &[0u8; 32]);
        });
        w.finish()
    }

    /// Encode and sign the Data packet.
    ///
    /// `sig_type` and `key_locator` describe the signature algorithm and
    /// optional KeyLocator name (for SignatureInfo). `sign_fn` receives the
    /// signed region (Name + MetaInfo + Content + SignatureInfo) and returns
    /// the raw signature value bytes.
    pub async fn sign<F, Fut>(
        self,
        sig_type: SignatureType,
        key_locator: Option<&Name>,
        sign_fn: F,
    ) -> Bytes
    where
        F: FnOnce(&[u8]) -> Fut,
        Fut: std::future::Future<Output = Bytes>,
    {
        // Build Name + MetaInfo (if needed) + Content.
        let mut inner = TlvWriter::new();
        write_name(&mut inner, &self.name);
        if let Some(freshness) = self.freshness {
            inner.write_nested(tlv_type::META_INFO, |w| {
                write_nni(w, tlv_type::FRESHNESS_PERIOD, freshness.as_millis() as u64);
            });
        }
        inner.write_tlv(tlv_type::CONTENT, &self.content);
        let inner_bytes = inner.finish();

        // Build SignatureInfo.
        let mut sig_info_writer = TlvWriter::new();
        sig_info_writer.write_nested(tlv_type::SIGNATURE_INFO, |w| {
            write_nni(w, tlv_type::SIGNATURE_TYPE, sig_type.code());
            if let Some(kl_name) = key_locator {
                w.write_nested(tlv_type::KEY_LOCATOR, |w| {
                    write_name(w, kl_name);
                });
            }
        });
        let sig_info_bytes = sig_info_writer.finish();

        // Signed region = Name + MetaInfo + Content + SignatureInfo.
        let mut signed_region = Vec::with_capacity(inner_bytes.len() + sig_info_bytes.len());
        signed_region.extend_from_slice(&inner_bytes);
        signed_region.extend_from_slice(&sig_info_bytes);

        // Sign the region.
        let sig_value = sign_fn(&signed_region).await;

        // Assemble the full Data packet.
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::DATA, |w| {
            w.write_raw(&signed_region);
            w.write_tlv(tlv_type::SIGNATURE_VALUE, &sig_value);
        });
        w.finish()
    }

    /// Synchronous encode-and-sign using a single pre-sized buffer.
    ///
    /// Avoids the three intermediate allocations of the async `sign()` path.
    /// `sign_fn` receives the signed region (Name + MetaInfo + Content +
    /// SignatureInfo) and must return the raw signature bytes.
    pub fn sign_sync<F>(
        self,
        sig_type: SignatureType,
        key_locator: Option<&Name>,
        sign_fn: F,
    ) -> Bytes
    where
        F: FnOnce(&[u8]) -> Bytes,
    {
        // Estimate total size: name + metainfo + content + siginfo + sigvalue + outer TLV.
        // Over-estimate is fine — BytesMut won't reallocate.
        let est = self.content.len() + 256;
        let mut w = TlvWriter::with_capacity(est);

        // Build the signed region (Name + MetaInfo + Content + SignatureInfo)
        // into the writer, then snapshot it for signing.
        let signed_start = w.len();
        write_name(&mut w, &self.name);
        if let Some(freshness) = self.freshness {
            w.write_nested(tlv_type::META_INFO, |w| {
                write_nni(w, tlv_type::FRESHNESS_PERIOD, freshness.as_millis() as u64);
            });
        }
        w.write_tlv(tlv_type::CONTENT, &self.content);
        w.write_nested(tlv_type::SIGNATURE_INFO, |w| {
            write_nni(w, tlv_type::SIGNATURE_TYPE, sig_type.code());
            if let Some(kl_name) = key_locator {
                w.write_nested(tlv_type::KEY_LOCATOR, |w| {
                    write_name(w, kl_name);
                });
            }
        });
        let signed_region = w.snapshot(signed_start);

        // Sign the region.
        let sig_value = sign_fn(&signed_region);

        // Wrap everything in the outer Data TLV.
        let inner_len = signed_region.len()
            + ndn_tlv::varu64_size(tlv_type::SIGNATURE_VALUE)
            + ndn_tlv::varu64_size(sig_value.len() as u64)
            + sig_value.len();
        let mut outer = TlvWriter::with_capacity(inner_len + 10);
        outer.write_varu64(tlv_type::DATA);
        outer.write_varu64(inner_len as u64);
        outer.write_raw(&signed_region);
        outer.write_tlv(tlv_type::SIGNATURE_VALUE, &sig_value);
        outer.finish()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::super::tests::{assert_bytes_eq, hex, name};
    use super::*;
    use crate::Data;
    use bytes::Bytes;
    use std::time::Duration;

    #[test]
    fn data_builder_basic() {
        let wire = DataBuilder::new("/test", b"hello").build();
        let data = Data::decode(wire).unwrap();
        assert_eq!(data.name.to_string(), "/test");
        assert_eq!(data.content().map(|b| b.as_ref()), Some(b"hello".as_ref()));
    }

    #[test]
    fn data_builder_freshness() {
        let wire = DataBuilder::new("/test", b"x")
            .freshness(Duration::from_secs(60))
            .build();
        let data = Data::decode(wire).unwrap();
        let mi = data.meta_info().expect("meta_info present");
        assert_eq!(mi.freshness_period, Some(Duration::from_secs(60)));
    }

    #[test]
    fn data_builder_sign() {
        use std::pin::pin;
        use std::task::{Context, Wake, Waker};

        struct NoopWaker;
        impl Wake for NoopWaker {
            fn wake(self: std::sync::Arc<Self>) {}
        }
        let waker = Waker::from(std::sync::Arc::new(NoopWaker));
        let mut cx = Context::from_waker(&waker);

        let key_name: Name = "/key/test".parse().unwrap();
        let fut = DataBuilder::new("/signed/data", b"payload")
            .freshness(Duration::from_secs(10))
            .sign(
                SignatureType::SignatureEd25519,
                Some(&key_name),
                |region: &[u8]| {
                    let digest = ring::digest::digest(&ring::digest::SHA256, region);
                    std::future::ready(Bytes::copy_from_slice(digest.as_ref()))
                },
            );
        let mut fut = pin!(fut);
        let wire = match fut.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(b) => b,
            std::task::Poll::Pending => panic!("sign future should complete immediately"),
        };

        let data = Data::decode(wire).unwrap();
        assert_eq!(data.name.to_string(), "/signed/data");
        assert_eq!(
            data.content().map(|b| b.as_ref()),
            Some(b"payload".as_ref())
        );

        let si = data.sig_info().expect("sig info");
        assert_eq!(si.sig_type, SignatureType::SignatureEd25519);
        let kl = si.key_locator.clone().expect("key locator");
        assert_eq!(kl.to_string(), "/key/test");
    }

    #[test]
    fn data_builder_sign_sync_matches_async() {
        use std::pin::pin;
        use std::task::{Context, Wake, Waker};

        let key_name: Name = "/key/test".parse().unwrap();
        let sign_fn = |region: &[u8]| -> Bytes {
            let digest = ring::digest::digest(&ring::digest::SHA256, region);
            Bytes::copy_from_slice(digest.as_ref())
        };

        // Async path
        struct NoopWaker;
        impl Wake for NoopWaker {
            fn wake(self: std::sync::Arc<Self>) {}
        }
        let waker = Waker::from(std::sync::Arc::new(NoopWaker));
        let mut cx = Context::from_waker(&waker);

        let fut = DataBuilder::new("/signed/data", b"payload")
            .freshness(Duration::from_secs(10))
            .sign(
                SignatureType::SignatureEd25519,
                Some(&key_name),
                |region: &[u8]| {
                    let digest = ring::digest::digest(&ring::digest::SHA256, region);
                    std::future::ready(Bytes::copy_from_slice(digest.as_ref()))
                },
            );
        let mut fut = pin!(fut);
        let async_wire = match fut.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(b) => b,
            std::task::Poll::Pending => panic!("should complete immediately"),
        };

        // Sync path
        let sync_wire = DataBuilder::new("/signed/data", b"payload")
            .freshness(Duration::from_secs(10))
            .sign_sync(SignatureType::SignatureEd25519, Some(&key_name), sign_fn);

        assert_eq!(
            async_wire, sync_wire,
            "sign_sync must produce identical wire format"
        );
    }

    #[test]
    fn data_builder_sign_sync_no_freshness() {
        let wire = DataBuilder::new("/test", b"content").sign_sync(
            SignatureType::SignatureEd25519,
            None,
            |region| {
                let digest = ring::digest::digest(&ring::digest::SHA256, region);
                Bytes::copy_from_slice(digest.as_ref())
            },
        );
        let data = Data::decode(wire).unwrap();
        assert_eq!(data.name.to_string(), "/test");
        assert_eq!(
            data.content().map(|b| b.as_ref()),
            Some(b"content".as_ref())
        );
        assert!(data.meta_info().is_none());
        let si = data.sig_info().expect("sig info");
        assert_eq!(si.sig_type, SignatureType::SignatureEd25519);
    }

    // ── Wire-format tests ────────────────────────────────────────────────────

    #[test]
    fn wire_data_builder_no_freshness_omits_metainfo() {
        let wire = DataBuilder::new("/A", b"X").build();

        assert_eq!(wire[0], 0x06);

        // After Name (07 03 08 01 41), next should be Content (15), not MetaInfo (14).
        assert_eq!(
            wire[7], 0x15,
            "Content should follow Name directly (no MetaInfo)"
        );
    }

    #[test]
    fn wire_data_builder_freshness_nni() {
        // 10 seconds = 10000ms = 0x2710 → 2-byte NNI
        let wire = DataBuilder::new("/A", b"X")
            .freshness(Duration::from_secs(10))
            .build();

        // MetaInfo: 14 04 19 02 27 10
        let meta_pos = 7; // after Name
        assert_bytes_eq(
            &wire[meta_pos..meta_pos + 6],
            &[0x14, 0x04, 0x19, 0x02, 0x27, 0x10],
            "MetaInfo with FreshnessPeriod=10000ms",
        );
    }

    #[test]
    fn wire_ed25519_sig_type() {
        use std::pin::pin;
        use std::task::{Context, Wake, Waker};

        struct NoopWaker;
        impl Wake for NoopWaker {
            fn wake(self: std::sync::Arc<Self>) {}
        }
        let waker = Waker::from(std::sync::Arc::new(NoopWaker));
        let mut cx = Context::from_waker(&waker);

        let fut = DataBuilder::new("/A", b"X").sign(
            SignatureType::SignatureEd25519,
            None,
            |_: &[u8]| std::future::ready(Bytes::from_static(&[0xFF; 64])),
        );
        let mut fut = pin!(fut);
        let wire = match fut.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(b) => b,
            std::task::Poll::Pending => panic!("should complete immediately"),
        };

        // SignatureInfo should contain: 1B 01 05 (SignatureType=5, 1-byte NNI)
        let sig_info_content = [0x1B, 0x01, 0x05];
        assert!(
            wire.windows(3).any(|w| w == sig_info_content),
            "SignatureType=5 should be 1-byte NNI: 1B 01 05, got: {}",
            hex(&wire),
        );
    }
}
