use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use ndn_tlv::TlvWriter;

use super::{write_name, write_nni};
use crate::{Name, SignatureType, tlv_type};

// ─── Fast-path shared helpers ─────────────────────────────────────────────────

/// Encoded SignatureInfo TLV for DigestSha256 with no KeyLocator (5 bytes, fixed).
///
/// `0x16` type SignatureInfo | `0x03` length | `0x1B` type SignatureType | `0x01` length | `0x00` DigestSha256
///
/// # Limitations
/// This encoding is correct only when no KeyLocator is present.  DigestSha256
/// packets that carry a KeyLocator (rare, used for self-signed certificates) must
/// be built via `sign_sync` / `sign` instead.
const SIGINFO_DIGEST_SHA256: [u8; 5] = [0x16, 0x03, 0x1B, 0x01, 0x00];

/// Encoded SignatureInfo TLV for DigestBlake3 with no KeyLocator (5 bytes, fixed).
///
/// Identical layout to `SIGINFO_DIGEST_SHA256` but with type code 6 (experimental
/// BLAKE3 digest, not yet in the NDN Packet Format specification).
const SIGINFO_DIGEST_BLAKE3: [u8; 5] = [0x16, 0x03, 0x1B, 0x01, 0x06];

/// Write a VarNumber (u64) into `buf` using NDN's minimal-byte encoding.
#[inline(always)]
fn put_vu(buf: &mut BytesMut, v: u64) {
    let mut tmp = [0u8; 9];
    let n = ndn_tlv::write_varu64(&mut tmp, v);
    buf.put_slice(&tmp[..n]);
}

/// Pre-computed TLV sizes for Name, MetaInfo, and Content.
///
/// Created once and shared between the size-calculation and write phases of
/// the single-buffer fast paths (`sign_digest_sha256`, `sign_none`).
struct FastPathSizes {
    /// Total byte count of all encoded name components (value part of Name TLV).
    comps_inner:  usize,
    /// Full encoded size of the Name TLV (type + length + comps_inner).
    name_tlv:     usize,
    /// Total byte count of MetaInfo *value* bytes (0 when no freshness/FinalBlockId).
    mi_inner:     usize,
    /// Full encoded size of the MetaInfo TLV (0 when `mi_inner == 0`).
    metainfo_tlv: usize,
    /// Full encoded size of the Content TLV.
    content_tlv:  usize,
}

impl FastPathSizes {
    fn compute(name: &Name, freshness: Option<Duration>, final_block_id: Option<&Bytes>, content: &[u8]) -> Self {
        use ndn_tlv::varu64_size;

        let comps_inner: usize = name.components().iter()
            .map(|c| varu64_size(c.typ) + varu64_size(c.value.len() as u64) + c.value.len())
            .sum();
        let name_tlv = varu64_size(tlv_type::NAME) + varu64_size(comps_inner as u64) + comps_inner;

        let mi_inner = {
            let mut s = 0usize;
            if let Some(f) = freshness {
                let (_, nni_len) = super::nni(f.as_millis() as u64);
                s += varu64_size(tlv_type::FRESHNESS_PERIOD) + varu64_size(nni_len as u64) + nni_len;
            }
            if let Some(fb) = final_block_id {
                s += varu64_size(tlv_type::FINAL_BLOCK_ID) + varu64_size(fb.len() as u64) + fb.len();
            }
            s
        };
        let metainfo_tlv = if mi_inner > 0 {
            varu64_size(tlv_type::META_INFO) + varu64_size(mi_inner as u64) + mi_inner
        } else { 0 };

        let content_tlv = varu64_size(tlv_type::CONTENT)
            + varu64_size(content.len() as u64)
            + content.len();

        Self { comps_inner, name_tlv, mi_inner, metainfo_tlv, content_tlv }
    }
}

/// Write Name, MetaInfo (if any), and Content TLVs directly into `buf`.
///
/// Relies on pre-computed sizes from [`FastPathSizes`] to avoid a second pass.
/// Must be called with the same `freshness`/`final_block_id`/`content` used
/// to compute `sz`, otherwise the written bytes will not match the size headers.
fn write_fields(
    buf: &mut BytesMut,
    name: &Name,
    freshness: Option<Duration>,
    final_block_id: Option<&Bytes>,
    content: &[u8],
    sz: &FastPathSizes,
) {
    put_vu(buf, tlv_type::NAME);
    put_vu(buf, sz.comps_inner as u64);
    for comp in name.components() {
        put_vu(buf, comp.typ);
        put_vu(buf, comp.value.len() as u64);
        buf.put_slice(&comp.value);
    }
    if sz.mi_inner > 0 {
        put_vu(buf, tlv_type::META_INFO);
        put_vu(buf, sz.mi_inner as u64);
        if let Some(f) = freshness {
            let (nni_buf, nni_len) = super::nni(f.as_millis() as u64);
            put_vu(buf, tlv_type::FRESHNESS_PERIOD);
            put_vu(buf, nni_len as u64);
            buf.put_slice(&nni_buf[..nni_len]);
        }
        if let Some(fb) = final_block_id {
            put_vu(buf, tlv_type::FINAL_BLOCK_ID);
            put_vu(buf, fb.len() as u64);
            buf.put_slice(fb);
        }
    }
    put_vu(buf, tlv_type::CONTENT);
    put_vu(buf, content.len() as u64);
    buf.put_slice(content);
}

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
    /// Raw bytes of a NameComponent TLV to write as the FinalBlockId value.
    ///
    /// Use [`DataBuilder::final_block_id_seg`] to set this from a segment index.
    final_block_id: Option<Bytes>,
}

impl DataBuilder {
    pub fn new(name: impl Into<Name>, content: &[u8]) -> Self {
        Self {
            name: name.into(),
            content: content.to_vec(),
            freshness: None,
            final_block_id: None,
        }
    }

    pub fn freshness(mut self, d: Duration) -> Self {
        self.freshness = Some(d);
        self
    }

    /// Set the FinalBlockId from a raw NameComponent TLV value.
    pub fn final_block_id(mut self, component_bytes: Bytes) -> Self {
        self.final_block_id = Some(component_bytes);
        self
    }

    /// Encode the last segment index as a GenericNameComponent and set as FinalBlockId.
    ///
    /// This matches the ASCII-string segment encoding used by `ndn-put` and `ndn-peek`.
    ///
    /// ```
    /// # use ndn_packet::encode::DataBuilder;
    /// let wire = DataBuilder::new("/test/0", b"hello")
    ///     .final_block_id_seg(5)   // segments 0..=5
    ///     .build();
    /// ```
    pub fn final_block_id_seg(self, last_seg: usize) -> Self {
        let s = last_seg.to_string();
        let bytes = s.as_bytes();
        // GenericNameComponent: type=0x08, length, value
        let mut buf = Vec::with_capacity(2 + bytes.len());
        buf.push(0x08u8); // GenericNameComponent type
        // Length as minimal variable-length (segments fit in < 128 bytes of digits)
        buf.push(bytes.len() as u8);
        buf.extend_from_slice(bytes);
        self.final_block_id(Bytes::from(buf))
    }

    /// Encode the last segment index as a SegmentNameComponent (TLV type 0x32, big-endian
    /// non-negative integer encoding) and set as FinalBlockId.
    ///
    /// This matches the segment encoding used by `ndn-cxx`'s `ndnputchunks`.
    /// Use [`DataBuilder::final_block_id_seg`] for ASCII-decimal encoding instead.
    pub fn final_block_id_typed_seg(self, last_seg: u64) -> Self {
        let encoded = encode_nni_be(last_seg);
        let mut buf = Vec::with_capacity(2 + encoded.len());
        buf.push(0x32u8); // SegmentNameComponent TLV type
        buf.push(encoded.len() as u8);
        buf.extend_from_slice(&encoded);
        self.final_block_id(Bytes::from(buf))
    }

    /// Build and sign the Data with `DigestSha256`.
    ///
    /// Single-buffer fast path: pre-computes all TLV sizes, allocates one
    /// `BytesMut`, writes Name + MetaInfo + Content + SignatureInfo directly,
    /// then hashes in-place — **1 allocation, 0 copies of the signed region**.
    ///
    /// **~6× fewer allocations** than `sign_sync` with a lambda; use this for
    /// all high-throughput DigestSha256 production.
    ///
    /// # Limitations
    /// - Requires the `std` feature (transitively requires `ring`).
    ///   `no_std` callers must use `build()` + out-of-band signing.
    /// - The hardcoded `SignatureInfo` contains no KeyLocator.  DigestSha256
    ///   packets that carry a KeyLocator must be built via `sign_sync`/`sign`.
    /// - `debug_assert` guards validate the size pre-computation but are elided
    ///   in release builds.  The math is deterministic once the name/content
    ///   are fixed; no runtime variability can trigger them in correct code.
    #[cfg(feature = "std")]
    pub fn sign_digest_sha256(self) -> Bytes {
        use ndn_tlv::varu64_size;

        // SignatureValue: type(1) + len(1) + SHA-256(32) = 34 bytes
        const SIGVALUE: usize = 34;

        let sz = FastPathSizes::compute(
            &self.name, self.freshness, self.final_block_id.as_ref(), &self.content,
        );
        let signed_size = sz.name_tlv + sz.metainfo_tlv + sz.content_tlv + SIGINFO_DIGEST_SHA256.len();
        let inner_size  = signed_size + SIGVALUE;
        let header_size = varu64_size(tlv_type::DATA) + varu64_size(inner_size as u64);

        let mut buf = BytesMut::with_capacity(header_size + inner_size);
        put_vu(&mut buf, tlv_type::DATA);
        put_vu(&mut buf, inner_size as u64);

        let signed_start = buf.len();
        write_fields(&mut buf, &self.name, self.freshness, self.final_block_id.as_ref(), &self.content, &sz);
        buf.put_slice(&SIGINFO_DIGEST_SHA256);
        debug_assert_eq!(buf.len() - signed_start, signed_size, "signed region size mismatch");

        let hash = ring::digest::digest(&ring::digest::SHA256, &buf[signed_start..]);
        buf.put_slice(&[0x17u8, 0x20]);
        buf.put_slice(hash.as_ref());
        debug_assert_eq!(buf.len(), header_size + inner_size, "total size mismatch");

        buf.freeze()
    }

    /// Build a Data packet signed with a **BLAKE3 digest** (experimental).
    ///
    /// Single-buffer fast path with **1 allocation, 0 copies of the signed region**,
    /// identical structure to `sign_digest_sha256` but using BLAKE3.
    ///
    /// Produces the same 32-byte output as SHA-256, so encoded packet size is identical.
    ///
    /// # Performance characteristics
    /// BLAKE3 uses SIMD (NEON on ARM, AVX2/AVX-512 on x86) and tree parallelism for
    /// large inputs. However, for the small per-packet payloads typical of NDN iperf
    /// (< a few KB), tree parallelism never activates. On hardware with dedicated SHA
    /// accelerators — ARM crypto extensions (Apple Silicon, Cortex-A) or Intel SHA-NI —
    /// `ring`'s SHA-256 implementation uses single-cycle hardware instructions and will
    /// match or beat BLAKE3 at these payload sizes. BLAKE3's advantage over SHA-256
    /// is most visible on hardware without such extensions (older x86, RISC-V, embedded).
    ///
    /// # Note
    /// Uses signature type code 6 (`DigestBlake3`), which is an experimental
    /// NDA extension not yet in the NDN Packet Format specification.
    #[cfg(feature = "std")]
    pub fn sign_digest_blake3(self) -> Bytes {
        use ndn_tlv::varu64_size;

        // SignatureValue: type(1) + len(1) + BLAKE3(32) = 34 bytes — same as SHA-256.
        const SIGVALUE: usize = 34;

        let sz = FastPathSizes::compute(
            &self.name, self.freshness, self.final_block_id.as_ref(), &self.content,
        );
        let signed_size = sz.name_tlv + sz.metainfo_tlv + sz.content_tlv + SIGINFO_DIGEST_BLAKE3.len();
        let inner_size  = signed_size + SIGVALUE;
        let header_size = varu64_size(tlv_type::DATA) + varu64_size(inner_size as u64);

        let mut buf = BytesMut::with_capacity(header_size + inner_size);
        put_vu(&mut buf, tlv_type::DATA);
        put_vu(&mut buf, inner_size as u64);

        let signed_start = buf.len();
        write_fields(&mut buf, &self.name, self.freshness, self.final_block_id.as_ref(), &self.content, &sz);
        buf.put_slice(&SIGINFO_DIGEST_BLAKE3);
        debug_assert_eq!(buf.len() - signed_start, signed_size, "signed region size mismatch");

        let hash = blake3::hash(&buf[signed_start..]);
        buf.put_slice(&[0x17u8, 0x20]);
        buf.put_slice(hash.as_bytes());
        debug_assert_eq!(buf.len(), header_size + inner_size, "total size mismatch");

        buf.freeze()
    }

    /// Build a Data packet with **no** signature fields (no SignatureInfo, no SignatureValue).
    ///
    /// Single-buffer fast path with **1 allocation, 0 crypto overhead**.
    ///
    /// # ⚠ Non-conformant NDN
    /// All conformant NDN Data packets must carry a signature.  Packets produced
    /// by this method will be **rejected by validators** unless validation is
    /// explicitly bypassed (e.g., `FlowSignMode::None` in iperf for benchmarking).
    /// Do not use in production data planes.
    pub fn sign_none(self) -> Bytes {
        use ndn_tlv::varu64_size;

        let sz = FastPathSizes::compute(
            &self.name, self.freshness, self.final_block_id.as_ref(), &self.content,
        );
        let inner_size  = sz.name_tlv + sz.metainfo_tlv + sz.content_tlv;
        let header_size = varu64_size(tlv_type::DATA) + varu64_size(inner_size as u64);

        let mut buf = BytesMut::with_capacity(header_size + inner_size);
        put_vu(&mut buf, tlv_type::DATA);
        put_vu(&mut buf, inner_size as u64);
        write_fields(&mut buf, &self.name, self.freshness, self.final_block_id.as_ref(), &self.content, &sz);
        buf.freeze()
    }

    /// Build unsigned Data with a DigestSha256 placeholder signature.
    pub fn build(self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::DATA, |w| {
            write_name(w, &self.name);
            if self.freshness.is_some() || self.final_block_id.is_some() {
                let freshness = self.freshness;
                let fbi = self.final_block_id.as_deref();
                w.write_nested(tlv_type::META_INFO, |w| {
                    if let Some(f) = freshness {
                        write_nni(w, tlv_type::FRESHNESS_PERIOD, f.as_millis() as u64);
                    }
                    if let Some(fb) = fbi {
                        w.write_tlv(tlv_type::FINAL_BLOCK_ID, fb);
                    }
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
        if self.freshness.is_some() || self.final_block_id.is_some() {
            let freshness = self.freshness;
            let fbi = self.final_block_id.as_deref();
            inner.write_nested(tlv_type::META_INFO, |w| {
                if let Some(f) = freshness {
                    write_nni(w, tlv_type::FRESHNESS_PERIOD, f.as_millis() as u64);
                }
                if let Some(fb) = fbi {
                    w.write_tlv(tlv_type::FINAL_BLOCK_ID, fb);
                }
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
        if self.freshness.is_some() || self.final_block_id.is_some() {
            let freshness = self.freshness;
            let fbi = self.final_block_id.as_deref();
            w.write_nested(tlv_type::META_INFO, |w| {
                if let Some(f) = freshness {
                    write_nni(w, tlv_type::FRESHNESS_PERIOD, f.as_millis() as u64);
                }
                if let Some(fb) = fbi {
                    w.write_tlv(tlv_type::FINAL_BLOCK_ID, fb);
                }
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
        // Sign the region — zero-copy slice, no Vec allocation.
        let sig_value = sign_fn(w.slice_from(signed_start));

        // Wrap everything in the outer Data TLV.
        let signed_region = w.slice_from(signed_start);
        let inner_len = signed_region.len()
            + ndn_tlv::varu64_size(tlv_type::SIGNATURE_VALUE)
            + ndn_tlv::varu64_size(sig_value.len() as u64)
            + sig_value.len();
        let mut outer = TlvWriter::with_capacity(inner_len + 10);
        outer.write_varu64(tlv_type::DATA);
        outer.write_varu64(inner_len as u64);
        outer.write_raw(signed_region);
        outer.write_tlv(tlv_type::SIGNATURE_VALUE, &sig_value);
        outer.finish()
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Encode a non-negative integer as a minimal big-endian byte string (no leading zeros,
/// except that 0 encodes as a single 0x00 byte). Used for typed name components.
fn encode_nni_be(v: u64) -> Vec<u8> {
    if v == 0 {
        return vec![0x00];
    }
    let bytes = v.to_be_bytes();
    let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(7);
    bytes[first_nonzero..].to_vec()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::super::tests::{assert_bytes_eq, hex};
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
