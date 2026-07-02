use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use ndn_tlv::TlvWriter;
use sha2::Digest;

use super::{write_name, write_nni};
use crate::{Name, SignatureType, tlv_type};

const SIGINFO_DIGEST_SHA256: [u8; 5] = [0x16, 0x03, 0x1B, 0x01, 0x00];

/// DigestBlake3 (type code 6) per the NDN TLV SignatureType registry.
const SIGINFO_DIGEST_BLAKE3: [u8; 5] = [0x16, 0x03, 0x1B, 0x01, 0x06];

#[inline(always)]
fn put_vu<B: BufMut>(buf: &mut B, v: u64) {
    let mut tmp = [0u8; 9];
    let n = ndn_tlv::write_varu64(&mut tmp, v);
    buf.put_slice(&tmp[..n]);
}

/// Pre-computed TLV sizes shared between the size-calculation and write
/// phases of the single-buffer fast paths.
struct FastPathSizes {
    comps_inner: usize,
    name_tlv: usize,
    mi_inner: usize,
    metainfo_tlv: usize,
    content_tlv: usize,
}

impl FastPathSizes {
    fn compute(
        name: &Name,
        freshness: Option<Duration>,
        final_block_id: Option<&Bytes>,
        content_type: Option<u64>,
        content: &[u8],
    ) -> Self {
        use ndn_tlv::varu64_size;

        let comps_inner: usize = name
            .components()
            .iter()
            .map(|c| varu64_size(c.typ) + varu64_size(c.value.len() as u64) + c.value.len())
            .sum();
        let name_tlv = varu64_size(tlv_type::NAME) + varu64_size(comps_inner as u64) + comps_inner;

        let mi_inner = {
            let mut s = 0usize;
            // ContentType is the first MetaInfo field (§6.2).
            if let Some(ct) = content_type {
                let (_, nni_len) = super::nni(ct);
                s += varu64_size(tlv_type::CONTENT_TYPE) + varu64_size(nni_len as u64) + nni_len;
            }
            if let Some(f) = freshness {
                let (_, nni_len) = super::nni(f.as_millis() as u64);
                s +=
                    varu64_size(tlv_type::FRESHNESS_PERIOD) + varu64_size(nni_len as u64) + nni_len;
            }
            if let Some(fb) = final_block_id {
                s +=
                    varu64_size(tlv_type::FINAL_BLOCK_ID) + varu64_size(fb.len() as u64) + fb.len();
            }
            s
        };
        let metainfo_tlv = if mi_inner > 0 {
            varu64_size(tlv_type::META_INFO) + varu64_size(mi_inner as u64) + mi_inner
        } else {
            0
        };

        let content_tlv =
            varu64_size(tlv_type::CONTENT) + varu64_size(content.len() as u64) + content.len();

        Self {
            comps_inner,
            name_tlv,
            mi_inner,
            metainfo_tlv,
            content_tlv,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn write_fields<B: BufMut>(
    buf: &mut B,
    name: &Name,
    freshness: Option<Duration>,
    final_block_id: Option<&Bytes>,
    content_type: Option<u64>,
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
        if let Some(ct) = content_type {
            let (nni_buf, nni_len) = super::nni(ct);
            put_vu(buf, tlv_type::CONTENT_TYPE);
            put_vu(buf, nni_len as u64);
            buf.put_slice(&nni_buf[..nni_len]);
        }
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
    final_block_id: Option<Bytes>,
    /// MetaInfo ContentType code; `None` omits the field (= Blob default).
    content_type: Option<u64>,
}

impl DataBuilder {
    pub fn new(name: impl Into<Name>, content: &[u8]) -> Self {
        Self {
            name: name.into(),
            content: content.to_vec(),
            freshness: None,
            final_block_id: None,
            content_type: None,
        }
    }

    pub fn freshness(mut self, d: Duration) -> Self {
        self.freshness = Some(d);
        self
    }

    /// Set the MetaInfo `ContentType` (NDN Packet Format §6.2.1). Emitted
    /// as the first MetaInfo field. Use e.g. `ContentType::Other(6)` to
    /// mark a packet that *encapsulates* another Data (the ndn-svs
    /// SVS-PS convention); the default (unset) is the Blob content type,
    /// which is omitted from the wire.
    pub fn content_type(mut self, ct: crate::meta_info::ContentType) -> Self {
        self.content_type = Some(ct.code());
        self
    }

    pub fn final_block_id(mut self, component_bytes: Bytes) -> Self {
        self.final_block_id = Some(component_bytes);
        self
    }

    /// ASCII-string segment encoding, matching `ndn-put` / `ndn-peek`.
    pub fn final_block_id_seg(self, last_seg: usize) -> Self {
        let s = last_seg.to_string();
        let bytes = s.as_bytes();
        let mut buf = Vec::with_capacity(2 + bytes.len());
        buf.push(0x08u8);
        buf.push(bytes.len() as u8);
        buf.extend_from_slice(bytes);
        self.final_block_id(Bytes::from(buf))
    }

    /// SegmentNameComponent (type 0x32) encoding, matching `ndn-cxx` `ndnputchunks`.
    pub fn final_block_id_typed_seg(self, last_seg: u64) -> Self {
        let encoded = encode_nni_be(last_seg);
        let mut buf = Vec::with_capacity(2 + encoded.len());
        buf.push(0x32u8);
        buf.push(encoded.len() as u8);
        buf.extend_from_slice(&encoded);
        self.final_block_id(Bytes::from(buf))
    }

    /// Single-buffer fast path: 1 allocation, 0 copies of the signed region.
    #[cfg(feature = "std")]
    pub fn sign_digest_sha256(self) -> Bytes {
        use ndn_tlv::varu64_size;

        const SIGVALUE: usize = 34;

        let sz = FastPathSizes::compute(
            &self.name,
            self.freshness,
            self.final_block_id.as_ref(),
            self.content_type,
            &self.content,
        );
        let signed_size =
            sz.name_tlv + sz.metainfo_tlv + sz.content_tlv + SIGINFO_DIGEST_SHA256.len();
        let inner_size = signed_size + SIGVALUE;
        let header_size = varu64_size(tlv_type::DATA) + varu64_size(inner_size as u64);

        let mut buf = BytesMut::with_capacity(header_size + inner_size);
        put_vu(&mut buf, tlv_type::DATA);
        put_vu(&mut buf, inner_size as u64);

        let signed_start = buf.len();
        write_fields(
            &mut buf,
            &self.name,
            self.freshness,
            self.final_block_id.as_ref(),
            self.content_type,
            &self.content,
            &sz,
        );
        buf.put_slice(&SIGINFO_DIGEST_SHA256);
        debug_assert_eq!(
            buf.len() - signed_start,
            signed_size,
            "signed region size mismatch"
        );

        let hash = sha2::Sha256::digest(&buf[signed_start..]);
        buf.put_slice(&[0x17u8, 0x20]);
        buf.put_slice(hash.as_ref());
        debug_assert_eq!(buf.len(), header_size + inner_size, "total size mismatch");

        buf.freeze()
    }

    /// Exact wire size of the `DigestSha256` Data this builder would produce, so
    /// a caller can reserve an exact buffer (e.g. an SHM ring slot) and encode
    /// into it with **zero allocations** via [`encode_digest_sha256_into`].
    ///
    /// [`encode_digest_sha256_into`]: Self::encode_digest_sha256_into
    #[cfg(feature = "std")]
    pub fn encoded_len_digest_sha256(&self) -> usize {
        use ndn_tlv::varu64_size;
        const SIGVALUE: usize = 34;
        let sz = FastPathSizes::compute(
            &self.name,
            self.freshness,
            self.final_block_id.as_ref(),
            self.content_type,
            &self.content,
        );
        let inner_size =
            sz.name_tlv + sz.metainfo_tlv + sz.content_tlv + SIGINFO_DIGEST_SHA256.len() + SIGVALUE;
        varu64_size(tlv_type::DATA) + varu64_size(inner_size as u64) + inner_size
    }

    /// Encode the `DigestSha256` Data **directly into `out`** with zero
    /// allocations (the producer floor — e.g. encode straight into an SHM ring
    /// slot via `SpscFace::send_with`). Returns the number of bytes written.
    /// `out` must be at least [`encoded_len_digest_sha256`] bytes. Byte-identical
    /// to [`sign_digest_sha256`]/[`build`].
    ///
    /// [`encoded_len_digest_sha256`]: Self::encoded_len_digest_sha256
    /// [`sign_digest_sha256`]: Self::sign_digest_sha256
    /// [`build`]: Self::build
    #[cfg(feature = "std")]
    pub fn encode_digest_sha256_into(self, out: &mut [u8]) -> usize {
        use ndn_tlv::varu64_size;
        const SIGVALUE: usize = 34;

        let sz = FastPathSizes::compute(
            &self.name,
            self.freshness,
            self.final_block_id.as_ref(),
            self.content_type,
            &self.content,
        );
        let signed_size =
            sz.name_tlv + sz.metainfo_tlv + sz.content_tlv + SIGINFO_DIGEST_SHA256.len();
        let inner_size = signed_size + SIGVALUE;
        let header_size = varu64_size(tlv_type::DATA) + varu64_size(inner_size as u64);
        let total = header_size + inner_size;
        assert!(
            out.len() >= total,
            "encode_digest_sha256_into: buffer too small ({} < {total})",
            out.len(),
        );

        // `&mut [u8]` is a `BufMut` cursor — same writes as the single-buffer
        // path, straight into the caller's slot (no BytesMut allocation).
        {
            let mut cur: &mut [u8] = &mut out[..total];
            put_vu(&mut cur, tlv_type::DATA);
            put_vu(&mut cur, inner_size as u64);
            write_fields(
                &mut cur,
                &self.name,
                self.freshness,
                self.final_block_id.as_ref(),
                self.content_type,
                &self.content,
                &sz,
            );
            cur.put_slice(&SIGINFO_DIGEST_SHA256);
        }

        // SignatureValue = SHA-256 over the signed region, written in place.
        let signed_start = header_size;
        let signed_end = header_size + signed_size;
        let hash = sha2::Sha256::digest(&out[signed_start..signed_end]);
        out[signed_end] = 0x17;
        out[signed_end + 1] = 0x20;
        out[signed_end + 2..signed_end + 34].copy_from_slice(hash.as_ref());
        total
    }

    /// Single-buffer fast path using BLAKE3 (`DigestBlake3`, type code 6).
    #[cfg(feature = "std")]
    pub fn sign_digest_blake3(self) -> Bytes {
        use ndn_tlv::varu64_size;

        // SignatureValue = type(1) + len(1) + BLAKE3(32) = 34 bytes.
        const SIGVALUE: usize = 34;

        let sz = FastPathSizes::compute(
            &self.name,
            self.freshness,
            self.final_block_id.as_ref(),
            self.content_type,
            &self.content,
        );
        let signed_size =
            sz.name_tlv + sz.metainfo_tlv + sz.content_tlv + SIGINFO_DIGEST_BLAKE3.len();
        let inner_size = signed_size + SIGVALUE;
        let header_size = varu64_size(tlv_type::DATA) + varu64_size(inner_size as u64);

        let mut buf = BytesMut::with_capacity(header_size + inner_size);
        put_vu(&mut buf, tlv_type::DATA);
        put_vu(&mut buf, inner_size as u64);

        let signed_start = buf.len();
        write_fields(
            &mut buf,
            &self.name,
            self.freshness,
            self.final_block_id.as_ref(),
            self.content_type,
            &self.content,
            &sz,
        );
        buf.put_slice(&SIGINFO_DIGEST_BLAKE3);
        debug_assert_eq!(
            buf.len() - signed_start,
            signed_size,
            "signed region size mismatch"
        );

        let hash = blake3::hash(&buf[signed_start..]);
        buf.put_slice(&[0x17u8, 0x20]);
        buf.put_slice(hash.as_bytes());
        debug_assert_eq!(buf.len(), header_size + inner_size, "total size mismatch");

        buf.freeze()
    }

    /// Non-conformant: omits signature fields entirely. Only for benchmarking.
    pub fn sign_none(self) -> Bytes {
        use ndn_tlv::varu64_size;

        let sz = FastPathSizes::compute(
            &self.name,
            self.freshness,
            self.final_block_id.as_ref(),
            self.content_type,
            &self.content,
        );
        let inner_size = sz.name_tlv + sz.metainfo_tlv + sz.content_tlv;
        let header_size = varu64_size(tlv_type::DATA) + varu64_size(inner_size as u64);

        let mut buf = BytesMut::with_capacity(header_size + inner_size);
        put_vu(&mut buf, tlv_type::DATA);
        put_vu(&mut buf, inner_size as u64);
        write_fields(
            &mut buf,
            &self.name,
            self.freshness,
            self.final_block_id.as_ref(),
            self.content_type,
            &self.content,
            &sz,
        );
        buf.freeze()
    }

    /// Build a self-signed Data with `SignatureType=DigestSha256`;
    /// `SignatureValue` is `SHA-256(signed region)` per NDN Packet Format §6.3.2.
    #[cfg(feature = "std")]
    pub fn build(self) -> Bytes {
        self.sign_digest_sha256()
    }

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
        let mut inner = TlvWriter::new();
        write_name(&mut inner, &self.name);
        if self.content_type.is_some() || self.freshness.is_some() || self.final_block_id.is_some()
        {
            let content_type = self.content_type;
            let freshness = self.freshness;
            let fbi = self.final_block_id.as_deref();
            inner.write_nested(tlv_type::META_INFO, |w| {
                if let Some(ct) = content_type {
                    write_nni(w, tlv_type::CONTENT_TYPE, ct);
                }
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

        let mut signed_region = Vec::with_capacity(inner_bytes.len() + sig_info_bytes.len());
        signed_region.extend_from_slice(&inner_bytes);
        signed_region.extend_from_slice(&sig_info_bytes);

        let sig_value = sign_fn(&signed_region).await;

        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::DATA, |w| {
            w.write_raw(&signed_region);
            w.write_tlv(tlv_type::SIGNATURE_VALUE, &sig_value);
        });
        w.finish()
    }

    /// Like [`Self::sign`] but the signing callback is fallible — for a
    /// remote/enclave/delegated signer whose async round-trip can fail. The
    /// wire is byte-identical to [`Self::sign`] on success.
    pub async fn sign_fallible<F, Fut, E>(
        self,
        sig_type: SignatureType,
        key_locator: Option<&Name>,
        sign_fn: F,
    ) -> Result<Bytes, E>
    where
        F: FnOnce(&[u8]) -> Fut,
        Fut: std::future::Future<Output = Result<Bytes, E>>,
    {
        let mut inner = TlvWriter::new();
        write_name(&mut inner, &self.name);
        if self.content_type.is_some() || self.freshness.is_some() || self.final_block_id.is_some()
        {
            let content_type = self.content_type;
            let freshness = self.freshness;
            let fbi = self.final_block_id.as_deref();
            inner.write_nested(tlv_type::META_INFO, |w| {
                if let Some(ct) = content_type {
                    write_nni(w, tlv_type::CONTENT_TYPE, ct);
                }
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

        let mut signed_region = Vec::with_capacity(inner_bytes.len() + sig_info_bytes.len());
        signed_region.extend_from_slice(&inner_bytes);
        signed_region.extend_from_slice(&sig_info_bytes);

        let sig_value = sign_fn(&signed_region).await?;

        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::DATA, |w| {
            w.write_raw(&signed_region);
            w.write_tlv(tlv_type::SIGNATURE_VALUE, &sig_value);
        });
        Ok(w.finish())
    }

    pub fn sign_sync<F>(
        self,
        sig_type: SignatureType,
        key_locator: Option<&Name>,
        sign_fn: F,
    ) -> Bytes
    where
        F: FnOnce(&[u8]) -> Bytes,
    {
        let est = self.content.len() + 256;
        let mut w = TlvWriter::with_capacity(est);

        let signed_start = w.len();
        write_name(&mut w, &self.name);
        if self.content_type.is_some() || self.freshness.is_some() || self.final_block_id.is_some()
        {
            let content_type = self.content_type;
            let freshness = self.freshness;
            let fbi = self.final_block_id.as_deref();
            w.write_nested(tlv_type::META_INFO, |w| {
                if let Some(ct) = content_type {
                    write_nni(w, tlv_type::CONTENT_TYPE, ct);
                }
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
        let sig_value = sign_fn(w.slice_from(signed_start));

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

fn encode_nni_be(v: u64) -> Vec<u8> {
    if v == 0 {
        return vec![0x00];
    }
    let bytes = v.to_be_bytes();
    let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(7);
    bytes[first_nonzero..].to_vec()
}

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
    fn data_builder_content_type_roundtrips() {
        use crate::meta_info::ContentType;
        // ContentType=6 (ndn-svs "encapsulated Data" marker), the first
        // MetaInfo field, alongside freshness + FinalBlockId.
        let wire = DataBuilder::new("/test", b"inner")
            .content_type(ContentType::Other(6))
            .freshness(Duration::from_secs(4))
            .final_block_id_typed_seg(2)
            .build();
        let data = Data::decode(wire).unwrap();
        let mi = data.meta_info().expect("meta_info present");
        assert_eq!(mi.content_type, ContentType::Other(6));
        assert_eq!(mi.freshness_period, Some(Duration::from_secs(4)));
        assert!(mi.final_block_id.is_some());
        assert_eq!(data.content().map(|b| b.as_ref()), Some(b"inner".as_ref()));
    }

    #[test]
    fn encode_into_matches_build_byte_for_byte() {
        use crate::meta_info::ContentType;
        // Identical builders each call (DataBuilder isn't Clone); zip → pairs.
        let mk = || -> Vec<DataBuilder> {
            vec![
                DataBuilder::new("/test", b"hello"),
                DataBuilder::new("/a/b/c", b""),
                DataBuilder::new("/x", &[0xABu8; 5000]),
                DataBuilder::new("/t", b"inner")
                    .content_type(ContentType::Other(6))
                    .freshness(Duration::from_secs(4))
                    .final_block_id_typed_seg(2),
            ]
        };
        for (a, b) in mk().into_iter().zip(mk()) {
            let expected = a.build(); // the allocating single-buffer path
            let len = b.encoded_len_digest_sha256();
            let mut buf = vec![0u8; len];
            let n = b.encode_digest_sha256_into(&mut buf);
            assert_eq!(n, len, "encode_into returned len");
            assert_eq!(len, expected.len(), "encoded_len matches build() len");
            assert_eq!(
                &buf[..n],
                &expected[..],
                "encode_into must be byte-identical to build()"
            );
            Data::decode(Bytes::copy_from_slice(&buf[..n])).expect("encode_into output decodes");
        }
    }

    #[test]
    fn content_type_alone_emits_metainfo() {
        use crate::meta_info::ContentType;
        // ContentType present but no freshness/FinalBlockId must still
        // produce a MetaInfo block.
        let wire = DataBuilder::new("/t", b"")
            .content_type(ContentType::Other(6))
            .build();
        let data = Data::decode(wire).unwrap();
        assert_eq!(
            data.meta_info().map(|m| m.content_type),
            Some(ContentType::Other(6))
        );
    }

    #[test]
    fn default_content_type_omits_metainfo() {
        // No content_type set → Blob default → no MetaInfo on the wire.
        let wire = DataBuilder::new("/t", b"x").build();
        let data = Data::decode(wire).unwrap();
        assert!(
            data.meta_info().is_none(),
            "Blob default must omit MetaInfo"
        );
    }

    #[test]
    fn data_builder_sign() {
        use std::pin::pin;
        use std::task::{Context, Waker};

        let mut cx = Context::from_waker(Waker::noop());

        let key_name: Name = "/key/test".parse().unwrap();
        let fut = DataBuilder::new("/signed/data", b"payload")
            .freshness(Duration::from_secs(10))
            .sign(
                SignatureType::SignatureEd25519,
                Some(&key_name),
                |region: &[u8]| {
                    let digest = sha2::Sha256::digest(region);
                    std::future::ready({
                        let mut buf = [0u8; 64];
                        buf[..32].copy_from_slice(&digest);
                        Bytes::copy_from_slice(&buf)
                    })
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
        use std::task::{Context, Waker};

        let key_name: Name = "/key/test".parse().unwrap();
        let sign_fn = |region: &[u8]| -> Bytes {
            let digest = sha2::Sha256::digest(region);
            {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&digest);
                Bytes::copy_from_slice(&buf)
            }
        };

        // Async path
        let mut cx = Context::from_waker(Waker::noop());

        let fut = DataBuilder::new("/signed/data", b"payload")
            .freshness(Duration::from_secs(10))
            .sign(
                SignatureType::SignatureEd25519,
                Some(&key_name),
                |region: &[u8]| {
                    let digest = sha2::Sha256::digest(region);
                    std::future::ready({
                        let mut buf = [0u8; 64];
                        buf[..32].copy_from_slice(&digest);
                        Bytes::copy_from_slice(&buf)
                    })
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
        let key_name: Name = "/key/test".parse().unwrap();
        let wire = DataBuilder::new("/test", b"content").sign_sync(
            SignatureType::SignatureEd25519,
            Some(&key_name),
            |region| {
                let digest = sha2::Sha256::digest(region);
                {
                    let mut buf = [0u8; 64];
                    buf[..32].copy_from_slice(&digest);
                    Bytes::copy_from_slice(&buf)
                }
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

    /// `build()` must emit a real `SHA-256(signed region)`, not zero bytes.
    #[test]
    fn a10_databuilder_build_emits_real_sha256() {
        let wire = DataBuilder::new("/test", b"hello").build();
        let data = Data::decode(wire).expect("Data must decode");

        let signed = data.signed_region();
        let recovered = data.sig_value();

        assert_eq!(
            recovered.len(),
            32,
            "DigestSha256 SignatureValue must be 32 bytes"
        );
        assert!(
            !recovered.iter().all(|&b| b == 0),
            "SignatureValue must not be all zeros (forged DigestSha256)"
        );

        let expected: [u8; 32] = sha2::Sha256::digest(signed).into();
        assert_eq!(
            recovered,
            &expected[..],
            "SignatureValue must equal SHA-256(signed region)"
        );
    }

    #[test]
    fn wire_data_builder_no_freshness_omits_metainfo() {
        let wire = DataBuilder::new("/A", b"X").build();

        assert_eq!(wire[0], 0x06);
        assert_eq!(
            wire[7], 0x15,
            "Content should follow Name directly (no MetaInfo)"
        );
    }

    #[test]
    fn wire_data_builder_freshness_nni() {
        let wire = DataBuilder::new("/A", b"X")
            .freshness(Duration::from_secs(10))
            .build();

        let meta_pos = 7;
        assert_bytes_eq(
            &wire[meta_pos..meta_pos + 6],
            &[0x14, 0x04, 0x19, 0x02, 0x27, 0x10],
            "MetaInfo with FreshnessPeriod=10000ms",
        );
    }

    #[test]
    fn wire_ed25519_sig_type() {
        use std::pin::pin;
        use std::task::{Context, Waker};

        let mut cx = Context::from_waker(Waker::noop());

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

        let sig_info_content = [0x1B, 0x01, 0x05];
        assert!(
            wire.windows(3).any(|w| w == sig_info_content),
            "SignatureType=5 should be 1-byte NNI: 1B 01 05, got: {}",
            hex(&wire),
        );
    }
}
