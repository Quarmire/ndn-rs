#[cfg(all(not(feature = "std"), not(target_arch = "wasm32")))]
use alloc::format;
#[cfg(all(not(feature = "std"), not(target_arch = "wasm32")))]
use core::cell::OnceCell as OnceLock;
#[cfg(any(feature = "std", target_arch = "wasm32"))]
use std::sync::OnceLock;

use crate::compat::Arc;

use bytes::Bytes;

use crate::tlv_type;
use crate::{MetaInfo, Name, PacketError, SignatureInfo};
use ndn_tlv::TlvReader;

/// Selector for the forwarder-internal `Data::content_sha256` sidecar.
/// Forwarder-only: distinct from implicit digest, ToBeSigned hash, and
/// app-level digests in Content; never propagates on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentHashTarget {
    /// SHA-256 over the entire Content field value.
    WholeContent,
    /// SHA-256 over the value bytes of the first inner TLV of this type
    /// (header excluded). Sidecar stays `None` if no such inner TLV exists.
    InnerTlvType(u64),
}

/// An NDN Data packet. The signed region is contiguous in the wire encoding
/// and sliced directly from `raw`, enabling zero-copy CS storage and verify.
#[derive(Debug)]
pub struct Data {
    pub(crate) raw: Bytes,
    signed_start: usize,
    signed_end: usize,
    sig_value_start: usize,
    sig_value_end: usize,
    pub name: Arc<Name>,
    meta_info: OnceLock<Option<MetaInfo>>,
    content: OnceLock<Option<Bytes>>,
    sig_info: OnceLock<Option<SignatureInfo>>,
    /// Forwarder-internal sidecar; see [`Data::populate_content_sha256`].
    /// Only ever written via `sha2`-using setters under the `std` feature;
    /// readable in any cfg so embedded forwarders can pass through values
    /// computed elsewhere.
    #[cfg_attr(not(feature = "std"), allow(dead_code))]
    content_sha256: Option<[u8; 32]>,
}

impl Data {
    pub fn decode(raw: Bytes) -> Result<Self, PacketError> {
        let mut reader = TlvReader::new(raw.clone());
        let (typ, value) = reader.read_tlv()?;
        if typ != tlv_type::DATA {
            return Err(PacketError::UnknownPacketType(typ));
        }

        let outer_header_len = raw.len() - value.len();
        let signed_start = outer_header_len;

        let mut inner = TlvReader::new(value.clone());
        let (name_typ, name_val) = inner.read_tlv()?;
        if name_typ != tlv_type::NAME {
            return Err(PacketError::UnknownPacketType(name_typ));
        }
        let name = Name::decode(name_val)?;

        if name.is_empty() {
            return Err(PacketError::MalformedPacket(
                "Data Name must have at least one component".into(),
            ));
        }

        validate_data_body_structure(&inner)?;

        let mut sig_value_start = 0;
        let mut sig_value_end = 0;
        let _ = scan_for_sig_value(
            &raw,
            outer_header_len,
            &mut sig_value_start,
            &mut sig_value_end,
        );
        let signed_end = if sig_value_start > 0 {
            sig_value_start
        } else {
            raw.len()
        };

        Ok(Self {
            raw,
            signed_start,
            signed_end,
            sig_value_start,
            sig_value_end,
            name: Arc::new(name),
            meta_info: OnceLock::new(),
            content: OnceLock::new(),
            sig_info: OnceLock::new(),
            content_sha256: None,
        })
    }

    pub fn signed_region(&self) -> &[u8] {
        &self.raw[self.signed_start..self.signed_end]
    }

    pub fn sig_value(&self) -> &[u8] {
        if self.sig_value_start == 0 || self.sig_value_end == 0 {
            return &[];
        }
        // Parse the SignatureValue TLV header to find where the value bytes begin.
        let sig_tlv = self.raw.slice(self.sig_value_start..self.sig_value_end);
        let mut r = TlvReader::new(sig_tlv);
        match r.read_tlv() {
            Ok((_, val)) => {
                let val_start = self.sig_value_end - val.len();
                &self.raw[val_start..self.sig_value_end]
            }
            Err(_) => &[],
        }
    }

    pub fn raw(&self) -> &Bytes {
        &self.raw
    }

    /// SHA-256 of the full wire encoding, used for exact Data retrieval via
    /// ImplicitSha256DigestComponent (type 0x01) in Interest names.
    #[cfg(feature = "std")]
    pub fn implicit_digest(&self) -> [u8; 32] {
        use sha2::Digest;
        sha2::Sha256::digest(&self.raw).into()
    }

    /// Forwarder-internal SHA-256 sidecar, populated during ingress when
    /// `FaceOptions::content_hash_target = Some(_)`. Distinct from implicit
    /// digest / ToBeSigned hash / Content-level digests and never wire-visible.
    ///
    /// Consumers must still verify the hash matches their content-addressed
    /// identifier; this sidecar attests only to the forwarder's computation.
    /// Returns `None` for packets that did not pass through ingress with this
    /// option set.
    #[cfg(feature = "std")]
    pub fn content_sha256(&self) -> Option<[u8; 32]> {
        self.content_sha256
    }

    /// Shorthand for `populate_content_sha256_with(WholeContent)`. No-op when
    /// the packet has no `Content` field.
    #[cfg(feature = "std")]
    pub fn populate_content_sha256(&mut self) {
        use sha2::Digest;
        let content_bytes: Option<Bytes> = self.content().cloned();
        if let Some(bytes) = content_bytes {
            self.content_sha256 = Some(sha2::Sha256::digest(&bytes).into());
        }
    }

    /// Compute SHA-256 of the bytes selected by `target` and cache as the
    /// sidecar. Called by the forwarder decode stage based on
    /// `FaceOptions::content_hash_target`. No-op when there is no `Content`
    /// field, or for `InnerTlvType(t)` when no inner TLV of type `t` exists.
    #[cfg(feature = "std")]
    pub fn populate_content_sha256_with(&mut self, target: ContentHashTarget) {
        use sha2::Digest;
        let content_bytes: Option<Bytes> = self.content().cloned();
        let Some(content) = content_bytes else {
            return;
        };
        match target {
            ContentHashTarget::WholeContent => {
                self.content_sha256 = Some(sha2::Sha256::digest(&content).into());
            }
            ContentHashTarget::InnerTlvType(target_type) => {
                let mut reader = ndn_tlv::TlvReader::new(content);
                while !reader.is_empty() {
                    let Ok((typ, val)) = reader.read_tlv() else {
                        break;
                    };
                    if typ == target_type {
                        self.content_sha256 = Some(sha2::Sha256::digest(&val).into());
                        return;
                    }
                }
            }
        }
    }

    pub fn content(&self) -> Option<&Bytes> {
        self.content
            .get_or_init(|| decode_content(&self.raw).ok().flatten())
            .as_ref()
    }

    pub fn meta_info(&self) -> Option<&MetaInfo> {
        self.meta_info
            .get_or_init(|| decode_meta_info(&self.raw).ok().flatten())
            .as_ref()
    }

    pub fn sig_info(&self) -> Option<&SignatureInfo> {
        self.sig_info
            .get_or_init(|| decode_sig_info(&self.raw).ok().flatten())
            .as_ref()
    }

    /// Per NDN Packet Format v0.3 §6.3.1, when ContentType is LINK the Content
    /// field contains one or more delegation Name TLVs.
    #[cfg(feature = "std")]
    pub fn link_delegations(&self) -> Option<Vec<Arc<Name>>> {
        let mi = self.meta_info()?;
        if mi.content_type != crate::meta_info::ContentType::Link {
            return None;
        }
        let content = self.content()?;
        let mut reader = TlvReader::new(content.clone());
        let mut names = Vec::new();
        while !reader.is_empty() {
            let (typ, val) = reader.read_tlv().ok()?;
            if typ == tlv_type::NAME {
                names.push(Arc::new(Name::decode(val).ok()?));
            }
        }
        if names.is_empty() { None } else { Some(names) }
    }
}

/// Body-structure check for Data, enforcing spec order per `data.html`:
/// Name=1, MetaInfo=2, Content=3, SignatureInfo=4, SignatureValue=5; aborts
/// on duplicates, out-of-order elements, or unknown critical TLV-TYPEs.
/// Forks the reader via `as_bytes()` so the caller's cursor is unaffected.
fn validate_data_body_structure(body: &TlvReader) -> Result<(), PacketError> {
    fn elem_index(typ: u64) -> Option<u8> {
        Some(match typ {
            t if t == tlv_type::META_INFO => 2,
            t if t == tlv_type::CONTENT => 3,
            t if t == tlv_type::SIGNATURE_INFO => 4,
            t if t == tlv_type::SIGNATURE_VALUE => 5,
            _ => return None,
        })
    }

    let mut scan = TlvReader::new(body.as_bytes());
    let mut last_element: u8 = 1;
    let mut last_sig_type: Option<crate::SignatureType> = None;
    while !scan.is_empty() {
        let (typ, val) = scan.read_tlv()?;
        match elem_index(typ) {
            Some(elem) => {
                if elem <= last_element {
                    return Err(PacketError::MalformedPacket(
                        "Data body element out of spec order or duplicated".into(),
                    ));
                }
                last_element = elem;
                // Eagerly decode SignatureInfo so the KeyLocator-by-SigType
                // rules (signature.html) surface at decode time instead of
                // silently via the lazy `sig_info()` accessor.
                if typ == tlv_type::SIGNATURE_INFO {
                    let info = crate::SignatureInfo::decode(val.clone())?;
                    last_sig_type = Some(info.sig_type);
                }
                // Fixed-width SignatureValue check: DigestSha256 / HmacSha256
                // / Ed25519 / BLAKE3 codes have exact lengths; RSA and ECDSA
                // are variable and skipped.
                if typ == tlv_type::SIGNATURE_VALUE
                    && let Some(sig_type) = last_sig_type
                    && let Some(expected) = sig_type.required_signature_value_len()
                    && val.len() != expected
                {
                    return Err(PacketError::MalformedPacket(format!(
                        "SignatureValue length {} != expected {} for {sig_type:?}",
                        val.len(),
                        expected,
                    )));
                }
            }
            None => {
                if crate::is_critical_tlv_type(typ) {
                    return Err(PacketError::MalformedPacket(
                        "unknown critical TLV-TYPE in Data body".into(),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn scan_for_sig_value(
    raw: &Bytes,
    start: usize,
    sig_start: &mut usize,
    sig_end: &mut usize,
) -> Result<(), PacketError> {
    let mut reader = TlvReader::new(raw.slice(start..));
    while !reader.is_empty() {
        let pos = start + reader.position();
        let (typ, val) = reader.read_tlv()?;
        if typ == tlv_type::SIGNATURE_VALUE {
            *sig_start = pos;
            *sig_end = start + reader.position();
            return Ok(());
        }
        let _ = val;
    }
    Ok(())
}

fn decode_content(raw: &Bytes) -> Result<Option<Bytes>, PacketError> {
    let mut reader = TlvReader::new(raw.clone());
    let (_, value) = reader.read_tlv()?;
    let mut inner = TlvReader::new(value);
    while !inner.is_empty() {
        let (typ, val) = inner.read_tlv()?;
        if typ == tlv_type::CONTENT {
            return Ok(Some(val));
        }
    }
    Ok(None)
}

fn decode_meta_info(raw: &Bytes) -> Result<Option<MetaInfo>, PacketError> {
    let mut reader = TlvReader::new(raw.clone());
    let (_, value) = reader.read_tlv()?;
    let mut inner = TlvReader::new(value);
    while !inner.is_empty() {
        let (typ, val) = inner.read_tlv()?;
        if typ == tlv_type::META_INFO {
            return Ok(Some(MetaInfo::decode(val)?));
        }
    }
    Ok(None)
}

#[cfg(test)]
pub(crate) fn build_data_packet(
    components: &[&[u8]],
    content: &[u8],
    freshness_ms: Option<u64>,
    sig_type_code: u8,
    sig_value: &[u8],
) -> Bytes {
    let mut w = ndn_tlv::TlvWriter::new();
    w.write_nested(tlv_type::DATA, |w| {
        w.write_nested(tlv_type::NAME, |w| {
            for comp in components {
                w.write_tlv(tlv_type::NAME_COMPONENT, comp);
            }
        });
        if let Some(ms) = freshness_ms {
            w.write_nested(tlv_type::META_INFO, |w| {
                w.write_tlv(tlv_type::FRESHNESS_PERIOD, &ms.to_be_bytes());
            });
        }
        w.write_tlv(tlv_type::CONTENT, content);
        w.write_nested(tlv_type::SIGNATURE_INFO, |w| {
            w.write_tlv(tlv_type::SIGNATURE_TYPE, &[sig_type_code]);
            // Sig types other than DigestSha256 (0) and DigestBlake3 (6) MUST
            // carry a KeyLocator; emit a stub `/test-key` for them.
            if !matches!(sig_type_code, 0 | 6) {
                w.write_nested(tlv_type::KEY_LOCATOR, |w| {
                    w.write_nested(tlv_type::NAME, |w| {
                        w.write_tlv(tlv_type::NAME_COMPONENT, b"test-key");
                    });
                });
            }
        });
        // Fixed-width algorithms get `sig_value` zero-padded or truncated to
        // the required width; variable-width algorithms pass through unchanged.
        let sig_type_for_width = crate::SignatureType::from_code(sig_type_code as u64);
        let sig_value_bytes: Vec<u8> = match sig_type_for_width.required_signature_value_len() {
            Some(width) => {
                let mut buf = vec![0u8; width];
                let n = sig_value.len().min(width);
                buf[..n].copy_from_slice(&sig_value[..n]);
                buf
            }
            None => sig_value.to_vec(),
        };
        w.write_tlv(tlv_type::SIGNATURE_VALUE, &sig_value_bytes);
    });
    w.finish()
}

fn decode_sig_info(raw: &Bytes) -> Result<Option<SignatureInfo>, PacketError> {
    let mut reader = TlvReader::new(raw.clone());
    let (_, value) = reader.read_tlv()?;
    let mut inner = TlvReader::new(value);
    while !inner.is_empty() {
        let (typ, val) = inner.read_tlv()?;
        if typ == tlv_type::SIGNATURE_INFO {
            return Ok(Some(SignatureInfo::decode(val)?));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    /// An unknown critical TLV-TYPE (>31, odd) at the Data body level must
    /// abort decoding per `tlv.html` §"TLV-TYPE".
    #[test]
    fn a03_data_decode_rejects_unknown_critical_tlv_in_body() {
        use bytes::Bytes;
        use ndn_tlv::TlvWriter;
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::DATA, |w| {
            w.write_nested(tlv_type::NAME, |w| {
                w.write_tlv(tlv_type::NAME_COMPONENT, b"audit");
            });
            w.write_tlv(0x99, b"x");
            w.write_tlv(tlv_type::CONTENT, b"hi");
            w.write_nested(tlv_type::SIGNATURE_INFO, |w| {
                w.write_tlv(tlv_type::SIGNATURE_TYPE, &[0u8]);
            });
            w.write_tlv(tlv_type::SIGNATURE_VALUE, &[0u8; 32]);
        });
        let raw: Bytes = w.finish();
        let err = Data::decode(raw)
            .expect_err("Data with an unknown critical TLV in body must be rejected (A.03)");
        match err {
            PacketError::MalformedPacket(_) => {}
            other => panic!("expected MalformedPacket, got {other:?}"),
        }
    }

    /// Data body element order per `data.html` is Name, MetaInfo, Content,
    /// SignatureInfo, SignatureValue; Content before MetaInfo must reject.
    #[test]
    fn a04_data_decode_rejects_content_before_meta_info() {
        use bytes::Bytes;
        use ndn_tlv::TlvWriter;
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::DATA, |w| {
            w.write_nested(tlv_type::NAME, |w| {
                w.write_tlv(tlv_type::NAME_COMPONENT, b"audit");
            });
            w.write_tlv(tlv_type::CONTENT, b"hi");
            w.write_nested(tlv_type::META_INFO, |w| {
                w.write_tlv(tlv_type::FRESHNESS_PERIOD, &[0x00, 0x01]);
            });
            w.write_nested(tlv_type::SIGNATURE_INFO, |w| {
                w.write_tlv(tlv_type::SIGNATURE_TYPE, &[0u8]);
            });
            w.write_tlv(tlv_type::SIGNATURE_VALUE, &[0u8; 32]);
        });
        let raw: Bytes = w.finish();
        let err = Data::decode(raw).expect_err("Content before MetaInfo is out of spec order");
        match err {
            PacketError::MalformedPacket(_) => {}
            other => panic!("expected MalformedPacket, got {other:?}"),
        }
    }

    /// Ed25519 (5) requires a KeyLocator per `signature.html`; Data without
    /// one must reject at decode rather than surfacing later as `sig_info() == None`.
    #[test]
    fn a15_data_decode_rejects_ed25519_without_keylocator() {
        let mut w = ndn_tlv::TlvWriter::new();
        w.write_nested(tlv_type::DATA, |w| {
            w.write_nested(tlv_type::NAME, |w| {
                w.write_tlv(tlv_type::NAME_COMPONENT, b"test");
            });
            w.write_tlv(tlv_type::CONTENT, b"payload");
            w.write_nested(tlv_type::SIGNATURE_INFO, |w| {
                w.write_tlv(tlv_type::SIGNATURE_TYPE, &[5u8]);
            });
            w.write_tlv(tlv_type::SIGNATURE_VALUE, &[0u8; 64]);
        });
        let raw: Bytes = w.finish();
        let err = Data::decode(raw).expect_err("Ed25519 Data without KeyLocator must be rejected");
        match err {
            PacketError::KeyLocatorRule { sig_type_code: 5 } => {}
            other => panic!("expected KeyLocatorRule(5), got {other:?}"),
        }
    }

    /// DigestSha256 (0) MUST NOT carry a KeyLocator; reject if a peer adds one.
    #[test]
    fn a15_data_decode_rejects_digest_sha256_with_keylocator() {
        let mut w = ndn_tlv::TlvWriter::new();
        w.write_nested(tlv_type::DATA, |w| {
            w.write_nested(tlv_type::NAME, |w| {
                w.write_tlv(tlv_type::NAME_COMPONENT, b"test");
            });
            w.write_tlv(tlv_type::CONTENT, b"x");
            w.write_nested(tlv_type::SIGNATURE_INFO, |w| {
                w.write_tlv(tlv_type::SIGNATURE_TYPE, &[0u8]);
                w.write_nested(tlv_type::KEY_LOCATOR, |w| {
                    w.write_nested(tlv_type::NAME, |w| {
                        w.write_tlv(tlv_type::NAME_COMPONENT, b"unexpected");
                    });
                });
            });
            w.write_tlv(tlv_type::SIGNATURE_VALUE, &[0u8; 32]);
        });
        let raw: Bytes = w.finish();
        let err = Data::decode(raw)
            .expect_err("DigestSha256 Data carrying a KeyLocator must be rejected");
        match err {
            PacketError::KeyLocatorRule { sig_type_code: 0 } => {}
            other => panic!("expected KeyLocatorRule(0), got {other:?}"),
        }
    }

    /// Decode rejects fixed-width SignatureValue lengths that disagree with
    /// the declared SignatureType.
    #[test]
    fn a16_data_decode_rejects_short_ed25519_signature_value() {
        let mut w = ndn_tlv::TlvWriter::new();
        w.write_nested(tlv_type::DATA, |w| {
            w.write_nested(tlv_type::NAME, |w| {
                w.write_tlv(tlv_type::NAME_COMPONENT, b"a16");
            });
            w.write_tlv(tlv_type::CONTENT, b"x");
            w.write_nested(tlv_type::SIGNATURE_INFO, |w| {
                w.write_tlv(tlv_type::SIGNATURE_TYPE, &[5u8]);
                w.write_nested(tlv_type::KEY_LOCATOR, |w| {
                    w.write_nested(tlv_type::NAME, |w| {
                        w.write_tlv(tlv_type::NAME_COMPONENT, b"key");
                    });
                });
            });
            w.write_tlv(tlv_type::SIGNATURE_VALUE, &[0xAB]);
        });
        let raw: Bytes = w.finish();
        let err =
            Data::decode(raw).expect_err("Ed25519 with 1-byte SignatureValue must be rejected");
        assert!(
            matches!(err, PacketError::MalformedPacket(ref m) if m.contains("SignatureValue length")),
            "expected SignatureValue length MalformedPacket, got {err:?}",
        );
    }

    /// DigestSha256 (0) requires exactly 32-byte SignatureValue.
    #[test]
    fn a16_data_decode_rejects_oversize_digest_sha256_value() {
        let mut w = ndn_tlv::TlvWriter::new();
        w.write_nested(tlv_type::DATA, |w| {
            w.write_nested(tlv_type::NAME, |w| {
                w.write_tlv(tlv_type::NAME_COMPONENT, b"a16");
            });
            w.write_tlv(tlv_type::CONTENT, b"x");
            w.write_nested(tlv_type::SIGNATURE_INFO, |w| {
                w.write_tlv(tlv_type::SIGNATURE_TYPE, &[0u8]);
            });
            w.write_tlv(tlv_type::SIGNATURE_VALUE, &[0u8; 64]);
        });
        let raw: Bytes = w.finish();
        let err = Data::decode(raw)
            .expect_err("DigestSha256 with 64-byte SignatureValue must be rejected");
        assert!(
            matches!(err, PacketError::MalformedPacket(ref m) if m.contains("SignatureValue length")),
            "expected SignatureValue length MalformedPacket, got {err:?}",
        );
    }

    /// RSA and ECDSA SignatureValue widths are variable and must not be
    /// rejected by the fixed-width check.
    #[test]
    fn a16_variable_width_sig_types_pass_length_check() {
        for &(code, lens) in &[(1u8, &[71usize, 72, 256][..]), (3u8, &[64, 72][..])] {
            for &len in lens {
                let mut w = ndn_tlv::TlvWriter::new();
                w.write_nested(tlv_type::DATA, |w| {
                    w.write_nested(tlv_type::NAME, |w| {
                        w.write_tlv(tlv_type::NAME_COMPONENT, b"a16");
                    });
                    w.write_tlv(tlv_type::CONTENT, b"x");
                    w.write_nested(tlv_type::SIGNATURE_INFO, |w| {
                        w.write_tlv(tlv_type::SIGNATURE_TYPE, &[code]);
                        w.write_nested(tlv_type::KEY_LOCATOR, |w| {
                            w.write_nested(tlv_type::NAME, |w| {
                                w.write_tlv(tlv_type::NAME_COMPONENT, b"key");
                            });
                        });
                    });
                    w.write_tlv(tlv_type::SIGNATURE_VALUE, &vec![0u8; len]);
                });
                let raw: Bytes = w.finish();
                Data::decode(raw).unwrap_or_else(|e| {
                    panic!("RSA/ECDSA code={code} len={len} should decode: {e:?}")
                });
            }
        }
    }

    #[test]
    fn a18_decode_nni_rejects_nonstandard_widths() {
        for buf in &[&[0u8][..], &[0u8, 0][..], &[0u8; 4][..], &[0u8; 8][..]] {
            assert!(
                crate::decode_nni(buf).is_ok(),
                "valid width {} rejected",
                buf.len()
            );
        }
        for buf in &[
            &[][..],
            &[0u8; 3][..],
            &[0u8; 5][..],
            &[0u8; 6][..],
            &[0u8; 7][..],
            &[0u8; 9][..],
        ] {
            assert!(
                crate::decode_nni(buf).is_err(),
                "invalid width {} should reject",
                buf.len()
            );
        }
    }

    #[test]
    fn decode_name() {
        let raw = build_data_packet(&[b"edu", b"ucla"], b"hello", None, 5, &[0xAB]);
        let d = Data::decode(raw).unwrap();
        assert_eq!(d.name.len(), 2);
        assert_eq!(d.name.components()[0].value.as_ref(), b"edu");
        assert_eq!(d.name.components()[1].value.as_ref(), b"ucla");
    }

    #[test]
    fn decode_content() {
        let raw = build_data_packet(&[b"test"], b"payload", None, 0, &[0x00]);
        let d = Data::decode(raw).unwrap();
        let content = d.content().expect("content present");
        assert_eq!(content.as_ref(), b"payload");
    }

    #[test]
    fn decode_empty_content() {
        let raw = build_data_packet(&[b"test"], b"", None, 0, &[0x00]);
        let d = Data::decode(raw).unwrap();
        let content = d.content().expect("content present");
        assert_eq!(content.len(), 0);
    }

    #[test]
    fn decode_meta_info_freshness() {
        let raw = build_data_packet(&[b"test"], b"", Some(5000), 5, &[0x00]);
        let d = Data::decode(raw).unwrap();
        let mi = d.meta_info().expect("meta_info present");
        assert_eq!(
            mi.freshness_period,
            Some(std::time::Duration::from_millis(5000))
        );
    }

    #[test]
    fn decode_no_meta_info() {
        let raw = build_data_packet(&[b"test"], b"data", None, 0, &[0x00]);
        let d = Data::decode(raw).unwrap();
        assert!(d.meta_info().is_none());
    }

    #[test]
    fn decode_sig_info_type() {
        let raw = build_data_packet(&[b"test"], b"", None, 0, &[0xAB]);
        let d = Data::decode(raw).unwrap();
        let si = d.sig_info().expect("sig_info present");
        assert_eq!(si.sig_type, crate::SignatureType::DigestSha256);
    }

    #[test]
    fn signed_region_excludes_sig_value() {
        let sig_bytes: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];
        let raw = build_data_packet(&[b"test"], b"content", None, 5, sig_bytes);
        let d = Data::decode(raw.clone()).unwrap();

        let region = d.signed_region();
        assert!(!region.is_empty());
        assert!(!region.ends_with(sig_bytes));
    }

    #[test]
    fn sig_value_correct_bytes() {
        // sig_type=1 (RSA, variable width) so the helper passes the bytes
        // through unchanged; fixed-width sigs get padded.
        let sig_bytes: &[u8] = &[0x11, 0x22, 0x33, 0x44];
        let raw = build_data_packet(&[b"test"], b"content", None, 1, sig_bytes);
        let d = Data::decode(raw).unwrap();
        assert_eq!(d.sig_value(), sig_bytes);
    }

    #[test]
    fn signed_end_equals_sig_value_start() {
        let raw = build_data_packet(&[b"n"], b"x", None, 0, &[0xAB, 0xCD]);
        let d = Data::decode(raw).unwrap();
        assert_eq!(d.signed_end, d.sig_value_start);
    }

    #[test]
    fn raw_field_is_full_wire_bytes() {
        let raw = build_data_packet(&[b"test"], b"hi", None, 0, &[0x00]);
        let d = Data::decode(raw.clone()).unwrap();
        assert_eq!(d.raw(), &raw);
    }

    fn build_link_data(name_comps: &[&[u8]], delegations: &[&[&[u8]]]) -> Bytes {
        let mut content_w = ndn_tlv::TlvWriter::new();
        for del in delegations {
            content_w.write_nested(tlv_type::NAME, |w| {
                for comp in *del {
                    w.write_tlv(tlv_type::NAME_COMPONENT, comp);
                }
            });
        }
        let content_bytes = content_w.finish();

        let mut w = ndn_tlv::TlvWriter::new();
        w.write_nested(tlv_type::DATA, |w| {
            w.write_nested(tlv_type::NAME, |w| {
                for comp in name_comps {
                    w.write_tlv(tlv_type::NAME_COMPONENT, comp);
                }
            });
            w.write_nested(tlv_type::META_INFO, |w| {
                w.write_tlv(tlv_type::CONTENT_TYPE, &[1]);
            });
            w.write_tlv(tlv_type::CONTENT, &content_bytes);
            w.write_nested(tlv_type::SIGNATURE_INFO, |w| {
                w.write_tlv(tlv_type::SIGNATURE_TYPE, &[0]);
            });
            w.write_tlv(tlv_type::SIGNATURE_VALUE, &[0u8; 32]);
        });
        w.finish()
    }

    #[test]
    fn link_delegations_parsed() {
        let raw = build_link_data(
            &[b"link"],
            &[&[b"ndn", b"gateway1"], &[b"ndn", b"gateway2"]],
        );
        let d = Data::decode(raw).unwrap();
        let dels = d.link_delegations().expect("delegations present");
        assert_eq!(dels.len(), 2);
        assert_eq!(dels[0].components()[1].value.as_ref(), b"gateway1");
        assert_eq!(dels[1].components()[1].value.as_ref(), b"gateway2");
    }

    #[test]
    fn non_link_data_has_no_delegations() {
        let raw = build_data_packet(&[b"test"], b"payload", None, 5, &[0x00]);
        let d = Data::decode(raw).unwrap();
        assert!(d.link_delegations().is_none());
    }

    #[test]
    fn implicit_digest_is_sha256_of_raw() {
        let raw = build_data_packet(&[b"test"], b"content", None, 5, &[0xAB]);
        let d = Data::decode(raw.clone()).unwrap();
        let expected: [u8; 32] = sha2::Sha256::digest(&raw).into();
        assert_eq!(d.implicit_digest(), expected);
    }

    #[test]
    fn decode_wrong_type_errors() {
        let mut w = ndn_tlv::TlvWriter::new();
        w.write_nested(0x05, |w| {
            w.write_nested(crate::tlv_type::NAME, |w| {
                w.write_tlv(crate::tlv_type::NAME_COMPONENT, b"test");
            });
        });
        assert!(matches!(
            Data::decode(w.finish()).unwrap_err(),
            crate::PacketError::UnknownPacketType(0x05)
        ));
    }
}
