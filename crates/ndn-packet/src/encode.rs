/// Packet encoding utilities.
///
/// Produces minimal wire-format Interest and Data TLVs using `TlvWriter`.
/// Intended for applications and the management plane, not the forwarding
/// pipeline (which operates on already-encoded `Bytes`).
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ndn_tlv::{TlvReader, TlvWriter};

use crate::{Name, SignatureType, tlv_type};

// ─── Public API ───────────────────────────────────────────────────────────────

/// Encode a minimal Interest TLV.
///
/// Includes:
/// - `Name` built from `name`
/// - `Nonce` (4 bytes, process-local counter XOR process ID — sufficient for
///   loop detection; not cryptographically random)
/// - `InterestLifetime` fixed at 4 000 ms
/// - `ApplicationParameters` (TLV type 0x24) if `app_params` is `Some`
///
/// The returned `Bytes` is a complete, self-contained TLV suitable for direct
/// transmission over any NDN face.
pub fn encode_interest(name: &Name, app_params: Option<&[u8]>) -> Bytes {
    let mut w = TlvWriter::new();
    w.write_nested(tlv_type::INTEREST, |w| {
        if let Some(params) = app_params {
            // Compute ParametersSha256DigestComponent: SHA-256 of the
            // ApplicationParameters TLV (type + length + value).
            let mut params_tlv = TlvWriter::new();
            params_tlv.write_tlv(tlv_type::APP_PARAMETERS, params);
            let params_wire = params_tlv.finish();
            let digest = ring::digest::digest(&ring::digest::SHA256, &params_wire);

            // Write Name with ParametersSha256DigestComponent appended.
            w.write_nested(tlv_type::NAME, |w| {
                for comp in name.components() {
                    w.write_tlv(comp.typ, &comp.value);
                }
                w.write_tlv(tlv_type::PARAMETERS_SHA256, digest.as_ref());
            });
            w.write_tlv(tlv_type::NONCE, &next_nonce().to_be_bytes());
            w.write_tlv(tlv_type::INTEREST_LIFETIME, &4000u64.to_be_bytes());
            w.write_tlv(tlv_type::APP_PARAMETERS, params);
        } else {
            write_name(w, name);
            w.write_tlv(tlv_type::NONCE, &next_nonce().to_be_bytes());
            w.write_tlv(tlv_type::INTEREST_LIFETIME, &4000u64.to_be_bytes());
        }
    });
    w.finish()
}

/// Encode a Data TLV with a placeholder `DigestSha256` signature.
///
/// The signature type is `0` (DigestSha256) and the value is 32 zero bytes.
/// This is intentionally unsigned — correctness for the management plane is
/// guaranteed by the transport (local Unix socket / shared-memory IPC), not by
/// the NDN signature chain.  Full `Ed25519` signing can be layered on later via
/// `SecurityManager`.
///
/// `FreshnessPeriod` is 0 so management responses are never served from cache.
pub fn encode_data_unsigned(name: &Name, content: &[u8]) -> Bytes {
    let mut w = TlvWriter::new();
    w.write_nested(tlv_type::DATA, |w| {
        write_name(w, name);
        // MetaInfo: FreshnessPeriod = 0
        w.write_nested(tlv_type::META_INFO, |w| {
            w.write_tlv(tlv_type::FRESHNESS_PERIOD, &0u64.to_be_bytes());
        });
        w.write_tlv(tlv_type::CONTENT, content);
        // SignatureInfo: DigestSha256 (type code 0)
        w.write_nested(tlv_type::SIGNATURE_INFO, |w| {
            w.write_tlv(tlv_type::SIGNATURE_TYPE, &[0u8]);
        });
        // 32-byte placeholder signature value
        w.write_tlv(tlv_type::SIGNATURE_VALUE, &[0u8; 32]);
    });
    w.finish()
}

/// Encode a Nack as an NDNLPv2 LpPacket wrapping the original Interest.
///
/// The resulting packet is an LpPacket (0x64) containing:
/// - Nack header (0x0320) with NackReason (0x0321)
/// - Fragment (0x50) containing the original Interest wire bytes
///
/// `interest_wire` must be a complete Interest TLV (type + length + value).
pub fn encode_nack(reason: crate::NackReason, interest_wire: &[u8]) -> Bytes {
    crate::lp::encode_lp_nack(reason, interest_wire)
}

/// Ensure an Interest has a Nonce field.
///
/// If the Interest wire bytes already contain a Nonce (TLV 0x0A), returns the
/// bytes unchanged. Otherwise, re-encodes the Interest with a generated Nonce
/// inserted after the Name.
///
/// Per RFC 8569 §4.2, a forwarder MUST add a Nonce before forwarding.
pub fn ensure_nonce(interest_wire: &Bytes) -> Bytes {
    // Quick scan: does a Nonce TLV already exist?
    let mut reader = TlvReader::new(interest_wire.clone());
    let Ok((typ, value)) = reader.read_tlv() else { return interest_wire.clone() };
    if typ != tlv_type::INTEREST { return interest_wire.clone(); }

    let mut inner = TlvReader::new(value.clone());
    while !inner.is_empty() {
        let Ok((t, _)) = inner.read_tlv() else { break };
        if t == tlv_type::NONCE {
            return interest_wire.clone(); // already has Nonce
        }
    }

    // No Nonce found — re-encode with one inserted.
    let mut w = TlvWriter::new();
    w.write_nested(tlv_type::INTEREST, |w| {
        let mut inner = TlvReader::new(value);
        let mut name_written = false;
        while !inner.is_empty() {
            let Ok((t, v)) = inner.read_tlv() else { break };
            w.write_tlv(t, &v);
            // Insert Nonce right after Name (type 0x07).
            if !name_written && t == tlv_type::NAME {
                w.write_tlv(tlv_type::NONCE, &next_nonce().to_be_bytes());
                name_written = true;
            }
        }
        if !name_written {
            // Name wasn't found (malformed), add Nonce at end as fallback.
            w.write_tlv(tlv_type::NONCE, &next_nonce().to_be_bytes());
        }
    });
    w.finish()
}

// ─── Builders ────────────────────────────────────────────────────────────────

/// Configurable Interest encoder.
///
/// ```
/// # use ndn_packet::encode::InterestBuilder;
/// # use std::time::Duration;
/// let wire = InterestBuilder::new("/ndn/test")
///     .lifetime(Duration::from_millis(2000))
///     .must_be_fresh()
///     .build();
/// ```
pub struct InterestBuilder {
    name:            Name,
    lifetime:        Option<Duration>,
    can_be_prefix:   bool,
    must_be_fresh:   bool,
    hop_limit:       Option<u8>,
    app_parameters:  Option<Vec<u8>>,
}

impl InterestBuilder {
    pub fn new(name: impl Into<Name>) -> Self {
        Self {
            name:           name.into(),
            lifetime:       None,
            can_be_prefix:  false,
            must_be_fresh:  false,
            hop_limit:      None,
            app_parameters: None,
        }
    }

    pub fn lifetime(mut self, d: Duration) -> Self {
        self.lifetime = Some(d); self
    }

    pub fn can_be_prefix(mut self) -> Self {
        self.can_be_prefix = true; self
    }

    pub fn must_be_fresh(mut self) -> Self {
        self.must_be_fresh = true; self
    }

    pub fn hop_limit(mut self, h: u8) -> Self {
        self.hop_limit = Some(h); self
    }

    pub fn app_parameters(mut self, p: impl Into<Vec<u8>>) -> Self {
        self.app_parameters = Some(p.into()); self
    }

    pub fn build(self) -> Bytes {
        let lifetime_ms = self.lifetime
            .map(|d| d.as_millis() as u64)
            .unwrap_or(4000);

        if let Some(params) = &self.app_parameters {
            // With ApplicationParameters: same logic as encode_interest.
            return encode_interest(&self.name, Some(params));
        }

        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::INTEREST, |w| {
            write_name(w, &self.name);
            if self.can_be_prefix {
                w.write_tlv(tlv_type::CAN_BE_PREFIX, &[]);
            }
            if self.must_be_fresh {
                w.write_tlv(tlv_type::MUST_BE_FRESH, &[]);
            }
            w.write_tlv(tlv_type::NONCE, &next_nonce().to_be_bytes());
            w.write_tlv(tlv_type::INTEREST_LIFETIME, &lifetime_ms.to_be_bytes());
            if let Some(h) = self.hop_limit {
                w.write_tlv(tlv_type::HOP_LIMIT, &[h]);
            }
        });
        w.finish()
    }
}

/// Allow `&str` and `String` to convert into `Name` for builder ergonomics.
impl From<&str> for Name {
    fn from(s: &str) -> Self {
        s.parse().unwrap_or_else(|_| Name::root())
    }
}

impl From<String> for Name {
    fn from(s: String) -> Self {
        s.parse().unwrap_or_else(|_| Name::root())
    }
}

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
    name:       Name,
    content:    Vec<u8>,
    freshness:  Option<Duration>,
}

impl DataBuilder {
    pub fn new(name: impl Into<Name>, content: &[u8]) -> Self {
        Self {
            name:      name.into(),
            content:   content.to_vec(),
            freshness: None,
        }
    }

    pub fn freshness(mut self, d: Duration) -> Self {
        self.freshness = Some(d); self
    }

    /// Build unsigned Data with a DigestSha256 placeholder signature.
    pub fn build(self) -> Bytes {
        let freshness_ms = self.freshness
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::DATA, |w| {
            write_name(w, &self.name);
            w.write_nested(tlv_type::META_INFO, |w| {
                w.write_tlv(tlv_type::FRESHNESS_PERIOD, &freshness_ms.to_be_bytes());
            });
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
        sig_type:    SignatureType,
        key_locator: Option<&Name>,
        sign_fn:     F,
    ) -> Bytes
    where
        F: FnOnce(&[u8]) -> Fut,
        Fut: std::future::Future<Output = Bytes>,
    {
        let freshness_ms = self.freshness
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        // Build Name + MetaInfo + Content.
        let mut inner = TlvWriter::new();
        write_name(&mut inner, &self.name);
        inner.write_nested(tlv_type::META_INFO, |w| {
            w.write_tlv(tlv_type::FRESHNESS_PERIOD, &freshness_ms.to_be_bytes());
        });
        inner.write_tlv(tlv_type::CONTENT, &self.content);
        let inner_bytes = inner.finish();

        // Build SignatureInfo.
        let mut sig_info_writer = TlvWriter::new();
        sig_info_writer.write_nested(tlv_type::SIGNATURE_INFO, |w| {
            let code = sig_type.code();
            if code == 0 {
                w.write_tlv(tlv_type::SIGNATURE_TYPE, &[0u8]);
            } else {
                let be = code.to_be_bytes();
                let start = be.iter().position(|&b| b != 0).unwrap_or(7);
                w.write_tlv(tlv_type::SIGNATURE_TYPE, &be[start..]);
            }
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
}

// ─── Private helpers ──────────────────────────────────────────────────────────

/// Write a `Name` TLV into an in-progress writer, preserving each component's
/// original type code (e.g. `0x08` generic, `0x01` ImplicitSha256Digest).
fn write_name(w: &mut TlvWriter, name: &Name) {
    w.write_nested(tlv_type::NAME, |w| {
        for comp in name.components() {
            w.write_tlv(comp.typ, &comp.value);
        }
    });
}

/// Produce a per-process-unique 4-byte nonce.
///
/// Combines a monotonically-increasing per-process counter with the low 16 bits
/// of the process ID.  Sufficient for loop detection; not cryptographically
/// random.
fn next_nonce() -> u32 {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    (std::process::id() << 16).wrapping_add(seq)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use crate::{Data, Interest, NameComponent};

    fn name(components: &[&[u8]]) -> Name {
        Name::from_components(
            components.iter().map(|c| NameComponent::generic(Bytes::copy_from_slice(c)))
        )
    }

    #[test]
    fn interest_roundtrip_name() {
        let n = name(&[b"localhost", b"ndn-ctl", b"get-stats"]);
        let bytes = encode_interest(&n, None);
        let interest = Interest::decode(bytes).unwrap();
        assert_eq!(*interest.name, n);
    }

    #[test]
    fn interest_with_app_params_roundtrip() {
        let n = name(&[b"localhost", b"ndn-ctl", b"add-route"]);
        let params = br#"{"cmd":"add_route","prefix":"/ndn","face":1,"cost":10}"#;
        let bytes = encode_interest(&n, Some(params));
        let interest = Interest::decode(bytes).unwrap();
        // Name has the original components plus ParametersSha256DigestComponent.
        assert_eq!(interest.name.len(), n.len() + 1);
        for (i, comp) in n.components().iter().enumerate() {
            assert_eq!(interest.name.components()[i], *comp);
        }
        // Last component is the digest (type 0x02, 32 bytes).
        let last = &interest.name.components()[n.len()];
        assert_eq!(last.typ, tlv_type::PARAMETERS_SHA256);
        assert_eq!(last.value.len(), 32);
        assert_eq!(interest.app_parameters().map(|b| b.as_ref()), Some(params.as_ref()));
    }

    #[test]
    fn interest_has_nonce_and_lifetime() {
        use core::time::Duration;
        let n = name(&[b"test"]);
        let bytes = encode_interest(&n, None);
        let interest = Interest::decode(bytes).unwrap();
        assert!(interest.nonce().is_some());
        assert_eq!(interest.lifetime(), Some(Duration::from_millis(4000)));
    }

    #[test]
    fn data_roundtrip_name_and_content() {
        let n = name(&[b"localhost", b"ndn-ctl", b"get-stats"]);
        let content = br#"{"status":"ok","pit_size":42}"#;
        let bytes = encode_data_unsigned(&n, content);
        let data = Data::decode(bytes).unwrap();
        assert_eq!(*data.name, n);
        assert_eq!(data.content().map(|b| b.as_ref()), Some(content.as_ref()));
    }

    #[test]
    fn data_freshness_is_zero() {
        use std::time::Duration;
        let n = name(&[b"test"]);
        let bytes = encode_data_unsigned(&n, b"hello");
        let data = Data::decode(bytes).unwrap();
        let mi = data.meta_info().expect("meta_info present");
        assert_eq!(mi.freshness_period, Some(Duration::from_millis(0)));
    }

    #[test]
    fn nack_roundtrip() {
        use crate::{Nack, NackReason};
        let n = name(&[b"test", b"nack"]);
        let interest_wire = encode_interest(&n, None);
        let nack_wire = encode_nack(NackReason::NoRoute, &interest_wire);
        let nack = Nack::decode(nack_wire).unwrap();
        assert_eq!(nack.reason, NackReason::NoRoute);
        assert_eq!(*nack.interest.name, n);
    }

    #[test]
    fn nack_congestion_roundtrip() {
        use crate::{Nack, NackReason};
        let n = name(&[b"hello"]);
        let interest_wire = encode_interest(&n, None);
        let nack_wire = encode_nack(NackReason::Congestion, &interest_wire);
        let nack = Nack::decode(nack_wire).unwrap();
        assert_eq!(nack.reason, NackReason::Congestion);
    }

    #[test]
    fn ensure_nonce_adds_when_missing() {
        // Build Interest without Nonce.
        let n = name(&[b"test"]);
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::INTEREST, |w| {
            write_name(w, &n);
            w.write_tlv(tlv_type::INTEREST_LIFETIME, &4000u64.to_be_bytes());
        });
        let no_nonce = w.finish();
        let interest = Interest::decode(no_nonce.clone()).unwrap();
        assert!(interest.nonce().is_none());

        let with_nonce = ensure_nonce(&no_nonce);
        let interest2 = Interest::decode(with_nonce).unwrap();
        assert!(interest2.nonce().is_some());
    }

    #[test]
    fn ensure_nonce_preserves_existing() {
        let n = name(&[b"test"]);
        let bytes = encode_interest(&n, None);
        let original_nonce = Interest::decode(bytes.clone()).unwrap().nonce();
        let result = ensure_nonce(&bytes);
        assert_eq!(result, bytes); // unchanged
        let after = Interest::decode(result).unwrap().nonce();
        assert_eq!(original_nonce, after);
    }

    #[test]
    fn nonces_are_unique() {
        let n = name(&[b"test"]);
        let b1 = encode_interest(&n, None);
        let b2 = encode_interest(&n, None);
        let i1 = Interest::decode(b1).unwrap();
        let i2 = Interest::decode(b2).unwrap();
        // Sequential calls should produce different nonces.
        assert_ne!(i1.nonce(), i2.nonce());
    }

    // ── InterestBuilder ──────────────────────────────────────────────────────

    #[test]
    fn interest_builder_basic() {
        let wire = InterestBuilder::new("/ndn/test").build();
        let interest = Interest::decode(wire).unwrap();
        assert_eq!(interest.name.to_string(), "/ndn/test");
        assert!(interest.nonce().is_some());
        assert_eq!(interest.lifetime(), Some(Duration::from_millis(4000)));
    }

    #[test]
    fn interest_builder_custom_lifetime() {
        let wire = InterestBuilder::new("/test")
            .lifetime(Duration::from_millis(2000))
            .build();
        let interest = Interest::decode(wire).unwrap();
        assert_eq!(interest.lifetime(), Some(Duration::from_millis(2000)));
    }

    #[test]
    fn interest_builder_from_str() {
        // Verify &str -> Name conversion works.
        let wire = InterestBuilder::new("/a/b/c").build();
        let interest = Interest::decode(wire).unwrap();
        assert_eq!(interest.name.len(), 3);
    }

    // ── DataBuilder ──────────────────────────────────────────────────────────

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

        // Minimal single-poll executor — our sign_fn completes immediately.
        struct NoopWaker;
        impl Wake for NoopWaker { fn wake(self: std::sync::Arc<Self>) {} }
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
        assert_eq!(data.content().map(|b| b.as_ref()), Some(b"payload".as_ref()));

        let si = data.sig_info().expect("sig info");
        assert_eq!(si.sig_type, SignatureType::SignatureEd25519);
        let kl = si.key_locator.clone().expect("key locator");
        assert_eq!(kl.to_string(), "/key/test");
    }
}
