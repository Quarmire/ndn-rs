use std::time::Duration;

use bytes::Bytes;
use ndn_tlv::{TlvReader, TlvWriter};

use super::{next_nonce, nni, rand_nonce_bytes, write_name, write_nni};
use crate::{Name, SignatureType, tlv_type};


pub fn encode_interest(name: &Name, app_params: Option<&[u8]>) -> Bytes {
    let mut w = TlvWriter::new();
    w.write_nested(tlv_type::INTEREST, |w| {
        if let Some(params) = app_params {
            let mut params_tlv = TlvWriter::new();
            params_tlv.write_tlv(tlv_type::APP_PARAMETERS, params);
            let params_wire = params_tlv.finish();
            let digest = ring::digest::digest(&ring::digest::SHA256, &params_wire);

            w.write_nested(tlv_type::NAME, |w| {
                for comp in name.components() {
                    w.write_tlv(comp.typ, &comp.value);
                }
                w.write_tlv(tlv_type::PARAMETERS_SHA256, digest.as_ref());
            });
            w.write_tlv(tlv_type::NONCE, &next_nonce().to_be_bytes());
            write_nni(w, tlv_type::INTEREST_LIFETIME, 4000);
            w.write_tlv(tlv_type::APP_PARAMETERS, params);
        } else {
            write_name(w, name);
            w.write_tlv(tlv_type::NONCE, &next_nonce().to_be_bytes());
            write_nni(w, tlv_type::INTEREST_LIFETIME, 4000);
        }
    });
    w.finish()
}

/// Per RFC 8569 §4.2, a forwarder MUST add a Nonce before forwarding.
pub fn ensure_nonce(interest_wire: &Bytes) -> Bytes {
    let mut reader = TlvReader::new(interest_wire.clone());
    let Ok((typ, value)) = reader.read_tlv() else {
        return interest_wire.clone();
    };
    if typ != tlv_type::INTEREST {
        return interest_wire.clone();
    }

    let mut inner = TlvReader::new(value.clone());
    while !inner.is_empty() {
        let Ok((t, _)) = inner.read_tlv() else { break };
        if t == tlv_type::NONCE {
            return interest_wire.clone();
        }
    }

    let mut w = TlvWriter::new();
    w.write_nested(tlv_type::INTEREST, |w| {
        let mut inner = TlvReader::new(value);
        let mut name_written = false;
        while !inner.is_empty() {
            let Ok((t, v)) = inner.read_tlv() else { break };
            w.write_tlv(t, &v);
            if !name_written && t == tlv_type::NAME {
                w.write_tlv(tlv_type::NONCE, &next_nonce().to_be_bytes());
                name_written = true;
            }
        }
        if !name_written {
            w.write_tlv(tlv_type::NONCE, &next_nonce().to_be_bytes());
        }
    });
    w.finish()
}


/// ```
/// # use ndn_packet::encode::InterestBuilder;
/// # use std::time::Duration;
/// let wire = InterestBuilder::new("/ndn/test")
///     .lifetime(Duration::from_millis(2000))
///     .must_be_fresh()
///     .build();
/// ```
pub struct InterestBuilder {
    name: Name,
    lifetime: Option<Duration>,
    can_be_prefix: bool,
    must_be_fresh: bool,
    hop_limit: Option<u8>,
    app_parameters: Option<Vec<u8>>,
    forwarding_hint: Option<Vec<Name>>,
}

impl InterestBuilder {
    pub fn new(name: impl Into<Name>) -> Self {
        Self {
            name: name.into(),
            lifetime: None,
            can_be_prefix: false,
            must_be_fresh: false,
            hop_limit: None,
            app_parameters: None,
            forwarding_hint: None,
        }
    }

    pub fn lifetime(mut self, d: Duration) -> Self {
        self.lifetime = Some(d);
        self
    }

    pub fn can_be_prefix(mut self) -> Self {
        self.can_be_prefix = true;
        self
    }

    pub fn must_be_fresh(mut self) -> Self {
        self.must_be_fresh = true;
        self
    }

    pub fn hop_limit(mut self, h: u8) -> Self {
        self.hop_limit = Some(h);
        self
    }

    pub fn app_parameters(mut self, p: impl Into<Vec<u8>>) -> Self {
        self.app_parameters = Some(p.into());
        self
    }

    pub fn forwarding_hint(mut self, names: Vec<Name>) -> Self {
        self.forwarding_hint = Some(names);
        self
    }

    /// Returns `(wire, timeout)` where timeout is lifetime + 500ms buffer.
    pub fn build_with_timeout(self) -> (Bytes, std::time::Duration) {
        let lifetime = self
            .lifetime
            .unwrap_or(std::time::Duration::from_millis(4000));
        let timeout = lifetime + std::time::Duration::from_millis(500);
        (self.build(), timeout)
    }

    pub fn build(self) -> Bytes {
        let lifetime_ms = self.lifetime.map(|d| d.as_millis() as u64).unwrap_or(4000);

        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::INTEREST, |w| {
            if let Some(ref params) = self.app_parameters {
                let mut params_tlv = TlvWriter::new();
                params_tlv.write_tlv(tlv_type::APP_PARAMETERS, params);
                let params_wire = params_tlv.finish();
                let digest = ring::digest::digest(&ring::digest::SHA256, &params_wire);

                w.write_nested(tlv_type::NAME, |w| {
                    for comp in self.name.components() {
                        w.write_tlv(comp.typ, &comp.value);
                    }
                    w.write_tlv(tlv_type::PARAMETERS_SHA256, digest.as_ref());
                });
            } else {
                write_name(w, &self.name);
            }
            if self.can_be_prefix {
                w.write_tlv(tlv_type::CAN_BE_PREFIX, &[]);
            }
            if self.must_be_fresh {
                w.write_tlv(tlv_type::MUST_BE_FRESH, &[]);
            }
            if let Some(ref hints) = self.forwarding_hint {
                w.write_nested(tlv_type::FORWARDING_HINT, |w| {
                    for h in hints {
                        write_name(w, h);
                    }
                });
            }
            w.write_tlv(tlv_type::NONCE, &next_nonce().to_be_bytes());
            write_nni(w, tlv_type::INTEREST_LIFETIME, lifetime_ms);
            if let Some(h) = self.hop_limit {
                w.write_tlv(tlv_type::HOP_LIMIT, &[h]);
            }
            if let Some(ref params) = self.app_parameters {
                w.write_tlv(tlv_type::APP_PARAMETERS, params);
            }
        });
        w.finish()
    }

    /// Signed Interest per NDN Packet Format v0.3 §5.4. Auto-generates
    /// SignatureNonce and SignatureTime for replay protection.
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
        let (mut signed_region, digest_value_offset, app_params_offset) =
            self.build_signed_interest_region(sig_type, key_locator);
        let sig_value = sign_fn(&signed_region).await;

        let mut sigval_w = TlvWriter::new();
        sigval_w.write_tlv(tlv_type::INTEREST_SIGNATURE_VALUE, &sig_value);
        let sigval_bytes = sigval_w.finish();

        let mut digest_input =
            Vec::with_capacity((signed_region.len() - app_params_offset) + sigval_bytes.len());
        digest_input.extend_from_slice(&signed_region[app_params_offset..]);
        digest_input.extend_from_slice(&sigval_bytes);
        let actual_digest = ring::digest::digest(&ring::digest::SHA256, &digest_input);

        signed_region[digest_value_offset..digest_value_offset + 32]
            .copy_from_slice(actual_digest.as_ref());

        let inner_len = signed_region.len() + sigval_bytes.len();
        let mut outer = TlvWriter::with_capacity(inner_len + 10);
        outer.write_varu64(tlv_type::INTEREST);
        outer.write_varu64(inner_len as u64);
        outer.write_raw(&signed_region);
        outer.write_raw(&sigval_bytes);
        outer.finish()
    }

    /// Minimum signature accepted by NFD for management Interests.
    #[cfg(feature = "std")]
    pub fn sign_digest_sha256(self) -> Bytes {
        self.sign_sync(SignatureType::DigestSha256, None, |region| {
            let digest = ring::digest::digest(&ring::digest::SHA256, region);
            Bytes::copy_from_slice(digest.as_ref())
        })
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
        let (mut signed_region, digest_value_offset, app_params_offset) =
            self.build_signed_interest_region(sig_type, key_locator);
        let sig_value = sign_fn(&signed_region);

        let mut sigval_w = TlvWriter::new();
        sigval_w.write_tlv(tlv_type::INTEREST_SIGNATURE_VALUE, &sig_value);
        let sigval_bytes = sigval_w.finish();

        // SHA-256 over ApplicationParameters + InterestSignatureInfo +
        // InterestSignatureValue TLVs (NDN Packet Format v0.3 §5.4).
        let mut digest_input =
            Vec::with_capacity((signed_region.len() - app_params_offset) + sigval_bytes.len());
        digest_input.extend_from_slice(&signed_region[app_params_offset..]);
        digest_input.extend_from_slice(&sigval_bytes);
        let actual_digest = ring::digest::digest(&ring::digest::SHA256, &digest_input);

        signed_region[digest_value_offset..digest_value_offset + 32]
            .copy_from_slice(actual_digest.as_ref());

        let inner_len = signed_region.len() + sigval_bytes.len();
        let mut outer = TlvWriter::with_capacity(inner_len + 10);
        outer.write_varu64(tlv_type::INTEREST);
        outer.write_varu64(inner_len as u64);
        outer.write_raw(&signed_region);
        outer.write_raw(&sigval_bytes);
        outer.finish()
    }

    /// Returns `(bytes, digest_value_offset, app_params_offset)`. The caller
    /// patches the 32-byte ParametersSha256DigestComponent placeholder after
    /// signing.
    fn build_signed_interest_region(
        self,
        sig_type: SignatureType,
        key_locator: Option<&Name>,
    ) -> (Vec<u8>, usize, usize) {
        let params = self.app_parameters.unwrap_or_default();
        let lifetime_ms = self.lifetime.map(|d| d.as_millis() as u64).unwrap_or(4000);

        let mut inner = TlvWriter::new();

        inner.write_nested(tlv_type::NAME, |w| {
            for comp in self.name.components() {
                w.write_tlv(comp.typ, &comp.value);
            }
            w.write_tlv(tlv_type::PARAMETERS_SHA256, &[0u8; 32]);
        });
        let digest_value_offset = inner.len() - 32;

        if self.can_be_prefix {
            inner.write_tlv(tlv_type::CAN_BE_PREFIX, &[]);
        }
        if self.must_be_fresh {
            inner.write_tlv(tlv_type::MUST_BE_FRESH, &[]);
        }

        if let Some(ref hints) = self.forwarding_hint {
            inner.write_nested(tlv_type::FORWARDING_HINT, |w| {
                for h in hints {
                    write_name(w, h);
                }
            });
        }

        inner.write_tlv(tlv_type::NONCE, &next_nonce().to_be_bytes());
        write_nni(&mut inner, tlv_type::INTEREST_LIFETIME, lifetime_ms);
        if let Some(h) = self.hop_limit {
            inner.write_tlv(tlv_type::HOP_LIMIT, &[h]);
        }

        let app_params_offset = inner.len();

        inner.write_tlv(tlv_type::APP_PARAMETERS, &params);

        inner.write_nested(tlv_type::INTEREST_SIGNATURE_INFO, |w| {
            write_nni(w, tlv_type::SIGNATURE_TYPE, sig_type.code());
            if let Some(kl) = key_locator {
                w.write_nested(tlv_type::KEY_LOCATOR, |w| {
                    write_name(w, kl);
                });
            }
            let nonce_bytes: [u8; 8] = rand_nonce_bytes();
            w.write_tlv(tlv_type::SIGNATURE_NONCE, &nonce_bytes);
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            let (time_buf, time_len) = nni(now_ms);
            w.write_tlv(tlv_type::SIGNATURE_TIME, &time_buf[..time_len]);
        });

        (
            inner.finish().to_vec(),
            digest_value_offset,
            app_params_offset,
        )
    }
}

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


#[cfg(test)]
mod tests {
    use super::super::tests::{assert_bytes_eq, name};
    use super::*;
    use crate::Interest;
    use bytes::Bytes;
    use std::time::Duration;

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
        assert_eq!(interest.name.len(), n.len() + 1);
        for (i, comp) in n.components().iter().enumerate() {
            assert_eq!(interest.name.components()[i], *comp);
        }
        let last = &interest.name.components()[n.len()];
        assert_eq!(last.typ, tlv_type::PARAMETERS_SHA256);
        assert_eq!(last.value.len(), 32);
        assert_eq!(
            interest.app_parameters().map(|b| b.as_ref()),
            Some(params.as_ref())
        );
    }

    #[test]
    fn interest_has_nonce_and_lifetime() {
        let n = name(&[b"test"]);
        let bytes = encode_interest(&n, None);
        let interest = Interest::decode(bytes).unwrap();
        assert!(interest.nonce().is_some());
        assert_eq!(interest.lifetime(), Some(Duration::from_millis(4000)));
    }

    #[test]
    fn ensure_nonce_adds_when_missing() {
        let n = name(&[b"test"]);
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::INTEREST, |w| {
            super::write_name(w, &n);
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
        assert_ne!(i1.nonce(), i2.nonce());
    }


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
        let wire = InterestBuilder::new("/a/b/c").build();
        let interest = Interest::decode(wire).unwrap();
        assert_eq!(interest.name.len(), 3);
    }

    #[test]
    fn interest_builder_app_params_preserves_selectors() {
        let wire = InterestBuilder::new("/cmd")
            .can_be_prefix()
            .must_be_fresh()
            .lifetime(Duration::from_millis(2000))
            .hop_limit(64)
            .app_parameters(b"payload".to_vec())
            .build();
        let interest = Interest::decode(wire).unwrap();
        assert!(interest.selectors().can_be_prefix);
        assert!(interest.selectors().must_be_fresh);
        assert_eq!(interest.lifetime(), Some(Duration::from_millis(2000)));
        assert_eq!(interest.hop_limit(), Some(64));
        assert_eq!(
            interest.app_parameters().map(|b| b.as_ref()),
            Some(b"payload".as_ref())
        );
    }

    #[test]
    fn interest_builder_forwarding_hint() {
        let hint: Name = "/ndn/gateway".parse().unwrap();
        let wire = InterestBuilder::new("/test")
            .forwarding_hint(vec![hint])
            .build();
        let interest = Interest::decode(wire).unwrap();
        let hints = interest.forwarding_hint().expect("forwarding_hint present");
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].to_string(), "/ndn/gateway");
    }

    #[test]
    fn interest_builder_sign_sync_roundtrip() {
        let key_name: Name = "/key/test".parse().unwrap();
        let wire = InterestBuilder::new("/signed/cmd")
            .app_parameters(b"params".to_vec())
            .sign_sync(
                crate::SignatureType::SignatureEd25519,
                Some(&key_name),
                |region| {
                    let digest = ring::digest::digest(&ring::digest::SHA256, region);
                    Bytes::copy_from_slice(digest.as_ref())
                },
            );
        let interest = Interest::decode(wire).unwrap();
        assert_eq!(interest.name.components()[0].value.as_ref(), b"signed");
        assert_eq!(interest.name.components()[1].value.as_ref(), b"cmd");
        let last = interest.name.components().last().unwrap();
        assert_eq!(last.typ, tlv_type::PARAMETERS_SHA256);
        assert_eq!(last.value.len(), 32);
        let si = interest.sig_info().expect("sig_info present");
        assert_eq!(si.sig_type, crate::SignatureType::SignatureEd25519);
        let kl = si.key_locator.as_ref().expect("key locator present");
        assert_eq!(kl.to_string(), "/key/test");
        assert!(interest.sig_value().is_some());
        assert_eq!(
            interest.app_parameters().map(|b| b.as_ref()),
            Some(b"params".as_ref())
        );
    }

    #[test]
    fn interest_builder_sign_sync_auto_anti_replay() {
        let wire = InterestBuilder::new("/cmd").sign_sync(
            crate::SignatureType::SignatureEd25519,
            None,
            |region| {
                Bytes::copy_from_slice(ring::digest::digest(&ring::digest::SHA256, region).as_ref())
            },
        );
        let interest = Interest::decode(wire).unwrap();
        let si = interest.sig_info().expect("sig_info");
        assert!(si.sig_nonce.is_some());
        assert!(si.sig_time.is_some());
    }

    #[test]
    fn interest_builder_sign_sync_empty_params_default() {
        let wire = InterestBuilder::new("/cmd").sign_sync(
            crate::SignatureType::DigestSha256,
            None,
            |region| {
                let d = ring::digest::digest(&ring::digest::SHA256, region);
                Bytes::copy_from_slice(d.as_ref())
            },
        );
        let interest = Interest::decode(wire).unwrap();
        let ap = interest.app_parameters().expect("app_params present");
        assert!(ap.is_empty());
    }

    #[test]
    fn interest_builder_sign_sync_signed_region() {
        let wire = InterestBuilder::new("/test")
            .app_parameters(b"data".to_vec())
            .sign_sync(crate::SignatureType::SignatureEd25519, None, |region| {
                assert_eq!(region[0], tlv_type::NAME as u8);
                Bytes::copy_from_slice(ring::digest::digest(&ring::digest::SHA256, region).as_ref())
            });
        let interest = Interest::decode(wire.clone()).unwrap();
        let region = interest.signed_region().expect("signed region present");
        assert_eq!(region[0], tlv_type::NAME as u8);
        assert!(interest.sig_value().is_some());
    }

    #[test]
    fn interest_builder_sign_async_matches_sync_structure() {
        use std::pin::pin;
        use std::task::{Context, Wake, Waker};

        struct NoopWaker;
        impl Wake for NoopWaker {
            fn wake(self: std::sync::Arc<Self>) {}
        }
        let waker = Waker::from(std::sync::Arc::new(NoopWaker));
        let mut cx = Context::from_waker(&waker);

        let fut = InterestBuilder::new("/test")
            .app_parameters(b"p".to_vec())
            .sign(
                crate::SignatureType::SignatureEd25519,
                None,
                |region: &[u8]| {
                    let d = ring::digest::digest(&ring::digest::SHA256, region);
                    std::future::ready(Bytes::copy_from_slice(d.as_ref()))
                },
            );
        let mut fut = pin!(fut);
        let async_wire = match fut.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(b) => b,
            std::task::Poll::Pending => panic!("should complete immediately"),
        };

        let async_i = Interest::decode(async_wire).unwrap();
        assert!(async_i.sig_info().is_some());
        assert!(async_i.sig_value().is_some());
        assert!(async_i.signed_region().is_some());

        let sync_wire = InterestBuilder::new("/test")
            .app_parameters(b"p".to_vec())
            .sign_sync(crate::SignatureType::SignatureEd25519, None, |region| {
                Bytes::copy_from_slice(ring::digest::digest(&ring::digest::SHA256, region).as_ref())
            });
        let sync_i = Interest::decode(sync_wire).unwrap();
        assert!(sync_i.sig_info().is_some());
        assert!(sync_i.sig_value().is_some());
    }

    #[test]
    fn interest_builder_sign_sync_with_all_options() {
        let hint: Name = "/ndn/relay".parse().unwrap();
        let key_name: Name = "/my/key".parse().unwrap();
        let wire = InterestBuilder::new("/prefix/command")
            .can_be_prefix()
            .must_be_fresh()
            .lifetime(Duration::from_millis(8000))
            .hop_limit(32)
            .forwarding_hint(vec![hint])
            .app_parameters(b"payload".to_vec())
            .sign_sync(
                crate::SignatureType::SignatureEd25519,
                Some(&key_name),
                |region| {
                    Bytes::copy_from_slice(
                        ring::digest::digest(&ring::digest::SHA256, region).as_ref(),
                    )
                },
            );
        let i = Interest::decode(wire).unwrap();
        assert!(i.selectors().can_be_prefix);
        assert!(i.selectors().must_be_fresh);
        assert_eq!(i.lifetime(), Some(Duration::from_millis(8000)));
        assert_eq!(i.hop_limit(), Some(32));
        let hints = i.forwarding_hint().expect("forwarding_hint");
        assert_eq!(hints[0].to_string(), "/ndn/relay");
        assert_eq!(
            i.app_parameters().map(|b| b.as_ref()),
            Some(b"payload".as_ref())
        );
        let si = i.sig_info().expect("sig_info");
        assert_eq!(si.sig_type, crate::SignatureType::SignatureEd25519);
        assert_eq!(si.key_locator.as_ref().unwrap().to_string(), "/my/key");
        assert!(i.sig_value().is_some());
        assert!(i.signed_region().is_some());
    }


    #[test]
    fn wire_interest_nni_lifetime() {
        let wire = encode_interest(&name(&[b"ndn", b"edu"]), None);

        let pos = wire
            .windows(2)
            .position(|w| w == [0x0C, 0x02])
            .expect("InterestLifetime should be type=0x0C len=0x02 (2 bytes)");
        assert_bytes_eq(
            &wire[pos..pos + 4],
            &[0x0C, 0x02, 0x0F, 0xA0],
            "InterestLifetime 4000ms",
        );
    }

    #[test]
    fn wire_interest_structure() {
        let wire = encode_interest(&name(&[b"A"]), None);

        assert_eq!(wire[0], 0x05, "outer type must be Interest (0x05)");

        let name_expected = [0x07, 0x03, 0x08, 0x01, 0x41];
        assert_bytes_eq(&wire[2..7], &name_expected, "Name /A");

        assert_eq!(wire[7], 0x0A, "Nonce type");
        assert_eq!(wire[8], 0x04, "Nonce length");

        assert_bytes_eq(&wire[13..17], &[0x0C, 0x02, 0x0F, 0xA0], "Lifetime");

        assert_eq!(wire.len(), 17, "total Interest length");
    }

    #[test]
    fn wire_interest_builder_selectors() {
        let wire = InterestBuilder::new("/A")
            .can_be_prefix()
            .must_be_fresh()
            .lifetime(Duration::from_millis(1000))
            .build();

        let after_name = 7;
        assert_bytes_eq(
            &wire[after_name..after_name + 2],
            &[0x21, 0x00],
            "CanBePrefix",
        );
        assert_bytes_eq(
            &wire[after_name + 2..after_name + 4],
            &[0x12, 0x00],
            "MustBeFresh",
        );
        assert_eq!(wire[after_name + 4], 0x0A, "Nonce type");
        let lt_pos = after_name + 4 + 6;
        assert_bytes_eq(
            &wire[lt_pos..lt_pos + 4],
            &[0x0C, 0x02, 0x03, 0xE8],
            "Lifetime 1000ms",
        );
    }

    #[test]
    fn wire_ndnd_interest_decode() {
        let ndnd_wire: &[u8] = &[
            0x05, 0x16, 0x07, 0x0A, 0x08, 0x03, 0x6E, 0x64, 0x6E, 0x08, 0x03, 0x65, 0x64, 0x75,
            0x0A, 0x04, 0x01, 0x02, 0x03, 0x04, 0x0C, 0x02, 0x0F, 0xA0,
        ];
        let interest = Interest::decode(Bytes::from_static(ndnd_wire)).unwrap();
        assert_eq!(interest.name.to_string(), "/ndn/edu");
        assert_eq!(interest.nonce(), Some(0x01020304));
        assert_eq!(interest.lifetime(), Some(Duration::from_millis(4000)));
    }

    #[test]
    fn wire_ndnd_interest_1byte_lifetime_decode() {
        let ndnd_wire: &[u8] = &[
            0x05, 0x15, 0x07, 0x0A, 0x08, 0x03, 0x6E, 0x64, 0x6E, 0x08, 0x03, 0x65, 0x64, 0x75,
            0x0A, 0x04, 0x00, 0x00, 0x00, 0x01, 0x0C, 0x01, 0x64,
        ];
        let interest = Interest::decode(Bytes::from_static(ndnd_wire)).unwrap();
        assert_eq!(interest.lifetime(), Some(Duration::from_millis(100)));
    }

    #[test]
    fn wire_ndnd_interest_4byte_lifetime_decode() {
        let ndnd_wire: &[u8] = &[
            0x05, 0x18, 0x07, 0x0A, 0x08, 0x03, 0x6E, 0x64, 0x6E, 0x08, 0x03, 0x65, 0x64, 0x75,
            0x0A, 0x04, 0x00, 0x00, 0x00, 0x01, 0x0C, 0x04, 0x00, 0x01, 0x86, 0xA0,
        ];
        let interest = Interest::decode(Bytes::from_static(ndnd_wire)).unwrap();
        assert_eq!(interest.lifetime(), Some(Duration::from_millis(100000)));
    }
}
