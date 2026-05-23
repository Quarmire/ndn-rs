use ndn_packet::Data;

/// The trust path used to validate a `SafeData`.
#[derive(Clone, Debug)]
pub enum TrustPath {
    /// Validated via full certificate chain.
    CertChain(Vec<ndn_packet::Name>),
    /// Trusted because it arrived on a local face with known process credentials.
    LocalFace { uid: u32 },
    /// Validated by verifying `SHA-256(signed_region) == sig_value`.
    /// No key or trust anchor involved — self-contained integrity check only.
    DigestSha256,
}

/// A Data packet whose signature has been verified.
///
/// Only constructible by `Validator::validate()` or the local-trust fast
/// path (`SafeData::from_local_trusted`); the `pub(crate)` constructor
/// prevents application code from bypassing verification.
///
/// Application callbacks receive `SafeData`, not `Data`, so the compiler
/// enforces that unverified data cannot flow where verified data is
/// required. The forwarding pipeline propagates the trust verdict via
/// `PacketContext::verified` to the CS admission gate.
#[derive(Debug)]
pub struct SafeData {
    pub(crate) inner: Data,
    pub(crate) trust_path: TrustPath,
    pub(crate) verified_at: u64,
}

impl SafeData {
    /// Construct from a Data packet that arrived on a trusted local face,
    /// bypassing crypto verification.
    #[allow(dead_code)]
    pub(crate) fn from_local_trusted(data: Data, uid: u32) -> Self {
        Self {
            inner: data,
            trust_path: TrustPath::LocalFace { uid },
            verified_at: now_ns(),
        }
    }

    pub fn data(&self) -> &Data {
        &self.inner
    }

    pub fn trust_path(&self) -> &TrustPath {
        &self.trust_path
    }

    pub fn verified_at(&self) -> u64 {
        self.verified_at
    }
}

#[allow(dead_code)]
fn now_ns() -> u64 {
    use web_time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_data() -> Data {
        use ndn_tlv::TlvWriter;
        let nc = {
            let mut w = TlvWriter::new();
            w.write_tlv(0x08, b"test");
            w.finish()
        };
        let name_tlv = {
            let mut w = TlvWriter::new();
            w.write_tlv(0x07, &nc);
            w.finish()
        };
        let data_bytes = {
            let mut w = TlvWriter::new();
            w.write_tlv(0x06, &name_tlv);
            w.finish()
        };
        Data::decode(data_bytes).unwrap()
    }

    #[test]
    fn from_local_trusted_sets_uid() {
        let data = minimal_data();
        let safe = SafeData::from_local_trusted(data, 1000);
        assert!(matches!(
            safe.trust_path(),
            TrustPath::LocalFace { uid: 1000 }
        ));
    }

    #[test]
    fn from_local_trusted_verified_at_is_nonzero() {
        let data = minimal_data();
        let safe = SafeData::from_local_trusted(data, 0);
        assert!(safe.verified_at() > 0);
    }

    #[test]
    fn data_accessor_returns_inner() {
        let data = minimal_data();
        let name_before = data.name.clone();
        let safe = SafeData::from_local_trusted(data, 0);
        assert_eq!(safe.data().name, name_before);
    }
}
