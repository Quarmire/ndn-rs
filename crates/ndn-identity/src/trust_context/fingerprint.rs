//! [`Fingerprint`] — SHA-256 over an anchor's canonical signed-region bytes.
//! The primary trust identifier shown to users (QR compare, spoken hash).
//! Labels are navigation; fingerprints are trust.

use sha2::{Digest, Sha256};

use ndn_security::Certificate;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint(pub [u8; 32]);

impl Fingerprint {
    pub fn zero() -> Self {
        Self([0u8; 32])
    }

    /// SHA-256 over the cert's retained signed region (Data minus
    /// SignatureValue). Falls back to the cert name's wire bytes for
    /// test-only certs that never went through the wire codec.
    pub fn of_cert(cert: &Certificate) -> Self {
        let mut hasher = Sha256::new();
        match &cert.signed_region {
            Some(sr) => hasher.update(sr),
            None => hasher.update(cert.name.encode_to_tlv()),
        }
        let out = hasher.finalize();
        let mut a = [0u8; 32];
        a.copy_from_slice(&out);
        Self(a)
    }

    pub fn short(&self) -> String {
        let mut s = String::with_capacity(8);
        for b in &self.0[..4] {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

impl std::fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Fingerprint(")?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

impl std::fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}
