use ndn_packet::Data;
use crate::{CertCache, Ed25519Verifier, SafeData, TrustError, TrustSchema, VerifyOutcome};
use crate::verifier::Verifier;

/// Result of a validation attempt.
pub enum ValidationResult {
    /// Signature verified and trust schema satisfied.
    Valid(SafeData),
    /// Signature was cryptographically invalid or schema rejected.
    Invalid(TrustError),
    /// Certificate chain is not yet resolved; validation is async.
    Pending,
}

/// Validates Data packets against a trust schema and certificate chain.
pub struct Validator {
    schema:     TrustSchema,
    cert_cache: CertCache,
    verifier:   Ed25519Verifier,
    max_chain:  usize,
}

impl Validator {
    pub fn new(schema: TrustSchema) -> Self {
        Self {
            schema,
            cert_cache:  CertCache::new(),
            verifier:    Ed25519Verifier,
            max_chain:   5,
        }
    }

    /// Validate a Data packet.
    ///
    /// Returns `ValidationResult::Pending` if certificate fetching is required.
    /// The caller must re-call once the certificate Interest is satisfied.
    pub async fn validate(&self, data: &Data) -> ValidationResult {
        // Retrieve signature info.
        let Some(sig_info) = data.sig_info() else {
            return ValidationResult::Invalid(TrustError::InvalidSignature);
        };
        let Some(key_locator) = &sig_info.key_locator else {
            return ValidationResult::Invalid(TrustError::InvalidSignature);
        };

        // Check trust schema.
        if !self.schema.allows(&data.name, key_locator) {
            return ValidationResult::Invalid(TrustError::SchemaMismatch);
        }

        // Look up the signing certificate.
        let Some(cert) = self.cert_cache.get(key_locator) else {
            return ValidationResult::Pending;
        };

        // Verify signature.
        match self.verifier.verify(
            data.signed_region(),
            data.sig_value(),
            &cert.public_key,
        ).await {
            Ok(VerifyOutcome::Valid) => {
                // Construct SafeData via the privileged constructor.
                let safe = SafeData {
                    inner:       Data::decode(data.raw().clone()).unwrap(),
                    trust_path:  crate::safe_data::TrustPath::CertChain(
                        vec![key_locator.as_ref().clone()]
                    ),
                    verified_at: now_ns(),
                };
                ValidationResult::Valid(safe)
            }
            Ok(VerifyOutcome::Invalid) => ValidationResult::Invalid(TrustError::InvalidSignature),
            Err(e) => ValidationResult::Invalid(e),
        }
    }
}

fn now_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}
