//! [`Unverified<T>`] — the type-level dual of [`SafeData`].
//!
//! `SafeData` means *"this was verified"* and can only be constructed by the
//! [`Validator`], so verification can't be faked. `Unverified<T>` is the other
//! half: it makes *"this was **not** verified"* a state the type system forces
//! you to resolve. A consumer that fetches a `Data` receives it as
//! `Unverified<Data>`; to get a usable value out you must explicitly choose:
//!
//! - [`verify`](Unverified::verify) — validate against a [`Validator`], yielding
//!   [`SafeData`] on success (the safe path); or
//! - [`trust_unchecked`](Unverified::trust_unchecked) — accept the value
//!   **without** verification, on purpose. The name is deliberately loud and
//!   greppable so an audit can find every bypass; it is never the silent default.
//!
//! This closes the consumer-side footgun where the ergonomic fetch returned raw
//! `Data` that application code silently consumed without validating. The
//! forwarder already enforces "only `SafeData` is forwarded"; this brings the
//! same compiler-enforced discipline to the application consumer path.

use ndn_packet::Data;

use crate::{SafeData, TrustError, ValidationResult, Validator};

/// A value whose signature has **not** been verified. See the module docs for
/// the two ways out: [`verify`](Self::verify) or [`trust_unchecked`](Self::trust_unchecked).
///
/// Freely constructible on purpose — "unverified" is the safe (pessimistic)
/// state to be in. The guarded invariant lives on the other side: [`SafeData`]
/// cannot be forged.
#[derive(Debug)]
pub struct Unverified<T> {
    inner: T,
}

/// Why [`Unverified::verify`] did not yield [`SafeData`].
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// Signature was cryptographically invalid, or the trust schema rejected it.
    #[error("verification failed: {0}")]
    Invalid(TrustError),
    /// The signing certificate chain is not yet resolved (async fetch pending).
    #[error("certificate chain not resolved")]
    Pending,
}

impl<T> Unverified<T> {
    /// Wrap an unverified value. Producers of fetched data construct this; an
    /// application typically *receives* it rather than building it.
    pub fn new(inner: T) -> Self {
        Self { inner }
    }

    /// Borrow the value for inspection — e.g. to read a `Data`'s name to choose
    /// a validator — without consuming the wrapper or claiming any trust.
    pub fn peek(&self) -> &T {
        &self.inner
    }

    /// Deliberately accept the value **without verification**. Use only where no
    /// trust schema applies: local in-process delivery, tests, research. Loud
    /// and greppable by design — this is the one bypass, and it is never silent.
    pub fn trust_unchecked(self) -> T {
        self.inner
    }
}

impl Unverified<Data> {
    /// Validate against `validator`, yielding [`SafeData`] on success. The safe
    /// path out of `Unverified<Data>`.
    pub async fn verify(self, validator: &Validator) -> Result<SafeData, VerifyError> {
        match validator.validate(&self.inner).await {
            ValidationResult::Valid(safe) => Ok(*safe),
            ValidationResult::Invalid(e) => Err(VerifyError::Invalid(e)),
            ValidationResult::Pending => Err(VerifyError::Pending),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TrustSchema;
    use ndn_packet::Data;
    use ndn_packet::encode::DataBuilder;

    fn sample_data() -> Data {
        let wire = DataBuilder::new("/demo/thing", b"payload").sign_digest_sha256();
        Data::decode(wire).expect("decode sample data")
    }

    #[test]
    fn peek_borrows_without_consuming() {
        let u = Unverified::new(sample_data());
        assert_eq!(u.peek().name.to_string(), "/demo/thing");
        // Still usable after peek — peek does not consume.
        let d = u.trust_unchecked();
        assert_eq!(d.name.to_string(), "/demo/thing");
    }

    #[test]
    fn trust_unchecked_is_the_explicit_bypass() {
        let u = Unverified::new(sample_data());
        let d = u.trust_unchecked();
        assert_eq!(d.name.to_string(), "/demo/thing");
    }

    /// The safe path out: `verify` yields `SafeData` (the only non-bypass way to
    /// a usable value). We use a DigestSha256 packet — which validates on
    /// self-contained integrity — to avoid a cert+schema fixture here.
    ///
    /// FINDING for the safe-by-default foundation work: an *empty* `TrustSchema`
    /// with no anchors accepts a DigestSha256 packet as `Valid`. DigestSha256
    /// proves integrity, not identity, so an empty/permissive schema treating it
    /// as verified is itself an authenticity footgun — track separately; it is a
    /// `Validator` policy question, not this primitive's.
    #[tokio::test]
    async fn verify_yields_safedata_on_the_safe_path() {
        let validator = Validator::new(TrustSchema::new());
        let u = Unverified::new(sample_data());
        let safe = u
            .verify(&validator)
            .await
            .expect("the safe path yields SafeData");
        assert_eq!(safe.data().name.to_string(), "/demo/thing");
    }
}
