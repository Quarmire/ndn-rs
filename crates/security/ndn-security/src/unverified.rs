//! [`Unverified<T>`] — the type-level dual of [`SafeData`].
//!
//! `SafeData` means *"this was verified"* and can only be constructed by the
//! [`Validator`], so verification can't be faked. `Unverified<T>` is the other
//! half: it makes *"this was **not** verified"* a state the type system forces
//! you to resolve. A consumer that fetches a `Data` receives it as
//! `Unverified<Data>`; to get a usable value out you must explicitly choose:
//!
//! - [`verify`](Unverified::verify) — validate against a [`Validator`] by the
//!   durable rule Data is judged by everywhere (no clock, cuts honoured),
//!   yielding [`SafeData`] on success (the safe path); for a live reply
//!   whose freshness is the point (an RPC answer),
//!   [`verify_live`](Unverified::verify_live); or
//! - [`trust_unchecked`](Unverified::trust_unchecked) — accept the value
//!   **without** verification, on purpose. The name is deliberately loud and
//!   greppable so an audit can find every bypass; it is never the silent default.
//!
//! This closes the consumer-side footgun where the ergonomic fetch returned raw
//! `Data` that application code silently consumed without validating. The
//! forwarder already enforces "only `SafeData` is forwarded"; this brings the
//! same compiler-enforced discipline to the application consumer path.

use ndn_packet::Data;

use crate::safe_data::TrustPath;
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
    /// The signing certificate chain (or a cut-manifest packet it needs) is
    /// not resolved yet: the validator has no fetcher, or the fetch failed.
    /// Attach a [`CertFetcher`](crate::CertFetcher) or try again later.
    #[error("certificate chain not resolved (no fetcher attached, or the fetch failed)")]
    Pending,
    /// The packet verified only as `DigestSha256` — integrity, not identity. It
    /// carries no authenticated signer, so [`verify`](Unverified::verify) rejects
    /// it by default; use [`verify_allowing_digest`](Unverified::verify_allowing_digest)
    /// to accept integrity-only data on purpose.
    #[error("unauthenticated: DigestSha256 proves integrity, not identity")]
    UnauthenticatedDigest,
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
    /// Validate against `validator` by the **durable** rule
    /// ([`Validator::validate_durable`]), yielding [`SafeData`] for an
    /// **authenticated** packet. The safe path out of `Unverified<Data>`.
    ///
    /// Data is judged as the forwarder and the data layer judge it: the
    /// whole chain to a trust anchor (missing certificates fetched when the
    /// validator has a fetcher), revocations — a key revoked with a cut
    /// keeps what its cut accepts — and never a certificate's validity
    /// period against the reader's clock (except for a key whose role the
    /// context lists in DataRequiresCut). Use [`verify_live`](Self::verify_live)
    /// for a reply whose freshness is the point (an RPC answer).
    ///
    /// A packet that verifies only as `DigestSha256` (integrity, no identity) is
    /// **rejected** with [`VerifyError::UnauthenticatedDigest`] — a valid digest
    /// is not authentication. Use [`verify_allowing_digest`](Self::verify_allowing_digest)
    /// to accept integrity-only data deliberately.
    pub async fn verify(self, validator: &Validator) -> Result<SafeData, VerifyError> {
        let result = validator.validate_durable(&self.inner).await;
        Self::resolve(result, false)
    }

    /// Like [`verify`](Self::verify) but also accepts a `DigestSha256`-only
    /// packet (integrity without identity). Use only in local / integrity-only
    /// contexts where an unauthenticated-but-intact packet is acceptable — never
    /// for data crossing a trust boundary.
    pub async fn verify_allowing_digest(
        self,
        validator: &Validator,
    ) -> Result<SafeData, VerifyError> {
        let result = validator.validate_durable(&self.inner).await;
        Self::resolve(result, true)
    }

    /// Validate a **live** reply — one whose freshness is the point, such
    /// as an RPC answer — by the single-hop live rule
    /// ([`Validator::validate`]): its signer's cached certificate must be
    /// valid now by the reader's clock, and any revocation of the signer
    /// refuses it. Stored or forwarded Data takes [`verify`](Self::verify).
    /// `DigestSha256`-only packets are rejected as by `verify`.
    pub async fn verify_live(self, validator: &Validator) -> Result<SafeData, VerifyError> {
        let result = validator.validate(&self.inner).await;
        Self::resolve(result, false)
    }

    fn resolve(result: ValidationResult, allow_digest: bool) -> Result<SafeData, VerifyError> {
        match result {
            ValidationResult::Valid(safe) => {
                // The validator honestly labels the trust path; the
                // *consumer* policy is that digest-only (integrity, not
                // identity) is not "verified" by default.
                if !allow_digest && matches!(safe.trust_path(), TrustPath::DigestSha256) {
                    return Err(VerifyError::UnauthenticatedDigest);
                }
                Ok(*safe)
            }
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
        let wire =
            DataBuilder::new(ndn_packet::name!("/demo/thing"), b"payload").sign_digest_sha256();
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

    /// `verify` rejects a `DigestSha256`-only packet by default: a valid digest
    /// is integrity, not authentication. (The `Validator` honestly reports the
    /// `DigestSha256` trust path even against an empty schema; the *consumer*
    /// policy here refuses to treat that as "verified".)
    #[tokio::test]
    async fn verify_rejects_digest_only_by_default() {
        let validator = Validator::new(TrustSchema::new());
        let u = Unverified::new(sample_data()); // DigestSha256-signed
        assert!(
            matches!(
                u.verify(&validator).await,
                Err(VerifyError::UnauthenticatedDigest)
            ),
            "digest-only must not pass as authenticated by default"
        );
    }

    /// The deliberate opt-out accepts integrity-only data and yields `SafeData`.
    #[tokio::test]
    async fn verify_allowing_digest_accepts_integrity_only() {
        let validator = Validator::new(TrustSchema::new());
        let u = Unverified::new(sample_data());
        let safe = u
            .verify_allowing_digest(&validator)
            .await
            .expect("opt-in accepts integrity-only data");
        assert_eq!(safe.data().name.to_string(), "/demo/thing");
    }

    /// `/home/bob`: root anchor, and the phone's key certified by the root
    /// with an expired certificate; `edit` shapes the context.
    async fn bob(
        edit: impl FnOnce(crate::SignedTrustContext) -> crate::SignedTrustContext,
    ) -> (Validator, crate::Ed25519Signer) {
        use crate::{CertCache, Certificate, Ed25519Signer, Keyring, SignedTrustContext, Signer};
        use std::sync::Arc;
        let n = |s: &str| -> ndn_packet::Name { s.parse().unwrap() };
        let root = Ed25519Signer::from_seed(&[1; 32], n("/home/bob/KEY/root"));
        let phone = Ed25519Signer::from_seed(&[2; 32], n("/home/bob/member/phone/KEY/k1"));
        let cert = |subject: &Ed25519Signer, issuer_id: &str, until: u64| {
            let name = subject
                .key_name()
                .clone()
                .append(issuer_id)
                .append_version(1);
            let pk = subject.public_key_bytes();
            let root = &root;
            async move {
                let wire = crate::manager::encode_cert_data(&name, &pk, root, 0, until)
                    .await
                    .unwrap();
                Certificate::decode(&Data::decode(wire).unwrap()).unwrap()
            }
        };
        let anchor = cert(&root, "self", u64::MAX).await;
        // NotAfter 2017-07-14: long expired.
        let leaf = cert(&phone, "root", 1_500_000_000_000_000_000).await;
        let ctx = edit(SignedTrustContext::hierarchical(n("/home/bob")).with_version(1));
        assert!(ctx.add_anchor(anchor));
        let keyring = Arc::new(Keyring::new());
        keyring.adopt(Arc::new(ctx)).unwrap();
        let cache = Arc::new(CertCache::new());
        cache.insert(leaf);
        (Validator::with_keyring(keyring, cache, None, 5), phone)
    }

    fn log_entry(seq: u64, by: &crate::Ed25519Signer) -> Data {
        use crate::Signer;
        let name: ndn_packet::Name = "/home/bob/member/phone/log/notes".parse().unwrap();
        let wire = DataBuilder::new(name.append_sequence_num(seq), b"v").sign_sync(
            ndn_packet::SignatureType::SignatureEd25519,
            Some(by.key_name()),
            |region| by.sign_sync(region).unwrap(),
        );
        Data::decode(wire).unwrap()
    }

    /// `verify` judges Data by the durable rule: a certificate expired by
    /// the reader's clock does not refuse it, and a key revoked with a cut
    /// keeps what its cut accepts.
    #[tokio::test]
    async fn verify_judges_data_by_the_durable_rule() {
        let (validator, phone) = bob(|c| c).await;
        let verdict = Unverified::new(log_entry(2, &phone))
            .verify(&validator)
            .await;
        assert!(verdict.is_ok(), "expired certificate: {verdict:?}");

        let key: ndn_packet::Name = "/home/bob/member/phone/KEY/k1".parse().unwrap();
        let mut cut = crate::RevocationCut::new(key.clone());
        cut.add_run(&"/home/bob/member/phone/log/notes".parse().unwrap(), 1, 3);
        let (validator, phone) = bob(|c| c.with_revocation(key).with_revocation_cut(cut)).await;
        let verdict = Unverified::new(log_entry(2, &phone))
            .verify(&validator)
            .await;
        assert!(verdict.is_ok(), "in the cut: {verdict:?}");
        assert!(matches!(
            Unverified::new(log_entry(7, &phone))
                .verify(&validator)
                .await,
            Err(VerifyError::Invalid(TrustError::Revoked { .. }))
        ));
    }

    /// `verify_live` keeps the clock and the all-or-nothing revocation, for
    /// replies whose freshness is the point.
    #[tokio::test]
    async fn verify_live_keeps_the_clock() {
        let (validator, phone) = bob(|c| c).await;
        assert!(matches!(
            Unverified::new(log_entry(2, &phone))
                .verify_live(&validator)
                .await,
            Err(VerifyError::Invalid(TrustError::CertNotFound { .. }))
        ));
    }
}
