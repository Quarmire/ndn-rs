//! Onboarding artefacts: the anchor [`anchor_fingerprint`], the verified,
//! TOFU-gated [`adopt_with_tofu`], RDR metadata naming for the published
//! context, and the privacy-preserving link-local [`AnchorAdvert`].
//!
//! A node does not "join a network" — it *adopts* an anchor-rooted
//! [`SignedTrustContext`]. The one irreducible bit a face cannot give for free is
//! **root authenticity**. An out-of-band `ndn-trust://anchor/…` envelope
//! (`ndn_trust_envelope::TrustEnvelope::Anchor`, a QR / deep link, *not* an NDN
//! wire packet) carries that bit: the namespace and the root anchor's
//! **fingerprint** (a public hash, not a secret), optionally with the signed
//! context Data inline. Adoption is never automatic — the context Data's
//! signature must verify under the anchor whose fingerprint was pinned out of
//! band (TOFU), so neither a flooded fake advert nor a tampered context (e.g. a
//! weakened schema riding a genuine anchor) can poison a keyring. See
//! `docs/wiki/src/reference/trust-policies.md`.

use std::sync::Arc;

use bytes::Bytes;
use ndn_packet::{Data, Name, NameComponent, SignatureType};
use ndn_security::{
    Certificate, Keyring, SignedTrustContext, SignedTrustContextError, VerifyOutcome,
};
use ndn_trust_envelope::TrustEnvelope;
use sha2::{Digest, Sha256};

/// The RDR keyword component naming a published context: `/<ns>/32=trust-context`.
/// Canonical definition lives in `ndn-security` (the `SignedTrustContext`
/// owner); re-exported here so there is one source of truth.
pub const TRUST_CONTEXT_KEYWORD: &[u8] = ndn_security::trust_context::TRUST_CONTEXT_KEYWORD;
/// The RDR metadata keyword (`32=metadata`).
pub const METADATA_KEYWORD: &[u8] = b"metadata";

/// SHA-256 over an anchor's public key — the public fingerprint an anchor
/// envelope commits to. (Public-key, not full-cert, so a re-issued anchor cert
/// for the same key keeps the same fingerprint.)
pub fn anchor_fingerprint(cert: &Certificate) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(&cert.public_key);
    h.finalize().into()
}

/// The RDR metadata name: `/<namespace>/32=trust-context/32=metadata`. The
/// versioned context itself is named by [`SignedTrustContext::rdr_name`].
pub fn rdr_metadata_name(namespace: &Name) -> Name {
    namespace
        .clone()
        .append_component(NameComponent::keyword(Bytes::from_static(
            TRUST_CONTEXT_KEYWORD,
        )))
        .append_component(NameComponent::keyword(Bytes::from_static(METADATA_KEYWORD)))
}

/// Why a trust context was not adopted.
#[derive(Debug, thiserror::Error)]
pub enum AdoptError {
    #[error("context Data is not a decodable NDN Data packet: {0}")]
    BadData(String),
    #[error("context Data name {0} is not /<namespace>/32=trust-context/v=<version>")]
    BadName(String),
    #[error("context Data carries no Content")]
    MissingContent,
    #[error("malformed trust context: {0}")]
    Malformed(#[from] SignedTrustContextError),
    #[error("context namespace {found} does not match the pinned namespace {pinned}")]
    NamespaceMismatch { pinned: String, found: String },
    #[error("context Data carries no KeyLocator naming its signer")]
    MissingKeyLocator,
    #[error("context signer {0} is not one of the context's own anchors")]
    SignerNotAnchor(String),
    #[error("context signer {0} does not match the pinned anchor fingerprint")]
    FingerprintMismatch(String),
    #[error("no anchor of the context matches the pinned fingerprint")]
    NoPinnedAnchor,
    #[error("context signature type {0} is not a public-key signature")]
    UnsupportedSignature(u64),
    #[error("context signature does not verify under anchor {0}")]
    BadSignature(String),
    #[error("refused: context version {offered} is older than the held version {held}")]
    Rollback { offered: u64, held: u64 },
    #[error("expected an anchor envelope, got a {0} envelope")]
    NotAnchor(&'static str),
    #[error("anchor envelope carries no {0} to pin")]
    MissingPin(&'static str),
    #[error("anchor envelope carries an invalid namespace {0:?}")]
    BadNamespace(String),
    #[error(
        "anchor envelope carries only a fingerprint: the signed context must be inline \
         for offline adoption (fetch it from the namespace and retry)"
    )]
    InlineContextRequired,
    #[error(
        "anchor envelope carries an unsigned legacy context; its integrity cannot be \
         verified, so it is not adopted (re-issue the envelope with a signed context)"
    )]
    UnsignedLegacyContext,
}

/// Decode and authenticate a signed trust-context Data: it must be named at
/// its own context's RDR name (`/<ns>/32=trust-context/v=<version>`) and carry
/// a public-key signature that verifies under one of the anchors the context
/// itself lists. Returns the context and the anchor that signed it.
///
/// This only proves *self-consistency* (the context is exactly what its anchor
/// signed). Whether that anchor is trusted is the caller's decision —
/// [`adopt_with_tofu`] pins it against an out-of-band fingerprint.
pub fn open_signed_context(data: &Data) -> Result<(SignedTrustContext, Certificate), AdoptError> {
    let version = data
        .name
        .components()
        .last()
        .and_then(NameComponent::as_version)
        .ok_or_else(|| AdoptError::BadName(data.name.to_string()))?;
    let content = data.content().ok_or(AdoptError::MissingContent)?;
    let ctx = SignedTrustContext::decode_content(content, version)?;
    if *data.name != ctx.rdr_name() {
        return Err(AdoptError::BadName(data.name.to_string()));
    }

    let sig_info = data.sig_info().ok_or(AdoptError::MissingKeyLocator)?;
    let signer = sig_info
        .key_locator_name()
        .ok_or(AdoptError::MissingKeyLocator)?;
    // Exact anchor (cert) name first, else the anchor cert under the signer's
    // key name (`/<id>/KEY/<k>` locating `/<id>/KEY/<k>/<issuer>/<v>`).
    let anchor = ctx
        .anchors()
        .get(&signer)
        .map(|r| r.value().clone())
        .or_else(|| {
            ctx.anchors()
                .iter()
                .find(|r| r.key().has_prefix(&signer))
                .map(|r| r.value().clone())
        })
        .ok_or_else(|| AdoptError::SignerNotAnchor(signer.to_string()))?;

    // Only public-key signatures authenticate a signer; a digest or shared-key
    // MAC would let anyone re-sign a tampered context.
    match sig_info.sig_type {
        SignatureType::SignatureEd25519
        | SignatureType::SignatureSha256WithEcdsa
        | SignatureType::SignatureSha256WithRsa => {}
        other => return Err(AdoptError::UnsupportedSignature(other.code())),
    }
    // The verifiers never suspend; drive the future inline.
    let outcome = futures::executor::block_on(ndn_security::verifier::verify_by_sig_type(
        sig_info.sig_type,
        data.signed_region(),
        data.sig_value(),
        &anchor.public_key,
    ));
    match outcome {
        Ok(VerifyOutcome::Valid) => Ok((ctx, anchor)),
        _ => Err(AdoptError::BadSignature(anchor.name.to_string())),
    }
}

/// Adopt the signed context `context_data` into `keyring` **only** if it
/// roots `namespace`, its signature verifies, and the anchor that signed it
/// matches the out-of-band `fingerprint` (TOFU). This is the sole sanctioned
/// path from "received a context" to "trust a context": a context whose
/// signing anchor was not authenticated out-of-band (QR/NFC/pre-baked), or
/// whose content was altered after signing, never enters the keyring.
pub fn adopt_with_tofu(
    keyring: &Keyring,
    context_data: &Data,
    namespace: &Name,
    fingerprint: &[u8; 32],
) -> Result<Arc<SignedTrustContext>, AdoptError> {
    let (ctx, signer) = open_signed_context(context_data)?;
    // The pinned namespace must match the context it claims to root.
    if ctx.namespace() != namespace {
        return Err(AdoptError::NamespaceMismatch {
            pinned: namespace.to_string(),
            found: ctx.namespace().to_string(),
        });
    }
    if &anchor_fingerprint(&signer) != fingerprint {
        return Err(AdoptError::FingerprintMismatch(signer.name.to_string()));
    }
    adopt_into(keyring, ctx)
}

/// [`adopt_with_tofu`] driven by a scanned anchor envelope: the envelope must
/// pin a namespace and fingerprint and carry the signed context inline.
/// Fingerprint-only envelopes ([`AdoptError::InlineContextRequired`]) and
/// unsigned legacy content ([`AdoptError::UnsignedLegacyContext`]) are refused.
/// Returns the adopted context and its signed Data (for persistence).
pub fn adopt_anchor_envelope(
    keyring: &Keyring,
    envelope: &TrustEnvelope,
) -> Result<(Arc<SignedTrustContext>, Data), AdoptError> {
    let TrustEnvelope::Anchor {
        namespace,
        fingerprint,
        context_data,
        context_content,
        ..
    } = envelope
    else {
        return Err(AdoptError::NotAnchor(envelope.kind().as_str()));
    };
    let namespace = namespace.as_deref().ok_or(AdoptError::MissingPin("namespace"))?;
    let pinned: Name = namespace
        .parse()
        .map_err(|_| AdoptError::BadNamespace(namespace.to_string()))?;
    let fingerprint = fingerprint.ok_or(AdoptError::MissingPin("anchor fingerprint"))?;
    let wire = match (context_data, context_content) {
        (Some(wire), _) => wire,
        (None, Some(_)) => return Err(AdoptError::UnsignedLegacyContext),
        (None, None) => return Err(AdoptError::InlineContextRequired),
    };
    let data = Data::decode(wire.clone()).map_err(|e| AdoptError::BadData(e.to_string()))?;
    let ctx = adopt_with_tofu(keyring, &data, &pinned, &fingerprint)?;
    Ok((ctx, data))
}

/// **Explicit opt-in, unverified.** Adopt a legacy *unsigned* context
/// (`encode_content()` / `ndn-ctx:1:` payloads) if it roots `namespace` and
/// any of its anchors matches `fingerprint`. Nothing authenticates the schema,
/// revocations or CA endpoints of such a context — whoever handed it over
/// could have weakened them — so no default path calls this; use it only when
/// the operator has deliberately chosen to trust the unsigned payload.
pub fn adopt_unsigned_legacy_with_tofu(
    keyring: &Keyring,
    ctx: SignedTrustContext,
    namespace: &Name,
    fingerprint: &[u8; 32],
) -> Result<Arc<SignedTrustContext>, AdoptError> {
    if ctx.namespace() != namespace {
        return Err(AdoptError::NamespaceMismatch {
            pinned: namespace.to_string(),
            found: ctx.namespace().to_string(),
        });
    }
    let matches = ctx
        .anchors()
        .iter()
        .any(|r| &anchor_fingerprint(r.value()) == fingerprint);
    if !matches {
        return Err(AdoptError::NoPinnedAnchor);
    }
    adopt_into(keyring, ctx)
}

/// Hand `ctx` to the keyring's anti-rollback adoption, surfacing a refusal.
pub(crate) fn adopt_into(
    keyring: &Keyring,
    ctx: SignedTrustContext,
) -> Result<Arc<SignedTrustContext>, AdoptError> {
    let ctx = Arc::new(ctx);
    if keyring.adopt(Arc::clone(&ctx)) {
        Ok(ctx)
    } else {
        Err(AdoptError::Rollback {
            offered: ctx.version(),
            held: keyring.version_of(ctx.namespace()).unwrap_or_default(),
        })
    }
}

/// Whether a node advertises its contexts on the link by default.
///
/// **Off by default** (N3 privacy): silent adopt/consume is the norm; only a
/// hub/rendezvous opts in. A passive listener of a non-advertising node sees
/// nothing.
#[derive(Clone, Copy, Debug, Default)]
pub struct AdvertConfig {
    pub enabled: bool,
}

/// A cold-discovery advertisement carried on the link-local
/// `/localhop/trust-context` prefix. It exposes **only** an opaque anchor
/// fingerprint — never the namespace in cleartext — so a passive listener
/// cannot learn which namespaces a node holds. Discovery-by-namespace is
/// pull-only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorAdvert {
    pub fingerprint: [u8; 32],
}

impl AnchorAdvert {
    /// Build an advert from a context's first anchor. Returns `None` for an
    /// anchorless context.
    pub fn from_context(ctx: &SignedTrustContext) -> Option<Self> {
        ctx.anchors().iter().next().map(|r| Self {
            fingerprint: anchor_fingerprint(r.value()),
        })
    }

    /// The link-local advert prefix — no namespace, by design.
    pub fn advert_prefix() -> Name {
        "/localhop/trust-context".parse().expect("static name")
    }

    /// The opaque wire payload: just the 32-byte fingerprint.
    pub fn encode(&self) -> Bytes {
        Bytes::copy_from_slice(&self.fingerprint)
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        (bytes.len() == 32).then(|| {
            let mut fp = [0u8; 32];
            fp.copy_from_slice(bytes);
            Self { fingerprint: fp }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[test]
    fn rdr_metadata_name_sits_beside_the_context() {
        let ctx = SignedTrustContext::hierarchical(n("/home/bob")).with_version(3);
        let meta = rdr_metadata_name(ctx.namespace());
        let rdr = ctx.rdr_name();
        // Same `/<ns>/32=trust-context` stem; versioned name vs metadata keyword.
        assert_eq!(meta.len(), rdr.len());
        assert_eq!(
            meta.components()[..meta.len() - 1],
            rdr.components()[..rdr.len() - 1]
        );
    }

    #[test]
    fn advert_carries_no_namespace() {
        let advert = AnchorAdvert {
            fingerprint: [0x11u8; 32],
        };
        let wire = advert.encode();
        assert_eq!(wire.len(), 32);
        assert_eq!(AnchorAdvert::decode(&wire), Some(advert));
        // The advert prefix is link-local and namespace-free.
        assert_eq!(AnchorAdvert::advert_prefix(), n("/localhop/trust-context"));
        assert!(!AdvertConfig::default().enabled);
    }
}
