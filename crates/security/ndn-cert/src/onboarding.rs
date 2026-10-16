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
use ndn_packet::encode::InterestBuilder;
use ndn_packet::{Data, Name, NameComponent, SignatureType};
use ndn_security::{
    Certificate, Keyring, SignedTrustContext, SignedTrustContextError, VerifyOutcome,
};
use ndn_tlv::TlvReader;
use ndn_trust_envelope::TrustEnvelope;
use sha2::{Digest, Sha256};

use crate::client::CaExchange;
use crate::error::CertError;

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

/// `/<namespace>/32=trust-context`: the prefix a namespace's context is
/// published under — its versioned Data ([`SignedTrustContext::rdr_name`])
/// and its RDR metadata ([`rdr_metadata_name`]) — so one FIB entry serves both.
pub fn rdr_prefix(namespace: &Name) -> Name {
    namespace
        .clone()
        .append_component(NameComponent::keyword(Bytes::from_static(
            TRUST_CONTEXT_KEYWORD,
        )))
}

/// The RDR metadata name: `/<namespace>/32=trust-context/32=metadata`. The
/// versioned context itself is named by [`SignedTrustContext::rdr_name`].
pub fn rdr_metadata_name(namespace: &Name) -> Name {
    rdr_prefix(namespace).append_component(NameComponent::keyword(Bytes::from_static(METADATA_KEYWORD)))
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

/// TLV type of the Name inside RDR metadata Content.
const TLV_NAME: u64 = 0x07;

/// Why [`fetch_context`] returned no context Data.
#[derive(Debug, thiserror::Error)]
pub enum FetchContextError {
    #[error("fetching {name}: {source}")]
    Transport {
        name: String,
        #[source]
        source: CertError,
    },
    #[error("metadata reply {found} is not under the requested {expected}")]
    MetadataName { expected: String, found: String },
    #[error("metadata Data carries no Content")]
    MetadataEmpty,
    #[error("malformed RDR metadata: {0}")]
    MetadataMalformed(String),
    #[error("metadata points at {found}, which is not {namespace}/32=trust-context/v=<version>")]
    ForeignPointer { namespace: String, found: String },
    #[error("context reply is named {found}, not the announced {expected}")]
    ContextName { expected: String, found: String },
}

/// Fetch the signed trust context `namespace` publishes, by name, over RDR:
///
/// 1. Interest `/<ns>/32=trust-context/32=metadata` (CanBePrefix,
///    MustBeFresh) → metadata Data whose Content is the versioned Name.
/// 2. That Name must be exactly `/<ns>/32=trust-context/v=<N>` under the
///    asked `namespace` ([`context_pointer`]).
/// 3. Interest for that exact name → the context Data, which must carry that
///    exact name.
///
/// The returned Data is **name-checked but not verified**: authenticating it
/// is [`adopt_with_tofu`]'s job (signature under the context's own anchor,
/// anchor pinned by the out-of-band fingerprint, anti-rollback), so it is
/// checked once, at the one place that decides trust.
///
/// The metadata is an unauthenticated pointer and needs no signature check
/// here: the joiner holds nothing but a fingerprint, so it could not verify
/// one anyway. The pointer is confined to `<ns>/32=trust-context/v=<N>`, so
/// a forged one can only point at (a) a forged or foreign context, which
/// fails the fingerprint pin in [`adopt_with_tofu`]; (b) an older genuine
/// version, which the keyring's anti-rollback refuses once a newer one is
/// held; or (c) a name nobody serves, which fails as a fetch error. On first
/// contact (nothing held yet) (b) means adopting an older context the owner
/// did sign; an on-path forger could equally replay an old *signed* metadata
/// Data that named it, so signing the pointer would not close it. The caller
/// closes it by demanding at least the version its envelope names
/// (`TrustEnvelope::Anchor::version`). A forger who can answer Interests can
/// also withhold the context, so the pointer adds no new power.
pub async fn fetch_context<E>(exchange: &mut E, namespace: &Name) -> Result<Data, FetchContextError>
where
    E: CaExchange + ?Sized,
{
    let meta_name = rdr_metadata_name(namespace);
    let meta = exchange
        .express(
            InterestBuilder::new(meta_name.clone())
                .can_be_prefix()
                .must_be_fresh()
                .build(),
        )
        .await
        .map_err(|source| FetchContextError::Transport {
            name: meta_name.to_string(),
            source,
        })?;
    // RDR names the metadata Data `<meta_name>/v=<ver>/seg=0`.
    if !meta.name.has_prefix(&meta_name) {
        return Err(FetchContextError::MetadataName {
            expected: meta_name.to_string(),
            found: meta.name.to_string(),
        });
    }
    let content = meta.content().ok_or(FetchContextError::MetadataEmpty)?;
    let versioned = context_pointer(namespace, content)?;

    let data = exchange
        .express(InterestBuilder::new(versioned.clone()).build())
        .await
        .map_err(|source| FetchContextError::Transport {
            name: versioned.to_string(),
            source,
        })?;
    if *data.name != versioned {
        return Err(FetchContextError::ContextName {
            expected: versioned.to_string(),
            found: data.name.to_string(),
        });
    }
    Ok(data)
}

/// Decode RDR metadata `content` (its Name TLV; other fields, e.g. segment
/// counts, are ignored) and accept the Name only if it is
/// `/<namespace>/32=trust-context/v=<N>`.
pub fn context_pointer(namespace: &Name, content: &Bytes) -> Result<Name, FetchContextError> {
    let mut reader = TlvReader::new(content.clone());
    let mut pointer = None;
    while !reader.is_empty() {
        let (typ, value) = reader
            .read_tlv()
            .map_err(|e| FetchContextError::MetadataMalformed(e.to_string()))?;
        if typ == TLV_NAME {
            pointer = Some(
                Name::decode(value)
                    .map_err(|e| FetchContextError::MetadataMalformed(format!("Name: {e}")))?,
            );
            break;
        }
    }
    let pointer =
        pointer.ok_or_else(|| FetchContextError::MetadataMalformed("no Name".into()))?;
    let prefix = rdr_prefix(namespace);
    let is_context = pointer.len() == prefix.len() + 1
        && pointer.has_prefix(&prefix)
        && pointer
            .components()
            .last()
            .and_then(NameComponent::as_version)
            .is_some();
    if !is_context {
        return Err(FetchContextError::ForeignPointer {
            namespace: namespace.to_string(),
            found: pointer.to_string(),
        });
    }
    Ok(pointer)
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

    /// An in-memory "network": answers an Interest whose name equals a
    /// registered name with that Data wire, records every Interest it saw.
    struct FakeNet {
        replies: Vec<(Name, Bytes)>,
        sent: Vec<ndn_packet::Interest>,
    }

    impl FakeNet {
        fn new(replies: Vec<(Name, Bytes)>) -> Self {
            Self {
                replies,
                sent: Vec::new(),
            }
        }
    }

    impl CaExchange for FakeNet {
        fn express(&mut self, interest: Bytes) -> impl Future<Output = Result<Data, CertError>> + Send {
            let interest = ndn_packet::Interest::decode(interest).expect("well-formed Interest");
            let reply = self
                .replies
                .iter()
                .find(|(name, _)| *name == *interest.name)
                .map(|(_, wire)| Data::decode(wire.clone()).expect("well-formed Data"))
                .ok_or_else(|| CertError::Transport(format!("no reply for {}", interest.name)));
            self.sent.push(interest);
            std::future::ready(reply)
        }
    }

    fn data(name: Name, content: &[u8]) -> Bytes {
        ndn_packet::encode::DataBuilder::new(name, content).build()
    }

    /// RDR metadata Data for `ns` as a publisher names it, with `content`.
    fn metadata(ns: &Name, content: &[u8]) -> (Name, Bytes) {
        let asked = rdr_metadata_name(ns);
        let named = asked.clone().append_version(1).append_segment(0);
        (asked, data(named, content))
    }

    fn hub(ns: &str) -> crate::hub::HubInit {
        crate::hub::init_hub(&ndn_security::SecurityManager::new(), &n(ns)).unwrap()
    }

    #[test]
    fn fetched_context_is_the_asked_namespace_and_passes_tofu() {
        let ns = n("/home/bob");
        let hub = hub("/home/bob");
        let versioned = hub.context.rdr_name();
        let mut net = FakeNet::new(vec![
            metadata(&ns, &versioned.encode_to_tlv()),
            (versioned.clone(), hub.context_data.raw().clone()),
        ]);

        let fetched = futures::executor::block_on(fetch_context(&mut net, &ns)).unwrap();
        assert_eq!(fetched.raw(), hub.context_data.raw());
        let discovery = net.sent[0].selectors();
        assert!(discovery.can_be_prefix && discovery.must_be_fresh);
        assert_eq!(*net.sent[1].name, versioned);

        let keyring = Keyring::new();
        let fp = anchor_fingerprint(&hub.anchor);
        let ctx = adopt_with_tofu(&keyring, &fetched, &ns, &fp).unwrap();
        assert_eq!(ctx.namespace(), &ns);
    }

    #[test]
    fn forged_or_malformed_metadata_is_refused_before_any_context_fetch() {
        let ns = n("/home/bob");
        let eve = hub("/home/eve");
        let foreign_pointers = [
            eve.context.rdr_name(),                     // another namespace's context
            n("/home/bob/32=trust-context"),            // no version
            n("/home/bob/32=trust-context/v=1/extra"),  // deeper than a context
            n("/home/bob/32=trust-context/seg=1"),      // not a version component
            n("/home/bob/KEY/root"),                    // outside the context prefix
            n("/home/bob/x/32=trust-context/v=1"),      // a sub-namespace's context
        ];
        // Invariant: a pointer outside `<ns>/32=trust-context/v=<N>` is refused
        // and never fetched; malformed content is refused without a panic.
        for pointer in foreign_pointers {
            let mut net = FakeNet::new(vec![metadata(&ns, &pointer.encode_to_tlv())]);
            let res = futures::executor::block_on(fetch_context(&mut net, &ns));
            assert!(res.is_err(), "{pointer} must be refused");
            assert_eq!(net.sent.len(), 1, "{pointer} must not be fetched");
        }

        let malformed: [&[u8]; 4] = [
            &[],                             // no Name at all
            &[0x07, 0x05, 0x08],             // truncated Name TLV
            &[0x07, 0x02, 0x00, 0x00],       // Name holding a type-0 component
            &[0xfd],                         // not TLV
        ];
        for content in malformed {
            let mut net = FakeNet::new(vec![metadata(&ns, content)]);
            let res = futures::executor::block_on(fetch_context(&mut net, &ns));
            assert!(res.is_err(), "{content:02x?} must be refused");
            assert_eq!(net.sent.len(), 1, "{content:02x?}: nothing may be fetched");
        }

        // A metadata reply named outside the metadata name.
        let mut net = FakeNet::new(vec![(
            rdr_metadata_name(&ns),
            data(n("/home/bob/other"), &eve.context.rdr_name().encode_to_tlv()),
        )]);
        let res = futures::executor::block_on(fetch_context(&mut net, &ns));
        assert!(res.is_err(), "a metadata reply under another name must be refused");
        assert_eq!(net.sent.len(), 1);

        // No metadata at all.
        let mut net = FakeNet::new(Vec::new());
        assert!(futures::executor::block_on(fetch_context(&mut net, &ns)).is_err());
    }

    #[test]
    fn context_reply_under_another_name_is_refused() {
        let ns = n("/home/bob");
        let bob = hub("/home/bob");
        let eve = hub("/home/eve");
        let versioned = bob.context.rdr_name();
        // The announced name answered with eve's (validly signed) context.
        let mut net = FakeNet::new(vec![
            metadata(&ns, &versioned.encode_to_tlv()),
            (versioned, eve.context_data.raw().clone()),
        ]);
        let res = futures::executor::block_on(fetch_context(&mut net, &ns));
        assert!(res.is_err(), "a context under another name must never be returned");
    }

    /// A forger serving its own context under the right name gets through the
    /// name check by construction; the fingerprint pin refuses it.
    #[test]
    fn forged_context_at_the_right_name_fails_the_pin() {
        let ns = n("/home/bob");
        let genuine = hub("/home/bob");
        let forged = hub("/home/bob");
        let versioned = forged.context.rdr_name();
        let mut net = FakeNet::new(vec![
            metadata(&ns, &versioned.encode_to_tlv()),
            (versioned, forged.context_data.raw().clone()),
        ]);
        let fetched = futures::executor::block_on(fetch_context(&mut net, &ns)).unwrap();
        let keyring = Keyring::new();
        assert!(
            adopt_with_tofu(&keyring, &fetched, &ns, &anchor_fingerprint(&genuine.anchor))
                .is_err()
        );
        assert!(keyring.is_empty(), "a forged context must not be adopted");
    }
}
