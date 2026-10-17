//! Onboarding artefacts: the anchor [`anchor_fingerprint`], the verified
//! adoption of a trust context against the fingerprint an out-of-band link
//! expects ([`adopt_with_tofu`], [`adopt_anchor_link`]), RDR naming and
//! fetching of the published context, and the privacy-preserving link-local
//! [`AnchorAdvert`].
//!
//! A node does not "join a network" — it *adopts* a namespace's anchor-rooted
//! [`SignedTrustContext`]. The one irreducible bit a face cannot give for free is
//! **root authenticity**. An out-of-band `ndn-trust://anchor/…` link
//! (`ndn_trust_envelope::TrustEnvelope::Anchor`, a QR / deep link, *not* an NDN
//! wire packet) carries that bit: the namespace and the **expected
//! fingerprint** of the root anchor (a public hash, not a secret), optionally
//! with the signed context Data inline. Adoption is never automatic — the
//! context Data's signature must verify under an anchor whose fingerprint is
//! the expected one (TOFU), so neither a flooded fake advert nor a tampered
//! context (e.g. a weakened schema riding a genuine anchor) can poison a
//! keyring. See `docs/wiki/src/reference/trust-policies.md` and
//! `docs/wiki/src/reference/context-adoption.md`.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_packet::encode::InterestBuilder;
use ndn_packet::{Data, Name, NameComponent};
use ndn_security::{
    Certificate, ExpectContextError, Keyring, OpenContextError, SignedTrustContext,
    SignedTrustContextError, Validator,
};
use ndn_tlv::TlvReader;
use ndn_trust_envelope::TrustEnvelope;

use crate::client::CaExchange;
use crate::error::CertError;

/// The RDR keyword component naming a published context: `/<ns>/32=trust-context`.
/// Canonical definition lives in `ndn-security` (the `SignedTrustContext`
/// owner); re-exported here so there is one source of truth.
pub const TRUST_CONTEXT_KEYWORD: &[u8] = ndn_security::trust_context::TRUST_CONTEXT_KEYWORD;
/// The RDR metadata keyword (`32=metadata`).
pub const METADATA_KEYWORD: &[u8] = b"metadata";

/// SHA-256 over an anchor's public key — the fingerprint an anchor link
/// carries. Defined in `ndn-security` so the validator's expected-context
/// admission computes exactly the same value.
pub use ndn_security::anchor_fingerprint;

/// How long a forwarder admits the context it expects while
/// [`adopt_anchor_link`] fetches it: covers the metadata and the context
/// Interest (each bounded by the fetch timeout); the expectation is withdrawn
/// as soon as the adoption returns, so this only bounds a lost one.
pub const CONTEXT_EXPECTATION_TTL: Duration = Duration::from_secs(30);

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

/// Why a trust context was not adopted. Every message says what is wrong and,
/// where the user can act, what to do instead.
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
    #[error(
        "context namespace {found} does not match the namespace {expected} from the invite/QR"
    )]
    NamespaceMismatch { expected: String, found: String },
    #[error("context Data carries no KeyLocator naming its signer")]
    MissingKeyLocator,
    #[error("context signer {0} is not one of the context's own anchors")]
    SignerNotAnchor(String),
    #[error(
        "context signer {0} does not have the expected fingerprint from the invite/QR: this is \
         not the namespace the link names (check the code you scanned, and that this node's \
         route for the namespace leads to a node serving that namespace's context)"
    )]
    FingerprintMismatch(String),
    #[error("no anchor of the context has the expected fingerprint from the invite/QR")]
    NoExpectedAnchor,
    #[error("context signature type {0} is not a public-key signature")]
    UnsupportedSignature(u64),
    #[error("context signature does not verify under anchor {0}")]
    BadSignature(String),
    #[error("refused: context version {offered} is older than the held version {held}")]
    Rollback { offered: u64, held: u64 },
    #[error(
        "refused: the fetched context is version {offered}, older than version {required} \
         named by the invite/QR (an outdated or replayed context); retry once the namespace \
         serves version {required} or newer, or use an anchor link with the context inline"
    )]
    Downgrade { offered: u64, required: u64 },
    #[error("expected an anchor link, got a {0} link")]
    NotAnchor(&'static str),
    #[error("not a readable trust link: {0}")]
    BadLink(String),
    #[error(
        "the anchor link carries no {0}; ask the namespace's owner for a new invite/QR \
         (`ndn-fwd init` prints one as anchor_uri)"
    )]
    LinkMissing(&'static str),
    #[error("anchor link carries an invalid namespace {0:?}")]
    BadNamespace(String),
    #[error(
        "the anchor link carries only a fingerprint, so the context has to be fetched over \
         NDN: that needs the running daemon with a link and a route toward a node serving \
         the context (start ndn-fwd and retry), or use an anchor link with the context inline"
    )]
    InlineContextRequired,
    #[error(
        "anchor link carries an unsigned legacy context; its integrity cannot be \
         verified, so it is not adopted (re-issue the link with a signed context)"
    )]
    UnsignedLegacyContext,
    #[error(
        "could not fetch the trust context of {namespace}: {source}. Check that this node \
         has a route for {namespace} toward a node that holds the namespace's context \
         (`ndn-ctl route add {namespace} --face <face-id>`), or use an anchor link with the \
         context inline"
    )]
    Fetch {
        namespace: String,
        #[source]
        source: FetchContextError,
    },
    #[error(
        "the reply for {namespace} carried a trust context that this node refused \
         ({reason}): it is not the namespace the link names. This node's route for {namespace} \
         leads to another namespace's node or to an impersonator — check the route \
         (`ndn-ctl route list`) and that you scanned the right code"
    )]
    WrongContext { namespace: String, reason: String },
    #[error("{0}")]
    InProgress(#[from] ExpectContextError),
}

impl From<OpenContextError> for AdoptError {
    fn from(e: OpenContextError) -> Self {
        match e {
            OpenContextError::BadName(n) => Self::BadName(n),
            OpenContextError::MissingContent => Self::MissingContent,
            OpenContextError::Malformed(e) => Self::Malformed(e),
            OpenContextError::MissingKeyLocator => Self::MissingKeyLocator,
            OpenContextError::SignerNotAnchor(s) => Self::SignerNotAnchor(s),
            OpenContextError::UnsupportedSignature(t) => Self::UnsupportedSignature(t),
            OpenContextError::BadSignature(a) => Self::BadSignature(a),
        }
    }
}

/// Decode and authenticate a signed trust-context Data (see
/// [`SignedTrustContext::open_signed`]): named at its own RDR name and signed
/// by one of its own anchors. Returns the context and the anchor that signed
/// it. Whether that anchor is trusted is the caller's decision —
/// [`adopt_with_tofu`] compares it with the expected fingerprint.
pub fn open_signed_context(data: &Data) -> Result<(SignedTrustContext, Certificate), AdoptError> {
    // The verifiers never suspend; drive the future inline.
    Ok(futures::executor::block_on(SignedTrustContext::open_signed(
        data,
    ))?)
}

/// [`SignedTrustContext::open_signed`] plus the out-of-band checks: the
/// context roots `namespace` and its signing anchor has
/// `expected_fingerprint`. Adopts nothing.
async fn authenticate(
    context_data: &Data,
    namespace: &Name,
    expected_fingerprint: &[u8; 32],
) -> Result<SignedTrustContext, AdoptError> {
    let (ctx, signer) = SignedTrustContext::open_signed(context_data).await?;
    if ctx.namespace() != namespace {
        return Err(AdoptError::NamespaceMismatch {
            expected: namespace.to_string(),
            found: ctx.namespace().to_string(),
        });
    }
    if &anchor_fingerprint(&signer) != expected_fingerprint {
        return Err(AdoptError::FingerprintMismatch(signer.name.to_string()));
    }
    Ok(ctx)
}

/// Adopt the signed context `context_data` into `keyring` **only** if it
/// roots `namespace`, its signature verifies, and the anchor that signed it
/// has the out-of-band `expected_fingerprint` (TOFU). This is the sanctioned
/// path from "received a context" to "trust a context": a context whose
/// signing anchor was not authenticated out-of-band (QR/NFC/pre-baked), or
/// whose content was altered after signing, never enters the keyring.
pub fn adopt_with_tofu(
    keyring: &Keyring,
    context_data: &Data,
    namespace: &Name,
    expected_fingerprint: &[u8; 32],
) -> Result<Arc<SignedTrustContext>, AdoptError> {
    // The verifiers never suspend; drive the future inline.
    let ctx = futures::executor::block_on(authenticate(
        context_data,
        namespace,
        expected_fingerprint,
    ))?;
    adopt_into(keyring, ctx)
}

/// What an `ndn-trust://anchor` link asks a device to adopt.
#[derive(Debug)]
pub struct AnchorLink {
    /// The namespace the anchor roots.
    pub namespace: Name,
    /// SHA-256 of the namespace root's public key ([`anchor_fingerprint`]).
    pub expected_fingerprint: [u8; 32],
    /// The context version the link names: a fetched context older than this
    /// is refused ([`AdoptError::Downgrade`]).
    pub min_version: Option<u64>,
    /// The signed context Data, when the link carries it inline.
    pub context_data: Option<Data>,
}

impl AnchorLink {
    /// Read an anchor envelope: it must name a namespace and an expected
    /// fingerprint; an inline context must be the signed Data form.
    pub fn from_envelope(envelope: &TrustEnvelope) -> Result<Self, AdoptError> {
        let TrustEnvelope::Anchor {
            namespace,
            fingerprint,
            version,
            context_data,
            context_content,
        } = envelope
        else {
            return Err(AdoptError::NotAnchor(envelope.kind().as_str()));
        };
        let namespace = namespace
            .as_deref()
            .ok_or(AdoptError::LinkMissing("namespace"))?;
        let namespace: Name = namespace
            .parse()
            .map_err(|_| AdoptError::BadNamespace(namespace.to_string()))?;
        let expected_fingerprint =
            fingerprint.ok_or(AdoptError::LinkMissing("expected fingerprint"))?;
        let context_data = match (context_data, context_content) {
            (Some(wire), _) => {
                Some(Data::decode(wire.clone()).map_err(|e| AdoptError::BadData(e.to_string()))?)
            }
            (None, Some(_)) => return Err(AdoptError::UnsignedLegacyContext),
            (None, None) => None,
        };
        Ok(Self {
            namespace,
            expected_fingerprint,
            min_version: *version,
            context_data,
        })
    }

    /// Parse an `ndn-trust://anchor/…` URI (or its https mirror).
    pub fn from_uri(uri: &str) -> Result<Self, AdoptError> {
        let envelope =
            TrustEnvelope::from_uri(uri.trim()).map_err(|e| AdoptError::BadLink(e.to_string()))?;
        Self::from_envelope(&envelope)
    }

    /// Authenticate `data` as this link's context (namespace, expected
    /// fingerprint, version not below the link's) without adopting it.
    async fn authenticate(&self, data: &Data) -> Result<SignedTrustContext, AdoptError> {
        let ctx = authenticate(data, &self.namespace, &self.expected_fingerprint).await?;
        self.check_version(&ctx)?;
        Ok(ctx)
    }

    fn check_version(&self, ctx: &SignedTrustContext) -> Result<(), AdoptError> {
        match self.min_version {
            Some(required) if ctx.version() < required => Err(AdoptError::Downgrade {
                offered: ctx.version(),
                required,
            }),
            _ => Ok(()),
        }
    }
}

/// [`adopt_with_tofu`] driven by a scanned anchor envelope: the envelope must
/// name a namespace and expected fingerprint and carry the signed context
/// inline (offline adoption). Fingerprint-only envelopes
/// ([`AdoptError::InlineContextRequired`]) need a fetch over NDN:
/// [`adopt_anchor_link`]. Unsigned legacy content
/// ([`AdoptError::UnsignedLegacyContext`]) is refused.
/// Returns the adopted context and its signed Data (for persistence).
pub fn adopt_anchor_envelope(
    keyring: &Keyring,
    envelope: &TrustEnvelope,
) -> Result<(Arc<SignedTrustContext>, Data), AdoptError> {
    let link = AnchorLink::from_envelope(envelope)?;
    let data = link.context_data.ok_or(AdoptError::InlineContextRequired)?;
    let link = AnchorLink {
        context_data: None,
        ..link
    };
    // The verifiers never suspend; drive the future inline.
    let ctx = futures::executor::block_on(link.authenticate(&data))?;
    Ok((adopt_into(keyring, ctx)?, data))
}

/// A context adopted from an anchor link.
#[derive(Debug)]
pub struct LinkAdoption {
    pub context: Arc<SignedTrustContext>,
    /// The signed Data exactly as received (what to persist and publish).
    pub data: Data,
    /// Whether it was fetched over NDN (else it came inline).
    pub fetched: bool,
}

/// Adopt the namespace an anchor link names into `keyring`.
///
/// - Context inline: verify it against the link (namespace, expected
///   fingerprint, version) and adopt; no network.
/// - Fingerprint only: fetch the context by name through `exchange`
///   ([`fetch_context`]), then verify and adopt it the same way. When the
///   Interests go through a validating forwarder, pass its `forwarder`
///   validator: an expectation for this namespace and fingerprint is
///   registered for the fetch, so that forwarder admits the not-yet-trusted
///   context Data (and drops a forged one) instead of dropping it for lack of
///   an anchor. If the forwarder admitted exactly the Data that arrived, its
///   verified result is reused instead of verifying again.
///
/// A fetched version older than the link's `version` is refused
/// ([`AdoptError::Downgrade`]), closing the first-contact downgrade an on-path
/// forger could otherwise attempt by pointing at an old genuine context. The
/// keyring's anti-rollback still refuses anything older than a held version.
/// Persistence is the caller's (the Data is returned verbatim).
pub async fn adopt_anchor_link<E>(
    keyring: &Keyring,
    forwarder: Option<&Validator>,
    exchange: &mut E,
    link: &AnchorLink,
) -> Result<LinkAdoption, AdoptError>
where
    E: CaExchange + ?Sized,
{
    if let Some(data) = &link.context_data {
        let ctx = link.authenticate(data).await?;
        return Ok(LinkAdoption {
            context: adopt_into(keyring, ctx)?,
            data: Data::decode(data.raw().clone())
                .map_err(|e| AdoptError::BadData(e.to_string()))?,
            fetched: false,
        });
    }
    let expectation = forwarder
        .map(|v| {
            v.expect_context(
                link.namespace.clone(),
                link.expected_fingerprint,
                CONTEXT_EXPECTATION_TTL,
            )
        })
        .transpose()?;
    let fetched = fetch_context(exchange, &link.namespace).await;
    let outcome = expectation.map(|e| e.finish()).unwrap_or_default();
    let data = fetched.map_err(|source| match outcome.refused.clone() {
        // Something answered, and this node's forwarder dropped it: say why.
        Some(reason) => AdoptError::WrongContext {
            namespace: link.namespace.to_string(),
            reason,
        },
        None => AdoptError::Fetch {
            namespace: link.namespace.to_string(),
            source,
        },
    })?;
    let context = match outcome.admitted {
        // The forwarder checked exactly these bytes against this link's
        // namespace (by name) and expected fingerprint: verified once.
        Some(a) if a.wire == *data.raw() => {
            link.check_version(&a.context)?;
            a.context
        }
        _ => Arc::new(link.authenticate(&data).await?),
    };
    Ok(LinkAdoption {
        context: adopt_arc_into(keyring, context)?,
        data,
        fetched: true,
    })
}

/// **Explicit opt-in, unverified.** Adopt a legacy *unsigned* context
/// (`encode_content()` / `ndn-ctx:1:` payloads) if it roots `namespace` and
/// any of its anchors has `expected_fingerprint`. Nothing authenticates the
/// schema, revocations or CA endpoints of such a context — whoever handed it
/// over could have weakened them — so no default path calls this; use it
/// only when the operator has deliberately chosen to trust the unsigned
/// payload.
pub fn adopt_unsigned_legacy_with_tofu(
    keyring: &Keyring,
    ctx: SignedTrustContext,
    namespace: &Name,
    expected_fingerprint: &[u8; 32],
) -> Result<Arc<SignedTrustContext>, AdoptError> {
    if ctx.namespace() != namespace {
        return Err(AdoptError::NamespaceMismatch {
            expected: namespace.to_string(),
            found: ctx.namespace().to_string(),
        });
    }
    let matches = ctx
        .anchors()
        .iter()
        .any(|r| &anchor_fingerprint(r.value()) == expected_fingerprint);
    if !matches {
        return Err(AdoptError::NoExpectedAnchor);
    }
    adopt_into(keyring, ctx)
}

/// Hand `ctx` to the keyring's anti-rollback adoption, surfacing a refusal.
pub(crate) fn adopt_into(
    keyring: &Keyring,
    ctx: SignedTrustContext,
) -> Result<Arc<SignedTrustContext>, AdoptError> {
    adopt_arc_into(keyring, Arc::new(ctx))
}

fn adopt_arc_into(
    keyring: &Keyring,
    ctx: Arc<SignedTrustContext>,
) -> Result<Arc<SignedTrustContext>, AdoptError> {
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
/// is the adopter's job ([`adopt_anchor_link`] / [`adopt_with_tofu`]:
/// signature under the context's own anchor, that anchor's fingerprint equal
/// to the expected one from the out-of-band link, anti-rollback), so it is
/// checked once, at the one place that decides trust.
///
/// The metadata is an unauthenticated pointer and needs no signature check
/// here: the adopter holds nothing but a fingerprint, so it could not verify
/// one anyway. The pointer is confined to `<ns>/32=trust-context/v=<N>`, so
/// a forged one can only point at (a) a forged or foreign context, which
/// fails the expected-fingerprint check; (b) an older genuine version, which
/// the keyring's anti-rollback refuses once a newer one is held; or (c) a
/// name nobody serves, which fails as a fetch error. On first contact
/// (nothing held yet) (b) means adopting an older context the owner did
/// sign; an on-path forger could equally replay an old *signed* metadata Data
/// that named it, so signing the pointer would not close it.
/// [`adopt_anchor_link`] closes it by demanding at least the version the link
/// names (`TrustEnvelope::Anchor::version`). A forger who can answer
/// Interests can also withhold the context, so the pointer adds no new power.
pub async fn fetch_context<E>(exchange: &mut E, namespace: &Name) -> Result<Data, FetchContextError>
where
    E: CaExchange + ?Sized,
{
    let versioned = fetch_context_pointer(exchange, namespace).await?;
    fetch_versioned_context(exchange, &versioned).await
}

/// Step 1–2 of [`fetch_context`]: ask for the newest version's name
/// (`/<ns>/32=trust-context/32=metadata`, MustBeFresh) and return it, confined
/// to `/<ns>/32=trust-context/v=<N>`. An updater compares `N` with the version
/// it holds before fetching anything else.
pub async fn fetch_context_pointer<E>(
    exchange: &mut E,
    namespace: &Name,
) -> Result<Name, FetchContextError>
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
    context_pointer(namespace, content)
}

/// Step 3 of [`fetch_context`]: fetch the context Data named exactly
/// `versioned` (a [`context_pointer`]); a reply under another name is refused.
pub async fn fetch_versioned_context<E>(
    exchange: &mut E,
    versioned: &Name,
) -> Result<Data, FetchContextError>
where
    E: CaExchange + ?Sized,
{
    let data = exchange
        .express(InterestBuilder::new(versioned.clone()).build())
        .await
        .map_err(|source| FetchContextError::Transport {
            name: versioned.to_string(),
            source,
        })?;
    if *data.name != *versioned {
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
/// root device or relay opts in. A passive listener of a non-advertising node sees
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

    fn root_dev(ns: &str) -> crate::namespace::NamespaceInit {
        crate::namespace::init_namespace(&ndn_security::SecurityManager::new(), &n(ns)).unwrap()
    }

    #[test]
    fn fetched_context_is_the_asked_namespace_and_passes_tofu() {
        let ns = n("/home/bob");
        let root_dev = root_dev("/home/bob");
        let versioned = root_dev.context.rdr_name();
        let mut net = FakeNet::new(vec![
            metadata(&ns, &versioned.encode_to_tlv()),
            (versioned.clone(), root_dev.context_data.raw().clone()),
        ]);

        let fetched = futures::executor::block_on(fetch_context(&mut net, &ns)).unwrap();
        assert_eq!(fetched.raw(), root_dev.context_data.raw());
        let discovery = net.sent[0].selectors();
        assert!(discovery.can_be_prefix && discovery.must_be_fresh);
        assert_eq!(*net.sent[1].name, versioned);

        let keyring = Keyring::new();
        let fp = anchor_fingerprint(&root_dev.anchor);
        let ctx = adopt_with_tofu(&keyring, &fetched, &ns, &fp).unwrap();
        assert_eq!(ctx.namespace(), &ns);
    }

    #[test]
    fn forged_or_malformed_metadata_is_refused_before_any_context_fetch() {
        let ns = n("/home/bob");
        let eve = root_dev("/home/eve");
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
        let bob = root_dev("/home/bob");
        let eve = root_dev("/home/eve");
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
    /// name check by construction; the expected-fingerprint check refuses it.
    #[test]
    fn forged_context_at_the_right_name_fails_the_expected_fingerprint() {
        let ns = n("/home/bob");
        let genuine = root_dev("/home/bob");
        let forged = root_dev("/home/bob");
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

    // ── Expected-context admission + adoption from a fingerprint-only link ──

    fn forwarder() -> Validator {
        Validator::new(ndn_security::TrustSchema::hierarchical())
    }

    fn decode(wire: &Bytes) -> Data {
        Data::decode(wire.clone()).unwrap()
    }

    fn verdict(v: &Validator, data: &Data) -> ndn_security::ValidationResult {
        futures::executor::block_on(v.validate_chain_cached(data)).0
    }

    fn same_kind(a: &ndn_security::ValidationResult, b: &ndn_security::ValidationResult) -> bool {
        std::mem::discriminant(a) == std::mem::discriminant(b)
    }

    /// The validator admits a context Data only while an expectation for its
    /// namespace is live, and only when its signing anchor has the expected
    /// fingerprint; otherwise it behaves exactly as without expectations.
    #[test]
    fn forwarder_admits_only_the_expected_context_while_expected() {
        let ns = n("/home/bob");
        let genuine = root_dev("/home/bob");
        let forged = root_dev("/home/bob");
        let v = forwarder();
        let before = verdict(&v, &genuine.context_data);
        let forged_before = verdict(&v, &forged.context_data);
        assert!(!matches!(before, ndn_security::ValidationResult::Valid(_)));

        let fp = anchor_fingerprint(&genuine.anchor);
        {
            let expectation = v.expect_context(ns.clone(), fp, Duration::from_secs(30)).unwrap();
            // A second adoption of the same namespace cannot overwrite it.
            assert!(v.expect_context(ns.clone(), [0; 32], Duration::from_secs(30)).is_err());
            assert!(matches!(
                verdict(&v, &forged.context_data),
                ndn_security::ValidationResult::Invalid(_)
            ));
            match verdict(&v, &genuine.context_data) {
                ndn_security::ValidationResult::Valid(safe) => assert!(matches!(
                    safe.trust_path(),
                    ndn_security::safe_data::TrustPath::ExpectedContext { .. }
                )),
                other => panic!("expected context not admitted: {other:?}"),
            }
            // Other names are untouched by the expectation.
            let other = root_dev("/home/alice");
            assert!(same_kind(
                &verdict(&v, &other.context_data),
                &verdict(&forwarder(), &other.context_data)
            ));
            let outcome = expectation.finish();
            let admitted = outcome.admitted.expect("admitted result kept");
            assert!(outcome.refused.is_some(), "the forged context's refusal is kept");
            assert_eq!(admitted.wire, *genuine.context_data.raw());
        }
        // Withdrawn: exactly as before any expectation.
        assert!(same_kind(&verdict(&v, &genuine.context_data), &before));
        assert!(same_kind(&verdict(&v, &forged.context_data), &forged_before));

        // An expired expectation admits nothing.
        let _expired = v.expect_context(ns.clone(), fp, Duration::ZERO).unwrap();
        assert!(same_kind(&verdict(&v, &genuine.context_data), &before));
    }

    /// A network seen through a validating forwarder: a reply the forwarder's
    /// validator does not admit is dropped, as `ndn-fwd` drops it.
    struct ForwardedNet<'a> {
        net: FakeNet,
        forwarder: &'a Validator,
    }

    impl CaExchange for ForwardedNet<'_> {
        async fn express(&mut self, interest: Bytes) -> Result<Data, CertError> {
            let data = self.net.express(interest).await?;
            match self.forwarder.validate_chain_cached(&data).await.0 {
                ndn_security::ValidationResult::Valid(_) => Ok(data),
                other => Err(CertError::Transport(format!("dropped by the forwarder: {other:?}"))),
            }
        }
    }

    fn serving(root_dev: &crate::namespace::NamespaceInit) -> FakeNet {
        let ns = root_dev.context.namespace().clone();
        let versioned = root_dev.context.rdr_name();
        FakeNet::new(vec![
            metadata(&ns, &versioned.encode_to_tlv()),
            (versioned, root_dev.context_data.raw().clone()),
        ])
    }

    fn link(ns: &str, fp: [u8; 32], min_version: Option<u64>) -> AnchorLink {
        AnchorLink {
            namespace: n(ns),
            expected_fingerprint: fp,
            min_version,
            context_data: None,
        }
    }

    #[test]
    fn fingerprint_only_link_adopts_through_a_validating_forwarder() {
        let genuine = root_dev("/home/bob");
        let fp = anchor_fingerprint(&genuine.anchor);
        let v = forwarder();
        let keyring = Keyring::new();
        let mut net = ForwardedNet {
            net: serving(&genuine),
            forwarder: &v,
        };
        let adopted = futures::executor::block_on(adopt_anchor_link(
            &keyring,
            Some(&v),
            &mut net,
            &link("/home/bob", fp, Some(1)),
        ))
        .unwrap();
        assert!(adopted.fetched);
        assert_eq!(adopted.data.raw(), genuine.context_data.raw());
        assert_eq!(keyring.version_of(&n("/home/bob")), Some(1));
        // The expectation ended with the adoption.
        assert!(
            v.expect_context(n("/home/bob"), fp, Duration::from_secs(1))
                .is_ok()
        );
    }

    /// Invariant: a context whose anchor fingerprint differs from the
    /// expected one is never admitted by the forwarder nor adopted — whether
    /// it comes through a validating forwarder, a non-validating one, or
    /// inline.
    #[test]
    fn forged_context_is_never_admitted_or_adopted() {
        let genuine = root_dev("/home/bob");
        let forged = root_dev("/home/bob");
        let fp = anchor_fingerprint(&genuine.anchor);
        let keyring = Keyring::new();

        let v = forwarder();
        let mut through_forwarder = ForwardedNet {
            net: serving(&forged),
            forwarder: &v,
        };
        let res = futures::executor::block_on(adopt_anchor_link(
            &keyring,
            Some(&v),
            &mut through_forwarder,
            &link("/home/bob", fp, None),
        ));
        assert!(matches!(res, Err(AdoptError::WrongContext { .. })), "{res:?}");

        let mut direct = serving(&forged);
        let res = futures::executor::block_on(adopt_anchor_link(
            &keyring,
            None,
            &mut direct,
            &link("/home/bob", fp, None),
        ));
        assert!(matches!(res, Err(AdoptError::FingerprintMismatch(_))), "{res:?}");

        let inline = AnchorLink {
            context_data: Some(decode(forged.context_data.raw())),
            ..link("/home/bob", fp, None)
        };
        let res = futures::executor::block_on(adopt_anchor_link(
            &keyring,
            None,
            &mut FakeNet::new(Vec::new()),
            &inline,
        ));
        assert!(res.is_err());
        assert!(keyring.is_empty(), "a forged context must never be adopted");
    }

    /// Invariant: a fetched version below the link's version is refused.
    #[test]
    fn fetched_version_below_the_links_is_refused() {
        let genuine = root_dev("/home/bob");
        let fp = anchor_fingerprint(&genuine.anchor);
        let keyring = Keyring::new();
        let v = forwarder();
        for forwarder in [Some(&v), None] {
            let mut net = serving(&genuine);
            let res = futures::executor::block_on(adopt_anchor_link(
                &keyring,
                forwarder,
                &mut net,
                &link("/home/bob", fp, Some(2)),
            ));
            assert!(
                matches!(res, Err(AdoptError::Downgrade { offered: 1, required: 2 })),
                "{res:?}"
            );
        }
        assert!(keyring.is_empty());
    }

    /// Invariant: malformed links are refused with a reason, never a panic.
    #[test]
    fn malformed_links_are_refused_without_panicking() {
        for uri in [
            "",
            "garbage",
            "ndn-trust://",
            "ndn-trust://anchor",
            "ndn-trust://anchor/",
            "ndn-trust://anchor/%%%",
            "ndn-trust://anchor/AAAA",
            "https://ndn.local/x",
            "ndn-trust://invite/AAAA",
        ] {
            assert!(AnchorLink::from_uri(uri).is_err(), "{uri:?}");
        }
        // A link without its namespace or expected fingerprint.
        for envelope in [
            TrustEnvelope::Anchor {
                namespace: None,
                fingerprint: Some([1; 32]),
                version: None,
                context_data: None,
                context_content: None,
            },
            TrustEnvelope::Anchor {
                namespace: Some("/home/bob".into()),
                fingerprint: None,
                version: None,
                context_data: None,
                context_content: None,
            },
            TrustEnvelope::Anchor {
                namespace: Some("/home/bob".into()),
                fingerprint: Some([1; 32]),
                version: None,
                context_data: Some(Bytes::from_static(b"not a Data")),
                context_content: None,
            },
        ] {
            assert!(AnchorLink::from_uri(&envelope.to_uri()).is_err());
        }
    }
}
