//! Credentials: the signed trust context and the certificate chain a party of an
//! introduction shows (spec §19.3), opened and judged without trusting anything of
//! them until the host adopts the context; the fingerprint a code names, and how it
//! is judged against the anchor of verified credentials.
//!
//! Shared by the two sides: the inviter opens an ask's credentials, the joiner an
//! answer's and a hint record's. Every function here reads the node's trust and the
//! host's anchor, and keeps nothing.

use std::sync::Arc;

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_heap::host::NodeHandle;
use ndn_packet::Data;
use ndn_security::cert_name::key_name_of;
use ndn_security::safe_data::TrustPath;
use ndn_security::self_certifying::self_certifying_digest;
use ndn_security::{
    CertCache, Certificate, Keyring, SignedTrustContext, ValidationResult, Validator,
    VerifyOutcome, anchor_fingerprint, public_key_digest, verifier::verify_public_key_signature,
};
use ndn_trust_envelope::TrustEnvelope;
use subtle::ConstantTimeEq;

use crate::error::InviteError;
use crate::host::Host;
use crate::policy::IntroPolicy;
use crate::proofs::{SECRET_LEN, keyed_fingerprint_matches};
use crate::short::SHORT_FINGERPRINT_LEN;

/// The longest certificate chain credentials carry, or are walked for.
pub(crate) const CHAIN_MAX: usize = 8;

/// The device of a key name `<D>/KEY/<id>`; `None` for a name that is no key's.
pub(crate) fn device_of(key: &Name) -> Option<Name> {
    let comps = key.components();
    let d = comps.len().checked_sub(2)?;
    (d >= 1
        && comps[d].typ == ndn_foundation_types::tlv_type::GENERIC_NAME_COMPONENT
        && comps[d].value.as_ref() == b"KEY")
        .then(|| Name::from_components(comps[..d].iter().cloned()))
}

/// Credentials opened: the signed trust context they carry, checked against its
/// own anchor only, and a validator that holds that context alone and their
/// certificates. Nothing of them is trusted by this device until its host adopts
/// the context.
pub(crate) struct Opened {
    pub(crate) ctx: Arc<SignedTrustContext>,
    anchor: Certificate,
    /// The trust context's signed Data, as the credentials carry it.
    context: Bytes,
    /// Their certificates.
    certs: Arc<CertCache>,
    validator: Validator,
}

/// Open `packets`: a signed trust context (its signature verified under one of its
/// own anchors, valid now), then certificates. `None` when they are not that.
pub(crate) async fn open_credentials(packets: &[Bytes]) -> Option<Opened> {
    let (first, rest) = packets.split_first()?;
    if rest.len() > CHAIN_MAX {
        return None;
    }
    let data = Data::decode(first.clone()).ok()?;
    let (ctx, anchor) = SignedTrustContext::open_received(&data).await.ok()?;
    let ctx = Arc::new(ctx);
    let keyring = Keyring::of_claim(Arc::clone(&ctx)).ok()?;
    let certs = Arc::new(CertCache::new());
    for p in rest {
        certs.insert(Certificate::decode(&Data::decode(p.clone()).ok()?).ok()?);
    }
    let validator = Validator::with_keyring(Arc::new(keyring), Arc::clone(&certs), None, CHAIN_MAX)
        .refuse_without_anchors();
    Some(Opened {
        ctx,
        anchor,
        context: first.clone(),
        certs,
        validator,
    })
}

impl Opened {
    /// The key that signed `data` and its public key's digest, if `data` verifies
    /// by a chain of these certificates to this context's anchor (its schema
    /// obeyed, certificates valid now).
    pub(crate) async fn signer(&self, data: &Data) -> Option<(Name, [u8; 32])> {
        self.signer_by(&self.validator, data).await
    }

    /// [`Self::signer`], judged by `keyring` — this device's, once its host adopted
    /// the namespace: by a chain of these certificates to an anchor of the version
    /// it holds, under that version's schema and revocations. A proof that
    /// verifies only under the context the credentials carry (an older one, a key
    /// the held version revokes) does not count.
    pub(crate) async fn signer_held(
        &self,
        keyring: &Arc<Keyring>,
        data: &Data,
    ) -> Option<(Name, [u8; 32])> {
        let held = Validator::with_keyring(
            Arc::clone(keyring),
            Arc::clone(&self.certs),
            None,
            CHAIN_MAX,
        )
        .refuse_without_anchors();
        self.signer_by(&held, data).await
    }

    async fn signer_by(&self, validator: &Validator, data: &Data) -> Option<(Name, [u8; 32])> {
        match validator.validate_chain(data).await {
            ValidationResult::Valid(safe)
                if !matches!(safe.trust_path(), TrustPath::DigestSha256) => {}
            _ => return None,
        }
        let locator = data.sig_info()?.key_locator_name()?;
        let key = key_name_of(&locator);
        Some((key.clone(), self.claimed(&key)?))
    }

    /// The public key digest `key` has by these credentials, unverified: an anchor
    /// of the context (a key that is its own anchor shows no certificate), else the
    /// certificate of it a chain walk picks.
    pub(crate) fn claimed(&self, key: &Name) -> Option<[u8; 32]> {
        let cert = self
            .ctx
            .anchor_for(key)
            .or_else(|| self.validator.cert_cache().get_valid(key))?;
        Some(public_key_digest(&cert.public_key))
    }

    /// The key that signed `data`, when the signature is good by the public key of
    /// a certificate these credentials chain to their anchor — judged by that
    /// key's own chain and the signature alone, not by what the context's schema
    /// lets the key sign ([`Self::signer`] adds that). A packet that is not even
    /// that was damaged in flight or is nobody's; one that is, and then fails the
    /// code's namespace, anchor or device, is authentic and not the code's
    /// inviter's (spec §19.3 S5).
    pub(crate) async fn authentic_signer(&self, data: &Data) -> Option<Name> {
        let info = data.sig_info()?;
        let locator = info.key_locator_name()?;
        let key = key_name_of(&locator);
        let cert = match self.ctx.anchor_for(&key) {
            Some(anchor) => anchor,
            None => {
                let cert = self.validator.cert_cache().get_valid(&key)?;
                let own = Data::decode(cert.data_wire()?).ok()?;
                match self.validator.validate_chain(&own).await {
                    ValidationResult::Valid(safe)
                        if !matches!(safe.trust_path(), TrustPath::DigestSha256) => {}
                    _ => return None,
                }
                cert
            }
        };
        matches!(
            verify_public_key_signature(
                info.sig_type,
                data.signed_region(),
                data.sig_value(),
                &cert.public_key
            ),
            Ok(VerifyOutcome::Valid)
        )
        .then_some(key)
    }

    /// The certificates on the chain from `key` to the context's anchor, as a chain
    /// walk picks them, named under `ns`: what a validator adopting the context
    /// takes of these credentials, and nothing else they carry (a certificate on
    /// no chain, of another party's key, would only shadow that party's in the
    /// cache).
    pub(crate) fn chain(&self, key: &Name, ns: &Name) -> Vec<Certificate> {
        let mut out = Vec::new();
        let mut at = key.clone();
        for _ in 0..=CHAIN_MAX {
            if self.ctx.anchor_for(&at).is_some() {
                break;
            }
            let Some(cert) = self.validator.cert_cache().get_valid(&at) else {
                break;
            };
            let Some(issuer) = cert.issuer.as_deref().cloned() else {
                break;
            };
            if cert.key_name().has_prefix(ns) {
                out.push(cert);
            }
            at = issuer;
        }
        out
    }

    /// Whether what `keyring` now holds of this context's namespace vouches for
    /// every anchor these credentials carry (by public key). Checked once the host
    /// adopted the namespace: a self-certifying one is adopted from its genesis by
    /// name, not from these credentials, so a proof checked against them counts
    /// only if their anchors are the namespace's. A namespace of another kind is
    /// adopted from these very credentials, and holds.
    pub(crate) fn vouched_by(&self, keyring: &Keyring) -> bool {
        let ns = self.ctx.namespace();
        if !matches!(self_certifying_digest(ns), Ok(Some(_))) {
            return true;
        }
        keyring.held(ns).is_some_and(|held| {
            self.ctx.anchors().iter().all(|a| {
                held.anchors()
                    .iter()
                    .any(|h| h.value().public_key == a.value().public_key)
            })
        })
    }

    /// SHA-256 of the anchor's public key.
    pub(crate) fn fingerprint(&self) -> [u8; 32] {
        anchor_fingerprint(&self.anchor)
    }

    /// The inline anchor link of the context, for the host to adopt.
    pub(crate) fn link(&self) -> TrustEnvelope {
        TrustEnvelope::Anchor {
            namespace: Some(self.ctx.namespace().to_string()),
            fingerprint: Some(self.fingerprint()),
            version: Some(self.ctx.version()),
            context_data: Some(self.context.clone()),
            context_content: None,
        }
    }
}

/// The anchor fingerprint a code names, as the code carries it, and how it is
/// judged against the whole fingerprint of the anchor of verified credentials (spec
/// §19.3, §19.7). Every comparison is in constant time.
#[derive(Clone, Debug)]
pub(crate) enum Fingerprint {
    /// All 32 octets: a link's, or a short code's of 36 words (a self-certifying
    /// namespace, whose name it is). Compared whole.
    Whole([u8; 32]),
    /// The first octets of the anchor's, as written: the words form's 16 (128
    /// bits), plain. A prefix of a public value, compared as the prefix.
    Prefix(Vec<u8>),
    /// A short code's 10 octets of a named namespace: the tag
    /// ([`keyed_fingerprint`](crate::proofs::keyed_fingerprint)) keyed by the
    /// code's own secret, which the joiner recomputes from the verified anchor's
    /// whole fingerprint.
    Keyed {
        secret: [u8; SECRET_LEN],
        tag: [u8; SHORT_FINGERPRINT_LEN],
    },
}

impl Fingerprint {
    /// The fingerprint `octets` of a short code made with `secret`: whole at 32
    /// octets, a keyed tag at [`SHORT_FINGERPRINT_LEN`], no other length.
    pub(crate) fn of(octets: &[u8], secret: &[u8; SECRET_LEN]) -> Option<Self> {
        if let Ok(whole) = <[u8; 32]>::try_from(octets) {
            return Some(Fingerprint::Whole(whole));
        }
        <[u8; SHORT_FINGERPRINT_LEN]>::try_from(octets)
            .ok()
            .map(|tag| Fingerprint::Keyed {
                secret: *secret,
                tag,
            })
    }

    pub(crate) fn matches(&self, fp: &[u8; 32]) -> bool {
        match self {
            Fingerprint::Whole(w) => bool::from(w.ct_eq(fp)),
            Fingerprint::Prefix(p) => p.len() <= fp.len() && bool::from(fp[..p.len()].ct_eq(p)),
            Fingerprint::Keyed { secret, tag } => keyed_fingerprint_matches(secret, fp, tag),
        }
    }
}

/// This device's credentials: its namespace's signed trust context, as the host
/// gives it, then the certificates of its key up to the context's anchor.
pub(crate) fn credentials(node: &NodeHandle, host: &dyn Host) -> Result<Vec<Bytes>, InviteError> {
    let context = host.anchor().ok_or_else(|| {
        InviteError::local(
            "the host gives no anchor (this device's namespace's signed trust context): enroll \
             the device in its namespace first",
        )
    })?;
    let ctx = node.validator().keyring().context_for(node.name());
    let mut out = vec![context];
    let mut at = node.writer().clone();
    for _ in 0..CHAIN_MAX {
        if ctx.anchor_for(&at).is_some() {
            return Ok(out);
        }
        let cert = node
            .keys()
            .cert_cache()
            .get_valid(&at)
            .or_else(|| node.validator().cert_cache().get_valid(&at))
            .ok_or_else(|| {
                InviteError::local(format!(
                    "no valid certificate of {at} is held, so this device cannot show the chain \
                     of its key to its namespace's anchor: renew the certificate"
                ))
            })?;
        out.push(cert.data_wire().ok_or_else(|| {
            InviteError::local(format!(
                "the certificate {} held carries no signature",
                cert.name
            ))
        })?);
        at = cert.issuer.as_deref().cloned().ok_or_else(|| {
            InviteError::local(format!("the certificate {} names no issuer", cert.name))
        })?;
    }
    Err(InviteError::local(format!(
        "the chain of {} to its namespace's anchor is longer than {CHAIN_MAX} certificates",
        node.writer()
    )))
}

/// Why `ns`, the namespace of an inviter or of an asker, cannot be brought by an
/// introduction (spec §19.3, §19.4): the policy's own refusals, a namespace
/// overlapping this device's, and every namespace it trusts — over or under one,
/// or equal under another anchor. The same namespace under the same anchor is a
/// party known already.
pub(crate) fn overlap(
    node: &NodeHandle,
    policy: &IntroPolicy,
    ns: &Name,
    fingerprint: &[u8; 32],
) -> Option<String> {
    if let Some(why) = policy.refuses(ns) {
        return Some(why);
    }
    let own = node.namespace();
    if ns == own || ns.has_prefix(own) || own.has_prefix(ns) {
        return Some(format!("overlaps this device's own namespace {own}"));
    }
    for ctx in node.validator().keyring().contexts() {
        let held = ctx.namespace();
        if held == ns {
            let same = ctx
                .anchors()
                .iter()
                .any(|a| anchor_fingerprint(a.value()) == *fingerprint);
            if !same {
                return Some("is trusted here already under another anchor".into());
            }
        } else if ns.has_prefix(held) {
            return Some(format!("lies under {held}, which this device trusts"));
        } else if held.has_prefix(ns) {
            return Some(format!("lies over {held}, which this device trusts"));
        }
    }
    None
}
