//! The durable rule's judgement of a Data packet's own signer, shared by the
//! chain walk ([`Validator::validate_durable`](super::Validator::validate_durable))
//! and the forwarder's cache re-check ([`chain_clear`]), so the two never
//! disagree about a revoked key's cut, its key binding, its manifest, or a
//! lapsed key whose role needs a cut.

use std::sync::Arc;

use ndn_packet::{Data, KeyLocator, Name, SignatureType};

use crate::TrustError;
use crate::cert_cache::{CertCache, Certificate};
use crate::cert_name::{is_cert_name, is_reserved_non_cert, key_name_of};
use crate::cut_manifest::{CutManifests, ManifestLookup};
use crate::trust_context::{RevocationCut, SignedTrustContext, public_key_digest};
use crate::verifier::{VerifyOutcome, verify_public_key_signature};

/// How far up a chain [`chain_clear`] follows; a longer chain is not known
/// clear.
const MAX_CHAIN: usize = 8;

/// The durable rule on the packet's own signer, once the certificate (or
/// anchor) whose public key verified the packet is known.
pub(crate) enum SignerRule {
    /// Nothing refuses it.
    Clear,
    /// Refused: the packet is authentic (its signature verified), and the
    /// context refuses it.
    Refused(TrustError),
    /// A cut-manifest packet on the entry's path is not held: the verdict
    /// waits for it (its full name).
    Missing(Name),
}

/// Whether `cut` accepts `packet`, verified under `public_key`.
enum Admit {
    Yes,
    No,
    Missing(Name),
}

fn cut_admits(
    cut: &RevocationCut,
    manifests: &CutManifests,
    packet: &Data,
    public_key: &[u8],
) -> Admit {
    // Bound to one public key: another key certified under the key's name
    // (mis-issued, or re-certified after a compromise) earns nothing.
    if cut
        .key_digest()
        .is_some_and(|d| public_key_digest(public_key) != *d)
    {
        return Admit::No;
    }
    let digest = packet.implicit_digest();
    if cut.accepts_exactly(&packet.name, &digest) {
        return Admit::Yes;
    }
    let Some((range, seq)) = cut.range_seq(&packet.name) else {
        return Admit::No;
    };
    let Some(root) = cut.manifest() else {
        // A cut without a manifest (an older cut) accepts by name.
        return Admit::Yes;
    };
    match manifests.lookup(root, &range.prefix, seq) {
        ManifestLookup::Listed(listed) if listed == digest => Admit::Yes,
        ManifestLookup::Listed(_) | ManifestLookup::NotListed => Admit::No,
        ManifestLookup::Missing(name) => Admit::Missing(name),
    }
}

/// The durable rule on `packet`'s own signer under `ctx`: `locator` is its
/// KeyLocator (a key or certificate name), `verifying` the certificate (or
/// anchor) whose public key verified the packet's signature.
///
/// - Revoked (the locator or the verifying certificate): without a cut,
///   refused; with one, the cut decides alone ([`RevocationCut`]: its key
///   digest must match `verifying`'s public key, an exact entry or a range
///   accepts it, and with a manifest the manifest lists its bytes).
/// - Not revoked, of a device role listed in DataRequiresCut: accepted only
///   while a cached certificate of the key with `verifying`'s public key is
///   valid at `now` (the reader's clock, which can only refuse).
/// - Otherwise clear: no validity period counts.
pub(crate) fn signer_rule(
    ctx: &SignedTrustContext,
    certs: &CertCache,
    packet: &Data,
    locator: &Name,
    verifying: &Certificate,
    now: u64,
) -> SignerRule {
    let key = key_name_of(locator);
    let revoked = [locator, verifying.name.as_ref()]
        .into_iter()
        .find(|n| ctx.is_revoked(n));
    if let Some(revoked) = revoked {
        let refused = |why| {
            SignerRule::Refused(TrustError::Revoked {
                name: revoked.to_string(),
                why,
            })
        };
        let Some(cut) = ctx.revocation_cut(&key) else {
            return refused(TrustError::REVOKED);
        };
        return match cut_admits(cut, certs.cut_manifests(), packet, &verifying.public_key) {
            Admit::Yes => SignerRule::Clear,
            Admit::No => refused(TrustError::REVOKED_OUTSIDE_CUT),
            Admit::Missing(name) => SignerRule::Missing(name),
        };
    }
    if ctx.requires_cut_for(&key) && !valid_now(certs, &key, verifying, now) {
        return SignerRule::Refused(TrustError::Revoked {
            name: key.to_string(),
            why: TrustError::REVOKED_LAPSED,
        });
    }
    SignerRule::Clear
}

/// Whether a certificate of `key` with `verifying`'s public key (it, or
/// one cached) is valid at `now`.
pub(crate) fn valid_now(certs: &CertCache, key: &Name, verifying: &Certificate, now: u64) -> bool {
    verifying.is_valid_at(now)
        || certs
            .all(key)
            .iter()
            .any(|c| c.public_key == verifying.public_key && c.is_valid_at(now))
}

/// Of `certs` (certificates of one key), the newest (NotBefore, then name)
/// whose public key verifies `sig_value` over `region`. `Ok(None)` when
/// `certs` is empty; an error when none verifies.
pub(crate) fn pick_verifying(
    mut certs: Vec<Certificate>,
    region: &[u8],
    sig_value: &[u8],
    sig_type: SignatureType,
) -> Result<Option<Certificate>, TrustError> {
    if certs.is_empty() {
        return Ok(None);
    }
    certs.sort_by(|a, b| (b.valid_from, b.name.as_ref()).cmp(&(a.valid_from, a.name.as_ref())));
    let mut failure = TrustError::InvalidSignature;
    let mut tried: Vec<&bytes::Bytes> = Vec::new();
    for cert in &certs {
        // Certificates of one key usually certify one public key.
        if tried.contains(&&cert.public_key) {
            continue;
        }
        tried.push(&cert.public_key);
        match verify_public_key_signature(sig_type, region, sig_value, &cert.public_key) {
            Ok(VerifyOutcome::Valid) => return Ok(Some(cert.clone())),
            Ok(VerifyOutcome::Invalid) => {}
            Err(e) => failure = e,
        }
    }
    Err(failure)
}

/// Whether `ctx` refuses nothing of `data`, as far as `certs` can tell: the
/// forwarder's Content Store re-check after a revoking update.
///
/// The chain is followed from the KeyLocator through `certs`, each hop
/// resolved to the cached certificate (of any validity) whose public key
/// verifies that hop's signature, the newest first — never merely the newest
/// certificate of the name, which may certify another public key. Known
/// clear when it reaches an anchor of `ctx`, or a certificate with no other
/// issuer above it, without passing a revoked issuer or certificate, and
/// the packet's own signer passes the durable rule the validator applies
/// (cut with its key digest and manifest, DataRequiresCut). A packet that
/// is a certificate `ctx` revokes is not clear, unless its key is revoked
/// with a cut (in-cut Data needs it to verify). Not known clear: a chain
/// `certs` cannot follow that far (a certificate not cached, none of them
/// verifying, a manifest packet not held, more than 8 hops).
pub fn chain_clear(ctx: &SignedTrustContext, certs: &CertCache, data: &Data) -> bool {
    if ctx.revocations().is_empty() && ctx.data_requires_cut().is_empty() {
        return true;
    }
    if ctx.is_revoked(&data.name) {
        let cut_key_certificate = is_cert_name(&data.name)
            && !is_reserved_non_cert(&data.name)
            && ctx.revocation_cut(&key_name_of(&data.name)).is_some();
        if !cut_key_certificate {
            return false;
        }
    }
    let Some(sig_info) = data.sig_info() else {
        return true;
    };
    let mut key: Arc<Name> = match sig_info.key_locator.as_ref() {
        Some(KeyLocator::Name(name)) => Arc::new(Name::clone(name)),
        Some(KeyLocator::KeyDigest(digest)) => match certs.get_by_key_digest(digest) {
            Some(cert) => Arc::new(cert.key_name()),
            None => return false,
        },
        // No signing key (DigestSha256, or unsigned): nothing to revoke.
        None => return true,
    };
    let now = super::now_ns();
    let mut region = bytes::Bytes::copy_from_slice(data.signed_region());
    let mut sig_value = bytes::Bytes::copy_from_slice(data.sig_value());
    let mut sig_type = sig_info.sig_type;
    for depth in 0..MAX_CHAIN {
        // The packet's own signer is judged by `signer_rule` once its
        // verifying certificate is known; a revoked key without a cut is
        // refused before. Issuers are refused by their revocation alone.
        if ctx.is_revoked(&key) && (depth > 0 || ctx.revocation_cut(&key_name_of(&key)).is_none()) {
            return false;
        }
        let anchor = ctx.anchor_for(&key);
        let verifying = match &anchor {
            Some(anchor) => {
                match verify_public_key_signature(sig_type, &region, &sig_value, &anchor.public_key)
                {
                    Ok(VerifyOutcome::Valid) => anchor.clone(),
                    _ => return false,
                }
            }
            None => match pick_verifying(certs.all(&key), &region, &sig_value, sig_type) {
                Ok(Some(cert)) => cert,
                _ => return false,
            },
        };
        if depth == 0 {
            if !matches!(
                signer_rule(ctx, certs, data, &key, &verifying, now),
                SignerRule::Clear
            ) {
                return false;
            }
        } else if ctx.is_revoked(&verifying.name) {
            return false;
        }
        if anchor.is_some() {
            return true;
        }
        // Self-signed, or no issuer named: nothing above it to revoke.
        let Some(issuer) = verifying
            .issuer
            .as_ref()
            .filter(|issuer| key_name_of(issuer) != verifying.key_name())
        else {
            return true;
        };
        // An issuer named, but nothing to verify it with.
        let (Some(sr), Some(sv)) = (&verifying.signed_region, &verifying.sig_value) else {
            return false;
        };
        key = Arc::clone(issuer);
        region = sr.clone();
        sig_value = sv.clone();
        sig_type = verifying.sig_type;
    }
    false
}
