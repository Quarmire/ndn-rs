//! Changing a trust context after it was adopted.
//!
//! - **Bump** ([`bump_context_revoking`], root device only): version `N+1` of
//!   the held context with keys added to its revocation list — and, for one
//!   of them, its revocation cut ([`check_cut`]) — signed by an
//!   anchor key of the held version — the namespace root, unlocked from its
//!   root store ([`crate::root_store`]). Nothing else changes: anchors,
//!   schema, CA endpoints, earlier revocations and their cuts are carried
//!   over verbatim.
//! - **Re-admission** ([`bump_context_readmitting`], root device only):
//!   version `N+1` adding exact packets (full names, ending in their
//!   implicit digest) to the cut of a revoked key ([`readmissions_to_add`]);
//!   everything else carried over verbatim.
//! - **Schema update** ([`bump_context_schema`], root device only): version
//!   `N+1` carrying a new schema (for a namespace made by `ndn-fwd init`, the
//!   current generated one, [`crate::roles::namespace_schema`]) and the
//!   enrollment hint of the policy the namespace's CA enforces, and the link
//!   policy `[ca]` states, else the held one; everything
//!   else is carried over verbatim. This is how a namespace made before a
//!   rule existed gets it (the `#deny` and `#pending` rules of enrollment by
//!   approval), without being initialized again. It is its own operator
//!   action, never a side effect of another bump: a revocation or a recovery
//!   kit must not change what devices may sign, and the operator sees which
//!   rules a schema update adds and removes before the root signs it. A
//!   schema update never narrows what devices may do silently
//!   ([`schema_change`]): every grant of the held schema — an LVS rule's
//!   data pattern with each of its signers, a native rule — must still be
//!   granted, word for word, by the new one, or the update is refused unless
//!   the caller consents to narrowing. Regenerating the generated schema of a
//!   namespace made by an earlier `ndn-fwd init` only adds rules; it narrows
//!   when the held schema is not the generated one — a custom schema signed
//!   in with `ndn-trust-context`, or the key-name schema of the earliest
//!   releases, whose rules read differently even where they grant the same —
//!   and is then refused until the operator has read the rules it drops.
//!   A link policy is held to the same rule: the update is refused unless
//!   the caller consents when a role that could link no longer can, a relay
//!   role is removed, or enrollment links are turned off.
//!   The new version is schema-authoritative, as the generated schema
//!   requires (its cross-identity grants are what the hierarchy floor
//!   forbids).
//! - **Refresh** ([`refresh_context`], every node): ask the namespace for its
//!   newest version by name (RDR metadata, the publication of
//!   `docs/wiki/src/reference/trust-context-publication.md`) and, if it is
//!   newer than the held one, fetch it and adopt it only under the
//!   **continuity rule** ([`open_context_update`]): signed by a key that is an
//!   anchor of the version held now — never merely by an anchor the update
//!   lists itself — and strictly newer. A refused or failed refresh changes
//!   nothing: the held version stays in force.
//! - **Catch-up** ([`follow_versions`]): when the newest version is not
//!   signed by an anchor of the held one — a recovery kit installed a new
//!   root in a version this node missed — the versions in between are
//!   fetched by exact name, oldest first, and each must be signed by an
//!   anchor of the one before it. Every node keeps and serves each version
//!   it held ([`crate::context_store`]), so the chain of signed versions, not
//!   the timing of refreshes, carries a node from any version it held to the
//!   newest. Bounded by [`MAX_CATCH_UP_VERSIONS`] and [`MAX_CATCH_UP_TIME`];
//!   the fetches hold no lock — the newest is adopted only if the version
//!   it was checked against is still held ([`Keyring::adopt_update_from`]).
//!
//! See `docs/wiki/src/reference/revocation.md` and
//! `docs/wiki/src/reference/context-updates.md`.

use std::collections::HashSet;
use std::ops::RangeInclusive;
use std::sync::Arc;

use bytes::Bytes;
use ndn_packet::{Data, Name, NameComponent, tlv_type};
use ndn_security::self_certifying::{Genesis, GenesisError, self_certifying_digest};
use ndn_security::{
    AdvertisedRelay, Certificate, EnrollmentHint, ExpectContextError, Keyring, LinkPolicy,
    LvsModel, OpenContextError, RevocationCut, SchemaBlob, SchemaFormat, SchemaRule,
    SignedTrustContext, SignedTrustContextError, Signer, Validator,
};

use crate::client::CaExchange;
use crate::error::CertError;
use crate::onboarding::{
    AdoptError, CONTEXT_EXPECTATION_TTL, FetchContextError, LinkAdoption, adopt_checked,
    fetch_context_pointer, fetch_versioned_context, rdr_prefix, refused,
};

// ── Bump (root device) ─────────────────────────────────────────────────────

/// The key name `name` designates for revocation: `/<id>/KEY/<k>` for a key
/// name or for any certificate name under it (`/<id>/KEY/<k>/<issuer>/<v>`);
/// `None` when `name` names no key (an identity `/<id>`). Revoking the key
/// name covers every certificate of that key
/// ([`SignedTrustContext::is_revoked`]).
pub fn key_name_of(name: &Name) -> Option<Name> {
    let key = NameComponent::generic(Bytes::from_static(b"KEY"));
    let comps = name.components();
    let at = comps
        .iter()
        .enumerate()
        .rev()
        .find(|(i, c)| **c == key && i + 1 < comps.len())
        .map(|(i, _)| i)?;
    Some(Name::from_components(comps[..at + 2].iter().cloned()))
}

/// The data-layer log of the device the key `key` (`<device>/KEY/<k>`)
/// belongs to: `<device>/32=log`. Every packet a revocation cut or a
/// re-admission names is under it (log entries `<device>/32=log/<C>/seq=<n>`
/// and snapshots `<device>/32=log/seq=<n>`); every other packet the key
/// signed stays refused once it is revoked.
pub fn device_log_of(key: &Name) -> Name {
    let comps = key.components();
    let device = &comps[..comps.len().saturating_sub(2)];
    Name::from_components(device.iter().cloned())
        .append_component(NameComponent::keyword(Bytes::from_static(b"log")))
}

/// A full name — one whose last component is an implicit SHA-256 digest
/// (32 octets) — as the packet's name and its digest; `None` for any other
/// name.
pub fn split_full_name(name: &Name) -> Option<(Name, [u8; 32])> {
    let (last, packet) = name.components().split_last()?;
    if last.typ != tlv_type::IMPLICIT_SHA256 {
        return None;
    }
    let digest: [u8; 32] = last.value.as_ref().try_into().ok()?;
    Some((Name::from_components(packet.iter().cloned()), digest))
}

/// Why [`bump_context_revoking`], [`bump_context_readmitting`] or
/// [`bump_context_schema`] made no new version.
#[derive(Debug, thiserror::Error)]
pub enum BumpError {
    #[error("the held context is not a valid signed trust context: {0}")]
    Unreadable(#[from] OpenContextError),
    #[error(
        "{key} is not an anchor of the held trust context of {namespace} (v{version}), so it \
         cannot sign its next version: only the namespace root signs it — run this on the \
         root device (where `ndn-fwd init --namespace {namespace}` ran)"
    )]
    NotAnAnchor {
        key: String,
        namespace: String,
        version: u64,
    },
    #[error("{name} is not a key name (<identity>/KEY/<key-id>) under {namespace}")]
    NotAKeyOfNamespace { name: String, namespace: String },
    #[error(
        "refusing to revoke {name}: it covers the namespace root {anchor}, and every key of \
         {namespace} chains to it (replacing the root is root rotation, not a revocation)"
    )]
    CoversRoot {
        name: String,
        anchor: String,
        namespace: String,
    },
    #[error("context version {0} cannot be bumped")]
    VersionExhausted(u64),
    #[error(
        "the revocation cut is for {key}, which this version does not revoke (it revokes {}): a \
         cut is added in the version that revokes its key — pass the cut of one of those keys, \
         or revoke {key} itself with it",
        .revoking.join(", ")
    )]
    CutOtherKey {
        key: String,
        /// The keys the version revokes.
        revoking: Vec<String>,
    },
    #[error(
        "{key} is revoked already in v{version} of {namespace}: a cut is added only in the \
         version that revokes its key, and never changes afterwards (it would accept packets \
         every holder refused). Re-admit single packets of it by their full names \
         (`ndn-fwd readmit {key} <full-name>`) if it has a cut; without one, its device \
         publishes again under a new key"
    )]
    CutAfterRevocation {
        key: String,
        namespace: String,
        version: u64,
    },
    #[error(
        "the revocation cut of {key} names {name}, which is not in the key's device log {log}: \
         a cut accepts only log entries its device published (`<device>/32=log/...`); make the \
         cut again from what the device holds verified (the data layer's `cut` of the key)"
    )]
    CutOutsideLog {
        key: String,
        name: String,
        log: String,
    },
    #[error(
        "the revocation cut of {key} lists sequence-number ranges but no cut manifest: a range \
         names entries, not their bytes, so a thief could put other bytes at an accepted name. \
         Make the cut again with a current data layer (its `cut` writes the manifest of every \
         entry the ranges accept, with their digests)"
    )]
    CutWithoutManifest { key: String },
    #[error(
        "the revocation cut of {key} carries no key digest (CutKeyDigest): a new cut must name \
         the public key that signed the entries it accepts, so no other key certified under the \
         same name is ever excused by it. Make the cut again with a current data layer"
    )]
    CutWithoutKeyDigest { key: String },
    #[error("two revocation cuts are given for {key}: give one cut per key")]
    DuplicateCut { key: String },
    #[error(
        "v{version} of {namespace} holds a revocation cut for {key}, which no revocation names: \
         an honest root never signs one (a cut comes only with its key's revocation), so it may \
         have been planted. Revoking {key} now would let that cut decide which of its packets \
         stay accepted — give {key}'s cut made from what this device holds verified (`--cut \
         <file>`, the data layer's `cut` of the key)"
    )]
    OrphanCut {
        key: String,
        namespace: String,
        version: u64,
    },
    #[error(
        "the cut file of {key} records no time bound: the device that wrote it did not say \
         which entries it held before the key was lost, so it may accept what a thief wrote. \
         Write the cut again with the loss time (the data layer's `cut {key} <file> \
         --held-before <when>`)"
    )]
    CutUnbounded { key: String },
    #[error(
        "the cut file of {key} keeps entries first verified up to {held_before} ms since the \
         epoch, later than the loss time given ({lost} ms): entries a thief wrote after the loss \
         could be in it. Write the cut again with `--held-before` at or before the loss time"
    )]
    CutAfterLoss {
        key: String,
        held_before: u64,
        lost: u64,
    },
    #[error(
        "the cut file of {key} does not carry its cut manifest ({reason}): the root publishes \
         the manifest with the version, so readers can check the bytes of every entry the cut \
         accepts. Write the cut file again with the data layer's `cut`"
    )]
    CutManifestIncomplete { key: String, reason: String },
    #[error(
        "{key} is not revoked in v{version} of {namespace}, so it has no cut to re-admit packets \
         into: revoke it with a cut first (`ndn-fwd revoke {key} --cut <file>`)"
    )]
    ReadmitNoCut {
        key: String,
        namespace: String,
        version: u64,
    },
    #[error(
        "{key} is revoked without a cut in v{version} of {namespace}: every packet it signed is \
         refused, and a cut is added only with the revocation of its key, so nothing of it can \
         be re-admitted. Its device publishes the data again under a new key"
    )]
    ReadmitRevokedWithoutCut {
        key: String,
        namespace: String,
        version: u64,
    },
    #[error(
        "{name} is not a full name: a re-admission names one exact packet, so the name must end \
         in the packet's implicit SHA-256 digest component (32 octets) — give the full name the \
         refusal of that packet reported"
    )]
    ReadmitNotFullName { key: String, name: String },
    #[error(
        "{name} is not a packet of {key}'s device log {log}: a key's cut re-admits only log \
         entries of its own device (`<device>/32=log/...`); re-admit it with the cut of the key \
         that signed it"
    )]
    ReadmitOutsideLog {
        key: String,
        name: String,
        log: String,
    },
    #[error(
        "refusing to narrow what devices of {namespace} may do: the new schema drops {} rule(s) \
         the held version (v{version}) grants — {}. A device relying on one would be refused \
         once its node holds the new version. If dropping them is intended (a custom schema \
         this replaces, a rule withdrawn on purpose), sign the update with consent to narrow \
         (`ndn-fwd schema update --accept-narrowing`); otherwise keep v{version}",
        .removed.len(),
        .removed.join("; ")
    )]
    Narrowing {
        namespace: String,
        version: u64,
        /// The held schema's rules the new one no longer grants.
        removed: Vec<String>,
    },
    #[error(
        "refusing to narrow which devices of {namespace} may link: the new link policy ({after}) \
         takes away what the held version (v{version}, {before}) allows — {}. A device relying \
         on it would lose its links once its node holds the new version. If that is intended, \
         sign the update with consent to narrow (`ndn-fwd schema update --accept-narrowing`); \
         otherwise set [ca] link_roles / relay_roles / enrollment_links / direct_paths / \
         direct_pairs to the held policy or remove them",
        .narrowed.join("; ")
    )]
    LinkNarrowing {
        namespace: String,
        version: u64,
        before: String,
        after: String,
        /// What devices could do under the held policy and no longer can.
        narrowed: Vec<String>,
    },
    #[error(
        "refusing to narrow the relays {namespace} advertises: the new version drops what the \
         held version (v{version}) advertises — {}. A device using that relay would lose it \
         once it holds the new version. If that is intended, sign the update with consent to \
         narrow (`ndn-fwd schema update --accept-narrowing`); otherwise keep the held relays as \
         [[ca.relay]] entries, or remove every [[ca.relay]] entry to carry them",
        .dropped.join("; ")
    )]
    RelayNarrowing {
        namespace: String,
        version: u64,
        /// The relays of the held version the new one no longer advertises.
        dropped: Vec<String>,
    },
    #[error("the schema cannot be read: {0}")]
    Schema(String),
    #[error("signing the new version: {0}")]
    Sign(#[from] SignedTrustContextError),
}

/// A new version of a context, signed and ready to adopt, store and publish.
#[derive(Debug)]
pub struct ContextBump {
    pub context: SignedTrustContext,
    /// Its signed Data at `/<ns>/32=trust-context/v=<N+1>`.
    pub data: Data,
    /// The revocation entries this version adds (none for a schema update
    /// or a re-admission).
    pub added: Vec<Name>,
}

/// The entries of `revoke` that a version after `ctx` would add to its
/// revocations — the ones `ctx` does not revoke already, each once; empty when
/// it revokes all of them. Refused when an entry is not a key name
/// ([`key_name_of`]) under the namespace, or is the key of one of its anchors.
/// Needs no key: a caller checks a revocation with it before unlocking the
/// root that signs it ([`bump_context_revoking`] applies the same checks).
pub fn revocations_to_add(
    ctx: &SignedTrustContext,
    revoke: &[Name],
) -> Result<Vec<Name>, BumpError> {
    let namespace = ctx.namespace();
    let mut added = Vec::new();
    for name in revoke {
        if !name.has_prefix(namespace) || key_name_of(name).as_ref() != Some(name) {
            return Err(BumpError::NotAKeyOfNamespace {
                name: name.to_string(),
                namespace: namespace.to_string(),
            });
        }
        if let Some(anchor) = ctx.anchors().iter().find(|a| a.key().has_prefix(name)) {
            return Err(BumpError::CoversRoot {
                name: name.to_string(),
                anchor: anchor.key().to_string(),
                namespace: namespace.to_string(),
            });
        }
        if !ctx.is_revoked(name) && !added.contains(name) {
            added.push(name.clone());
        }
    }
    Ok(added)
}

/// Check the revocation cut `cut` against a version after `ctx` that adds
/// `adding` to its revocations ([`revocations_to_add`]): its key must be
/// one of `adding` (a cut comes with the revocation of exactly its key,
/// never after it), every name it lists (range prefixes, exact names)
/// must be in that key's device log ([`device_log_of`]), it must name the
/// public key that signed what it accepts (CutKeyDigest), and a cut with
/// ranges must carry its manifest (CutManifest: the digest of every entry
/// the ranges accept). Needs no key: a caller checks a cut with it before
/// unlocking the root ([`bump_context_revoking`] applies the same checks).
pub fn check_cut(
    ctx: &SignedTrustContext,
    adding: &[Name],
    cut: &RevocationCut,
) -> Result<(), BumpError> {
    let key = cut.key();
    if !adding.contains(key) {
        if ctx.is_revoked(key) {
            return Err(BumpError::CutAfterRevocation {
                key: key.to_string(),
                namespace: ctx.namespace().to_string(),
                version: ctx.version(),
            });
        }
        return Err(BumpError::CutOtherKey {
            key: key.to_string(),
            revoking: adding.iter().map(Name::to_string).collect(),
        });
    }
    check_cut_names(cut)?;
    if cut.key_digest().is_none() {
        return Err(BumpError::CutWithoutKeyDigest {
            key: key.to_string(),
        });
    }
    if !cut.ranges().is_empty() && cut.manifest().is_none() {
        return Err(BumpError::CutWithoutManifest {
            key: key.to_string(),
        });
    }
    Ok(())
}

/// Refuse `cut` unless every name it lists (range prefixes, exact names)
/// is in its key's device log ([`device_log_of`]).
pub(crate) fn check_cut_names(cut: &RevocationCut) -> Result<(), BumpError> {
    let key = cut.key();
    let log = device_log_of(key);
    let listed = cut.ranges().iter().map(|r| &r.prefix).chain(cut.exact());
    for name in listed {
        if !name.has_prefix(&log) {
            return Err(BumpError::CutOutsideLog {
                key: key.to_string(),
                name: name.to_string(),
                log: log.to_string(),
            });
        }
    }
    Ok(())
}

/// The keys of the cuts `ctx` holds that no revocation of it names
/// (orphan cuts). An honest root never signs one — a cut is added only in
/// the version that revokes its key — so one may have been planted (by
/// whoever held a compromised root) to take effect the day its key is
/// revoked. Versions made from `ctx` do not carry them.
pub fn orphan_cuts(ctx: &SignedTrustContext) -> Vec<Name> {
    ctx.revocation_cuts()
        .iter()
        .filter(|c| !ctx.revocations().contains(c.key()))
        .map(|c| c.key().clone())
        .collect()
}

/// Check the cuts `cuts` of a version after `ctx` that adds `adding` to
/// its revocations: each as [`check_cut`] does, at most one per key; and a
/// key of `adding` that `ctx` holds an orphan cut for ([`orphan_cuts`])
/// must be given its cut here (the orphan is never what decides).
pub fn check_cuts(
    ctx: &SignedTrustContext,
    adding: &[Name],
    cuts: &[RevocationCut],
) -> Result<(), BumpError> {
    for (i, cut) in cuts.iter().enumerate() {
        if cuts[..i].iter().any(|c| c.key() == cut.key()) {
            return Err(BumpError::DuplicateCut {
                key: cut.key().to_string(),
            });
        }
        check_cut(ctx, adding, cut)?;
    }
    let orphans = orphan_cuts(ctx);
    if let Some(key) = adding
        .iter()
        .find(|k| orphans.contains(k) && !cuts.iter().any(|c| c.key() == *k))
    {
        return Err(BumpError::OrphanCut {
            key: key.to_string(),
            namespace: ctx.namespace().to_string(),
            version: ctx.version(),
        });
    }
    Ok(())
}

/// Version `N+1` of the held context `held` (its signed Data, version `N`)
/// with the key names `revoke` added to its revocations, and `cuts` beside
/// them ([`check_cuts`]: each the cut of one of the keys this version
/// adds), signed by `signer`
/// — the key of an anchor of `held` (the namespace root from its root store,
/// or any other anchor the held version lists), through its async signing
/// path, so hardware and custodian signers work. Every other field — the
/// cuts of earlier revocations too — is carried over verbatim, except
/// orphan cuts ([`orphan_cuts`]), which are dropped. The entries
/// are checked as [`revocations_to_add`] does;
/// ones already revoked are not repeated, and `Ok(None)` when all of them are
/// (no new version is needed, nothing is signed; a cut is then refused, as
/// its key is revoked already). Pure: nothing is adopted, stored or
/// published.
pub async fn bump_context_revoking(
    signer: &dyn Signer,
    held: &Data,
    revoke: &[Name],
    cuts: &[RevocationCut],
) -> Result<Option<ContextBump>, BumpError> {
    let (ctx, _signed_by) = SignedTrustContext::open_signed(held).await?;
    ensure_anchor(signer, &ctx)?;

    let added = revocations_to_add(&ctx, revoke)?;
    check_cuts(&ctx, &added, cuts)?;
    if added.is_empty() {
        return Ok(None);
    }

    let version = next_version(&ctx)?;
    // `held` verified above, so its Content is present and decodes.
    let content = held.content().map(|c| c.as_ref()).unwrap_or_default();
    let orphans = orphan_cuts(&ctx);
    let mut next = SignedTrustContext::decode_content(content, version)?
        .without_revocation_cuts(|c| orphans.contains(c.key()));
    for name in &added {
        next = next.with_revocation(name.clone());
    }
    for cut in cuts {
        next = next.with_revocation_cut(cut.clone());
    }
    let data = next.sign_into_data_async(signer).await?;
    Ok(Some(ContextBump {
        context: next,
        data,
        added,
    }))
}

/// The cut of `key` in `ctx` and the names of `names` a version after `ctx`
/// would add to it as exact entries: those it does not accept already,
/// each once; empty when it accepts all of them. Refused when `key` is not
/// a key name under the namespace, has no cut (not revoked, or revoked
/// without one), or a name is not a full name (ending in its implicit
/// digest) in the key's device log ([`device_log_of`]).
fn readmission(
    ctx: &SignedTrustContext,
    key: &Name,
    names: &[Name],
) -> Result<(RevocationCut, Vec<Name>), BumpError> {
    let namespace = ctx.namespace();
    if !key.has_prefix(namespace) || key_name_of(key).as_ref() != Some(key) {
        return Err(BumpError::NotAKeyOfNamespace {
            name: key.to_string(),
            namespace: namespace.to_string(),
        });
    }
    let Some(cut) = ctx.revocation_cut(key) else {
        let revoked = ctx.is_revoked(key);
        let (key, namespace, version) = (key.to_string(), namespace.to_string(), ctx.version());
        return Err(if revoked {
            BumpError::ReadmitRevokedWithoutCut {
                key,
                namespace,
                version,
            }
        } else {
            BumpError::ReadmitNoCut {
                key,
                namespace,
                version,
            }
        });
    };
    let log = device_log_of(key);
    let mut added: Vec<Name> = Vec::new();
    for name in names {
        let Some((packet, digest)) = split_full_name(name) else {
            return Err(BumpError::ReadmitNotFullName {
                key: key.to_string(),
                name: name.to_string(),
            });
        };
        // The packet's name (without its digest) is an entry below the log.
        if !packet.has_prefix(&log) || packet.len() <= log.len() {
            return Err(BumpError::ReadmitOutsideLog {
                key: key.to_string(),
                name: name.to_string(),
                log: log.to_string(),
            });
        }
        // A name inside a range is decided by the range (with a manifest:
        // only the bytes it lists), never by a re-admission of other bytes.
        let in_range = cut.range_seq(&packet).is_some();
        if !in_range && !cut.accepts(&packet, &digest) && !added.contains(name) {
            added.push(name.clone());
        }
    }
    Ok((cut.clone(), added))
}

/// The full names of `names` a version after `ctx` would add to the cut of
/// the revoked key `key` as exact entries (re-admission) — those the cut
/// does not accept already, each once; empty when it accepts all of them.
/// Refused when `key` is not a key name under the namespace, has no cut
/// (not revoked: revoke it with a cut first; revoked without one: nothing
/// of it can be re-admitted), or a name is not a full name (ending in its
/// 32-octet implicit digest) of the key's device log ([`device_log_of`]).
/// Needs no key ([`bump_context_readmitting`] applies the same checks).
pub fn readmissions_to_add(
    ctx: &SignedTrustContext,
    key: &Name,
    names: &[Name],
) -> Result<Vec<Name>, BumpError> {
    readmission(ctx, key, names).map(|(_, added)| added)
}

/// Version `N+1` of the held context `held` with the full names `names`
/// added to the cut of the revoked key `key` as exact entries
/// (re-admission: each accepts one packet, by name and digest; never a
/// range), signed by `signer`, an anchor key of `held`. Checked as
/// [`readmissions_to_add`] does; `Ok(None)` when the cut accepts all of
/// them already (nothing is signed). Every other field — the cut's ranges
/// and earlier exact entries, the other cuts — is carried over verbatim.
/// Pure: nothing is adopted, stored or published.
pub async fn bump_context_readmitting(
    signer: &dyn Signer,
    held: &Data,
    key: &Name,
    names: &[Name],
) -> Result<Option<ContextBump>, BumpError> {
    let (ctx, _signed_by) = SignedTrustContext::open_signed(held).await?;
    ensure_anchor(signer, &ctx)?;
    let (mut cut, added) = readmission(&ctx, key, names)?;
    if added.is_empty() {
        return Ok(None);
    }
    for name in added {
        cut.readmit(name.clone())
            .map_err(|_| BumpError::ReadmitNotFullName {
                key: key.to_string(),
                name: name.to_string(),
            })?;
    }

    let version = next_version(&ctx)?;
    // `held` verified above, so its Content is present and decodes.
    let content = held.content().map(|c| c.as_ref()).unwrap_or_default();
    let next = SignedTrustContext::decode_content(content, version)?.with_revocation_cut(cut);
    let data = next.sign_into_data_async(signer).await?;
    Ok(Some(ContextBump {
        context: next,
        data,
        added: Vec::new(),
    }))
}

/// Version `N+1` of the held context `held` listing exactly `roles` in
/// DataRequiresCut (0x0434; empty: none), signed by `signer`, an anchor key
/// of `held`. Data a key of a listed role signs is accepted only while a
/// certificate of the key is valid by the reader's clock, or once the key
/// is revoked with a cut that accepts it. `Ok(None)` when `held` lists
/// exactly these roles already (nothing is signed). Every other field is
/// carried over verbatim. Pure: nothing is adopted, stored or published.
pub async fn bump_context_data_requires_cut(
    signer: &dyn Signer,
    held: &Data,
    roles: &[crate::roles::Role],
) -> Result<Option<ContextBump>, BumpError> {
    let (ctx, _signed_by) = SignedTrustContext::open_signed(held).await?;
    ensure_anchor(signer, &ctx)?;
    let mut wanted: Vec<String> = roles.iter().map(|r| r.as_str().to_string()).collect();
    wanted.sort();
    wanted.dedup();
    if ctx.data_requires_cut() == wanted.as_slice() {
        return Ok(None);
    }
    let version = next_version(&ctx)?;
    // `held` verified above, so its Content is present and decodes.
    let content = held.content().map(|c| c.as_ref()).unwrap_or_default();
    let mut next = SignedTrustContext::decode_content(content, version)?;
    for role in ctx.data_requires_cut() {
        next = next.without_data_requires_cut(role);
    }
    for role in wanted {
        next = next.with_data_requires_cut(role);
    }
    let data = next.sign_into_data_async(signer).await?;
    Ok(Some(ContextBump {
        context: next,
        data,
        added: Vec::new(),
    }))
}

/// Refuse `signer` unless it is the key of an anchor of `ctx`: only those
/// sign its next version (the continuity rule every node applies).
fn ensure_anchor(signer: &dyn Signer, ctx: &SignedTrustContext) -> Result<(), BumpError> {
    let is_anchor = signer.public_key().is_some_and(|pk| {
        ctx.anchors()
            .iter()
            .any(|a| crate::root_store::same_public_key(&a.value().public_key, &pk))
    });
    if is_anchor {
        return Ok(());
    }
    Err(BumpError::NotAnAnchor {
        key: signer.key_name().to_string(),
        namespace: ctx.namespace().to_string(),
        version: ctx.version(),
    })
}

fn next_version(ctx: &SignedTrustContext) -> Result<u64, BumpError> {
    ctx.version()
        .checked_add(1)
        .ok_or(BumpError::VersionExhausted(ctx.version()))
}

// ── Schema update (root device) ────────────────────────────────────────────

/// What a schema update changes, decided before the root is unlocked
/// ([`schema_change`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaChange {
    /// Rules the new schema grants that the held one does not.
    pub added: Vec<String>,
    /// Rules the held schema grants that the new one does not: what devices
    /// would lose. Non-empty only with consent to narrowing.
    pub removed: Vec<String>,
    /// The held version's enrollment hint.
    pub hint_before: Option<EnrollmentHint>,
    /// The enrollment hint the new version carries.
    pub hint: EnrollmentHint,
    /// The held version is not schema-authoritative; the new one is.
    pub becomes_authoritative: bool,
    /// The held version's link policy (stated, else the default).
    pub link_before: LinkPolicy,
    /// The link policy the new version carries.
    pub link: LinkPolicy,
    /// What devices could do under `link_before` and no longer can under
    /// `link`. Non-empty only with consent to narrowing.
    pub link_narrowed: Vec<String>,
    /// The relays the held version advertises.
    pub relays_before: Vec<AdvertisedRelay>,
    /// The relays the new version advertises.
    pub relays: Vec<AdvertisedRelay>,
    /// The relays of `relays_before` the new version drops
    /// ([`relay_narrowing`]). Non-empty only with consent to narrowing.
    pub relays_dropped: Vec<String>,
}

impl SchemaChange {
    /// Whether the new version carries another enrollment hint.
    pub fn changes_hint(&self) -> bool {
        self.hint_before.as_ref() != Some(&self.hint)
    }

    /// Whether the new version carries another link policy.
    pub fn changes_link(&self) -> bool {
        self.link_before != self.link
    }

    /// Whether the new version advertises other relays.
    pub fn changes_relays(&self) -> bool {
        !same_relays(&self.relays_before, &self.relays)
    }

    /// Nothing to sign: the held version carries these rules, this hint,
    /// this link policy, these relays and the authoritative flag already.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty()
            && self.removed.is_empty()
            && !self.changes_hint()
            && !self.changes_link()
            && !self.changes_relays()
            && !self.becomes_authoritative
    }
}

/// What devices may do under `before` and no longer under `after`: a role
/// that could link and no longer can (every role → a list counts), a relay
/// role removed, enrollment links or direct paths turned off, a pair of
/// roles that may no longer make direct paths. Empty: `after` only widens.
pub fn link_narrowing(before: &LinkPolicy, after: &LinkPolicy) -> Vec<String> {
    let mut narrowed = Vec::new();
    if before.roles.is_empty() && !after.roles.is_empty() {
        narrowed.push(format!(
            "every role could link, now only {}",
            after.roles.join(", ")
        ));
    }
    for role in before.roles.iter().filter(|r| !after.allows_link(r)) {
        narrowed.push(format!("{role} devices may no longer link"));
    }
    for role in before
        .relay_roles
        .iter()
        .filter(|r| !after.relay_roles.contains(r))
    {
        narrowed.push(format!("{role} devices may no longer relay"));
    }
    if before.enrollment_links && !after.enrollment_links {
        narrowed.push("relays no longer admit enrollment links".to_string());
    }
    if before.direct_paths && !after.direct_paths {
        narrowed.push("linked devices may no longer try direct paths".to_string());
    } else if before.direct_paths {
        for (a, b) in before
            .canonical_direct_pairs()
            .iter()
            .filter(|(a, b)| !after.allows_direct_path(a, b))
        {
            narrowed.push(if a == b {
                format!("two {a} devices may no longer make a direct path with each other")
            } else {
                format!("{a} and {b} devices may no longer make direct paths with each other")
            });
        }
    }
    narrowed
}

/// The relays of `before` that `after` no longer advertises: one whose
/// device `after` does not list, or lists only with another expected
/// fingerprint. Empty: `after` only adds relays or moves them to other
/// endpoints or preferences.
pub fn relay_narrowing(before: &[AdvertisedRelay], after: &[AdvertisedRelay]) -> Vec<String> {
    before
        .iter()
        .filter(|b| {
            !after
                .iter()
                .any(|a| a.device == b.device && (a.key.is_none() || a.key == b.key))
        })
        .map(|b| {
            if after.iter().any(|a| a.device == b.device) {
                format!(
                    "{} is advertised with another expected fingerprint",
                    b.device
                )
            } else {
                format!("{} is no longer advertised as a relay", b.device)
            }
        })
        .collect()
}

/// Whether two relay lists advertise the same relays, in any order.
pub(crate) fn same_relays(a: &[AdvertisedRelay], b: &[AdvertisedRelay]) -> bool {
    a.len() == b.len() && a.iter().all(|r| b.contains(r)) && b.iter().all(|r| a.contains(r))
}

/// A schema update signed by [`bump_context_schema`].
#[derive(Debug)]
pub struct SchemaBump {
    pub bump: ContextBump,
    pub change: SchemaChange,
}

/// Every grant of a schema, as `(comparison key, rule as shown)`: an LVS
/// rule's data pattern with each of its signers (`#rule: <pattern> <=
/// #signer`, compared by both patterns, not by rule names or node ids),
/// and each native rule (`<data> => <key>`, compared in its canonical form).
fn schema_grants(blobs: &[SchemaBlob]) -> Result<Vec<(String, String)>, BumpError> {
    let mut grants = Vec::new();
    for (i, blob) in blobs.iter().enumerate() {
        match blob.format {
            SchemaFormat::Lvs => {
                let model = LvsModel::decode(&blob.body)
                    .map_err(|e| BumpError::Schema(format!("schema blob {i} (LVS binary): {e}")))?;
                for node in &model.nodes {
                    if node.sign_constraints.is_empty() {
                        continue;
                    }
                    let Some(pattern) = model.node_pattern(node.id) else {
                        continue;
                    };
                    let label = model.node_label(node.id);
                    for signer in &node.sign_constraints {
                        let signer_label = model.node_label(*signer);
                        let signer_pattern = model
                            .node_pattern(*signer)
                            .unwrap_or_else(|| signer_label.clone());
                        grants.push((
                            format!("lvs {pattern} <= {signer_pattern}"),
                            format!("{label}: {pattern} <= {signer_label}"),
                        ));
                    }
                }
            }
            SchemaFormat::NativeText => {
                let text = std::str::from_utf8(&blob.body).map_err(|_| {
                    BumpError::Schema(format!("schema blob {i} (native rules) is not UTF-8"))
                })?;
                for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
                    let rule = SchemaRule::parse(line)
                        .map_err(|e| {
                            BumpError::Schema(format!("schema blob {i}: rule {line:?}: {e}"))
                        })?
                        .to_string();
                    grants.push((format!("native {rule}"), rule));
                }
            }
            // Kept verbatim, not understood here: dropping it is a narrowing
            // for the nodes that do understand it.
            SchemaFormat::Unknown(code) => {
                let body: String = blob.body.iter().map(|b| format!("{b:02x}")).collect();
                grants.push((
                    format!("format {code} {body}"),
                    format!(
                        "schema blob {i} in format {code} ({} bytes, not understood here)",
                        blob.body.len()
                    ),
                ));
            }
        }
    }
    Ok(grants)
}

/// The rules of `next` not in `held`, each once, in `next`'s order.
fn grants_missing(next: &[(String, String)], held: &[(String, String)]) -> Vec<String> {
    let held: HashSet<&str> = held.iter().map(|(key, _)| key.as_str()).collect();
    let mut seen = HashSet::new();
    next.iter()
        .filter(|(key, _)| !held.contains(key.as_str()) && seen.insert(key.as_str()))
        .map(|(_, shown)| shown.clone())
        .collect()
}

/// What a version after `ctx` carrying `schema`, `hint`, the link policy
/// `link` and the relays `relays` (`None`: the held ones, carried verbatim)
/// would change: the rules it adds and removes, and whether the hint, the
/// link policy, the relays or the authoritative flag change
/// ([`SchemaChange::is_empty`]: nothing to sign). Refused unless
/// `accept_narrowing` when a rule of `ctx` is missing from `schema`
/// ([`BumpError::Narrowing`], listing the rules devices would lose), `link`
/// takes away what the held policy allows ([`BumpError::LinkNarrowing`],
/// [`link_narrowing`]) or `relays` drops a held relay
/// ([`BumpError::RelayNarrowing`], [`relay_narrowing`]). Needs no key: a
/// caller checks a schema update with it before unlocking the root that
/// signs it ([`bump_context_schema`] applies the same checks).
pub fn schema_change(
    ctx: &SignedTrustContext,
    schema: &[SchemaBlob],
    hint: &EnrollmentHint,
    link: Option<&LinkPolicy>,
    relays: Option<&[AdvertisedRelay]>,
    accept_narrowing: bool,
) -> Result<SchemaChange, BumpError> {
    let held = schema_grants(&ctx.published_schemas())?;
    let next = schema_grants(schema)?;
    let removed = grants_missing(&held, &next);
    if !removed.is_empty() && !accept_narrowing {
        return Err(BumpError::Narrowing {
            namespace: ctx.namespace().to_string(),
            version: ctx.version(),
            removed,
        });
    }
    let link_before = ctx.link_policy();
    let link = link.cloned().unwrap_or_else(|| link_before.clone());
    let link_narrowed = link_narrowing(&link_before, &link);
    if !link_narrowed.is_empty() && !accept_narrowing {
        return Err(BumpError::LinkNarrowing {
            namespace: ctx.namespace().to_string(),
            version: ctx.version(),
            before: link_before.describe(),
            after: link.describe(),
            narrowed: link_narrowed,
        });
    }
    let relays_before = ctx.relays().to_vec();
    let relays = relays.map_or_else(|| relays_before.clone(), <[AdvertisedRelay]>::to_vec);
    let relays_dropped = relay_narrowing(&relays_before, &relays);
    if !relays_dropped.is_empty() && !accept_narrowing {
        return Err(BumpError::RelayNarrowing {
            namespace: ctx.namespace().to_string(),
            version: ctx.version(),
            dropped: relays_dropped,
        });
    }
    Ok(SchemaChange {
        added: grants_missing(&next, &held),
        removed,
        hint_before: ctx.enrollment_hint().cloned(),
        hint: hint.clone(),
        becomes_authoritative: !ctx.schema_is_authoritative(),
        link_before,
        link,
        link_narrowed,
        relays_before,
        relays,
        relays_dropped,
    })
}

/// Version `N+1` of the held context `held` (its signed Data, version `N`)
/// carrying the schema blobs `schema` (their OR is the schema: at most one
/// LVS binary, plus native rules — as
/// [`NamespaceSchema::blobs`](crate::roles::NamespaceSchema::blobs) gives)
/// and the enrollment hint `hint`, schema-authoritative, signed by `signer`
/// — the key of an anchor of `held`, as for [`bump_context_revoking`].
/// It states the link policy `link` and advertises the relays `relays`
/// when they differ from the held ones; otherwise (and with `None`) the
/// held ones are carried over verbatim, like anchors, CA endpoints,
/// revocations and key roles. Checked as [`schema_change`] checks (a
/// narrowing of the schema, the link policy or the relays refused unless
/// `accept_narrowing`); `Ok(None)` when `held` carries these rules, this
/// hint, this link policy and these relays already (nothing is signed).
/// Pure: nothing is adopted, stored or published.
pub async fn bump_context_schema(
    signer: &dyn Signer,
    held: &Data,
    schema: &[SchemaBlob],
    hint: &EnrollmentHint,
    link: Option<&LinkPolicy>,
    relays: Option<&[AdvertisedRelay]>,
    accept_narrowing: bool,
) -> Result<Option<SchemaBump>, BumpError> {
    let (ctx, _signed_by) = SignedTrustContext::open_signed(held).await?;
    ensure_anchor(signer, &ctx)?;
    let change = schema_change(&ctx, schema, hint, link, relays, accept_narrowing)?;
    if change.is_empty() {
        return Ok(None);
    }

    let version = next_version(&ctx)?;
    // `held` verified above, so its Content is present and decodes.
    let content = held.content().map(|c| c.as_ref()).unwrap_or_default();
    let mut next = SignedTrustContext::decode_content(content, version)?
        .with_schema_blobs(schema.to_vec())
        .map_err(|e| BumpError::Schema(e.to_string()))?
        .with_enrollment_hint(hint.clone())
        .schema_authoritative();
    if change.changes_link() {
        next = next.with_link_policy(change.link.clone());
    }
    if change.changes_relays() {
        next = next.with_relays(change.relays.clone());
    }
    let data = next.sign_into_data_async(signer).await?;
    Ok(Some(SchemaBump {
        bump: ContextBump {
            context: next,
            data,
            added: Vec::new(),
        },
        change,
    }))
}

// ── Refresh (every node) ───────────────────────────────────────────────────

/// How many versions a refresh follows one by one ([`follow_versions`]) at
/// most, when the newest is not signed by an anchor of the held version. A
/// version is one operator action on the root device (a revocation, a
/// recovery kit added or revoked, a recovery), so this covers a node that
/// was offline across years of a namespace's changes, at one Interest per
/// version and within a management command's wait; a node further behind
/// adopts the namespace again from a current anchor link, which costs one
/// fetch. A self-certifying namespace has no such shortcut — it is adopted
/// again only from its genesis, a longer walk still — so its walks are not
/// bounded by position, only by [`MAX_CATCH_UP_TIME`] when they fetch.
pub const MAX_CATCH_UP_VERSIONS: u64 = 128;

/// How long a refresh's walk ([`follow_versions`]) fetches versions at
/// most: a walk whose upstream answers the newest version's name but lets
/// every version time out would otherwise take one Interest lifetime per
/// position. Positions not fetched by then count as unreachable — the walk
/// stops with nothing adopted, and the next refresh starts again from the
/// version held. It fits, with the newest version's two fetches, within
/// the wait of a management command that runs a refresh.
pub const MAX_CATCH_UP_TIME: std::time::Duration = std::time::Duration::from_secs(40);

/// Why a fetched update was not adopted.
#[derive(Debug, thiserror::Error)]
pub enum UpdateRefusal {
    #[error("{0}")]
    Unauthentic(#[from] OpenContextError),
    #[error("it is a context for {found}, not {expected}")]
    OtherNamespace { expected: String, found: String },
    #[error("it is version {offered}, not newer than the held version {held}")]
    NotNewer { offered: u64, held: u64 },
    #[error(
        "it is signed by {signer}, which is not an anchor of the held version v{held} (an \
         update must be signed by the root this node already trusts)"
    )]
    NotSignedByHeldAnchor { signer: String, held: u64 },
    #[error("this node's forwarder dropped it: {0}")]
    DroppedByForwarder(String),
    /// The newest version does not follow from the held one directly, and
    /// the versions in between did not carry this node to it.
    #[error(
        "v{offered} does not follow from the held version v{held} directly, and following the \
         versions in between failed: {stop}"
    )]
    CatchUp {
        held: u64,
        offered: u64,
        stop: CatchUpStop,
    },
}

/// `v<first>` or `v<first>..=v<last>`.
fn versions(first: &u64, last: &u64) -> String {
    if first == last {
        format!("v{first}")
    } else {
        format!("v{first}..=v{last}")
    }
}

/// Why [`follow_versions`] did not reach the newest version. Nothing is
/// adopted in any case.
#[derive(Debug, thiserror::Error)]
pub enum CatchUpStop {
    #[error(
        "that is {gap} versions, more than the {max} a refresh follows one by one; adopt the \
         namespace again from a current anchor link"
    )]
    TooFar { gap: u64, max: u64 },
    #[error(
        "v{version} was refused: {refusal}. Whatever served it does not serve this namespace's \
         versions; if the namespace changed its root, adopt it again from a current anchor link"
    )]
    Refused {
        version: u64,
        refusal: Box<UpdateRefusal>,
    },
    #[error(
        "{} could not be fetched ({reason}), and v{version} does not follow without them \
         ({refusal}); retry once a node that kept them is reachable (every node serves the \
         versions it held), or adopt the namespace again from a current anchor link",
        versions(.first, .last)
    )]
    Missing {
        first: u64,
        last: u64,
        reason: String,
        version: u64,
        refusal: Box<UpdateRefusal>,
    },
    #[error("v{version} could not be fetched ({reason}); retry once it is reachable")]
    Unreachable { version: u64, reason: String },
    #[error("{0}")]
    InProgress(#[from] ExpectContextError),
}

/// One version a walk went through ([`follow_versions`]).
#[derive(Debug)]
pub struct ContextStep {
    pub context: Arc<SignedTrustContext>,
    /// The signed Data exactly as received (what to persist and publish).
    pub data: Data,
    /// The anchor of the version before it that signed it.
    pub signer: Certificate,
}

/// Why a [`VersionSource`] returned no Data for a position.
#[derive(Debug)]
pub enum Unfetched {
    /// Nothing usable arrived (no route, no answer, a reply under another
    /// name, not a Data packet): why.
    Missing(String),
    /// Something arrived, and this node's forwarder dropped it: why.
    Dropped(String),
    /// Another adoption or update of the namespace runs on this node.
    InProgress(ExpectContextError),
}

/// Where [`follow_versions`] gets the signed context Data of each position
/// of a walk: a version fetched by its exact name (a refresh), or a sync
/// group's sequence number, which is the version its publisher republished
/// (`ndn_identity::context_sync`).
pub trait VersionSource {
    /// The signed context Data at `position`, fetched as an update of
    /// `from` — the version the walk has reached, which a validating
    /// forwarder is told to expect an update of.
    fn fetch(
        &mut self,
        position: u64,
        from: &SignedTrustContext,
    ) -> impl Future<Output = Result<Data, Unfetched>> + Send;
}

/// Why [`refresh_context`] could not check for, or adopt, an update. The held
/// version stays in force in every case.
#[derive(Debug, thiserror::Error)]
pub enum RefreshError {
    #[error("no trust context is held for {0}; adopt it first")]
    NotHeld(String),
    /// Nothing answered the Interest for the newest version's name (no
    /// route, no reply, a Nack): the namespace could not be asked at all.
    /// Unlike [`Self::Fetch`], nothing announced a version either.
    #[error(
        "nothing answered for the newest trust context of {namespace} ({source}); the held \
         version v{held} stays in force"
    )]
    NoAnswer {
        namespace: String,
        held: u64,
        #[source]
        source: FetchContextError,
    },
    #[error(
        "could not check {namespace} for a newer trust context ({source}); the held version \
         v{held} stays in force"
    )]
    Fetch {
        namespace: String,
        held: u64,
        #[source]
        source: FetchContextError,
    },
    #[error(
        "refused a trust-context update for {namespace}: {refusal}; the held version v{held} \
         stays in force"
    )]
    Refused {
        namespace: String,
        held: u64,
        #[source]
        refusal: UpdateRefusal,
    },
    #[error("{0}")]
    InProgress(#[from] ExpectContextError),
    /// The held version changed while the refresh fetched and checked the
    /// newest one against it (another command adopted a version), so
    /// nothing was adopted from this refresh.
    #[error(
        "the held trust context of {namespace} changed from v{held} to v{now} during the \
         refresh; nothing was adopted from it — the next refresh starts from v{now}"
    )]
    ChangedMeanwhile {
        namespace: String,
        held: u64,
        now: u64,
    },
}

/// What [`refresh_context`] found.
// Boxing would change the public API; these are cold control-plane results.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum ContextRefresh {
    /// The namespace serves the version held.
    Current { version: u64 },
    /// What answered serves an older version than held (e.g. a relay that
    /// has not refreshed yet); nothing changed.
    UpstreamOlder { held: u64, offered: u64 },
    /// A newer version was adopted into the keyring.
    Updated(ContextUpdate),
}

/// A newer context adopted by [`refresh_context`]. Persisting and publishing
/// it — and the versions in `walked` — are the caller's.
#[derive(Debug)]
pub struct ContextUpdate {
    /// The version held before.
    pub previous: u64,
    pub context: Arc<SignedTrustContext>,
    /// The signed Data exactly as received (what to persist and publish).
    pub data: Data,
    /// The anchor that signed it: of the held version, or — after a walk —
    /// of the last version in `walked`.
    pub signer: Certificate,
    /// Revocation entries this version adds to the held one.
    pub revoked: Vec<Name>,
    /// The versions between `previous` and `context` this node followed one
    /// by one, oldest first, because the newest is not signed by an anchor
    /// of the held version ([`follow_versions`]); empty when it is. Keep and
    /// serve them too, so the nodes behind this one can follow the same way.
    pub walked: Vec<ContextStep>,
}

/// Open `data` as an update of the held context `held`: a self-consistent
/// signed context whose signing anchor is valid now
/// ([`SignedTrustContext::open_received`]) of the same namespace, strictly
/// newer, and signed by a key that is an anchor of `held` — the continuity
/// rule: an update is authorized by the version it replaces. A new version
/// may list other anchors (a root rotation is signed by the old root), but
/// those are trusted only once it is adopted. The held anchor is matched by
/// public key only, not by its certificate's validity, so a root whose held
/// certificate expired still signs a version re-issuing it.
pub async fn open_context_update(
    held: &SignedTrustContext,
    data: &Data,
) -> Result<(SignedTrustContext, Certificate), UpdateRefusal> {
    let (ctx, signer) = SignedTrustContext::open_received(data).await?;
    if ctx.namespace() != held.namespace() {
        return Err(UpdateRefusal::OtherNamespace {
            expected: held.namespace().to_string(),
            found: ctx.namespace().to_string(),
        });
    }
    if ctx.version() <= held.version() {
        return Err(UpdateRefusal::NotNewer {
            offered: ctx.version(),
            held: held.version(),
        });
    }
    // `open_signed` verified the signature under `signer`'s key; that key
    // must be one the held version names as an anchor.
    let held_anchor = held
        .anchors()
        .iter()
        .find(|a| a.value().public_key == signer.public_key)
        .map(|a| a.value().clone())
        .ok_or_else(|| UpdateRefusal::NotSignedByHeldAnchor {
            signer: signer.name.to_string(),
            held: held.version(),
        })?;
    Ok((ctx, held_anchor))
}

/// Why [`fetch_update`] returned no Data.
enum UpdateFetchError {
    Fetch(FetchContextError),
    /// Something answered, and this node's forwarder dropped it: why.
    Dropped(String),
    InProgress(ExpectContextError),
}

impl From<UpdateFetchError> for Unfetched {
    fn from(e: UpdateFetchError) -> Self {
        match e {
            UpdateFetchError::Fetch(source) => Unfetched::Missing(source.to_string()),
            UpdateFetchError::Dropped(reason) => Unfetched::Dropped(reason),
            UpdateFetchError::InProgress(e) => Unfetched::InProgress(e),
        }
    }
}

/// Fetch the context named `versioned` as an update of `from`. Through a
/// validating forwarder (`forwarder`), it is told to expect an update signed
/// by an anchor of `from` ([`Validator::expect_context_update`]), so it
/// admits it even if it does not hold the context itself, and a refused one
/// is reported with why — at once: the forwarder answers the refused Data's
/// Interest with a refusal Nack ([`CertError::Refused`]) rather than letting
/// it time out.
async fn fetch_update<E>(
    exchange: &mut E,
    forwarder: Option<&Validator>,
    from: &SignedTrustContext,
    versioned: &Name,
) -> Result<Data, UpdateFetchError>
where
    E: CaExchange + ?Sized,
{
    let expectation = forwarder
        .map(|v| v.expect_context_update(from, CONTEXT_EXPECTATION_TTL))
        .transpose()
        .map_err(UpdateFetchError::InProgress)?;
    let fetched = fetch_versioned_context(exchange, versioned).await;
    let outcome = expectation.map(|e| e.finish()).unwrap_or_default();
    fetched.map_err(|source| match (outcome.refused, source) {
        (Some(reason), _) => UpdateFetchError::Dropped(reason),
        // A final refusal is about what the version is; one for now
        // (`unverifiable`) is a fetch to try again, like no answer.
        (
            None,
            FetchContextError::Transport {
                source: CertError::Refused { reason, .. },
                ..
            },
        ) if reason.is_final() => UpdateFetchError::Dropped(format!("refused it ({reason})")),
        (None, source) => UpdateFetchError::Fetch(source),
    })
}

/// A refresh's [`VersionSource`]: each version fetched by its exact name,
/// `<ns>/32=trust-context/v=<N>`, from wherever the namespace is served.
struct ByName<'a, E: ?Sized> {
    exchange: &'a mut E,
    forwarder: Option<&'a Validator>,
    namespace: &'a Name,
    /// The newest version, already fetched once (and not following from the
    /// held version directly), so the walk does not fetch it again.
    newest: Option<(u64, Data)>,
    /// No fetch starts after this ([`MAX_CATCH_UP_TIME`]).
    deadline: web_time::Instant,
}

impl<E> VersionSource for ByName<'_, E>
where
    E: CaExchange + Send + ?Sized,
{
    async fn fetch(&mut self, position: u64, from: &SignedTrustContext) -> Result<Data, Unfetched> {
        if let Some((_, data)) = self.newest.take_if(|(version, _)| *version == position) {
            return Ok(data);
        }
        if web_time::Instant::now() >= self.deadline {
            return Err(Unfetched::Missing(format!(
                "the walk fetches for {}s at most",
                MAX_CATCH_UP_TIME.as_secs()
            )));
        }
        let versioned = rdr_prefix(self.namespace).append_version(position);
        Ok(fetch_update(&mut *self.exchange, self.forwarder, from, &versioned).await?)
    }
}

/// Follow `held`'s namespace from `held` through `positions`, in order —
/// the versions this node is missing, oldest first — adopting nothing:
/// each version must be signed by an anchor of the version before it (the
/// continuity rule, [`open_context_update`]), the first by an anchor of
/// `held`. So a node holding `N` follows `N+1`, signed by a recovery key
/// that is an anchor of `N`, and then `N+2`, signed by the new root that
/// `N+1` installed, though `N+2` alone is not signed by any anchor of `N`.
///
/// - A position whose Data cannot be fetched is passed over — a version the
///   upstream never held, or a sequence number that carries none — as long
///   as a later one follows from the version reached; otherwise the walk
///   ends at that later one, naming the versions it missed.
/// - A Data that arrives and is refused (forged, foreign, or not signed by
///   an anchor of the version before it) ends the walk.
/// - A position carrying a version not newer than the one reached is passed
///   over, except the last.
/// - The last position must be fetched and must follow.
///
/// At most [`MAX_CATCH_UP_VERSIONS`] positions are walked; a longer range
/// is refused before anything is fetched — except for a self-certifying
/// namespace, whose walk is the only way to its newest version (a walk
/// from its genesis is longer still): the source bounds its fetching
/// instead ([`MAX_CATCH_UP_TIME`]). Returns every version reached,
/// oldest first: the last is the one at the last position (empty only for
/// an empty range). A walk that stops returns why, and the caller adopts
/// nothing: a node changes its held version only to the newest, so a
/// stopped walk changes nothing.
pub async fn follow_versions<S>(
    held: &SignedTrustContext,
    positions: RangeInclusive<u64>,
    source: &mut S,
) -> Result<Vec<ContextStep>, CatchUpStop>
where
    S: VersionSource + ?Sized,
{
    let (first, last) = (*positions.start(), *positions.end());
    if first > last {
        return Ok(Vec::new());
    }
    let gap = last - first + 1;
    let by_genesis = matches!(self_certifying_digest(held.namespace()), Ok(Some(_)));
    if gap > MAX_CATCH_UP_VERSIONS && !by_genesis {
        return Err(CatchUpStop::TooFar {
            gap,
            max: MAX_CATCH_UP_VERSIONS,
        });
    }
    let mut steps: Vec<ContextStep> = Vec::new();
    // Positions passed over since the last version reached: first, last, why.
    let mut passed: Option<(u64, u64, String)> = None;
    for position in positions {
        let from: &SignedTrustContext = steps.last().map_or(held, |s| s.context.as_ref());
        let refusal = match source.fetch(position, from).await {
            Ok(data) => match open_context_update(from, &data).await {
                Ok((context, signer)) => {
                    steps.push(ContextStep {
                        context: Arc::new(context),
                        data,
                        signer,
                    });
                    passed = None;
                    continue;
                }
                Err(UpdateRefusal::NotNewer { .. }) if position < last => continue,
                Err(refusal) => refusal,
            },
            Err(Unfetched::Dropped(reason)) => UpdateRefusal::DroppedByForwarder(reason),
            Err(Unfetched::InProgress(e)) => return Err(e.into()),
            Err(Unfetched::Missing(reason)) if position < last => {
                passed = Some(match passed {
                    Some((first, _, _)) => (first, position, reason),
                    None => (position, position, reason),
                });
                continue;
            }
            Err(Unfetched::Missing(reason)) => {
                return Err(CatchUpStop::Unreachable {
                    version: position,
                    reason,
                });
            }
        };
        return Err(match passed {
            Some((first, last, reason)) => CatchUpStop::Missing {
                first,
                last,
                reason,
                version: position,
                refusal: Box::new(refusal),
            },
            None => CatchUpStop::Refused {
                version: position,
                refusal: Box::new(refusal),
            },
        });
    }
    Ok(steps)
}

/// Check the namespace `namespace` for a newer version of the context held
/// in `keyring`, and adopt it if it passes [`open_context_update`]:
///
/// 1. Metadata Interest `/<ns>/32=trust-context/32=metadata` (MustBeFresh)
///    through `exchange` → the newest version's name. Not newer than held:
///    nothing else is fetched.
/// 2. Fetch that version. When the Interests go through a validating
///    forwarder, pass its `forwarder` validator: it is told to expect an
///    update signed by an anchor of the held version
///    ([`Validator::expect_context_update`]), so it admits it even if it does
///    not hold the context itself, and a refused one is reported with why.
/// 3. Continuity and version ([`open_context_update`]). When it is not
///    signed by an anchor of the held version (or the forwarder dropped it)
///    and there are versions in between, follow them by exact name, oldest
///    first, each under the continuity rule from the one before
///    ([`follow_versions`], the forwarder expecting each in turn).
/// 4. Adopt the newest with [`Keyring::adopt_update_from`]: only if the
///    keyring still holds the version it was checked against (nothing
///    changed the namespace during the fetches, which hold no lock) and it
///    is strictly newer. The versions walked through are returned for the
///    caller to keep and serve; they are not adopted one by one.
///
/// A refused or failed refresh — the newest not reached — leaves the held
/// version in force.
pub async fn refresh_context<E>(
    keyring: &Keyring,
    forwarder: Option<&Validator>,
    exchange: &mut E,
    namespace: &Name,
) -> Result<ContextRefresh, RefreshError>
where
    E: CaExchange + Send + ?Sized,
{
    let held = keyring
        .contexts()
        .into_iter()
        .find(|c| c.namespace() == namespace)
        .ok_or_else(|| RefreshError::NotHeld(namespace.to_string()))?;
    let fetch_failed = |source| RefreshError::Fetch {
        namespace: namespace.to_string(),
        held: held.version(),
        source,
    };
    let refused = |refusal| RefreshError::Refused {
        namespace: namespace.to_string(),
        held: held.version(),
        refusal,
    };

    let pointer =
        fetch_context_pointer(exchange, namespace)
            .await
            .map_err(|source| match source {
                FetchContextError::Transport { .. } => RefreshError::NoAnswer {
                    namespace: namespace.to_string(),
                    held: held.version(),
                    source,
                },
                source => fetch_failed(source),
            })?;
    // `fetch_context_pointer` confines the pointer to `<ns>/32=trust-context/v=<N>`.
    let offered = pointer
        .components()
        .last()
        .and_then(NameComponent::as_version)
        .unwrap_or_default();
    if offered == held.version() {
        return Ok(ContextRefresh::Current { version: offered });
    }
    if offered < held.version() {
        return Ok(ContextRefresh::UpstreamOlder {
            held: held.version(),
            offered,
        });
    }

    let mut versions = ByName {
        exchange,
        forwarder,
        namespace,
        newest: None,
        deadline: web_time::Instant::now() + MAX_CATCH_UP_TIME,
    };
    let (newest, walked) = reach_newest(&mut versions, &held, offered, &pointer)
        .await
        .map_err(|unreached| match unreached {
            Unreached::Refused(refusal) => refused(refusal),
            Unreached::Fetch(source) => fetch_failed(source),
            Unreached::InProgress(e) => e.into(),
        })?;

    let ContextStep {
        context,
        data,
        signer,
    } = newest;
    keyring
        .adopt_update_from(&held, Arc::clone(&context))
        .map_err(|now_held| match now_held {
            Some(now) => RefreshError::ChangedMeanwhile {
                namespace: namespace.to_string(),
                held: held.version(),
                now,
            },
            None => RefreshError::NotHeld(namespace.to_string()),
        })?;
    let revoked = context
        .revocations()
        .iter()
        .filter(|r| !held.revocations().contains(r))
        .cloned()
        .collect();
    Ok(ContextRefresh::Updated(ContextUpdate {
        previous: held.version(),
        context,
        data,
        signer,
        revoked,
        walked,
    }))
}

/// Why [`reach_newest`] did not reach the newest version.
enum Unreached {
    Refused(UpdateRefusal),
    Fetch(FetchContextError),
    InProgress(ExpectContextError),
}

/// From `from`, the newest version `offered`, named `pointer`: fetched as
/// an update of `from` and taken when signed by an anchor of it
/// ([`open_context_update`]); else, when versions lie in between, reached
/// by walking them ([`follow_versions`]). Adopts nothing. The newest, and
/// the versions walked to it, oldest first.
async fn reach_newest<E>(
    versions: &mut ByName<'_, E>,
    from: &SignedTrustContext,
    offered: u64,
    pointer: &Name,
) -> Result<(ContextStep, Vec<ContextStep>), Unreached>
where
    E: CaExchange + Send + ?Sized,
{
    let direct = match fetch_update(&mut *versions.exchange, versions.forwarder, from, pointer)
        .await
    {
        Ok(data) => match open_context_update(from, &data).await {
            Ok((context, signer)) => Ok(ContextStep {
                context: Arc::new(context),
                data,
                signer,
            }),
            Err(refusal) => {
                versions.newest = Some((offered, data));
                Err(refusal)
            }
        },
        Err(UpdateFetchError::Dropped(reason)) => Err(UpdateRefusal::DroppedByForwarder(reason)),
        Err(UpdateFetchError::InProgress(e)) => return Err(Unreached::InProgress(e)),
        Err(UpdateFetchError::Fetch(source)) => return Err(Unreached::Fetch(source)),
    };
    match direct {
        Ok(newest) => Ok((newest, Vec::new())),
        // Not signed by an anchor of `from`: a version in between may have
        // installed the key that signed it (a recovery).
        Err(UpdateRefusal::NotSignedByHeldAnchor { .. } | UpdateRefusal::DroppedByForwarder(_))
            if offered > from.version() + 1 =>
        {
            let mut walked = follow_versions(from, from.version() + 1..=offered, versions)
                .await
                .map_err(|stop| {
                    Unreached::Refused(UpdateRefusal::CatchUp {
                        held: from.version(),
                        offered,
                        stop,
                    })
                })?;
            let newest = walked
                .pop()
                .expect("a walk that succeeds ends at its last position");
            Ok((newest, walked))
        }
        Err(refusal) => Err(Unreached::Refused(refusal)),
    }
}

/// The version a context Data's name carries (`…/v=<N>`), if any.
pub(crate) fn version_of(data: &Data) -> Option<u64> {
    data.name.components().last()?.as_version()
}

/// Adopt the self-certifying namespace `namespace`
/// (`/user/<0xA1: SHA-256 of an Ed25519 key>`) by its name alone — the
/// name is the expected fingerprint of its genesis root, so nothing else is
/// needed (`docs/specs/trust-context.md` §4.5):
///
/// 1. Version 1, `<ns>/32=trust-context/v=1`, and the newest version's
///    name (RDR metadata) are fetched through `exchange`; a validating
///    `forwarder` is told to expect a context of `namespace` signed by the
///    key the name hashes ([`Validator::expect_context`]).
/// 2. Version 1 must be its genesis ([`Genesis::open_received`]): signed
///    with Ed25519 by an anchor of its own whose raw public key's SHA-256 is
///    the name's last component. A forged genesis is refused here.
/// 3. The newest, not older than `min_version`, is reached from the
///    genesis by the continuity rule — directly, or by walking the versions
///    in between ([`follow_versions`]) — so a recovery, or a root moved to
///    another key type, keeps the name.
/// 4. It is adopted with the genesis ([`Keyring::adopt_genesis`]).
///
/// A namespace held already moves on only by continuity, as from any link.
/// The adoption returns the genesis and the versions walked
/// ([`LinkAdoption::earlier`]): keep them with the newest
/// ([`crate::persist_adoption`]), since a restart takes the namespace again
/// only from its genesis.
pub async fn adopt_by_name<E>(
    keyring: &Keyring,
    forwarder: Option<&Validator>,
    exchange: &mut E,
    namespace: &Name,
    min_version: Option<u64>,
) -> Result<LinkAdoption, AdoptError>
where
    E: CaExchange + Send + ?Sized,
{
    let digest =
        self_certifying_digest(namespace)?.ok_or_else(|| GenesisError::NotSelfCertifying {
            namespace: namespace.to_string(),
        })?;
    if keyring.held(namespace).is_some() {
        let link = crate::AnchorLink {
            namespace: namespace.clone(),
            expected_fingerprint: digest,
            min_version,
            context_data: None,
        };
        return crate::onboarding::adopt_fetched(keyring, forwarder, exchange, &link).await;
    }

    let expectation = forwarder
        .map(|v| v.expect_context(namespace.clone(), digest, CONTEXT_EXPECTATION_TTL))
        .transpose()?;
    let fetched = async {
        let genesis =
            fetch_versioned_context(&mut *exchange, &rdr_prefix(namespace).append_version(1))
                .await?;
        let pointer = fetch_context_pointer(&mut *exchange, namespace).await?;
        Ok::<_, FetchContextError>((genesis, pointer))
    }
    .await;
    let outcome = expectation.map(|e| e.finish()).unwrap_or_default();
    let (genesis, pointer) = fetched.map_err(|source| match outcome.refused {
        Some(reason) => AdoptError::WrongContext {
            namespace: namespace.to_string(),
            reason,
        },
        None => AdoptError::Fetch {
            namespace: namespace.to_string(),
            source,
        },
    })?;
    let genesis = Genesis::open_received(&genesis).await?;
    // `fetch_context_pointer` confines the pointer to `<ns>/32=trust-context/v=<N>`.
    let offered = pointer
        .components()
        .last()
        .and_then(NameComponent::as_version)
        .unwrap_or_default();
    if let Some(required) = min_version.filter(|&required| offered < required) {
        return Err(AdoptError::Downgrade { offered, required });
    }
    let first = ContextStep {
        context: Arc::clone(genesis.context()),
        data: Data::decode(genesis.data().raw().clone())
            .map_err(|e| AdoptError::BadData(e.to_string()))?,
        signer: genesis.root().clone(),
    };
    let (newest, earlier) = if offered <= 1 {
        (first, Vec::new())
    } else {
        let mut versions = ByName {
            exchange,
            forwarder,
            namespace,
            newest: None,
            deadline: web_time::Instant::now() + MAX_CATCH_UP_TIME,
        };
        let (newest, walked) = reach_newest(&mut versions, genesis.context(), offered, &pointer)
            .await
            .map_err(|unreached| match unreached {
                Unreached::Refused(refusal) => AdoptError::NotReached {
                    namespace: namespace.to_string(),
                    version: offered,
                    refusal: Box::new(refusal),
                },
                Unreached::Fetch(source) => AdoptError::Fetch {
                    namespace: namespace.to_string(),
                    source,
                },
                Unreached::InProgress(e) => e.into(),
            })?;
        (newest, std::iter::once(first).chain(walked).collect())
    };
    if let Err(refusal) = keyring.adopt_genesis(&genesis, Arc::clone(&newest.context)) {
        // Taken meanwhile by another adoption: this one moves it on only
        // by continuity from what is held.
        refused(refusal, newest.context.version())?;
        adopt_checked(keyring, Arc::clone(&newest.context), Some(&newest.data)).await?;
    }
    Ok(LinkAdoption {
        context: newest.context,
        data: newest.data,
        fetched: true,
        earlier,
    })
}
