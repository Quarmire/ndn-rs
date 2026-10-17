//! Changing a trust context after it was adopted.
//!
//! - **Bump** ([`bump_context_revoking`], root device only): version `N+1` of
//!   the held context with keys added to its revocation list, signed by an
//!   anchor key of the held version — the namespace root, unlocked from its
//!   root store ([`crate::root_store`]). Nothing else changes: anchors,
//!   schema, CA endpoints and earlier revocations are carried over verbatim.
//! - **Refresh** ([`refresh_context`], every node): ask the namespace for its
//!   newest version by name (RDR metadata, the publication of
//!   `docs/wiki/src/reference/trust-context-publication.md`) and, if it is
//!   newer than the held one, fetch it and adopt it only under the
//!   **continuity rule** ([`open_context_update`]): signed by a key that is an
//!   anchor of the version held now — never merely by an anchor the update
//!   lists itself — and strictly newer. A refused or failed refresh changes
//!   nothing: the held version stays in force.
//!
//! See `docs/wiki/src/reference/revocation.md` and
//! `docs/wiki/src/reference/context-updates.md`.

use std::sync::Arc;

use bytes::Bytes;
use ndn_packet::{Data, Name, NameComponent};
use ndn_security::{
    Certificate, ExpectContextError, Keyring, OpenContextError, SignedTrustContext,
    SignedTrustContextError, Signer, Validator,
};

use crate::client::CaExchange;
use crate::onboarding::{
    CONTEXT_EXPECTATION_TTL, FetchContextError, fetch_context_pointer, fetch_versioned_context,
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

/// Why [`bump_context_revoking`] made no new version.
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
    #[error("signing the new version: {0}")]
    Sign(#[from] SignedTrustContextError),
}

/// A new version of a context, signed and ready to adopt, store and publish.
#[derive(Debug)]
pub struct ContextBump {
    pub context: SignedTrustContext,
    /// Its signed Data at `/<ns>/32=trust-context/v=<N+1>`.
    pub data: Data,
    /// The revocation entries this version adds.
    pub added: Vec<Name>,
}

/// Version `N+1` of the held context `held` (its signed Data, version `N`)
/// with the key names `revoke` added to its revocations, signed by `signer`
/// — the key of an anchor of `held` (the namespace root from its root store,
/// or any other anchor the held version lists), through its async signing
/// path, so hardware and custodian signers work. Every other field is carried
/// over verbatim. Each entry must be a key name ([`key_name_of`]) under the
/// namespace that does not cover one of its anchors. Entries already revoked
/// are not repeated; `Ok(None)` when all of them are (no new version is
/// needed, nothing is signed). Pure: nothing is adopted, stored or published.
pub async fn bump_context_revoking(
    signer: &dyn Signer,
    held: &Data,
    revoke: &[Name],
) -> Result<Option<ContextBump>, BumpError> {
    let (ctx, _signed_by) = SignedTrustContext::open_signed(held).await?;
    let namespace = ctx.namespace().clone();

    let is_anchor = signer.public_key().is_some_and(|pk| {
        ctx.anchors()
            .iter()
            .any(|a| crate::root_store::same_public_key(&a.value().public_key, &pk))
    });
    if !is_anchor {
        return Err(BumpError::NotAnAnchor {
            key: signer.key_name().to_string(),
            namespace: namespace.to_string(),
            version: ctx.version(),
        });
    }

    let mut added = Vec::new();
    for name in revoke {
        if !name.has_prefix(&namespace) || key_name_of(name).as_ref() != Some(name) {
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
    if added.is_empty() {
        return Ok(None);
    }

    let version = ctx
        .version()
        .checked_add(1)
        .ok_or(BumpError::VersionExhausted(ctx.version()))?;
    // `held` verified above, so its Content is present and decodes.
    let content = held.content().map(|c| c.as_ref()).unwrap_or_default();
    let mut next = SignedTrustContext::decode_content(content, version)?;
    for name in &added {
        next = next.with_revocation(name.clone());
    }
    let data = next.sign_into_data_async(signer).await?;
    Ok(Some(ContextBump {
        context: next,
        data,
        added,
    }))
}

// ── Refresh (every node) ───────────────────────────────────────────────────

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
}

/// Why [`refresh_context`] could not check for, or adopt, an update. The held
/// version stays in force in every case.
#[derive(Debug, thiserror::Error)]
pub enum RefreshError {
    #[error("no trust context is held for {0}; adopt it first (`ndn-fwd adopt`)")]
    NotHeld(String),
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
}

/// What [`refresh_context`] found.
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
/// it are the caller's.
#[derive(Debug)]
pub struct ContextUpdate {
    /// The version held before.
    pub previous: u64,
    pub context: Arc<SignedTrustContext>,
    /// The signed Data exactly as received (what to persist and publish).
    pub data: Data,
    /// The held anchor that signed it.
    pub signer: Certificate,
    /// Revocation entries this version adds.
    pub revoked: Vec<Name>,
}

/// Open `data` as an update of the held context `held`: a self-consistent
/// signed context ([`SignedTrustContext::open_signed`]) of the same namespace,
/// strictly newer, and signed by a key that is an anchor of `held` — the
/// continuity rule: an update is authorized by the version it replaces. A
/// new version may list other anchors (a root rotation is signed by the old
/// root), but those are trusted only once it is adopted.
pub async fn open_context_update(
    held: &SignedTrustContext,
    data: &Data,
) -> Result<(SignedTrustContext, Certificate), UpdateRefusal> {
    let (ctx, signer) = SignedTrustContext::open_signed(data).await?;
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
/// 3. Continuity and version ([`open_context_update`]), then adopt with
///    [`Keyring::adopt_update`] (strictly newer, atomic).
///
/// A refused or failed refresh leaves the held version in force.
pub async fn refresh_context<E>(
    keyring: &Keyring,
    forwarder: Option<&Validator>,
    exchange: &mut E,
    namespace: &Name,
) -> Result<ContextRefresh, RefreshError>
where
    E: CaExchange + ?Sized,
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

    let pointer = fetch_context_pointer(exchange, namespace)
        .await
        .map_err(fetch_failed)?;
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

    let expectation = forwarder
        .map(|v| v.expect_context_update(&held, CONTEXT_EXPECTATION_TTL))
        .transpose()?;
    let fetched = fetch_versioned_context(exchange, &pointer).await;
    let outcome = expectation.map(|e| e.finish()).unwrap_or_default();
    let data = fetched.map_err(|source| match outcome.refused {
        // Something answered, and this node's forwarder dropped it: say why.
        Some(reason) => refused(UpdateRefusal::DroppedByForwarder(reason)),
        None => fetch_failed(source),
    })?;

    let (ctx, signer) = open_context_update(&held, &data).await.map_err(refused)?;
    let context = Arc::new(ctx);
    keyring
        .adopt_update(Arc::clone(&context))
        .map_err(|now_held| match now_held {
            Some(h) => refused(UpdateRefusal::NotNewer {
                offered: context.version(),
                held: h,
            }),
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
    }))
}
