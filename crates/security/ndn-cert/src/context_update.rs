//! Changing a trust context after it was adopted.
//!
//! - **Bump** ([`bump_context_revoking`], root device only): version `N+1` of
//!   the held context with keys added to its revocation list, signed by an
//!   anchor key of the held version — the namespace root, unlocked from its
//!   root store ([`crate::root_store`]). Nothing else changes: anchors,
//!   schema, CA endpoints and earlier revocations are carried over verbatim.
//! - **Schema update** ([`bump_context_schema`], root device only): version
//!   `N+1` carrying a new schema (for a namespace made by `ndn-fwd init`, the
//!   current generated one, [`crate::roles::namespace_schema`]) and the
//!   enrollment hint of the policy the namespace's CA enforces; everything
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
use ndn_packet::{Data, Name, NameComponent};
use ndn_security::{
    Certificate, EnrollmentHint, ExpectContextError, Keyring, LvsModel, OpenContextError,
    SchemaBlob, SchemaFormat, SchemaRule, SignedTrustContext, SignedTrustContextError, Signer,
    Validator,
};

use crate::client::CaExchange;
use crate::error::CertError;
use crate::onboarding::{
    CONTEXT_EXPECTATION_TTL, FetchContextError, fetch_context_pointer, fetch_versioned_context,
    rdr_prefix,
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

/// Why [`bump_context_revoking`] or [`bump_context_schema`] made no new
/// version.
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
    /// The revocation entries this version adds (none for a schema update).
    pub added: Vec<Name>,
}

/// The entries of `revoke` that a version after `ctx` would add to its
/// revocations — the ones `ctx` does not revoke already, each once; empty when
/// it revokes all of them. Refused when an entry is not a key name
/// ([`key_name_of`]) under the namespace, or is the key of one of its anchors.
/// Needs no key: a caller checks a revocation with it before unlocking the
/// root that signs it ([`bump_context_revoking`] applies the same checks).
pub fn revocations_to_add(ctx: &SignedTrustContext, revoke: &[Name]) -> Result<Vec<Name>, BumpError> {
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

/// Version `N+1` of the held context `held` (its signed Data, version `N`)
/// with the key names `revoke` added to its revocations, signed by `signer`
/// — the key of an anchor of `held` (the namespace root from its root store,
/// or any other anchor the held version lists), through its async signing
/// path, so hardware and custodian signers work. Every other field is carried
/// over verbatim. The entries are checked as [`revocations_to_add`] does;
/// ones already revoked are not repeated, and `Ok(None)` when all of them are
/// (no new version is needed, nothing is signed). Pure: nothing is adopted,
/// stored or published.
pub async fn bump_context_revoking(
    signer: &dyn Signer,
    held: &Data,
    revoke: &[Name],
) -> Result<Option<ContextBump>, BumpError> {
    let (ctx, _signed_by) = SignedTrustContext::open_signed(held).await?;
    ensure_anchor(signer, &ctx)?;

    let added = revocations_to_add(&ctx, revoke)?;
    if added.is_empty() {
        return Ok(None);
    }

    let version = next_version(&ctx)?;
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
}

impl SchemaChange {
    /// Whether the new version carries another enrollment hint.
    pub fn changes_hint(&self) -> bool {
        self.hint_before.as_ref() != Some(&self.hint)
    }

    /// Nothing to sign: the held version carries these rules, this hint and
    /// the authoritative flag already.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty()
            && self.removed.is_empty()
            && !self.changes_hint()
            && !self.becomes_authoritative
    }
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
                        let signer_pattern =
                            model.node_pattern(*signer).unwrap_or_else(|| signer_label.clone());
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

/// What a version after `ctx` carrying `schema` and `hint` would change:
/// the rules it adds and removes, and whether the hint or the authoritative
/// flag change ([`SchemaChange::is_empty`]: nothing to sign). Refused
/// ([`BumpError::Narrowing`], listing the rules devices would lose) when a
/// rule of `ctx` is missing from `schema`, unless `accept_narrowing`.
/// Needs no key: a caller checks a schema update with it before unlocking
/// the root that signs it ([`bump_context_schema`] applies the same checks).
pub fn schema_change(
    ctx: &SignedTrustContext,
    schema: &[SchemaBlob],
    hint: &EnrollmentHint,
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
    Ok(SchemaChange {
        added: grants_missing(&next, &held),
        removed,
        hint_before: ctx.enrollment_hint().cloned(),
        hint: hint.clone(),
        becomes_authoritative: !ctx.schema_is_authoritative(),
    })
}

/// Version `N+1` of the held context `held` (its signed Data, version `N`)
/// carrying the schema blobs `schema` (their OR is the schema: at most one
/// LVS binary, plus native rules — as
/// [`NamespaceSchema::blobs`](crate::roles::NamespaceSchema::blobs) gives)
/// and the enrollment hint `hint`, schema-authoritative, signed by `signer`
/// — the key of an anchor of `held`, as for [`bump_context_revoking`].
/// Anchors, CA endpoints, revocations and key roles are carried over
/// verbatim. Checked as [`schema_change`] checks (a narrowing refused
/// unless `accept_narrowing`); `Ok(None)` when `held` carries these rules
/// and this hint already (nothing is signed). Pure: nothing is adopted,
/// stored or published.
pub async fn bump_context_schema(
    signer: &dyn Signer,
    held: &Data,
    schema: &[SchemaBlob],
    hint: &EnrollmentHint,
    accept_narrowing: bool,
) -> Result<Option<SchemaBump>, BumpError> {
    let (ctx, _signed_by) = SignedTrustContext::open_signed(held).await?;
    ensure_anchor(signer, &ctx)?;
    let change = schema_change(&ctx, schema, hint, accept_narrowing)?;
    if change.is_empty() {
        return Ok(None);
    }

    let version = next_version(&ctx)?;
    // `held` verified above, so its Content is present and decodes.
    let content = held.content().map(|c| c.as_ref()).unwrap_or_default();
    let next = SignedTrustContext::decode_content(content, version)?
        .with_schema_blobs(schema.to_vec())
        .map_err(|e| BumpError::Schema(e.to_string()))?
        .with_enrollment_hint(hint.clone())
        .schema_authoritative();
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
/// fetch.
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
         namespace again from a current anchor link (`ndn-fwd adopt <link>`)"
    )]
    TooFar { gap: u64, max: u64 },
    #[error(
        "v{version} was refused: {refusal}. Whatever served it does not serve this namespace's \
         versions; if the namespace changed its root, adopt it again from a current anchor link \
         (`ndn-fwd adopt <link>`)"
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
    #[error("no trust context is held for {0}; adopt it first (`ndn-fwd adopt`)")]
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
        (
            None,
            FetchContextError::Transport {
                source: CertError::Refused { reason, .. },
                ..
            },
        ) => UpdateFetchError::Dropped(format!("refused it ({reason})")),
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
/// is refused before anything is fetched. Returns every version reached,
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
    if gap > MAX_CATCH_UP_VERSIONS {
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

    let pointer = fetch_context_pointer(exchange, namespace)
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
    let direct = match fetch_update(&mut *versions.exchange, forwarder, &held, &pointer).await {
        Ok(data) => match open_context_update(&held, &data).await {
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
        Err(UpdateFetchError::InProgress(e)) => return Err(e.into()),
        Err(UpdateFetchError::Fetch(source)) => return Err(fetch_failed(source)),
    };
    let (newest, walked) = match direct {
        Ok(newest) => (newest, Vec::new()),
        // Not signed by an anchor of the held version: a version in between
        // may have installed the key that signed it (a recovery).
        Err(UpdateRefusal::NotSignedByHeldAnchor { .. } | UpdateRefusal::DroppedByForwarder(_))
            if offered > held.version() + 1 =>
        {
            let mut walked = follow_versions(&held, held.version() + 1..=offered, &mut versions)
                .await
                .map_err(|stop| {
                    refused(UpdateRefusal::CatchUp {
                        held: held.version(),
                        offered,
                        stop,
                    })
                })?;
            let newest = walked
                .pop()
                .expect("a walk that succeeds ends at its last position");
            (newest, walked)
        }
        Err(refusal) => return Err(refused(refusal)),
    };

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
