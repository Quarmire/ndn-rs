//! The trust schema of the held contexts, as data, and bringing a
//! namespace's schema up to date on its root device.
//!
//! - [`load`] reads every context the PIB holds, verified on load exactly
//!   as a running device loads them; [`Adopted::select`] picks one,
//!   [`view`] shows it (an LVS binary decoded back to LVS source, native
//!   rules verbatim), [`Adopted::explain`] says whether a key may sign a
//!   name and which rule decides.
//! - [`root_of`] / [`plan_update`] / [`update`]: version `N+1` carrying the
//!   current generated schema ([`ndn_cert::namespace_schema`]), the
//!   enrollment hint of the policy the namespace's CA enforces, and the
//!   stated link policy and relays ([`ndn_cert::bump_context_schema`]).
//!   **An explicit operation**, not something every root-signed version
//!   does: a revocation or a recovery kit carries the schema over verbatim.
//!   It never narrows silently: a rule of the held schema missing from the
//!   new one is refused (`schema-narrowing`) unless narrowing is accepted.
//! - [`parse_data_requires_cut`] / [`plan_data_requires_cut`] /
//!   [`set_data_requires_cut`]: version `N+1` listing exactly the device
//!   roles given in DataRequiresCut
//!   ([`ndn_cert::bump_context_data_requires_cut`]): Data a key of a listed
//!   role signs is accepted only while a certificate of the key is valid by
//!   the reader's clock, or once the key is revoked with a cut.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use ndn_cert::report::code;
use ndn_cert::{
    ApprovalPolicy, PolicyInput, Role, RootDevice, SchemaChange, SchemaPlanError, SchemaUpdatePlan,
    bump_context_data_requires_cut, bump_context_schema, load_persisted_contexts,
};
use ndn_packet::Name;
use ndn_security::{
    AdvertisedRelay, ContextExplanation, Keyring, LinkPolicy, LvsModel, SchemaFormat,
    SignedTrustContext,
};

use super::device::{check_device, hand_over, settle};
use super::{RootError, RunningDevice, SecretSource, VersionChange, open_pib, unlock_root};
use crate::admin::HandedOver;

/// The contexts a PIB holds, verified.
pub struct Adopted {
    pib_dir: PathBuf,
    keyring: Keyring,
    /// Stored contexts that failed to verify, skipped as a running device
    /// skips them: where, and why.
    pub skipped: Vec<(PathBuf, String)>,
}

/// Every context stored in the PIB at `pib_dir`, verified.
pub fn load(pib_dir: &Path) -> Result<Adopted, RootError> {
    let keyring = Keyring::new();
    let loaded = load_persisted_contexts(pib_dir, &keyring).map_err(|e| {
        RootError::new(
            code::ROOT_LOCAL_FAILURE,
            "the held contexts could not be read",
        )
        .with("error", &e)
        .with("read", pib_dir.display())
        .caused_by(e)
    })?;
    let skipped = loaded
        .into_iter()
        .filter_map(|(path, result)| result.err().map(|e| (path, e.to_string())))
        .collect();
    Ok(Adopted {
        pib_dir: pib_dir.to_path_buf(),
        keyring,
        skipped,
    })
}

impl Adopted {
    fn none_held(&self) -> Result<(), RootError> {
        if self.keyring.is_empty() {
            return Err(RootError::new(
                code::NO_NAMESPACE_HELD,
                "no trust context is held: make or adopt a namespace first",
            )
            .with("pib", self.pib_dir.display()));
        }
        Ok(())
    }

    /// The context of `namespace`, else the only one held.
    pub fn select(&self, namespace: Option<&Name>) -> Result<Arc<SignedTrustContext>, RootError> {
        self.none_held()?;
        let contexts = self.keyring.contexts();
        if let Some(ns) = namespace {
            return contexts
                .into_iter()
                .find(|c| c.namespace() == ns)
                .ok_or_else(|| {
                    RootError::new(
                        code::NAMESPACE_NOT_HELD,
                        "no trust context of the namespace is held",
                    )
                    .with("namespace", ns)
                });
        }
        match contexts.as_slice() {
            [one] => Ok(Arc::clone(one)),
            many => Err(RootError::new(
                code::SEVERAL_NAMESPACES,
                "several trust contexts are held: name the namespace",
            )
            .with("count", many.len())
            .with(
                "namespaces",
                many.iter()
                    .map(|c| c.namespace().to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            )),
        }
    }

    /// Whether `key` may sign `data` under the context of `namespace`, else
    /// the one governing `data`, and which rule decides.
    pub fn explain(
        &self,
        data: &Name,
        key: &Name,
        namespace: Option<&Name>,
    ) -> Result<Explained, RootError> {
        let context = if namespace.is_some() {
            self.select(namespace)?
        } else {
            self.none_held()?;
            let Some(ctx) = self.keyring.held_for(data) else {
                return Err(RootError::new(
                    code::NO_CONTEXT_GOVERNS,
                    "no held trust context governs the name",
                )
                .with("name", data));
            };
            ctx
        };
        Ok(Explained {
            explanation: context.explain(data, key),
            context,
        })
    }
}

/// [`Adopted::explain`]'s answer.
pub struct Explained {
    /// The context that decides.
    pub context: Arc<SignedTrustContext>,
    /// Whether the hierarchy floor passes, the rule that admits the pair,
    /// and the verdict ([`ContextExplanation::allowed`]).
    pub explanation: ContextExplanation,
}

/// How a context's schema is evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evaluation {
    /// Schema only, on every certificate hop.
    Authoritative,
    /// Schema and the hierarchy floor (the signer's identity must prefix
    /// the name), first signature.
    WithHierarchyFloor,
    /// Schema only, first signature.
    FirstSignature,
}

/// One schema blob, readable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaBlobView {
    /// An LVS binary (`bytes` long), decoded to LVS source.
    Lvs { bytes: usize, source: String },
    /// Native rules (`data => key`), one per entry, OR'd with the others.
    Native { rules: Vec<String> },
    /// A format this node does not understand: it authorizes nothing here
    /// and is carried into the next version unchanged.
    Unknown { format: u64, bytes: usize },
}

/// A held context and its schema, readable.
pub struct SchemaView {
    pub namespace: Name,
    pub version: u64,
    pub anchors: Vec<Name>,
    pub ca_endpoints: Vec<Name>,
    pub link_policy: LinkPolicy,
    pub relays: Vec<AdvertisedRelay>,
    pub evaluation: Evaluation,
    /// Each blob in order; one that cannot be read is `schema-unreadable`
    /// (param `format`: `lvs` or `native`).
    pub blobs: Vec<Result<SchemaBlobView, RootError>>,
}

/// `ctx` and its schema, readable.
pub fn view(ctx: &SignedTrustContext) -> SchemaView {
    let unreadable = |i: usize, format: &str| {
        RootError::new(code::SCHEMA_UNREADABLE, "a schema blob cannot be read")
            .with("blob", i)
            .with("format", format)
    };
    let blobs = ctx
        .published_schemas()
        .iter()
        .enumerate()
        .map(|(i, blob)| match blob.format {
            SchemaFormat::Lvs => LvsModel::decode(&blob.body)
                .map(|model| SchemaBlobView::Lvs {
                    bytes: blob.body.len(),
                    source: model.to_text(),
                })
                .map_err(|e| unreadable(i, "lvs").with("error", e)),
            SchemaFormat::NativeText => std::str::from_utf8(&blob.body)
                .map(|text| SchemaBlobView::Native {
                    rules: text
                        .lines()
                        .filter(|l| !l.trim().is_empty())
                        .map(|l| l.trim().to_string())
                        .collect(),
                })
                .map_err(|e| unreadable(i, "native").with("error", e).caused_by(e)),
            SchemaFormat::Unknown(format) => Ok(SchemaBlobView::Unknown {
                format: format.into(),
                bytes: blob.body.len(),
            }),
        })
        .collect();
    SchemaView {
        namespace: ctx.namespace().clone(),
        version: ctx.version(),
        anchors: ctx.anchors().iter().map(|r| Name::clone(r.key())).collect(),
        ca_endpoints: ctx.ca_endpoints().to_vec(),
        link_policy: ctx.link_policy().clone(),
        relays: ctx.relays().to_vec(),
        evaluation: if ctx.schema_is_authoritative() {
            Evaluation::Authoritative
        } else if ctx.enforces_hierarchy() {
            Evaluation::WithHierarchyFloor
        } else {
            Evaluation::FirstSignature
        },
        blobs,
    }
}

/// The root device of `namespace` in the PIB at `pib_dir` (else of the only
/// namespace whose root it holds), for a schema update: `not-root-device`,
/// `other-namespace-root` (it holds the roots of other namespaces only),
/// `several-namespaces` (none named, several held), `no-longer-root`.
pub fn root_of(pib_dir: &Path, namespace: Option<&Name>) -> Result<RootDevice, RootError> {
    let pib = open_pib(pib_dir)?;
    Ok(ndn_cert::root_device(
        &pib,
        namespace,
        "a namespace's schema is updated",
    )?)
}

/// What a schema update signs, decided before the root is unlocked.
pub struct SchemaUpdate {
    pub root: RootDevice,
    /// The schema, enrollment policy and hint, link policy and relays of
    /// the next version, and what they change.
    pub plan: SchemaUpdatePlan,
    pub accept_narrowing: bool,
}

/// Every check of a schema update that needs no key: what it changes, given
/// the `stated` policy of the namespace's CA (the enrollment hint is the
/// held version's own when it advertises a policy — refused when `stated`
/// names another — else the one the CA enforces); refused when it narrows
/// without `accept_narrowing` ([`ndn_cert::plan_schema_update`]). An empty
/// `plan.change`: nothing to sign.
pub fn plan_update(
    root: RootDevice,
    stated: &PolicyInput,
    accept_narrowing: bool,
) -> Result<SchemaUpdate, RootError> {
    let plan = ndn_cert::plan_schema_update(&root.context, stated, accept_narrowing)?;
    Ok(SchemaUpdate {
        root,
        plan,
        accept_narrowing,
    })
}

/// A schema update signed and handed over.
pub struct SchemaUpdated {
    pub namespace: Name,
    pub held_version: u64,
    pub version: u64,
    pub root_key: Name,
    /// The rules added and removed, the hint, link policy and relays before
    /// and after.
    pub change: SchemaChange,
    /// The enrollment policy the new version states.
    pub policy: ApprovalPolicy,
    pub handed_over: HandedOver,
}

/// Sign and hand over the schema update `update` (on the PIB at
/// `pib_dir`). Refusals: `nothing-to-sign`, the running device's (before
/// the root is unlocked), the secret's and `root-not-unlocked`, the
/// signature's (`schema-narrowing`, `signer-not-an-anchor`, …),
/// `version-not-taken`, `hand-over-unknown` (param `namespace`).
pub async fn update(
    update: SchemaUpdate,
    pib_dir: &Path,
    device: &dyn RunningDevice,
    secrets: &dyn SecretSource,
) -> Result<SchemaUpdated, RootError> {
    let SchemaUpdate {
        root,
        plan,
        accept_narrowing,
    } = update;
    let held_version = root.context.version();
    let namespace = root.context.namespace().clone();
    let nothing = || {
        RootError::new(
            code::NOTHING_TO_SIGN,
            "the held trust context carries this schema, enrollment hint, link policy and relays \
             already; nothing was signed",
        )
        .with("version", held_version)
    };
    if plan.change.is_empty() {
        return Err(nothing());
    }
    check_device(device, pib_dir).await?;
    let signer = unlock_root(
        &root.store,
        secrets,
        VersionChange::UpdateSchema {
            namespace: namespace.clone(),
        },
    )
    .await?;
    let signed = bump_context_schema(
        signer.as_ref(),
        &root.data,
        &plan.schema,
        &plan.hint,
        plan.link.as_ref(),
        plan.relays.as_deref(),
        accept_narrowing,
    )
    .await;
    // The root signed its one version: drop it now.
    drop(signer);
    // Refused as the plan refuses: nothing was signed.
    let signed = signed
        .map_err(|e| RootError::from(SchemaPlanError::Change(e)))?
        .ok_or_else(nothing)?;
    let version = signed.bump.context.version();
    let handed_over = settle(
        hand_over(device, pib_dir, &signed.bump).await,
        version,
        held_version,
        &[("namespace", namespace.to_string())],
    )?;
    Ok(SchemaUpdated {
        namespace,
        held_version,
        version,
        root_key: root.store.key_name().clone(),
        change: signed.change,
        policy: plan.policy,
        handed_over,
    })
}

/// The device roles `text` names for DataRequiresCut: comma-separated role
/// names (`guest`, `guest,member`), or `none` for no role
/// (`root-bad-request`, params `role` and `error`, for a name that is no
/// device role).
pub fn parse_data_requires_cut(text: &str) -> Result<Vec<Role>, RootError> {
    let text = text.trim();
    if text == "none" {
        return Ok(Vec::new());
    }
    let mut roles: Vec<Role> = Vec::new();
    for word in text.split(',').map(str::trim) {
        let role: Role = word.parse().map_err(|e: ndn_cert::RoleError| {
            RootError::new(
                code::ROOT_BAD_REQUEST,
                "that is no device role: name roles among admin, member, node and guest, \
                 separated by commas, or `none`",
            )
            .with("role", word)
            .with("error", e)
        })?;
        if !roles.contains(&role) {
            roles.push(role);
        }
    }
    Ok(roles)
}

/// What setting the DataRequiresCut roles of a namespace signs, decided
/// before the root is unlocked ([`plan_data_requires_cut`]).
pub struct DataRequiresCutPlan {
    pub root: RootDevice,
    /// The roles the next version lists.
    pub roles: Vec<Role>,
    /// The roles the held version lists, sorted.
    pub before: Vec<String>,
    /// The roles the next version lists, sorted.
    pub after: Vec<String>,
}

impl DataRequiresCutPlan {
    /// Whether the next version would list the same roles: nothing to sign.
    pub fn is_unchanged(&self) -> bool {
        self.before == self.after
    }
}

/// Plan listing exactly `roles` in the DataRequiresCut of the namespace
/// whose root device is `root` ([`root_of`]). A key of a listed role signs
/// Data accepted only while a certificate of the key is valid by the
/// reader's clock, or once the key is revoked with a cut that accepts it;
/// a listed role's lapsed keys are ended by the root ([`super::end_keys`]).
pub fn plan_data_requires_cut(root: RootDevice, roles: &[Role]) -> DataRequiresCutPlan {
    let before = root.context.data_requires_cut().to_vec();
    let mut after: Vec<String> = roles.iter().map(|r| r.as_str().to_string()).collect();
    after.sort();
    after.dedup();
    DataRequiresCutPlan {
        root,
        roles: roles.to_vec(),
        before,
        after,
    }
}

/// DataRequiresCut set in a version signed and handed over.
pub struct DataRequiresCutSet {
    pub namespace: Name,
    pub held_version: u64,
    pub version: u64,
    pub root_key: Name,
    /// The roles the held version listed.
    pub before: Vec<String>,
    /// The roles the new version lists.
    pub after: Vec<String>,
    pub handed_over: HandedOver,
}

/// Sign and hand over the DataRequiresCut roles `plan` lists (on the PIB at
/// `pib_dir`) with [`ndn_cert::bump_context_data_requires_cut`]. Refusals:
/// `nothing-to-sign` (the held version lists those roles already), the
/// running device's (before the root is unlocked), the secret's and
/// `root-not-unlocked`, `signer-not-an-anchor`, `version-not-taken`,
/// `hand-over-unknown` (param `namespace`).
pub async fn set_data_requires_cut(
    plan: DataRequiresCutPlan,
    pib_dir: &Path,
    device: &dyn RunningDevice,
    secrets: &dyn SecretSource,
) -> Result<DataRequiresCutSet, RootError> {
    let DataRequiresCutPlan {
        root,
        roles,
        before,
        after,
    } = plan;
    let held_version = root.context.version();
    let namespace = root.context.namespace().clone();
    let nothing = || {
        RootError::new(
            code::NOTHING_TO_SIGN,
            "the held trust context lists these roles in DataRequiresCut already; nothing was \
             signed",
        )
        .with("version", held_version)
        .with("roles", after.join(","))
    };
    if before == after {
        return Err(nothing());
    }
    check_device(device, pib_dir).await?;
    let signer = unlock_root(
        &root.store,
        secrets,
        VersionChange::DataRequiresCut {
            namespace: namespace.clone(),
        },
    )
    .await?;
    let bump = bump_context_data_requires_cut(signer.as_ref(), &root.data, &roles).await;
    // The root signed its one version: drop it now.
    drop(signer);
    let bump = bump?.ok_or_else(nothing)?;
    let version = bump.context.version();
    let handed_over = settle(
        hand_over(device, pib_dir, &bump).await,
        version,
        held_version,
        &[("namespace", namespace.to_string())],
    )?;
    Ok(DataRequiresCutSet {
        namespace,
        held_version,
        version,
        root_key: root.store.key_name().clone(),
        before,
        after,
        handed_over,
    })
}
