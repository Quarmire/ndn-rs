//! Namespace creation on the root device: mint a namespace's root key, publish its
//! [`SignedTrustContext`] (signed by the root) + an `ndn-trust://anchor`
//! [`TrustEnvelope`], and the clockless validity policy that offline/embedded
//! nodes degrade to.
//!
//! The root device holds the namespace root and runs its issuing CA. Other
//! devices scan a QR (or overhear an advert), adopt the context (free), and —
//! only if they want to *produce* — enroll: by invite, or for the roles the
//! context's enrollment hint names, by an admin's approval
//! ([`crate::policy::ApprovalPolicy`]).
//! The context carries the generated namespace schema
//! ([`crate::roles::namespace_schema`]) and makes it authoritative, so names
//! carry roles: `/<ns>/<role>/<device>` (`docs/specs/personal-namespace.md`
//! §2, §4). [`init_namespace_in_pib`] is the persistent form `ndn-fwd init`
//! runs: the root key lands in the root store the operator chose
//! ([`crate::root_store`]); the CA identity, the primary device's admin
//! identity and the signed context land in the node's PIB (same document, §6).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use ndn_packet::{Data, Name};
use ndn_security::{
    Certificate, EnrollmentHint, FilePib, KeyRole, LinkPolicy, PibError, SecurityManager, SignedTrustContext,
    SignedTrustContextError, TrustError,
};
use ndn_trust_envelope::TrustEnvelope;

use crate::ca::serialize_cert;
use crate::context_store::{
    ContextStoreError, context_file_path, persist_context, remove_stored_context,
};
use crate::onboarding::anchor_fingerprint;
use crate::policy::ApprovalPolicy;
use crate::roles::{Role, RoleError, device_identity, namespace_schema, validate_namespace};
use crate::root_store::{NewRootStore, PendingRoot, RootStore, RootStoreError};

/// Directory (under the PIB root) holding the root device's certificate Data wires
/// (CA, root anchor, primary device) and the CA's persistent state.
pub const CA_DIR: &str = "ca";
/// The CA signing cert (issued by the namespace root), as raw signed Data TLV.
pub const CA_CERT_FILE: &str = "ca-cert.data";
/// The namespace root's self-signed anchor cert, as raw signed Data TLV.
pub const ANCHOR_CERT_FILE: &str = "anchor-cert.data";
/// The primary device's admin cert (issued by the CA), as raw signed Data
/// TLV. The PIB keeps only a summary of it, without the CA's signature.
pub const DEVICE_CERT_FILE: &str = "device-cert.data";
/// Lifetime of the CA signing cert minted by [`init_namespace_in_pib`] (10 years).
pub const CA_CERT_VALIDITY_MS: u64 = 10 * 365 * 24 * 3600 * 1000;
/// Lifetime of the primary device's cert minted by [`init_namespace_in_pib`]: a day
/// short of the CA's, so it ends inside the issuer's validity.
pub const DEVICE_CERT_VALIDITY_MS: u64 = CA_CERT_VALIDITY_MS - 24 * 3600 * 1000;

/// The namespace root key name: `<namespace>/KEY/root`.
pub fn root_key_name(namespace: &Name) -> Name {
    namespace.clone().append("KEY").append("root")
}

/// The namespace CA signing key name: `<namespace>/CA/KEY/ca` (identity `<ns>/CA`).
pub fn ca_key_name(namespace: &Name) -> Name {
    namespace.clone().append("CA").append("KEY").append("ca")
}

/// The primary device's signing key name: `<device identity>/KEY/device`.
pub fn device_key_name(device_identity: &Name) -> Name {
    device_identity.clone().append("KEY").append("device")
}

/// Result of initializing a namespace on its root device.
pub struct NamespaceInit {
    /// The namespace anchor's key name (`<namespace>/KEY/root`).
    pub anchor_key: Name,
    /// The self-signed namespace anchor certificate.
    pub anchor: Certificate,
    /// The published, versioned trust context (generated namespace
    /// schema, authoritative; the default enrollment policy:
    /// [`ApprovalPolicy::default`]).
    pub context: Arc<SignedTrustContext>,
    /// The context as signed NDN Data at [`SignedTrustContext::rdr_name`],
    /// signed by the root anchor — what is published and what adopters verify.
    pub context_data: Data,
    /// The out-of-band anchor envelope (QR / deep link):
    /// [`TrustEnvelope::Anchor`] carrying the namespace, the anchor
    /// fingerprint, and the signed context Data inline.
    pub envelope: TrustEnvelope,
}

impl NamespaceInit {
    /// The context `Content` to publish at
    /// [`SignedTrustContext::rdr_name`].
    pub fn published_content(&self) -> bytes::Bytes {
        self.context.encode_content()
    }
}

/// Initialize the namespace `namespace`: generate a signing key in `mgr`,
/// self-sign the namespace anchor, build a context carrying the generated
/// namespace schema ([`namespace_schema`], authoritative) with the default
/// enrollment policy ([`EnrollmentHint::namespace_default`]), sign it into Data with the
/// anchor, and mint an anchor envelope committing to the anchor fingerprint.
///
/// The default deployment keeps the *root* offline and runs a delegated
/// context-signer online; this in-process helper signs directly for the
/// self-contained case (tests, single-box root devices). The signing key never leaves
/// `mgr`, and is lost with it — use [`init_namespace_in_pib`] for a namespace that
/// must survive a restart.
pub fn init_namespace(
    mgr: &SecurityManager,
    namespace: &Name,
) -> Result<NamespaceInit, NamespaceInitError> {
    validate_namespace(namespace)?;
    let anchor_key = root_key_name(namespace);
    mgr.generate_ed25519(anchor_key)?;
    // In-memory Ed25519 signers never suspend: drive the future inline.
    futures::executor::block_on(build_namespace(
        mgr,
        namespace,
        None,
        &[],
        EnrollmentHint::namespace_default(),
        LinkPolicy::default(),
    ))
}

/// Build the namespace around the root key `root_key_name(namespace)` already held
/// by `mgr` (in memory or a hardware signer registered with it). The
/// `root_device_keys` (the CA and admin keys that will live beside the root)
/// get the [`KeyRole::ROOT_DEVICE`] role in the context.
async fn build_namespace(
    mgr: &SecurityManager,
    namespace: &Name,
    ca_endpoint: Option<Name>,
    root_device_keys: &[Name],
    hint: EnrollmentHint,
    link: LinkPolicy,
) -> Result<NamespaceInit, NamespaceInitError> {
    let anchor_key = root_key_name(namespace);
    let signer = mgr.get_signer_sync(&anchor_key)?;
    let pk = signer.public_key().unwrap_or_default();
    let anchor = mgr.issue_self_signed_async(&anchor_key, pk, u64::MAX).await?;

    let schema = namespace_schema(namespace)?;
    let mut context = SignedTrustContext::hierarchical(namespace.clone())
        .with_version(1)
        .with_enrollment_hint(hint)
        .with_link_policy(link)
        .with_schema_blobs(schema.blobs())?
        .schema_authoritative();
    if let Some(ca) = ca_endpoint {
        context = context.with_ca_endpoint(ca);
    }
    for key in root_device_keys {
        context = context.with_key_role(KeyRole::ROOT_DEVICE, key.clone());
    }
    context.add_anchor(anchor.clone());
    let context_data = context.sign_into_data_async(signer.as_ref()).await?;
    let context = Arc::new(context);

    let envelope = TrustEnvelope::Anchor {
        namespace: Some(namespace.to_string()),
        fingerprint: Some(anchor_fingerprint(&anchor)),
        version: Some(context.version()),
        context_data: Some(context_data.raw().clone()),
        context_content: None,
    };
    Ok(NamespaceInit {
        anchor_key,
        anchor,
        context,
        context_data,
        envelope,
    })
}

/// A namespace initialized into its root device's PIB by [`init_namespace_in_pib`].
pub struct PersistedNamespace {
    /// The root, context and envelope (as [`init_namespace`]).
    pub init: NamespaceInit,
    /// The CA signing key name (`<ns>/CA/KEY/ca`).
    pub ca_key: Name,
    /// The CA signing cert, issued by the namespace root.
    pub ca_cert: Certificate,
    /// The primary device's own identity (`<ns>/admin/<device>`), for the
    /// forwarder's `[security] identity`.
    pub device_identity: Name,
    /// The device's signing key (`<device identity>/KEY/device`), in the PIB.
    pub device_key: Name,
    /// The device's admin cert, issued by the CA (the schema's device-key
    /// rule: device keys are certified by `<ns>/CA`, the CA by the root).
    pub device_cert: Certificate,
    /// Where the signed context was stored (the node's adopted-context store).
    pub context_path: PathBuf,
    /// `<pib>/ca/ca-cert.data`.
    pub ca_cert_path: PathBuf,
    /// `<pib>/ca/anchor-cert.data`.
    pub anchor_cert_path: PathBuf,
    /// `<pib>/ca/device-cert.data`.
    pub device_cert_path: PathBuf,
    /// Where the root key lives now.
    pub root_store: RootStore,
}

/// Why [`init_namespace_in_pib`] failed.
#[derive(Debug, thiserror::Error)]
pub enum NamespaceInitError {
    #[error(
        "{namespace} is already initialized in {pib} ({what} exists); refusing to replace \
         its root — re-run with force to mint a new root (every adopter must then re-adopt)"
    )]
    AlreadyInitialized {
        namespace: String,
        pib: String,
        what: String,
    },
    #[error(transparent)]
    RootStore(#[from] RootStoreError),
    /// The namespace or the device name does not fit the role layout.
    #[error(transparent)]
    Role(#[from] RoleError),
    #[error(transparent)]
    Trust(#[from] TrustError),
    #[error("trust context: {0}")]
    Context(#[from] SignedTrustContextError),
    #[error(transparent)]
    Pib(#[from] PibError),
    #[error("I/O on {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error(transparent)]
    Store(#[from] ContextStoreError),
}

/// Persistent namespace init: the [`init_namespace`] flow with every secret and
/// artefact written so the root device survives restarts —
///
/// - root key `<ns>/KEY/root` in the root store `root` ([`crate::root_store`]:
///   OS keychain, passphrase-sealed file, YubiKey PIV, or plaintext `file`),
///   recorded in `<pib>/root/store.toml`; its self-signed anchor cert is a PIB
///   trust anchor;
/// - CA signing identity `<ns>/CA` (key `<ns>/CA/KEY/ca`) with a cert issued
///   by the root, plus both certs as signed Data in `<pib>/ca/`;
/// - the primary device's admin identity `<ns>/admin/<device>` (key
///   `<ns>/admin/<device>/KEY/device`) with a cert issued by the CA, so the
///   forwarder loads it with `[security] identity` instead of falling back to
///   an ephemeral key; its signed cert Data is `<pib>/ca/device-cert.data`;
/// - the root-signed context (generated schema, advertising the CA endpoint
///   `<ns>/CA`) in the node's adopted-context store, so the root device validates its
///   own namespace.
///
/// The root signs the anchor, the context and the CA cert through its async
/// signer, so a hardware root works. The CA and device keys stay in the
/// FilePib: the daemon uses them unattended.
///
/// `device` must pass [`crate::roles::validate_device_name`]. An existing
/// root, CA key, device key or stored context for `namespace` is never
/// silently replaced: without `force` this fails with
/// [`NamespaceInitError::AlreadyInitialized`]. A PIB holding the root of
/// another namespace is refused even with `force`.
///
/// The context advertises the default enrollment policy
/// ([`ApprovalPolicy::default`]) and states the default link policy
/// ([`LinkPolicy::default`]); [`init_namespace_in_pib_with`] takes others.
pub async fn init_namespace_in_pib(
    pib: &FilePib,
    namespace: &Name,
    device: &str,
    force: bool,
    root: &NewRootStore,
) -> Result<PersistedNamespace, NamespaceInitError> {
    init_namespace_in_pib_with(
        pib,
        namespace,
        device,
        force,
        root,
        &ApprovalPolicy::default(),
        &LinkPolicy::default(),
    )
    .await
}

/// [`init_namespace_in_pib`] whose context advertises `approval` — which
/// roles enroll only on an admin's approval, and whether with an invite too
/// — the policy the namespace's CA (`[ca]`) then enforces, and states
/// `link`: which devices may link and relay, and whether relays admit
/// enrollment links.
pub async fn init_namespace_in_pib_with(
    pib: &FilePib,
    namespace: &Name,
    device: &str,
    force: bool,
    root: &NewRootStore,
    approval: &ApprovalPolicy,
    link: &LinkPolicy,
) -> Result<PersistedNamespace, NamespaceInitError> {
    validate_namespace(namespace)?;
    let anchor_key = root_key_name(namespace);
    let ca_key = ca_key_name(namespace);
    let device_identity = device_identity(namespace, Role::Admin, device)?;
    let device_key = device_key_name(&device_identity);
    let context_path = context_file_path(pib.root(), namespace);
    let held_root = RootStore::open(pib)?;
    if let Some(held) = &held_root
        && held.namespace() != namespace
    {
        return Err(RootStoreError::OtherNamespace {
            pib: pib.root().display().to_string(),
            held: held.namespace().to_string(),
            requested: namespace.to_string(),
        }
        .into());
    }
    let existing = if let Some(held) = &held_root {
        Some(format!("root key {anchor_key} ({} root store)", held.kind()))
    } else if pib.has_private_key(&anchor_key) {
        Some(format!("root key {anchor_key}"))
    } else if pib.has_private_key(&ca_key) {
        Some(format!("CA key {ca_key}"))
    } else if pib.has_private_key(&device_key) {
        Some(format!("device key {device_key}"))
    } else if context_path.exists() {
        Some(format!("trust context {}", context_path.display()))
    } else {
        None
    };
    if let Some(what) = existing {
        if !force {
            return Err(NamespaceInitError::AlreadyInitialized {
                namespace: namespace.to_string(),
                pib: pib.root().display().to_string(),
                what,
            });
        }
        if let Some(held) = &held_root {
            held.destroy(pib)?;
        }
        pib.delete_key(&anchor_key)?;
        pib.delete_key(&ca_key)?;
        pib.delete_key(&device_key)?;
        pib.remove_trust_anchor(&anchor_key)?;
        // The versions of the namespace being replaced are not the new
        // root's: none of them may be served beside its v1.
        remove_stored_context(pib.root(), namespace)?;
    }

    // Root: generated in its store (in memory for a sealed one, on the token
    // for a YubiKey), held by an in-process manager for the signing steps
    // below, and recorded once the anchor is signed.
    let pending = PendingRoot::create(pib, &anchor_key, root).await?;
    let mgr = SecurityManager::new();
    mgr.register_signer(anchor_key.clone(), pending.signer());
    let init = build_namespace(
        &mgr,
        namespace,
        Some(namespace.clone().append("CA")),
        &[ca_key.clone(), device_key.clone()],
        approval.to_hint(),
        link.clone(),
    )
    .await?;
    let root_store = pending.commit(pib, namespace, &init.anchor)?;
    pib.add_trust_anchor(&anchor_key, &init.anchor)?;

    // The CA is certified by the root; the primary device by the CA, as the
    // schema's chain requires of every device. Certificates are cert-v2
    // named: the CA's `<ca key>/NA/<v>` (ndn-cxx's default issuer id), the
    // device's `<device key>/NDNCERT/<v>` like every certificate the CA issues.
    let ca_cert = certify_new_key(
        pib,
        &mgr,
        &ca_key,
        &anchor_key,
        CA_CERT_VALIDITY_MS,
        ndn_security::cert_name::DEFAULT_ISSUER,
    )
    .await?;
    mgr.register_signer(ca_key.clone(), pib.get_signer(&ca_key)?);
    let device_cert = certify_new_key(
        pib,
        &mgr,
        &device_key,
        &ca_key,
        DEVICE_CERT_VALIDITY_MS,
        ndn_security::cert_name::NDNCERT_ISSUER,
    )
    .await?;

    let ca_dir = pib.root().join(CA_DIR);
    let io = |path: &Path| {
        let path = path.to_path_buf();
        move |source| NamespaceInitError::Io { path, source }
    };
    // Owner-only like the rest of the PIB (`ndn_security::secure_fs`).
    ndn_security::secure_fs::create_private_dir_all(&ca_dir).map_err(io(&ca_dir))?;
    let ca_cert_path = ca_dir.join(CA_CERT_FILE);
    ndn_security::secure_fs::write_private(&ca_cert_path, serialize_cert(&ca_cert))
        .map_err(io(&ca_cert_path))?;
    let anchor_cert_path = ca_dir.join(ANCHOR_CERT_FILE);
    ndn_security::secure_fs::write_private(&anchor_cert_path, serialize_cert(&init.anchor))
        .map_err(io(&anchor_cert_path))?;
    let device_cert_path = ca_dir.join(DEVICE_CERT_FILE);
    ndn_security::secure_fs::write_private(&device_cert_path, serialize_cert(&device_cert))
        .map_err(io(&device_cert_path))?;

    let context_path = persist_context(pib.root(), &init.context, &init.context_data)?;
    Ok(PersistedNamespace {
        init,
        ca_key,
        ca_cert,
        device_identity,
        device_key,
        device_cert,
        context_path,
        ca_cert_path,
        anchor_cert_path,
        device_cert_path,
        root_store,
    })
}

/// Generate `key` in the PIB and store a cert for it issued by `issuer`
/// (held by `mgr`, possibly a hardware signer), named
/// `<key>/<issuer_id>/<version>`.
pub(crate) async fn certify_new_key(
    pib: &FilePib,
    mgr: &SecurityManager,
    key: &Name,
    issuer: &Name,
    validity_ms: u64,
    issuer_id: &str,
) -> Result<Certificate, NamespaceInitError> {
    let signer = pib.generate_ed25519(key)?;
    let pk = ndn_security::Signer::public_key(&signer).unwrap_or_default();
    let cert = mgr
        .certify_as(key, pk, issuer, validity_ms, issuer_id, None)
        .await?;
    pib.store_cert(key, &cert)?;
    Ok(cert)
}

/// How a node enforces validity, given whether it has a reliable clock (N4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidityMode {
    /// Wall-clock present: enforce `ValidityPeriod` against the current time.
    WallClock,
    /// No reliable clock (embedded / freshly-imaged): rely on the keyring's
    /// **monotonic context version** plus **single-use / scoped tokens**
    /// instead of TTL. `ValidityPeriod` is still encoded but is not the sole
    /// offline gate; the `baked` archetype prefers approval + scope over TTL.
    Clockless,
}

impl ValidityMode {
    /// Pick a mode from whether a trusted wall-clock is available.
    pub fn detect(has_wall_clock: bool) -> Self {
        if has_wall_clock {
            ValidityMode::WallClock
        } else {
            ValidityMode::Clockless
        }
    }

    /// Whether validity may rely on TTL/`ValidityPeriod`. In `Clockless` mode
    /// it cannot — the caller must fall back to version + single-use tokens.
    pub fn ttl_enforceable(&self) -> bool {
        matches!(self, ValidityMode::WallClock)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[test]
    fn init_namespace_builds_anchored_gated_context() {
        let mgr = SecurityManager::new();
        let init = init_namespace(&mgr, &n("/home/bob")).unwrap();
        assert_eq!(init.anchor_key, n("/home/bob/KEY/root"));
        assert_eq!(init.context.namespace(), &n("/home/bob"));
        assert_eq!(init.context.version(), 1);
        // The generated schema governs alone (no hierarchy floor) and is
        // carried as LVS plus native rules.
        assert!(!init.context.enforces_hierarchy());
        let schemas = init.context.published_schemas();
        assert_eq!(schemas.len(), 2);
        assert_eq!(schemas[0].format, ndn_security::SchemaFormat::Lvs);
        assert_eq!(schemas[0].body.as_ref(), namespace_schema(&n("/home/bob")).unwrap().lvs_binary);
        // The root certifies the CA (judged by the root's certificate name).
        assert!(ndn_security::cert_name::is_cert_name(&init.anchor.name));
        assert!(init.context.authorizes_hop(
            &n("/home/bob/CA/KEY/ca/NA/v=1"),
            &init.anchor_key,
            Some(&init.anchor.name)
        ));
        assert!(!init.context.authorizes(&n("/home/bob/anything"), &init.anchor_key));
        assert_eq!(
            init.context.enrollment_hint(),
            Some(&EnrollmentHint::namespace_default())
        );
        assert!(init.context.is_anchor(&init.anchor_key));
        // The envelope commits to the anchor we just minted, with the context
        // inline as root-signed Data (no unsigned content).
        let TrustEnvelope::Anchor {
            namespace,
            fingerprint,
            version,
            context_data,
            context_content,
        } = &init.envelope
        else {
            panic!("init_namespace must yield an anchor envelope");
        };
        assert_eq!(namespace.as_deref(), Some("/home/bob"));
        assert_eq!(*fingerprint, Some(anchor_fingerprint(&init.anchor)));
        assert_eq!(*version, Some(1));
        assert_eq!(context_data.as_ref(), Some(init.context_data.raw()));
        assert_eq!(*context_content, None);
        assert_eq!(*init.context_data.name, init.context.rdr_name());
        assert_eq!(init.context_data.content(), Some(&init.published_content()));
        // …and it verifies under that very anchor.
        let (_, signer) = crate::onboarding::open_signed_context(&init.context_data).unwrap();
        assert_eq!(signer.name, init.anchor.name);
    }

    fn root_public_key(pib: &FilePib, ns: &Name) -> bytes::Bytes {
        pib.get_signer(&root_key_name(ns))
            .unwrap()
            .public_key()
            .unwrap()
    }

    /// `init_namespace_in_pib` with the root in the FilePib (`file` store).
    fn init_in_pib(
        pib: &FilePib,
        ns: &Name,
        device: &str,
        force: bool,
    ) -> Result<PersistedNamespace, NamespaceInitError> {
        futures::executor::block_on(init_namespace_in_pib(
            pib,
            ns,
            device,
            force,
            &NewRootStore::File,
        ))
    }

    /// `ndn-fwd init` regression: the root, the CA identity and the signed
    /// context must outlive the process (they used to live in a dropped
    /// in-memory manager), and a re-run must not silently replace the root.
    #[test]
    fn init_namespace_in_pib_persists_root_ca_and_context() {
        let dir = tempfile::tempdir().unwrap();
        let pib = FilePib::new(dir.path()).unwrap();
        let ns = n("/home/bob");
        let out = init_in_pib(&pib, &ns, "laptop", false).unwrap();

        // Root key + cert + anchor are in the PIB.
        let root = root_key_name(&ns);
        assert_eq!(root_public_key(&pib, &ns), out.init.anchor.public_key);
        assert_eq!(pib.get_cert(&root).unwrap().public_key, out.init.anchor.public_key);
        assert!(pib.list_anchors().unwrap().contains(&root));

        // CA identity: key in the PIB, cert issued (and signed) by the root.
        assert_eq!(out.ca_key, n("/home/bob/CA/KEY/ca"));
        let ca_pk = pib.get_signer(&out.ca_key).unwrap().public_key().unwrap();
        assert_eq!(out.ca_cert.public_key, ca_pk);
        assert_eq!(out.ca_cert.issuer.as_deref(), Some(&root));
        let ca_wire = std::fs::read(&out.ca_cert_path).unwrap();
        let ca_data = Data::decode(bytes::Bytes::from(ca_wire)).unwrap();
        let outcome = futures::executor::block_on(ndn_security::verifier::verify_by_sig_type(
            ca_data.sig_info().unwrap().sig_type,
            ca_data.signed_region(),
            ca_data.sig_value(),
            &out.init.anchor.public_key,
        ))
        .unwrap();
        assert_eq!(outcome, ndn_security::VerifyOutcome::Valid);
        assert!(out.anchor_cert_path.exists());

        // The signed context is stored, names the CA, and re-loads verified.
        assert_eq!(out.init.context.ca_endpoints(), &[n("/home/bob/CA")]);
        // The inline envelope still fits one QR code (version 40, byte mode,
        // low error correction: 2953 bytes) for a typical namespace.
        let uri = out.init.envelope.to_uri();
        assert!(uri.len() <= 2953, "anchor envelope is {} bytes", uri.len());
        let keyring = ndn_security::Keyring::new();
        let loaded = crate::context_store::load_persisted_contexts(dir.path(), &keyring).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].0, out.context_path);
        assert!(loaded[0].1.is_ok());
        assert_eq!(keyring.version_of(&ns), Some(1));
    }

    /// The primary device gets its own admin identity `<ns>/admin/<device>`,
    /// certified by the CA (not the root), loadable by `from_pib`.
    #[test]
    fn init_namespace_in_pib_mints_loadable_admin_device_identity() {
        let dir = tempfile::tempdir().unwrap();
        let pib = FilePib::new(dir.path()).unwrap();
        let ns = n("/home/bob");
        let out = init_in_pib(&pib, &ns, "laptop", false).unwrap();
        let root = root_key_name(&ns);

        assert_eq!(out.device_identity, n("/home/bob/admin/laptop"));
        assert_eq!(out.device_key, n("/home/bob/admin/laptop/KEY/device"));
        assert_eq!(out.device_cert.issuer.as_deref(), Some(&out.ca_key));
        assert!(out.device_cert.is_valid_now());
        assert!(out.device_cert.valid_until <= out.ca_cert.valid_until);
        // The persisted signed cert is signed by the CA key.
        let wire = std::fs::read(&out.device_cert_path).unwrap();
        let data = Data::decode(bytes::Bytes::from(wire)).unwrap();
        assert!(data.name.has_prefix(&out.device_key) && data.name.len() == out.device_key.len() + 2);
        assert_eq!(data.name.components()[out.device_key.len()].value.as_ref(), b"NDNCERT");
        let outcome = futures::executor::block_on(ndn_security::verifier::verify_by_sig_type(
            data.sig_info().unwrap().sig_type,
            data.signed_region(),
            data.sig_value(),
            &out.ca_cert.public_key,
        ))
        .unwrap();
        assert_eq!(outcome, ndn_security::VerifyOutcome::Valid);

        // A restarted forwarder with `[security] identity = /home/bob/admin/laptop`
        // loads exactly this key, its cert and the root anchor.
        let reopened = FilePib::open(dir.path()).unwrap();
        let mgr = SecurityManager::from_pib(&reopened, &out.device_identity).unwrap();
        assert_eq!(
            mgr.identity_key_name(&out.device_identity),
            Some(out.device_key.clone())
        );
        let signer = mgr.get_signer_sync(&out.device_key).unwrap();
        assert_eq!(signer.public_key().unwrap(), out.device_cert.public_key);
        assert!(mgr.trust_anchor(&root).is_some());
        // …and the namespace's own identity still resolves to the root.
        assert_eq!(reopened.default_key(&ns).unwrap(), Some(root));
    }

    #[test]
    fn init_namespace_in_pib_rejects_invalid_device_names_and_namespaces() {
        let dir = tempfile::tempdir().unwrap();
        let pib = FilePib::new(dir.path()).unwrap();
        let ns = n("/home/bob");
        for bad in ["", "KEY", "CA", "admin", "guest", "a/b", "-x"] {
            let err = init_in_pib(&pib, &ns, bad, false)
                .err()
                .expect("invalid device name must be refused");
            assert!(
                matches!(err, NamespaceInitError::Role(RoleError::InvalidDevice { .. })),
                "{bad:?}: {err}"
            );
        }
        let err = init_in_pib(&pib, &n("/"), "laptop", false).err().unwrap();
        assert!(matches!(err, NamespaceInitError::Role(RoleError::InvalidNamespace { .. })));
        assert!(pib.list_keys().unwrap().is_empty(), "nothing written");
    }

    #[test]
    fn init_namespace_in_pib_refuses_to_replace_root_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let pib = FilePib::new(dir.path()).unwrap();
        let ns = n("/home/bob");
        let first = init_in_pib(&pib, &ns, "laptop", false).unwrap();
        let root_before = root_public_key(&pib, &ns);

        let err = init_in_pib(&pib, &ns, "laptop", false)
            .err()
            .expect("re-init must fail");
        assert!(matches!(err, NamespaceInitError::AlreadyInitialized { .. }), "{err}");
        assert_eq!(root_public_key(&pib, &ns), root_before, "root untouched");

        // With force a fresh root replaces it (and the stored context follows).
        let second = init_in_pib(&pib, &ns, "laptop", true).unwrap();
        assert_ne!(second.device_cert.public_key, first.device_cert.public_key);
        assert_ne!(root_public_key(&pib, &ns), root_before);
        assert_ne!(
            anchor_fingerprint(&second.init.anchor),
            anchor_fingerprint(&first.init.anchor)
        );
        let keyring = ndn_security::Keyring::new();
        let loaded = crate::context_store::load_persisted_contexts(dir.path(), &keyring).unwrap();
        assert_eq!(loaded.len(), 1);
        let ctx = loaded[0].1.as_ref().unwrap();
        let fps: Vec<_> = ctx.anchors().iter().map(|r| anchor_fingerprint(r.value())).collect();
        assert_eq!(fps, vec![anchor_fingerprint(&second.init.anchor)]);
    }

    /// Sign `name` with `key` held by `mgr`.
    fn signed(mgr: &SecurityManager, key: &Name, name: &str) -> Data {
        let signer = mgr.get_signer_sync(key).unwrap();
        let wire = ndn_packet::encode::DataBuilder::new(n(name), b"x").sign_sync(
            signer.sig_type(),
            Some(key),
            |r| signer.sign_sync(r).unwrap_or_default(),
        );
        Data::decode(wire).unwrap()
    }

    /// End to end through a validator whose keyring is loaded from the root device's
    /// PIB: the generated schema admits the role layout's signing chains and
    /// refuses what the roles forbid — on every certificate hop, so a device
    /// cannot self-issue a key, least of all an admin one.
    #[tokio::test]
    async fn namespace_context_validates_role_chains_on_every_hop() {
        use ndn_security::{CertCache, TrustSchema, ValidationResult, Validator};

        let dir = tempfile::tempdir().unwrap();
        let pib = FilePib::new(dir.path()).unwrap();
        let ns = n("/home/bob");
        let out = init_namespace_in_pib(&pib, &ns, "laptop", false, &NewRootStore::File)
            .await
            .unwrap();
        let v = Validator::with_chain(
            TrustSchema::new(),
            Arc::new(CertCache::new()),
            Arc::new(dashmap::DashMap::new()),
            None,
            5,
        );
        crate::context_store::load_persisted_contexts(dir.path(), v.keyring()).unwrap();
        v.cert_cache().insert(out.ca_cert.clone());
        v.cert_cache().insert(out.device_cert.clone());

        let mgr = SecurityManager::new();
        mgr.register_signer(out.device_key.clone(), pib.get_signer(&out.device_key).unwrap());
        mgr.register_signer(out.ca_key.clone(), pib.get_signer(&out.ca_key).unwrap());
        // A member enrolled through the CA.
        let member = n("/home/bob/member/phone/KEY/k1");
        mgr.generate_ed25519(member.clone()).unwrap();
        let pk = mgr.get_signer_sync(&member).unwrap().public_key().unwrap();
        let cert = mgr
            .certify_as(&member, pk, &out.ca_key, 3_600_000, "NDNCERT", None)
            .await
            .unwrap();
        assert!(ndn_security::cert_name::is_cert_name(&cert.name), "{}", cert.name);
        v.cert_cache().insert(cert);
        // The member self-issues an "admin" key.
        let forged = n("/home/bob/admin/phone/KEY/k1");
        mgr.generate_ed25519(forged.clone()).unwrap();
        let pk = mgr.get_signer_sync(&forged).unwrap().public_key().unwrap();
        let cert = mgr.certify(&forged, pk, &member, 3_600_000).await.unwrap();
        v.cert_cache().insert(cert);

        let valid = |r: &ValidationResult| matches!(r, ValidationResult::Valid(_));
        let approval = "/home/bob/member/tablet/KEY/k1/ndncert-approve/req-1";
        let admin = &out.device_key;
        for (key, name, ok) in [
            (admin, "/home/bob/admin/laptop/status", true),
            (admin, approval, true),
            (&member, "/home/bob/shared/list", true),
            (&member, "/home/bob/member/phone/notes", true),
            (&member, approval, false),
            (&member, "/home/bob/admin/laptop/status", false),
            (&forged, approval, false),
        ] {
            let result = v.validate_chain(&signed(&mgr, key, name)).await;
            assert_eq!(valid(&result), ok, "{name} by {key}: {result:?}");
        }
        // The CA cert itself validates as Data under the context.
        let ca_data = Data::decode(bytes::Bytes::from(serialize_cert(&out.ca_cert))).unwrap();
        assert!(valid(&v.validate_chain(&ca_data).await));
    }

    #[test]
    fn validity_mode_clockless_disables_ttl() {
        assert_eq!(ValidityMode::detect(true), ValidityMode::WallClock);
        assert_eq!(ValidityMode::detect(false), ValidityMode::Clockless);
        assert!(ValidityMode::WallClock.ttl_enforceable());
        assert!(!ValidityMode::Clockless.ttl_enforceable());
    }
}
