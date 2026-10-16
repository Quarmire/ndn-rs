//! Hub-archetype onboarding: stand up a network root, publish its
//! [`SignedTrustContext`] (signed by the root) + an `ndn-trust://anchor`
//! [`TrustEnvelope`], and the clockless validity policy that offline/embedded
//! nodes degrade to.
//!
//! The home-hub is the local-gains-first archetype: one node is root + issuing
//! CA + rendezvous. Peers overhear or scan a QR, adopt the context (free), and
//! — only if they want to *produce* — enroll behind `token AND device-approval`.
//! [`init_hub_in_pib`] is the persistent form `ndn-fwd init --profile hub`
//! runs: root key, CA identity, the hub node's own identity and the signed
//! context all land in the node's PIB. See
//! `.claude/notes/trust-context/trust-context-model-2026-05-25.md` §9, §16.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use ndn_packet::{Data, Name};
use ndn_security::{
    Certificate, EnrollmentHint, FilePib, PibError, SecurityManager, SignedTrustContext,
    TrustError,
};
use ndn_trust_envelope::TrustEnvelope;

use crate::ca::serialize_cert;
use crate::context_store::{ContextStoreError, context_file_path, persist_context};
use crate::onboarding::anchor_fingerprint;

/// Directory (under the PIB root) holding the hub's certificate Data wires
/// (CA, root anchor, node identity) and the CA's persistent state.
pub const CA_DIR: &str = "ca";
/// The CA signing cert (issued by the hub root), as raw signed Data TLV.
pub const CA_CERT_FILE: &str = "ca-cert.data";
/// The hub root's self-signed anchor cert, as raw signed Data TLV.
pub const ANCHOR_CERT_FILE: &str = "anchor-cert.data";
/// The hub node's identity cert (issued by the hub root), as raw signed Data
/// TLV. The PIB keeps only a summary of it, without the root's signature.
pub const NODE_CERT_FILE: &str = "node-cert.data";
/// Lifetime of the CA signing cert minted by [`init_hub_in_pib`] (10 years).
pub const CA_CERT_VALIDITY_MS: u64 = 10 * 365 * 24 * 3600 * 1000;
/// Lifetime of the hub node's identity cert minted by [`init_hub_in_pib`].
pub const NODE_CERT_VALIDITY_MS: u64 = CA_CERT_VALIDITY_MS;
/// Default node-name component: the hub node's identity is `<ns>/hub`.
pub const DEFAULT_NODE_NAME: &str = "hub";

/// The hub root key name: `<namespace>/KEY/root`.
pub fn root_key_name(namespace: &Name) -> Name {
    namespace.clone().append("KEY").append("root")
}

/// The hub CA signing key name: `<namespace>/CA/KEY/ca` (identity `<ns>/CA`).
pub fn ca_key_name(namespace: &Name) -> Name {
    namespace.clone().append("CA").append("KEY").append("ca")
}

/// The hub node's identity `<namespace>/<node_name>`, the forwarder's
/// `[security] identity`. `node_name` is one name component other than `KEY`
/// (whose keys would count as the namespace's own) and `CA` (the CA identity).
pub fn node_identity_name(namespace: &Name, node_name: &str) -> Result<Name, HubInitError> {
    if node_name.is_empty() || node_name.contains('/') || matches!(node_name, "KEY" | "CA") {
        return Err(HubInitError::InvalidNodeName(node_name.to_string()));
    }
    Ok(namespace.clone().append(node_name))
}

/// The hub node's signing key name: `<node identity>/KEY/node`.
pub fn node_key_name(node_identity: &Name) -> Name {
    node_identity.clone().append("KEY").append("node")
}

/// Result of initializing a hub.
pub struct HubInit {
    /// The network anchor's key name (`<namespace>/KEY/root`).
    pub anchor_key: Name,
    /// The self-signed network anchor certificate.
    pub anchor: Certificate,
    /// The published, versioned trust context (hierarchical, hub-default gate).
    pub context: Arc<SignedTrustContext>,
    /// The context as signed NDN Data at [`SignedTrustContext::rdr_name`],
    /// signed by the root anchor — what is published and what adopters verify.
    pub context_data: Data,
    /// The out-of-band anchor envelope (QR / deep link):
    /// [`TrustEnvelope::Anchor`] carrying the namespace, the anchor
    /// fingerprint, and the signed context Data inline.
    pub envelope: TrustEnvelope,
}

impl HubInit {
    /// The context `Content` to publish at
    /// [`SignedTrustContext::rdr_name`].
    pub fn published_content(&self) -> bytes::Bytes {
        self.context.encode_content()
    }
}

/// Initialize a hub rooted at `namespace`: generate a signing key in `mgr`,
/// self-sign the network anchor, build a hierarchical context (the
/// skeleton-key-safe default) with the hub enrollment gate
/// (`token AND device-approval`), sign it into Data with the anchor, and mint
/// an anchor envelope committing to the anchor fingerprint.
///
/// The default deployment keeps the *root* offline and runs a delegated
/// context-signer online; this in-process helper signs directly for the
/// self-contained case (tests, single-box hubs). The signing key never leaves
/// `mgr`, and is lost with it — use [`init_hub_in_pib`] for a hub that must
/// survive a restart.
pub fn init_hub(mgr: &SecurityManager, namespace: &Name) -> Result<HubInit, TrustError> {
    let anchor_key = root_key_name(namespace);
    mgr.generate_ed25519(anchor_key)?;
    build_hub(mgr, namespace, None)
}

/// Build the hub around the root key `root_key_name(namespace)` already held
/// by `mgr`.
fn build_hub(
    mgr: &SecurityManager,
    namespace: &Name,
    ca_endpoint: Option<Name>,
) -> Result<HubInit, TrustError> {
    let anchor_key = root_key_name(namespace);
    let signer = mgr.get_signer_sync(&anchor_key)?;
    let pk = signer.public_key().unwrap_or_default();
    let anchor = mgr.issue_self_signed(&anchor_key, pk, u64::MAX)?;

    let mut context = SignedTrustContext::hierarchical(namespace.clone())
        .with_version(1)
        .with_enrollment_hint(EnrollmentHint::hub_default());
    if let Some(ca) = ca_endpoint {
        context = context.with_ca_endpoint(ca);
    }
    context.add_anchor(anchor.clone());
    let context_data = context
        .sign_into_data(signer.as_ref())
        .map_err(|e| TrustError::KeyStore(format!("sign trust context: {e}")))?;
    let context = Arc::new(context);

    let envelope = TrustEnvelope::Anchor {
        namespace: Some(namespace.to_string()),
        fingerprint: Some(anchor_fingerprint(&anchor)),
        version: Some(context.version()),
        context_data: Some(context_data.raw().clone()),
        context_content: None,
    };
    Ok(HubInit {
        anchor_key,
        anchor,
        context,
        context_data,
        envelope,
    })
}

/// A hub initialized into a node's PIB by [`init_hub_in_pib`].
pub struct PersistedHub {
    /// The root, context and envelope (as [`init_hub`]).
    pub hub: HubInit,
    /// The CA signing key name (`<ns>/CA/KEY/ca`).
    pub ca_key: Name,
    /// The CA signing cert, issued by the hub root.
    pub ca_cert: Certificate,
    /// The hub node's own identity (`<ns>/<node_name>`), for the forwarder's
    /// `[security] identity`.
    pub node_identity: Name,
    /// The node's signing key (`<node identity>/KEY/node`), in the PIB.
    pub node_key: Name,
    /// The node's identity cert, issued by the hub root.
    pub node_cert: Certificate,
    /// Where the signed context was stored (the node's adopted-context store).
    pub context_path: PathBuf,
    /// `<pib>/ca/ca-cert.data`.
    pub ca_cert_path: PathBuf,
    /// `<pib>/ca/anchor-cert.data`.
    pub anchor_cert_path: PathBuf,
    /// `<pib>/ca/node-cert.data`.
    pub node_cert_path: PathBuf,
}

/// Why [`init_hub_in_pib`] failed.
#[derive(Debug, thiserror::Error)]
pub enum HubInitError {
    #[error(
        "{namespace} is already initialized in {pib} ({what} exists); refusing to replace \
         its root — re-run with force to mint a new root (every adopter must then re-adopt)"
    )]
    AlreadyInitialized {
        namespace: String,
        pib: String,
        what: String,
    },
    #[error(
        "invalid node name {0:?}: it must be one name component other than `KEY` and `CA`, \
         e.g. `hub`"
    )]
    InvalidNodeName(String),
    #[error(transparent)]
    Trust(#[from] TrustError),
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

/// Persistent hub init: the [`init_hub`] flow with every secret and artefact
/// written to `pib` so the hub survives restarts —
///
/// - root key `<ns>/KEY/root` (+ its cert, registered as a PIB trust anchor);
/// - CA signing identity `<ns>/CA` (key `<ns>/CA/KEY/ca`) with a cert issued
///   by the root, plus both certs as signed Data in `<pib>/ca/`;
/// - the hub node's own identity `<ns>/<node_name>` (key
///   `<ns>/<node_name>/KEY/node`) with a cert issued by the root, so the
///   forwarder loads it with `[security] identity` instead of falling back to
///   an ephemeral key; its signed cert Data is `<pib>/ca/node-cert.data`;
/// - the root-signed context (advertising the CA endpoint `<ns>/CA`) in the
///   node's adopted-context store, so the hub validates its own namespace.
///
/// An existing root, CA key, node key or stored context for `namespace` is
/// never silently replaced: without `force` this fails with
/// [`HubInitError::AlreadyInitialized`].
pub fn init_hub_in_pib(
    pib: &FilePib,
    namespace: &Name,
    node_name: &str,
    force: bool,
) -> Result<PersistedHub, HubInitError> {
    let anchor_key = root_key_name(namespace);
    let ca_key = ca_key_name(namespace);
    let node_identity = node_identity_name(namespace, node_name)?;
    let node_key = node_key_name(&node_identity);
    let context_path = context_file_path(pib.root(), namespace);
    let existing = if pib.get_signer(&anchor_key).is_ok() {
        Some(format!("root key {anchor_key}"))
    } else if pib.get_signer(&ca_key).is_ok() {
        Some(format!("CA key {ca_key}"))
    } else if pib.get_signer(&node_key).is_ok() {
        Some(format!("node key {node_key}"))
    } else if context_path.exists() {
        Some(format!("trust context {}", context_path.display()))
    } else {
        None
    };
    if let Some(what) = existing {
        if !force {
            return Err(HubInitError::AlreadyInitialized {
                namespace: namespace.to_string(),
                pib: pib.root().display().to_string(),
                what,
            });
        }
        pib.delete_key(&anchor_key)?;
        pib.delete_key(&ca_key)?;
        pib.delete_key(&node_key)?;
        pib.remove_trust_anchor(&anchor_key)?;
    }

    // Root: generated straight into the PIB, then held by an in-process
    // manager for the signing steps below.
    let mgr = SecurityManager::new();
    mgr.install_signer(pib.generate_ed25519(&anchor_key)?);
    let hub = build_hub(&mgr, namespace, Some(namespace.clone().append("CA")))?;
    pib.store_cert(&anchor_key, &hub.anchor)?;
    pib.add_trust_anchor(&anchor_key, &hub.anchor)?;

    // CA signing identity and the hub node's identity, both certified by
    // the root.
    let ca_cert = certify_new_key(pib, &mgr, &ca_key, &anchor_key, CA_CERT_VALIDITY_MS)?;
    let node_cert = certify_new_key(pib, &mgr, &node_key, &anchor_key, NODE_CERT_VALIDITY_MS)?;

    let ca_dir = pib.root().join(CA_DIR);
    let io = |path: &Path| {
        let path = path.to_path_buf();
        move |source| HubInitError::Io { path, source }
    };
    std::fs::create_dir_all(&ca_dir).map_err(io(&ca_dir))?;
    let ca_cert_path = ca_dir.join(CA_CERT_FILE);
    std::fs::write(&ca_cert_path, serialize_cert(&ca_cert)).map_err(io(&ca_cert_path))?;
    let anchor_cert_path = ca_dir.join(ANCHOR_CERT_FILE);
    std::fs::write(&anchor_cert_path, serialize_cert(&hub.anchor))
        .map_err(io(&anchor_cert_path))?;
    let node_cert_path = ca_dir.join(NODE_CERT_FILE);
    std::fs::write(&node_cert_path, serialize_cert(&node_cert)).map_err(io(&node_cert_path))?;

    let context_path = persist_context(pib.root(), &hub.context, &hub.context_data)?;
    Ok(PersistedHub {
        hub,
        ca_key,
        ca_cert,
        node_identity,
        node_key,
        node_cert,
        context_path,
        ca_cert_path,
        anchor_cert_path,
        node_cert_path,
    })
}

/// Generate `key` in the PIB and store a cert for it issued by `issuer`
/// (held by `mgr`).
fn certify_new_key(
    pib: &FilePib,
    mgr: &SecurityManager,
    key: &Name,
    issuer: &Name,
    validity_ms: u64,
) -> Result<Certificate, HubInitError> {
    let signer = pib.generate_ed25519(key)?;
    let pk = ndn_security::Signer::public_key(&signer).unwrap_or_default();
    let cert = futures::executor::block_on(mgr.certify(key, pk, issuer, validity_ms))?;
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
    fn init_hub_builds_anchored_gated_context() {
        let mgr = SecurityManager::new();
        let hub = init_hub(&mgr, &n("/home/bob")).unwrap();
        assert_eq!(hub.anchor_key, n("/home/bob/KEY/root"));
        assert_eq!(hub.context.namespace(), &n("/home/bob"));
        assert_eq!(hub.context.version(), 1);
        assert!(hub.context.enforces_hierarchy());
        assert_eq!(
            hub.context.enrollment_hint(),
            Some(&EnrollmentHint::hub_default())
        );
        assert!(hub.context.is_anchor(&hub.anchor_key));
        // The envelope commits to the anchor we just minted, with the context
        // inline as root-signed Data (no unsigned content).
        let TrustEnvelope::Anchor {
            namespace,
            fingerprint,
            version,
            context_data,
            context_content,
        } = &hub.envelope
        else {
            panic!("init_hub must yield an anchor envelope");
        };
        assert_eq!(namespace.as_deref(), Some("/home/bob"));
        assert_eq!(*fingerprint, Some(anchor_fingerprint(&hub.anchor)));
        assert_eq!(*version, Some(1));
        assert_eq!(context_data.as_ref(), Some(hub.context_data.raw()));
        assert_eq!(*context_content, None);
        assert_eq!(*hub.context_data.name, hub.context.rdr_name());
        assert_eq!(hub.context_data.content(), Some(&hub.published_content()));
        // …and it verifies under that very anchor.
        let (_, signer) = crate::onboarding::open_signed_context(&hub.context_data).unwrap();
        assert_eq!(signer.name, hub.anchor.name);
    }

    fn root_public_key(pib: &FilePib, ns: &Name) -> bytes::Bytes {
        pib.get_signer(&root_key_name(ns))
            .unwrap()
            .public_key()
            .unwrap()
    }

    /// `ndn-fwd init` regression: the root, the CA identity and the signed
    /// context must outlive the process (they used to live in a dropped
    /// in-memory manager), and a re-run must not silently replace the root.
    #[test]
    fn init_hub_in_pib_persists_root_ca_and_context() {
        let dir = tempfile::tempdir().unwrap();
        let pib = FilePib::new(dir.path()).unwrap();
        let ns = n("/home/bob");
        let out = init_hub_in_pib(&pib, &ns, DEFAULT_NODE_NAME, false).unwrap();

        // Root key + cert + anchor are in the PIB.
        let root = root_key_name(&ns);
        assert_eq!(root_public_key(&pib, &ns), out.hub.anchor.public_key);
        assert_eq!(pib.get_cert(&root).unwrap().public_key, out.hub.anchor.public_key);
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
            &out.hub.anchor.public_key,
        ))
        .unwrap();
        assert_eq!(outcome, ndn_security::VerifyOutcome::Valid);
        assert!(out.anchor_cert_path.exists());

        // The signed context is stored, names the CA, and re-loads verified.
        assert_eq!(out.hub.context.ca_endpoints(), &[n("/home/bob/CA")]);
        let keyring = ndn_security::Keyring::new();
        let loaded = crate::context_store::load_persisted_contexts(dir.path(), &keyring).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].0, out.context_path);
        assert!(loaded[0].1.is_ok());
        assert_eq!(keyring.version_of(&ns), Some(1));
    }

    /// `ndn-fwd init` regression: the hub node had no identity of its own in
    /// the PIB, so the forwarder fell back to an ephemeral key. Init now mints
    /// `<ns>/<node-name>` with a root-issued cert that `from_pib` loads.
    #[test]
    fn init_hub_in_pib_mints_loadable_node_identity() {
        let dir = tempfile::tempdir().unwrap();
        let pib = FilePib::new(dir.path()).unwrap();
        let ns = n("/home/bob");
        let out = init_hub_in_pib(&pib, &ns, DEFAULT_NODE_NAME, false).unwrap();
        let root = root_key_name(&ns);

        assert_eq!(out.node_identity, n("/home/bob/hub"));
        assert_eq!(out.node_key, n("/home/bob/hub/KEY/node"));
        assert_eq!(out.node_cert.issuer.as_deref(), Some(&root));
        assert!(out.node_cert.is_valid_now());
        // The persisted signed cert chains to the root anchor.
        let node_wire = std::fs::read(&out.node_cert_path).unwrap();
        let node_data = Data::decode(bytes::Bytes::from(node_wire)).unwrap();
        assert_eq!(*node_data.name, out.node_key);
        let outcome = futures::executor::block_on(ndn_security::verifier::verify_by_sig_type(
            node_data.sig_info().unwrap().sig_type,
            node_data.signed_region(),
            node_data.sig_value(),
            &out.hub.anchor.public_key,
        ))
        .unwrap();
        assert_eq!(outcome, ndn_security::VerifyOutcome::Valid);

        // A restarted forwarder with `[security] identity = /home/bob/hub`
        // loads exactly this key, its cert and the root anchor.
        let reopened = FilePib::open(dir.path()).unwrap();
        let mgr = SecurityManager::from_pib(&reopened, &out.node_identity).unwrap();
        assert_eq!(mgr.identity_key_name(&out.node_identity), Some(out.node_key.clone()));
        let signer = mgr.get_signer_sync(&out.node_key).unwrap();
        assert_eq!(signer.public_key().unwrap(), out.node_cert.public_key);
        assert!(mgr.trust_anchor(&root).is_some());
        // …and the namespace's own identity still resolves to the root.
        assert_eq!(reopened.default_key(&ns).unwrap(), Some(root));
    }

    #[test]
    fn init_hub_in_pib_rejects_node_names_that_collide() {
        let dir = tempfile::tempdir().unwrap();
        let pib = FilePib::new(dir.path()).unwrap();
        let ns = n("/home/bob");
        for bad in ["", "KEY", "CA", "a/b"] {
            let err = init_hub_in_pib(&pib, &ns, bad, false)
                .err()
                .expect("colliding node name must be refused");
            assert!(matches!(err, HubInitError::InvalidNodeName(_)), "{bad:?}: {err}");
        }
        assert!(pib.list_keys().unwrap().is_empty(), "nothing written");
    }

    #[test]
    fn init_hub_in_pib_refuses_to_replace_root_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let pib = FilePib::new(dir.path()).unwrap();
        let ns = n("/home/bob");
        let first = init_hub_in_pib(&pib, &ns, DEFAULT_NODE_NAME, false).unwrap();
        let root_before = root_public_key(&pib, &ns);

        let err = init_hub_in_pib(&pib, &ns, DEFAULT_NODE_NAME, false)
            .err()
            .expect("re-init must fail");
        assert!(matches!(err, HubInitError::AlreadyInitialized { .. }), "{err}");
        assert_eq!(root_public_key(&pib, &ns), root_before, "root untouched");

        // With force a fresh root replaces it (and the stored context follows).
        let second = init_hub_in_pib(&pib, &ns, DEFAULT_NODE_NAME, true).unwrap();
        assert_ne!(second.node_cert.public_key, first.node_cert.public_key);
        assert_ne!(root_public_key(&pib, &ns), root_before);
        assert_ne!(
            anchor_fingerprint(&second.hub.anchor),
            anchor_fingerprint(&first.hub.anchor)
        );
        let keyring = ndn_security::Keyring::new();
        let loaded = crate::context_store::load_persisted_contexts(dir.path(), &keyring).unwrap();
        assert_eq!(loaded.len(), 1);
        let ctx = loaded[0].1.as_ref().unwrap();
        let fps: Vec<_> = ctx.anchors().iter().map(|r| anchor_fingerprint(r.value())).collect();
        assert_eq!(fps, vec![anchor_fingerprint(&second.hub.anchor)]);
    }

    #[test]
    fn validity_mode_clockless_disables_ttl() {
        assert_eq!(ValidityMode::detect(true), ValidityMode::WallClock);
        assert_eq!(ValidityMode::detect(false), ValidityMode::Clockless);
        assert!(ValidityMode::WallClock.ttl_enforceable());
        assert!(!ValidityMode::Clockless.ttl_enforceable());
    }
}
