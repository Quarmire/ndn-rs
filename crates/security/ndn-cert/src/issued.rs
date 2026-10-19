//! The certificates the CAs of a host issued, as `ca/issued-list` answers
//! them: the members of each namespace as its CA knows them.
//!
//! A listing is read from the running CA ([`CaState::issued_certificates`]),
//! which loads its durable record (`issued/` and `revoked/` of its store,
//! [`crate::store::FileCaStore`]) when it starts and records every issuance
//! and revocation before it takes effect. The CA's own certificate and those
//! of earlier CAs of its identity are not listed.
//!
//! An entry is `revoked` when the CA revoked it (or its key), or when the
//! trust context the host holds for its name revokes the certificate, its
//! key, or a key on its issuer chain (the CA's key, the namespace root's).
//! Entries are ordered by identity, then newest first (latest `valid_from`),
//! then by certificate name.

use std::sync::Arc;

use ndn_packet::Name;
use ndn_security::{Certificate, Keyring, SignedTrustContext};

use crate::ca::CaState;
use crate::invites::HostInvites;
use crate::report::{TrustRefusal, code};
use crate::roles::parse_device_key;

/// One certificate a CA issued.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IssuedEntry {
    /// The certificate's name.
    pub certificate: String,
    /// The key it certifies (`<identity>/KEY/<id>`).
    pub key: String,
    /// The key's identity: the key name without `KEY/<id>`.
    pub identity: String,
    /// The role of the identity (`admin`, `member`, `node`, `guest`), when
    /// it follows the namespace's role layout `/<ns>/<role>/<device>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// The device name of the identity, under the same layout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// Start of the validity period, ISO 8601 basic, UTC (`20261017T120000Z`).
    pub valid_from: String,
    /// End of the validity period, ISO 8601 basic, UTC.
    pub valid_until: String,
    /// The CA revoked it, or the held trust context revokes it, its key or
    /// a key on its issuer chain.
    pub revoked: bool,
}

/// The certificates one CA issued, as `ca/issued-list` answers them.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CaIssuedListing {
    /// The CA's prefix.
    pub ca: String,
    /// The namespace it certifies in.
    pub namespace: String,
    /// By identity, then newest first.
    pub certificates: Vec<IssuedEntry>,
}

/// One CA a host runs, as its issued certificates are listed.
#[derive(Clone)]
pub struct CaIssued {
    state: Arc<CaState>,
    ca_prefix: Name,
    namespace: Name,
}

impl CaIssued {
    /// The running CA `state`, whose prefix is `ca_prefix` and which
    /// certifies in `namespace` (its prefix for a CA without one).
    pub fn new(state: Arc<CaState>, ca_prefix: Name, namespace: Name) -> Self {
        Self {
            state,
            ca_prefix,
            namespace,
        }
    }

    /// Whether `name` names this CA: its namespace or its prefix.
    pub fn is_named(&self, name: &Name) -> bool {
        &self.namespace == name || &self.ca_prefix == name
    }

    /// Every certificate the CA issued, revocation judged also against the
    /// trust contexts `keyring` holds.
    pub fn listing(&self, keyring: &Keyring) -> CaIssuedListing {
        let mut issued: Vec<(u64, IssuedEntry)> = self
            .state
            .issued_certificates()
            .into_iter()
            .map(|(cert, revoked_here)| {
                let revoked = revoked_here
                    || revoked_by(
                        &keyring.context_for(&cert.name),
                        &cert,
                        &self.state.issuer_chain(&cert),
                    );
                (cert.valid_from, self.entry(&cert, revoked))
            })
            .collect();
        issued.sort_by(|(a_from, a), (b_from, b)| {
            a.identity
                .cmp(&b.identity)
                .then(b_from.cmp(a_from))
                .then_with(|| a.certificate.cmp(&b.certificate))
        });
        CaIssuedListing {
            ca: self.ca_prefix.to_string(),
            namespace: self.namespace.to_string(),
            certificates: issued.into_iter().map(|(_, entry)| entry).collect(),
        }
    }

    fn entry(&self, cert: &Certificate, revoked: bool) -> IssuedEntry {
        let key = cert.key_name();
        let device = parse_device_key(&self.namespace, &key);
        IssuedEntry {
            certificate: cert.name.to_string(),
            identity: identity_of(&key).to_string(),
            key: key.to_string(),
            role: device.as_ref().map(|d| d.role.as_str().to_owned()),
            device: device.map(|d| d.device),
            valid_from: iso(cert.valid_from),
            valid_until: iso(cert.valid_until),
            revoked,
        }
    }
}

/// The certificates every CA of a host issued: what `ca/issued-list` acts
/// on. A request names its CA by namespace or prefix; naming none lists
/// every CA's.
#[derive(Clone)]
pub struct HostIssued {
    cas: Vec<CaIssued>,
    /// The trust contexts the host holds, which revocation is judged against.
    keyring: Arc<Keyring>,
}

impl HostIssued {
    pub fn new(cas: Vec<CaIssued>, keyring: Arc<Keyring>) -> Self {
        Self { cas, keyring }
    }

    /// The certificates of the CA `ca` names, or of every CA of the host
    /// when none is named.
    pub fn list(&self, ca: Option<&Name>) -> Result<Vec<CaIssuedListing>, TrustRefusal> {
        if self.cas.is_empty() {
            return Err(TrustRefusal::new(
                code::ISSUED_NO_CA,
                "this node runs no CA, so it issued no certificates",
            ));
        }
        let Some(name) = ca else {
            return Ok(self.cas.iter().map(|c| c.listing(&self.keyring)).collect());
        };
        match self.cas.iter().find(|c| c.is_named(name)) {
            Some(c) => Ok(vec![c.listing(&self.keyring)]),
            None => {
                let held = self
                    .cas
                    .iter()
                    .map(|c| c.namespace.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                Err(TrustRefusal::new(
                    code::ISSUED_CA_UNKNOWN,
                    format!("this node runs no CA of {name}; it runs the CAs of {held}"),
                )
                .with("requested", name)
                .with("namespaces", held))
            }
        }
    }
}

/// The CAs a host runs, as its management acts on them: their invites
/// (`ca/invite-*`) and the certificates they issued (`ca/issued-list`).
#[derive(Clone)]
pub struct HostCas {
    invites: HostInvites,
    issued: HostIssued,
}

impl HostCas {
    pub fn new(invites: HostInvites, issued: HostIssued) -> Self {
        Self { invites, issued }
    }

    pub fn invites(&self) -> &HostInvites {
        &self.invites
    }

    pub fn issued(&self) -> &HostIssued {
        &self.issued
    }
}

/// Whether `ctx` revokes `cert`: the certificate or its key (a revocation
/// covers every name under it), or a key on its issuer chain.
fn revoked_by(ctx: &SignedTrustContext, cert: &Certificate, chain: &[Name]) -> bool {
    ctx.is_revoked(&cert.name) || chain.iter().any(|issuer| ctx.is_revoked(issuer))
}

/// The identity of `key`: `<identity>/KEY/<id>` without `KEY/<id>`; a name
/// of another shape is its own identity.
fn identity_of(key: &Name) -> Name {
    if ndn_security::cert_name::is_key_name(key) {
        Name::from_components(key.components()[..key.len() - 2].iter().cloned())
    } else {
        key.clone()
    }
}

/// `ns` since the Unix epoch, as ISO 8601 basic, UTC.
fn iso(ns: u64) -> String {
    crate::approval::iso_secs(ns / 1_000_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::{CaConfig, serialize_cert};
    use crate::challenge::ChallengeHandler;
    use crate::store::{CaStore, FileCaStore};
    use crate::{HierarchicalPolicy, NopChallenge};
    use ndn_security::SecurityManager;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn ca_key() -> Name {
        n("/home/bob/CA/KEY/ca")
    }

    /// A namespace CA of `/home/bob` (root `/home/bob/KEY/root`), backed by
    /// a store in `dir` that records `phone`, `tv` and `tablet` as issued
    /// and `tv` as revoked.
    async fn ca_with_store(dir: &std::path::Path) -> (Arc<CaState>, Vec<Certificate>) {
        let root = n("/home/bob/KEY/root");
        let mgr = SecurityManager::new();
        let public_key = |mgr: &SecurityManager, key: &Name| {
            mgr.get_signer_sync(key).unwrap().public_key().unwrap()
        };
        mgr.generate_ed25519_from_seed(root.clone(), &[1; 32])
            .unwrap();
        mgr.issue_self_signed(&root, public_key(&mgr, &root), u64::MAX)
            .unwrap();
        mgr.generate_ed25519_from_seed(ca_key(), &[2; 32]).unwrap();
        mgr.certify(&ca_key(), public_key(&mgr, &ca_key()), &root, 86_400_000)
            .await
            .unwrap();

        let store = FileCaStore::open(dir).unwrap();
        let mut issued = Vec::new();
        for (seed, key) in [
            (3, "/home/bob/member/phone/KEY/p"),
            (4, "/home/bob/guest/tv/KEY/t"),
            (5, "/home/bob/member/tablet/KEY/s"),
        ] {
            let key = n(key);
            mgr.generate_ed25519_from_seed(key.clone(), &[seed; 32])
                .unwrap();
            let cert = mgr
                .certify(&key, public_key(&mgr, &key), &ca_key(), 86_400_000)
                .await
                .unwrap();
            store
                .record_issued(&cert.name.to_string(), &serialize_cert(&cert))
                .unwrap();
            issued.push(cert);
        }
        store.record_revoked(&issued[1].name.to_string()).unwrap();

        let challenges: Vec<Box<dyn ChallengeHandler>> = vec![Box::new(NopChallenge::new())];
        let config = CaConfig::new(
            n("/home/bob"),
            "namespace CA".into(),
            std::time::Duration::from_secs(86_400),
            std::time::Duration::from_secs(86_400),
            challenges,
            Box::new(HierarchicalPolicy),
        )
        .with_signing_key(ca_key());
        let store: Arc<dyn CaStore> = Arc::new(store);
        let state = CaState::with_store(config, Arc::new(mgr), store).unwrap();
        (Arc::new(state), issued)
    }

    fn host(state: Arc<CaState>, keyring: Arc<Keyring>) -> HostIssued {
        HostIssued::new(
            vec![CaIssued::new(state, n("/home/bob"), n("/home/bob"))],
            keyring,
        )
    }

    /// Every certificate the store records as issued is listed with its
    /// identity, role, device and validity, by identity; the one the store
    /// records as revoked is revoked; the CA's own certificate is not
    /// listed.
    #[tokio::test]
    async fn lists_what_the_store_records() {
        let dir = tempfile::tempdir().unwrap();
        let (state, issued) = ca_with_store(dir.path()).await;
        let listed = host(state, Arc::new(Keyring::new())).list(None).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].ca, "/home/bob");
        assert_eq!(listed[0].namespace, "/home/bob");
        let certs = &listed[0].certificates;
        let identities: Vec<&str> = certs.iter().map(|c| c.identity.as_str()).collect();
        assert_eq!(
            identities,
            [
                "/home/bob/guest/tv",
                "/home/bob/member/phone",
                "/home/bob/member/tablet"
            ]
        );
        let tv = &certs[0];
        assert_eq!(tv.certificate, issued[1].name.to_string());
        assert_eq!(tv.key, "/home/bob/guest/tv/KEY/t");
        assert_eq!(tv.role.as_deref(), Some("guest"));
        assert_eq!(tv.device.as_deref(), Some("tv"));
        assert!(tv.revoked, "the store records it revoked");
        assert!(tv.valid_from.ends_with('Z') && tv.valid_from < tv.valid_until);
        assert!(!certs[1].revoked && !certs[2].revoked);
        assert!(
            certs.iter().all(|c| !c.key.starts_with("/home/bob/CA/")),
            "the CA's own certificate is not listed"
        );
        let json = serde_json::to_string(&listed).unwrap();
        assert_eq!(
            serde_json::from_str::<Vec<CaIssuedListing>>(&json).unwrap(),
            listed
        );
    }

    /// The held trust context revokes a key (that certificate only), or the
    /// CA's key on every chain (each certificate).
    #[tokio::test]
    async fn the_held_context_revokes_a_key_or_its_chain() {
        let dir = tempfile::tempdir().unwrap();
        let (state, _) = ca_with_store(dir.path()).await;
        let keyring = Arc::new(Keyring::new());
        let ctx = SignedTrustContext::hierarchical(n("/home/bob"))
            .with_version(2)
            .with_revocation(n("/home/bob/member/tablet/KEY/s"));
        assert!(keyring.adopt(Arc::new(ctx)));
        let hosted = host(Arc::clone(&state), Arc::clone(&keyring));
        let revoked: Vec<(String, bool)> = hosted.list(None).unwrap()[0]
            .certificates
            .iter()
            .map(|c| (c.device.clone().unwrap(), c.revoked))
            .collect();
        assert_eq!(
            revoked,
            [
                ("tv".to_owned(), true),
                ("phone".to_owned(), false),
                ("tablet".to_owned(), true)
            ]
        );

        let ctx = SignedTrustContext::hierarchical(n("/home/bob"))
            .with_version(3)
            .with_revocation(ca_key());
        assert!(keyring.adopt(Arc::new(ctx)));
        assert!(
            hosted.list(None).unwrap()[0]
                .certificates
                .iter()
                .all(|c| c.revoked),
            "a revoked issuer revokes every certificate it signed"
        );
    }

    /// No CA, and a CA the host does not run, are refused with their codes;
    /// a CA is named by its namespace or prefix.
    #[tokio::test]
    async fn refusals_are_coded() {
        let none = HostIssued::new(Vec::new(), Arc::new(Keyring::new()));
        assert_eq!(none.list(None).unwrap_err().code, code::ISSUED_NO_CA.code);
        let dir = tempfile::tempdir().unwrap();
        let (state, _) = ca_with_store(dir.path()).await;
        let hosted = host(state, Arc::new(Keyring::new()));
        let unknown = hosted.list(Some(&n("/work/acme"))).unwrap_err();
        assert_eq!(unknown.code, code::ISSUED_CA_UNKNOWN.code);
        assert_eq!(unknown.params.get("namespaces").unwrap(), "/home/bob");
        assert_eq!(hosted.list(Some(&n("/home/bob"))).unwrap().len(), 1);
    }
}
