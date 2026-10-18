//! Planning a revocation on the root device, before the root is unlocked.
//!
//! A revocation is a new version of the trust context that lists keys as
//! revoked ([`crate::bump_context_revoking`]). What a name designates: a key
//! or certificate name, its key; a device identity, every key the namespace
//! CA of the root device certified for exactly that identity (read from its
//! store, `<pib>/ca/`). Never the root's key (every key chains to it) nor the
//! CA's, and nothing to sign when the held version revokes them all already
//! ([`crate::revocations_to_add`]).

use std::path::{Path, PathBuf};

use ndn_packet::Name;
use ndn_security::FilePib;

use crate::context_update::{BumpError, key_name_of, revocations_to_add};
use crate::error::CertError;
use crate::namespace::CA_DIR;
use crate::root_device::{RootDevice, RootDeviceError, root_device};
use crate::store::{CaStore, FileCaStore};

/// Why a revocation is refused before anything is signed.
#[derive(Debug, thiserror::Error)]
pub enum RevocationError {
    #[error(transparent)]
    RootDevice(#[from] RootDeviceError),
    #[error(
        "{name} is not in {namespace}, the namespace whose root this device holds; nothing was \
         signed"
    )]
    OutsideNamespace { name: Name, namespace: Name },
    #[error(
        "refusing to revoke {name}: it is the namespace CA, and every device certificate of \
         {namespace} chains to it. Replacing the CA (a compromised relay) is not built yet; \
         revoke the devices one by one instead. Nothing was signed"
    )]
    NamespaceCa { name: Name, namespace: Name },
    #[error("read the CA store {}", .dir.display())]
    CaStore {
        dir: PathBuf,
        #[source]
        source: CertError,
    },
    #[error(
        "the namespace CA of {} issued no certificate for {name}, so there is no key to revoke \
         under that name; pass the device identity as enrolled (/<namespace>/<role>/<device>), \
         or a key name (<identity>/KEY/<key-id>) to revoke a key this CA did not certify. \
         Nothing was signed",
        .pib.display()
    )]
    NoneIssued { pib: PathBuf, name: Name },
    /// A key that may not be revoked (not of the namespace, or an anchor's).
    #[error("{0}; nothing was signed")]
    Refused(BumpError),
}

/// What a revocation signs, decided before the root is unlocked.
pub struct RevocationPlan {
    /// The root device and the version the revocation follows.
    pub root: RootDevice,
    /// The key names the command names.
    pub keys: Vec<Name>,
    /// Those the held version does not revoke yet; empty when it revokes all.
    pub adding: Vec<Name>,
}

/// The key names `name` designates: itself (or the key of a certificate
/// name), else every key the namespace CA of the PIB `pib_dir` certified for
/// the device identity `name` — keys of exactly that identity, not of names
/// below it.
pub fn keys_to_revoke(pib_dir: &Path, name: &Name) -> Result<Vec<Name>, RevocationError> {
    if let Some(key) = key_name_of(name) {
        return Ok(vec![key]);
    }
    let ca_dir = pib_dir.join(CA_DIR);
    let issued = if ca_dir.is_dir() {
        FileCaStore::open(&ca_dir)
            .and_then(|store| store.load())
            .map_err(|source| RevocationError::CaStore {
                dir: ca_dir.clone(),
                source,
            })?
            .issued
    } else {
        Vec::new()
    };
    let mut keys: Vec<Name> = Vec::new();
    for (cert, _) in issued {
        let Some(key) = cert.parse::<Name>().ok().as_ref().and_then(key_name_of) else {
            continue;
        };
        // `<identity>/KEY/<k>`: only keys of exactly this identity.
        if key.has_prefix(name) && key.len() == name.len() + 2 && !keys.contains(&key) {
            keys.push(key);
        }
    }
    if keys.is_empty() {
        return Err(RevocationError::NoneIssued {
            pib: pib_dir.to_path_buf(),
            name: name.clone(),
        });
    }
    Ok(keys)
}

/// Every check of a revocation of `name` that needs no key: `pib` is the
/// root device of the namespace containing `name`, and `name` designates
/// keys that may be revoked — never the root's nor the CA's.
pub fn plan_revocation(pib: &FilePib, name: &Name) -> Result<RevocationPlan, RevocationError> {
    let root = root_device(pib, "devices are revoked")?;
    let namespace = root.context.namespace().clone();
    if !name.has_prefix(&namespace) {
        return Err(RevocationError::OutsideNamespace {
            name: name.clone(),
            namespace,
        });
    }
    if name.has_prefix(&namespace.clone().append("CA")) {
        return Err(RevocationError::NamespaceCa {
            name: name.clone(),
            namespace,
        });
    }
    let keys = keys_to_revoke(pib.root(), name)?;
    let adding = revocations_to_add(&root.context, &keys).map_err(RevocationError::Refused)?;
    Ok(RevocationPlan { root, keys, adding })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::namespace::{PersistedNamespace, init_namespace_in_pib};
    use crate::root_store::NewRootStore;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    /// A root device of `/home/bob` whose CA issued the admin device's
    /// certificate.
    fn root_device_pib(dir: &Path) -> (FilePib, PersistedNamespace) {
        let pib = FilePib::new(dir).unwrap();
        let out = futures::executor::block_on(init_namespace_in_pib(
            &pib,
            &n("/home/bob"),
            "laptop",
            false,
            &NewRootStore::File,
        ))
        .unwrap();
        FileCaStore::open(dir.join(CA_DIR))
            .unwrap()
            .record_issued(
                &out.device_cert.name.to_string(),
                &crate::ca::serialize_cert(&out.device_cert),
            )
            .unwrap();
        (pib, out)
    }

    #[test]
    fn a_device_identity_designates_the_keys_its_ca_certified() {
        let dir = tempfile::tempdir().unwrap();
        let (pib, out) = root_device_pib(dir.path());
        let plan = plan_revocation(&pib, &out.device_identity).unwrap();
        assert_eq!(plan.keys, vec![out.device_key.clone()]);
        assert_eq!(plan.adding, vec![out.device_key.clone()]);
        // A key name designates itself; a certificate name its key.
        let key = n("/home/bob/member/phone/KEY/k");
        assert_eq!(keys_to_revoke(dir.path(), &key).unwrap(), vec![key.clone()]);
        assert_eq!(
            keys_to_revoke(dir.path(), &out.device_cert.name).unwrap(),
            vec![out.device_key.clone()]
        );
        // Only exactly that identity, not names below or above it.
        assert!(matches!(
            keys_to_revoke(dir.path(), &n("/home/bob/admin")),
            Err(RevocationError::NoneIssued { .. })
        ));
    }

    #[test]
    fn never_the_root_the_ca_or_a_name_outside_the_namespace() {
        let dir = tempfile::tempdir().unwrap();
        let (pib, _) = root_device_pib(dir.path());
        for (name, refused) in [
            ("/home/bob/KEY/root", "covers the namespace root"),
            ("/home/bob/CA", "it is the namespace CA"),
            ("/home/bob/CA/KEY/ca", "it is the namespace CA"),
            ("/home/bob/member/tablet", "issued no certificate"),
            ("/home/alice/member/phone/KEY/k", "is not in /home/bob"),
        ] {
            let e = plan_revocation(&pib, &n(name)).err().unwrap().to_string();
            assert!(e.contains(refused), "{name}: {e}");
            assert!(
                e.to_lowercase().contains("nothing was signed"),
                "{name}: {e}"
            );
        }
    }

    #[test]
    fn only_on_the_root_device() {
        let (root_dir, other) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (_, out) = root_device_pib(root_dir.path());
        let pib = FilePib::new(other.path()).unwrap();
        crate::persist_context(other.path(), &out.init.context, &out.init.context_data).unwrap();
        assert!(matches!(
            plan_revocation(&pib, &out.device_identity),
            Err(RevocationError::RootDevice(RootDeviceError::NoRoot { .. }))
        ));
    }
}
