//! The root device of a namespace: the device whose PIB holds the root
//! store ([`crate::root_store`]) of a namespace whose held trust context
//! lists that root as an anchor. New versions of the context are made only
//! there (revocations, recovery kits, schema updates), so every such command
//! starts with [`root_device`].
//!
//! A device that ran `ndn-fwd recover` holds the new root; the lost device
//! still holds its old root store, but once a version without that root is
//! held there it is no longer the root device.

use std::path::{Path, PathBuf};

use ndn_packet::{Data, Name};
use ndn_security::{FilePib, SignedTrustContext};

use crate::context_store::{ContextStoreError, read_stored_context, read_stored_contexts};
use crate::recovery::{FileKit, RecoveryError};
use crate::root_store::{RootStore, RootStoreError};

/// Why this PIB is not the root device, or what a root-device command acts
/// on could not be read.
#[derive(Debug, thiserror::Error)]
pub enum RootDeviceError {
    #[error(transparent)]
    RootStore(#[from] RootStoreError),
    #[error(
        "{} holds no namespace root: {work} on the root device (where `ndn-fwd init` ran, or a \
         device that ran `ndn-fwd recover`)",
        .pib.display()
    )]
    NoRoot { pib: PathBuf, work: String },
    #[error(transparent)]
    Store(#[from] ContextStoreError),
    #[error(
        "{} holds no trust context for {namespace} (adopt it first: ndn-fwd adopt <link>)",
        .pib.display()
    )]
    NotHeld { pib: PathBuf, namespace: Name },
    #[error(
        "the root key {key} of this PIB is not an anchor of the held trust context of \
         {namespace} (v{version}): this is no longer the root device of the namespace"
    )]
    NoLongerRoot {
        key: Name,
        namespace: Name,
        version: u64,
    },
    #[error(transparent)]
    Kit(#[from] RecoveryError),
    #[error("{} holds no trust context; pass --namespace <ns>", .pib.display())]
    NoContext { pib: PathBuf },
    #[error("{} holds several trust contexts; pass --namespace <ns>", .pib.display())]
    SeveralContexts { pib: PathBuf },
}

/// The root device's root store and the version of its namespace's trust
/// context it holds — the version the next one is made from.
pub struct RootDevice {
    pub store: RootStore,
    pub context: SignedTrustContext,
    /// `context` as stored: its signed Data, byte for byte.
    pub data: Data,
}

/// The context `pib_dir` holds for `namespace`, as stored.
pub fn held_context(
    pib_dir: &Path,
    namespace: &Name,
) -> Result<(SignedTrustContext, Data), RootDeviceError> {
    read_stored_context(pib_dir, namespace)?.ok_or_else(|| RootDeviceError::NotHeld {
        pib: pib_dir.to_path_buf(),
        namespace: namespace.clone(),
    })
}

/// `pib`'s root store and the context it is the root of: the store must
/// hold the key of an anchor of the held version. `work` says what is done
/// only on the root device, for the refusal on any other device (`devices
/// are revoked`).
pub fn root_device(pib: &FilePib, work: &str) -> Result<RootDevice, RootDeviceError> {
    let pib_dir = pib.root();
    let store = RootStore::open(pib)?.ok_or_else(|| RootDeviceError::NoRoot {
        pib: pib_dir.to_path_buf(),
        work: work.to_string(),
    })?;
    let (context, data) = held_context(pib_dir, store.namespace())?;
    if !store.holds_anchor_of(&context) {
        return Err(RootDeviceError::NoLongerRoot {
            key: store.key_name().clone(),
            namespace: store.namespace().clone(),
            version: context.version(),
        });
    }
    Ok(RootDevice {
        store,
        context,
        data,
    })
}

/// The namespace a recovery-kit command acts on when none is named: the one
/// the file kit `kit_file` recovers, else the only context `pib_dir` holds.
pub fn kit_namespace(kit_file: Option<&Path>, pib_dir: &Path) -> Result<Name, RootDeviceError> {
    if let Some(path) = kit_file {
        return Ok(FileKit::read(path)?.namespace);
    }
    let held: Vec<Name> = read_stored_contexts(pib_dir)?
        .into_iter()
        .filter_map(|(_, r)| r.ok().map(|(ctx, _)| ctx.namespace().clone()))
        .collect();
    match held.as_slice() {
        [one] => Ok(one.clone()),
        [] => Err(RootDeviceError::NoContext {
            pib: pib_dir.to_path_buf(),
        }),
        _ => Err(RootDeviceError::SeveralContexts {
            pib: pib_dir.to_path_buf(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::namespace::init_namespace_in_pib;
    use crate::root_store::NewRootStore;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[test]
    fn the_root_device_holds_an_anchor_of_the_held_context() {
        let dir = tempfile::tempdir().unwrap();
        let pib = FilePib::new(dir.path()).unwrap();
        let ns = n("/home/bob");
        let out = futures::executor::block_on(init_namespace_in_pib(
            &pib,
            &ns,
            "laptop",
            false,
            &NewRootStore::File,
        ))
        .unwrap();
        let root = root_device(&pib, "devices are revoked").unwrap();
        assert_eq!(root.context.namespace(), &ns);
        assert_eq!(root.data.raw(), out.init.context_data.raw());
        assert_eq!(kit_namespace(None, dir.path()).unwrap(), ns);

        // A device holding the context but no root store.
        let other = tempfile::tempdir().unwrap();
        let other_pib = FilePib::new(other.path()).unwrap();
        crate::persist_context(other.path(), &out.init.context, &out.init.context_data).unwrap();
        let refused = root_device(&other_pib, "devices are revoked")
            .err()
            .unwrap();
        assert!(
            matches!(refused, RootDeviceError::NoRoot { .. }),
            "{refused}"
        );
        assert!(
            refused
                .to_string()
                .contains("devices are revoked on the root device")
        );
    }

    #[test]
    fn a_pib_holding_no_or_several_contexts_names_no_namespace() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            kit_namespace(None, dir.path()),
            Err(RootDeviceError::NoContext { .. })
        ));
        assert!(matches!(
            held_context(dir.path(), &n("/home/bob")),
            Err(RootDeviceError::NotHeld { .. })
        ));
        for ns in ["/home/bob", "/home/alice"] {
            let init =
                crate::init_namespace(&ndn_security::SecurityManager::new(), &n(ns)).unwrap();
            crate::persist_context(dir.path(), &init.context, &init.context_data).unwrap();
        }
        assert!(matches!(
            kit_namespace(None, dir.path()),
            Err(RootDeviceError::SeveralContexts { .. })
        ));
    }
}
