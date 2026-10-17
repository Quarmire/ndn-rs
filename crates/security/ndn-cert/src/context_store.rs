//! On-disk store of the trust contexts a node holds, kept beside its PIB so
//! adoption survives restarts and every version the node held stays
//! available to the nodes behind it:
//!
//! ```text
//! <pib_root>/contexts/<hex(namespace URI)>.tc               # the newest version held
//! <pib_root>/contexts/<hex(namespace URI)>.versions/<N>.tc  # every version held, by version
//! ```
//!
//! Each file is the SIGNED context Data wire exactly as it was verified on
//! adoption. The newest file is what a node loads into its keyring at start
//! ([`load_persisted_contexts`]); it only ever moves forward
//! ([`persist_context`]). The version files are what the node serves by
//! exact name (`<ns>/32=trust-context/v=<N>`): a node still holding an
//! older version follows the namespace version by version when the newest
//! is not signed by an anchor of the version it holds — a recovery kit
//! installed a new root in between ([`crate::context_update`]). A store
//! written before version files were kept holds the newest file only; the
//! versions it holds from then on are kept.
//!
//! Loading and reading re-verify each file's signature against the anchors
//! that same file carries, and refuse a file stored under another
//! namespace's name (or another version's). That catches corruption and
//! misfiling (a truncated or bit-flipped file, a context copied under the
//! wrong name); it does not stop a deliberate edit, which can re-sign the
//! context under a substituted anchor of the same namespace. Tamper
//! resistance against local writers is out of this store's reach: write
//! access to the PIB directory already controls the node (its keys live
//! there), and any expected fingerprint stored beside the file — e.g. the
//! adopted anchor's — could be rewritten by the same writer.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use ndn_packet::{Data, Name};
use ndn_security::{Keyring, SignedTrustContext};
use ndn_trust_envelope::TrustEnvelope;

use crate::onboarding::{AdoptError, adopt_anchor_envelope, adopt_into, open_signed_context};

/// Directory (under the PIB root) holding adopted contexts.
pub const CONTEXTS_DIR: &str = "contexts";
/// File extension of a stored context.
pub const CONTEXT_FILE_EXT: &str = "tc";
/// Extension of the directory beside a namespace's newest file that holds
/// every version of it the node held.
pub const VERSIONS_DIR_EXT: &str = "versions";

/// Why a stored context could not be written or loaded.
#[derive(Debug, thiserror::Error)]
pub enum ContextStoreError {
    #[error("I/O on {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{path} is not a decodable NDN Data packet: {reason}")]
    BadData { path: PathBuf, reason: String },
    #[error("{path} holds the context for {namespace}, which is stored under another name")]
    Misfiled { path: PathBuf, namespace: String },
    #[error("{path} holds version {version}, which is stored under another version")]
    MisfiledVersion { path: PathBuf, version: u64 },
    #[error(transparent)]
    Adopt(#[from] AdoptError),
}

/// The hex of `namespace`'s URI: the file stem of its store entries.
fn namespace_stem(namespace: &Name) -> String {
    let uri = namespace.to_string();
    let mut stem = String::with_capacity(uri.len() * 2);
    for b in uri.as_bytes() {
        stem.push_str(&format!("{b:02x}"));
    }
    stem
}

/// `<pib_root>/contexts/<hex of the namespace URI>.tc`: the newest version
/// held.
pub fn context_file_path(pib_root: &Path, namespace: &Name) -> PathBuf {
    let stem = namespace_stem(namespace);
    pib_root
        .join(CONTEXTS_DIR)
        .join(format!("{stem}.{CONTEXT_FILE_EXT}"))
}

/// `<pib_root>/contexts/<hex of the namespace URI>.versions`: every version
/// held.
pub fn context_versions_dir(pib_root: &Path, namespace: &Name) -> PathBuf {
    let stem = namespace_stem(namespace);
    pib_root
        .join(CONTEXTS_DIR)
        .join(format!("{stem}.{VERSIONS_DIR_EXT}"))
}

/// `<pib_root>/contexts/<hex of the namespace URI>.versions/<version>.tc`.
pub fn context_version_path(pib_root: &Path, namespace: &Name, version: u64) -> PathBuf {
    context_versions_dir(pib_root, namespace).join(format!("{version}.{CONTEXT_FILE_EXT}"))
}

/// The version of the newest context stored for `namespace` under
/// `pib_root`, when that file verifies; a missing or damaged one counts as
/// none (it is replaced).
fn stored_newest_version(pib_root: &Path, namespace: &Name) -> Option<u64> {
    read_one(pib_root, &context_file_path(pib_root, namespace))
        .ok()
        .map(|(ctx, _)| ctx.version())
}

/// Keep `context_data` (the signed Data of `context`, version `N`) under
/// `pib_root`: as version `N` of its namespace, and as the namespace's
/// newest version unless a newer one is stored — the newest file only moves
/// forward, so storing the versions a node walked through, in any order,
/// never takes it back. Returns the newest file when this version is the
/// newest stored, else its version file. Each write is atomic (temp file +
/// rename) so a crash never leaves a truncated context, and owner-only like
/// the rest of the PIB (`ndn_security::secure_fs`).
pub fn persist_context(
    pib_root: &Path,
    context: &SignedTrustContext,
    context_data: &Data,
) -> Result<PathBuf, ContextStoreError> {
    let namespace = context.namespace();
    let io = |path: &Path| {
        let path = path.to_path_buf();
        move |source| ContextStoreError::Io { path, source }
    };
    let versions = context_versions_dir(pib_root, namespace);
    ndn_security::secure_fs::create_private_dir_all(&versions).map_err(io(&versions))?;
    let newest = context_file_path(pib_root, namespace);
    let is_newest =
        stored_newest_version(pib_root, namespace).is_none_or(|stored| stored <= context.version());
    if is_newest {
        ndn_security::secure_fs::write_private(&newest, context_data.raw()).map_err(io(&newest))?;
    }
    let version = context_version_path(pib_root, namespace, context.version());
    ndn_security::secure_fs::write_private(&version, context_data.raw()).map_err(io(&version))?;
    Ok(if is_newest { newest } else { version })
}

/// Forget everything stored for `namespace` under `pib_root`: its newest
/// file and every version (`ndn-fwd init --force` replacing a namespace
/// with a new root). Nothing stored is not an error.
pub fn remove_stored_context(pib_root: &Path, namespace: &Name) -> Result<(), ContextStoreError> {
    let io = |path: PathBuf| move |source| ContextStoreError::Io { path, source };
    let newest = context_file_path(pib_root, namespace);
    match std::fs::remove_file(&newest) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(io(newest)(e)),
        _ => {}
    }
    let versions = context_versions_dir(pib_root, namespace);
    match std::fs::remove_dir_all(&versions) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(io(versions)(e)),
        _ => Ok(()),
    }
}

/// Load every stored context under `pib_root` into `keyring`, re-verifying
/// each one. Returns one entry per `*.tc` file (sorted by path) with the
/// adopted context or why that file was refused; a missing store directory
/// yields an empty list.
pub fn load_persisted_contexts(
    pib_root: &Path,
    keyring: &Keyring,
) -> Result<Vec<(PathBuf, Result<Arc<SignedTrustContext>, ContextStoreError>)>, ContextStoreError> {
    Ok(read_stored_contexts(pib_root)?
        .into_iter()
        .map(|(path, stored)| {
            let result = stored.and_then(|(ctx, _data)| Ok(adopt_into(keyring, ctx)?));
            (path, result)
        })
        .collect())
}

/// Read and re-verify every stored context under `pib_root` without adopting
/// it: one entry per `*.tc` file (sorted by path) with the decoded context and
/// its signed Data exactly as stored, or why that file was refused. A missing
/// store directory yields an empty list. This is what a node publishes
/// (byte-identical Data, never re-signed).
pub fn read_stored_contexts(
    pib_root: &Path,
) -> Result<Vec<(PathBuf, Result<(SignedTrustContext, Data), ContextStoreError>)>, ContextStoreError>
{
    let dir = pib_root.join(CONTEXTS_DIR);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => return Err(ContextStoreError::Io { path: dir, source }),
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|ext| ext == CONTEXT_FILE_EXT))
        .collect();
    paths.sort();
    Ok(paths
        .into_iter()
        .map(|path| {
            let result = read_one(pib_root, &path);
            (path, result)
        })
        .collect())
}

/// The stored context of `namespace` under `pib_root`, re-verified as
/// [`read_stored_contexts`] does; `None` when none is stored.
pub fn read_stored_context(
    pib_root: &Path,
    namespace: &Name,
) -> Result<Option<(SignedTrustContext, Data)>, ContextStoreError> {
    let path = context_file_path(pib_root, namespace);
    if !path.exists() {
        return Ok(None);
    }
    read_one(pib_root, &path).map(Some)
}

/// Every version of `namespace` stored under `pib_root`, oldest first: the
/// decoded context and its signed Data exactly as stored, or why that file
/// was refused — re-verified as [`read_stored_contexts`] does, and refused
/// when it holds another namespace or another version than its file names.
/// Files whose name is no version are not the store's and are skipped; a
/// missing directory yields an empty list. What a node serves by exact name
/// so nodes behind it can follow the namespace version by version.
pub fn read_stored_versions(
    pib_root: &Path,
    namespace: &Name,
) -> Result<Vec<(PathBuf, Result<(SignedTrustContext, Data), ContextStoreError>)>, ContextStoreError>
{
    let dir = context_versions_dir(pib_root, namespace);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => return Err(ContextStoreError::Io { path: dir, source }),
    };
    let mut versions: Vec<(u64, PathBuf)> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|ext| ext == CONTEXT_FILE_EXT))
        .filter_map(|p| {
            let version = p.file_stem()?.to_str()?.parse::<u64>().ok()?;
            Some((version, p))
        })
        .collect();
    versions.sort();
    Ok(versions
        .into_iter()
        .map(|(version, path)| {
            let result = read_one_version(pib_root, namespace, version, &path);
            (path, result)
        })
        .collect())
}

fn read_verified(path: &Path) -> Result<(SignedTrustContext, Data), ContextStoreError> {
    let wire = std::fs::read(path).map_err(|source| ContextStoreError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let data = Data::decode(Bytes::from(wire)).map_err(|e| ContextStoreError::BadData {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })?;
    // Re-verify against the context's own anchors (the expected fingerprint
    // from the out-of-band link was checked on first adoption, continuity on
    // every update).
    let (ctx, _signer) = open_signed_context(&data)?;
    Ok((ctx, data))
}

fn read_one(
    pib_root: &Path,
    path: &Path,
) -> Result<(SignedTrustContext, Data), ContextStoreError> {
    let (ctx, data) = read_verified(path)?;
    // Check the file is stored under its own namespace *before* anyone
    // trusts or publishes it, so a context copied over another namespace's
    // file is refused.
    if context_file_path(pib_root, ctx.namespace()) != path {
        return Err(ContextStoreError::Misfiled {
            path: path.to_path_buf(),
            namespace: ctx.namespace().to_string(),
        });
    }
    Ok((ctx, data))
}

fn read_one_version(
    pib_root: &Path,
    namespace: &Name,
    version: u64,
    path: &Path,
) -> Result<(SignedTrustContext, Data), ContextStoreError> {
    let (ctx, data) = read_verified(path)?;
    if ctx.namespace() != namespace {
        return Err(ContextStoreError::Misfiled {
            path: path.to_path_buf(),
            namespace: ctx.namespace().to_string(),
        });
    }
    if ctx.version() != version || context_version_path(pib_root, namespace, version) != path {
        return Err(ContextStoreError::MisfiledVersion {
            path: path.to_path_buf(),
            version: ctx.version(),
        });
    }
    Ok((ctx, data))
}

/// `ndn-fwd adopt`'s one-shot: TOFU-adopt the context carried inline by an
/// anchor `envelope` and persist it under `pib_root`. Contexts already stored
/// there are loaded first, so anti-rollback holds across invocations (an
/// older version never replaces a newer stored one). Returns the adopted
/// context and the file it was written to.
pub fn adopt_envelope_into_store(
    pib_root: &Path,
    envelope: &TrustEnvelope,
) -> Result<(Arc<SignedTrustContext>, PathBuf), ContextStoreError> {
    let keyring = Keyring::new();
    // A stored file that no longer verifies must not block a fresh adoption;
    // it is simply replaced below.
    for (path, result) in load_persisted_contexts(pib_root, &keyring)? {
        if let Err(e) = result {
            tracing::warn!(path = %path.display(), error = %e, "ignoring unloadable stored trust context");
        }
    }
    let (ctx, data) = adopt_anchor_envelope(&keyring, envelope)?;
    let path = persist_context(pib_root, &ctx, &data)?;
    Ok((ctx, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_name_is_hex_of_the_namespace_uri() {
        let ns: Name = "/home/bob".parse().unwrap();
        assert_eq!(
            context_file_path(Path::new("/pib"), &ns),
            PathBuf::from("/pib/contexts/2f686f6d652f626f62.tc")
        );
    }

    #[test]
    fn missing_store_loads_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let keyring = Keyring::new();
        assert!(
            load_persisted_contexts(dir.path(), &keyring)
                .unwrap()
                .is_empty()
        );
        assert!(keyring.is_empty());
    }

    /// What a node publishes is exactly the stored signed Data; a damaged file
    /// is refused with a reason, not published.
    #[test]
    fn stored_context_reads_back_byte_identical_and_damage_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let ns: Name = "/home/bob".parse().unwrap();
        let root_dev = crate::namespace::init_namespace(&ndn_security::SecurityManager::new(), &ns).unwrap();
        let path = persist_context(dir.path(), &root_dev.context, &root_dev.context_data).unwrap();

        let stored = read_stored_contexts(dir.path()).unwrap();
        assert_eq!(stored.len(), 1);
        let (ctx, data) = stored[0].1.as_ref().unwrap();
        assert_eq!(data.raw(), root_dev.context_data.raw());
        assert_eq!(ctx.namespace(), &ns);

        let mut wire = root_dev.context_data.raw().to_vec();
        let last = wire.len() - 1;
        wire[last] ^= 0xff; // flip a signature byte
        std::fs::write(&path, &wire).unwrap();
        let stored = read_stored_contexts(dir.path()).unwrap();
        assert!(matches!(
            stored[0].1,
            Err(ContextStoreError::Adopt(AdoptError::BadSignature(_)))
        ));
        std::fs::write(&path, &wire[..wire.len() / 2]).unwrap();
        let stored = read_stored_contexts(dir.path()).unwrap();
        assert!(matches!(stored[0].1, Err(ContextStoreError::BadData { .. })));
    }

    /// Every version stored is kept by version, for nodes behind this one;
    /// the newest file only moves forward, so storing the versions a walk
    /// went through never takes a node back; a version file holding another
    /// version is refused; forgetting a namespace removes all of it.
    #[test]
    fn every_version_is_kept_and_the_newest_only_moves_forward() {
        let dir = tempfile::tempdir().unwrap();
        let ns: Name = "/home/bob".parse().unwrap();
        let mgr = ndn_security::SecurityManager::new();
        let root_dev = crate::namespace::init_namespace(&mgr, &ns).unwrap();
        let signer = mgr.get_signer_sync(&root_dev.anchor_key).unwrap();
        let content = root_dev.context.encode_content();
        let version = |v: u64| {
            let ctx = SignedTrustContext::decode_content(&content, v).unwrap();
            let data = ctx.sign_into_data(signer.as_ref()).unwrap();
            (ctx, data)
        };
        let (v1, v2, v3) = (version(1), version(2), version(3));
        for (ctx, data) in [&v1, &v3, &v2] {
            persist_context(dir.path(), ctx, data).unwrap();
        }
        let (newest, _) = read_stored_context(dir.path(), &ns).unwrap().unwrap();
        assert_eq!(newest.version(), 3);
        assert_eq!(read_stored_contexts(dir.path()).unwrap().len(), 1);
        let kept: Vec<u64> = read_stored_versions(dir.path(), &ns)
            .unwrap()
            .into_iter()
            .map(|(_, stored)| stored.unwrap().0.version())
            .collect();
        assert_eq!(kept, [1, 2, 3]);

        std::fs::copy(
            context_version_path(dir.path(), &ns, 2),
            context_version_path(dir.path(), &ns, 7),
        )
        .unwrap();
        let stored = read_stored_versions(dir.path(), &ns).unwrap();
        assert!(matches!(
            stored.last().unwrap().1,
            Err(ContextStoreError::MisfiledVersion { version: 2, .. })
        ));

        remove_stored_context(dir.path(), &ns).unwrap();
        assert!(read_stored_context(dir.path(), &ns).unwrap().is_none());
        assert!(read_stored_versions(dir.path(), &ns).unwrap().is_empty());
    }
}
