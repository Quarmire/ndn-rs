//! On-disk store of the trust contexts a node has adopted, kept beside its PIB
//! so adoption survives restarts:
//!
//! ```text
//! <pib_root>/contexts/<hex(namespace URI)>.tc   # the SIGNED context Data wire
//! ```
//!
//! Files hold exactly the Data that was verified on adoption. Loading
//! ([`load_persisted_contexts`]) re-verifies each file's signature against the
//! anchors that same file carries and refuses a file stored under another
//! namespace's name. That catches corruption and misfiling (a truncated or
//! bit-flipped file, a context copied under the wrong name); it does not stop
//! a deliberate edit, which can re-sign the context under a substituted
//! anchor of the same namespace. Tamper resistance against local writers is
//! out of this store's reach: write access to the PIB directory already
//! controls the node (its keys live there), and any expected fingerprint
//! stored beside the file — e.g. the adopted anchor's — could be rewritten by
//! the same writer.

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
    #[error(transparent)]
    Adopt(#[from] AdoptError),
}

/// `<pib_root>/contexts/<hex of the namespace URI>.tc`.
pub fn context_file_path(pib_root: &Path, namespace: &Name) -> PathBuf {
    let uri = namespace.to_string();
    let mut file = String::with_capacity(uri.len() * 2 + 1 + CONTEXT_FILE_EXT.len());
    for b in uri.as_bytes() {
        file.push_str(&format!("{b:02x}"));
    }
    file.push('.');
    file.push_str(CONTEXT_FILE_EXT);
    pib_root.join(CONTEXTS_DIR).join(file)
}

/// Persist `context_data` (the signed Data of `context`) under `pib_root`,
/// replacing any earlier version of the same namespace. The write is atomic
/// (temp file + rename) so a crash never leaves a truncated context, and
/// owner-only like the rest of the PIB (`ndn_security::secure_fs`).
pub fn persist_context(
    pib_root: &Path,
    context: &SignedTrustContext,
    context_data: &Data,
) -> Result<PathBuf, ContextStoreError> {
    let path = context_file_path(pib_root, context.namespace());
    let io = |path: &Path| {
        let path = path.to_path_buf();
        move |source| ContextStoreError::Io { path, source }
    };
    let dir = pib_root.join(CONTEXTS_DIR);
    ndn_security::secure_fs::create_private_dir_all(&dir).map_err(io(&dir))?;
    ndn_security::secure_fs::write_private(&path, context_data.raw()).map_err(io(&path))?;
    Ok(path)
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

fn read_one(
    pib_root: &Path,
    path: &Path,
) -> Result<(SignedTrustContext, Data), ContextStoreError> {
    let wire = std::fs::read(path).map_err(|source| ContextStoreError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let data = Data::decode(Bytes::from(wire)).map_err(|e| ContextStoreError::BadData {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })?;
    // Re-verify against the context's own anchors (the expected fingerprint
    // from the out-of-band link was checked on first adoption), and check the
    // file is stored under its own namespace *before* anyone trusts or
    // publishes it, so a context copied over another namespace's file is
    // refused.
    let (ctx, _signer) = open_signed_context(&data)?;
    if context_file_path(pib_root, ctx.namespace()) != path {
        return Err(ContextStoreError::Misfiled {
            path: path.to_path_buf(),
            namespace: ctx.namespace().to_string(),
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
}
