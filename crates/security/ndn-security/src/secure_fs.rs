//! Owner-only filesystem helpers for secret material (private keys, CA state,
//! tokens).
//!
//! The rule every key store in the workspace follows:
//!
//! - directories holding secrets are created `0700`;
//! - secret files are created with their final mode (`0600`, or `0400` where
//!   ndn-cxx expects it) *before* the first byte is written — written to a
//!   sibling temp file opened with that mode, then renamed into place — so a
//!   secret is never readable by group/other, not even briefly, and a
//!   reader never sees a partial file;
//! - opening an existing store tightens group/other-accessible entries back
//!   to owner-only (logging what was changed) and refuses entries owned by a
//!   different user.
//!
//! # Non-unix targets
//!
//! Unix permission bits do not exist on Windows (or wasm). There these helpers
//! fall back to plain create/write/rename: files inherit the ACL of their parent
//! directory — on Windows, a directory under the user's profile is accessible only
//! to that user, SYSTEM and Administrators — and the repair/ownership checks are
//! no-ops. Keep key stores under the user's profile on those platforms.

use std::io::{self, Write};
use std::path::Path;

/// Mode for secret files and everything else in an owner-only store.
pub const PRIVATE_FILE_MODE: u32 = 0o600;
/// Mode for directories holding secrets.
pub const PRIVATE_DIR_MODE: u32 = 0o700;

/// `create_dir_all`, creating every missing component `0700`. An existing
/// `path` is tightened to `0700` if group/other could access it.
pub fn create_private_dir_all(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(PRIVATE_DIR_MODE)
            .create(path)?;
        tighten(path)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)
    }
}

/// Write `contents` to `path` as an owner-only (`0600`) file. See
/// [`write_private_with_mode`].
pub fn write_private(path: &Path, contents: impl AsRef<[u8]>) -> io::Result<()> {
    write_private_with_mode(path, contents.as_ref(), PRIVATE_FILE_MODE)
}

/// Atomically replace `path` with `contents`, the file carrying `mode` from
/// creation: a temp file in the same directory is created with `mode`
/// (`O_CREAT|O_EXCL`, so umask can only narrow it), written, synced and
/// renamed over `path`. `mode` must not grant group/other access.
pub fn write_private_with_mode(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    debug_assert_eq!(mode & 0o077, 0, "secret file mode must be owner-only");
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    // Unique temp name: pid + counter, retried on collision with a stale file.
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let (tmp, mut file) = loop {
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut tmp_name = std::ffi::OsString::from(".");
        tmp_name.push(file_name);
        tmp_name.push(format!(".{}.{n}.tmp", std::process::id()));
        let tmp = dir.join(tmp_name);
        match opts.open(&tmp) {
            Ok(f) => break (tmp, f),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    };
    let result = file
        .write_all(contents)
        .and_then(|()| file.sync_all())
        .and_then(|()| std::fs::rename(&tmp, path));
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Remove the secret file `path` after overwriting its contents with zeros
/// and syncing, so the old bytes are not left in the freed blocks of a
/// filesystem that rewrites in place (ext4, xfs). Copy-on-write and
/// log-structured filesystems (btrfs, zfs, f2fs) and SSD wear levelling may
/// still keep an old copy: keeping a secret off such a disk takes full-disk
/// encryption. A missing `path` is not an error.
pub fn shred_file(path: &Path) -> io::Result<()> {
    let len = match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_file() => meta.len(),
        Ok(_) => return Err(io::Error::other(format!("{} is not a file", path.display()))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    {
        let mut file = std::fs::OpenOptions::new().write(true).open(path)?;
        let zeros = [0u8; 4096];
        let mut left = len;
        while left > 0 {
            let n = left.min(zeros.len() as u64) as usize;
            file.write_all(&zeros[..n])?;
            left -= n as u64;
        }
        file.sync_all()?;
    }
    std::fs::remove_file(path)
}

/// Tighten `path` to owner-only if group/other has any access (`0700` for a
/// directory, `0600` for a file, keeping a stricter owner mode like `0400`).
/// Returns the previous mode when it changed. Refuses (`PermissionDenied`) an
/// entry owned by another user — trusting someone else's key file would let
/// them choose our key. A symlinked `path` is resolved (the store's root may
/// live elsewhere); [`repair_tree`] refuses symlinks *inside* a store. No-op on
/// non-unix targets.
pub fn tighten(path: &Path) -> io::Result<Option<u32>> {
    #[cfg(unix)]
    {
        tighten_for(path, &std::fs::metadata(path)?, euid())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(None)
    }
}

/// The effective uid, against which store entries' owners are checked.
#[cfg(unix)]
#[allow(unsafe_code)]
fn euid() -> u32 {
    // SAFETY: geteuid takes no arguments, has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

#[cfg(unix)]
fn tighten_for(path: &Path, meta: &std::fs::Metadata, euid: u32) -> io::Result<Option<u32>> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if meta.uid() != euid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is owned by uid {}, not by this user (uid {euid}); refusing to use \
                 secret material another user controls — fix its ownership or remove it",
                path.display(),
                meta.uid()
            ),
        ));
    }
    let mode = meta.mode() & 0o7777;
    if mode & 0o077 == 0 {
        return Ok(None);
    }
    let owner = if meta.is_dir() { PRIVATE_DIR_MODE } else { mode & 0o700 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(owner))?;
    Ok(Some(mode))
}

/// [`tighten`] `root` and everything beneath it, logging a warning for each
/// entry whose permissions were narrowed. Fails on the first entry owned by
/// another user, and on a symlink below `root` (a store holds only plain files
/// and directories; following a link could chmod, or trust, files elsewhere).
/// No-op on non-unix targets.
pub fn repair_tree(root: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        repair_entry(root, &std::fs::metadata(root)?, euid())
    }
    #[cfg(not(unix))]
    {
        let _ = root;
        Ok(())
    }
}

#[cfg(unix)]
fn repair_entry(path: &Path, meta: &std::fs::Metadata, euid: u32) -> io::Result<()> {
    if let Some(old) = tighten_for(path, meta, euid)? {
        warn_tightened(path, old);
    }
    if !meta.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(path)? {
        let child = entry?.path();
        let child_meta = std::fs::symlink_metadata(&child)?;
        if child_meta.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{} is a symlink; refusing to use it inside a private key store",
                    child.display()
                ),
            ));
        }
        repair_entry(&child, &child_meta, euid)?;
    }
    Ok(())
}

#[cfg(unix)]
fn warn_tightened(path: &Path, old: u32) {
    tracing::warn!(
        path = %path.display(),
        "tightened permissions on private key store entry from {old:04o} to owner-only \
         (group/other could read it)"
    );
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn write_private_is_owner_only_and_replaces_readonly() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("k");
        write_private_with_mode(&p, b"a", 0o400).unwrap();
        assert_eq!(mode(&p), 0o400);
        write_private_with_mode(&p, b"b", 0o400).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"b");
        let d = dir.path().join("x/y");
        create_private_dir_all(&d).unwrap();
        assert_eq!(mode(&d), 0o700);
        assert_eq!(mode(&dir.path().join("x")), 0o700);
    }

    #[test]
    fn repair_tree_tightens() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("s");
        std::fs::create_dir(&sub).unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o755)).unwrap();
        let f = sub.join("f");
        std::fs::write(&f, b"x").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        repair_tree(dir.path()).unwrap();
        assert_eq!(mode(&sub), 0o700);
        assert_eq!(mode(&f), 0o600);
    }

    #[test]
    fn foreign_owned_entry_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("private.pkcs8.der");
        write_private(&f, b"x").unwrap();
        let meta = std::fs::metadata(&f).unwrap();
        let other = euid().wrapping_add(1);
        let err = repair_entry(&f, &meta, other).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("owned by uid"));
    }
}
