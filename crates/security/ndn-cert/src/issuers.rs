//! The issuer certificates of a node's own certificates, kept beside its PIB.
//!
//! A certificate is only as good as its chain: a validator follows its
//! KeyLocator to the issuing CA's certificate, and on to the namespace root.
//! The namespace CA normally serves its own certificate. When the root device
//! that ran the CA is replaced through a recovery kit, the new root device
//! runs a new CA key under the same CA identity (`<ns>/CA/KEY/<fresh id>`);
//! the certificates the earlier CA issued keep validating (its root stays an
//! anchor of the trust context), but the earlier CA's certificate lived on
//! the lost device and nobody serves it any more.
//!
//! So a node keeps the issuer certificates of each certificate it is issued,
//! as they were fetched to check its chain
//! ([`IssuedCertificate::issuers`](crate::IssuedCertificate::issuers)). It
//! serves them beside its own certificates, which lets validators — and its
//! own renewal walk — resolve the chain, and it sends them with a renewal
//! ([`crate::renewal`]): a CA that did not issue the certificate verifies the
//! chain with them under the trust context it holds, then serves the earlier
//! CA's certificate itself.
//!
//! Layout: `<pib>/issuers/<lowercase hex SHA-256 of the certificate name's
//! TLV encoding>.data`, each the signed certificate Data, owner-only
//! ([`ndn_security::secure_fs`]). A certificate kept again overwrites its
//! entry with the same bytes.

use std::path::{Path, PathBuf};

use bytes::Bytes;
use ndn_packet::Data;
use ndn_security::{Certificate, secure_fs};

/// The directory under the PIB root that holds the kept issuer certificates.
pub const ISSUERS_DIR: &str = "issuers";

/// Keep `certs` — issuer certificate Data of this node's certificates — under
/// `<pib_root>/issuers`, owner-only. Data that is not a certificate is
/// skipped. Returns the path of each certificate written.
pub fn keep_issuer_certs(pib_root: &Path, certs: &[Data]) -> std::io::Result<Vec<PathBuf>> {
    let dir = pib_root.join(ISSUERS_DIR);
    let mut written = Vec::new();
    for data in certs {
        let Ok(cert) = Certificate::decode(data) else {
            continue;
        };
        if written.is_empty() {
            secure_fs::create_private_dir_all(&dir)?;
        }
        let path = dir.join(format!("{}.data", name_hash(&cert)));
        secure_fs::write_private(&path, data.raw())?;
        written.push(path);
    }
    Ok(written)
}

/// The issuer certificates kept under `<pib_root>/issuers`, as signed Data
/// wires. A missing directory holds none; an unreadable entry is skipped.
pub fn stored_issuer_certs(pib_root: &Path) -> Vec<Bytes> {
    let Ok(entries) = std::fs::read_dir(pib_root.join(ISSUERS_DIR)) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("data"))
        .filter_map(|path| std::fs::read(path).ok())
        .map(Bytes::from)
        .collect()
}

/// Lowercase hex SHA-256 of `cert`'s name TLV.
fn name_hash(cert: &Certificate) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(cert.name.encode_to_tlv())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use ndn_security::SecurityManager;

    /// A certificate kept is read back byte for byte, owner-only; Data that
    /// is not a certificate is not kept.
    #[test]
    fn kept_certificates_read_back_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = SecurityManager::new();
        let key: ndn_packet::Name = "/home/bob/CA/KEY/ca".parse().unwrap();
        mgr.generate_ed25519(key.clone()).unwrap();
        let pk = mgr.get_signer_sync(&key).unwrap().public_key().unwrap();
        let cert = mgr.issue_self_signed(&key, pk, 86_400_000).unwrap();
        let wire = cert.data_wire().unwrap();
        // Empty content: no public key, so not a certificate.
        let other: ndn_packet::Name = "/home/bob/x".parse().unwrap();
        let not_a_cert =
            Data::decode(ndn_packet::encode::DataBuilder::new(other, b"").sign_digest_sha256())
                .unwrap();

        let written = keep_issuer_certs(
            dir.path(),
            &[Data::decode(wire.clone()).unwrap(), not_a_cert],
        )
        .unwrap();
        assert_eq!(written.len(), 1);
        assert_eq!(stored_issuer_certs(dir.path()), vec![wire]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&written[0]).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "owner-only");
        }
        assert!(stored_issuer_certs(&dir.path().join("none")).is_empty());
    }
}
