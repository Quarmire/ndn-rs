//! Plaintext PEM cert + key cached on disk under `cache_dir/`.

use std::path::{Path, PathBuf};

use tokio::fs;

#[derive(Debug, Clone)]
pub struct CertCache {
    dir: PathBuf,
}

impl CertCache {
    pub async fn open(dir: impl AsRef<Path>) -> std::io::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir).await?;
        Ok(Self { dir })
    }

    fn cert_path(&self, domain: &str) -> PathBuf {
        self.dir.join(format!("{domain}.cert.pem"))
    }
    fn key_path(&self, domain: &str) -> PathBuf {
        self.dir.join(format!("{domain}.key.pem"))
    }

    pub async fn load(&self, domain: &str) -> Option<(Vec<u8>, Vec<u8>)> {
        let cert = fs::read(self.cert_path(domain)).await.ok()?;
        let key = fs::read(self.key_path(domain)).await.ok()?;
        Some((cert, key))
    }

    pub async fn store(
        &self,
        domain: &str,
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> std::io::Result<()> {
        fs::write(self.cert_path(domain), cert_pem).await?;
        fs::write(self.key_path(domain), key_pem).await?;
        Ok(())
    }
}
