//! Blob storage abstraction.
//!
//! In M1 the control plane holds uploaded bytes long enough to scan them
//! and serve them to the recipient. From Phase D onwards, bytes flow
//! through the Cloudflare-backed data plane and this trait is only used
//! by tests + the in-process audit replay.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;

#[async_trait]
pub trait BlobStore: Send + Sync {
    async fn put(&self, transfer_id: &str, bytes: &[u8]) -> io::Result<()>;
    async fn get(&self, transfer_id: &str) -> io::Result<Vec<u8>>;
    async fn delete(&self, transfer_id: &str) -> io::Result<()>;
    async fn exists(&self, transfer_id: &str) -> bool;
}

/// On-disk blob store. Used by the control plane binary. Files are written
/// atomically (tmp + rename) so an aborted request never leaves a partial
/// blob readable.
pub struct FileBlobStore {
    root: PathBuf,
}

impl FileBlobStore {
    pub async fn new(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        tokio::fs::create_dir_all(&root).await?;
        Ok(Self { root })
    }

    fn path_for(&self, transfer_id: &str) -> PathBuf {
        // transfer_ids are `tx_<hex>`. Sanitize by replacing any unexpected
        // char just in case; the id is already validated upstream.
        let safe: String = transfer_id
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
            .collect();
        self.root.join(safe)
    }
}

#[async_trait]
impl BlobStore for FileBlobStore {
    async fn put(&self, transfer_id: &str, bytes: &[u8]) -> io::Result<()> {
        let target = self.path_for(transfer_id);
        let tmp = target.with_extension("tmp");
        {
            let mut f = tokio::fs::File::create(&tmp).await?;
            f.write_all(bytes).await?;
            f.flush().await?;
            f.sync_all().await?;
        }
        // Blob may contain pending transfer content the recipient hasn't
        // read yet. On shared hosts we want 0600 so only the server user
        // (not other local processes) can read mid-flight bytes.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).await?;
        }
        tokio::fs::rename(&tmp, &target).await
    }

    async fn get(&self, transfer_id: &str) -> io::Result<Vec<u8>> {
        tokio::fs::read(self.path_for(transfer_id)).await
    }

    async fn delete(&self, transfer_id: &str) -> io::Result<()> {
        let path = self.path_for(transfer_id);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    async fn exists(&self, transfer_id: &str) -> bool {
        Path::exists(&self.path_for(transfer_id))
    }
}

/// In-memory blob store used by integration tests so a test fixture can
/// run without touching disk.
#[derive(Default)]
pub struct MemoryBlobStore {
    inner: Arc<RwLock<std::collections::HashMap<String, Vec<u8>>>>,
}

impl MemoryBlobStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl BlobStore for MemoryBlobStore {
    async fn put(&self, transfer_id: &str, bytes: &[u8]) -> io::Result<()> {
        self.inner
            .write()
            .await
            .insert(transfer_id.to_string(), bytes.to_vec());
        Ok(())
    }

    async fn get(&self, transfer_id: &str) -> io::Result<Vec<u8>> {
        self.inner
            .read()
            .await
            .get(transfer_id)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "blob not found"))
    }

    async fn delete(&self, transfer_id: &str) -> io::Result<()> {
        self.inner.write().await.remove(transfer_id);
        Ok(())
    }

    async fn exists(&self, transfer_id: &str) -> bool {
        self.inner.read().await.contains_key(transfer_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_put_get_roundtrip() {
        let s = MemoryBlobStore::new();
        s.put("tx_1", b"hello").await.unwrap();
        assert_eq!(s.get("tx_1").await.unwrap(), b"hello");
        assert!(s.exists("tx_1").await);
    }

    #[tokio::test]
    async fn memory_delete_missing_ok() {
        let s = MemoryBlobStore::new();
        s.delete("tx_missing").await.unwrap();
    }

    #[tokio::test]
    async fn file_store_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let s = FileBlobStore::new(dir.path()).await.unwrap();
        s.put("tx_1", b"hello").await.unwrap();
        assert_eq!(s.get("tx_1").await.unwrap(), b"hello");
        s.delete("tx_1").await.unwrap();
        assert!(!s.exists("tx_1").await);
    }
}
