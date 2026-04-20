//! Control-plane signing key.
//!
//! The control plane owns an Ed25519 keypair used to sign data-plane
//! tickets (Phase D2) and, eventually, org-root identity chain entries.
//! Callers go through [`ControlPlaneSigner`] rather than touching the
//! raw key — this is where key rotation + HSM-backing plug in later.
//!
//! # Storage
//!
//! For now the key is persisted to disk at `SIGNING_KEY_PATH` (default
//! `./data/signing-key.bin`, 32 raw bytes, 0600). If the file is
//! missing on startup, a fresh key is generated and written. For
//! production we plan:
//!
//! - Encrypted-at-rest secret via KMS / Vault (Phase 2).
//! - HSM-backed signer for enterprise deployments.
//! - Scheduled rotation with a "previous" key retained for rolling
//!   ticket validation.

use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignerError {
    #[error("I/O error loading signing key: {0}")]
    Io(#[from] std::io::Error),

    #[error("signing key file is {0} bytes, expected 32")]
    BadLength(usize),
}

pub struct ControlPlaneSigner {
    key: SigningKey,
    path: PathBuf,
}

impl std::fmt::Debug for ControlPlaneSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlPlaneSigner")
            .field("public_key_hex", &self.public_key_hex())
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl ControlPlaneSigner {
    /// Load the key at `path`, or generate + persist one if the file
    /// does not exist. Parent directories are created as needed.
    pub async fn load_or_generate(path: impl Into<PathBuf>) -> Result<Self, SignerError> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                tokio::fs::create_dir_all(parent).await?;
            }
        }
        match tokio::fs::read(&path).await {
            Ok(bytes) => {
                if bytes.len() != 32 {
                    return Err(SignerError::BadLength(bytes.len()));
                }
                let arr: [u8; 32] = bytes.as_slice().try_into().expect("len checked");
                Ok(Self {
                    key: SigningKey::from_bytes(&arr),
                    path,
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let key = SigningKey::generate(&mut rand::rngs::OsRng);
                Self::persist(&path, &key).await?;
                Ok(Self { key, path })
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn persist(path: &Path, key: &SigningKey) -> std::io::Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        let tmp = path.with_extension("tmp");
        let mut options = std::fs::OpenOptions::new();
        options
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600);
        // tokio::fs doesn't expose OpenOptionsExt directly; use std then convert.
        let f = options.open(&tmp)?;
        drop(f);
        tokio::fs::write(&tmp, key.to_bytes()).await?;
        tokio::fs::rename(&tmp, path).await?;
        Ok(())
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.key.verifying_key().to_bytes())
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.key.sign(message).to_bytes().to_vec()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn generates_on_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signing-key.bin");
        assert!(!path.exists());
        let signer = ControlPlaneSigner::load_or_generate(&path).await.unwrap();
        assert!(path.exists());
        assert_eq!(signer.public_key_hex().len(), 64);
    }

    #[tokio::test]
    async fn reloads_existing_file_deterministically() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signing-key.bin");
        let first = ControlPlaneSigner::load_or_generate(&path).await.unwrap();
        let second = ControlPlaneSigner::load_or_generate(&path).await.unwrap();
        assert_eq!(first.public_key_hex(), second.public_key_hex());
    }

    #[tokio::test]
    async fn bad_length_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signing-key.bin");
        tokio::fs::write(&path, b"short").await.unwrap();
        let err = ControlPlaneSigner::load_or_generate(&path).await.unwrap_err();
        assert!(matches!(err, SignerError::BadLength(5)));
    }

    #[tokio::test]
    async fn sign_produces_64_byte_signature() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signing-key.bin");
        let signer = ControlPlaneSigner::load_or_generate(&path).await.unwrap();
        let sig = signer.sign(b"hello");
        assert_eq!(sig.len(), 64);
    }
}
