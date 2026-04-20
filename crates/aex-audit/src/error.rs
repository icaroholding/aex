use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("chain broken at position {position}: expected prev_hash {expected}, found {found}")]
    ChainBroken {
        position: u64,
        expected: String,
        found: String,
    },

    #[error("hash mismatch at position {position}: stored {stored}, recomputed {recomputed}")]
    HashMismatch {
        position: u64,
        stored: String,
        recomputed: String,
    },

    #[error("invalid event: {0}")]
    InvalidEvent(String),
}

pub type AuditResult<T> = Result<T, AuditError>;
