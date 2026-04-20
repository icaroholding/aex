use thiserror::Error;

/// Top-level error type for the Agent Exchange Protocol (AEX) core.
///
/// Each variant names a specific failure mode. We avoid catch-all variants
/// (`StandardError`, `anyhow::Error`) because the control plane needs to
/// map errors to HTTP responses, audit events, and user-facing messages —
/// and those mappings depend on knowing exactly what went wrong.
#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid agent_id: {0}")]
    InvalidAgentId(String),

    #[error("unknown identity scheme")]
    UnknownIdentityScheme,

    #[error("signature verification failed")]
    SignatureInvalid,

    #[error("signature format invalid: {0}")]
    SignatureFormat(String),

    #[error("key unavailable: {0}")]
    KeyUnavailable(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, Error>;
