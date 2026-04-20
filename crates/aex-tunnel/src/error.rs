use thiserror::Error;

#[derive(Debug, Error)]
pub enum TunnelError {
    #[error("cloudflared binary not found: tried {tried:?}")]
    CloudflaredNotFound { tried: Vec<String> },

    #[error("cloudflared failed to start: {0}")]
    Spawn(#[from] std::io::Error),

    #[error("timed out after {secs}s waiting for tunnel URL")]
    UrlTimeout { secs: u64 },

    #[error("tunnel URL channel closed before URL was observed")]
    ChannelClosed,

    #[error("tunnel is already running")]
    AlreadyRunning,

    #[error("{0}")]
    Other(String),
}

pub type TunnelResult<T> = Result<T, TunnelError>;
