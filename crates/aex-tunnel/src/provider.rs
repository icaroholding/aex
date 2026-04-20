use async_trait::async_trait;
use serde::Serialize;

use crate::TunnelResult;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TunnelStatus {
    Disconnected { reason: String },
    Connecting,
    Reconnecting { attempt: u32 },
    Connected { url: String },
}

#[async_trait]
pub trait TunnelProvider: Send + Sync {
    /// Start the tunnel pointing at `local_port` on 127.0.0.1. Resolves
    /// once the public URL is known, or with an error on timeout.
    async fn start(&mut self, local_port: u16) -> TunnelResult<()>;

    /// Stop the tunnel. Idempotent.
    async fn stop(&mut self) -> TunnelResult<()>;

    /// The public URL if the tunnel is currently connected.
    fn public_url(&self) -> Option<String>;

    /// Current status.
    fn status(&self) -> TunnelStatus;
}
