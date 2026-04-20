//! Test stub: pretends to be a tunnel without starting any process.

use async_trait::async_trait;

use crate::{
    provider::{TunnelProvider, TunnelStatus},
    TunnelResult,
};

pub struct StubTunnel {
    configured_url: String,
    status: TunnelStatus,
    public_url: Option<String>,
}

impl StubTunnel {
    pub fn new(configured_url: impl Into<String>) -> Self {
        Self {
            configured_url: configured_url.into(),
            status: TunnelStatus::Disconnected {
                reason: "not started".into(),
            },
            public_url: None,
        }
    }
}

#[async_trait]
impl TunnelProvider for StubTunnel {
    async fn start(&mut self, _local_port: u16) -> TunnelResult<()> {
        self.public_url = Some(self.configured_url.clone());
        self.status = TunnelStatus::Connected {
            url: self.configured_url.clone(),
        };
        Ok(())
    }

    async fn stop(&mut self) -> TunnelResult<()> {
        self.public_url = None;
        self.status = TunnelStatus::Disconnected {
            reason: "stopped".into(),
        };
        Ok(())
    }

    fn public_url(&self) -> Option<String> {
        self.public_url.clone()
    }

    fn status(&self) -> TunnelStatus {
        self.status.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn start_then_stop() {
        let mut t = StubTunnel::new("https://stub.trycloudflare.com");
        assert!(t.public_url().is_none());
        t.start(8080).await.unwrap();
        assert_eq!(
            t.public_url().as_deref(),
            Some("https://stub.trycloudflare.com")
        );
        assert!(matches!(t.status(), TunnelStatus::Connected { .. }));
        t.stop().await.unwrap();
        assert!(t.public_url().is_none());
    }
}
