//! Named Cloudflare tunnel provider.
//!
//! Unlike [`CloudflareQuickTunnel`] (which gets a fresh `*.trycloudflare.com`
//! URL on every restart) a named tunnel has a persistent hostname the
//! operator owns — a real domain routed via Cloudflare's tunnel ingress
//! configuration. The public URL does NOT come from `cloudflared` stdout:
//! the operator has already configured it server-side and passes it into
//! the provider at construction time.
//!
//! Transport model:
//! - `cloudflared tunnel --url http://127.0.0.1:<port> run --token <token>`
//! - `start()` spawns the child and waits until the configured public URL
//!   answers a probe — this mirrors the readiness handshake the
//!   control plane does for the quick-tunnel case.
//! - `stop()` kills the child.
//!
//! The token is expected to come from an environment variable or the
//! operator's orchestration layer — we never log or serialize it.

use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout};

use crate::{
    cloudflare::CANDIDATE_PATHS,
    provider::{TunnelProvider, TunnelStatus},
    TunnelError, TunnelResult,
};

const DEFAULT_READY_TIMEOUT: Duration = Duration::from_secs(60);
const PROBE_INTERVAL: Duration = Duration::from_secs(2);
const PROBE_HTTP_TIMEOUT: Duration = Duration::from_secs(5);

/// Persistent Cloudflare tunnel wired to a pre-configured public
/// hostname. The token + URL are supplied by the operator; we only
/// orchestrate the child process.
pub struct NamedCloudflareTunnel {
    tunnel_token: String,
    public_url: String,
    binary_path: Option<String>,
    ready_timeout: Duration,
    child: Option<Child>,
    status: TunnelStatus,
    cached_url: Option<String>,
}

impl NamedCloudflareTunnel {
    pub fn new(tunnel_token: impl Into<String>, public_url: impl Into<String>) -> Self {
        Self {
            tunnel_token: tunnel_token.into(),
            public_url: public_url.into(),
            binary_path: None,
            ready_timeout: DEFAULT_READY_TIMEOUT,
            child: None,
            status: TunnelStatus::Disconnected {
                reason: "not started".into(),
            },
            cached_url: None,
        }
    }

    /// Override the `cloudflared` binary path — useful for pinning a
    /// specific version or for test harnesses that want to point at a
    /// mock.
    pub fn with_binary_path(mut self, path: impl Into<String>) -> Self {
        self.binary_path = Some(path.into());
        self
    }

    /// Tighten or loosen the ready-probe budget. Default: 60s.
    pub fn with_ready_timeout(mut self, timeout: Duration) -> Self {
        self.ready_timeout = timeout;
        self
    }

    pub fn is_alive(&mut self) -> bool {
        let Some(child) = self.child.as_mut() else {
            return false;
        };
        match child.try_wait() {
            Ok(Some(_)) => {
                self.status = TunnelStatus::Disconnected {
                    reason: "process exited".into(),
                };
                self.cached_url = None;
                false
            }
            Ok(None) => true,
            Err(_) => false,
        }
    }

    fn resolve_binary(&self) -> TunnelResult<String> {
        if let Some(p) = &self.binary_path {
            return Ok(p.clone());
        }
        for path in CANDIDATE_PATHS {
            let exists = std::process::Command::new(path)
                .arg("--version")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok();
            if exists {
                return Ok((*path).to_string());
            }
        }
        Err(TunnelError::CloudflaredNotFound {
            tried: CANDIDATE_PATHS.iter().map(|p| (*p).to_string()).collect(),
        })
    }

    async fn probe_until_ready(&self) -> TunnelResult<()> {
        let healthz = format!("{}/healthz", self.public_url.trim_end_matches('/'));
        let client = reqwest::Client::builder()
            .timeout(PROBE_HTTP_TIMEOUT)
            .build()
            .map_err(|e| TunnelError::Other(format!("reqwest build: {e}")))?;
        let poll = async {
            loop {
                match client.get(&healthz).send().await {
                    Ok(r) if r.status().is_success() => return Ok(()),
                    Ok(r) => {
                        tracing::debug!(target: "aex_tunnel::named", status = %r.status(), "named tunnel not ready");
                    }
                    Err(e) => {
                        tracing::debug!(target: "aex_tunnel::named", error = %e, "named tunnel probe error");
                    }
                }
                sleep(PROBE_INTERVAL).await;
            }
        };
        timeout(self.ready_timeout, poll)
            .await
            .map_err(|_| TunnelError::UrlTimeout {
                secs: self.ready_timeout.as_secs(),
            })?
    }
}

#[async_trait]
impl TunnelProvider for NamedCloudflareTunnel {
    async fn start(&mut self, local_port: u16) -> TunnelResult<()> {
        if self.child.is_some() {
            return Err(TunnelError::AlreadyRunning);
        }
        self.status = TunnelStatus::Connecting;
        let binary = match self.resolve_binary() {
            Ok(b) => b,
            Err(e) => {
                self.status = TunnelStatus::Disconnected {
                    reason: e.to_string(),
                };
                return Err(e);
            }
        };

        let child = Command::new(&binary)
            .args([
                "tunnel",
                "--url",
                &format!("http://127.0.0.1:{}", local_port),
                "--no-autoupdate",
                "run",
                "--token",
                &self.tunnel_token,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn();
        let child = match child {
            Ok(c) => c,
            Err(e) => {
                self.status = TunnelStatus::Disconnected {
                    reason: format!("spawn: {e}"),
                };
                return Err(TunnelError::Spawn(e));
            }
        };
        self.child = Some(child);

        if let Err(e) = self.probe_until_ready().await {
            self.status = TunnelStatus::Disconnected {
                reason: e.to_string(),
            };
            if let Some(mut c) = self.child.take() {
                let _ = c.kill().await;
            }
            return Err(e);
        }

        self.cached_url = Some(self.public_url.clone());
        self.status = TunnelStatus::Connected {
            url: self.public_url.clone(),
        };
        Ok(())
    }

    async fn stop(&mut self) -> TunnelResult<()> {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill().await;
        }
        self.cached_url = None;
        self.status = TunnelStatus::Disconnected {
            reason: "stopped".into(),
        };
        Ok(())
    }

    fn public_url(&self) -> Option<String> {
        self.cached_url.clone()
    }

    fn status(&self) -> TunnelStatus {
        self.status.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_overrides_applied() {
        let t = NamedCloudflareTunnel::new("tok", "https://files.example.com")
            .with_ready_timeout(Duration::from_secs(3))
            .with_binary_path("/opt/cloudflared");
        assert_eq!(t.ready_timeout, Duration::from_secs(3));
        assert_eq!(t.binary_path.as_deref(), Some("/opt/cloudflared"));
        assert_eq!(t.public_url, "https://files.example.com");
    }

    #[tokio::test]
    async fn stop_without_start_is_noop() {
        let mut t = NamedCloudflareTunnel::new("tok", "https://files.example.com");
        t.stop().await.unwrap();
        assert!(t.public_url().is_none());
        assert!(matches!(t.status(), TunnelStatus::Disconnected { .. }));
    }

    #[test]
    fn resolve_binary_honors_override() {
        let t = NamedCloudflareTunnel::new("tok", "https://files.example.com")
            .with_binary_path("/nonexistent/cloudflared");
        assert_eq!(t.resolve_binary().unwrap(), "/nonexistent/cloudflared");
    }
}
