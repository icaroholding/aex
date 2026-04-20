//! `cloudflared tunnel --url …` wrapper.
//!
//! Spawns the external `cloudflared` process, scrapes stderr for the
//! public URL, and owns the child handle until the caller stops it.
//! Kill-on-drop is enabled so a panicked caller doesn't leak a running
//! cloudflared.

use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::watch;
use tokio::time::timeout;

use crate::{
    provider::{TunnelProvider, TunnelStatus},
    url_parser::extract_tunnel_url,
    TunnelError, TunnelResult,
};

const URL_TIMEOUT: Duration = Duration::from_secs(30);

const CANDIDATE_PATHS: &[&str] = &[
    "cloudflared",
    "/opt/homebrew/bin/cloudflared",
    "/usr/local/bin/cloudflared",
];

pub struct CloudflareQuickTunnel {
    child: Option<Child>,
    public_url: Option<String>,
    status: TunnelStatus,
    binary_path: Option<String>,
}

impl Default for CloudflareQuickTunnel {
    fn default() -> Self {
        Self::new()
    }
}

impl CloudflareQuickTunnel {
    pub fn new() -> Self {
        Self {
            child: None,
            public_url: None,
            status: TunnelStatus::Disconnected {
                reason: "not started".into(),
            },
            binary_path: None,
        }
    }

    /// Override the binary resolution (useful in tests or when the user
    /// pins a specific cloudflared version).
    pub fn with_binary_path(mut self, path: impl Into<String>) -> Self {
        self.binary_path = Some(path.into());
        self
    }

    /// Returns true if a child process is still alive.
    pub fn is_alive(&mut self) -> bool {
        let Some(child) = self.child.as_mut() else {
            return false;
        };
        match child.try_wait() {
            Ok(Some(_)) => {
                self.status = TunnelStatus::Disconnected {
                    reason: "process exited".into(),
                };
                self.public_url = None;
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
}

#[async_trait]
impl TunnelProvider for CloudflareQuickTunnel {
    async fn start(&mut self, local_port: u16) -> TunnelResult<()> {
        if self.child.is_some() {
            return Err(TunnelError::AlreadyRunning);
        }

        self.status = TunnelStatus::Connecting;
        let binary = self.resolve_binary()?;

        let mut child = Command::new(&binary)
            .args([
                "tunnel",
                "--url",
                &format!("http://127.0.0.1:{}", local_port),
                "--no-autoupdate",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;

        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| TunnelError::Other("cloudflared stderr unavailable".into()))?;

        let (url_tx, mut url_rx) = watch::channel::<Option<String>>(None);

        tokio::spawn(async move {
            let reader = BufReader::new(stderr);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                tracing::debug!(target: "aex_tunnel::cloudflare", "{}", line);
                if let Some(url) = extract_tunnel_url(&line) {
                    tracing::info!(target: "aex_tunnel::cloudflare", "tunnel url = {}", url);
                    let _ = url_tx.send(Some(url));
                }
            }
        });

        // Keep the child before awaiting the URL so Drop still kills it
        // if this function panics.
        self.child = Some(child);

        let url = timeout(URL_TIMEOUT, async move {
            loop {
                if url_rx.changed().await.is_err() {
                    return None;
                }
                let val = url_rx.borrow().clone();
                if val.is_some() {
                    return val;
                }
            }
        })
        .await;

        match url {
            Ok(Some(u)) => {
                self.public_url = Some(u.clone());
                self.status = TunnelStatus::Connected { url: u };
                Ok(())
            }
            Ok(None) => {
                self.status = TunnelStatus::Disconnected {
                    reason: "cloudflared closed stderr without emitting URL".into(),
                };
                Err(TunnelError::ChannelClosed)
            }
            Err(_) => {
                self.status = TunnelStatus::Disconnected {
                    reason: "timeout waiting for URL".into(),
                };
                Err(TunnelError::UrlTimeout {
                    secs: URL_TIMEOUT.as_secs(),
                })
            }
        }
    }

    async fn stop(&mut self) -> TunnelResult<()> {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill().await;
        }
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

    #[test]
    fn resolve_binary_honors_override() {
        let t = CloudflareQuickTunnel::new().with_binary_path("/nonexistent/cloudflared");
        assert_eq!(t.resolve_binary().unwrap(), "/nonexistent/cloudflared");
    }

    #[tokio::test]
    async fn stop_without_start_is_noop() {
        let mut t = CloudflareQuickTunnel::new();
        t.stop().await.unwrap();
        assert!(matches!(t.status(), TunnelStatus::Disconnected { .. }));
    }
}
