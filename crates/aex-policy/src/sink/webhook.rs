//! HTTP webhook-based [`crate::DecisionSink`].
//!
//! The sink POSTs the [`super::DecisionRequest`] as JSON to a
//! user-configured webhook URL and returns immediately. The remote
//! system is expected to call back the control plane with a signed
//! `aex-decision-response:v2` when the decider has produced an
//! outcome — the response is verified and persisted in the audit
//! chain separately, not through this sink.
//!
//! Typical use cases:
//!
//! - Enterprise approval workflows that already speak HTTP webhooks.
//! - Off-process orchestrators that route requests to specialist
//!   workers.
//! - Multi-tenant approval brokers.
//!
//! # SSRF safety
//!
//! Webhook URLs come from operator configuration, not from peer
//! traffic, so the SSRF concerns that motivated
//! [`aex_net::safe_http`] do not strictly apply here. The sink
//! nonetheless reuses [`aex_net::safe_http`]'s host-classification
//! helpers to refuse loopback / RFC1918 / link-local targets unless
//! the operator has explicitly opted in via configuration. This
//! defends against accidentally pointing at an internal admin
//! endpoint during operator misconfiguration.

use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use super::{DecisionRequest, DecisionSink, DecisionSinkError};

/// Default HTTP timeout for a webhook POST. Tuned to allow the
/// remote system to enqueue the request — not to wait for the
/// decider to finish.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Default retry count for transient webhook failures.
pub const DEFAULT_MAX_RETRIES: u8 = 3;

/// Configuration for a [`WebhookDecisionSink`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// HTTPS URL of the webhook. HTTP is refused.
    pub url: String,
    /// Optional bearer token. If present, sent as
    /// `Authorization: Bearer <token>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer_token: Option<String>,
    /// Per-request HTTP timeout.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    /// Maximum retry attempts on transient failures.
    #[serde(default = "default_max_retries")]
    pub max_retries: u8,
    /// If true, the host-classification check that refuses internal
    /// IP ranges is bypassed. Use only when the webhook genuinely
    /// targets an internal service in a controlled environment.
    #[serde(default)]
    pub allow_internal_targets: bool,
}

fn default_timeout_secs() -> u64 {
    DEFAULT_TIMEOUT.as_secs()
}
fn default_max_retries() -> u8 {
    DEFAULT_MAX_RETRIES
}

/// Errors specific to the webhook sink. Mapped onto
/// [`DecisionSinkError`] when surfaced through the
/// [`DecisionSink`] trait.
#[derive(Debug, Error)]
pub enum WebhookSinkError {
    /// URL parsing failed or the URL is not https://.
    #[error("invalid webhook URL: {0}")]
    InvalidUrl(String),
    /// The configured URL resolves to an internal address and the
    /// operator did not opt into internal targets.
    #[error("webhook URL resolves to internal address (set allow_internal_targets to override)")]
    InternalTarget,
    /// The webhook responded with a non-2xx status code.
    #[error("webhook returned HTTP {0}")]
    HttpStatus(u16),
    /// Transport-level failure after all retries.
    #[error("webhook transport error after retries: {0}")]
    Transport(String),
}

/// HTTP webhook-based [`DecisionSink`].
pub struct WebhookDecisionSink {
    client: reqwest::Client,
    config: WebhookConfig,
}

impl WebhookDecisionSink {
    /// Build a sink from configuration. Returns an error if the URL
    /// is malformed.
    pub fn new(config: WebhookConfig) -> Result<Self, WebhookSinkError> {
        let url =
            Url::parse(&config.url).map_err(|e| WebhookSinkError::InvalidUrl(e.to_string()))?;
        if url.scheme() != "https" {
            return Err(WebhookSinkError::InvalidUrl(format!(
                "scheme must be https, got '{}'",
                url.scheme()
            )));
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .user_agent(format!(
                "aex-policy/{} webhook-decision-sink",
                env!("CARGO_PKG_VERSION")
            ))
            .build()
            .map_err(|e| WebhookSinkError::Transport(e.to_string()))?;
        Ok(Self { client, config })
    }

    fn check_host(&self, url: &Url) -> Result<(), WebhookSinkError> {
        if self.config.allow_internal_targets {
            return Ok(());
        }
        let host = url
            .host_str()
            .ok_or_else(|| WebhookSinkError::InvalidUrl("URL has no host".into()))?;
        // We resolve via the OS for the check (a webhook URL is
        // operator-configured; resolution privacy isn't a concern
        // here the way it is for safe_http). Any resolved address
        // in a forbidden range fails the check.
        use std::net::ToSocketAddrs;
        let resolved: Vec<std::net::SocketAddr> = match (host, 0u16).to_socket_addrs() {
            Ok(iter) => iter.collect(),
            Err(_) => return Ok(()),
        };
        for addr in resolved {
            if aex_net::is_forbidden_ip(addr.ip()) {
                return Err(WebhookSinkError::InternalTarget);
            }
        }
        Ok(())
    }
}

#[async_trait]
impl DecisionSink for WebhookDecisionSink {
    async fn submit(&self, request: DecisionRequest) -> Result<(), DecisionSinkError> {
        let url = Url::parse(&self.config.url)
            .map_err(|e| DecisionSinkError::Infra(format!("invalid url: {}", e)))?;
        self.check_host(&url)
            .map_err(|e| DecisionSinkError::Infra(e.to_string()))?;

        let mut attempts: u8 = 0;
        let max = self.config.max_retries.max(1);
        loop {
            attempts += 1;
            let mut builder = self.client.post(url.clone()).json(&request);
            if let Some(token) = &self.config.bearer_token {
                builder = builder.bearer_auth(token);
            }
            match builder.send().await {
                Ok(resp) if resp.status().is_success() => return Ok(()),
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    if attempts >= max || !is_retriable(status) {
                        return Err(DecisionSinkError::Infra(format!(
                            "webhook returned {} after {} attempts",
                            status, attempts
                        )));
                    }
                }
                Err(e) => {
                    if attempts >= max {
                        return Err(DecisionSinkError::Infra(format!(
                            "webhook transport failed after {} attempts: {}",
                            attempts, e
                        )));
                    }
                }
            }
            let backoff_ms = 250u64.saturating_mul(1u64 << attempts.min(5));
            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
        }
    }
}

fn is_retriable(status: u16) -> bool {
    matches!(status, 408 | 425 | 429 | 500..=599)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_http_scheme() {
        let cfg = WebhookConfig {
            url: "http://example.com/webhook".into(),
            bearer_token: None,
            timeout_secs: 5,
            max_retries: 3,
            allow_internal_targets: false,
        };
        match WebhookDecisionSink::new(cfg) {
            Err(WebhookSinkError::InvalidUrl(_)) => {}
            other => panic!("expected InvalidUrl, got {:?}", other.err()),
        }
    }

    #[test]
    fn rejects_malformed_url() {
        let cfg = WebhookConfig {
            url: "not a url".into(),
            bearer_token: None,
            timeout_secs: 5,
            max_retries: 3,
            allow_internal_targets: false,
        };
        match WebhookDecisionSink::new(cfg) {
            Err(WebhookSinkError::InvalidUrl(_)) => {}
            other => panic!("expected InvalidUrl, got {:?}", other.err()),
        }
    }

    #[test]
    fn accepts_https_url() {
        let cfg = WebhookConfig {
            url: "https://example.com/webhook".into(),
            bearer_token: Some("secret".into()),
            timeout_secs: 5,
            max_retries: 3,
            allow_internal_targets: false,
        };
        let _ = WebhookDecisionSink::new(cfg).expect("valid https URL must build");
    }

    #[test]
    fn is_retriable_classification() {
        assert!(is_retriable(429));
        assert!(is_retriable(500));
        assert!(is_retriable(503));
        assert!(!is_retriable(400));
        assert!(!is_retriable(401));
        assert!(!is_retriable(404));
    }

    #[test]
    fn config_serde_roundtrip() {
        let cfg = WebhookConfig {
            url: "https://api.example.com/aex-decisions".into(),
            bearer_token: Some("tok".into()),
            timeout_secs: 7,
            max_retries: 5,
            allow_internal_targets: false,
        };
        let j = serde_json::to_string(&cfg).unwrap();
        let back: WebhookConfig = serde_json::from_str(&j).unwrap();
        assert_eq!(back.url, cfg.url);
        assert_eq!(back.bearer_token.as_deref(), Some("tok"));
        assert_eq!(back.timeout_secs, 7);
        assert_eq!(back.max_retries, 5);
    }
}
