//! [`TierPolicy`] — a table-driven [`crate::PolicyEngine`] covering the
//! first-year SaaS tiers (free-human / dev / enterprise).
//!
//! Fields are public so the control plane can load per-org overrides at
//! startup (e.g. raised size caps for paying customers).

use aex_scanner::{PipelineVerdict, ScanResult};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{
    decision::{PolicyDecision, TierName},
    request::{PolicyRequest, RecipientKind},
    PolicyEngine,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierPolicy {
    pub name: TierName,
    pub max_bytes: u64,
    /// Explicit MIME deny-list. `application/x-msdownload` (Windows PE),
    /// `application/x-executable`, etc. live here.
    pub mime_deny: Vec<String>,
    /// If false, `Suspicious` pipeline verdicts are blocked. Dev tier sets
    /// this to true and lets operators review via audit.
    pub allow_suspicious: bool,
    /// If false, `Error` pipeline verdicts are blocked (fail-closed).
    /// Dev tier sets true (fail-open).
    pub fail_open_on_scanner_error: bool,
    /// If false, transfers to non-native (human bridge) recipients are
    /// refused. Free-human tier uses this.
    pub allow_human_bridge: bool,
}

impl TierPolicy {
    pub fn for_tier(tier: TierName) -> Self {
        match tier {
            TierName::FreeHuman => Self {
                name: tier,
                max_bytes: 25 * 1024 * 1024, // 25 MB
                mime_deny: default_mime_deny(),
                allow_suspicious: false,
                fail_open_on_scanner_error: false,
                allow_human_bridge: true,
            },
            TierName::Dev => Self {
                name: tier,
                max_bytes: 100 * 1024 * 1024, // 100 MB
                mime_deny: default_mime_deny(),
                allow_suspicious: true,
                fail_open_on_scanner_error: true,
                allow_human_bridge: true,
            },
            TierName::Enterprise => Self {
                name: tier,
                max_bytes: 5 * 1024 * 1024 * 1024, // 5 GB
                mime_deny: default_mime_deny(),
                allow_suspicious: false,
                fail_open_on_scanner_error: false,
                allow_human_bridge: true,
            },
        }
    }
}

fn default_mime_deny() -> Vec<String> {
    vec![
        "application/x-msdownload".into(),
        "application/x-executable".into(),
        "application/x-mach-binary".into(),
        "application/x-msdos-program".into(),
    ]
}

#[async_trait]
impl PolicyEngine for TierPolicy {
    async fn evaluate(&self, req: &PolicyRequest<'_>) -> PolicyDecision {
        // 1. Size cap.
        if req.size_bytes > self.max_bytes {
            return PolicyDecision::deny(
                "size_exceeded",
                format!(
                    "{} bytes exceeds tier limit {}",
                    req.size_bytes, self.max_bytes
                ),
            );
        }

        // 2. Human-bridge gate.
        if !self.allow_human_bridge && matches!(req.recipient_kind, RecipientKind::HumanBridge) {
            return PolicyDecision::deny(
                "human_bridge_disallowed",
                "this tier does not permit sending to email/phone recipients",
            );
        }

        // 3. MIME deny-list (only enforced when declared_mime is present —
        //    if the client didn't declare one we'd need to infer, which
        //    the scanner handles separately).
        if let Some(mime) = req.declared_mime {
            if self.mime_deny.iter().any(|m| m == mime) {
                return PolicyDecision::deny(
                    "mime_blocked",
                    format!("MIME {} is on the tier deny-list", mime),
                );
            }
        }

        // 4. Scanner verdict (if present).
        if let Some(verdict) = req.scanner_verdict {
            if let Some(denial) = self.decide_on_verdict(verdict) {
                return denial;
            }
        }

        PolicyDecision::Allow
    }
}

impl TierPolicy {
    fn decide_on_verdict(&self, v: &PipelineVerdict) -> Option<PolicyDecision> {
        match v.overall {
            ScanResult::Malicious => Some(PolicyDecision::deny(
                "scanner_malicious",
                summarize_verdict(v),
            )),
            ScanResult::Error => {
                if self.fail_open_on_scanner_error {
                    None
                } else {
                    Some(PolicyDecision::deny(
                        "scanner_error",
                        format!(
                            "tier '{:?}' fails closed on scanner error: {}",
                            self.name,
                            summarize_verdict(v)
                        ),
                    ))
                }
            }
            ScanResult::Suspicious => {
                if self.allow_suspicious {
                    None
                } else {
                    Some(PolicyDecision::deny(
                        "scanner_suspicious",
                        summarize_verdict(v),
                    ))
                }
            }
            ScanResult::Clean => None,
        }
    }
}

fn summarize_verdict(v: &PipelineVerdict) -> String {
    let notes: Vec<String> = v
        .verdicts
        .iter()
        .filter(|sv| sv.result != ScanResult::Clean)
        .map(|sv| format!("{}={:?}:{}", sv.scanner, sv.result, sv.details))
        .collect();
    notes.join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use aex_core::AgentId;
    use aex_scanner::verdict::ScanVerdict;

    fn alice() -> AgentId {
        AgentId::new("spize:acme/alice:aabbcc").unwrap()
    }

    fn base_req<'a>(sender: &'a AgentId) -> PolicyRequest<'a> {
        PolicyRequest::new(
            sender,
            "acme",
            "spize:acme/bob:ddeeff",
            RecipientKind::SpizeNative,
            1024,
        )
    }

    #[tokio::test]
    async fn dev_tier_allows_small_clean_transfer() {
        let p = TierPolicy::for_tier(TierName::Dev);
        let a = alice();
        let req = base_req(&a);
        let d = p.evaluate(&req).await;
        assert!(d.is_allow());
    }

    #[tokio::test]
    async fn oversize_denied() {
        let p = TierPolicy::for_tier(TierName::Dev);
        let a = alice();
        let mut req = base_req(&a);
        req.size_bytes = 500 * 1024 * 1024;
        let d = p.evaluate(&req).await;
        match d {
            PolicyDecision::Deny { code, .. } => assert_eq!(code, "size_exceeded"),
            _ => panic!("expected deny"),
        }
    }

    #[tokio::test]
    async fn mime_deny_enforced() {
        let p = TierPolicy::for_tier(TierName::Dev);
        let a = alice();
        let req = base_req(&a).with_declared_mime("application/x-msdownload");
        let d = p.evaluate(&req).await;
        match d {
            PolicyDecision::Deny { code, .. } => assert_eq!(code, "mime_blocked"),
            _ => panic!("expected deny"),
        }
    }

    #[tokio::test]
    async fn malicious_verdict_blocks_all_tiers() {
        let a = alice();
        let verdict = PipelineVerdict::aggregate(vec![
            ScanVerdict::clean("size-limit", 1),
            ScanVerdict::malicious("eicar", "EICAR matched", 1),
        ]);
        for tier in [TierName::FreeHuman, TierName::Dev, TierName::Enterprise] {
            let p = TierPolicy::for_tier(tier);
            let req = base_req(&a).with_verdict(&verdict);
            let d = p.evaluate(&req).await;
            match d {
                PolicyDecision::Deny { code, .. } => assert_eq!(code, "scanner_malicious"),
                _ => panic!("tier {:?} should block malicious", tier),
            }
        }
    }

    #[tokio::test]
    async fn suspicious_allowed_only_in_dev() {
        let a = alice();
        let verdict = PipelineVerdict::aggregate(vec![ScanVerdict::suspicious(
            "regex-prompt-injection",
            "x",
            1,
        )]);
        let dev = TierPolicy::for_tier(TierName::Dev);
        let req = base_req(&a).with_verdict(&verdict);
        assert!(dev.evaluate(&req).await.is_allow());

        let ent = TierPolicy::for_tier(TierName::Enterprise);
        let d = ent.evaluate(&req).await;
        match d {
            PolicyDecision::Deny { code, .. } => assert_eq!(code, "scanner_suspicious"),
            _ => panic!("enterprise should block suspicious"),
        }
    }

    #[tokio::test]
    async fn scanner_error_fail_open_dev_fail_closed_ent() {
        let a = alice();
        let verdict = PipelineVerdict::aggregate(vec![ScanVerdict::error("eicar", "crashed", 1)]);
        let dev = TierPolicy::for_tier(TierName::Dev);
        assert!(dev
            .evaluate(&base_req(&a).with_verdict(&verdict))
            .await
            .is_allow());

        let ent = TierPolicy::for_tier(TierName::Enterprise);
        let d = ent.evaluate(&base_req(&a).with_verdict(&verdict)).await;
        match d {
            PolicyDecision::Deny { code, .. } => assert_eq!(code, "scanner_error"),
            _ => panic!("enterprise should fail closed on scanner error"),
        }
    }
}
