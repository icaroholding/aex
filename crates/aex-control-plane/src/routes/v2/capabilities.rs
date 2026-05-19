//! `GET /v2/capabilities` — advertises wire versions and capability
//! bits supported by this control plane (ADR-0043 §5.1).
//!
//! Used by sender adapters before initiating a transfer: they pick the
//! highest mutually-supported wire version from the
//! `wire_versions` field and check the `capabilities` array for any
//! feature bits they care about.

use aex_core::{Capability, CapabilitySet};
use axum::{routing::get, Json, Router};
use serde::Serialize;

use crate::AppState;

/// Response body for `GET /v2/capabilities`.
#[derive(Debug, Serialize)]
pub struct CapabilitiesBody {
    /// Wire versions accepted by this control plane, ordered
    /// preferred-first. During the v1→v2 grace window this is
    /// `["v2", "v1"]`; after sunset it becomes `["v2"]`.
    pub wire_versions: Vec<&'static str>,
    /// Capability bits advertised, as stable string names. Forward-
    /// compatible per ADR-0018.
    pub capabilities: Vec<&'static str>,
    /// Supported DID methods at the resolver layer (ADR-0047).
    pub supported_did_methods: Vec<&'static str>,
}

async fn capabilities() -> Json<CapabilitiesBody> {
    Json(CapabilitiesBody {
        wire_versions: vec!["v2", "v1"],
        capabilities: default_capability_set().to_string_array(),
        supported_did_methods: vec!["spize", "web", "ethr", "key"],
    })
}

/// The capability set advertised by a Spize-hosted reference control
/// plane at v2.0 beta. Operators forking this crate are free to add
/// further capability bits, but must NOT remove these without
/// breaking ADR-0048 conformance.
pub fn default_capability_set() -> CapabilitySet {
    CapabilitySet::empty()
        .with(Capability::WireV2)
        .with(Capability::JwsAgentCard)
        .with(Capability::CardEtag)
        .with(Capability::SafeHttp)
        .with(Capability::ClockSkew60s)
}

pub fn router() -> Router<AppState> {
    Router::new().route("/v2/capabilities", get(capabilities))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_set_includes_v2_essentials() {
        let set = default_capability_set();
        assert!(set.has(Capability::WireV2));
        assert!(set.has(Capability::JwsAgentCard));
        assert!(set.has(Capability::CardEtag));
        assert!(set.has(Capability::SafeHttp));
        assert!(set.has(Capability::ClockSkew60s));
        // Not advertised at GA — staged for v2.1.
        assert!(!set.has(Capability::A2ABridge));
        assert!(!set.has(Capability::StreamingTransfer));
    }

    #[test]
    fn default_set_serializes_to_stable_strings() {
        let names = default_capability_set().to_string_array();
        // Order follows Capability::ALL declaration order.
        assert_eq!(
            names,
            vec![
                "wire-v2",
                "jws-agent-card",
                "card-etag",
                "safe-http",
                "clock-skew-60s",
            ]
        );
    }

    #[tokio::test]
    async fn capabilities_handler_returns_expected_body() {
        let body = capabilities().await;
        assert_eq!(body.wire_versions, vec!["v2", "v1"]);
        assert!(body.capabilities.contains(&"wire-v2"));
        assert_eq!(
            body.supported_did_methods,
            vec!["spize", "web", "ethr", "key"]
        );
    }
}
