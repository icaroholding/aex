//! Conformance test suite for AEX v2 (ADR-0048).
//!
//! Each test is an async function that returns
//! `Result<(), ConformanceFailure>`. The library exposes them as a
//! flat list so the binary can iterate, capture results, and print a
//! summary; downstream code (CI integrations, dashboards) can also
//! import the list and slice it by category.
//!
//! # Scope at v2.0 GA
//!
//! Offline checks of the local AEX stack: wire-v2 round-trip, JWS
//! algorithm whitelist enforcement, SSRF resistance of `safe_http`,
//! clock-skew handling, capability registry stability, DID URI
//! parser strictness, cross-version isolation between v1 and v2.
//! Network-aware checks against a remote control plane URL stage as
//! v2.1.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use aex_core::{
    capability::Capability, wire, wire_v2, AgentId, CapabilitySet, IdScheme, IdentityProvider,
};
use aex_identity::DidKeyProvider;
use aex_jws::{sign_ed25519, verify, JwsError, VerifierKey};
use aex_net::is_forbidden_ip;
use ed25519_dalek::SigningKey;

/// Outcome of running a single conformance test.
#[derive(Debug, Clone)]
pub struct ConformanceResult {
    /// Stable identifier (kebab-case). Becomes part of the JSON
    /// report and the badge URL hash.
    pub id: &'static str,
    /// Category for output grouping. Free-text; the binary groups by
    /// exact-string equality.
    pub category: &'static str,
    /// Pass/fail outcome.
    pub outcome: Outcome,
}

/// Pass / fail discriminant.
#[derive(Debug, Clone)]
pub enum Outcome {
    /// All assertions held.
    Pass,
    /// One or more assertions failed; the message is operator-readable.
    Fail(String),
}

impl Outcome {
    /// True iff `self` is [`Outcome::Pass`].
    pub fn is_pass(&self) -> bool {
        matches!(self, Outcome::Pass)
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Outcome::Pass => write!(f, "PASS"),
            Outcome::Fail(msg) => write!(f, "FAIL: {}", msg),
        }
    }
}

/// Future type produced by every conformance test runner.
pub type TestFuture = Pin<Box<dyn Future<Output = Result<(), String>> + Send>>;

/// Runner function pointer type. Kept as a type alias for clippy.
pub type TestRunner = fn() -> TestFuture;

/// A single conformance test registration.
pub struct ConformanceTest {
    /// Stable identifier (kebab-case). Becomes part of the JSON report.
    pub id: &'static str,
    /// Display category.
    pub category: &'static str,
    /// Runner function — async, returns `Ok(())` on pass.
    pub run: TestRunner,
}

/// Build the full v2.0 GA conformance test list.
///
/// Order matters only for output grouping. The set is stable: removing
/// or renaming a test breaks any deployment that pinned its
/// `conformance_hash` in a release artefact.
pub fn all_tests() -> Vec<ConformanceTest> {
    vec![
        ConformanceTest {
            id: "wire-v2-roundtrip",
            category: "wire",
            run: || Box::pin(test_wire_v2_roundtrip()),
        },
        ConformanceTest {
            id: "wire-v1-still-functional",
            category: "wire",
            run: || Box::pin(test_wire_v1_still_functional()),
        },
        ConformanceTest {
            id: "cross-version-isolation",
            category: "wire",
            run: || Box::pin(test_cross_version_isolation()),
        },
        ConformanceTest {
            id: "jws-algorithm-whitelist",
            category: "jws",
            run: || Box::pin(test_jws_algorithm_whitelist()),
        },
        ConformanceTest {
            id: "jws-alg-none-rejected",
            category: "jws",
            run: || Box::pin(test_jws_alg_none_rejected()),
        },
        ConformanceTest {
            id: "jws-alg-hs256-rejected",
            category: "jws",
            run: || Box::pin(test_jws_alg_hs256_rejected()),
        },
        ConformanceTest {
            id: "jws-tampered-payload-rejected",
            category: "jws",
            run: || Box::pin(test_jws_tampered_payload_rejected()),
        },
        ConformanceTest {
            id: "ssrf-rejects-loopback",
            category: "ssrf",
            run: || Box::pin(test_ssrf_rejects_loopback()),
        },
        ConformanceTest {
            id: "ssrf-rejects-rfc1918",
            category: "ssrf",
            run: || Box::pin(test_ssrf_rejects_rfc1918()),
        },
        ConformanceTest {
            id: "ssrf-rejects-link-local",
            category: "ssrf",
            run: || Box::pin(test_ssrf_rejects_link_local()),
        },
        ConformanceTest {
            id: "ssrf-accepts-public-ips",
            category: "ssrf",
            run: || Box::pin(test_ssrf_accepts_public_ips()),
        },
        ConformanceTest {
            id: "clock-skew-60s-window",
            category: "time",
            run: || Box::pin(test_clock_skew_60s_window()),
        },
        ConformanceTest {
            id: "clock-skew-rejects-outside-window",
            category: "time",
            run: || Box::pin(test_clock_skew_rejects_outside_window()),
        },
        ConformanceTest {
            id: "did-uri-parser-strict",
            category: "identity",
            run: || Box::pin(test_did_uri_parser_strict()),
        },
        ConformanceTest {
            id: "did-key-roundtrip",
            category: "identity",
            run: || Box::pin(test_did_key_roundtrip()),
        },
        ConformanceTest {
            id: "did-key-rejects-malformed",
            category: "identity",
            run: || Box::pin(test_did_key_rejects_malformed()),
        },
        ConformanceTest {
            id: "capability-bits-stable",
            category: "capability",
            run: || Box::pin(test_capability_bits_stable()),
        },
        ConformanceTest {
            id: "capability-forward-compat",
            category: "capability",
            run: || Box::pin(test_capability_forward_compat()),
        },
        ConformanceTest {
            id: "wire-v2-rejects-nonce-too-short",
            category: "wire",
            run: || Box::pin(test_wire_v2_rejects_nonce_too_short()),
        },
        ConformanceTest {
            id: "wire-v2-rejects-newline-in-fields",
            category: "wire",
            run: || Box::pin(test_wire_v2_rejects_newline_in_fields()),
        },
        ConformanceTest {
            id: "wire-v2-rotate-key-same-keys-rejected",
            category: "wire",
            run: || Box::pin(test_wire_v2_rotate_key_same_keys_rejected()),
        },
        ConformanceTest {
            id: "wire-v2-receipt-action-whitelist",
            category: "wire",
            run: || Box::pin(test_wire_v2_receipt_action_whitelist()),
        },
        ConformanceTest {
            id: "decision-request-bytes-stable",
            category: "deferred-decision",
            run: || Box::pin(test_decision_request_bytes_stable()),
        },
        ConformanceTest {
            id: "decision-response-bytes-stable",
            category: "deferred-decision",
            run: || Box::pin(test_decision_response_bytes_stable()),
        },
        ConformanceTest {
            id: "deferred-decision-capability-bit-stable",
            category: "deferred-decision",
            run: || Box::pin(test_deferred_decision_capability_bit_stable()),
        },
    ]
}

/// Run every test and collect results.
pub async fn run_all() -> Vec<ConformanceResult> {
    let mut results = Vec::new();
    for t in all_tests() {
        let outcome = match (t.run)().await {
            Ok(()) => Outcome::Pass,
            Err(msg) => Outcome::Fail(msg),
        };
        results.push(ConformanceResult {
            id: t.id,
            category: t.category,
            outcome,
        });
    }
    results
}

// ── Test implementations ─────────────────────────────────────────────

const NONCE: &str = "0123456789abcdef0123456789abcdef";

async fn test_wire_v2_roundtrip() -> Result<(), String> {
    let bytes = wire_v2::transfer_intent_bytes_v2(
        "did:web:acme.com#agent",
        "did:web:beta.com#bob",
        12345,
        "application/pdf",
        "x.pdf",
        NONCE,
        1_700_000_000,
    )
    .map_err(|e| format!("encode failed: {}", e))?;
    let s = std::str::from_utf8(&bytes).map_err(|e| e.to_string())?;
    if !s.starts_with("aex-transfer-intent:v2\n") {
        return Err(format!("unexpected prefix: {:?}", &s[..30]));
    }
    Ok(())
}

async fn test_wire_v1_still_functional() -> Result<(), String> {
    let bytes = wire::transfer_intent_bytes(
        "spize:acme/alice:aabbcc",
        "spize:acme/bob:ddeeff",
        100,
        "",
        "",
        NONCE,
        1_700_000_000,
    )
    .map_err(|e| e.to_string())?;
    let s = std::str::from_utf8(&bytes).map_err(|e| e.to_string())?;
    if !s.starts_with("spize-transfer-intent:v1\n") {
        return Err(format!("v1 prefix missing: {:?}", &s[..30]));
    }
    Ok(())
}

async fn test_cross_version_isolation() -> Result<(), String> {
    let v1 = wire::registration_challenge_bytes("aa", "acme", "alice", NONCE, 1_700_000_000)
        .map_err(|e| e.to_string())?;
    let v2 = wire_v2::registration_challenge_bytes_v2("aa", "acme", "alice", NONCE, 1_700_000_000)
        .map_err(|e| e.to_string())?;
    if v1 == v2 {
        return Err("v1 and v2 bytes collide for identical inputs".into());
    }
    if !std::str::from_utf8(&v1).unwrap().starts_with("spize-") {
        return Err("v1 missing spize- prefix".into());
    }
    if !std::str::from_utf8(&v2).unwrap().starts_with("aex-") {
        return Err("v2 missing aex- prefix".into());
    }
    Ok(())
}

async fn test_jws_algorithm_whitelist() -> Result<(), String> {
    let sk = SigningKey::from_bytes(&[1u8; 32]);
    let jws = sign_ed25519(b"payload", &sk, "did:key:test").map_err(|e| e.to_string())?;
    let _ = verify(&jws, |_| Ok(Some(VerifierKey::Ed25519(sk.verifying_key()))))
        .map_err(|e| e.to_string())?;
    Ok(())
}

async fn test_jws_alg_none_rejected() -> Result<(), String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let header = serde_json::json!({"alg": "none", "kid": "did:web:attacker"});
    let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let p = URL_SAFE_NO_PAD.encode(b"forged");
    let jws = format!("{}.{}.", h, p);
    match verify(&jws, |_| Ok(None)) {
        Err(JwsError::AlgorithmNotPermitted(s)) if s == "none" => Ok(()),
        other => Err(format!("expected AlgorithmNotPermitted, got {:?}", other)),
    }
}

async fn test_jws_alg_hs256_rejected() -> Result<(), String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let header = serde_json::json!({"alg": "HS256", "kid": "did:web:attacker"});
    let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let p = URL_SAFE_NO_PAD.encode(b"forged");
    let s = URL_SAFE_NO_PAD.encode([0u8; 32]);
    let jws = format!("{}.{}.{}", h, p, s);
    match verify(&jws, |_| Ok(None)) {
        Err(JwsError::AlgorithmNotPermitted(s)) if s == "HS256" => Ok(()),
        other => Err(format!("expected AlgorithmNotPermitted, got {:?}", other)),
    }
}

async fn test_jws_tampered_payload_rejected() -> Result<(), String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let sk = SigningKey::from_bytes(&[2u8; 32]);
    let vk = sk.verifying_key();
    let jws = sign_ed25519(b"original", &sk, "did:web:bob").unwrap();
    let parts: Vec<&str> = jws.split('.').collect();
    let tampered_p = URL_SAFE_NO_PAD.encode(b"forged");
    let bad = format!("{}.{}.{}", parts[0], tampered_p, parts[2]);
    match verify(&bad, |_| Ok(Some(VerifierKey::Ed25519(vk)))) {
        Err(JwsError::BadSignature(_)) => Ok(()),
        other => Err(format!("expected BadSignature, got {:?}", other)),
    }
}

async fn test_ssrf_rejects_loopback() -> Result<(), String> {
    if !is_forbidden_ip("127.0.0.1".parse().unwrap()) {
        return Err("127.0.0.1 not flagged forbidden".into());
    }
    if !is_forbidden_ip("::1".parse().unwrap()) {
        return Err("::1 not flagged forbidden".into());
    }
    Ok(())
}

async fn test_ssrf_rejects_rfc1918() -> Result<(), String> {
    for ip in ["10.0.0.1", "172.16.0.1", "192.168.0.1"] {
        if !is_forbidden_ip(ip.parse().unwrap()) {
            return Err(format!("{} not flagged forbidden", ip));
        }
    }
    Ok(())
}

async fn test_ssrf_rejects_link_local() -> Result<(), String> {
    if !is_forbidden_ip("169.254.169.254".parse().unwrap()) {
        return Err("EC2 metadata IP 169.254.169.254 not flagged".into());
    }
    if !is_forbidden_ip("fe80::1".parse().unwrap()) {
        return Err("fe80::1 not flagged".into());
    }
    Ok(())
}

async fn test_ssrf_accepts_public_ips() -> Result<(), String> {
    for ip in ["1.1.1.1", "8.8.8.8"] {
        if is_forbidden_ip(ip.parse().unwrap()) {
            return Err(format!("public IP {} unexpectedly flagged", ip));
        }
    }
    Ok(())
}

async fn test_clock_skew_60s_window() -> Result<(), String> {
    let now = 1_700_000_000;
    if !wire_v2::is_within_clock_skew_v2(now, now) {
        return Err("zero skew rejected".into());
    }
    if !wire_v2::is_within_clock_skew_v2(now, now - 60) {
        return Err("-60s skew rejected".into());
    }
    if !wire_v2::is_within_clock_skew_v2(now, now + 60) {
        return Err("+60s skew rejected".into());
    }
    Ok(())
}

async fn test_clock_skew_rejects_outside_window() -> Result<(), String> {
    let now = 1_700_000_000;
    if wire_v2::is_within_clock_skew_v2(now, now - 61) {
        return Err("-61s skew accepted".into());
    }
    if wire_v2::is_within_clock_skew_v2(now, now + 61) {
        return Err("+61s skew accepted".into());
    }
    Ok(())
}

async fn test_did_uri_parser_strict() -> Result<(), String> {
    // Empty fragment must be rejected by the URI parser.
    let id = AgentId::new("did:web:acme.com#").map_err(|e| e.to_string())?;
    if id.as_did_uri().is_some() {
        return Err("empty fragment accepted by parser".into());
    }
    // Uppercase method must be rejected by the URI parser.
    let id = AgentId::new("did:WEB:acme.com").map_err(|e| e.to_string())?;
    if id.as_did_uri().is_some() {
        return Err("uppercase method accepted".into());
    }
    // Well-formed URI must parse.
    let id = AgentId::new("did:web:acme.com#x").map_err(|e| e.to_string())?;
    let u = id
        .as_did_uri()
        .ok_or_else(|| "well-formed URI failed to parse".to_string())?;
    if u.method != "web" || u.method_specific_id != "acme.com" {
        return Err("parse extracted wrong components".into());
    }
    Ok(())
}

async fn test_did_key_roundtrip() -> Result<(), String> {
    let p = DidKeyProvider::generate().map_err(|e| e.to_string())?;
    if p.agent_id().scheme() != IdScheme::DidKey {
        return Err("generated did:key has wrong scheme".into());
    }
    let _ = DidKeyProvider::decode_pubkey(p.agent_id()).map_err(|e| e.to_string())?;
    Ok(())
}

async fn test_did_key_rejects_malformed() -> Result<(), String> {
    let id = AgentId::new("did:key:fabc").map_err(|e| e.to_string())?;
    if DidKeyProvider::decode_pubkey(&id).is_ok() {
        return Err("malformed did:key accepted".into());
    }
    Ok(())
}

async fn test_capability_bits_stable() -> Result<(), String> {
    let expected: &[(Capability, u8, &str)] = &[
        (Capability::WireV2, 0, "wire-v2"),
        (Capability::JwsAgentCard, 1, "jws-agent-card"),
        (Capability::CardEtag, 2, "card-etag"),
        (Capability::A2ABridge, 3, "a2a-bridge"),
        (Capability::EtereCitizenTrust, 4, "etere-citizen-trust"),
        (Capability::SafeHttp, 5, "safe-http"),
        (Capability::ClockSkew60s, 6, "clock-skew-60s"),
        (Capability::StreamingTransfer, 7, "streaming-transfer"),
    ];
    for (cap, bit, name) in expected {
        if cap.as_bit() != *bit {
            return Err(format!(
                "capability {:?} bit changed: {} != {}",
                cap,
                cap.as_bit(),
                bit
            ));
        }
        if cap.as_str() != *name {
            return Err(format!(
                "capability {:?} name changed: {:?} != {:?}",
                cap,
                cap.as_str(),
                name
            ));
        }
    }
    Ok(())
}

async fn test_capability_forward_compat() -> Result<(), String> {
    // Unknown names must be silently dropped, not errored.
    let set = CapabilitySet::from_string_array([
        "wire-v2",
        "future-capability-the-future-invented",
        "jws-agent-card",
    ]);
    if !set.has(Capability::WireV2) || !set.has(Capability::JwsAgentCard) {
        return Err("known caps lost during forward-compat parse".into());
    }
    if set.to_string_array().len() != 2 {
        return Err(format!(
            "expected 2 known caps after dropping unknown, got {}",
            set.to_string_array().len()
        ));
    }
    Ok(())
}

async fn test_wire_v2_rejects_nonce_too_short() -> Result<(), String> {
    let r =
        wire_v2::registration_challenge_bytes_v2("aa", "acme", "alice", "deadbeef", 1_700_000_000);
    if r.is_ok() {
        return Err("short nonce accepted".into());
    }
    Ok(())
}

async fn test_wire_v2_rejects_newline_in_fields() -> Result<(), String> {
    let r = wire_v2::registration_challenge_bytes_v2("aa", "ac\nme", "alice", NONCE, 1_700_000_000);
    if r.is_ok() {
        return Err("newline in org field accepted".into());
    }
    Ok(())
}

async fn test_wire_v2_rotate_key_same_keys_rejected() -> Result<(), String> {
    let same = "a".repeat(64);
    let r = wire_v2::rotate_key_challenge_bytes_v2(
        "did:spize:acme/alice#aabbcc",
        &same,
        &same,
        NONCE,
        1_700_000_000,
    );
    if r.is_ok() {
        return Err("identical old/new keys accepted in rotate".into());
    }
    Ok(())
}

async fn test_wire_v2_receipt_action_whitelist() -> Result<(), String> {
    // Accept all four allowed actions.
    for action in ["download", "ack", "inbox", "request_ticket"] {
        wire_v2::transfer_receipt_bytes_v2(
            "did:web:bob.com#x",
            "tx_abc",
            action,
            NONCE,
            1_700_000_000,
        )
        .map_err(|e| format!("action {} rejected: {}", action, e))?;
    }
    // Reject anything else.
    let r = wire_v2::transfer_receipt_bytes_v2(
        "did:web:bob.com#x",
        "tx_abc",
        "overwrite",
        NONCE,
        1_700_000_000,
    );
    if r.is_ok() {
        return Err("non-whitelisted action accepted".into());
    }
    Ok(())
}

async fn test_decision_request_bytes_stable() -> Result<(), String> {
    let bytes = wire_v2::decision_request_bytes_v2(
        "did:web:acme.com#agent-vendite",
        "tx_abc123",
        "dec_0001",
        86_400,
        NONCE,
        1_700_000_000,
    )
    .map_err(|e| e.to_string())?;
    let s = std::str::from_utf8(&bytes).map_err(|e| e.to_string())?;
    if !s.starts_with("aex-decision-request:v2\n") {
        return Err(format!("unexpected prefix: {:?}", &s[..40]));
    }
    if !s.contains("decision=dec_0001\n") {
        return Err("decision id field missing".into());
    }
    if !s.contains("eta_secs=86400\n") {
        return Err("eta_secs field missing or malformed".into());
    }
    Ok(())
}

async fn test_decision_response_bytes_stable() -> Result<(), String> {
    let accepted = wire_v2::decision_response_bytes_v2(
        "did:web:acme.com#agent-vendite",
        "tx_abc123",
        "dec_0001",
        "accepted",
        "",
        NONCE,
        1_700_000_000,
    )
    .map_err(|e| e.to_string())?;
    if !std::str::from_utf8(&accepted)
        .unwrap()
        .starts_with("aex-decision-response:v2\n")
    {
        return Err("accepted prefix wrong".into());
    }
    // Outcome whitelist enforced
    let bad =
        wire_v2::decision_response_bytes_v2("x", "tx", "dec", "maybe", "", NONCE, 1_700_000_000);
    if bad.is_ok() {
        return Err("non-whitelisted outcome accepted".into());
    }
    Ok(())
}

async fn test_deferred_decision_capability_bit_stable() -> Result<(), String> {
    if Capability::DeferredDecision.as_bit() != 8 {
        return Err(format!(
            "DeferredDecision bit changed: {}",
            Capability::DeferredDecision.as_bit()
        ));
    }
    if Capability::DeferredDecision.as_str() != "deferred-decision" {
        return Err(format!(
            "DeferredDecision name changed: {:?}",
            Capability::DeferredDecision.as_str()
        ));
    }
    // Forward-compat: a set containing the bit must still parse and
    // serialize the bit back correctly.
    let set = CapabilitySet::empty().with(Capability::DeferredDecision);
    if !set.has(Capability::DeferredDecision) {
        return Err("set membership broken".into());
    }
    let names = set.to_string_array();
    if !names.contains(&"deferred-decision") {
        return Err("string array missing deferred-decision".into());
    }
    Ok(())
}

/// Useful in tests: poke `Duration` so the unused-import warning
/// doesn't fire on bookkeeping helpers we may add later.
#[doc(hidden)]
pub const _DURATION_HINT: Duration = Duration::from_secs(0);

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn full_suite_passes_against_local_stack() {
        let results = run_all().await;
        let failed: Vec<_> = results.iter().filter(|r| !r.outcome.is_pass()).collect();
        assert!(
            failed.is_empty(),
            "conformance failures: {:#?}",
            failed
                .iter()
                .map(|r| format!("{}: {}", r.id, r.outcome))
                .collect::<Vec<_>>()
        );
        // Sanity: we expect a stable test count.
        assert_eq!(results.len(), 25);
    }

    #[tokio::test]
    async fn every_test_has_unique_id() {
        let tests = all_tests();
        let mut seen = std::collections::HashSet::new();
        for t in &tests {
            assert!(seen.insert(t.id), "duplicate test id: {}", t.id);
        }
    }
}
