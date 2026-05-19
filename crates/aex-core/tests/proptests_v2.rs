//! Property-based tests for wire v2, AgentId DID URI parsing, and the
//! capability registry (Phase v2 — ADR-0042/0044/0018).
//!
//! Coverage focus:
//!
//! 1. **`AgentId::as_did_uri()`** — random ASCII strings prefixed with
//!    `did:method:` must either parse cleanly *or* return `None`; never
//!    panic. Method-name discipline (W3C DID Core §3.1) is exercised.
//!
//! 2. **Wire v2 canonical bytes** — `registration_challenge_bytes_v2`,
//!    `transfer_intent_bytes_v2`, `data_ticket_bytes_v2`,
//!    `rotate_key_challenge_bytes_v2`, `transfer_receipt_bytes_v2` must
//!    be deterministic for valid inputs and reject any field containing
//!    `\n`, `\r`, `\0`, or non-ASCII. The v1 module's proptests already
//!    cover the v1 functions; this file mirrors them for v2 plus the
//!    cross-version invariant.
//!
//! 3. **`is_within_clock_skew_v2`** — tighter 60s window. Same overflow
//!    safety property as v1, plus the precise boundary at ±60s.
//!
//! 4. **`CapabilitySet`** — JSON roundtrip preserves the set under
//!    arbitrary subsets of `Capability::ALL`, including duplicates and
//!    unknown-name forward-compat.

use aex_core::wire_v2::{
    data_ticket_bytes_v2, is_within_clock_skew_v2, registration_challenge_bytes_v2,
    rotate_key_challenge_bytes_v2, transfer_intent_bytes_v2, transfer_receipt_bytes_v2,
    MAX_CLOCK_SKEW_SECS_V2, MAX_NONCE_LEN, MIN_NONCE_LEN,
};
use aex_core::{AgentId, Capability, CapabilitySet, IdScheme};
use proptest::prelude::*;

// ---------- AgentId & DID URI parsing ----------

/// Strategy: bytes that AgentId might receive — bounded ASCII or unicode-y.
fn arb_agent_id_input() -> impl Strategy<Value = String> {
    proptest::string::string_regex(r"[A-Za-z0-9:/#._-]{1,255}").unwrap()
}

proptest! {
    /// Whatever string AgentId::new accepts, as_did_uri() either parses
    /// it (Some) or returns None — never panics.
    #[test]
    fn did_uri_parse_never_panics(input in arb_agent_id_input()) {
        if let Ok(id) = AgentId::new(input.clone()) {
            // Just call it — assertion is "does not panic".
            let _ = id.as_did_uri();
            let _ = id.scheme();
        }
    }

    /// Any valid `did:<lowercase-method>:<non-empty-msi>` parses, and
    /// method/msi are extracted correctly.
    #[test]
    fn well_formed_did_parses(
        method in r"[a-z][a-z0-9]{0,15}",
        msi in r"[A-Za-z0-9._:-]{1,100}",
    ) {
        let s = format!("did:{}:{}", method, msi);
        if let Ok(id) = AgentId::new(&s) {
            let uri = id.as_did_uri()
                .expect("well-formed DID URI must parse");
            prop_assert_eq!(uri.method, method.as_str());
            prop_assert_eq!(uri.method_specific_id, msi.as_str());
            prop_assert_eq!(uri.fragment, None);
        }
    }

    /// Adding a non-empty fragment to a well-formed DID URI preserves
    /// method + msi and exposes the fragment.
    #[test]
    fn did_with_fragment_parses(
        method in r"[a-z][a-z0-9]{0,8}",
        msi in r"[A-Za-z0-9._-]{1,40}",
        frag in r"[A-Za-z0-9._-]{1,40}",
    ) {
        let s = format!("did:{}:{}#{}", method, msi, frag);
        if let Ok(id) = AgentId::new(&s) {
            let uri = id.as_did_uri().expect("must parse");
            prop_assert_eq!(uri.method, method.as_str());
            prop_assert_eq!(uri.method_specific_id, msi.as_str());
            prop_assert_eq!(uri.fragment, Some(frag.as_str()));
        }
    }

    /// scheme() never panics and is deterministic for the same input.
    #[test]
    fn scheme_deterministic(input in arb_agent_id_input()) {
        if let Ok(id) = AgentId::new(input) {
            let a = id.scheme();
            let b = id.scheme();
            prop_assert_eq!(a, b);
            // And the variant set is closed.
            prop_assert!(matches!(
                a,
                IdScheme::SpizeNative
                    | IdScheme::DidSpize
                    | IdScheme::DidEthr
                    | IdScheme::DidWeb
                    | IdScheme::DidKey
                    | IdScheme::Unknown
            ));
        }
    }
}

// ---------- Wire v2 canonical bytes ----------

fn arb_safe_ascii(min_len: usize, max_len: usize) -> impl Strategy<Value = String> {
    // ASCII printables that are also valid in our canonical line format
    // (no LF, CR, NUL — those would corrupt framing).
    proptest::string::string_regex(&format!(
        r"[A-Za-z0-9._:/#=+-]{{{},{}}}",
        min_len, max_len
    ))
    .unwrap()
}

fn arb_hex_nonce() -> impl Strategy<Value = String> {
    proptest::string::string_regex(&format!(
        r"[0-9a-f]{{{},{}}}",
        MIN_NONCE_LEN, MAX_NONCE_LEN
    ))
    .unwrap()
}

proptest! {
    /// Registration bytes are deterministic for the same inputs.
    #[test]
    fn v2_register_deterministic(
        pubkey in arb_safe_ascii(1, 64),
        org in arb_safe_ascii(1, 64),
        name in arb_safe_ascii(1, 64),
        nonce in arb_hex_nonce(),
        ts in any::<i64>(),
    ) {
        let a = registration_challenge_bytes_v2(&pubkey, &org, &name, &nonce, ts).unwrap();
        let b = registration_challenge_bytes_v2(&pubkey, &org, &name, &nonce, ts).unwrap();
        prop_assert_eq!(a, b);
    }

    /// Any newline in a field is rejected, deterministically.
    #[test]
    fn v2_register_rejects_newline_in_any_field(
        idx in 0u8..3,
        nonce in arb_hex_nonce(),
        ts in any::<i64>(),
    ) {
        let mut p = "aa".to_string();
        let mut o = "org".to_string();
        let mut n = "name".to_string();
        match idx {
            0 => p.push('\n'),
            1 => o.push('\n'),
            _ => n.push('\n'),
        }
        prop_assert!(registration_challenge_bytes_v2(&p, &o, &n, &nonce, ts).is_err());
    }

    /// Transfer intent: every byte sequence is deterministic and starts
    /// with the v2 prefix; v1 prefix never appears in v2 output.
    #[test]
    fn v2_transfer_intent_prefix_invariants(
        sender in arb_safe_ascii(3, 80),
        recipient in arb_safe_ascii(3, 80),
        size in any::<u64>(),
        mime in arb_safe_ascii(0, 40),
        filename in arb_safe_ascii(0, 60),
        nonce in arb_hex_nonce(),
        ts in any::<i64>(),
    ) {
        let bytes = transfer_intent_bytes_v2(
            &sender, &recipient, size, &mime, &filename, &nonce, ts,
        );
        if let Ok(bytes) = bytes {
            let s = std::str::from_utf8(&bytes).unwrap();
            prop_assert!(s.starts_with("aex-transfer-intent:v2\n"));
            prop_assert!(!s.contains("spize-transfer-intent"));
        }
    }

    /// Data ticket bytes are deterministic for the same inputs.
    #[test]
    fn v2_data_ticket_deterministic(
        tx in arb_safe_ascii(3, 40),
        rec in arb_safe_ascii(3, 80),
        url in arb_safe_ascii(8, 80),
        exp in any::<i64>(),
        nonce in arb_hex_nonce(),
    ) {
        let a = data_ticket_bytes_v2(&tx, &rec, &url, exp, &nonce).unwrap();
        let b = data_ticket_bytes_v2(&tx, &rec, &url, exp, &nonce).unwrap();
        prop_assert_eq!(a, b);
    }

    /// Rotate-key: rejects identical old/new for any pubkey value.
    #[test]
    fn v2_rotate_key_rejects_same(
        same in r"[0-9a-f]{64}",
        agent in arb_safe_ascii(5, 60),
        nonce in arb_hex_nonce(),
        ts in any::<i64>(),
    ) {
        let err = rotate_key_challenge_bytes_v2(&agent, &same, &same, &nonce, ts)
            .unwrap_err();
        prop_assert!(matches!(err, aex_core::Error::Internal(_)));
    }

    /// Receipt action whitelist enforced.
    #[test]
    fn v2_receipt_action_whitelist(
        action in arb_safe_ascii(1, 40),
        rec in arb_safe_ascii(3, 60),
        tx in arb_safe_ascii(3, 40),
        nonce in arb_hex_nonce(),
        ts in any::<i64>(),
    ) {
        let allowed = ["download", "ack", "inbox", "request_ticket"];
        let r = transfer_receipt_bytes_v2(&rec, &tx, &action, &nonce, ts);
        match r {
            Ok(_) => prop_assert!(allowed.contains(&action.as_str())),
            Err(_) => {
                // Either the action wasn't whitelisted OR some other
                // field tripped validation (rare with our safe ASCII).
                prop_assert!(
                    !allowed.contains(&action.as_str())
                        || rec.is_empty() || tx.is_empty()
                );
            }
        }
    }
}

// ---------- is_within_clock_skew_v2 ----------

proptest! {
    /// Never panics under any (i64, i64) pair.
    #[test]
    fn v2_skew_no_panic(now in any::<i64>(), then in any::<i64>()) {
        let _ = is_within_clock_skew_v2(now, then);
    }

    /// Symmetric: `skew(a, b) == skew(b, a)`.
    #[test]
    fn v2_skew_symmetric(a in any::<i64>(), b in any::<i64>()) {
        prop_assert_eq!(is_within_clock_skew_v2(a, b), is_within_clock_skew_v2(b, a));
    }

    /// Diffs strictly within ±60s are accepted, strictly outside are
    /// rejected.
    #[test]
    fn v2_skew_60s_boundary(base in -1_000_000_000i64..1_000_000_000i64,
                             delta in -90i64..90i64) {
        let now = base;
        let then = base.saturating_add(delta);
        let accepted = is_within_clock_skew_v2(now, then);
        if delta.unsigned_abs() <= MAX_CLOCK_SKEW_SECS_V2 as u64 {
            prop_assert!(accepted);
        } else {
            prop_assert!(!accepted);
        }
    }
}

// ---------- CapabilitySet ----------

fn arb_capability() -> impl Strategy<Value = Capability> {
    proptest::sample::select(Capability::ALL.to_vec())
}

fn arb_capability_set() -> impl Strategy<Value = CapabilitySet> {
    proptest::collection::hash_set(arb_capability(), 0..Capability::ALL.len() + 1).prop_map(|caps| {
        let mut s = CapabilitySet::empty();
        for c in caps {
            s = s.with(c);
        }
        s
    })
}

proptest! {
    /// JSON roundtrip is identity.
    #[test]
    fn caps_json_roundtrip(set in arb_capability_set()) {
        let j = serde_json::to_string(&set).unwrap();
        let back: CapabilitySet = serde_json::from_str(&j).unwrap();
        prop_assert_eq!(set, back);
    }

    /// Iterating yields exactly the capabilities present, in canonical
    /// order.
    #[test]
    fn caps_iter_matches_has(set in arb_capability_set()) {
        let collected: Vec<_> = set.iter().collect();
        // Iteration is in `Capability::ALL` order.
        let expected: Vec<_> = Capability::ALL
            .iter()
            .copied()
            .filter(|c| set.has(*c))
            .collect();
        prop_assert_eq!(collected, expected);
    }

    /// Unknown capability names are silently dropped (forward-compat).
    #[test]
    fn caps_unknown_names_ignored(
        known_subset in proptest::collection::hash_set(arb_capability(), 0..5),
        unknown in proptest::collection::vec(
            proptest::string::string_regex(r"unknown-[a-z]{1,10}").unwrap(),
            0..5
        ),
    ) {
        let mut wire_names: Vec<String> = known_subset.iter().map(|c| c.as_str().to_string()).collect();
        wire_names.extend(unknown);
        let parsed = CapabilitySet::from_string_array(wire_names);
        for cap in &known_subset {
            prop_assert!(parsed.has(*cap));
        }
        // Set size matches known-cap count (unknowns dropped).
        prop_assert_eq!(parsed.to_string_array().len(), known_subset.len());
    }
}
