//! Wire format **v2** — namespace-agnostic, AEX-branded prefix.
//!
//! This module is the v2 counterpart of [`crate::wire`]. The only semantic
//! changes versus v1 are:
//!
//! 1. **Prefix is brand-neutral**: every canonical message starts with
//!    `aex-<msg>:v2` instead of `spize-<msg>:v1`. The wire format no longer
//!    embeds a vendor name in cryptographically signed bytes.
//! 2. **Tighter clock skew window**: 60 seconds (down from 300s in v1).
//!    Aligns with JWT/OAuth2 RFC 7519 §4.1.4 norms — see ADR-0044.
//!    AgentId values inside the payload are expected to be W3C DID URIs
//!    (`did:method:specific-id[#fragment]`), but legacy `spize:` strings
//!    are still accepted at parse-time for the v1→v2 grace window.
//!
//! The byte-level shape (line-based, LF terminator, no trailing LF,
//! ASCII-only fields) is **identical** to v1. Existing signers/verifiers
//! that operate on raw bytes need only swap the bytes-producing function.
//!
//! See [`crate::wire`] for the v1 canonical formats kept stable for the
//! 30-day sunset grace defined in ADR-0036.

use crate::{Error, Result};

/// Wire protocol version produced by this module.
pub const PROTOCOL_VERSION_V2: &str = "v2";

/// Maximum acceptable clock skew between client and server for v2 messages,
/// in seconds. Tighter than v1's 300s; see ADR-0044.
pub const MAX_CLOCK_SKEW_SECS_V2: i64 = 60;

/// Minimum nonce length (hex chars). 32 chars = 128 bits of entropy.
/// Unchanged from v1 — entropy budget is the same regardless of prefix.
pub const MIN_NONCE_LEN: usize = 32;

/// Maximum nonce length (hex chars). Prevents pathological inputs.
pub const MAX_NONCE_LEN: usize = 128;

/// Check if `issued_at` is within the v2 allowed skew relative to `now`.
/// Overflow-safe under all `i64` inputs.
pub fn is_within_clock_skew_v2(now_unix: i64, issued_at_unix: i64) -> bool {
    let diff = (now_unix as i128).saturating_sub(issued_at_unix as i128);
    diff.unsigned_abs() <= MAX_CLOCK_SKEW_SECS_V2 as u128
}

/// Produce the canonical bytes a client signs to register an agent (v2).
///
/// Format:
/// ```text
/// aex-register:v2
/// pub={public_key_hex}
/// org={org}
/// name={name}
/// nonce={nonce}
/// ts={issued_at_unix}
/// ```
///
/// All inputs must be ASCII. Returns an error if any field contains
/// characters that could create canonicalization ambiguity (newlines,
/// NULs, non-ASCII).
pub fn registration_challenge_bytes_v2(
    public_key_hex: &str,
    org: &str,
    name: &str,
    nonce: &str,
    issued_at_unix: i64,
) -> Result<Vec<u8>> {
    validate_ascii_line(public_key_hex, "public_key_hex")?;
    validate_ascii_line(org, "org")?;
    validate_ascii_line(name, "name")?;
    validate_nonce(nonce)?;

    let msg = format!(
        "aex-register:{version}\npub={pub}\norg={org}\nname={name}\nnonce={nonce}\nts={ts}",
        version = PROTOCOL_VERSION_V2,
        pub = public_key_hex,
        org = org,
        name = name,
        nonce = nonce,
        ts = issued_at_unix,
    );
    Ok(msg.into_bytes())
}

/// Canonical bytes signed by the **sender** when initiating a transfer (v2).
///
/// Format:
/// ```text
/// aex-transfer-intent:v2
/// sender={sender_agent_id}
/// recipient={recipient}
/// size={size_bytes}
/// mime={declared_mime_or_empty}
/// filename={filename_or_empty}
/// nonce={nonce}
/// ts={issued_at_unix}
/// ```
///
/// `sender_agent_id` and `recipient` are expected to be either W3C DID
/// URIs (`did:method:id[#fragment]`) or legacy `spize:` ids during the
/// dual-wire grace window.
pub fn transfer_intent_bytes_v2(
    sender_agent_id: &str,
    recipient: &str,
    size_bytes: u64,
    declared_mime: &str,
    filename: &str,
    nonce: &str,
    issued_at_unix: i64,
) -> Result<Vec<u8>> {
    validate_ascii_line(sender_agent_id, "sender_agent_id")?;
    validate_ascii_line(recipient, "recipient")?;
    validate_ascii_line_opt(declared_mime, "declared_mime")?;
    validate_ascii_line_opt(filename, "filename")?;
    validate_nonce(nonce)?;

    let msg = format!(
        "aex-transfer-intent:{version}\nsender={sender}\nrecipient={recipient}\nsize={size}\nmime={mime}\nfilename={filename}\nnonce={nonce}\nts={ts}",
        version = PROTOCOL_VERSION_V2,
        sender = sender_agent_id,
        recipient = recipient,
        size = size_bytes,
        mime = declared_mime,
        filename = filename,
        nonce = nonce,
        ts = issued_at_unix,
    );
    Ok(msg.into_bytes())
}

/// Canonical bytes signed by the control plane when issuing a data-plane
/// ticket (v2). Semantically identical to v1; only the prefix changes.
///
/// ```text
/// aex-data-ticket:v2
/// transfer={transfer_id}
/// recipient={recipient_agent_id}
/// data_plane={data_plane_url}
/// expires={expires_unix}
/// nonce={nonce}
/// ```
pub fn data_ticket_bytes_v2(
    transfer_id: &str,
    recipient_agent_id: &str,
    data_plane_url: &str,
    expires_unix: i64,
    nonce: &str,
) -> Result<Vec<u8>> {
    validate_ascii_line(transfer_id, "transfer_id")?;
    validate_ascii_line(recipient_agent_id, "recipient_agent_id")?;
    validate_ascii_line(data_plane_url, "data_plane_url")?;
    validate_nonce(nonce)?;

    let msg = format!(
        "aex-data-ticket:{version}\ntransfer={tx}\nrecipient={rec}\ndata_plane={dp}\nexpires={exp}\nnonce={nonce}",
        version = PROTOCOL_VERSION_V2,
        tx = transfer_id,
        rec = recipient_agent_id,
        dp = data_plane_url,
        exp = expires_unix,
        nonce = nonce,
    );
    Ok(msg.into_bytes())
}

/// Canonical bytes signed by an agent's current key when requesting a
/// key rotation (v2). Mirrors the v1 protocol defined in ADR-0024.
///
/// ```text
/// aex-rotate-key:v2
/// agent={agent_id}
/// old_pub={current_public_key_hex}
/// new_pub={new_public_key_hex}
/// nonce={nonce}
/// ts={issued_at_unix}
/// ```
pub fn rotate_key_challenge_bytes_v2(
    agent_id: &str,
    old_public_key_hex: &str,
    new_public_key_hex: &str,
    nonce: &str,
    issued_at_unix: i64,
) -> Result<Vec<u8>> {
    validate_ascii_line(agent_id, "agent_id")?;
    validate_ascii_line(old_public_key_hex, "old_public_key_hex")?;
    validate_ascii_line(new_public_key_hex, "new_public_key_hex")?;
    validate_nonce(nonce)?;

    if old_public_key_hex == new_public_key_hex {
        return Err(Error::Internal(
            "old_public_key_hex and new_public_key_hex must differ".into(),
        ));
    }

    let msg = format!(
        "aex-rotate-key:{version}\nagent={agent}\nold_pub={old}\nnew_pub={new}\nnonce={nonce}\nts={ts}",
        version = PROTOCOL_VERSION_V2,
        agent = agent_id,
        old = old_public_key_hex,
        new = new_public_key_hex,
        nonce = nonce,
        ts = issued_at_unix,
    );
    Ok(msg.into_bytes())
}

/// Canonical bytes signed by the **recipient** when requesting a blob or
/// acknowledging delivery (v2).
pub fn transfer_receipt_bytes_v2(
    recipient_agent_id: &str,
    transfer_id: &str,
    action: &str,
    nonce: &str,
    issued_at_unix: i64,
) -> Result<Vec<u8>> {
    validate_ascii_line(recipient_agent_id, "recipient_agent_id")?;
    validate_ascii_line(transfer_id, "transfer_id")?;
    validate_ascii_line(action, "action")?;
    validate_nonce(nonce)?;

    if !matches!(action, "download" | "ack" | "inbox" | "request_ticket") {
        return Err(Error::Internal(format!(
            "action must be 'download', 'ack', 'inbox' or 'request_ticket', got {}",
            action
        )));
    }

    let msg = format!(
        "aex-transfer-receipt:{version}\nrecipient={rec}\ntransfer={tx}\naction={act}\nnonce={nonce}\nts={ts}",
        version = PROTOCOL_VERSION_V2,
        rec = recipient_agent_id,
        tx = transfer_id,
        act = action,
        nonce = nonce,
        ts = issued_at_unix,
    );
    Ok(msg.into_bytes())
}

// ── shared validators (duplicate of wire.rs internals; intentional to
// keep v1 untouched and v2 self-contained) ──────────────────────────

fn validate_ascii_line(s: &str, field: &str) -> Result<()> {
    if s.is_empty() {
        return Err(Error::Internal(format!("{} is empty", field)));
    }
    for (i, c) in s.chars().enumerate() {
        if !c.is_ascii() || c == '\n' || c == '\r' || c == '\0' {
            return Err(Error::Internal(format!(
                "{} has invalid char at {}: {:?}",
                field, i, c
            )));
        }
    }
    Ok(())
}

fn validate_ascii_line_opt(s: &str, field: &str) -> Result<()> {
    if s.is_empty() {
        return Ok(());
    }
    validate_ascii_line(s, field)
}

fn validate_nonce(nonce: &str) -> Result<()> {
    if nonce.len() < MIN_NONCE_LEN || nonce.len() > MAX_NONCE_LEN {
        return Err(Error::Internal(format!(
            "nonce length {} outside [{}, {}]",
            nonce.len(),
            MIN_NONCE_LEN,
            MAX_NONCE_LEN
        )));
    }
    if !nonce.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::Internal("nonce must be hex".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONCE: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn v2_register_canonical_bytes_stable() {
        let bytes =
            registration_challenge_bytes_v2("aabbcc", "acme", "alice", NONCE, 1_700_000_000)
                .unwrap();
        let expected = "aex-register:v2\npub=aabbcc\norg=acme\nname=alice\nnonce=0123456789abcdef0123456789abcdef\nts=1700000000";
        assert_eq!(bytes, expected.as_bytes());
    }

    #[test]
    fn v2_transfer_intent_uses_did_uri() {
        let bytes = transfer_intent_bytes_v2(
            "did:web:acme.com#agent-vendite",
            "did:web:beta-corp.com#acquisti",
            12345,
            "application/pdf",
            "invoice.pdf",
            NONCE,
            1_700_000_000,
        )
        .unwrap();
        let expected = "aex-transfer-intent:v2\nsender=did:web:acme.com#agent-vendite\nrecipient=did:web:beta-corp.com#acquisti\nsize=12345\nmime=application/pdf\nfilename=invoice.pdf\nnonce=0123456789abcdef0123456789abcdef\nts=1700000000";
        assert_eq!(bytes, expected.as_bytes());
    }

    #[test]
    fn v2_transfer_intent_with_legacy_spize_id() {
        // During grace window, v2 wire still accepts legacy `spize:` ids.
        let bytes = transfer_intent_bytes_v2(
            "spize:acme/alice:aabbcc",
            "did:ethr:0x14a34:0xabc",
            100,
            "",
            "",
            NONCE,
            1_700_000_000,
        )
        .unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.starts_with("aex-transfer-intent:v2\n"));
        assert!(s.contains("sender=spize:acme/alice:aabbcc\n"));
        assert!(s.contains("recipient=did:ethr:0x14a34:0xabc\n"));
    }

    #[test]
    fn v2_data_ticket_stable() {
        let bytes = data_ticket_bytes_v2(
            "tx_abc123",
            "did:web:acme.com#bob",
            "https://data.acme.com",
            1_700_000_100,
            NONCE,
        )
        .unwrap();
        let expected = "aex-data-ticket:v2\ntransfer=tx_abc123\nrecipient=did:web:acme.com#bob\ndata_plane=https://data.acme.com\nexpires=1700000100\nnonce=0123456789abcdef0123456789abcdef";
        assert_eq!(bytes, expected.as_bytes());
    }

    #[test]
    fn v2_rotate_key_stable() {
        let old = "1".repeat(64);
        let new = "2".repeat(64);
        let bytes = rotate_key_challenge_bytes_v2(
            "did:spize:acme/alice#aabbcc",
            &old,
            &new,
            NONCE,
            1_700_000_000,
        )
        .unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.starts_with("aex-rotate-key:v2\n"));
        assert!(s.contains("agent=did:spize:acme/alice#aabbcc\n"));
    }

    #[test]
    fn v2_receipt_stable() {
        let bytes = transfer_receipt_bytes_v2(
            "did:web:beta-corp.com#acquisti",
            "tx_abc123",
            "ack",
            NONCE,
            1_700_000_000,
        )
        .unwrap();
        let expected = "aex-transfer-receipt:v2\nrecipient=did:web:beta-corp.com#acquisti\ntransfer=tx_abc123\naction=ack\nnonce=0123456789abcdef0123456789abcdef\nts=1700000000";
        assert_eq!(bytes, expected.as_bytes());
    }

    #[test]
    fn v2_clock_skew_60s_window() {
        let now = 1_700_000_000_i64;
        assert!(is_within_clock_skew_v2(now, now));
        assert!(is_within_clock_skew_v2(now, now - 60));
        assert!(is_within_clock_skew_v2(now, now + 60));
        assert!(!is_within_clock_skew_v2(now, now - 61));
        assert!(!is_within_clock_skew_v2(now, now + 61));
    }

    #[test]
    fn v2_clock_skew_extreme_inputs_do_not_panic() {
        let now = 1_700_000_000_i64;
        assert!(!is_within_clock_skew_v2(now, i64::MIN));
        assert!(!is_within_clock_skew_v2(now, i64::MAX));
        assert!(!is_within_clock_skew_v2(i64::MAX, i64::MIN));
    }

    #[test]
    fn v2_newline_in_field_rejected() {
        let err = registration_challenge_bytes_v2("aa", "ac\nme", "alice", NONCE, 100).unwrap_err();
        assert!(matches!(err, Error::Internal(_)));
    }

    #[test]
    fn v2_non_ascii_field_rejected() {
        let err = registration_challenge_bytes_v2("aa", "acmè", "alice", NONCE, 100).unwrap_err();
        assert!(matches!(err, Error::Internal(_)));
    }

    #[test]
    fn v2_short_nonce_rejected() {
        let err =
            registration_challenge_bytes_v2("aa", "acme", "alice", "deadbeef", 100).unwrap_err();
        assert!(matches!(err, Error::Internal(_)));
    }

    #[test]
    fn v2_non_hex_nonce_rejected() {
        let err = registration_challenge_bytes_v2("aa", "acme", "alice", &"z".repeat(32), 100)
            .unwrap_err();
        assert!(matches!(err, Error::Internal(_)));
    }

    #[test]
    fn v2_rotate_key_rejects_same_old_and_new() {
        let same = "a".repeat(64);
        let err = rotate_key_challenge_bytes_v2(
            "did:spize:acme/alice#aabbcc",
            &same,
            &same,
            NONCE,
            1_700_000_000,
        )
        .unwrap_err();
        assert!(matches!(err, Error::Internal(_)));
    }

    #[test]
    fn v2_receipt_rejects_bad_action() {
        let err =
            transfer_receipt_bytes_v2("did:web:beta-corp.com#bob", "tx_abc", "overwrite", NONCE, 1)
                .unwrap_err();
        assert!(matches!(err, Error::Internal(_)));
    }

    #[test]
    fn v2_data_ticket_rejects_newline_url() {
        let err = data_ticket_bytes_v2(
            "tx_abc",
            "did:web:acme.com#bob",
            "https://evil.test\nspoof",
            1,
            NONCE,
        )
        .unwrap_err();
        assert!(matches!(err, Error::Internal(_)));
    }

    #[test]
    fn v2_prefix_differs_from_v1_for_identical_inputs() {
        // Critical invariant: v1 and v2 bytes for the same logical message
        // are NEVER equal — they encode different wire versions and any
        // signature verifier must distinguish them.
        let v1 = crate::wire::registration_challenge_bytes(
            "aabbcc",
            "acme",
            "alice",
            NONCE,
            1_700_000_000,
        )
        .unwrap();
        let v2 = registration_challenge_bytes_v2("aabbcc", "acme", "alice", NONCE, 1_700_000_000)
            .unwrap();
        assert_ne!(v1, v2);
        // Specifically: v1 starts with "spize-", v2 with "aex-".
        assert!(std::str::from_utf8(&v1).unwrap().starts_with("spize-"));
        assert!(std::str::from_utf8(&v2).unwrap().starts_with("aex-"));
    }
}
