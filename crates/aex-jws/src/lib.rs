//! JWS Compact Serialization (RFC 7515) sign/verify for AEX agent cards.
//!
//! Hardcoded algorithm whitelist: `EdDSA` (Ed25519) and `ES256K` (secp256k1).
//! Per ADR-0045 §3, the whitelist is not configurable — it is compiled in.
//! `alg=none`, `alg=HS256`, and every other value are rejected at parse time,
//! before any signature work happens.
//!
//! # Why a custom JWS layer
//!
//! AEX already depends on `ed25519-dalek` and `k256` for native signatures
//! (ADR-0011). Pulling in a full JOSE library (`josekit`, `jsonwebtoken`)
//! would add MB of transitive dependencies for the ~200 lines of code we
//! actually need: parse three base64url segments, validate `alg`,
//! verify a signature, return the payload. The narrow surface also makes
//! algorithm-confusion attacks easier to audit — every place we touch
//! `alg` is in this file.
//!
//! # Algorithms
//!
//! - **`EdDSA`** — Ed25519, signature over the raw `header.payload` bytes
//!   (no pre-hash; Ed25519 internally uses SHA-512).
//! - **`ES256K`** — secp256k1 with SHA-256 pre-hash; signature is the
//!   raw 64-byte concatenation of `r || s` (JWS conventions, RFC 8812).
//!
//! # Verifier injection
//!
//! [`verify`] takes a `key_lookup` closure that resolves `kid` to a
//! [`VerifierKey`]. This keeps the JWS layer decoupled from how keys
//! are stored — `aex-identity` providers each plug in their own
//! resolution logic without `aex-jws` knowing about DID methods.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::Verifier as _;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use thiserror::Error;

/// JWS verification or signing failure.
#[derive(Debug, Error)]
pub enum JwsError {
    /// Compact serialization is not three `.`-separated segments.
    #[error("JWS must have exactly three segments separated by '.'")]
    InvalidStructure,

    /// Base64url decoding of header or signature failed.
    #[error("base64url decode failed: {0}")]
    Base64Decode(String),

    /// Header JSON parsing failed or required field missing.
    #[error("invalid JWS header: {0}")]
    InvalidHeader(String),

    /// `alg` value is not in the whitelist. Includes `"none"`, `"HS256"`,
    /// and any other non-`EdDSA`/`ES256K` string.
    #[error("algorithm '{0}' is not permitted; only EdDSA and ES256K accepted")]
    AlgorithmNotPermitted(String),

    /// Header carries `alg` as a non-string (e.g. array or number).
    #[error("alg must be a single string value")]
    AlgorithmMalformed,

    /// `kid` field is missing or empty in the header.
    #[error("kid is required and must be a non-empty string")]
    MissingKid,

    /// `key_lookup` returned `None` for the header's `kid`.
    #[error("no key found for kid '{0}'")]
    UnknownKid(String),

    /// `key_lookup` returned a key whose algorithm doesn't match `alg`.
    #[error("kid '{kid}' resolves to a key of algorithm {key_alg}, but header declared {header_alg}")]
    KidAlgMismatch {
        /// kid value from the header
        kid: String,
        /// algorithm declared in the header
        header_alg: String,
        /// algorithm of the key resolved by key_lookup
        key_alg: String,
    },

    /// Signature did not verify against the resolved key. **Never log
    /// the raw bytes** — only the kid and algorithm.
    #[error("signature verification failed for kid '{0}'")]
    BadSignature(String),

    /// Header or payload exceeded the safety cap. Real JWS payloads
    /// are < 8 KiB; we cap at 64 KiB to defend against memory-bomb
    /// inputs.
    #[error("segment exceeds {SEGMENT_MAX_BYTES} byte cap")]
    SegmentTooLarge,

    /// Crypto primitive error during signing (key serialization etc).
    #[error("signing error: {0}")]
    SigningError(String),
}

/// Maximum size of any single base64-decoded segment. Real agent cards
/// are < 8 KiB; 64 KiB is the hard ceiling for memory safety.
pub const SEGMENT_MAX_BYTES: usize = 64 * 1024;

/// JWS algorithms whitelisted by AEX.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Algorithm {
    /// Ed25519 signature.
    #[serde(rename = "EdDSA")]
    EdDsa,
    /// secp256k1 ECDSA with SHA-256 pre-hash.
    #[serde(rename = "ES256K")]
    Es256k,
}

impl Algorithm {
    /// Stable wire-string name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Algorithm::EdDsa => "EdDSA",
            Algorithm::Es256k => "ES256K",
        }
    }

    /// Parse from JWS `alg` string. Returns `None` for any value outside
    /// the whitelist — including `"none"`, `"HS256"`, `"RS256"`.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "EdDSA" => Some(Algorithm::EdDsa),
            "ES256K" => Some(Algorithm::Es256k),
            _ => None,
        }
    }
}

/// JWS Protected Header.
///
/// Only the fields we use are modeled; unknown fields are tolerated by
/// the JSON deserializer (forward-compat). `alg` is parsed strictly
/// because everything else hinges on it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwsHeader {
    /// Algorithm. Must be `EdDSA` or `ES256K`.
    pub alg: Algorithm,
    /// Key identifier. Required by AEX; in practice the full DID URI of
    /// the signing agent.
    pub kid: String,
    /// Media type. Conventionally `"JOSE+JSON"` or `"jwt"`. Optional;
    /// AEX does not enforce a value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
}

/// A verifier key resolved by the caller's `key_lookup` closure.
#[derive(Debug, Clone)]
pub enum VerifierKey {
    /// Ed25519 verifying key.
    Ed25519(ed25519_dalek::VerifyingKey),
    /// secp256k1 verifying key.
    Secp256k1(k256::ecdsa::VerifyingKey),
}

impl VerifierKey {
    fn algorithm(&self) -> Algorithm {
        match self {
            VerifierKey::Ed25519(_) => Algorithm::EdDsa,
            VerifierKey::Secp256k1(_) => Algorithm::Es256k,
        }
    }
}

/// A successfully verified JWS payload.
#[derive(Debug, Clone)]
pub struct VerifiedPayload {
    /// Decoded header.
    pub header: JwsHeader,
    /// Raw decoded payload bytes — caller deserializes per use case
    /// (agent card schema, etc.).
    pub payload: Vec<u8>,
}

/// Sign `payload` as a JWS using an Ed25519 key.
///
/// `kid` lands in the header; verifiers look it up to find the
/// matching [`VerifierKey::Ed25519`].
pub fn sign_ed25519(
    payload: &[u8],
    signing_key: &ed25519_dalek::SigningKey,
    kid: impl Into<String>,
) -> Result<String, JwsError> {
    sign_inner(payload, kid.into(), Algorithm::EdDsa, |signing_input| {
        use ed25519_dalek::Signer;
        let sig = signing_key.sign(signing_input);
        Ok(sig.to_bytes().to_vec())
    })
}

/// Sign `payload` as a JWS using a secp256k1 key.
pub fn sign_es256k(
    payload: &[u8],
    signing_key: &k256::ecdsa::SigningKey,
    kid: impl Into<String>,
) -> Result<String, JwsError> {
    sign_inner(payload, kid.into(), Algorithm::Es256k, |signing_input| {
        use k256::ecdsa::signature::Signer;
        let sig: k256::ecdsa::Signature = signing_key.sign(signing_input);
        Ok(sig.to_bytes().to_vec())
    })
}

fn sign_inner(
    payload: &[u8],
    kid: String,
    alg: Algorithm,
    sign_fn: impl FnOnce(&[u8]) -> Result<Vec<u8>, JwsError>,
) -> Result<String, JwsError> {
    if kid.is_empty() {
        return Err(JwsError::MissingKid);
    }
    let header = JwsHeader {
        alg,
        kid,
        typ: Some("JOSE+JSON".into()),
    };
    let header_json =
        serde_json::to_vec(&header).map_err(|e| JwsError::InvalidHeader(e.to_string()))?;
    let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload);
    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let sig_bytes = sign_fn(signing_input.as_bytes())?;
    let sig_b64 = URL_SAFE_NO_PAD.encode(&sig_bytes);
    Ok(format!("{}.{}", signing_input, sig_b64))
}

/// Verify a JWS Compact Serialization.
///
/// The `key_lookup` closure resolves the header's `kid` to a
/// [`VerifierKey`]. It returns `Ok(None)` for unknown kids (the function
/// then returns [`JwsError::UnknownKid`]) and `Err` for lookup
/// failures the caller wants to surface (e.g. transient DB error).
///
/// On success, returns the parsed header and the decoded payload bytes.
pub fn verify<F>(jws: &str, key_lookup: F) -> Result<VerifiedPayload, JwsError>
where
    F: FnOnce(&str) -> Result<Option<VerifierKey>, JwsError>,
{
    // Three segments, exactly. Reject any other shape before any
    // base64 work — keeps the parser cheap and predictable.
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err(JwsError::InvalidStructure);
    }
    let (header_b64, payload_b64, sig_b64) = (parts[0], parts[1], parts[2]);

    // Size caps before allocation to defend against memory-bomb inputs.
    if header_b64.len() > SEGMENT_MAX_BYTES
        || payload_b64.len() > SEGMENT_MAX_BYTES
        || sig_b64.len() > SEGMENT_MAX_BYTES
    {
        return Err(JwsError::SegmentTooLarge);
    }

    let header_json = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|e| JwsError::Base64Decode(format!("header: {}", e)))?;
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| JwsError::Base64Decode(format!("payload: {}", e)))?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|e| JwsError::Base64Decode(format!("signature: {}", e)))?;

    // Parse the header with strict alg validation. `serde_json` parsing
    // of `Algorithm` rejects unknown / malformed `alg` automatically
    // (returns serde error), which we re-classify as AlgorithmNotPermitted
    // when the raw value is recoverable.
    let raw_header: serde_json::Value = serde_json::from_slice(&header_json)
        .map_err(|e| JwsError::InvalidHeader(e.to_string()))?;
    // Pre-check alg shape explicitly so the error is precise.
    match raw_header.get("alg") {
        None => return Err(JwsError::InvalidHeader("missing alg".into())),
        Some(serde_json::Value::String(s)) => {
            if Algorithm::parse(s).is_none() {
                return Err(JwsError::AlgorithmNotPermitted(s.clone()));
            }
        }
        Some(_) => return Err(JwsError::AlgorithmMalformed),
    }

    let header: JwsHeader = serde_json::from_value(raw_header)
        .map_err(|e| JwsError::InvalidHeader(e.to_string()))?;

    if header.kid.is_empty() {
        return Err(JwsError::MissingKid);
    }

    // Resolve the key.
    let key = match key_lookup(&header.kid)? {
        Some(k) => k,
        None => return Err(JwsError::UnknownKid(header.kid.clone())),
    };
    if key.algorithm() != header.alg {
        return Err(JwsError::KidAlgMismatch {
            kid: header.kid.clone(),
            header_alg: header.alg.as_str().to_string(),
            key_alg: key.algorithm().as_str().to_string(),
        });
    }

    // Reconstruct the signing input. Per RFC 7515 §5.2, the input is
    // exactly `<header_b64>.<payload_b64>` as bytes — no re-encoding.
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    let ok = match key {
        VerifierKey::Ed25519(vk) => {
            let sig = ed25519_dalek::Signature::from_slice(&sig_bytes)
                .map_err(|_| JwsError::BadSignature(header.kid.clone()))?;
            vk.verify(signing_input.as_bytes(), &sig).is_ok()
        }
        VerifierKey::Secp256k1(vk) => {
            let sig = k256::ecdsa::Signature::from_slice(&sig_bytes)
                .map_err(|_| JwsError::BadSignature(header.kid.clone()))?;
            // ES256K is SHA-256 pre-hash, but k256's `verify` already
            // applies SHA-256 internally when called with a `Verifier`
            // impl on the raw message.
            vk.verify(signing_input.as_bytes(), &sig).is_ok()
        }
    };

    if !ok {
        return Err(JwsError::BadSignature(header.kid));
    }

    Ok(VerifiedPayload {
        header,
        payload: payload_bytes,
    })
}

/// Convenience: SHA-256 digest of a byte slice. Exposed because every
/// AEX layer that touches JWS at some point also needs to hash. Saves
/// a `use sha2::Digest` and a `Sha256::digest(..).into()` everywhere.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, VerifyingKey};

    fn fixed_ed25519_keypair() -> (SigningKey, VerifyingKey) {
        // Deterministic key for reproducible tests. NEVER use in prod.
        let seed: [u8; 32] = [42u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    fn fixed_secp256k1_keypair() -> (k256::ecdsa::SigningKey, k256::ecdsa::VerifyingKey) {
        let seed: [u8; 32] = [1u8; 32];
        let sk = k256::ecdsa::SigningKey::from_slice(&seed).unwrap();
        let vk = *sk.verifying_key();
        (sk, vk)
    }

    // ── Algorithm enum ─────────────────────────────────────────────

    #[test]
    fn algorithm_names_stable() {
        assert_eq!(Algorithm::EdDsa.as_str(), "EdDSA");
        assert_eq!(Algorithm::Es256k.as_str(), "ES256K");
    }

    #[test]
    fn parse_rejects_none() {
        assert!(Algorithm::parse("none").is_none());
        assert!(Algorithm::parse("None").is_none());
        assert!(Algorithm::parse("NONE").is_none());
    }

    #[test]
    fn parse_rejects_hs256() {
        assert!(Algorithm::parse("HS256").is_none());
        assert!(Algorithm::parse("HS384").is_none());
        assert!(Algorithm::parse("HS512").is_none());
    }

    #[test]
    fn parse_rejects_rsa() {
        assert!(Algorithm::parse("RS256").is_none());
        assert!(Algorithm::parse("PS256").is_none());
    }

    #[test]
    fn parse_accepts_eddsa_and_es256k() {
        assert_eq!(Algorithm::parse("EdDSA"), Some(Algorithm::EdDsa));
        assert_eq!(Algorithm::parse("ES256K"), Some(Algorithm::Es256k));
    }

    // ── Sign + verify round trip ──────────────────────────────────

    #[test]
    fn ed25519_sign_and_verify() {
        let (sk, vk) = fixed_ed25519_keypair();
        let payload = b"hello world";
        let kid = "did:key:test-ed25519";
        let jws = sign_ed25519(payload, &sk, kid).unwrap();

        let verified = verify(&jws, |k| {
            assert_eq!(k, kid);
            Ok(Some(VerifierKey::Ed25519(vk)))
        })
        .unwrap();

        assert_eq!(verified.payload, payload);
        assert_eq!(verified.header.alg, Algorithm::EdDsa);
        assert_eq!(verified.header.kid, kid);
    }

    #[test]
    fn es256k_sign_and_verify() {
        let (sk, vk) = fixed_secp256k1_keypair();
        let payload = b"hello secp256k1";
        let kid = "did:ethr:8453:0xabc";
        let jws = sign_es256k(payload, &sk, kid).unwrap();

        let verified = verify(&jws, |_| Ok(Some(VerifierKey::Secp256k1(vk)))).unwrap();
        assert_eq!(verified.payload, payload);
        assert_eq!(verified.header.alg, Algorithm::Es256k);
    }

    // ── Algorithm confusion / negative ────────────────────────────

    #[test]
    fn rejects_alg_none() {
        // Hand-craft a JWS with alg=none, no signature.
        let header = serde_json::json!({"alg": "none", "kid": "did:web:attacker.com"});
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(b"forged");
        let jws = format!("{}.{}.", header_b64, payload_b64); // empty sig
        let err = verify(&jws, |_| panic!("must not reach key_lookup")).unwrap_err();
        assert!(matches!(err, JwsError::AlgorithmNotPermitted(ref s) if s == "none"));
    }

    #[test]
    fn rejects_alg_hs256() {
        let header = serde_json::json!({"alg": "HS256", "kid": "did:web:attacker.com"});
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(b"forged");
        let sig_b64 = URL_SAFE_NO_PAD.encode([0u8; 32]);
        let jws = format!("{}.{}.{}", header_b64, payload_b64, sig_b64);
        let err = verify(&jws, |_| panic!("must not reach key_lookup")).unwrap_err();
        assert!(matches!(err, JwsError::AlgorithmNotPermitted(ref s) if s == "HS256"));
    }

    #[test]
    fn rejects_missing_alg() {
        let header = serde_json::json!({"kid": "did:web:foo.com"});
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(b"x");
        let sig_b64 = URL_SAFE_NO_PAD.encode([0u8; 32]);
        let jws = format!("{}.{}.{}", header_b64, payload_b64, sig_b64);
        let err = verify(&jws, |_| panic!()).unwrap_err();
        assert!(matches!(err, JwsError::InvalidHeader(_)));
    }

    #[test]
    fn rejects_alg_as_array() {
        let header = serde_json::json!({"alg": ["EdDSA"], "kid": "did:web:foo.com"});
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(b"x");
        let sig_b64 = URL_SAFE_NO_PAD.encode([0u8; 32]);
        let jws = format!("{}.{}.{}", header_b64, payload_b64, sig_b64);
        let err = verify(&jws, |_| panic!()).unwrap_err();
        assert!(matches!(err, JwsError::AlgorithmMalformed));
    }

    #[test]
    fn rejects_two_segments() {
        let err = verify("aa.bb", |_| panic!()).unwrap_err();
        assert!(matches!(err, JwsError::InvalidStructure));
    }

    #[test]
    fn rejects_four_segments() {
        let err = verify("aa.bb.cc.dd", |_| panic!()).unwrap_err();
        assert!(matches!(err, JwsError::InvalidStructure));
    }

    #[test]
    fn rejects_unknown_kid() {
        let (sk, _vk) = fixed_ed25519_keypair();
        let jws = sign_ed25519(b"x", &sk, "did:web:mystery.com").unwrap();
        let err = verify(&jws, |_| Ok(None)).unwrap_err();
        assert!(matches!(err, JwsError::UnknownKid(_)));
    }

    #[test]
    fn rejects_missing_kid() {
        // Hand-craft: valid alg, empty kid.
        let header = serde_json::json!({"alg": "EdDSA", "kid": ""});
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(b"x");
        let sig_b64 = URL_SAFE_NO_PAD.encode([0u8; 64]);
        let jws = format!("{}.{}.{}", header_b64, payload_b64, sig_b64);
        let err = verify(&jws, |_| panic!()).unwrap_err();
        assert!(matches!(err, JwsError::MissingKid));
    }

    #[test]
    fn rejects_sign_with_empty_kid() {
        let (sk, _) = fixed_ed25519_keypair();
        let err = sign_ed25519(b"x", &sk, "").unwrap_err();
        assert!(matches!(err, JwsError::MissingKid));
    }

    #[test]
    fn rejects_kid_alg_mismatch() {
        // Sign with Ed25519, present a secp256k1 key to the verifier.
        let (sk_ed, _) = fixed_ed25519_keypair();
        let (_, vk_k) = fixed_secp256k1_keypair();
        let jws = sign_ed25519(b"x", &sk_ed, "did:web:foo").unwrap();
        let err = verify(&jws, |_| Ok(Some(VerifierKey::Secp256k1(vk_k)))).unwrap_err();
        assert!(matches!(err, JwsError::KidAlgMismatch { .. }));
    }

    #[test]
    fn rejects_tampered_payload() {
        let (sk, vk) = fixed_ed25519_keypair();
        let jws = sign_ed25519(b"original", &sk, "did:web:bob").unwrap();

        // Swap payload segment.
        let parts: Vec<&str> = jws.split('.').collect();
        let tampered_payload = URL_SAFE_NO_PAD.encode(b"forged");
        let tampered = format!("{}.{}.{}", parts[0], tampered_payload, parts[2]);

        let err = verify(&tampered, |_| Ok(Some(VerifierKey::Ed25519(vk)))).unwrap_err();
        assert!(matches!(err, JwsError::BadSignature(_)));
    }

    #[test]
    fn rejects_corrupted_signature() {
        let (sk, vk) = fixed_ed25519_keypair();
        let jws = sign_ed25519(b"x", &sk, "did:web:bob").unwrap();

        let parts: Vec<&str> = jws.split('.').collect();
        let corrupted_sig = URL_SAFE_NO_PAD.encode([0u8; 64]);
        let bad = format!("{}.{}.{}", parts[0], parts[1], corrupted_sig);

        let err = verify(&bad, |_| Ok(Some(VerifierKey::Ed25519(vk)))).unwrap_err();
        assert!(matches!(err, JwsError::BadSignature(_)));
    }

    #[test]
    fn rejects_malformed_base64_header() {
        let err = verify("!!!!.bb.cc", |_| panic!()).unwrap_err();
        assert!(matches!(err, JwsError::Base64Decode(_)));
    }

    #[test]
    fn rejects_segment_too_large() {
        // Build a base64 string longer than SEGMENT_MAX_BYTES.
        let huge = "a".repeat(SEGMENT_MAX_BYTES + 1);
        let jws = format!("{}.bb.cc", huge);
        let err = verify(&jws, |_| panic!()).unwrap_err();
        assert!(matches!(err, JwsError::SegmentTooLarge));
    }

    #[test]
    fn key_lookup_error_propagates() {
        let (sk, _vk) = fixed_ed25519_keypair();
        let jws = sign_ed25519(b"x", &sk, "did:web:bob").unwrap();
        let err =
            verify(&jws, |_| Err(JwsError::UnknownKid("db down".into()))).unwrap_err();
        assert!(matches!(err, JwsError::UnknownKid(ref s) if s == "db down"));
    }

    #[test]
    fn sha256_helper_matches_known_vector() {
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let h = sha256(b"abc");
        assert_eq!(
            hex::encode(h),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn typ_omitted_by_default_serialization() {
        // Ensure JWS we produce includes typ JOSE+JSON; verifier tolerates absent.
        let (sk, _) = fixed_ed25519_keypair();
        let jws = sign_ed25519(b"x", &sk, "did:web:bob").unwrap();
        let parts: Vec<&str> = jws.split('.').collect();
        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let header_json: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header_json["typ"].as_str(), Some("JOSE+JSON"));
    }
}
