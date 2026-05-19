//! SSRF-resistant HTTP GET for fetching third-party well-known documents
//! (ADR-0045).
//!
//! Every well-known fetch in AEX v2 — agent cards, DID documents,
//! capability documents — has a peer-controlled host. Without
//! mitigation, a transfer-intent with recipient
//! `did:web:internal-admin.local` causes the resolver to GET
//! `https://internal-admin.local/.well-known/agent-card.json`, leaking
//! internal-network reachability and (via redirect) potentially
//! exfiltrating credentials.
//!
//! [`safe_get`] applies every defence in ADR-0045 §Decision:
//!
//! 1. HTTPS only (rejects `http://`, `file://`, custom schemes).
//! 2. Resolve DNS once, classify every resolved IP.
//! 3. Reject loopback, RFC1918 private, link-local, multicast for IPv4;
//!    loopback, ULA, link-local, multicast for IPv6.
//! 4. Connect by IP literal with `Host:` header preserved (no DNS
//!    rebinding window between resolve and connect).
//! 5. `redirect::Policy::none()` — a 3xx is a hard fail, never
//!    silently followed (would bypass step 3).
//! 6. 5-second total timeout.
//! 7. Hard 64 KiB body cap, enforced at stream level.
//! 8. No proxy. `HTTPS_PROXY` env var is ignored.
//!
//! The module is intentionally compact: one entry point, one error
//! enum, one helper for IP classification. Any change to the policy
//! lives here.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use thiserror::Error;
use url::Url;

/// Per-request timeout for safe-http fetches (connect + read budget).
pub const SAFE_HTTP_TIMEOUT: Duration = Duration::from_secs(5);

/// Hard ceiling on response body size for safe-http fetches.
pub const SAFE_HTTP_MAX_BODY: usize = 64 * 1024;

/// Errors raised by [`safe_get`].
///
/// Every variant maps to a single specific failure mode; verifiers and
/// observability hooks can match on the discriminant.
#[derive(Debug, Error)]
pub enum SafeHttpError {
    /// URL parsing failed.
    #[error("invalid URL: {0}")]
    InvalidUrl(String),

    /// URL scheme is not `https`.
    #[error("only https is permitted; got scheme '{0}'")]
    NonHttpsScheme(String),

    /// URL has no host component (e.g. `https:///foo`).
    #[error("URL has no host")]
    MissingHost,

    /// DNS resolution failed.
    #[error("DNS resolution failed: {0}")]
    DnsFailure(String),

    /// At least one of the resolved IP addresses is in a forbidden
    /// range (loopback, RFC1918 private, link-local, multicast, IPv6
    /// ULA). The URL is rejected without any network connection
    /// attempt.
    #[error("resolved IP {0} is in a forbidden internal range")]
    InternalAddrForbidden(IpAddr),

    /// The HTTP request returned a 3xx response. Redirects are not
    /// followed because they can bypass [`SafeHttpError::InternalAddrForbidden`].
    #[error("redirect responses are not followed; got status {0}")]
    UnexpectedRedirect(u16),

    /// Non-success HTTP status (4xx / 5xx).
    #[error("HTTP status {0}")]
    HttpStatus(u16),

    /// Response body exceeded [`SAFE_HTTP_MAX_BODY`].
    #[error("response body exceeded {SAFE_HTTP_MAX_BODY} bytes")]
    BodyTooLarge,

    /// Underlying transport (TLS, TCP, timeout) error.
    #[error("transport error: {0}")]
    Transport(String),
}

/// Successful safe-http response: status code + bounded body bytes.
#[derive(Debug)]
pub struct SafeHttpResponse {
    /// HTTP status code (always 2xx; non-2xx surfaces as `HttpStatus` error).
    pub status: u16,
    /// Response body, capped at [`SAFE_HTTP_MAX_BODY`] bytes.
    pub body: Vec<u8>,
    /// `ETag` header value if present; lets callers do conditional GETs
    /// per ADR-0046.
    pub etag: Option<String>,
}

/// SSRF-resistant HTTPS GET. See module-level docs for the policy.
///
/// The `component_name` mirrors [`crate::http::build_http_client`]
/// (`"control-plane"`, `"data-plane"`, `"sdk"`) and lands in the
/// User-Agent header.
pub async fn safe_get(
    url: &str,
    component_name: &str,
) -> Result<SafeHttpResponse, SafeHttpError> {
    let parsed = Url::parse(url).map_err(|e| SafeHttpError::InvalidUrl(e.to_string()))?;

    // Scheme check FIRST so e.g. `file:///etc/passwd` surfaces as
    // NonHttpsScheme instead of MissingHost — the security-relevant
    // failure mode is the scheme, not the missing host.
    if parsed.scheme() != "https" {
        return Err(SafeHttpError::NonHttpsScheme(parsed.scheme().to_string()));
    }

    let host = parsed
        .host_str()
        .ok_or(SafeHttpError::MissingHost)?
        .to_owned();

    // Resolve DNS once, before any connection attempt. Use the same
    // CloudflareDoH resolver the rest of AEX uses for reachability
    // checks — consistent behaviour, single audit point.
    let port = parsed.port_or_known_default().unwrap_or(443);
    let ips = resolve_host(&host, port).await?;

    // Reject if any resolved IP is internal. First-match wins so we
    // can name the offending address in the error.
    for ip in &ips {
        if is_forbidden_ip(*ip) {
            return Err(SafeHttpError::InternalAddrForbidden(*ip));
        }
    }

    // Pin the connection to the first allowed IP. `reqwest::resolve` overrides
    // the connect-time DNS lookup so an attacker that flips a TTL=0 record
    // between resolve and connect can't redirect us to an internal address.
    let chosen_ip = ips[0];
    let socket_addr = std::net::SocketAddr::new(chosen_ip, port);

    let client = reqwest::Client::builder()
        .timeout(SAFE_HTTP_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .resolve(&host, socket_addr)
        .user_agent(format!(
            "aex-{}/{}",
            component_name,
            env!("CARGO_PKG_VERSION")
        ))
        .build()
        .map_err(|e| SafeHttpError::Transport(e.to_string()))?;

    let resp = client
        .get(parsed.as_str())
        .send()
        .await
        .map_err(|e| SafeHttpError::Transport(e.to_string()))?;

    let status = resp.status();
    if status.is_redirection() {
        return Err(SafeHttpError::UnexpectedRedirect(status.as_u16()));
    }
    if !status.is_success() {
        return Err(SafeHttpError::HttpStatus(status.as_u16()));
    }

    let etag = resp
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    // Read the body in chunks to enforce the size cap without ever
    // allocating more than 64 KiB. `Response::bytes()` would load the
    // full body into memory regardless of declared Content-Length.
    let mut body = Vec::with_capacity(8 * 1024);
    let mut stream = resp;
    while let Some(chunk) = stream
        .chunk()
        .await
        .map_err(|e| SafeHttpError::Transport(e.to_string()))?
    {
        if body.len() + chunk.len() > SAFE_HTTP_MAX_BODY {
            return Err(SafeHttpError::BodyTooLarge);
        }
        body.extend_from_slice(&chunk);
    }

    Ok(SafeHttpResponse {
        status: status.as_u16(),
        body,
        etag,
    })
}

/// Resolve `host` to a list of IPs via Cloudflare 1.1.1.1.
///
/// Going through hickory directly (rather than reqwest's
/// `dns_resolver()` setting) lets us classify resolved IPs *before*
/// any connection attempt, which is what closes the SSRF window.
/// Mirrors the resolver configuration used by [`CloudflareDnsResolver`].
async fn resolve_host(host: &str, _port: u16) -> Result<Vec<IpAddr>, SafeHttpError> {
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};
    use hickory_resolver::TokioAsyncResolver;

    let resolver = TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default());

    let lookup = resolver
        .lookup_ip(host)
        .await
        .map_err(|e| SafeHttpError::DnsFailure(e.to_string()))?;

    let mut ips: Vec<IpAddr> = lookup.iter().collect();
    if ips.is_empty() {
        return Err(SafeHttpError::DnsFailure(format!(
            "no A/AAAA records for {}",
            host
        )));
    }
    // Stable preference: IPv4 first, IPv6 second. Most enterprise
    // egress paths handle v4 better; the choice is observable but
    // immaterial for SSRF correctness.
    ips.sort_by_key(|ip| matches!(ip, IpAddr::V6(_)));
    Ok(ips)
}

/// Return `true` if `ip` lies in a range that safe-http MUST refuse to
/// connect to. The classification mirrors ADR-0045 §3 verbatim.
pub fn is_forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_forbidden_ipv4(v4),
        IpAddr::V6(v6) => is_forbidden_ipv6(v6),
    }
}

fn is_forbidden_ipv4(ip: Ipv4Addr) -> bool {
    // Loopback (127.0.0.0/8).
    if ip.is_loopback() {
        return true;
    }
    // RFC 1918 private (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
    if ip.is_private() {
        return true;
    }
    // Link-local (169.254.0.0/16).
    if ip.is_link_local() {
        return true;
    }
    // Multicast (224.0.0.0/4).
    if ip.is_multicast() {
        return true;
    }
    // Broadcast (255.255.255.255) — std exposes the predicate.
    if ip.is_broadcast() {
        return true;
    }
    // Unspecified (0.0.0.0).
    if ip.is_unspecified() {
        return true;
    }
    // Reserved 240.0.0.0/4 — std flags but no predicate; check first octet.
    if ip.octets()[0] >= 240 {
        return true;
    }
    false
}

fn is_forbidden_ipv6(ip: Ipv6Addr) -> bool {
    // Loopback (::1) and unspecified (::).
    if ip.is_loopback() || ip.is_unspecified() {
        return true;
    }
    // Multicast (ff00::/8).
    if ip.is_multicast() {
        return true;
    }
    let segs = ip.segments();
    // Link-local fe80::/10 — first 10 bits are 1111_1110_10.
    if (segs[0] & 0xffc0) == 0xfe80 {
        return true;
    }
    // Unique local fc00::/7 — first 7 bits are 1111_110.
    if (segs[0] & 0xfe00) == 0xfc00 {
        return true;
    }
    // IPv4-mapped (::ffff:0:0/96) — if the inner v4 is forbidden, so is this.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_forbidden_ipv4(v4);
    }
    // IPv4-compatible (::/96 with v4) — same logic.
    if segs[0] == 0 && segs[1] == 0 && segs[2] == 0 && segs[3] == 0 && segs[4] == 0 && segs[5] == 0
    {
        let v4 = Ipv4Addr::new(
            (segs[6] >> 8) as u8,
            (segs[6] & 0xff) as u8,
            (segs[7] >> 8) as u8,
            (segs[7] & 0xff) as u8,
        );
        return is_forbidden_ipv4(v4);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── IPv4 classification ───────────────────────────────────────────

    #[test]
    fn reject_loopback_v4() {
        assert!(is_forbidden_ip("127.0.0.1".parse().unwrap()));
        assert!(is_forbidden_ip("127.255.255.255".parse().unwrap()));
    }

    #[test]
    fn reject_rfc1918_10() {
        assert!(is_forbidden_ip("10.0.0.1".parse().unwrap()));
        assert!(is_forbidden_ip("10.255.255.255".parse().unwrap()));
    }

    #[test]
    fn reject_rfc1918_172_16() {
        assert!(is_forbidden_ip("172.16.0.1".parse().unwrap()));
        assert!(is_forbidden_ip("172.31.255.255".parse().unwrap()));
        // 172.15.x.x and 172.32.x.x are public — accepted.
        assert!(!is_forbidden_ip("172.15.0.1".parse().unwrap()));
        assert!(!is_forbidden_ip("172.32.0.1".parse().unwrap()));
    }

    #[test]
    fn reject_rfc1918_192_168() {
        assert!(is_forbidden_ip("192.168.0.1".parse().unwrap()));
        assert!(is_forbidden_ip("192.168.255.255".parse().unwrap()));
    }

    #[test]
    fn reject_link_local_169_254() {
        assert!(is_forbidden_ip("169.254.0.1".parse().unwrap()));
        assert!(is_forbidden_ip("169.254.169.254".parse().unwrap())); // EC2 metadata
    }

    #[test]
    fn reject_multicast_v4() {
        assert!(is_forbidden_ip("224.0.0.1".parse().unwrap()));
        assert!(is_forbidden_ip("239.255.255.255".parse().unwrap()));
    }

    #[test]
    fn reject_broadcast_unspecified_reserved() {
        assert!(is_forbidden_ip("255.255.255.255".parse().unwrap()));
        assert!(is_forbidden_ip("0.0.0.0".parse().unwrap()));
        assert!(is_forbidden_ip("240.0.0.1".parse().unwrap()));
    }

    #[test]
    fn accept_public_v4() {
        assert!(!is_forbidden_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_forbidden_ip("1.1.1.1".parse().unwrap()));
        assert!(!is_forbidden_ip("93.184.216.34".parse().unwrap())); // example.com
    }

    // ── IPv6 classification ───────────────────────────────────────────

    #[test]
    fn reject_loopback_v6() {
        assert!(is_forbidden_ip("::1".parse().unwrap()));
    }

    #[test]
    fn reject_ipv6_unspecified() {
        assert!(is_forbidden_ip("::".parse().unwrap()));
    }

    #[test]
    fn reject_ipv6_multicast() {
        assert!(is_forbidden_ip("ff02::1".parse().unwrap()));
        assert!(is_forbidden_ip("ff05::2".parse().unwrap()));
    }

    #[test]
    fn reject_ipv6_link_local() {
        assert!(is_forbidden_ip("fe80::1".parse().unwrap()));
        assert!(is_forbidden_ip("fe80::1234:5678".parse().unwrap()));
        // febf:: is still link-local (top 10 bits match).
        assert!(is_forbidden_ip("febf::1".parse().unwrap()));
    }

    #[test]
    fn reject_ipv6_ula() {
        assert!(is_forbidden_ip("fc00::1".parse().unwrap()));
        assert!(is_forbidden_ip("fd00::1".parse().unwrap()));
        // fec0:: is NOT ULA (deprecated site-local; outside fc00::/7).
        assert!(!is_forbidden_ip("fec0::1".parse().unwrap()));
    }

    #[test]
    fn reject_ipv4_mapped_to_loopback() {
        // ::ffff:127.0.0.1 — IPv4-mapped IPv6, inner v4 is loopback.
        assert!(is_forbidden_ip("::ffff:127.0.0.1".parse().unwrap()));
        assert!(is_forbidden_ip("::ffff:10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn accept_public_v6() {
        // Google DNS IPv6.
        assert!(!is_forbidden_ip("2001:4860:4860::8888".parse().unwrap()));
        // Cloudflare DNS IPv6.
        assert!(!is_forbidden_ip("2606:4700:4700::1111".parse().unwrap()));
    }

    // ── safe_get scheme / URL validation ───────────────────────────────

    #[tokio::test]
    async fn reject_http_scheme() {
        let err = safe_get("http://example.com/agent-card.json", "test")
            .await
            .unwrap_err();
        assert!(matches!(err, SafeHttpError::NonHttpsScheme(_)));
    }

    #[tokio::test]
    async fn reject_file_scheme() {
        let err = safe_get("file:///etc/passwd", "test").await.unwrap_err();
        assert!(matches!(err, SafeHttpError::NonHttpsScheme(_)));
    }

    #[tokio::test]
    async fn reject_malformed_url() {
        let err = safe_get("not a url", "test").await.unwrap_err();
        assert!(matches!(err, SafeHttpError::InvalidUrl(_)));
    }

    // ── Constants ─────────────────────────────────────────────────────

    #[test]
    fn timeout_is_five_seconds() {
        assert_eq!(SAFE_HTTP_TIMEOUT, Duration::from_secs(5));
    }

    #[test]
    fn body_cap_is_64_kib() {
        assert_eq!(SAFE_HTTP_MAX_BODY, 64 * 1024);
    }
}
