//! Extract the public URL from cloudflared's stderr output.
//!
//! cloudflared prints the URL in a few formats across versions, but they
//! all contain `trycloudflare.com` for quick tunnels. We tokenize on
//! whitespace, strip common decorative characters, and look for the first
//! `https://*.trycloudflare.com` token.

pub fn extract_tunnel_url(line: &str) -> Option<String> {
    for raw in line.split_whitespace() {
        let trimmed = raw.trim_matches(|c: char| {
            c == '|' || c == ',' || c == '"' || c == '\'' || c == '<' || c == '>'
        });
        if let Some(stripped) = strip_trailing_punct(trimmed) {
            if is_trycloudflare_url(stripped) {
                return Some(stripped.to_string());
            }
        }
    }
    None
}

fn is_trycloudflare_url(s: &str) -> bool {
    s.starts_with("https://") && s.contains("trycloudflare.com")
}

fn strip_trailing_punct(s: &str) -> Option<&str> {
    let mut end = s.len();
    while end > 0 {
        let last = s.as_bytes()[end - 1];
        if matches!(last, b'.' | b',' | b';' | b':' | b'!' | b'?' | b')') {
            end -= 1;
        } else {
            break;
        }
    }
    if end == 0 {
        None
    } else {
        Some(&s[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_from_canonical_line() {
        let line = "2024-01-01T00:00:00 INF | https://foo-bar-baz.trycloudflare.com | ";
        assert_eq!(
            extract_tunnel_url(line),
            Some("https://foo-bar-baz.trycloudflare.com".into())
        );
    }

    #[test]
    fn extracts_from_surrounded_quotes() {
        let line = r#"tunnel ready: "https://nice-name.trycloudflare.com""#;
        assert_eq!(
            extract_tunnel_url(line),
            Some("https://nice-name.trycloudflare.com".into())
        );
    }

    #[test]
    fn extracts_with_trailing_period() {
        let line = "Your tunnel URL is https://x.trycloudflare.com.";
        assert_eq!(
            extract_tunnel_url(line),
            Some("https://x.trycloudflare.com".into())
        );
    }

    #[test]
    fn ignores_non_trycloudflare_urls() {
        let line = "https://example.com and https://other.trycloudfl.are.com";
        assert_eq!(extract_tunnel_url(line), None);
    }

    #[test]
    fn ignores_http_urls() {
        let line = "http://foo.trycloudflare.com should be ignored";
        assert_eq!(extract_tunnel_url(line), None);
    }

    #[test]
    fn returns_none_on_empty() {
        assert_eq!(extract_tunnel_url(""), None);
        assert_eq!(extract_tunnel_url("no url here"), None);
    }
}
