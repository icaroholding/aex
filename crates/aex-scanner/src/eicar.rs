//! EICAR test-file detection.
//!
//! The [EICAR test string](https://en.wikipedia.org/wiki/EICAR_test_file) is
//! the standard non-malicious sample used to verify that antivirus pipelines
//! are wired up. Hitting it is the canonical smoke test for this scanner.
//!
//! The string is ASCII 68 bytes long and has been the same since 1991. We
//! match it as a substring (not an exact file) so ZIP-wrapped or
//! concatenated variants are still caught.

use std::time::Instant;

use async_trait::async_trait;

use crate::{pipeline::ScanInput, verdict::ScanVerdict, Scanner};

/// Canonical EICAR signature. DO NOT auto-format this line — splitting the
/// string would prevent detection.
pub const EICAR_SIGNATURE: &[u8] =
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

#[derive(Default)]
pub struct EicarScanner;

impl EicarScanner {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Scanner for EicarScanner {
    fn name(&self) -> &'static str {
        "eicar"
    }

    async fn scan(&self, input: &ScanInput<'_>) -> ScanVerdict {
        let t0 = Instant::now();
        let hit = contains_slice(input.bytes, EICAR_SIGNATURE);
        let dur = t0.elapsed().as_millis() as u64;
        if hit {
            ScanVerdict::malicious(self.name(), "EICAR test signature matched", dur)
        } else {
            ScanVerdict::clean(self.name(), dur)
        }
    }
}

/// Naive substring search. Sufficient for the EICAR signature (ASCII, short).
/// If this hotspot becomes expensive, switch to `memchr::memmem`.
fn contains_slice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::ScanResult;

    #[tokio::test]
    async fn clean_file_passes() {
        let s = EicarScanner::new();
        let v = s.scan(&ScanInput::new(b"hello world, this is fine")).await;
        assert_eq!(v.result, ScanResult::Clean);
    }

    #[tokio::test]
    async fn raw_eicar_detected() {
        let s = EicarScanner::new();
        let v = s.scan(&ScanInput::new(EICAR_SIGNATURE)).await;
        assert_eq!(v.result, ScanResult::Malicious);
    }

    #[tokio::test]
    async fn embedded_eicar_detected() {
        let s = EicarScanner::new();
        let mut payload = vec![0x00; 1024];
        payload.extend_from_slice(EICAR_SIGNATURE);
        payload.extend_from_slice(b"trailing data");
        let v = s.scan(&ScanInput::new(&payload)).await;
        assert_eq!(v.result, ScanResult::Malicious);
    }

    #[tokio::test]
    async fn empty_input_clean() {
        let s = EicarScanner::new();
        let v = s.scan(&ScanInput::new(b"")).await;
        assert_eq!(v.result, ScanResult::Clean);
    }
}
