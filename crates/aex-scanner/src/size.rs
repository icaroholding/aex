//! Size-limit scanner: refuses payloads larger than `max_bytes`.

use std::time::Instant;

use async_trait::async_trait;

use crate::{pipeline::ScanInput, verdict::ScanVerdict, Scanner};

pub struct SizeLimitScanner {
    max_bytes: u64,
}

impl SizeLimitScanner {
    pub fn new(max_bytes: u64) -> Self {
        Self { max_bytes }
    }
}

#[async_trait]
impl Scanner for SizeLimitScanner {
    fn name(&self) -> &'static str {
        "size-limit"
    }

    async fn scan(&self, input: &ScanInput<'_>) -> ScanVerdict {
        let t0 = Instant::now();
        let size = input.bytes.len() as u64;
        let dur = t0.elapsed().as_millis() as u64;
        if size > self.max_bytes {
            ScanVerdict::malicious(
                self.name(),
                format!("size {} exceeds limit {}", size, self.max_bytes),
                dur,
            )
        } else {
            ScanVerdict::clean(self.name(), dur)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::ScanResult;

    #[tokio::test]
    async fn within_limit_clean() {
        let s = SizeLimitScanner::new(100);
        let v = s.scan(&ScanInput::new(&[0u8; 50])).await;
        assert_eq!(v.result, ScanResult::Clean);
    }

    #[tokio::test]
    async fn exactly_limit_clean() {
        let s = SizeLimitScanner::new(100);
        let v = s.scan(&ScanInput::new(&[0u8; 100])).await;
        assert_eq!(v.result, ScanResult::Clean);
    }

    #[tokio::test]
    async fn over_limit_malicious() {
        let s = SizeLimitScanner::new(100);
        let v = s.scan(&ScanInput::new(&[0u8; 101])).await;
        assert_eq!(v.result, ScanResult::Malicious);
        assert!(v.details.contains("exceeds"));
    }
}
