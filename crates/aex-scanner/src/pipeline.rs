use std::sync::Arc;
use std::time::Instant;

use futures::future::join_all;

use crate::{PipelineVerdict, Scanner};

/// Everything a scanner might want to know about the candidate payload.
///
/// Deliberately zero-copy over `bytes` — the data plane holds the payload
/// in a temp file or memory, and passes a slice down into scanning.
pub struct ScanInput<'a> {
    pub bytes: &'a [u8],
    pub filename: Option<&'a str>,
    pub declared_mime: Option<&'a str>,
}

impl<'a> ScanInput<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            filename: None,
            declared_mime: None,
        }
    }

    pub fn with_filename(mut self, filename: &'a str) -> Self {
        self.filename = Some(filename);
        self
    }

    pub fn with_declared_mime(mut self, mime: &'a str) -> Self {
        self.declared_mime = Some(mime);
        self
    }
}

/// An ordered list of scanners to run over each candidate payload.
///
/// Scanners execute concurrently (via `futures::join_all`) so total time
/// is `max(t_i)` rather than `sum(t_i)`. This matters as we add slower
/// scanners (ML classifier, external process scanners).
#[derive(Clone, Default)]
pub struct ScanPipeline {
    scanners: Vec<Arc<dyn Scanner>>,
}

impl ScanPipeline {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_scanner(mut self, scanner: Arc<dyn Scanner>) -> Self {
        self.scanners.push(scanner);
        self
    }

    pub fn len(&self) -> usize {
        self.scanners.len()
    }

    pub fn is_empty(&self) -> bool {
        self.scanners.is_empty()
    }

    pub async fn scan(&self, input: &ScanInput<'_>) -> PipelineVerdict {
        let t0 = Instant::now();
        let futs: Vec<_> = self.scanners.iter().map(|s| s.scan(input)).collect();
        let verdicts = join_all(futs).await;
        let mut agg = PipelineVerdict::aggregate(verdicts);
        // Override sum-of-durations with wall-clock, which is the meaningful
        // number for an operator watching latency.
        agg.total_duration_ms = t0.elapsed().as_millis() as u64;
        agg
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::{ScanResult, ScanVerdict};
    use async_trait::async_trait;

    struct Fixed {
        name: &'static str,
        result: ScanResult,
    }

    #[async_trait]
    impl Scanner for Fixed {
        fn name(&self) -> &'static str {
            self.name
        }
        async fn scan(&self, _input: &ScanInput<'_>) -> ScanVerdict {
            match self.result {
                ScanResult::Clean => ScanVerdict::clean(self.name, 1),
                ScanResult::Suspicious => ScanVerdict::suspicious(self.name, "x", 1),
                ScanResult::Malicious => ScanVerdict::malicious(self.name, "x", 1),
                ScanResult::Error => ScanVerdict::error(self.name, "x", 1),
            }
        }
    }

    #[tokio::test]
    async fn empty_pipeline_is_clean() {
        let p = ScanPipeline::new();
        let v = p.scan(&ScanInput::new(b"hello")).await;
        assert_eq!(v.overall, ScanResult::Clean);
    }

    #[tokio::test]
    async fn pipeline_runs_all_scanners() {
        let p = ScanPipeline::new()
            .with_scanner(Arc::new(Fixed {
                name: "a",
                result: ScanResult::Clean,
            }))
            .with_scanner(Arc::new(Fixed {
                name: "b",
                result: ScanResult::Suspicious,
            }));
        let v = p.scan(&ScanInput::new(b"hello")).await;
        assert_eq!(v.verdicts.len(), 2);
        assert_eq!(v.overall, ScanResult::Suspicious);
    }

    #[tokio::test]
    async fn malicious_blocks_pipeline() {
        let p = ScanPipeline::new()
            .with_scanner(Arc::new(Fixed {
                name: "good",
                result: ScanResult::Clean,
            }))
            .with_scanner(Arc::new(Fixed {
                name: "bad",
                result: ScanResult::Malicious,
            }));
        let v = p.scan(&ScanInput::new(b"payload")).await;
        assert!(v.is_blocking());
    }
}
