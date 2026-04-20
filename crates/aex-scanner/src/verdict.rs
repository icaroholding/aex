use serde::{Deserialize, Serialize};

/// Per-scanner result classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanResult {
    /// No findings. Safe to deliver from this scanner's perspective.
    Clean,
    /// Findings that warrant human review but do not strictly block.
    Suspicious,
    /// High-confidence malicious finding. Delivery must be blocked.
    Malicious,
    /// Scanner itself failed (crash, timeout, dependency missing).
    /// The pipeline lets caller decide fail-open vs fail-closed.
    Error,
}

/// A single scanner's output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanVerdict {
    pub scanner: String,
    pub result: ScanResult,
    /// Human-readable summary (what matched, what rule, which limit).
    pub details: String,
    pub duration_ms: u64,
}

impl ScanVerdict {
    pub fn clean(scanner: impl Into<String>, duration_ms: u64) -> Self {
        Self {
            scanner: scanner.into(),
            result: ScanResult::Clean,
            details: String::new(),
            duration_ms,
        }
    }

    pub fn suspicious(
        scanner: impl Into<String>,
        details: impl Into<String>,
        duration_ms: u64,
    ) -> Self {
        Self {
            scanner: scanner.into(),
            result: ScanResult::Suspicious,
            details: details.into(),
            duration_ms,
        }
    }

    pub fn malicious(
        scanner: impl Into<String>,
        details: impl Into<String>,
        duration_ms: u64,
    ) -> Self {
        Self {
            scanner: scanner.into(),
            result: ScanResult::Malicious,
            details: details.into(),
            duration_ms,
        }
    }

    pub fn error(
        scanner: impl Into<String>,
        details: impl Into<String>,
        duration_ms: u64,
    ) -> Self {
        Self {
            scanner: scanner.into(),
            result: ScanResult::Error,
            details: details.into(),
            duration_ms,
        }
    }
}

/// Pipeline-level outcome. Clean/Blocked/Suspicious/Error reflect the
/// aggregated state; `verdicts` retains every per-scanner output for the
/// audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineVerdict {
    pub overall: ScanResult,
    pub verdicts: Vec<ScanVerdict>,
    pub total_duration_ms: u64,
}

impl PipelineVerdict {
    pub fn aggregate(verdicts: Vec<ScanVerdict>) -> Self {
        let total_duration_ms = verdicts.iter().map(|v| v.duration_ms).sum();
        let mut overall = ScanResult::Clean;
        for v in &verdicts {
            overall = match (overall, v.result) {
                // Malicious is absorbing — once seen, nothing upgrades it.
                (_, ScanResult::Malicious) | (ScanResult::Malicious, _) => ScanResult::Malicious,
                // Error dominates below Malicious.
                (_, ScanResult::Error) | (ScanResult::Error, _) => ScanResult::Error,
                // Suspicious dominates below Error.
                (_, ScanResult::Suspicious) | (ScanResult::Suspicious, _) => ScanResult::Suspicious,
                (ScanResult::Clean, ScanResult::Clean) => ScanResult::Clean,
            };
        }
        Self {
            overall,
            verdicts,
            total_duration_ms,
        }
    }

    pub fn is_blocking(&self) -> bool {
        matches!(self.overall, ScanResult::Malicious)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_verdict_is_clean() {
        let p = PipelineVerdict::aggregate(vec![]);
        assert_eq!(p.overall, ScanResult::Clean);
    }

    #[test]
    fn malicious_dominates() {
        let p = PipelineVerdict::aggregate(vec![
            ScanVerdict::clean("a", 1),
            ScanVerdict::suspicious("b", "note", 1),
            ScanVerdict::malicious("c", "hit", 1),
            ScanVerdict::error("d", "oops", 1),
        ]);
        assert_eq!(p.overall, ScanResult::Malicious);
        assert!(p.is_blocking());
    }

    #[test]
    fn error_beats_suspicious() {
        let p = PipelineVerdict::aggregate(vec![
            ScanVerdict::suspicious("a", "note", 1),
            ScanVerdict::error("b", "fail", 1),
        ]);
        assert_eq!(p.overall, ScanResult::Error);
    }

    #[test]
    fn suspicious_beats_clean() {
        let p = PipelineVerdict::aggregate(vec![
            ScanVerdict::clean("a", 1),
            ScanVerdict::suspicious("b", "note", 1),
        ]);
        assert_eq!(p.overall, ScanResult::Suspicious);
    }

    #[test]
    fn all_clean_is_clean() {
        let p = PipelineVerdict::aggregate(vec![
            ScanVerdict::clean("a", 1),
            ScanVerdict::clean("b", 1),
        ]);
        assert_eq!(p.overall, ScanResult::Clean);
        assert!(!p.is_blocking());
    }

    #[test]
    fn total_duration_sums() {
        let p = PipelineVerdict::aggregate(vec![
            ScanVerdict::clean("a", 5),
            ScanVerdict::clean("b", 7),
        ]);
        assert_eq!(p.total_duration_ms, 12);
    }
}
