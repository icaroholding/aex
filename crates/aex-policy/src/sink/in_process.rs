//! In-process closure-based [`crate::DecisionSink`].
//!
//! The decision is produced synchronously by user code that lives
//! in the same process as the control plane. Typical use cases:
//!
//! - A local LLM evaluator that returns accept/reject in milliseconds.
//! - A blocking CLI prompt for interactive single-tenant deployments
//!   (the prompt thread blocks the sink's submit).
//! - A deterministic in-memory policy function.
//! - Test setups.
//!
//! The sink does not assume any particular type of decider. It just
//! invokes the configured closure and forwards the outcome to a
//! caller-supplied response handler.

use std::sync::Arc;

use async_trait::async_trait;

use super::{DecisionRequest, DecisionResponse, DecisionSink, DecisionSinkError};

/// Synchronous decider closure type.
pub type DeciderFn =
    Arc<dyn Fn(&DecisionRequest) -> Result<DecisionResponse, DecisionSinkError> + Send + Sync>;

/// Callback invoked once the decider has produced an outcome.
///
/// In production this is the function that signs an
/// `aex-decision-response:v2` and POSTs it back to the sender via
/// the control plane. Tests can supply an in-memory recorder.
pub type ResponseHandler =
    Arc<dyn Fn(DecisionResponse) -> Result<(), DecisionSinkError> + Send + Sync>;

/// Closure-based [`DecisionSink`]. Calls the decider synchronously
/// inside `submit`, then hands the response to the configured
/// handler.
pub struct InProcessDecisionSink {
    decider: DeciderFn,
    on_response: ResponseHandler,
}

impl InProcessDecisionSink {
    /// Build a sink with the given decider and response handler.
    pub fn new(decider: DeciderFn, on_response: ResponseHandler) -> Self {
        Self {
            decider,
            on_response,
        }
    }
}

#[async_trait]
impl DecisionSink for InProcessDecisionSink {
    async fn submit(&self, request: DecisionRequest) -> Result<(), DecisionSinkError> {
        let response = (self.decider)(&request)?;
        if response.decision_id != request.decision_id {
            return Err(DecisionSinkError::Infra(format!(
                "decider returned decision_id '{}' for request '{}'",
                response.decision_id, request.decision_id
            )));
        }
        (self.on_response)(response)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::sink::DecisionOutcome;

    fn sample_request(id: &str) -> DecisionRequest {
        DecisionRequest {
            decision_id: id.into(),
            transfer_id: "tx".into(),
            sender_agent_id: "did:web:a.com#a".into(),
            recipient_agent_id: "did:web:b.com#b".into(),
            declared_mime: "application/pdf".into(),
            filename: "x.pdf".into(),
            size_bytes: 1,
            summary: String::new(),
        }
    }

    #[tokio::test]
    async fn accept_path() {
        let captured: Arc<Mutex<Option<DecisionResponse>>> = Arc::new(Mutex::new(None));
        let store = captured.clone();
        let sink = InProcessDecisionSink::new(
            Arc::new(|req| {
                Ok(DecisionResponse {
                    decision_id: req.decision_id.clone(),
                    outcome: DecisionOutcome::Accepted,
                    reason: String::new(),
                })
            }),
            Arc::new(move |resp| {
                *store.lock().unwrap() = Some(resp);
                Ok(())
            }),
        );

        sink.submit(sample_request("dec_1")).await.unwrap();
        let stored = captured.lock().unwrap().clone().unwrap();
        assert_eq!(stored.outcome, DecisionOutcome::Accepted);
        assert_eq!(stored.decision_id, "dec_1");
    }

    #[tokio::test]
    async fn reject_path() {
        let sink = InProcessDecisionSink::new(
            Arc::new(|req| {
                Ok(DecisionResponse {
                    decision_id: req.decision_id.clone(),
                    outcome: DecisionOutcome::Rejected,
                    reason: "policy".into(),
                })
            }),
            Arc::new(|_| Ok(())),
        );
        sink.submit(sample_request("dec_2")).await.unwrap();
    }

    #[tokio::test]
    async fn decider_id_mismatch_is_infra_error() {
        let sink = InProcessDecisionSink::new(
            Arc::new(|_| {
                Ok(DecisionResponse {
                    decision_id: "WRONG".into(),
                    outcome: DecisionOutcome::Accepted,
                    reason: String::new(),
                })
            }),
            Arc::new(|_| Ok(())),
        );
        let err = sink.submit(sample_request("dec_3")).await.unwrap_err();
        assert!(matches!(err, DecisionSinkError::Infra(_)));
    }

    #[tokio::test]
    async fn decider_error_propagates() {
        let sink = InProcessDecisionSink::new(
            Arc::new(|_| Err(DecisionSinkError::Timeout)),
            Arc::new(|_| Ok(())),
        );
        let err = sink.submit(sample_request("dec_4")).await.unwrap_err();
        assert!(matches!(err, DecisionSinkError::Timeout));
    }

    #[tokio::test]
    async fn response_handler_error_propagates() {
        let sink = InProcessDecisionSink::new(
            Arc::new(|req| {
                Ok(DecisionResponse {
                    decision_id: req.decision_id.clone(),
                    outcome: DecisionOutcome::Accepted,
                    reason: String::new(),
                })
            }),
            Arc::new(|_| Err(DecisionSinkError::Infra("db down".into()))),
        );
        let err = sink.submit(sample_request("dec_5")).await.unwrap_err();
        assert!(matches!(err, DecisionSinkError::Infra(_)));
    }
}
